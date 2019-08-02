#include <assert.h>

#include <linux/err.h>

#include "kvm/devices.h"
#include "kvm/ioport.h"
#include "kvm/irq.h"
#include "kvm/kvm.h"
#include "kvm/pci.h"
#include "kvm/util.h"

static u32 pci_config_address_bits;

/* This is within our PCI gap - in an unused area.
 * Note this is a PCI *bus address*, is used to assign BARs etc.!
 * (That's why it can still 32bit even with 64bit guests-- 64bit
 * PCI isn't currently supported.)
 */
static u32 mmio_space_blocks		= KVM_PCI_MMIO_AREA;
static u16 io_port_blocks		= PCI_IOPORT_START;

u16 pci_get_io_port_block(u32 size)
{
	u16 port = ALIGN(io_port_blocks, PCI_IO_SIZE);
	io_port_blocks = port + size;
	return port;
}

/*
 * BARs must be naturally aligned, so enforce this in the allocator.
 */
u32 pci_get_mmio_block(u32 size)
{
	u32 block = ALIGN(mmio_space_blocks, size);
	mmio_space_blocks = block + size;
	return block;
}

void *pci_find_cap(struct pci_device_header *hdr, u8 cap_type)
{
	u8 pos;
	struct pci_cap_hdr *cap;

	pci_for_each_cap(pos, cap, hdr) {
		if (cap->type == cap_type)
			return cap;
	}

	return NULL;
}

void pci__assign_irq(struct device_header *dev_hdr)
{
	struct pci_device_header *pci_hdr = dev_hdr->data;

	/*
	 * PCI supports only INTA#,B#,C#,D# per device.
	 *
	 * A#,B#,C#,D# are allowed for multifunctional devices so stick
	 * with A# for our single function devices.
	 */
	pci_hdr->irq_pin	= 1;
	pci_hdr->irq_line	= irq__alloc_line();

	if (!pci_hdr->irq_type)
		pci_hdr->irq_type = IRQ_TYPE_EDGE_RISING;
}

static void *pci_config_address_ptr(u16 port)
{
	unsigned long offset;
	void *base;

	offset	= port - PCI_CONFIG_ADDRESS;
	base	= &pci_config_address_bits;

	return base + offset;
}

static bool pci_config_address_out(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	void *p = pci_config_address_ptr(port);

	memcpy(p, data, size);

	return true;
}

static bool pci_config_address_in(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	void *p = pci_config_address_ptr(port);

	memcpy(data, p, size);

	return true;
}

static struct ioport_operations pci_config_address_ops = {
	.io_in	= pci_config_address_in,
	.io_out	= pci_config_address_out,
};

static bool pci_device_exists(u8 bus_number, u8 device_number, u8 function_number)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);

	if (pci_config_address.bus_number != bus_number)
		return false;

	if (pci_config_address.function_number != function_number)
		return false;

	return !IS_ERR_OR_NULL(device__find_dev(DEVICE_BUS_PCI, device_number));
}

static bool pci_config_data_out(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);
	/*
	 * If someone accesses PCI configuration space offsets that are not
	 * aligned to 4 bytes, it uses ioports to signify that.
	 */
	pci_config_address.reg_offset = port - PCI_CONFIG_DATA;

	pci__config_wr(vcpu->kvm, pci_config_address, data, size);

	return true;
}

static bool pci_config_data_in(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);
	/*
	 * If someone accesses PCI configuration space offsets that are not
	 * aligned to 4 bytes, it uses ioports to signify that.
	 */
	pci_config_address.reg_offset = port - PCI_CONFIG_DATA;

	pci__config_rd(vcpu->kvm, pci_config_address, data, size);

	return true;
}

static struct ioport_operations pci_config_data_ops = {
	.io_in	= pci_config_data_in,
	.io_out	= pci_config_data_out,
};

void pci__config_wr(struct kvm *kvm, union pci_config_address addr, void *data, int size)
{
	void *base;
	u8 bar, offset;
	struct pci_device_header *pci_hdr;
	u8 dev_num = addr.device_number;

	if (!pci_device_exists(addr.bus_number, dev_num, 0))
		return;

	offset = addr.w & PCI_DEV_CFG_MASK;
	base = pci_hdr = device__find_dev(DEVICE_BUS_PCI, dev_num)->data;

	down_write(&pci_hdr->device_lock);

	if (pci_hdr->cfg_ops.write)
		pci_hdr->cfg_ops.write(kvm, pci_hdr, offset, data, size);

	/*
	 * legacy hack: ignore writes to uninitialized regions (e.g. ROM BAR).
	 * Not very nice but has been working so far.
	 */
	if (*(u32 *)(base + offset) == 0)
		goto unlock_device;

	bar = (offset - PCI_BAR_OFFSET(0)) / sizeof(u32);

	/*
	 * If the kernel masks the BAR it would expect to find the size of the
	 * BAR there next time it reads from it. When the kernel got the size it
	 * would write the address back.
	 */
	if (bar < 6) {
		/*
		 * According to the PCI local bus specification REV 3.0:
		 * The number of upper bits that a device actually implements
		 * depends on how much of the address space the device will
		 * respond to. A device that wants a 1 MB memory address space
		 * (using a 32-bit base address register) would build the top
		 * 12 bits of the address register, hardwiring the other bits
		 * to 0.
		 * Furthermore software can determine how much address space the
		 * device requires by writing a value of all 1's to the register
		 * and then reading the value back. The device will return 0's in
		 * all don't-care address bits, effectively specifying the address
		 * space required.
		 *
		 * The following code emulates this by storing the value written
		 * to the BAR, applying the size mask to clear the lower bits,
		 * restoring the information bits and then updating the BAR value.
		 */
		u32 bar_value;
		u32 info = pci_hdr->bar[bar] & 0xF;	/* Extract the info bits */


		/* Store the value written by software */
		memcpy(base + offset, data, size);

		/* Apply the size mask to the bar value to clear the lower bits */
		bar_value = pci_hdr->bar[bar] & ~(pci_hdr->bar_size[bar] - 1);

		/* Warn if the bar size is not a power of 2 */
		WARN_ON(!is_power_of_2(pci_hdr->bar_size[bar]));

		/* Restore the info bits */
		if ((info & 0x1) == 0x1) {
			/* BAR for I/O */
			bar_value = ((bar_value & ~0x3) | 0x1);
		} else {
			/* BAR for Memory */
			bar_value = ((bar_value & ~0xF) | info);
		}

		/* Store the final BAR value */
		pci_hdr->bar[bar] = bar_value;
	} else {
		memcpy(base + offset, data, size);
	}

unlock_device:
	up_write(&pci_hdr->device_lock);
}

void pci__config_rd(struct kvm *kvm, union pci_config_address addr, void *data, int size)
{
	u8 offset;
	struct pci_device_header *pci_hdr;
	u8 dev_num = addr.device_number;

	if (pci_device_exists(addr.bus_number, dev_num, 0)) {
		pci_hdr = device__find_dev(DEVICE_BUS_PCI, dev_num)->data;
		offset = addr.w & PCI_DEV_CFG_MASK;

		down_read(&pci_hdr->device_lock);
		if (pci_hdr->cfg_ops.read)
			pci_hdr->cfg_ops.read(kvm, pci_hdr, offset, data, size);

		memcpy(data, (void *)pci_hdr + offset, size);
		up_read(&pci_hdr->device_lock);
	} else {
		memset(data, 0xff, size);
	}
}

static void pci_config_mmio_access(struct kvm_cpu *vcpu, u64 addr, u8 *data,
				   u32 len, u8 is_write, void *kvm)
{
	union pci_config_address cfg_addr;

	addr			-= KVM_PCI_CFG_AREA;
	cfg_addr.w		= (u32)addr;
	cfg_addr.enable_bit	= 1;

	if (is_write)
		pci__config_wr(kvm, cfg_addr, data, len);
	else
		pci__config_rd(kvm, cfg_addr, data, len);
}

struct pci_device_header *pci__find_dev(u8 dev_num)
{
	struct device_header *hdr = device__find_dev(DEVICE_BUS_PCI, dev_num);

	if (IS_ERR_OR_NULL(hdr))
		return NULL;

	return hdr->data;
}

int pci__init(struct kvm *kvm)
{
	int r;

	r = ioport__register(kvm, PCI_CONFIG_DATA + 0, &pci_config_data_ops, 4, NULL);
	if (r < 0)
		return r;

	r = ioport__register(kvm, PCI_CONFIG_ADDRESS + 0, &pci_config_address_ops, 4, NULL);
	if (r < 0)
		goto err_unregister_data;

	r = kvm__register_mmio(kvm, KVM_PCI_CFG_AREA, PCI_CFG_SIZE, false,
			       pci_config_mmio_access, kvm);
	if (r < 0)
		goto err_unregister_addr;

	return 0;

err_unregister_addr:
	ioport__unregister(kvm, PCI_CONFIG_ADDRESS);
err_unregister_data:
	ioport__unregister(kvm, PCI_CONFIG_DATA);
	return r;
}
dev_base_init(pci__init);

int pci__exit(struct kvm *kvm)
{
	kvm__deregister_mmio(kvm, KVM_PCI_CFG_AREA);
	ioport__unregister(kvm, PCI_CONFIG_DATA);
	ioport__unregister(kvm, PCI_CONFIG_ADDRESS);

	return 0;
}
dev_base_exit(pci__exit);
