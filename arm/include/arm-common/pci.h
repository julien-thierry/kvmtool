#ifndef ARM_COMMON__PCI_H
#define ARM_COMMON__PCI_H

void pci__arm_init(struct kvm *kvm);
void pci__generate_fdt_nodes(void *fdt);

#endif /* ARM_COMMON__PCI_H */
