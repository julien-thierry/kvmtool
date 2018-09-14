#ifndef KVM__REF_CNT_H
#define KVM__REF_CNT_H

#include "kvm/mutex.h"

#ifdef __ATOMIC_ACQUIRE

#define KVM_ATOMIC_ACQUIRE __ATOMIC_ACQUIRE
#define KVM_ATOMIC_RELEASE __ATOMIC_RELEASE

#define kvm_atomic_add_fetch(ptr, val, memorder)	\
	__atomic_add_fetch((ptr), (val), (memorder))

#define kvm_atomic_sub_fetch(ptr, val, memorder)	\
	__atomic_sub_fetch((ptr), (val), (memorder))
#else

#define KVM_ATOMIC_ACQUIRE 0
#define KVM_ATOMIC_RELEASE 0

#define kvm_atomic_add_fetch(ptr, val, memorder)	\
	__sync_fetch_and_add((ptr), (val))

#define kvm_atomic_sub_fetch(ptr, val, memorder)	\
	__sync_fetch_and_sub((ptr), (val))

#endif

struct ref_cnt {
	int cnt;
};

#define REF_CNT_INIT (struct ref_cnt) { .cnt = 1 }

static inline void ref_cnt_init(struct ref_cnt *ref_cnt)
{
	ref_cnt->cnt = 1;
}

static inline void ref_get(struct ref_cnt *ref_cnt)
{
	kvm_atomic_add_fetch(&ref_cnt->cnt, 1, KVM_ATOMIC_ACQUIRE);

}

static inline void ref_put(struct ref_cnt *ref_cnt,
			   void (*release)(struct ref_cnt *ref_cnt))
{
	if (!kvm_atomic_sub_fetch(&ref_cnt->cnt, 1, KVM_ATOMIC_RELEASE))
		release(ref_cnt);
}

#endif /* KVM__REF_CNT_H */
