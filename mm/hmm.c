/*
 * Copyright 2013 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 */
/*
 * Refer to include/linux/hmm.h for information about heterogeneous memory
 * management or HMM for short.
 */
#include <linux/mm.h>
#include <linux/hmm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/mmu_notifier.h>


/*
 * struct hmm - HMM per mm struct
 *
 * @mm: mm struct this HMM struct is bound to
 * @lock: lock protecting mirrors list
 * @mirrors: list of mirrors for this mm
 * @wait_queue: wait queue
 * @sequence: we track updates to the CPU page table with a sequence number
 * @mmu_notifier: mmu notifier to track updates to CPU page table
 * @notifier_count: number of currently active notifiers
 */
struct hmm {
	struct mm_struct	*mm;
	spinlock_t		lock;
	struct list_head	ranges;
	struct list_head	mirrors;
	atomic_t		sequence;
	wait_queue_head_t	wait_queue;
	struct mmu_notifier	mmu_notifier;
	atomic_t		notifier_count;
};

/*
 * hmm_register - register HMM against an mm (HMM internal)
 *
 * @mm: mm struct to attach to
 *
 * This is not intended to be used directly by device drivers. It allocates an
 * HMM struct if mm does not have one, and initializes it.
 */
static struct hmm *hmm_register(struct mm_struct *mm)
{
	if (!mm->hmm) {
		struct hmm *hmm = NULL;

		hmm = kmalloc(sizeof(*hmm), GFP_KERNEL);
		if (!hmm)
			return NULL;
		init_waitqueue_head(&hmm->wait_queue);
		atomic_set(&hmm->notifier_count, 0);
		INIT_LIST_HEAD(&hmm->mirrors);
		atomic_set(&hmm->sequence, 0);
		hmm->mmu_notifier.ops = NULL;
		INIT_LIST_HEAD(&hmm->ranges);
		spin_lock_init(&hmm->lock);
		hmm->mm = mm;

		spin_lock(&mm->page_table_lock);
		if (!mm->hmm)
			mm->hmm = hmm;
		else
			kfree(hmm);
		spin_unlock(&mm->page_table_lock);
	}

	/*
	 * The hmm struct can only be freed once the mm_struct goes away,
	 * hence we should always have pre-allocated an new hmm struct
	 * above.
	 */
	return mm->hmm;
}

void hmm_mm_destroy(struct mm_struct *mm)
{
	struct hmm *hmm;

	/*
	 * We should not need to lock here as no one should be able to register
	 * a new HMM while an mm is being destroy. But just to be safe ...
	 */
	spin_lock(&mm->page_table_lock);
	hmm = mm->hmm;
	mm->hmm = NULL;
	spin_unlock(&mm->page_table_lock);
	kfree(hmm);
}


#if IS_ENABLED(CONFIG_HMM_MIRROR)
static void hmm_invalidate_range(struct hmm *hmm,
				 enum hmm_update action,
				 unsigned long start,
				 unsigned long end)
{
	struct hmm_mirror *mirror;
	struct hmm_range *range;

	spin_lock(&hmm->lock);
	list_for_each_entry(range, &hmm->ranges, list) {
		unsigned long addr, idx, npages;

		if (end < range->start || start >= range->end)
			continue;

		range->valid = false;
		addr = max(start, range->start);
		idx = (addr - range->start) >> PAGE_SHIFT;
		npages = (min(range->end, end) - addr) >> PAGE_SHIFT;
		memset(&range->pfns[idx], 0, sizeof(*range->pfns) * npages);
	}
	spin_unlock(&hmm->lock);

	/*
	 * Mirror being added or removed is a rare event so list traversal isn't
	 * protected by a lock, we rely on simple rules. All list modification
	 * are done using list_add_rcu() and list_del_rcu() under a spinlock to
	 * protect from concurrent addition or removal but not traversal.
	 *
	 * Because hmm_mirror_unregister() waits for all running invalidation to
	 * complete (and thus all list traversals to finish), none of the mirror
	 * structs can be freed from under us while traversing the list and thus
	 * it is safe to dereference their list pointer even if they were just
	 * removed.
	 */
	list_for_each_entry (mirror, &hmm->mirrors, list)
		mirror->ops->update(mirror, action, start, end);
}

static void hmm_invalidate_page(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long addr)
{
	unsigned long start = addr & PAGE_MASK;
	unsigned long end = start + PAGE_SIZE;
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->notifier_count);
	atomic_inc(&hmm->sequence);
	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
	atomic_dec(&hmm->notifier_count);
	wake_up(&hmm->wait_queue);
}

static void hmm_invalidate_range_start(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long start,
				       unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->notifier_count);
	atomic_inc(&hmm->sequence);
}

static void hmm_invalidate_range_end(struct mmu_notifier *mn,
				     struct mm_struct *mm,
				     unsigned long start,
				     unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);

	/* Reverse order here because we are getting out of invalidation */
	atomic_dec(&hmm->notifier_count);
	wake_up(&hmm->wait_queue);
}

static const struct mmu_notifier_ops hmm_mmu_notifier_ops = {
	.invalidate_page	= hmm_invalidate_page,
	.invalidate_range_start	= hmm_invalidate_range_start,
	.invalidate_range_end	= hmm_invalidate_range_end,
};

static int hmm_mirror_do_register(struct hmm_mirror *mirror,
				  struct mm_struct *mm,
				  const bool locked)
{
	/* Sanity check */
	if (!mm || !mirror || !mirror->ops)
		return -EINVAL;

	mirror->hmm = hmm_register(mm);
	if (!mirror->hmm)
		return -ENOMEM;

	/* Register mmu_notifier if not already, use mmap_sem for locking */
	if (!mirror->hmm->mmu_notifier.ops) {
		struct hmm *hmm = mirror->hmm;

		if (!locked)
			down_write(&mm->mmap_sem);
		if (!hmm->mmu_notifier.ops) {
			hmm->mmu_notifier.ops = &hmm_mmu_notifier_ops;
			if (__mmu_notifier_register(&hmm->mmu_notifier, mm)) {
				hmm->mmu_notifier.ops = NULL;
				up_write(&mm->mmap_sem);
				return -ENOMEM;
			}
		}
		if (!locked)
			up_write(&mm->mmap_sem);
	}

	spin_lock(&mirror->hmm->lock);
	list_add_rcu(&mirror->list, &mirror->hmm->mirrors);
	spin_unlock(&mirror->hmm->lock);

	return 0;
}

/*
 * hmm_mirror_register() - register a mirror against an mm
 *
 * @mirror: new mirror struct to register
 * @mm: mm to register against
 *
 * To start mirroring a process address space, the device driver must register
 * an HMM mirror struct.
 */
int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm)
{
	return hmm_mirror_do_register(mirror, mm, false);
}
EXPORT_SYMBOL(hmm_mirror_register);

/*
 * hmm_mirror_register_locked() - register a mirror against an mm
 *
 * @mirror: new mirror struct to register
 * @mm: mm to register against
 *
 * Same as hmm_mirror_register() except that mmap_sem must be held for writing.
 */
int hmm_mirror_register_locked(struct hmm_mirror *mirror, struct mm_struct *mm)
{
	return hmm_mirror_do_register(mirror, mm, true);
}
EXPORT_SYMBOL(hmm_mirror_register_locked);

/*
 * hmm_mirror_unregister() - unregister a mirror
 *
 * @mirror: new mirror struct to register
 *
 * Stop mirroring a process address space, and cleanup.
 */
void hmm_mirror_unregister(struct hmm_mirror *mirror)
{
	struct hmm *hmm = mirror->hmm;

	spin_lock(&hmm->lock);
	list_del_rcu(&mirror->list);
	spin_unlock(&hmm->lock);

	/*
	 * Wait for all active notifiers so that it is safe to traverse the
	 * mirror list without holding any locks.
	 */
	wait_event(hmm->wait_queue, !atomic_read(&hmm->notifier_count));
}
EXPORT_SYMBOL(hmm_mirror_unregister);


static void hmm_pfns_error(hmm_pfn_t *pfns,
			   unsigned long addr,
			   unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_ERROR;
}

static void hmm_pfns_empty(hmm_pfn_t *pfns,
			   unsigned long addr,
			   unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_EMPTY;
}

static void hmm_pfns_special(hmm_pfn_t *pfns,
			     unsigned long addr,
			     unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_SPECIAL;
}

static void hmm_pfns_clear(hmm_pfn_t *pfns,
			   unsigned long addr,
			   unsigned long end)
{
	unsigned long npfns = (end - addr) >> PAGE_SHIFT;

	memset(pfns, 0, sizeof(*pfns) * npfns);
}

static int hmm_vma_do_fault(struct vm_area_struct *vma,
			    const hmm_pfn_t fault,
			    unsigned long addr,
			    hmm_pfn_t *pfn,
			    bool block)
{
	unsigned flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_REMOTE;
	int r;

	flags |= block ? 0 : FAULT_FLAG_ALLOW_RETRY;
	flags |= (fault & HMM_PFN_WRITE) ? FAULT_FLAG_WRITE : 0;
	r = handle_mm_fault(vma, addr, flags);
	if (r & VM_FAULT_RETRY)
		return -EAGAIN;
	if (r & VM_FAULT_ERROR) {
		*pfn = HMM_PFN_ERROR;
		return -EFAULT;
	}

	return 0;
}

static int hmm_vma_walk(struct vm_area_struct *vma,
			const hmm_pfn_t fault,
			unsigned long start,
			unsigned long end,
			hmm_pfn_t *pfns,
			bool block)
{
	unsigned long addr, next;
	hmm_pfn_t flag;

	flag = vma->vm_flags & VM_READ ? HMM_PFN_READ : 0;

	for (addr = start; addr < end; addr = next) {
		unsigned long i = (addr - start) >> PAGE_SHIFT;
		pgd_t *pgdp;
		pud_t *pudp;
		pmd_t *pmdp;
		pte_t *ptep;
		pmd_t pmd;
		int ret;

		/*
		 * We are accessing/faulting for a device from an unknown
		 * thread that might be foreign to the mm we are faulting
		 * against so do not call arch_vma_access_permitted() !
		 */

		next = pgd_addr_end(addr, end);
		pgdp = pgd_offset(vma->vm_mm, addr);
		if (pgd_none(*pgdp) || pgd_bad(*pgdp)) {
			if (!(vma->vm_flags & VM_READ)) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			if (!fault) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			pudp = pud_alloc(vma->vm_mm, pgdp, addr);
			if (!pudp) {
				hmm_pfns_error(&pfns[i], addr, next);
				continue;
			}
		}

		next = pud_addr_end(addr, end);
		pudp = pud_offset(pgdp, addr);
		if (pud_none(*pudp) || pud_bad(*pudp)) {
			if (!(vma->vm_flags & VM_READ)) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			if (!fault) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			pmdp = pmd_alloc(vma->vm_mm, pudp, addr);
			if (!pmdp) {
				hmm_pfns_error(&pfns[i], addr, next);
				continue;
			}
		}

		next = pmd_addr_end(addr, end);
		pmdp = pmd_offset(pudp, addr);
		pmd = pmd_read_atomic(pmdp);
		barrier();
		if (pmd_none(pmd) || pmd_bad(pmd)) {
			if (!(vma->vm_flags & VM_READ)) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			if (!fault) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			/*
			 * Use pte_alloc() instead of pte_alloc_map, because we
			 * can't run pte_offset_map on the pmd, if a huge pmd
			 * could materialize from under us.
			 */
			if (unlikely(pte_alloc(vma->vm_mm, pmdp, addr))) {
				hmm_pfns_error(&pfns[i], addr, next);
				continue;
			}
			pmd = *pmdp;
		}
		if (pmd_trans_huge(pmd) || pmd_devmap(pmd)) {
			unsigned long pfn = pmd_pfn(pmd) + pte_index(addr);
			hmm_pfn_t flags = flag;

			if (pmd_protnone(pmd)) {
				hmm_pfns_clear(&pfns[i], addr, next);
				if (fault)
					goto fault;
				continue;
			}
			flags |= pmd_write(*pmdp) ? HMM_PFN_WRITE : 0;
			flags |= pmd_devmap(pmd) ? HMM_PFN_DEVICE : 0;
			if ((flags & fault) != fault)
				goto fault;
			for (; addr < next; addr += PAGE_SIZE, i++, pfn++)
				pfns[i] = hmm_pfn_from_pfn(pfn) | flags;
			continue;
		}

		ptep = pte_offset_map(pmdp, addr);
		for (; addr < next; addr += PAGE_SIZE, i++, ptep++) {
			swp_entry_t entry;
			pte_t pte = *ptep;

			if (pte_none(pte)) {
				if (fault) {
					pte_unmap(ptep);
					goto fault;
				}
				pfns[i] = HMM_PFN_EMPTY;
				continue;
			}

			entry = pte_to_swp_entry(pte);
			if (!pte_present(pte) && !non_swap_entry(entry)) {
				if (fault) {
					pte_unmap(ptep);
					goto fault;
				}
				pfns[i] = 0;
				continue;
			}

			if (pte_present(pte)) {
				pfns[i] = hmm_pfn_from_pfn(pte_pfn(pte))|flag;
				pfns[i] |= pte_write(pte) ? HMM_PFN_WRITE : 0;
			} else if (is_device_entry(entry)) {
				/* Do not fault device entry */
				pfns[i] = hmm_pfn_from_pfn(swp_offset(entry));
				if (is_write_device_entry(entry))
					pfns[i] |= HMM_PFN_WRITE;
				pfns[i] |= HMM_PFN_DEVICE;
				pfns[i] |= HMM_PFN_UNADDRESSABLE;
				pfns[i] |= flag;
			} else if (is_migration_entry(entry) && fault) {
				migration_entry_wait(vma->vm_mm, pmdp, addr);
				/* Start again for current address */
				next = addr;
				ptep++;
				break;
			} else {
				/* Report error for everything else */
				pfns[i] = HMM_PFN_ERROR;
			}
			if ((fault & pfns[i]) != fault) {
				pte_unmap(ptep);
				goto fault;
			}
		}
		pte_unmap(ptep - 1);
		continue;

fault:
		ret = hmm_vma_do_fault(vma, fault, addr, &pfns[i], block);
		if (ret)
			return ret;
		/* Start again for current address */
		next = addr;
	}

	return 0;
}

/*
 * hmm_vma_get_pfns() - snapshot CPU page table for a range of virtual address
 * @vma: virtual memory area containing the virtual address range
 * @range: use to track snapshot validity
 * @start: range virtual start address (inclusive)
 * @end: range virtual end address (exclusive)
 * @entries: array of hmm_pfn_t provided by caller fill by function
 * Returns: -EINVAL if invalid argument, -ENOMEM out of memory, 0 success
 *
 * This snapshot the CPU page table for a range of virtual address, snapshot
 * validity is track by the range struct see hmm_vma_range_done() for further
 * informations.
 *
 * The range struct is initialized and track CPU page table only if function
 * returns success (0) then you must call hmm_vma_range_done() to stop range
 * CPU page table update tracking.
 *
 * NOT CALLING hmm_vma_range_done() IF FUNCTION RETURNS 0 WILL LEAD TO SERIOUS
 * MEMORY CORRUPTION ! YOU HAVE BEEN WARN !
 */
int hmm_vma_get_pfns(struct vm_area_struct *vma,
		     struct hmm_range *range,
		     unsigned long start,
		     unsigned long end,
		     hmm_pfn_t *pfns)
{
	struct hmm *hmm;

	/* FIXME support hugetlb fs */
	if (is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_SPECIAL)) {
		hmm_pfns_special(pfns, start, end);
		return -EINVAL;
	}

	/* Sanity check, this really should not happen ! */
	if (start < vma->vm_start || start >= vma->vm_end)
		return -EINVAL;
	if (end < vma->vm_start || end > vma->vm_end)
		return -EINVAL;

	hmm = hmm_register(vma->vm_mm);
	if (!hmm)
		return -ENOMEM;
	/* Caller must have register a mirror (with hmm_mirror_register()) ! */
	if (!hmm->mmu_notifier.ops)
		return -EINVAL;

	/* Initialize range to track CPU page table update */
	range->start = start;
	range->pfns = pfns;
	range->end = end;
	spin_lock(&hmm->lock);
	range->valid = true;
	list_add_rcu(&range->list, &hmm->ranges);
	spin_unlock(&hmm->lock);

	hmm_vma_walk(vma, 0, start, end, pfns, false);
	return 0;
}
EXPORT_SYMBOL(hmm_vma_get_pfns);

/*
 * hmm_vma_range_done() - stop tracking change to CPU page table over a range
 * @vma: virtual memory area containing the virtual address range
 * @range: range being track
 * Returns: false if range data have been invalidated, true otherwise
 *
 * Range struct is use to track update to CPU page table after call to either
 * hmm_vma_get_pfns() or hmm_vma_fault(). Once device driver is done using or
 * want to lock update to data it gots from those functions it must call the
 * hmm_vma_range_done() function which stop tracking CPU page table update.
 *
 * Note that device driver must still implement general CPU page table update
 * tracking either by using hmm_mirror (see hmm_mirror_register()) or by using
 * mmu_notifier API directly.
 *
 * CPU page table update tracking done through hmm_range is only temporary and
 * to be use while trying to duplicate CPU page table content for a range of
 * virtual address.
 *
 * There is 2 way to use this :
 * again:
 *   hmm_vma_get_pfns(vma, range, start, end, pfns); or hmm_vma_fault(...);
 *   trans = device_build_page_table_update_transaction(pfns);
 *   device_page_table_lock();
 *   if (!hmm_vma_range_done(vma, range)) {
 *     device_page_table_unlock();
 *     goto again;
 *   }
 *   device_commit_transaction(trans);
 *   device_page_table_unlock();
 *
 * Or:
 *   hmm_vma_get_pfns(vma, range, start, end, pfns); or hmm_vma_fault(...);
 *   device_page_table_lock();
 *   hmm_vma_range_done(vma, range);
 *   device_update_page_table(pfns);
 *   device_page_table_unlock();
 */
bool hmm_vma_range_done(struct vm_area_struct *vma, struct hmm_range *range)
{
	unsigned long npages = (range->end - range->start) >> PAGE_SHIFT;
	struct hmm *hmm;

	if (range->end <= range->start) {
		BUG();
		return false;
	}

	hmm = hmm_register(vma->vm_mm);
	if (!hmm) {
		memset(range->pfns, 0, sizeof(*range->pfns) * npages);
		return false;
	}

	spin_lock(&hmm->lock);
	list_del_rcu(&range->list);
	spin_unlock(&hmm->lock);

	return range->valid;
}
EXPORT_SYMBOL(hmm_vma_range_done);

/*
 * hmm_vma_fault() - try to fault some address in a virtual address range
 * @vma: virtual memory area containing the virtual address range
 * @range: use to track pfns array content validity
 * @start: fault range virtual start address (inclusive)
 * @end: fault range virtual end address (exclusive)
 * @pfns: array of hmm_pfn_t, only entry with fault flag set will be faulted
 * @write: is it a write fault
 * @block: allow blocking on fault (if true it sleeps and do not drop mmap_sem)
 * Returns: 0 success, error otherwise (-EAGAIN means mmap_sem have been drop)
 *
 * This is similar to a regular CPU page fault except that it will not trigger
 * any memory migration if the memory being faulted is not accessible by CPUs.
 *
 * On error, for one virtual address in the range, the function will set the
 * hmm_pfn_t error flag for the corresponding pfn entry.
 *
 * Expected use pattern:
 * retry:
 *   down_read(&mm->mmap_sem);
 *   // Find vma and address device wants to fault, initialize hmm_pfn_t
 *   // array accordingly
 *   ret = hmm_vma_fault(vma, start, end, pfns, allow_retry);
 *   switch (ret) {
 *   case -EAGAIN:
 *     hmm_vma_range_done(vma, range);
 *     // You might want to rate limit or yield to play nicely, you may
 *     // also commit any valid pfn in the array assuming that you are
 *     // getting true from hmm_vma_range_monitor_end()
 *     goto retry;
 *   case 0:
 *     break;
 *   default:
 *     // Handle error !
 *     up_read(&mm->mmap_sem)
 *     return;
 *   }
 *   // Take device driver lock that serialize device page table update
 *   driver_lock_device_page_table_update();
 *   hmm_vma_range_done(vma, range);
 *   // Commit pfns we got from hmm_vma_fault()
 *   driver_unlock_device_page_table_update();
 *   up_read(&mm->mmap_sem)
 *
 * YOU MUST CALL hmm_vma_range_done() AFTER THIS FUNCTION RETURN SUCCESS (0)
 * BEFORE FREEING THE range struct OR YOU WILL HAVE SERIOUS MEMORY CORRUPTION !
 *
 * YOU HAVE BEEN WARN !
 */
int hmm_vma_fault(struct vm_area_struct *vma,
		  struct hmm_range *range,
		  unsigned long start,
		  unsigned long end,
		  hmm_pfn_t *pfns,
		  bool write,
		  bool block)
{
	hmm_pfn_t fault = HMM_PFN_READ | (write ? HMM_PFN_WRITE : 0);
	struct hmm *hmm;
	int ret;

	/* Sanity check, this really should not happen ! */
	if (start < vma->vm_start || start >= vma->vm_end)
		return -EINVAL;
	if (end < vma->vm_start || end > vma->vm_end)
		return -EINVAL;

	hmm = hmm_register(vma->vm_mm);
	if (!hmm) {
		hmm_pfns_clear(pfns, start, end);
		return -ENOMEM;
	}
	/* Caller must have registered a mirror using hmm_mirror_register() */
	if (!hmm->mmu_notifier.ops)
		return -EINVAL;

	/* Initialize range to track CPU page table update */
	range->start = start;
	range->pfns = pfns;
	range->end = end;
	spin_lock(&hmm->lock);
	range->valid = true;
	list_add_rcu(&range->list, &hmm->ranges);
	spin_unlock(&hmm->lock);

	/* FIXME support hugetlb fs */
	if (is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_SPECIAL)) {
		hmm_pfns_special(pfns, start, end);
		return 0;
	}

	ret = hmm_vma_walk(vma, fault, start, end, pfns, block);
	if (ret)
		hmm_vma_range_done(vma, range);
	return ret;
}
EXPORT_SYMBOL(hmm_vma_fault);
#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */
