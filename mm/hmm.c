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
#include <linux/slab.h>
#include <linux/sched.h>
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
#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */
