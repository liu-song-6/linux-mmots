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
 * HMM provides 3 separate types of functionality:
 *   - Mirroring: synchronize CPU page table and device page table
 *   - Device memory: allocating struct pages for device memory
 *   - Migration: migrating regular memory to device memory
 *
 * Each can be used independently from the others.
 *
 *
 * Mirroring:
 *
 * HMM provides helpers to mirror a process address space on a device. For this,
 * it provides several helpers to order device page table updates with respect
 * to CPU page table updates. The requirement is that for any given virtual
 * address the CPU and device page table cannot point to different physical
 * pages. It uses the mmu_notifier API behind the scenes.
 *
 * Device memory:
 *
 * HMM provides helpers to help leverage device memory. Device memory is, at any
 * given time, either CPU-addressable like regular memory, or completely
 * unaddressable. In both cases the device memory is associated with dedicated
 * struct pages (which are allocated as if for hotplugged memory). Device memory
 * management is under the responsibility of the device driver. HMM only
 * allocates and initializes the struct pages associated with the device memory,
 * by hotplugging a ZONE_DEVICE memory range.
 *
 * Allocating struct pages for device memory allows us to use device memory
 * almost like regular CPU memory. Unlike regular memory, however, it cannot be
 * added to the lru, nor can any memory allocation can use device memory
 * directly. Device memory will only end up in use by a process if the device
 * driver migrates some of the process memory from regular memory to device
 * memory.
 *
 * Migration:
 *
 * The existing memory migration mechanism (mm/migrate.c) does not allow using
 * anything other than the CPU to copy from source to destination memory.
 * Moreover, existing code does not provide a way to migrate based on a virtual
 * address range. Existing code only supports struct-page-based migration. Also,
 * the migration flow does not allow for graceful failure at intermediate stages
 * of the migration process.
 *
 * HMM solves all of the above, by providing a simple API:
 *
 *      hmm_vma_migrate(ops, vma, src_pfns, dst_pfns, start, end, private);
 *
 * finalize_and_map(). The first,  alloc_and_copy(), allocates the destination
 * memory and initializes it using source memory. Migration can fail at this
 * point, and the device driver then has a place to abort the migration. The
 * finalize_and_map() callback allows the device driver to know which pages
 * were successfully migrated and which were not.
 *
 * This can easily be used outside of the original HMM use case.
 *
 *
 * This header file contain all the APIs related to hmm_vma_migrate. Additional
 * detailed documentation may be found below.
 */
#ifndef LINUX_HMM_H
#define LINUX_HMM_H

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_HMM)

struct hmm;

/*
 * hmm_pfn_t - HMM use its own pfn type to keep several flags per page
 *
 * Flags:
 * HMM_PFN_VALID: pfn is valid
 * HMM_PFN_WRITE: CPU page table have the write permission set
 */
typedef unsigned long hmm_pfn_t;

#define HMM_PFN_VALID (1 << 0)
#define HMM_PFN_WRITE (1 << 1)
#define HMM_PFN_SHIFT 2

/*
 * hmm_pfn_to_page() - return struct page pointed to by a valid hmm_pfn_t
 * @pfn: hmm_pfn_t to convert to struct page
 * Returns: struct page pointer if pfn is a valid hmm_pfn_t, NULL otherwise
 *
 * If the hmm_pfn_t is valid (ie valid flag set) then return the struct page
 * matching the pfn value store in the hmm_pfn_t. Otherwise return NULL.
 */
static inline struct page *hmm_pfn_to_page(hmm_pfn_t pfn)
{
	if (!(pfn & HMM_PFN_VALID))
		return NULL;
	return pfn_to_page(pfn >> HMM_PFN_SHIFT);
}

/*
 * hmm_pfn_to_pfn() - return pfn value store in a hmm_pfn_t
 * @pfn: hmm_pfn_t to extract pfn from
 * Returns: pfn value if hmm_pfn_t is valid, -1UL otherwise
 */
static inline unsigned long hmm_pfn_to_pfn(hmm_pfn_t pfn)
{
	if (!(pfn & HMM_PFN_VALID))
		return -1UL;
	return (pfn >> HMM_PFN_SHIFT);
}

/*
 * hmm_pfn_from_page() - create a valid hmm_pfn_t value from struct page
 * @page: struct page pointer for which to create the hmm_pfn_t
 * Returns: valid hmm_pfn_t for the page
 */
static inline hmm_pfn_t hmm_pfn_from_page(struct page *page)
{
	return (page_to_pfn(page) << HMM_PFN_SHIFT) | HMM_PFN_VALID;
}

/*
 * hmm_pfn_from_pfn() - create a valid hmm_pfn_t value from pfn
 * @pfn: pfn value for which to create the hmm_pfn_t
 * Returns: valid hmm_pfn_t for the pfn
 */
static inline hmm_pfn_t hmm_pfn_from_pfn(unsigned long pfn)
{
	return (pfn << HMM_PFN_SHIFT) | HMM_PFN_VALID;
}


#if IS_ENABLED(CONFIG_HMM_MIRROR)
/*
 * Mirroring: how to use synchronize device page table with CPU page table ?
 *
 * Device driver must always synchronize with CPU page table update, for this
 * they can either directly use mmu_notifier API or they can use the hmm_mirror
 * API. Device driver can decide to register one mirror per device per process
 * or just one mirror per process for a group of device. Pattern is:
 *
 *      int device_bind_address_space(..., struct mm_struct *mm, ...)
 *      {
 *          struct device_address_space *das;
 *          int ret;
 *          // Device driver specific initialization, and allocation of das
 *          // which contain an hmm_mirror struct as one of its field.
 *          ret = hmm_mirror_register(&das->mirror, mm, &device_mirror_ops);
 *          if (ret) {
 *              // Cleanup on error
 *              return ret;
 *          }
 *          // Other device driver specific initialization
 *      }
 *
 * Device driver must not free the struct containing hmm_mirror struct before
 * calling hmm_mirror_unregister() expected usage is to do that when device
 * driver is unbinding from an address space.
 *
 *      void device_unbind_address_space(struct device_address_space *das)
 *      {
 *          // Device driver specific cleanup
 *          hmm_mirror_unregister(&das->mirror);
 *          // Other device driver specific cleanup and now das can be free
 *      }
 *
 * Once an hmm_mirror is registered for an address space, device driver will get
 * callbacks through the update() operation (see hmm_mirror_ops struct).
 */

struct hmm_mirror;

/*
 * enum hmm_update - type of update
 * @HMM_UPDATE_INVALIDATE: invalidate range (no indication as to why)
 */
enum hmm_update {
	HMM_UPDATE_INVALIDATE,
};

/*
 * struct hmm_mirror_ops - HMM mirror device operations callback
 *
 * @update: callback to update range on a device
 */
struct hmm_mirror_ops {
	/* update() - update virtual address range of memory
	 *
	 * @mirror: pointer to struct hmm_mirror
	 * @update: update's type (turn read only, unmap, ...)
	 * @start: virtual start address of the range to update
	 * @end: virtual end address of the range to update
	 *
	 * This callback is call when the CPU page table is updated, the device
	 * driver must update device page table accordingly to update's action.
	 *
	 * Device driver callback must wait until the device has fully updated
	 * its view for the range. Note we plan to make this asynchronous in
	 * later patches, so that multiple devices can schedule update to their
	 * page tables, and once all device have schedule the update then we
	 * wait for them to propagate.
	 */
	void (*update)(struct hmm_mirror *mirror,
		       enum hmm_update action,
		       unsigned long start,
		       unsigned long end);
};

/*
 * struct hmm_mirror - mirror struct for a device driver
 *
 * @hmm: pointer to struct hmm (which is unique per mm_struct)
 * @ops: device driver callback for HMM mirror operations
 * @list: for list of mirrors of a given mm
 *
 * Each address space (mm_struct) being mirrored by a device must register one
 * of hmm_mirror struct with HMM. HMM will track list of all mirrors for each
 * mm_struct (or each process).
 */
struct hmm_mirror {
	struct hmm			*hmm;
	const struct hmm_mirror_ops	*ops;
	struct list_head		list;
};

int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm);
int hmm_mirror_register_locked(struct hmm_mirror *mirror,
			       struct mm_struct *mm);
void hmm_mirror_unregister(struct hmm_mirror *mirror);
#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */


/* Below are for HMM internal use only! Not to be used by device driver! */
void hmm_mm_destroy(struct mm_struct *mm);

#else /* IS_ENABLED(CONFIG_HMM) */

/* Below are for HMM internal use only! Not to be used by device driver! */
static inline void hmm_mm_destroy(struct mm_struct *mm) {}

#endif /* IS_ENABLED(CONFIG_HMM) */
#endif /* LINUX_HMM_H */
