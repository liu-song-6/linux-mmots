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


/* Below are for HMM internal use only! Not to be used by device driver! */
void hmm_mm_destroy(struct mm_struct *mm);

#else /* IS_ENABLED(CONFIG_HMM) */

/* Below are for HMM internal use only! Not to be used by device driver! */
static inline void hmm_mm_destroy(struct mm_struct *mm) {}

#endif /* IS_ENABLED(CONFIG_HMM) */
#endif /* LINUX_HMM_H */
