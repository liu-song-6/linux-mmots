#ifndef _LINUX_MIGRATE_H
#define _LINUX_MIGRATE_H

#include <linux/mm.h>
#include <linux/mempolicy.h>
#include <linux/migrate_mode.h>

typedef struct page *new_page_t(struct page *page, unsigned long private,
				int **reason);
typedef void free_page_t(struct page *page, unsigned long private);

/*
 * Return values from addresss_space_operations.migratepage():
 * - negative errno on page migration failure;
 * - zero on page migration success;
 */
#define MIGRATEPAGE_SUCCESS		0

enum migrate_reason {
	MR_COMPACTION,
	MR_MEMORY_FAILURE,
	MR_MEMORY_HOTPLUG,
	MR_SYSCALL,		/* also applies to cpusets */
	MR_MEMPOLICY_MBIND,
	MR_NUMA_MISPLACED,
	MR_CMA,
	MR_TYPES
};

/* In mm/debug.c; also keep sync with include/trace/events/migrate.h */
extern char *migrate_reason_names[MR_TYPES];

#ifdef CONFIG_MIGRATION

extern void putback_movable_pages(struct list_head *l);
extern int migrate_page(struct address_space *mapping,
			struct page *newpage,
			struct page *page,
			enum migrate_mode,
			bool copy);
extern int migrate_pages(struct list_head *l, new_page_t new, free_page_t free,
		unsigned long private, enum migrate_mode mode, int reason);
extern int isolate_movable_page(struct page *page, isolate_mode_t mode);
extern void putback_movable_page(struct page *page);

extern int migrate_prep(void);
extern int migrate_prep_local(void);
extern void migrate_page_copy(struct page *newpage, struct page *page);
extern int migrate_huge_page_move_mapping(struct address_space *mapping,
				  struct page *newpage, struct page *page);
extern int migrate_page_move_mapping(struct address_space *mapping,
		struct page *newpage, struct page *page,
		struct buffer_head *head, enum migrate_mode mode,
		int extra_count);
#else

static inline void putback_movable_pages(struct list_head *l) {}
static inline int migrate_pages(struct list_head *l, new_page_t new,
		free_page_t free, unsigned long private, enum migrate_mode mode,
		int reason)
	{ return -ENOSYS; }
static inline int isolate_movable_page(struct page *page, isolate_mode_t mode)
	{ return -EBUSY; }

static inline int migrate_prep(void) { return -ENOSYS; }
static inline int migrate_prep_local(void) { return -ENOSYS; }

static inline void migrate_page_copy(struct page *newpage,
				     struct page *page) {}

static inline int migrate_huge_page_move_mapping(struct address_space *mapping,
				  struct page *newpage, struct page *page)
{
	return -ENOSYS;
}

#endif /* CONFIG_MIGRATION */

#ifdef CONFIG_COMPACTION
extern int PageMovable(struct page *page);
extern void __SetPageMovable(struct page *page, struct address_space *mapping);
extern void __ClearPageMovable(struct page *page);
#else
static inline int PageMovable(struct page *page) { return 0; };
static inline void __SetPageMovable(struct page *page,
				struct address_space *mapping)
{
}
static inline void __ClearPageMovable(struct page *page)
{
}
#endif

#ifdef CONFIG_NUMA_BALANCING
extern bool pmd_trans_migrating(pmd_t pmd);
extern int migrate_misplaced_page(struct page *page,
				  struct vm_area_struct *vma, int node);
#else
static inline bool pmd_trans_migrating(pmd_t pmd)
{
	return false;
}
static inline int migrate_misplaced_page(struct page *page,
					 struct vm_area_struct *vma, int node)
{
	return -EAGAIN; /* can't migrate now */
}
#endif /* CONFIG_NUMA_BALANCING */

#if defined(CONFIG_NUMA_BALANCING) && defined(CONFIG_TRANSPARENT_HUGEPAGE)
extern int migrate_misplaced_transhuge_page(struct mm_struct *mm,
			struct vm_area_struct *vma,
			pmd_t *pmd, pmd_t entry,
			unsigned long address,
			struct page *page, int node);
#else
static inline int migrate_misplaced_transhuge_page(struct mm_struct *mm,
			struct vm_area_struct *vma,
			pmd_t *pmd, pmd_t entry,
			unsigned long address,
			struct page *page, int node)
{
	return -EAGAIN;
}
#endif /* CONFIG_NUMA_BALANCING && CONFIG_TRANSPARENT_HUGEPAGE*/


#define MIGRATE_PFN_VALID	(1UL << (BITS_PER_LONG_LONG - 1))
#define MIGRATE_PFN_MIGRATE	(1UL << (BITS_PER_LONG_LONG - 2))
#define MIGRATE_PFN_HUGE	(1UL << (BITS_PER_LONG_LONG - 3))
#define MIGRATE_PFN_LOCKED	(1UL << (BITS_PER_LONG_LONG - 4))
#define MIGRATE_PFN_WRITE	(1UL << (BITS_PER_LONG_LONG - 5))
#define MIGRATE_PFN_DEVICE	(1UL << (BITS_PER_LONG_LONG - 6))
#define MIGRATE_PFN_ERROR	(1UL << (BITS_PER_LONG_LONG - 7))
#define MIGRATE_PFN_MASK	((1UL << (BITS_PER_LONG_LONG - PAGE_SHIFT)) - 1)

static inline struct page *migrate_pfn_to_page(unsigned long mpfn)
{
	if (!(mpfn & MIGRATE_PFN_VALID))
		return NULL;
	return pfn_to_page(mpfn & MIGRATE_PFN_MASK);
}

static inline unsigned long migrate_pfn_size(unsigned long mpfn)
{
	return mpfn & MIGRATE_PFN_HUGE ? PMD_SIZE : PAGE_SIZE;
}

/*
 * struct migrate_vma_ops - migrate operation callback
 *
 * @alloc_and_copy: alloc destination memoiry and copy source to it
 * @finalize_and_map: allow caller to inspect successfull migrated page
 *
 * migrate_vma() allow memory migration to use DMA  engine to perform copy from
 * source to destination memory it also allow caller to use its own memory
 * allocator for destination memory.
 *
 * Note that in alloc_and_copy device driver can decide not to migrate some of
 * the entry by simply setting corresponding dst entry 0.
 *
 * Destination page must locked and MIGRATE_PFN_LOCKED set in the corresponding
 * entry of dstarray. It is expected that page allocated will have an elevated
 * refcount and that a put_page() will free the page.
 *
 * Device driver might want to allocate with an extra-refcount if they want to
 * control deallocation of failed migration inside finalize_and_map() callback.
 *
 * The finalize_and_map() callback must use the MIGRATE_PFN_MIGRATE flag to
 * determine which page have been successfully migrated (it is set in the src
 * array for each entry that have been successfully migrated).
 *
 * For migration from device memory to system memory device driver must set any
 * dst entry to MIGRATE_PFN_ERROR for any entry it can not migrate back due to
 * hardware fatal failure that can not be recovered. Such failure will trigger
 * a SIGBUS for the process trying to access such memory.
 */
struct migrate_vma_ops {
	void (*alloc_and_copy)(struct vm_area_struct *vma,
			       const unsigned long *src,
			       unsigned long *dst,
			       unsigned long start,
			       unsigned long end,
			       void *private);
	void (*finalize_and_map)(struct vm_area_struct *vma,
				 const unsigned long *src,
				 const unsigned long *dst,
				 unsigned long start,
				 unsigned long end,
				 void *private);
};

int migrate_vma(const struct migrate_vma_ops *ops,
		struct vm_area_struct *vma,
		unsigned long mentries,
		unsigned long start,
		unsigned long end,
		unsigned long *src,
		unsigned long *dst,
		void *private);

#endif /* _LINUX_MIGRATE_H */
