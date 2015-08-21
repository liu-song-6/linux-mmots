#ifndef LINUX_MM_CONFIG_H_INCLUDED
#define LINUX_MM_CONFIG_H_INCLUDED

/*
 * mm-config.h is the place where new mm-related #defines are calculated from
 * Kconfig variables.  And related activities, perhaps.
 */

#define USE_SPLIT_PTE_PTLOCKS	(CONFIG_NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS)
#define USE_SPLIT_PMD_PTLOCKS	(USE_SPLIT_PTE_PTLOCKS && \
		IS_ENABLED(CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK))
#define ALLOC_SPLIT_PTLOCKS	(SPINLOCK_SIZE > BITS_PER_LONG/8)

#if USE_SPLIT_PTE_PTLOCKS && defined(CONFIG_MMU)
#define SPLIT_RSS_COUNTING
#endif

#endif		/* LINUX_MM_CONFIG_H_INCLUDED */
