#ifndef MM_RSS_H_INCLUDED
#define MM_RSS_H_INCLUDED

#include <linux/mm-config.h>
#include <asm-generic/atomic-long.h>

enum {
	MM_FILEPAGES,
	MM_ANONPAGES,
	MM_SWAPENTS,
	NR_MM_COUNTERS
};

struct mm_rss_stat {
	atomic_long_t count[NR_MM_COUNTERS];
};

#ifdef SPLIT_RSS_COUNTING
/* per-thread cached information, */
struct task_rss_stat {
	int events;	/* for synchronization threshold */
	int count[NR_MM_COUNTERS];
};
#endif /* USE_SPLIT_PTE_PTLOCKS */

#endif		/* MM_RSS_H_INCLUDED */
