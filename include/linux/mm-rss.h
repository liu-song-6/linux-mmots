#ifndef MM_RSS_H_INCLUDED
#define MM_RSS_H_INCLUDED

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

#endif		/* MM_RSS_H_INCLUDED */
