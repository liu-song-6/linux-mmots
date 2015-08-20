#ifndef PAGE_FRAG_H_INCLUDED
#define PAGE_FRAG_H_INCLUDED

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm-generic/getorder.h>

struct page;

struct page_frag {
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	__u32 offset;
	__u32 size;
#else
	__u16 offset;
	__u16 size;
#endif
};

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

struct page_frag_cache {
	void *va;
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size;
#else
	__u32 offset;
#endif
	/* we maintain a pagecount bias, so that we dont dirty cache line
	 * containing page->_count every time we allocate a fragment.
	 */
	unsigned int		pagecnt_bias;
	bool pfmemalloc;
};

#endif		/* PAGE_FRAG_H_INCLUDED */
