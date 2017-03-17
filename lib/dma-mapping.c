#include <linux/dma-mapping.h>
#include <linux/module.h>

void *dma_alloc_attrs(struct device *dev, size_t size,
		      dma_addr_t *dma_handle, gfp_t flag,
		      unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	void *cpu_addr;

	BUG_ON(!ops);

	if (dma_alloc_from_coherent(dev, size, dma_handle, &cpu_addr))
		return cpu_addr;

	if (!arch_dma_alloc_attrs(&dev, &flag))
		return NULL;
	if (!ops->alloc)
		return NULL;

	cpu_addr = ops->alloc(dev, size, dma_handle, flag, attrs);
	debug_dma_alloc_coherent(dev, size, *dma_handle, cpu_addr);
	return cpu_addr;
}

EXPORT_SYMBOL(dma_alloc_attrs);

void dma_free_attrs(struct device *dev, size_t size,
		    void *cpu_addr, dma_addr_t dma_handle,
		    unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!ops);
	WARN_ON(irqs_disabled());

	if (dma_release_from_coherent(dev, get_order(size), cpu_addr))
		return;

	if (!ops->free || !cpu_addr)
		return;

	debug_dma_free_coherent(dev, size, cpu_addr, dma_handle);
	ops->free(dev, size, cpu_addr, dma_handle, attrs);
}

EXPORT_SYMBOL(dma_free_attrs);
