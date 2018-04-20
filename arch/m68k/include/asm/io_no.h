/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _M68KNOMMU_IO_H
#define _M68KNOMMU_IO_H

/*
 * Convert a physical memory address into a IO memory address.
 * For us this is trivially a type cast.
 */
#define iomem(a)	((void __iomem *) (a))

/*
 * The non-MMU m68k and ColdFire IO and memory mapped hardware accesses
 * functions have always worked in CPU native endian. We need to preserve
 * that behavior - even though we are using asm-generioc/io.h now.
 * We can rely on asm-generic/io.h for the __raw functions, they are
 * always defined to be CPU native endian. The PCI bus case is a little
 * more complicated - due to it being little-endian.
 */

#if defined(CONFIG_PCI) && defined(CONFIG_COLDFIRE)
/*
 * Support for PCI bus access uses the asm-generic access functions.
 * We need to supply the base address and masks for the normal memory
 * and IO address space mappings.
 */
#include <asm/byteorder.h>
#include <asm/coldfire.h>
#include <asm/mcfsim.h>

#define PCI_MEM_PA	0xf0000000		/* Host physical address */
#define PCI_MEM_BA	0xf0000000		/* Bus physical address */
#define PCI_MEM_SIZE	0x08000000		/* 128 MB */
#define PCI_MEM_MASK	(PCI_MEM_SIZE - 1)

#define PCI_IO_PA	0xf8000000		/* Host physical address */
#define PCI_IO_BA	0x00000000		/* Bus physical address */
#define PCI_IO_SIZE	0x00010000		/* 64k */
#define PCI_IO_MASK	(PCI_IO_SIZE - 1)

#define HAVE_ARCH_PIO_SIZE
#define PIO_OFFSET	0
#define PIO_MASK	0xffff
#define PIO_RESERVED	0x10000
#define PCI_IOBASE	((void __iomem *) PCI_IO_PA)
#define PCI_SPACE_LIMIT	PCI_IO_MASK

/*
 * The ColdFire SoC internal peripherals are mapped into virtual address
 * space using the ACR registers of the cache control unit. This means we
 * are using a 1:1 physical:virtual mapping for them. We can quickly
 * determine if we are accessing an internal peripheral device given the
 * physical or vitrual address using the same range check.
 */
static int __cf_internalio(unsigned long addr)
{
	return (addr >= IOMEMBASE) && (addr <= IOMEMBASE + IOMEMSIZE - 1);
}

static int cf_internalio(const volatile void __iomem *addr)
{
	return __cf_internalio((unsigned long) addr);
}

/*
 * We need these forward declarations here first so that we can use them
 * for our local readw/readl/writew/writel.
 */
static inline u16 __raw_readw(const volatile void __iomem *addr);
static inline u32 __raw_readl(const volatile void __iomem *addr);
static inline void __raw_writew(u16 value, volatile void __iomem *addr);
static inline void __raw_writel(u32 value, volatile void __iomem *addr);

/*
 * We need to treat built-in peripherals and bus based address ranges
 * differently. Local built-in peripherals (and the ColdFire SoC parts
 * have quite a lot of them) are always native endian - which is big
 * endian on m68k/ColdFire. Bus based address ranges, like the PIC bus,
 * are accessed little endian - so we need to byte swap those.
 */
#define readw readw
static inline u16 readw(const volatile void __iomem *addr)
{
	if (cf_internalio(addr))
		return __raw_readw(addr);
	return __le16_to_cpu(__raw_readw(addr));
}

#define readl readl
static inline u32 readl(const volatile void __iomem *addr)
{
	if (cf_internalio(addr))
		return __raw_readl(addr);
	return __le32_to_cpu(__raw_readl(addr));
}

#define writew writew
static inline void writew(u16 value, volatile void __iomem *addr)
{
	if (cf_internalio(addr))
		__raw_writew(value, addr);
	else
		__raw_writew(__cpu_to_le16(value), addr);
}

#define writel writel
static inline void writel(u32 value, volatile void __iomem *addr)
{
	if (cf_internalio(addr))
		__raw_writel(value, addr);
	else
		__raw_writel(__cpu_to_le32(value), addr);
}

#else

/*
 * Preserve CPU native endian ordering for multi-byte IO access.
 * (So we can ignore readb and writeb).
 */
#define readw __raw_readw
#define readl __raw_readl
#define writew __raw_writew
#define writel __raw_writel

#endif /* CONFIG_PCI && CONFIG_COLDFIRE */

#include <asm/kmap.h>
#include <asm/virtconvert.h>
#include <asm-generic/io.h>

#endif /* _M68KNOMMU_IO_H */
