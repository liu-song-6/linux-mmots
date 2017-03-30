/* See atomic-instrumented.h for explanation. */
#ifndef _LINUX_BITOPS_INSTRUMENTED_H
#define _LINUX_BITOPS_INSTRUMENTED_H

#include <linux/kasan-checks.h>

#define ADDR(nr, addr) ((void *)(addr) + ((nr) >> 3))

#define INSTR_VOID(func)						\
static __always_inline void func(long nr, volatile unsigned long *addr)	\
{									\
	kasan_check_write(ADDR(nr, addr), 1);				\
	arch_##func(nr, addr);						\
}

#define INSTR_BOOL(func)						\
static __always_inline bool func(long nr, volatile unsigned long *addr)	\
{									\
	kasan_check_write(ADDR(nr, addr), 1);				\
	return arch_##func(nr, addr);					\
}

INSTR_VOID(set_bit);
INSTR_VOID(__set_bit);
INSTR_VOID(clear_bit);
INSTR_VOID(__clear_bit);
INSTR_VOID(clear_bit_unlock);
INSTR_VOID(__clear_bit_unlock);
INSTR_VOID(change_bit);
INSTR_VOID(__change_bit);

INSTR_BOOL(test_and_set_bit);
INSTR_BOOL(test_and_set_bit_lock);
INSTR_BOOL(__test_and_set_bit);
INSTR_BOOL(test_and_clear_bit);
INSTR_BOOL(__test_and_clear_bit);
INSTR_BOOL(test_and_change_bit);
INSTR_BOOL(__test_and_change_bit);
#ifdef clear_bit_unlock_is_negative_byte
INSTR_BOOL(clear_bit_unlock_is_negative_byte);
#endif

static bool test_bit(int nr, const volatile unsigned long *addr)
{
	kasan_check_read(ADDR(nr, addr), 1);
	return arch_test_bit(nr, addr);
}

#undef ADDR
#undef INSTR_VOID
#undef INSTR_BOOL

#endif /* _LINUX_BITOPS_INSTRUMENTED_H */
