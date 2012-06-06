/*
 * Code mostly taken from libunwind (git://git.sv.gnu.org/libunwind.git)
 * Adding copyright notice as requested:
 *
 * Copyright (c) 2002 Hewlett-Packard Co.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 */

#ifndef _ARCH_X86_KERNEL_DWARF_H
#define _ARCH_X86_KERNEL_DWARF_H

#include <linux/types.h>

#ifdef __i386__
typedef uint32_t dwarf_word_t;
typedef int32_t dwarf_sword_t;

enum {
	/* Standard x86 registers. */
	DWARF_X86_EAX,
	DWARF_X86_ECX,
	DWARF_X86_EDX,
	DWARF_X86_EBX,
	DWARF_X86_ESP,
	DWARF_X86_EBP,
	DWARF_X86_ESI,
	DWARF_X86_EDI,
	DWARF_X86_EIP,
	DWARF_X86_EFLAGS,
	DWARF_X86_TRAPNO,
	DWARF_X86_ST0,
	DWARF_X86_ST1,
	DWARF_X86_ST2,
	DWARF_X86_ST3,
	DWARF_X86_ST4,
	DWARF_X86_ST5,
	DWARF_X86_ST6,
	DWARF_X86_ST7,

	/* Trating CFA as special register. */
	DWARF_CFA_REG_COLUMN,
	DWARF_CFA_OFF_COLUMN,

	DWARF_REGS_NUM,
	DWARF_SP = DWARF_X86_ESP,
};
#else
typedef uint64_t dwarf_word_t;
typedef int64_t dwarf_sword_t;

enum {
	/* Standard x86_64 registers. */
	DWARF_X86_64_RAX,
	DWARF_X86_64_RDX,
	DWARF_X86_64_RCX,
	DWARF_X86_64_RBX,
	DWARF_X86_64_RSI,
	DWARF_X86_64_RDI,
	DWARF_X86_64_RBP,
	DWARF_X86_64_RSP,
	DWARF_X86_64_R8,
	DWARF_X86_64_R9,
	DWARF_X86_64_R10,
	DWARF_X86_64_R11,
	DWARF_X86_64_R12,
	DWARF_X86_64_R13,
	DWARF_X86_64_R14,
	DWARF_X86_64_R15,
	DWARF_X86_64_RIP,

	/* Trating CFA as special register. */
	DWARF_CFA_REG_COLUMN,
	DWARF_CFA_OFF_COLUMN,

	DWARF_REGS_NUM,
	DWARF_SP = DWARF_X86_64_RSP,
};
#endif /* __i386__ */
#endif  /* _ARCH_X86_KERNEL_UNWIND_H */
