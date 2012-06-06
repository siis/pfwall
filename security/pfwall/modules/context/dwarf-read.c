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

#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/dwarf.h>

typedef union __packed {
	int8_t          s8;
	int16_t		s16;
	int32_t		s32;
	int64_t		s64;
	uint8_t		u8;
	uint16_t	u16;
	uint32_t	u32;
	uint64_t	u64;
} dwarf_misaligned_value_t;

int8_t dwarf_reads8(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void *) *addr;
	*addr += sizeof (mvp->s8);
	return mvp->s8;
}

int16_t dwarf_reads16(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void*) *addr;
	*addr += sizeof (mvp->s16);
	return mvp->s16;
}

int32_t dwarf_reads32(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void *) *addr;
	*addr += sizeof (mvp->s32);
	return mvp->s32;
}

int64_t dwarf_reads64(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void *) *addr;
	*addr += sizeof (mvp->s64);
	return mvp->s64;
}

uint8_t dwarf_readu8(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void *) *addr;
	*addr += sizeof (mvp->u8);
	return mvp->u8;
}

uint16_t dwarf_readu16(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void *) *addr;
	*addr += sizeof (mvp->u16);
	return mvp->u16;
}

uint32_t dwarf_readu32(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void *) *addr;
	*addr += sizeof (mvp->u32);
	return mvp->u32;
}

uint64_t dwarf_readu64(dwarf_word_t *addr)
{
	dwarf_misaligned_value_t *mvp = (void *) *addr;
	*addr += sizeof (mvp->u64);
	return mvp->u64;
}

dwarf_word_t dwarf_read_uleb128(dwarf_word_t *addr)
{
	dwarf_word_t val = 0, shift = 0;
	unsigned char byte;

	do {
		byte = dwarf_readu8(addr);
		val |= ((unsigned long) byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);

	return val;
}

dwarf_word_t dwarf_read_sleb128(dwarf_word_t *addr)
{
	dwarf_word_t val = 0, shift = 0;
	unsigned char byte;

	do {
		byte = dwarf_readu8(addr);
		val |= ((unsigned long) byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);

	if (shift < 8 * sizeof(unsigned long) && (byte & 0x40) != 0)
		/* sign-extend negative value */
		val |= ((unsigned long) -1) << shift;

	return val;
}

dwarf_word_t dwarf_readw(dwarf_word_t *addr)
{
	switch (sizeof(dwarf_word_t)) {
	case 4:
		return dwarf_readu32(addr);
	case 8:
		return dwarf_readu64(addr);
	}

	WARN_ON(1);
	return 0;
}

int dwarf_read_pointer(dwarf_word_t *addr, unsigned char encoding,
		       dwarf_word_t *valp)
{
	dwarf_word_t val, initial_addr = *addr;

	if (encoding == DW_EH_PE_omit) {
		*valp = 0;
		return 0;
	} else if (encoding == DW_EH_PE_aligned) {
		int size = sizeof(unsigned long);
		*addr = (initial_addr + size - 1) & -size;
		*valp = dwarf_readw(addr);
		return 0;
	}

	switch (encoding & DW_EH_PE_FORMAT_MASK) {
	case DW_EH_PE_ptr:
		val = dwarf_readw(addr);
		break;

	case DW_EH_PE_uleb128:
		val = dwarf_read_uleb128(addr);
		break;

	case DW_EH_PE_udata2:
		val = dwarf_readu16(addr);
		break;

	case DW_EH_PE_udata4:
		val = dwarf_readu32(addr);
		break;

	case DW_EH_PE_udata8:
		val = dwarf_readu64(addr);
		break;

	case DW_EH_PE_sleb128:
		val = dwarf_read_uleb128(addr);
		break;

	case DW_EH_PE_sdata2:
		val = dwarf_reads16(addr);
		break;

	case DW_EH_PE_sdata4:
		val = dwarf_reads32(addr);
		break;

	case DW_EH_PE_sdata8:
		val = dwarf_reads64(addr);
		break;

	default:
		return -EINVAL;
	}

	if (val == 0) {
		*valp = 0;
		return 0;
	}

	switch (encoding & DW_EH_PE_APPL_MASK) {
	case DW_EH_PE_absptr:
		break;

	case DW_EH_PE_pcrel:
		val += initial_addr;
		break;

	case DW_EH_PE_datarel:
		/* TODO
		val += pi->gp;
		*/
		break;

	case DW_EH_PE_funcrel:
		/* TODO
		val += pi->start_ip;
		*/
		break;

	case DW_EH_PE_textrel:
		return -EINVAL;
	}

	if (encoding & DW_EH_PE_indirect) {
		dwarf_word_t indirect_addr = val;
		val = dwarf_readw(&indirect_addr);
	}

	*valp = val;
	return 0;
}
