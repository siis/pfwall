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

#ifndef DWARF_H
#define DWARF_H

#include <linux/ptrace.h>
#include <asm/dwarf.h>

#define DWARF_DEBUG_LVL 0
#define DWARF_DEBUG(cond, fmt, args...) \
do { \
        if (cond > DWARF_DEBUG_LVL) \
                break; \
	printk("[%s:%05d] ", __FUNCTION__, __LINE__); \
        printk(fmt, ## args); \
} while(0)

#define DWARF_CIE_VERSION	3
#define DWARF_CIE_VERSION_GCC	1

#define DWARF_CFA_OPCODE_MASK	0xc0
#define DWARF_CFA_OPERAND_MASK	0x3f

#define DW_EH_PE_FORMAT_MASK	0x0f	/* format of the encoded value */
#define DW_EH_PE_APPL_MASK	0x70	/* how the value is to be applied */
/*
 * Flag bit.  If set, the resulting pointer is the address of the word
 * that contains the final address.
 */
#define DW_EH_PE_indirect	0x80

/* Pointer-encoding formats: */
#define DW_EH_PE_omit		0xff
#define DW_EH_PE_ptr		0x00	/* pointer-sized unsigned value */
#define DW_EH_PE_uleb128	0x01	/* unsigned LE base-128 value */
#define DW_EH_PE_udata2		0x02	/* unsigned 16-bit value */
#define DW_EH_PE_udata4		0x03	/* unsigned 32-bit value */
#define DW_EH_PE_udata8		0x04	/* unsigned 64-bit value */
#define DW_EH_PE_sleb128	0x09	/* signed LE base-128 value */
#define DW_EH_PE_sdata2		0x0a	/* signed 16-bit value */
#define DW_EH_PE_sdata4		0x0b	/* signed 32-bit value */
#define DW_EH_PE_sdata8		0x0c	/* signed 64-bit value */

/* Pointer-encoding application: */
#define DW_EH_PE_absptr		0x00	/* absolute value */
#define DW_EH_PE_pcrel		0x10	/* rel. to addr. of encoded value */
#define DW_EH_PE_textrel	0x20	/* text-relative (GCC-specific???) */
#define DW_EH_PE_datarel	0x30	/* data-relative */
/*
 * The following are not documented by LSB v1.3, yet they are used by
 * GCC, presumably they aren't documented by LSB since they aren't
 * used on Linux:
 */
#define DW_EH_PE_funcrel	0x40	/* start-of-procedure-relative */
#define DW_EH_PE_aligned	0x50	/* aligned pointer */

enum {
        DWARF_WHERE_UNDEF,      /* register isn't saved at all */
        DWARF_WHERE_SAME,       /* register has same value as in prev. frame */
        DWARF_WHERE_CFAREL,     /* register saved at CFA-relative address */
        DWARF_WHERE_REG,        /* register saved in another register */
        DWARF_WHERE_EXPR,       /* register saved */
};

/* eh_frame unwind information */
struct unw_t {
	struct pt_regs regs;
	dwarf_word_t cfa;
};

struct eh_table_data {
	dwarf_word_t table_count; 
	dwarf_word_t table_base;
	struct table_entry* table_data;
}; 

struct eh_frame_hdr {
	unsigned char version;
	unsigned char eh_frame_ptr_enc;
	unsigned char fde_count_enc;
	unsigned char table_enc;
};

/* eh_frame structure information */
struct dwarf_cie {
	dwarf_word_t cie_instr_start;
	dwarf_word_t cie_instr_end;
	dwarf_word_t code_align;
	dwarf_word_t data_align;
	dwarf_word_t ret_addr_column;
        uint8_t lsda_encoding;
	uint8_t fde_encoding;
	unsigned int sized_augmentation : 1;
};

struct dwarf_fde {
	struct dwarf_cie cie;
        dwarf_word_t start_ip;
        dwarf_word_t end_ip;
        dwarf_word_t fde_instr_start;
        dwarf_word_t fde_instr_end;
        dwarf_word_t lsda;
};

struct dwarf_save_loc {
	int where;
	dwarf_word_t val;
};

struct dwarf_regs_state {
	struct dwarf_save_loc reg[DWARF_REGS_NUM];
	struct dwarf_regs_state *next;
};

struct dwarf_state {
	struct dwarf_regs_state rs_initial;
	struct dwarf_regs_state rs_current;
};

struct dwarf_regs {
	dwarf_word_t reg[DWARF_REGS_NUM];
	dwarf_word_t cfa;
};

dwarf_word_t dwarf_regs_ip(struct dwarf_regs *regs);
void dwarf_regs_pt2dwarf(struct pt_regs *pt, struct dwarf_regs *dw);
void dwarf_regs_dwarf2pt(struct dwarf_regs *dw, struct pt_regs *pt);

uint8_t  dwarf_readu8(dwarf_word_t *addr);
uint16_t dwarf_readu16(dwarf_word_t *addr);
uint32_t dwarf_readu32(dwarf_word_t *addr);
uint64_t dwarf_readu64(dwarf_word_t *addr);
int8_t   dwarf_reads8(dwarf_word_t *addr);
int16_t  dwarf_reads16(dwarf_word_t *addr);
int32_t  dwarf_reads32(dwarf_word_t *addr);
int64_t  dwarf_reads64(dwarf_word_t *addr);

dwarf_word_t dwarf_read_sleb128(dwarf_word_t *addr);
dwarf_word_t dwarf_read_uleb128(dwarf_word_t *addr);

dwarf_word_t dwarf_readw(dwarf_word_t *addr);

int dwarf_read_pointer(dwarf_word_t *addr,
		       unsigned char encoding,
		       dwarf_word_t *valp);

int dwarf_fde_init(struct dwarf_fde *fde, void *data);
int dwarf_fde_process(struct dwarf_fde *fde, struct dwarf_regs *regs,
		unsigned long st_high, unsigned long st_low);

int dwarf_cfi_run(struct dwarf_fde *fde, struct dwarf_state *state,
		  dwarf_word_t ip, dwarf_word_t start_addr,
		  dwarf_word_t end_addr);

int dwarf_expression(struct dwarf_regs *regs, dwarf_word_t *addr,
		     dwarf_word_t len, dwarf_word_t *val, 
		unsigned long st_high, unsigned long st_low);

static inline
void dwarf_setreg(struct dwarf_regs_state *rs, dwarf_word_t regnum,
		  int where, dwarf_word_t val)
{
	rs->reg[regnum].where = where;
	rs->reg[regnum].val = val;
}

#endif /* DWARF_H */
