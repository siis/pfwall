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

#include <linux/kernel.h>
#include <linux/dwarf.h>
#include <linux/errno.h>
#include <linux/wall.h>

#define MAX_EXPR_STACK_SIZE	64

#define NUM_OPERANDS(signature)	(((signature) >> 6) & 0x3)
#define OPND1_TYPE(signature)	(((signature) >> 3) & 0x7)
#define OPND2_TYPE(signature)	(((signature) >> 0) & 0x7)

#define OPND_SIGNATURE(n, t1, t2) (((n) << 6) | ((t1) << 3) | ((t2) << 0))
#define OPND1(t1)		OPND_SIGNATURE(1, t1, 0)
#define OPND2(t1, t2)		OPND_SIGNATURE(2, t1, t2)

#define VAL8	0x0
#define VAL16	0x1
#define VAL32	0x2
#define VAL64	0x3
#define ULEB128	0x4
#define SLEB128	0x5
#define OFFSET	0x6	/* 32-bit offset for 32-bit DWARF, 64-bit otherwise */
#define ADDR	0x7	/* Machine address.  */

enum {
	DW_OP_addr			= 0x03,
	DW_OP_deref			= 0x06,
	DW_OP_const1u			= 0x08,
	DW_OP_const1s			= 0x09,
	DW_OP_const2u			= 0x0a,
	DW_OP_const2s			= 0x0b,
	DW_OP_const4u			= 0x0c,
	DW_OP_const4s			= 0x0d,
	DW_OP_const8u			= 0x0e,
	DW_OP_const8s			= 0x0f,
	DW_OP_constu			= 0x10,
	DW_OP_consts			= 0x11,
	DW_OP_dup			= 0x12,
	DW_OP_drop			= 0x13,
	DW_OP_over			= 0x14,
	DW_OP_pick			= 0x15,
	DW_OP_swap			= 0x16,
	DW_OP_rot			= 0x17,
	DW_OP_xderef			= 0x18,
	DW_OP_abs			= 0x19,
	DW_OP_and			= 0x1a,
	DW_OP_div			= 0x1b,
	DW_OP_minus			= 0x1c,
	DW_OP_mod			= 0x1d,
	DW_OP_mul			= 0x1e,
	DW_OP_neg			= 0x1f,
	DW_OP_not			= 0x20,
	DW_OP_or			= 0x21,
	DW_OP_plus			= 0x22,
	DW_OP_plus_uconst		= 0x23,
	DW_OP_shl			= 0x24,
	DW_OP_shr			= 0x25,
	DW_OP_shra			= 0x26,
	DW_OP_xor			= 0x27,
	DW_OP_skip			= 0x2f,
	DW_OP_bra			= 0x28,
	DW_OP_eq			= 0x29,
	DW_OP_ge			= 0x2a,
	DW_OP_gt			= 0x2b,
	DW_OP_le			= 0x2c,
	DW_OP_lt			= 0x2d,
	DW_OP_ne			= 0x2e,
	DW_OP_lit0			= 0x30,
	DW_OP_lit1,  DW_OP_lit2,  DW_OP_lit3,  DW_OP_lit4,  DW_OP_lit5,
	DW_OP_lit6,  DW_OP_lit7,  DW_OP_lit8,  DW_OP_lit9,  DW_OP_lit10,
	DW_OP_lit11, DW_OP_lit12, DW_OP_lit13, DW_OP_lit14, DW_OP_lit15,
	DW_OP_lit16, DW_OP_lit17, DW_OP_lit18, DW_OP_lit19, DW_OP_lit20,
	DW_OP_lit21, DW_OP_lit22, DW_OP_lit23, DW_OP_lit24, DW_OP_lit25,
	DW_OP_lit26, DW_OP_lit27, DW_OP_lit28, DW_OP_lit29, DW_OP_lit30,
	DW_OP_lit31,
	DW_OP_reg0			= 0x50,
	DW_OP_reg1,  DW_OP_reg2,  DW_OP_reg3,  DW_OP_reg4,  DW_OP_reg5,
	DW_OP_reg6,  DW_OP_reg7,  DW_OP_reg8,  DW_OP_reg9,  DW_OP_reg10,
	DW_OP_reg11, DW_OP_reg12, DW_OP_reg13, DW_OP_reg14, DW_OP_reg15,
	DW_OP_reg16, DW_OP_reg17, DW_OP_reg18, DW_OP_reg19, DW_OP_reg20,
	DW_OP_reg21, DW_OP_reg22, DW_OP_reg23, DW_OP_reg24, DW_OP_reg25,
	DW_OP_reg26, DW_OP_reg27, DW_OP_reg28, DW_OP_reg29, DW_OP_reg30,
	DW_OP_reg31,
	DW_OP_breg0			= 0x70,
	DW_OP_breg1,  DW_OP_breg2,  DW_OP_breg3,  DW_OP_breg4,  DW_OP_breg5,
	DW_OP_breg6,  DW_OP_breg7,  DW_OP_breg8,  DW_OP_breg9,  DW_OP_breg10,
	DW_OP_breg11, DW_OP_breg12, DW_OP_breg13, DW_OP_breg14, DW_OP_breg15,
	DW_OP_breg16, DW_OP_breg17, DW_OP_breg18, DW_OP_breg19, DW_OP_breg20,
	DW_OP_breg21, DW_OP_breg22, DW_OP_breg23, DW_OP_breg24, DW_OP_breg25,
	DW_OP_breg26, DW_OP_breg27, DW_OP_breg28, DW_OP_breg29, DW_OP_breg30,
	DW_OP_breg31,
	DW_OP_regx			= 0x90,
	DW_OP_fbreg			= 0x91,
	DW_OP_bregx			= 0x92,
	DW_OP_piece			= 0x93,
	DW_OP_deref_size		= 0x94,
	DW_OP_xderef_size		= 0x95,
	DW_OP_nop			= 0x96,
	DW_OP_push_object_address	= 0x97,
	DW_OP_call2			= 0x98,
	DW_OP_call4			= 0x99,
	DW_OP_call_ref			= 0x9a,
	DW_OP_lo_user			= 0xe0,
	DW_OP_hi_user			= 0xff
};

static uint8_t operands[256] =
{
	[DW_OP_addr] =		OPND1 (ADDR),
	[DW_OP_const1u] =		OPND1 (VAL8),
	[DW_OP_const1s] =		OPND1 (VAL8),
	[DW_OP_const2u] =		OPND1 (VAL16),
	[DW_OP_const2s] =		OPND1 (VAL16),
	[DW_OP_const4u] =		OPND1 (VAL32),
	[DW_OP_const4s] =		OPND1 (VAL32),
	[DW_OP_const8u] =		OPND1 (VAL64),
	[DW_OP_const8s] =		OPND1 (VAL64),
	[DW_OP_pick] =		OPND1 (VAL8),
	[DW_OP_plus_uconst] =	OPND1 (ULEB128),
	[DW_OP_skip] =		OPND1 (VAL16),
	[DW_OP_bra] =		OPND1 (VAL16),
	[DW_OP_breg0 +  0] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  1] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  2] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  3] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  4] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  5] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  6] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  7] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  8] =	OPND1 (SLEB128),
	[DW_OP_breg0 +  9] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 10] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 11] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 12] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 13] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 14] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 15] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 16] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 17] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 18] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 19] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 20] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 21] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 22] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 23] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 24] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 25] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 26] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 27] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 28] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 29] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 30] =	OPND1 (SLEB128),
	[DW_OP_breg0 + 31] =	OPND1 (SLEB128),
	[DW_OP_regx] =		OPND1 (ULEB128),
	[DW_OP_fbreg] =		OPND1 (SLEB128),
	[DW_OP_bregx] =		OPND2 (ULEB128, SLEB128),
	[DW_OP_piece] =		OPND1 (ULEB128),
	[DW_OP_deref_size] =	OPND1 (VAL8),
	[DW_OP_xderef_size] =	OPND1 (VAL8),
	[DW_OP_call2] =		OPND1 (VAL16),
	[DW_OP_call4] =		OPND1 (VAL32),
	[DW_OP_call_ref] =		OPND1 (OFFSET)
};

static dwarf_sword_t sword(dwarf_word_t val)
{
	switch (sizeof(val)) {
	case 4: return (int32_t) val;
	case 8: return (int64_t) val;
	}

	WARN(1, "wrong dwarf_word_t size %u\n", sizeof(val));
	return -1;
}

static int read_operand(dwarf_word_t *addr, int operand_type,
			dwarf_word_t *val)
{
	int ret = 0;

	if (operand_type == ADDR)
		switch (sizeof(dwarf_word_t)) {
		case 4: operand_type = VAL32; break;
		case 8: operand_type = VAL64; break;
		default:
			WARN(1, "wrong dwarf_word_t size %u\n", sizeof(val));
			return -1;
		}

	switch (operand_type) {
	case VAL8:
		*val = dwarf_readu8(addr);
		break;

	case VAL16:
		*val = dwarf_readu16(addr);
		break;

	case VAL32:
		*val = dwarf_readu32(addr);
		break;

	case VAL64:
		*val = dwarf_readu64(addr);
		break;

	case ULEB128:
		*val = dwarf_read_uleb128(addr);
		break;

	case SLEB128:
		*val = dwarf_read_sleb128(addr);
		break;

	case OFFSET: /* only used by DW_OP_call_ref, which we don't implement */
	default:
		DWARF_DEBUG(1, "Unexpected operand type %d\n", operand_type);
		ret = -EINVAL;
	}

	return ret;
}

#define dwarf_is_big_endian() 0

int dwarf_expression(struct dwarf_regs *regs, dwarf_word_t *addr,
                     dwarf_word_t len, dwarf_word_t *val, 
					 unsigned long st_high, unsigned long st_low)
{
	dwarf_word_t operand1 = 0, operand2 = 0, tmp1, tmp2, tmp3, end_addr;
	uint8_t opcode, operands_signature;
	dwarf_word_t stack[MAX_EXPR_STACK_SIZE];
	unsigned int tos = 0;
	int ret, reg;
	unsigned long addr_tmp; 

#define pop()						\
({							\
	if ((tos - 1) >= MAX_EXPR_STACK_SIZE)		\
	{						\
		DWARF_DEBUG(1, "Stack underflow\n");	\
		return -EINVAL;				\
	}						\
	stack[--tos];					\
})

#define push(x)						\
do {							\
	if (tos >= MAX_EXPR_STACK_SIZE)			\
	{						\
		DWARF_DEBUG(1, "Stack overflow\n");	\
		return -EINVAL;				\
	}						\
	stack[tos++] = (x);				\
} while (0)

# define pick(n)					\
({							\
	unsigned int _index = tos - 1 - (n);		\
	if (_index >= MAX_EXPR_STACK_SIZE)		\
	{						\
		DWARF_DEBUG(1, "Out-of-stack pick\n");	\
		return -EINVAL;				\
	}						\
	stack[_index];					\
})

	end_addr = *addr + len;

	DWARF_DEBUG(1, "len=%lu, pushing cfa=0x%lx\n",
		    (unsigned long) len, (unsigned long) regs->cfa);

	/* push current CFA as required by DWARF spec */
	push(regs->cfa);

	while (*addr < end_addr) {

		opcode = dwarf_readu8(addr);
		operands_signature = operands[opcode];

		if ((NUM_OPERANDS(operands_signature) > 0)) {
			if (read_operand(addr, OPND1_TYPE(operands_signature),
					 &operand1))
				return -EINVAL;

			if (NUM_OPERANDS(operands_signature > 1)) {
				if (read_operand(addr, OPND2_TYPE(operands_signature),
						 &operand2))
					return ret;
			}
		}

		switch (opcode) {
		case DW_OP_lit0:  case DW_OP_lit1:  case DW_OP_lit2:
		case DW_OP_lit3:  case DW_OP_lit4:  case DW_OP_lit5:
		case DW_OP_lit6:  case DW_OP_lit7:  case DW_OP_lit8:
		case DW_OP_lit9:  case DW_OP_lit10: case DW_OP_lit11:
		case DW_OP_lit12: case DW_OP_lit13: case DW_OP_lit14:
		case DW_OP_lit15: case DW_OP_lit16: case DW_OP_lit17:
		case DW_OP_lit18: case DW_OP_lit19: case DW_OP_lit20:
		case DW_OP_lit21: case DW_OP_lit22: case DW_OP_lit23:
		case DW_OP_lit24: case DW_OP_lit25: case DW_OP_lit26:
		case DW_OP_lit27: case DW_OP_lit28: case DW_OP_lit29:
		case DW_OP_lit30: case DW_OP_lit31:
			DWARF_DEBUG(1, "OP_lit(%d)\n", (int) opcode - DW_OP_lit0);
			push(opcode - DW_OP_lit0);
			break;

		case DW_OP_breg0:  case DW_OP_breg1:  case DW_OP_breg2:
		case DW_OP_breg3:  case DW_OP_breg4:  case DW_OP_breg5:
		case DW_OP_breg6:  case DW_OP_breg7:  case DW_OP_breg8:
		case DW_OP_breg9:  case DW_OP_breg10: case DW_OP_breg11:
		case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14:
		case DW_OP_breg15: case DW_OP_breg16: case DW_OP_breg17:
		case DW_OP_breg18: case DW_OP_breg19: case DW_OP_breg20:
		case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
		case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26:
		case DW_OP_breg27: case DW_OP_breg28: case DW_OP_breg29:
		case DW_OP_breg30: case DW_OP_breg31:
			reg = (int) opcode - DW_OP_breg0;

			DWARF_DEBUG(1, "OP_breg(r%d,0x%lx)\n",
				    reg, (unsigned long) operand1);

			if (reg >= DWARF_REGS_NUM) {
				DWARF_DEBUG(1, "wrong register number %d\n", reg);
				return -EINVAL;
			}

			tmp1 = regs->reg[reg];
			push(tmp1 + operand1);
			break;

		case DW_OP_bregx:
			reg = (int) operand1;

			DWARF_DEBUG(1, "OP_bregx(r%d,0x%lx)\n",
				    reg, (unsigned long) operand2);

			if (reg >= DWARF_REGS_NUM) {
				DWARF_DEBUG(1, "wrong register number %d\n", reg);
				return -EINVAL;
			}

			tmp1 = regs->reg[reg];
			push(tmp1 + operand2);
			break;

		case DW_OP_reg0:  case DW_OP_reg1:  case DW_OP_reg2:
		case DW_OP_reg3:  case DW_OP_reg4:  case DW_OP_reg5:
		case DW_OP_reg6:  case DW_OP_reg7:  case DW_OP_reg8:
		case DW_OP_reg9:  case DW_OP_reg10: case DW_OP_reg11:
		case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14:
		case DW_OP_reg15: case DW_OP_reg16: case DW_OP_reg17:
		case DW_OP_reg18: case DW_OP_reg19: case DW_OP_reg20:
		case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
		case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26:
		case DW_OP_reg27: case DW_OP_reg28: case DW_OP_reg29:
		case DW_OP_reg30: case DW_OP_reg31:
			reg = (int) opcode - DW_OP_reg0;
			DWARF_DEBUG(1, "OP_reg(r%d)\n", reg);
			*val = regs->reg[reg];
			return 0;

		case DW_OP_regx:
			reg = (int) operand1;
			DWARF_DEBUG(1, "OP_regx(r%d)\n", reg);
			*val = regs->reg[reg];
			return 0;

		case DW_OP_addr:
		case DW_OP_const1u:
		case DW_OP_const2u:
		case DW_OP_const4u:
		case DW_OP_const8u:
		case DW_OP_constu:
		case DW_OP_const8s:
		case DW_OP_consts:
			DWARF_DEBUG(1, "OP_const(0x%lx)\n", (unsigned long) operand1);
			push(operand1);
			break;

		case DW_OP_const1s:
			if (operand1 & 0x80)
				operand1 |= ((dwarf_word_t) -1) << 8;
			DWARF_DEBUG(1, "OP_const1s(%ld)\n", (long) operand1);
			push(operand1);
			break;

		case DW_OP_const2s:
			if (operand1 & 0x8000)
				operand1 |= ((dwarf_word_t) -1) << 16;

			DWARF_DEBUG(1, "OP_const2s(%ld)\n", (long) operand1);
			push(operand1);
			break;

		case DW_OP_const4s:
			if (operand1 & 0x80000000)
				operand1 |= (((dwarf_word_t) -1) << 16) << 16;
			DWARF_DEBUG(1, "OP_const4s(%ld)\n", (long) operand1);
			push(operand1);
			break;

		case DW_OP_deref:
			DWARF_DEBUG(1, "OP_deref\n");
			tmp1 = pop();
			addr_tmp = (unsigned long) tmp1; 
			if (!(addr_tmp >= st_low && addr_tmp < st_high)) {
				PFWALL_ERR(1, "invalid address not in stack: [%s, %lx]\n", current->comm, addr_tmp); 
				return -EINVAL; 
			}
			tmp2 = dwarf_readw(&tmp1);
			push(tmp2);
			break;

		case DW_OP_deref_size:
			DWARF_DEBUG(1, "OP_deref_size(%d)\n", (int) operand1);
			tmp1 = pop();
			addr_tmp = (unsigned long) tmp1; 

			if (!(addr_tmp >= st_low && addr_tmp < st_high)) {
				PFWALL_ERR(1, "invalid address not in stack: [%s, %lx]\n", current->comm, addr_tmp); 
				return -EINVAL; 
			}
			switch (operand1) {
			default:
				DWARF_DEBUG(1, "Unexpected DW_OP_deref_size size %d\n",
					    (int) operand1);
				return -EINVAL;

			case 1:
				tmp2 = dwarf_readu8(&tmp1);
				break;

			case 2:
				tmp2 = dwarf_readu16(&tmp1);
				break;

			case 3:
			case 4:
				tmp2 = dwarf_readu32(&tmp1);

				if (operand1 == 3) {
					if (dwarf_is_big_endian())
						tmp2 >>= 8;
					else
						tmp2 &= 0xffffff;
				}
				break;
			case 5:
			case 6:
			case 7:
			case 8:
				tmp2 = dwarf_readu64(&tmp1);

				if (operand1 != 8) {
					if (dwarf_is_big_endian())
						tmp2 >>= 64 - 8 * operand1;
					else
						tmp2 &= (~ (dwarf_word_t) 0) << (8 * operand1);
				}
				break;
			}
			push(tmp2);
			break;

		case DW_OP_dup:
			DWARF_DEBUG(1, "OP_dup\n");
			push(pick(0));
			break;

		case DW_OP_drop:
			DWARF_DEBUG(1, "OP_drop\n");
			pop();
			break;

		case DW_OP_pick:
			DWARF_DEBUG(1, "OP_pick(%d)\n", (int) operand1);
			push(pick (operand1));
			break;

		case DW_OP_over:
			DWARF_DEBUG(1, "OP_over\n");
			push(pick(1));
			break;

		case DW_OP_swap:
			DWARF_DEBUG(1, "OP_swap\n");
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1);
			push(tmp2);
			break;

		case DW_OP_rot:
			DWARF_DEBUG(1, "OP_rot\n");
			tmp1 = pop();
			tmp2 = pop();
			tmp3 = pop();
			push(tmp1);
			push(tmp3);
			push(tmp2);
			break;

		case DW_OP_abs:
			DWARF_DEBUG(1, "OP_abs\n");
			tmp1 = pop();
			if (tmp1 & ((dwarf_word_t) 1 << (8 * sizeof(dwarf_word_t) - 1)))
			tmp1 = -tmp1;
			push(tmp1);
			break;

		case DW_OP_and:
			DWARF_DEBUG(1, "OP_and\n");
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1 & tmp2);
			break;

		case DW_OP_div:
			DWARF_DEBUG(1, "OP_div\n");
			tmp1 = pop();
			tmp2 = pop();
			if (tmp1)
				tmp1 = sword(tmp2) / sword(tmp1);
			push (tmp1);
			break;

		case DW_OP_minus:
			DWARF_DEBUG(1, "OP_minus\n");
			tmp1 = pop();
			tmp2 = pop();
			tmp1 = tmp2 - tmp1;
			push(tmp1);
			break;

		case DW_OP_mod:
			DWARF_DEBUG(1, "OP_mod\n");
			tmp1 = pop();
			tmp2 = pop();
			if (tmp1)
				tmp1 = tmp2 % tmp1;
			push (tmp1);
			break;

		case DW_OP_mul:
			DWARF_DEBUG(1, "OP_mul\n");
			tmp1 = pop();
			tmp2 = pop();
			if (tmp1)
				tmp1 = tmp2 * tmp1;
			push(tmp1);
			break;

		case DW_OP_neg:
			DWARF_DEBUG(1, "OP_neg\n");
			push(-pop());
			break;

		case DW_OP_not:
			DWARF_DEBUG(1, "OP_not\n");
			push(~pop());
			break;

		case DW_OP_or:
			DWARF_DEBUG(1, "OP_or\n");
			tmp1 = pop();
			tmp2 = pop();
			push (tmp1 | tmp2);
			break;

		case DW_OP_plus:
			DWARF_DEBUG(1, "OP_plus\n");
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1 + tmp2);
			break;

		case DW_OP_plus_uconst:
			DWARF_DEBUG(1, "OP_plus_uconst(%lu)\n", (unsigned long) operand1);
			tmp1 = pop();
			push(tmp1 + operand1);
			break;

		case DW_OP_shl:
			DWARF_DEBUG(1, "OP_shl\n");
			tmp1 = pop();
			tmp2 = pop();
			push(tmp2 << tmp1);
			break;

		case DW_OP_shr:
			DWARF_DEBUG(1, "OP_shr\n");
			tmp1 = pop();
			tmp2 = pop();
			push(tmp2 >> tmp1);
			break;

		case DW_OP_shra:
			DWARF_DEBUG(1, "OP_shra\n");
			tmp1 = pop();
			tmp2 = pop();
			push (sword(tmp2) >> tmp1);
			break;

		case DW_OP_xor:
			DWARF_DEBUG(1, "OP_xor\n");
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1 ^ tmp2);
			break;

		case DW_OP_le:
			DWARF_DEBUG(1, "OP_le\n");
			tmp1 = pop();
			tmp2 = pop();
			push (sword(tmp1) <= sword(tmp2));
			break;

		case DW_OP_ge:
			DWARF_DEBUG(1, "OP_ge\n");
			tmp1 = pop();
			tmp2 = pop();
			push (sword(tmp1) >= sword(tmp2));
			break;

		case DW_OP_eq:
			DWARF_DEBUG(1, "OP_eq\n");
			tmp1 = pop();
			tmp2 = pop();
			push(sword(tmp1) == sword(tmp2));
			break;

		case DW_OP_lt:
			DWARF_DEBUG(1, "OP_lt\n");
			tmp1 = pop();
			tmp2 = pop();
			push (sword(tmp1) < sword(tmp2));
			break;

		case DW_OP_gt:
			DWARF_DEBUG(1, "OP_gt\n");
			tmp1 = pop();
			tmp2 = pop();
			push (sword(tmp1) > sword(tmp2));
			break;

		case DW_OP_ne:
			DWARF_DEBUG(1, "OP_ne\n");
			tmp1 = pop();
			tmp2 = pop();
			push (sword(tmp1) != sword(tmp2));
			break;

		case DW_OP_skip:
			DWARF_DEBUG(1, "OP_skip(%d)\n", (int16_t) operand1);
			*addr += (int16_t) operand1;
			break;

		case DW_OP_bra:
			DWARF_DEBUG(1, "OP_skip(%d)\n", (int16_t) operand1);
			tmp1 = pop();
			if (tmp1)
				*addr += (int16_t) operand1;
			break;

		case DW_OP_nop:
			DWARF_DEBUG(1, "OP_nop\n");
			break;

		case DW_OP_call2:
		case DW_OP_call4:
		case DW_OP_call_ref:
		case DW_OP_fbreg:
		case DW_OP_piece:
		case DW_OP_push_object_address:
		case DW_OP_xderef:
		case DW_OP_xderef_size:
		default:
			DWARF_DEBUG(1, "Unexpected opcode 0x%x\n", opcode);
			return -EINVAL;
		} /* switch opcode */
	}

	*val = pop ();
	DWARF_DEBUG(1, "final value = 0x%lx\n", (unsigned long) *val);
	return 0;
}
