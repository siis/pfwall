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
#include <linux/slab.h>

typedef enum {
	DW_CFA_advance_loc		= 0x40,
	DW_CFA_offset			= 0x80,
	DW_CFA_restore			= 0xc0,
	DW_CFA_nop			= 0x00,
	DW_CFA_set_loc			= 0x01,
	DW_CFA_advance_loc1		= 0x02,
	DW_CFA_advance_loc2		= 0x03,
	DW_CFA_advance_loc4		= 0x04,
	DW_CFA_offset_extended		= 0x05,
	DW_CFA_restore_extended		= 0x06,
	DW_CFA_undefined		= 0x07,
	DW_CFA_same_value		= 0x08,
	DW_CFA_register			= 0x09,
	DW_CFA_remember_state		= 0x0a,
	DW_CFA_restore_state		= 0x0b,
	DW_CFA_def_cfa			= 0x0c,
	DW_CFA_def_cfa_register		= 0x0d,
	DW_CFA_def_cfa_offset		= 0x0e,
	DW_CFA_def_cfa_expression	= 0x0f,
	DW_CFA_expression		= 0x10,
	DW_CFA_offset_extended_sf	= 0x11,
	DW_CFA_def_cfa_sf		= 0x12,
	DW_CFA_def_cfa_offset_sf	= 0x13,
	DW_CFA_lo_user			= 0x1c,
	DW_CFA_MIPS_advance_loc8	= 0x1d,
	DW_CFA_GNU_window_save		= 0x2d,
	DW_CFA_GNU_args_size		= 0x2e,
	DW_CFA_GNU_negative_offset_extended	= 0x2f,
	DW_CFA_hi_user			= 0x3c
} dwarf_cfa_t;

static int read_regnum(dwarf_word_t *addr, dwarf_word_t *valp)
{
	*valp = dwarf_read_uleb128(addr);

	if (*valp >= DWARF_REGS_NUM) {
		DWARF_DEBUG(1, "Invalid register number %u\n", (unsigned int) *valp);
		return -EINVAL;
	}
	return 0;
}

int dwarf_cfi_run(struct dwarf_fde *fde, struct dwarf_state *state,
                  dwarf_word_t ip, dwarf_word_t start_addr,
		  dwarf_word_t end_addr)
{
	struct dwarf_regs_state *new_rs, *old_rs, *rs_stack = NULL;
	dwarf_word_t curr_ip, operand = 0, regnum, val;
	dwarf_word_t addr = start_addr;
	dwarf_word_t len;
	uint8_t u8, op;
	uint16_t u16;
	uint32_t u32;
	int ret = 0;

	curr_ip = fde->start_ip;

	/*
	 * Process everything up to and including the current 'ip',
	 * including all the DW_CFA_advance_loc instructions.  See
	 * 'c->use_prev_instr' use in 'fetch_proc_info' for details.
	 */
	while (curr_ip <= ip && addr < end_addr) {
		op = dwarf_readu8(&addr);

		if (op & DWARF_CFA_OPCODE_MASK) {
			operand = op & DWARF_CFA_OPERAND_MASK;
			op &= ~DWARF_CFA_OPERAND_MASK;
		}

		switch ((dwarf_cfa_t) op) {
		case DW_CFA_advance_loc:
			curr_ip += operand * fde->cie.code_align;
			DWARF_DEBUG(1, "CFA_advance_loc to 0x%lx\n", (long) curr_ip);
			break;

		case DW_CFA_advance_loc1:
			u8 = dwarf_readu8(&addr);
			curr_ip += u8 * fde->cie.code_align;
			DWARF_DEBUG(1, "CFA_advance_loc1 to 0x%lx\n", (long) curr_ip);
			break;

		case DW_CFA_advance_loc2:
			u16 = dwarf_readu16(&addr);
			curr_ip += u16 * fde->cie.code_align;
			DWARF_DEBUG(1, "CFA_advance_loc2 to 0x%lx\n", (long) curr_ip);
			break;

		case DW_CFA_advance_loc4:
			u32 = dwarf_readu32(&addr);
			curr_ip += u32 * fde->cie.code_align;
			DWARF_DEBUG(1, "CFA_advance_loc4 to 0x%lx\n", (long) curr_ip);
			break;

		case DW_CFA_MIPS_advance_loc8:
			DWARF_DEBUG(1, "FAILED DW_CFA_MIPS_advance_loc8\n");
			goto fail;

		case DW_CFA_offset:
			regnum = operand;
			if (regnum >= DWARF_REGS_NUM) {
				DWARF_DEBUG(1, "Invalid register number %u in DW_cfa_OFFSET\n",
					(unsigned int) regnum);
				ret = -EINVAL;
				goto fail;
			}
			val = dwarf_read_uleb128(&addr);
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_CFAREL, val * fde->cie.data_align);
			DWARF_DEBUG(1, "CFA_offset r%lu at cfa+0x%lx\n", (long) regnum, (long) (val * fde->cie.data_align));
			break;

		case DW_CFA_offset_extended:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;
			val = dwarf_read_uleb128(&addr);
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_CFAREL, val * fde->cie.data_align);
			DWARF_DEBUG(1, "CFA_offset_extended r%lu at cf+0x%lx\n", (long) regnum, (long) (val * fde->cie.data_align));
			break;

		case DW_CFA_offset_extended_sf:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;

			val = dwarf_read_sleb128(&addr);
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_CFAREL, val * fde->cie.data_align);
			DWARF_DEBUG(1, "CFA_offset_extended_sf r%lu at cf+0x%lx\n", (long) regnum, (long) (val * fde->cie.data_align));
			break;

		case DW_CFA_restore:
			regnum = operand;
			if (regnum >= DWARF_REGS_NUM) {
				DWARF_DEBUG(1, "Invalid register number %u in DW_CFA_restore\n", (unsigned int) regnum);
				ret = -EINVAL;
				goto fail;
			}
			state->rs_current.reg[regnum] = state->rs_initial.reg[regnum];
			DWARF_DEBUG(1, "CFA_restore r%lu\n", (long) regnum);
			break;

		case DW_CFA_restore_extended:
			regnum = dwarf_read_uleb128(&addr);
			if (regnum >= DWARF_REGS_NUM) {
				DWARF_DEBUG(1, "Invalid register number %u in "
					"DW_CFA_restore_extended\n", (unsigned int) regnum);
				ret = -EINVAL;
				goto fail;
			}
			state->rs_current.reg[regnum] = state->rs_initial.reg[regnum];
			DWARF_DEBUG(1, "CFA_restore_extended r%lu\n", (long) regnum);
			break;

		case DW_CFA_nop:
			DWARF_DEBUG(1, "DW_CFA_nop\n");
			break;

		case DW_CFA_set_loc:
			if ((ret = dwarf_read_pointer(&addr, fde->cie.fde_encoding, &curr_ip)) < 0)
				goto fail;
			DWARF_DEBUG(1, "CFA_set_loc to 0x%lx\n", (long) curr_ip);
			break;

		case DW_CFA_undefined:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_UNDEF, 0);
			DWARF_DEBUG(1, "CFA_undefined r%lu\n", (long) regnum);
			break;

		case DW_CFA_same_value:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_SAME, 0);
			DWARF_DEBUG(1, "CFA_same_value r%lu\n", (long) regnum);
			break;

		case DW_CFA_register:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;

			val = dwarf_read_uleb128(&addr);
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_REG, val);
			DWARF_DEBUG(1, "CFA_register r%lu to r%lu\n", (long) regnum, (long) val);
			break;

		case DW_CFA_remember_state:
			new_rs = kzalloc(sizeof(*new_rs), GFP_KERNEL);
			if (!new_rs) {
				DWARF_DEBUG(1, "Out of memory in DW_CFA_remember_state\n");
				ret = -ENOMEM;
				goto fail;
			}

			memcpy (new_rs->reg, &state->rs_current.reg, sizeof(new_rs->reg));
			new_rs->next = rs_stack;
			rs_stack = new_rs;
			DWARF_DEBUG(1, "CFA_remember_state\n");
			break;

		case DW_CFA_restore_state:
			if (!rs_stack) {
				DWARF_DEBUG(1, "register-state stack underflow\n");
				ret = -EINVAL;
				goto fail;
			}

			memcpy(&state->rs_current.reg, &rs_stack->reg, sizeof(rs_stack->reg));
			old_rs = rs_stack;
			rs_stack = rs_stack->next;
			kfree(old_rs);
			DWARF_DEBUG(1, "CFA_restore_state\n");
			break;

		case DW_CFA_def_cfa:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;

			val = dwarf_read_uleb128(&addr);
			dwarf_setreg(&state->rs_current, DWARF_CFA_REG_COLUMN, DWARF_WHERE_REG, regnum);
			dwarf_setreg(&state->rs_current, DWARF_CFA_OFF_COLUMN, 0, val);
			DWARF_DEBUG(1, "CFA_def_cfa r%lu+0x%lx\n", (long) regnum, (long) val);
			break;

		case DW_CFA_def_cfa_sf:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;

			val = dwarf_read_sleb128(&addr);
			dwarf_setreg(&state->rs_current, DWARF_CFA_REG_COLUMN, DWARF_WHERE_REG, regnum);
			dwarf_setreg(&state->rs_current, DWARF_CFA_OFF_COLUMN, 0, val * fde->cie.data_align);
			DWARF_DEBUG(1, "CFA_def_cfa_sf r%lu+0x%lx\n", (long) regnum, (long) (val * fde->cie.data_align));
			break;

		case DW_CFA_def_cfa_register:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;
			dwarf_setreg(&state->rs_current, DWARF_CFA_REG_COLUMN, DWARF_WHERE_REG, regnum);
			DWARF_DEBUG(1, "CFA_def_cfa_register r%lu\n", (long) regnum);
			break;

		case DW_CFA_def_cfa_offset:
			val = dwarf_read_uleb128(&addr);
			dwarf_setreg(&state->rs_current, DWARF_CFA_OFF_COLUMN, 0, val);
			DWARF_DEBUG(1, "CFA_def_cfa_offset 0x%lx\n", (long) val);
			break;

		case DW_CFA_def_cfa_offset_sf:
			val = dwarf_read_sleb128(&addr);
			dwarf_setreg(&state->rs_current, DWARF_CFA_OFF_COLUMN, 0, val * fde->cie.data_align);
			DWARF_DEBUG(1, "CFA_def_cfa_offset_sf 0x%lx\n", (long) (val * fde->cie.data_align));
			break;

		case DW_CFA_def_cfa_expression:
			dwarf_setreg(&state->rs_current, DWARF_CFA_REG_COLUMN, DWARF_WHERE_EXPR, addr);

			len = dwarf_read_uleb128(&addr);
			DWARF_DEBUG(1, "CFA_def_cfa_expr @ 0x%lx [%lu bytes]\n", (long) addr, (long) len);
			addr += len;
			break;

		case DW_CFA_expression:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;

			/* Save the address of the DW_FORM_block for later evaluation. */
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_EXPR, addr);

			len = dwarf_read_uleb128(&addr);
			DWARF_DEBUG(1, "CFA_expression r%lu @ 0x%lx [%lu bytes]\n", (long) regnum, (long) addr, (long) len);
			addr += len;
			break;

/* XXX NOT USED?
		case DW_CFA_GNU_args_size:
			if ((ret = dwarf_read_uleb128(&addr, &val)) < 0)
				goto fail;
			sr->args_size = val;
			printk("CFA_GNU_args_size %lu\n", (long) val);
			break;
*/
		case DW_CFA_GNU_negative_offset_extended:
			if ((ret = read_regnum(&addr, &regnum)) < 0)
				goto fail;

			val = dwarf_read_uleb128(&addr);
			dwarf_setreg(&state->rs_current, regnum, DWARF_WHERE_CFAREL, -(val * fde->cie.data_align));
			DWARF_DEBUG(1, "CFA_GNU_negative_offset_extended cfa+0x%lx\n", (long) -(val * fde->cie.data_align));
			break;

		case DW_CFA_GNU_window_save:
			/* This is a special CFA to handle all 16 windowed registers
			   on SPARC. FALL THROUGH */

		case DW_CFA_lo_user:
		case DW_CFA_hi_user:
		default:
			printk("Unexpected CFA opcode 0x%x\n", op);
			ret = -EINVAL;
			goto fail;
		}
	}

 fail:
	DWARF_DEBUG(1, "run_cfi_program ret %d\n", ret);

	/* Free the register-state stack, if not empty already.  */
	while (rs_stack) {
		old_rs = rs_stack;
		rs_stack = rs_stack->next;
		kfree(old_rs);
	}

	return ret;
}
