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
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/dwarf.h>
#include <linux/wall.h>

static int parse_cie(struct dwarf_cie *cie, void *cie_data)
{
	dwarf_word_t addr = (dwarf_word_t) cie_data;
	dwarf_word_t len, cie_end_addr, aug_size, pfunc; 
	uint8_t fde_encoding, augstr[5], ch, version, handler_encoding;
	uint32_t u32val;
	uint64_t u64val;
	int i;

	DWARF_DEBUG(1, "cie %p\n", cie_data);

	switch(sizeof(dwarf_word_t)) {
	case 4:
		fde_encoding = DW_EH_PE_udata4;
		break;
	case 8:
		fde_encoding = DW_EH_PE_udata8;
		break;
	default:
		return -EINVAL;
	}

	u32val = dwarf_readu32(&addr);

	if (u32val != 0xffffffff) {
		/* The CIE is in the 32-bit DWARF format */
		uint32_t cie_id;

		len = u32val;
		cie_end_addr = addr + len;
		cie_id = dwarf_readu32(&addr);
		if (cie_id != 0)
			return -EINVAL;
	} else {
		uint64_t cie_id;

		u64val = dwarf_readu64(&addr);
		len = u64val;
		cie_end_addr = addr + len;

		cie_id = dwarf_readu64(&addr);
		if (cie_id != 0)
			return -EINVAL;
	}

	cie->cie_instr_end = cie_end_addr;

	version = dwarf_readu8(&addr);

	DWARF_DEBUG(1, "version %d\n", version);

	if (version != DWARF_CIE_VERSION_GCC &&
	    version != DWARF_CIE_VERSION)
		return -EINVAL;

	memset(augstr, 0, sizeof(augstr));
	for (i = 0;;) {
		ch = dwarf_readu8(&addr);
		if (!ch)
			break;

		DWARF_DEBUG(1, "aug '%c'\n", ch);

		if (i < sizeof (augstr) - 1)
			augstr[i++] = ch;
	}

	cie->code_align = dwarf_read_uleb128(&addr);
	cie->data_align = dwarf_read_sleb128(&addr);

	DWARF_DEBUG(1, "code_align %llx\n", (long long unsigned int) cie->code_align);
	DWARF_DEBUG(1, "data_align %llx\n", (long long unsigned int) cie->data_align);

	/* Read the return-address column either as a u8 or as a uleb128. */
	if (version == DWARF_CIE_VERSION_GCC)
		cie->ret_addr_column = dwarf_readu8(&addr);
	else
		cie->ret_addr_column = dwarf_read_uleb128(&addr);

	DWARF_DEBUG(1, "ret_addr_column %llu\n", (long long unsigned int) cie->ret_addr_column);

	i = 0;

	if (augstr[0] == 'z') {
		cie->sized_augmentation = 1;
		aug_size = dwarf_read_uleb128(&addr);
		i++;
	}

	for (; i < sizeof(augstr) && augstr[i]; i++)
		switch (augstr[i]) {
		case 'L':
			cie->lsda_encoding = dwarf_readu8(&addr);
			break;

		case 'R':
			fde_encoding = dwarf_readu8(&addr);
			break;

		/* XXX Handler only applicable to ia64(?) */
		case 'P':
			handler_encoding = dwarf_readu8(&addr); 
			if (dwarf_read_pointer(&addr, handler_encoding, &pfunc) < 0)
				return -EINVAL;
			break; 

		/* XXX ommiting this as well... supposee this should never appear in kernel..  */
		case 'S':
			return -EINVAL;

		default:
			/* If we have the size of the augmentation body, we can skip
			*  over the parts that we don't understand, so we're OK. */
			if (cie->sized_augmentation)
				goto done;
			else
				return -EINVAL;
		}

 done:
	cie->fde_encoding = fde_encoding;
	cie->cie_instr_start = addr;

	DWARF_DEBUG(1, "cie_instr_start %p, cie_instr_end %p\n",
	      (void*) cie->cie_instr_start, (void*) cie->cie_instr_end);
	return 0;
}

static int is_cie_id(dwarf_word_t val)
{
	return (val == 0);
}

int dwarf_fde_init(struct dwarf_fde *fde, void *data)
{
	dwarf_word_t addr = (dwarf_word_t) data;
	dwarf_word_t fde_end_addr, cie_offset_addr, cie_addr;
	dwarf_word_t start_ip, ip_range;
	dwarf_word_t aug_size, aug_end_addr = 0;
	uint64_t u64val;
	uint32_t u32val;
	int ret, ip_range_encoding;

	memset(fde, 0, sizeof(*fde));
	fde->cie.lsda_encoding = DW_EH_PE_omit;

	DWARF_DEBUG(1, "fde %p\n", data);

	u32val = dwarf_readu32(&addr);

	if (u32val != 0xffffffff) {
		int32_t cie_offset;

		if (u32val == 0)
			return -ENODEV;

		fde_end_addr = addr + u32val;
		cie_offset_addr = addr;
		cie_offset = dwarf_reads32(&addr);

		if (is_cie_id(cie_offset))
			return 0;

		cie_addr = cie_offset_addr - cie_offset;
	} else {
		int64_t cie_offset;

		u64val = dwarf_readu64(&addr);

		fde_end_addr = addr + u64val;
		cie_offset_addr = addr;

		cie_offset = dwarf_reads64(&addr);

		if (is_cie_id(cie_offset))
			return 0;

		cie_addr = (dwarf_word_t) ((uint64_t) cie_offset_addr - cie_offset);
	}

	ret = parse_cie(&fde->cie, (void *) cie_addr);
	if (ret)
		return ret;

	ip_range_encoding = fde->cie.fde_encoding & DW_EH_PE_FORMAT_MASK;

	DWARF_DEBUG(1, "ip_range_encoding %x\n", ip_range_encoding);

	if ((ret = dwarf_read_pointer(&addr, fde->cie.fde_encoding, &start_ip)) < 0 ||
	    (ret = dwarf_read_pointer(&addr, ip_range_encoding, &ip_range)) < 0)
		return ret;

	fde->start_ip = start_ip;
	fde->end_ip = start_ip + ip_range;

	DWARF_DEBUG(1, "start_ip %p, end_ip %p\n",
		    (void*) fde->start_ip, (void*) fde->end_ip);
	DWARF_DEBUG(1, "sized_augmentation %d\n",
		    fde->cie.sized_augmentation);

	if (fde->cie.sized_augmentation) {
		aug_size = dwarf_read_uleb128(&addr);
		aug_end_addr = addr + aug_size;

		DWARF_DEBUG(1, "aug_end_addr %p, aug_size %llx\n",
		      (void*) aug_end_addr, (long long unsigned int) aug_size);
	}

	DWARF_DEBUG(1, "lsda_encoding %x\n", fde->cie.lsda_encoding);

	if ((ret = dwarf_read_pointer(&addr, fde->cie.lsda_encoding,
				      &fde->lsda)) < 0)
		return ret;

	DWARF_DEBUG(1, "lsda %p\n", (void*) fde->lsda);

	if (fde->cie.sized_augmentation)
		fde->fde_instr_start = aug_end_addr;
	else
		fde->fde_instr_start = addr;

	fde->fde_instr_end = fde_end_addr;

	DWARF_DEBUG(1, "fde_instr_start %p, fde_instr_end %p\n",
	      (void*) fde->fde_instr_start, (void*) fde->fde_instr_end);
	return 0;
}

/*  Security: Verify that all dereferences in (and below) this function
	fall in the stack. This will guarantee protection in dereferencing
	malicious stacks. The stack bounds are st_low .. st_high. 

	TODO: For binaries, do the same when dereferencing eh_frame in 
	dwarf_cfi_run. 
 */

static int
apply_reg_state(struct dwarf_regs *regs, struct dwarf_regs_state *rs, 
	unsigned long st_high, unsigned long st_low) 
{
	dwarf_word_t prev_cfa, cfa;
	dwarf_word_t prev_ip;
	dwarf_word_t regnum;
	dwarf_word_t addr, addr_tmp;
	dwarf_word_t len;
	int i;

	prev_ip  = dwarf_regs_ip(regs);
	prev_cfa = regs->cfa;

	if (rs->reg[DWARF_CFA_REG_COLUMN].where == DWARF_WHERE_REG) {
		/* CFA is equal to [reg] + offset: */
		/*
		 * As a special-case, if the stack-pointer is the CFA and the
		 * stack-pointer wasn't saved, popping the CFA implicitly pops
		 * the stack-pointer as well.
		 */
		if ((rs->reg[DWARF_CFA_REG_COLUMN].val == DWARF_SP) &&
		    (rs->reg[DWARF_SP].where == DWARF_WHERE_SAME))
			cfa = prev_cfa;
		else {
			regnum = rs->reg[DWARF_CFA_REG_COLUMN].val;
			cfa = regs->reg[regnum];
		}

		cfa += rs->reg[DWARF_CFA_OFF_COLUMN].val;
       } else {
		if (rs->reg[DWARF_CFA_REG_COLUMN].where != DWARF_WHERE_EXPR)
			return -EINVAL;

		addr = rs->reg[DWARF_CFA_REG_COLUMN].val;
		len = dwarf_read_uleb128(&addr);

		if (dwarf_expression(regs, &addr, len, &cfa, st_high, st_low))
			return -EINVAL;
	}

	for (i = 0; i < DWARF_REGS_NUM; ++i) {
		switch (rs->reg[i].where) {
		case DWARF_WHERE_UNDEF:
			regs->reg[i] = 0;
			break;

		case DWARF_WHERE_SAME:
			break;

		case DWARF_WHERE_CFAREL:
			DWARF_DEBUG(1, "setting regs->reg[%d] to *(0x%lx + 0x%lx) = %lx\n", 
				i, (long unsigned int) cfa, (long unsigned int) rs->reg[i].val, (long unsigned int) *((dwarf_word_t*) (cfa + rs->reg[i].val))); 
			addr_tmp = (unsigned long) ((dwarf_word_t *) (cfa + rs->reg[i].val)); 
			if (!(addr_tmp >= st_low && addr_tmp < st_high)) {
				PFWALL_ERR(1, "invalid address not in stack: [%s, %lx]\n", current->comm, (long unsigned int) addr_tmp); 
				return -EINVAL; 
			}
			regs->reg[i] = *((dwarf_word_t*) (cfa + rs->reg[i].val));
			break;

		case DWARF_WHERE_REG:
			DWARF_DEBUG(1, "setting regs->reg[%d] to %lx\n", i, (long unsigned int) rs->reg[i].val); 
			regs->reg[i] = rs->reg[i].val;
			break;

		case DWARF_WHERE_EXPR:
			addr = rs->reg[i].val;
			addr_tmp = (unsigned long) addr; 
			if (!(addr_tmp >= st_low && addr_tmp < st_high)) {
				PFWALL_ERR(1, "invalid address not in stack: [%s, %lx]\n", current->comm, (long unsigned int) addr_tmp); 
				return -EINVAL; 
			}
			len = dwarf_read_uleb128(&addr);
			DWARF_DEBUG(1, "setting inside expression\n"); 
			if (dwarf_expression(regs, &addr, len, &regs->reg[i], st_high, st_low))
				return -EINVAL;
			break;
		}
	}

	/* Update CFA "register" */
	regs->cfa = cfa; 

	/* XXX: Update stack pointer -- special case? */
	regs->reg[DWARF_SP] = cfa; 

	if ((dwarf_regs_ip(regs) == prev_ip) &&
	    (cfa == prev_cfa)) {
		DWARF_DEBUG(1, "ip and cfa unchanged, ip=0x%lx)\n",
			    (long unsigned int) dwarf_regs_ip(regs));
		return -EINVAL;
	}

	return 0;
}

int dwarf_fde_process(struct dwarf_fde *fde, struct dwarf_regs *regs, 
		unsigned long st_high, unsigned long st_low)
{
	struct dwarf_state state;
	int i, ret;

	memset(&state, 0, sizeof(state));
	for(i = 0; i < DWARF_REGS_NUM; ++i)
		dwarf_setreg(&state.rs_current, i, DWARF_WHERE_SAME, 0);

	ret = dwarf_cfi_run(fde, &state, dwarf_regs_ip(regs),
			    fde->cie.cie_instr_start,
			    fde->cie.cie_instr_end);
	if (ret)
		return ret;

	memcpy(&state.rs_initial, &state.rs_current, sizeof(state.rs_initial));

	ret = dwarf_cfi_run(fde, &state, dwarf_regs_ip(regs),
			    fde->fde_instr_start,
			    fde->fde_instr_end);
	if (ret)
		return ret;

	return apply_reg_state(regs, &state.rs_current, st_high, st_low);
}
