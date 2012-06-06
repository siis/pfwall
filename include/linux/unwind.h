#ifndef UNWIND_H
#define UNWIND_H

#include <linux/ptrace.h>
#include <asm/unwind.h>
#include <linux/dwarf.h>

struct unw_t {
	struct pt_regs regs;
	dwarf_word_t cfa;

	/*
	 * First 2 items are touched by assembly code,
	 * do not move them.
	 */
};

void unw_init(struct unw_t *u);
void unw_regs(struct unw_t *u, struct pt_regs *regs);
int  unw_step(struct unw_t *u);
void unw_backtrace(void);

#endif /* UNWIND_H */
