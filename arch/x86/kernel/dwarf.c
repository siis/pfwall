#include <linux/dwarf.h>
#include <linux/ptrace.h>

dwarf_word_t dwarf_regs_ip(struct dwarf_regs *regs)
{
#ifdef __i386__
	return regs->reg[DWARF_X86_EIP];
#else
	return regs->reg[DWARF_X86_64_RIP];
#endif /* __i386__ */
}

void dwarf_regs_pt2dwarf(struct pt_regs *pt, struct dwarf_regs *dw)
{
#ifdef __i386__
	dw->reg[DWARF_X86_EAX] = pt->ax;
	dw->reg[DWARF_X86_ECX] = pt->cx;
	dw->reg[DWARF_X86_EDX] = pt->dx;
	dw->reg[DWARF_X86_EBX] = pt->bx;
	dw->reg[DWARF_X86_ESP] = pt->sp;
	dw->reg[DWARF_X86_EBP] = pt->bp;
	dw->reg[DWARF_X86_ESI] = pt->si;
	dw->reg[DWARF_X86_EDI] = pt->di;
	dw->reg[DWARF_X86_EIP] = pt->ip;
	dw->reg[DWARF_X86_EFLAGS] = pt->flags;
/* WTF???
	dw->reg[DWARF_X86_TRAPNO]
	dw->reg[DWARF_X86_ST0]
	dw->reg[DWARF_X86_ST1]
	dw->reg[DWARF_X86_ST2]
	dw->reg[DWARF_X86_ST3]
	dw->reg[DWARF_X86_ST4]
	dw->reg[DWARF_X86_ST5]
	dw->reg[DWARF_X86_ST6]
	dw->reg[DWARF_X86_ST]
*/
#else
	dw->reg[DWARF_X86_64_RAX] = pt->ax;
        dw->reg[DWARF_X86_64_RDX] = pt->dx;
        dw->reg[DWARF_X86_64_RCX] = pt->cx;
        dw->reg[DWARF_X86_64_RBX] = pt->bx;
        dw->reg[DWARF_X86_64_RSI] = pt->si;
        dw->reg[DWARF_X86_64_RDI] = pt->di;
        dw->reg[DWARF_X86_64_RBP] = pt->bp;
        dw->reg[DWARF_X86_64_RSP] = pt->sp;
        dw->reg[DWARF_X86_64_R8] =  pt->r8;
        dw->reg[DWARF_X86_64_R9] =  pt->r9;
        dw->reg[DWARF_X86_64_R10] = pt->r10;
        dw->reg[DWARF_X86_64_R11] = pt->r11;
        dw->reg[DWARF_X86_64_R12] = pt->r12;
        dw->reg[DWARF_X86_64_R13] = pt->r13;
        dw->reg[DWARF_X86_64_R14] = pt->r14;
        dw->reg[DWARF_X86_64_R15] = pt->r15;
        dw->reg[DWARF_X86_64_RIP] = pt->ip;
#endif
}

void dwarf_regs_dwarf2pt(struct dwarf_regs *dw, struct pt_regs *pt)
{
#ifdef __i386__
	pt->ax = dw->reg[DWARF_X86_EAX];
	pt->cx = dw->reg[DWARF_X86_ECX];
	pt->dx = dw->reg[DWARF_X86_EDX];
	pt->bx = dw->reg[DWARF_X86_EBX];
	pt->sp = dw->reg[DWARF_X86_ESP];
	pt->bp = dw->reg[DWARF_X86_EBP];
	pt->si = dw->reg[DWARF_X86_ESI];
	pt->di = dw->reg[DWARF_X86_EDI];
	pt->ip = dw->reg[DWARF_X86_EIP];
	pt->flags = dw->reg[DWARF_X86_EFLAGS];
/* WTF???
	dw->reg[DWARF_X86_TRAPNO]
	dw->reg[DWARF_X86_ST0]
	dw->reg[DWARF_X86_ST1]
	dw->reg[DWARF_X86_ST2]
	dw->reg[DWARF_X86_ST3]
	dw->reg[DWARF_X86_ST4]
	dw->reg[DWARF_X86_ST5]
	dw->reg[DWARF_X86_ST6]
	dw->reg[DWARF_X86_ST]
*/
#else
	pt->ax = dw->reg[DWARF_X86_64_RAX];
	pt->dx = dw->reg[DWARF_X86_64_RDX];
	pt->cx = dw->reg[DWARF_X86_64_RCX];
	pt->bx = dw->reg[DWARF_X86_64_RBX];
	pt->si = dw->reg[DWARF_X86_64_RSI];
	pt->di = dw->reg[DWARF_X86_64_RDI];
	pt->bp = dw->reg[DWARF_X86_64_RBP];
	pt->sp = dw->reg[DWARF_X86_64_RSP];
	pt->r8 = dw->reg[DWARF_X86_64_R8];
	pt->r9 = dw->reg[DWARF_X86_64_R9];
	pt->r10 = dw->reg[DWARF_X86_64_R10];
	pt->r11 = dw->reg[DWARF_X86_64_R11];
	pt->r12 = dw->reg[DWARF_X86_64_R12];
	pt->r13 = dw->reg[DWARF_X86_64_R13];
	pt->r14 = dw->reg[DWARF_X86_64_R14];
	pt->r15 = dw->reg[DWARF_X86_64_R15];
	pt->ip = dw->reg[DWARF_X86_64_RIP];
#endif
}
