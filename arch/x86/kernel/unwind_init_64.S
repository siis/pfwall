
#include <linux/linkage.h>
#include <asm/ptrace-abi.h>
#include <asm/unwind.h>

	.code64
ENTRY(unw_init)
	/* Callee saved: RBX, RBP, R12-R15  */
	movq %r12, R12(%rdi)
	movq %r13, R13(%rdi)
	movq %r14, R14(%rdi)
	movq %r15, R15(%rdi)
	movq %rbp, RBP(%rdi)
	movq %rbx, RBX(%rdi)

	movq %r8,  R8(%rdi)
	movq %r9,  R9(%rdi)
	movq %rdi, RDI(%rdi)
	movq %rsi, RSI(%rdi)
	movq %rdx, RDX(%rdi)
	movq %rax, RAX(%rdi)
	movq %rcx, RCX(%rdi)

	leaq 8(%rsp), %rax /* exclude this call.  */
	movq %rax, UNW_X86_64_CFA_OFF(%rdi)
	movq 0(%rsp), %rax
	movq %rax, RIP(%rdi)

	xorq %rax, %rax
	retq
END(unw_init)
