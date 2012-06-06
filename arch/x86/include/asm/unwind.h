#ifndef _ARCH_X86_KERNEL_UNWIND_H
#define _ARCH_X86_KERNEL_UNWIND_H

#include <asm/ptrace-abi.h>

#ifdef __ASSEMBLY__
#ifdef __i386__
#define UNW_X86_CFA_OFF 	(FRAME_SIZE + 0x0)
#else
#define UNW_X86_64_CFA_OFF 	(FRAME_SIZE + 0x0)
#endif /* __i386__ */
#endif /* __ASSEMBLY__ */

#endif  /* _ARCH_X86_KERNEL_UNWIND_H */
