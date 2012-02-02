#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/suspend.h>
#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/rcupdate.h>
#include <linux/wall.h>
#include <linux/relay.h>
#include <asm/syscall.h>
#include <linux/net.h>

/* This target module keeps a record of the current system call when it is called */
/* For example, if we call this module on every DIR__SEARCH, we get the list of
system calls performing name resolution */

atomic_t pfw_syscalls_invoked[NR_syscalls + 1];
EXPORT_SYMBOL(pfw_syscalls_invoked);
atomic_t pfw_socketcalls_invoked[NR_socketcalls + 1];
EXPORT_SYMBOL(pfw_socketcalls_invoked);

struct pft_syscall_invoked_target {

};

/* Add 1 to the current system call count */
int pft_syscall_invoked_target(struct pf_packet_context *p, void *target_specific_data)
{
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int sn = ptregs->orig_ax; /* Syscall number */

	if (sn >= 0) {
		/* Negative syscall numbers possible. When? */
		atomic_inc(&pfw_syscalls_invoked[sn]);
	}

	/* Socketcall demultiplexes a large number of system calls */
	if (sn == __NR_socketcall) {
		atomic_inc(&pfw_socketcalls_invoked[ptregs->bx]);
	}

	return PF_CONTINUE;
}

static int __init pft_syscall_invoked_target_init(void)
{
	int rc = 0;
	int i;
	struct pft_target_module syscall_invoked_target_module = {
		.list = {NULL, NULL},
		.name = "syscall_invoked",
//		.context_mask = 0,
		.target = &pft_syscall_invoked_target
	};

	printk(KERN_INFO PFWALL_PFX "syscall_invoked target module initializing\n");

	rc = pf_register_target(&syscall_invoked_target_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_target syscall_invoked failed: %d\n", rc);
	}

	/* Initialize array */
	for (i = 0; i <= NR_syscalls; i++)
		pfw_syscalls_invoked[i].counter = 0;

	for (i = 0; i <= NR_socketcalls; i++)
		pfw_socketcalls_invoked[i].counter = 0;

	return rc;
}
module_init(pft_syscall_invoked_target_init);
