#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/hardirq.h>
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

#define PF_SYSCALL_STRING 1
#define PF_SYSCALL_INT	  2

#define PF_SYSCALL_STR_MAX 128

struct pft_syscall_match
{
	int arg_num;
	int offset;
	int type;
	int equal;
	union {
		int test_value_int;
		char test_value_str[128];
	} v;
};

bool pft_syscall_match(struct pf_packet_context *p, void *match_specific_data)
{
	struct pft_syscall_match *sm = (struct pft_syscall_match *)
				match_specific_data;

	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));

	int value = 0;
	char *value_ptr;

	switch(sm->arg_num) {
		case -1:
			value = ptregs->ax; /* Ret val / syscall number */
			break;
		case 0:
			value = ptregs->orig_ax; /* System call number */
			break;
		case 1:
			value = ptregs->bx; /* Parameter start */
			break;
		case 2:
			value = ptregs->cx;
			break;
		case 3:
			value = ptregs->dx;
			break;
		case 4:
			value = ptregs->si;
			break;
		case 5:
			value = ptregs->di;
			break;
		case 6:
			value = ptregs->bp;
			break;
	}

	value_ptr = (char *) value + sm->offset;
//	value = *value_ptr;

	// Hack for open() check
	/*
	if (value == ptregs->cx) {
		if (!(value & O_EXCL) && (value & O_CREAT))
			return 1;
	}
	*/
	if (sm->type == PF_SYSCALL_INT) {
		if (sm->offset > 0)
			value = *value_ptr;
		if (!(sm->equal ^ (sm->v.test_value_int == value)))
			return 1;
		else
			return 0;
	} else if (sm->type == PF_SYSCALL_STRING) {
		if (!((sm->equal) ^ (!strcmp(sm->v.test_value_str, value_ptr))))
			return 1;
		else
			return 0;
	}
	/* Should not come here */
	printk(KERN_INFO PFWALL_PFX "Error in syscall match module\n");

	return 1;
}


static int __init pft_syscall_match_init(void)
{
	int rc = 0;
	struct pft_match_module syscall_match_module = {
		.list = {NULL, NULL},
		.name = "syscall",
//		.context_mask = 0,
		.match = &pft_syscall_match
	};

	printk(KERN_INFO PFWALL_PFX "syscall match module initializing\n");

	rc = pf_register_match(&syscall_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_match syscall failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_syscall_match_init);
