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

int pft_data_context(struct pf_packet_context *p)
{
	/* Only in the case of read operations do we actually want to
	* postpone */
	/*
	((p->info.tclass == SECCLASS_FILE && p->info.requested == FILE__READ) ||
	(p->info.tclass == SECCLASS_IPC && p->info.requested == IPC__READ))
	*/
	/* TODO: Proper handling of permissions */
	# if 0
	if (p->hook < PF_HOOK_READ &&
		((p->info.tclass == 6 && p->info.requested == 2UL) ||
		(p->info.tclass == 29 && p->info.requested == 0x10UL))
	   ) {
		return
	}
	#endif
	return 0;
}

static int __init pft_data_context_init(void)
{
	int rc = 0;
	rc = pf_register_context(PF_CONTEXT_DATA, &pft_data_context);
	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "Failed to register syscall context module: %d\n", rc);
	}
	return rc;
}
module_init(pft_data_context_init);
