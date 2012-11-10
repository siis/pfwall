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
#include <linux/un.h>
#include <linux/log2.h>
#include <linux/stat.h>
#include <linux/syscalls.h>

int pft_resource_context(struct pf_packet_context *p)
{
	int ret = 0;
	mm_segment_t old_fs = get_fs();

	if (!(p->context & PF_CONTEXT_SYSCALL_FILENAME)) {
		ret = pf_context_array[ilog2(PF_CONTEXT_SYSCALL_FILENAME)](p);
		if (ret < 0)
			goto out;
	}

	PFW_SYSCALL(ret = sys_lstat64(p->syscall_filename, &p->stat_res));
	if (ret >= 0)
		p->context |= PF_CONTEXT_RESOURCE;

out:
	return ret;
}

static int __init pft_resource_context_init(void)
{
	int rc = 0;
	rc = pf_register_context(PF_CONTEXT_RESOURCE, &pft_resource_context);
	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "Failed to register resource context module: %d\n", rc);
	}
	return rc;
}
module_init(pft_resource_context_init);
