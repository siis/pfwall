#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
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

struct pft_inode_match
{
	unsigned long inode_number;
};

bool pft_inode_match(struct pf_packet_context *p, void *match_specific_data)
{
	struct pft_inode_match *sm = (struct pft_inode_match *)
				match_specific_data;

	if (p->info.filename_inoden == sm->inode_number)
		return 1;

	return 0;
}


static int __init pft_inode_match_init(void)
{
	int rc = 0;
	struct pft_match_module inode_match_module = {
		.list = {NULL, NULL},
		.name = "inode",
		.match = &pft_inode_match
	};

	printk(KERN_INFO PFWALL_PFX "inode match module initializing\n");

	rc = pf_register_match(&inode_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_match inode failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_inode_match_init);
