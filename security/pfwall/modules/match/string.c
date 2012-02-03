#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
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

bool pft_string_match(struct pf_packet_context *p, void *match_specific_data)
{
	return 1;
}


static int __init pft_string_match_init(void)
{
	int rc = 0;
	struct pft_match_module string_match_module = {
		.list = {NULL, NULL},
		.name = "string",
//		.context_mask = PF_CONTEXT_DATA,
		.match = &pft_string_match
	};

	printk(KERN_INFO PFWALL_PFX "string match module initializing\n");

	rc = pf_register_match(&string_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_match string failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_string_match_init);
