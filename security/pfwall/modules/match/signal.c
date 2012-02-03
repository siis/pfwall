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
#include <linux/signal.h>

/* Match if handler is registered for this signal */
bool pft_signal_match(struct pf_packet_context *p, void *match_specific_data)
{
	int si_code = 0;
	struct sigpending *list = NULL;
	struct sigqueue *q;
	__sighandler_t h = NULL;

	if (current->pid == 1 || current->pid == 0)
		return 0;

	if (p->signo == SIGKILL || p->signo == SIGSTOP)
		return 0;

	h = current->sighand->action[p->signo - 1].sa.sa_handler;
	if (h == SIG_DFL || h == SIG_IGN)
		return 0;

	/* Get the deliverer (code) of the signal */
	if (p->signal_queue == SIGNAL_QUEUE_PRIVATE)
		list = &current->pending;
	else if (p->signal_queue == SIGNAL_QUEUE_SHARED)
		list = &current->signal->shared_pending;

	list_for_each_entry(q, &list->list, list) {
		if (q->info.si_signo == p->signo) {
			si_code = q->info.si_code;
		}
	}

	if (si_code == SI_TKILL || si_code == SI_DETHREAD)
		return 0;

	return 1;
}


static int __init pft_signal_match_init(void)
{
	int rc = 0;
	struct pft_match_module signal_match_module = {
		.list = {NULL, NULL},
		.name = "signal",
		.match = &pft_signal_match
	};

	printk(KERN_INFO PFWALL_PFX "signal match module initializing\n");

	rc = pf_register_match(&signal_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_match signal failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_signal_match_init);
