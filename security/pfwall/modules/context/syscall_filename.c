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

/* For socketcalls */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[20] = {
	AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
	AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
	AL(6),AL(2),AL(5),AL(5),AL(3),AL(3),
	AL(4),AL(5)
};

int pft_syscall_filename_context(struct pf_packet_context *p)
{
	int ret = 0, nr_arg = 0;
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int sn = ptregs->orig_ax; /* Syscall number */
	struct sockaddr_un *sock = NULL;

	if (in_set(sn, first_arg_set))
		nr_arg = 1;
	else if (in_set(sn, second_arg_set))
		nr_arg = 2;

	switch(nr_arg) {
		case 1:
			p->syscall_filename = (char __user *) ptregs->bx;
			break;
		case 2:
			p->syscall_filename = (char __user *) ptregs->cx;
			break;
		default:
			/* Not in list of syscalls performing nameres */
			p->syscall_filename = NULL;
	}

	/* Handle socketcall specially, and only for AF_UNIX */
	/* Currently, we handle only bind and connect */
	if (sn == __NR_socketcall) {
		unsigned long a[6];
		unsigned int len;
		int call = ptregs->bx;
		unsigned long __user *args = (unsigned long __user *) ptregs->cx;

		if (call < 1 || call > SYS_RECVMMSG) {
			ret = -EINVAL;
			goto out;
		}

		len = nargs[call];
		if (len > sizeof(a)) {
			ret = -EFAULT;
			goto out;
		}

		/* copy_from_user should be SMP safe. */
		if (copy_from_user(a, args, len)) {
			ret = -EFAULT;
			goto out;
		}

		switch(ptregs->bx) {
			case SYS_BIND:
			case SYS_CONNECT:
				sock = kmalloc(sizeof(struct sockaddr_un), GFP_ATOMIC);
				if (!sock)
					goto out;
				if (copy_from_user(sock, (const void __user *) a[1],
					sizeof(struct sockaddr))) {
					ret = -EFAULT;
					goto out_free;
				}
				if (((struct sockaddr *) sock)->sa_family == AF_UNIX) {
					p->syscall_filename = (char __user *)
						((struct sockaddr_un __user *) a[1])->sun_path;
					/* TODO: Why does this happen? */
					if (!strcmp(p->syscall_filename, ""))
						p->syscall_filename = NULL;
					#if 0
					if (copy_from_user(sock, (const void __user *) a[1],
						sizeof(struct sockaddr_un))) {
						ret = -EFAULT;
						goto out_free;
					}
					p->syscall_filename = (char __user *) (sock->sun_path);
					#endif
				}
				break;
			default:
				;
		}
	}

out_free:
	if (sock)
		kfree(sock);
out:
	return 0;
}

static int __init pft_syscall_filename_context_init(void)
{
	int rc = 0;
	rc = pf_register_context(PF_CONTEXT_SYSCALL_FILENAME, &pft_syscall_filename_context);
	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "Failed to register syscall filename context module: %d\n", rc);
	}
	return rc;
}
module_init(pft_syscall_filename_context_init);
