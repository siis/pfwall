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
#include <linux/syscalls.h>
#include <linux/stat.h>
#include <linux/lsm_audit.h>
#include <linux/fs.h>
#include <linux/namei.h>

#if 0
/* TODO: follow as flag */
int pft_match_attacker_marked(struct pf_packet_context *p, void *match_specific_data)
{
	int tret = 1; /* Not marked */
	char *xattr_list = NULL;
	size_t size = 0;
	char *ptr = NULL;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	current->kernel_request++;
//	if (!follow) {
	size = sys_llistxattr(p->syscall_filename, xattr_list, 0);
	if (((int) size) < 0) {
		/* Some error */
		goto out;
	}
	xattr_list = kzalloc(size, GFP_ATOMIC);
	if (!xattr_list)
		goto out;
	tret = sys_llistxattr(p->syscall_filename, xattr_list, size);
	# if 0
	} else {
		size = sys_listxattr(filename, xattr_list, 0);
		if (((int) size) < 0) {
			/* Some error */
			goto out;
		}
		xattr_list = kzalloc(size, GFP_ATOMIC);
		if (!xattr_list)
			goto out;
		tret = sys_listxattr(filename, xattr_list, size);
	}
	#endif
	current->kernel_request--;
	set_fs(old_fs);
	if (tret == -ENOTSUPP) {
		printk(KERN_INFO PFWALL_PFX "Xattrs not supported!\n");
		goto out;
	} else if (tret < 0)
		goto out;
	ptr = xattr_list;
	tret = 1; /* Not marked */
	while (ptr < xattr_list + size) {
		if (!ptr) /* In between keys - shouldn't happen! */
			continue;
		if (!strcmp(ptr, ATTACKER_XATTR_STRING)) {
			tret = 0;
			break;
		} else /* Jump to next key */
			ptr += strlen(ptr) + 1;
	}

out:
	if (xattr_list)
		kfree(xattr_list);
	return (tret == 0) ? 1 : 0;
}
#endif


/**
 * Use the current resource being accessed, from the dentry object, to determine the
 * xattr; NOT the filename in the initial system call -- that won't be able to
 * track non-filename resolution system calls such as read().
 */

int pft_match_attacker_marked(struct pf_packet_context *p, void *match_specific_data)
{
	int error = 0;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	char value[4]; /* The value set should be "1" */

	if (p->auditdata) {
		switch (p->auditdata->type) {
		case LSM_AUDIT_DATA_FS:
			if (p->auditdata->u.fs.path.dentry) {
				dentry = p->auditdata->u.fs.path.dentry;
				inode = dentry->d_inode;
			} else if (p->auditdata->u.fs.inode) {
				inode = p->auditdata->u.fs.inode;
				dentry = d_find_alias(inode);
			}

		break;
		default:
			;
		}
	}
	if (dentry && inode && inode->i_op->getxattr)
		error = inode->i_op->getxattr(dentry, ATTACKER_XATTR_STRING, value, 4);

	if (error <= 0) {
		/* What to do? */
	}

	return (error > 0 || error == -ERANGE) ? 1 : 0;

}
EXPORT_SYMBOL(pft_match_attacker_marked);

static int __init pft_attacker_marked_match_init(void)
{
	int rc = 0;
	struct pft_match_module attacker_marked_match_module = {
		.list = {NULL, NULL},
		.name = "attacker_marked",
//		.context_mask = PF_CONTEXT_FILENAME,
		.match = &pft_match_attacker_marked
	};

	printk(KERN_INFO PFWALL_PFX "attacker marked match module initializing\n");
	rc = pf_register_match(&attacker_marked_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pft_attacker_marked_match_init failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_attacker_marked_match_init);
