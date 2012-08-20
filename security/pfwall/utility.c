/* This file contains utility functions for the process firewall */

#include <linux/module.h>
#include <linux/wall.h>

#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/signalfd.h>

#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>

#include <asm/param.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/siginfo.h>

// #include "../selinux/include/avc_ss.h"
// #include "../selinux/include/classmap.h"

#include "avc_ss.h"

#define PFWALL_HASH_BITS            16
/* String -> ULong hash */
unsigned long pfwall_hash(unsigned char *str)
{
	unsigned long hash = 0;
	int c;

	while ((c = *str++))
	hash = c + (hash << 6) + (hash << 16) - hash;

	return hash >> (32 - PFWALL_HASH_BITS);
}
EXPORT_SYMBOL(pfwall_hash);


# if 0
/* inotify hook callback - enabled whenever
 * we need context of the inode we are creating -
 * watch placed on p->last_dir_searched */

struct inotify_handle *pfwall_ih;

static void pfwall_handle_ievent(struct inotify_watch *i_watch, u32 wd, u32 mask,
			 u32 cookie, const char *dname, struct inode *inode)
{
//	pfwall_remove_watch_locked(pfwall_ih, i_watch);
}

static void pfwall_destroy_watch(struct inotify_watch *i_watch)
{

}

static const struct inotify_operations pfwall_inotify_ops = {
	.handle_event   = pfwall_handle_ievent,
	.destroy_watch  = pfwall_destroy_watch,
};

/* inotify init */
static int __init pfwall_inotify_init(void)
{
	pfwall_ih = inotify_init(pfwall_inotify_ops);
	if (IS_ERR(pfwall_ih))
		printk(KERN_INFO PFWALL_PFX "Cannot initialize inotify handle\n");
	else
		printk(KERN_INFO PFWALL_PFX "Initialized inotify handle\n");
	return 0;
}

#endif


#define SYNCHRONOUS_MASK \
	(sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
	 sigmask(SIGTRAP) | sigmask(SIGFPE))

unsigned long ___blocked = 0;
pid_t ___blocked_pid = 0;
EXPORT_SYMBOL(___blocked);
EXPORT_SYMBOL(___blocked_pid);

/* Modified to insert a process firewall hook */
int next_signal_to_deliver(struct sigpending *pending, sigset_t *mask,
		int queue, sigset_t *add_mask)
{
	unsigned long i, *s, *m, x;
	int sig = 0;
	int tmp_sig = 0, v = 0;


	s = pending->signal.sig;
	m = mask->sig;

	/*
	 * Handle the first word specially: it contains the
	 * synchronous signals that need to be dequeued first.
	 */
	x = *s &~ *m;
	if (x) {
		if (x & SYNCHRONOUS_MASK)
			x &= SYNCHRONOUS_MASK;

		while (x) {
			tmp_sig = ffz(~x) + 1;
			v = pfwall_check(PF_HOOK_SIGNAL_DELIVER, tmp_sig, queue);
			if (v == 0) {
				sig = tmp_sig;
				break;
			} else if (v == -EACCES) {
				unsigned long and_val = ~(1 << (tmp_sig - 1));
//				current->blocked.sig[0] |= (1 << (tmp_sig - 1));
//				___blocked = tmp_sig;
				___blocked_pid = current->pid;
				x = x & and_val;
				if (tmp_sig <= _NSIG_BPW) {
					add_mask->sig[0] |= sigmask(tmp_sig);
				} else if (tmp_sig > _NSIG_BPW) {
					add_mask->sig[1] |=
						(sigmask(tmp_sig - _NSIG_BPW));
				}
//				x = (x & (~(1 << (_NSIG_BPW - tmp_sig + 1))));
			}
		}

//		sig = ffz(~x) + 1;
		return sig;
	}

	switch (_NSIG_WORDS) {
	default:
		for (i = 1; i < _NSIG_WORDS; ++i) {
			x = *++s &~ *++m;
			if (!x)
				continue;
			sig = ffz(~x) + i*_NSIG_BPW + 1;
			break;
		}
		break;

	case 2:
		x = s[1] &~ m[1];
		if (!x)
			break;
		while (x) {
			tmp_sig = ffz(~x) + _NSIG_BPW + 1;
			v = pfwall_check(PF_HOOK_SIGNAL_DELIVER, tmp_sig, queue);
			if (v == 0) {
				sig = tmp_sig;
				break;
			} else if (v == -EACCES) {
				x &= ~((1 << (tmp_sig - 1 - _NSIG_BPW)));
			}
		}
//		sig = ffz(~x) + _NSIG_BPW + 1;
		break;

	case 1:
		/* Nothing to do */
		break;
	}

	return sig;
}
EXPORT_SYMBOL(next_signal_to_deliver);

/****
 File exported to userspace to get UIDs to see which can be
 an attacker
****/

/* uid_array[x][0] is the UID, [x][1 .. ] are the GID of groups */
uid_t uid_array[MAX_USERS][GRP_MEMB_MAX];

EXPORT_SYMBOL(uid_array);
static DEFINE_MUTEX(node_lock);

static ssize_t
uids_read(struct file *file, char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	char *buf = NULL; /* Allocate a single page for the buf */
	int i, ret;
	if (!(buf = (char*) get_zeroed_page(GFP_KERNEL))) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; uid_array[i]; i++)
		printk(KERN_INFO "attacker: uid: %d\n", uid_array[i][0]);
	strcpy(buf, "See printk buffer\n");
	ret = simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
out:
	if (buf)
		free_page((unsigned long) buf);
	return ret;
}

static ssize_t
uids_write(struct file *filp, const char __user *ubuf,
	size_t cnt, loff_t *ppos)
{
	ssize_t length;
	void *data = NULL;
	int i = 0, j = 0;
	char *runner = NULL;
	char *token = NULL;
	char *p = NULL;
	mutex_lock(&node_lock);

	if (*ppos != 0) {
		/* No partial writes. */
		length = -EINVAL;
		goto out;
	}

	if ((cnt > 64 * 1024 * 1024)
		|| (data = vmalloc(cnt)) == NULL) {
		length = -ENOMEM;
		goto out;
	}

	if ((length = copy_from_user(data, ubuf, cnt)) != 0)
		goto out;
	runner = data;

	while ((token = strsep(&runner, "\n")) && (i < MAX_USERS)) {
		j = 0;
		if (!strcmp(token, ""))
			break;
		while ((p = strsep(&token, " ")) && (j < GRP_MEMB_MAX))
			uid_array[i][j++] = simple_strtoul(p, NULL, 10);
		i++;
	}
out:
	mutex_unlock(&node_lock);
	vfree(data);
	return cnt;
}

static const struct file_operations uids_fops = {
       .write  = uids_write,
       .read   = uids_read,
};

static int __init attacker_init(void)
{
	struct dentry *uids;
	uids = debugfs_create_file("uids", 0600, NULL, NULL, &uids_fops);
	printk(KERN_ALERT "attacker: Initializing\n");

	if(!uids) {
		printk(KERN_ALERT "attacker: Unable to create uids\n");
	}
	return 0;
}
fs_initcall(attacker_init);

#define ATTACK_DIR_PREFIX "/attacker/"
#define ATTACK_EXISTING_FILE_PREFIX "/existing_file"
#define ATTACK_NEW_FILE_PREFIX "/new_file"
#define ATTACK_EXISTING_DIR_PREFIX "/existing_dir"
#define SYMLINK_FILE_INFIX "symlink"
#define HARDLINK_FILE_INFIX "hardlink"

/**
 * get_existing_target_file() - Return /attacker/uid/file_existing_#filename
 * @uid:
 * @filename:
 * @fname: allocated pointer
 * @type: %TYPE_SYMLINK/HARDLINK
 */

char *get_existing_target_file(uid_t uid, char *filename, char *fname, int type)
{
	char uid_str[6];

	sprintf(uid_str, "%d", uid);
	strcpy(fname, ATTACK_DIR_PREFIX);
	strcat(fname, uid_str);
	strcat(fname, ATTACK_EXISTING_FILE_PREFIX);
	strcat(fname, "_");
	strcat(fname, (type == TYPE_SYMLINK) ? SYMLINK_FILE_INFIX : HARDLINK_FILE_INFIX);
	strcat(fname, "_");
	strcat(fname, get_last(filename));

	return fname;
}
EXPORT_SYMBOL(get_existing_target_file);

/**
 * get_existing_target_dir() - /attacker/uid/existing_dir_#filename
 * @uid:
 * @filename:
 * @fname: allocated pointer
 */

char *get_existing_target_dir(uid_t uid, char *filename, char *fname)
{
	char uid_str[6];

	sprintf(uid_str, "%d", uid);
	strcpy(fname, ATTACK_DIR_PREFIX);
	strcat(fname, uid_str);
	strcat(fname, ATTACK_EXISTING_DIR_PREFIX);
	strcat(fname, "_");
	strcat(fname, get_last(filename));

	return fname;
}
EXPORT_SYMBOL(get_existing_target_dir);

/**
 * get_new_target_file() - /attacker/uid/new_file_#filename
 * @uid:
 * @filename:
 * Remember to free returned pointer!
 *
 */

char *get_new_target_file(uid_t uid, char *filename, char *fname)
{
	char uid_str[6];

	sprintf(uid_str, "%d", uid);
	strcpy(fname, ATTACK_DIR_PREFIX);
	strcat(fname, uid_str);
	strcat(fname, ATTACK_NEW_FILE_PREFIX);
	strcat(fname, "_");
	/* TODO: Possible bug page fault: use copy_from_user */
	strcat(fname, get_last(filename));

	return fname;
}
EXPORT_SYMBOL(get_new_target_file);

char __user *get_last(char __user *filename)
{
	char __user *ptr = (char __user *) filename + strlen(filename);
	while ((*ptr != '/') && (ptr != filename))
		ptr--;
	if (*ptr == '/')
		ptr++;
	return ptr;
}
EXPORT_SYMBOL(get_last);

char *existing_target_file = "/etc/attacker/existing_";
EXPORT_SYMBOL(existing_target_file);
char *new_target_file = "/etc/attacker/new_";
EXPORT_SYMBOL(new_target_file);

/* fill a group_info from a user-space array - it must be allocated already
   - kernel version using memcpy instead of copy_from_user */
static int groups_from_list(struct group_info *group_info,
    gid_t __user *grouplist)
{
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < group_info->nblocks; i++) {
		unsigned int cp_count = min(NGROUPS_PER_BLOCK, count);
		unsigned int len = cp_count * sizeof(*grouplist);

		memcpy(group_info->blocks[i], grouplist, len);

		grouplist += NGROUPS_PER_BLOCK;
		count -= cp_count;
	}
	return 0;
}

/* a simple Shell sort - have to duplicate here because kernel/groups.c is
   static */
static void groups_sort(struct group_info *group_info)
{
	int base, max, stride;
	int gidsetsize = group_info->ngroups;

	for (stride = 1; stride < gidsetsize; stride = 3 * stride + 1)
		; /* nothing */
	stride /= 3;

	while (stride) {
		max = gidsetsize - stride;
		for (base = 0; base < max; base++) {
			int left = base;
			int right = left + stride;
			gid_t tmp = GROUP_AT(group_info, right);

			while (left >= 0 && GROUP_AT(group_info, left) > tmp) {
				GROUP_AT(group_info, right) =
				    GROUP_AT(group_info, left);
				right = left;
				left -= stride;
			}
			GROUP_AT(group_info, right) = tmp;
		}
		stride /= 3;
	}
}


/**
 * set_creds() - Change the credentials of current process temporarily
 * @ug_list:		ug_list[0] is uid, ug_list[1] is gid,
 *			ug_list[2 .. ] are supplementary groups.
 * @ret:		Returns the old credentials
 *
 * Set process' credentials to attacker's
 * to see if she can do anything.
 * See nfsd_setuser() in fs/nfsd/auth.c for reference
 */

struct cred *set_creds(uid_t *ug_list)
{
	struct group_info *gi = NULL;
	struct cred *override_cred = NULL;
	const struct cred *old_cred;
	int ret = 0, size = 0, i;

	override_cred = prepare_creds();
	if (!override_cred) {
		ret = -ENOMEM;
		goto out;
	}

	/* Calculate size of supplementary group list */
	for (i = 2; ug_list[i]; i++)
		size++;

	/* Save old credential */
//	old_cred = override_creds(*override_cred);

	/* Set fsuid, fsgid */
	override_cred->fsuid = ug_list[0];
	override_cred->fsgid = (gid_t) ug_list[1];

	/* Set (clear) capabilities */
	cap_clear(override_cred->cap_effective);

	/* Set supplementary groups */
	gi = groups_alloc(size);
	if (!gi) {
		ret = -ENOMEM;
		goto out;
	}
	if (size > 0) {
		ret = groups_from_list(gi, (gid_t *) &ug_list[2]);
		if (ret < 0) {
			printk(KERN_INFO "attacker: groups failed!\n");
			if (gi)
				put_group_info(gi);
			goto out;
		}
		groups_sort(gi);
	}
	ret = set_groups(override_cred, gi);
	if (ret < 0)
		goto out;

	/* Alloc and set_group_info would have ++'ed group_info usage,
	   we don't need our reference (alloc) any more, so when next
	   put_group_info comes along, it will be kfree'd */
	put_group_info(gi);
//	(*override_cred)->group_info = *group_info;

	/* Finally, exchange creds */
	old_cred = override_creds(override_cred);
	put_cred(override_cred);

out:
	return (ret < 0) ? (struct cred *) ERR_PTR(ret) : old_cred;
}
EXPORT_SYMBOL(set_creds);

int first_arg_set[] = {
	__NR_open,
	__NR_creat,
	__NR_link,
	__NR_unlink,
	/* __NR_execve, */
	__NR_chdir,
	__NR_mknod,
	__NR_chmod,
	__NR_mount,
	__NR_utime,
	__NR_access,
	__NR_rename,
	__NR_mkdir,
	__NR_rmdir,
	__NR_chroot,
	__NR_symlink,
	__NR_readlink,
	__NR_uselib,
	__NR_swapon,
	__NR_truncate,
	__NR_statfs,
	__NR_swapoff,
	__NR_quotactl,
	__NR_chown,
	__NR_truncate64,
	__NR_lchown32,
	__NR_mount,
	__NR_pivot_root,
	__NR_utimes,
	__NR_stat,
	__NR_lstat,
	__NR_stat64,
	__NR_lstat64,
	__NR_setxattr,
	__NR_lsetxattr,
	__NR_getxattr,
	__NR_lgetxattr,
	__NR_listxattr,
	__NR_llistxattr,
	__NR_removexattr,
	__NR_lremovexattr,
	__NR_statfs64,
	__NR_symlinkat,
	-1
};

/* System calls for which the second argument is a filename to resolve */
int second_arg_set[] = {
	__NR_inotify_add_watch,
	__NR_openat,
	__NR_mkdirat,
	__NR_mknodat,
	__NR_fchownat,
	__NR_futimesat,
	__NR_fstatat64,
	__NR_unlinkat,
	__NR_renameat,
	__NR_linkat,
	__NR_readlinkat,
	__NR_fchmodat,
	__NR_faccessat,
	__NR_utimensat,
	__NR_name_to_handle_at,
	-1
};

/* System calls checking resource (and namespace bindings), and
   deciding whether to accept the resource or not. */
int check_set[] = {
	__NR_access,
	__NR_stat,
	__NR_lstat,
	__NR_stat64,
	__NR_lstat64,
	__NR_fstatat64,
	__NR_faccessat,
	__NR_statfs,
	__NR_statfs64,
	-1
};

/* System calls creating resources (and thus namespace bindings) */
int create_set[] = {
	/* __NR_open, 2nd - O_CREAT */
	__NR_creat,
	__NR_link, /* second argument */
	__NR_mknod,
	__NR_rename, /* second argument */
	__NR_mkdir,
	__NR_symlink, /* second argument */
	/* __NR_socketcall (bind) */
	/* __NR_openat, 3rd - O_CREAT */
	__NR_mkdirat,
	__NR_mknodat,
	__NR_linkat,
	__NR_symlinkat,
	-1
};

/* System calls using resources (and thus traversing namespace bindings) */
int use_set[] = {
	/* __NR_open, 2nd - ~O_CREAT */
	/* __NR_unlink, */
	/* __NR_execve, */
	__NR_chdir,
	__NR_chmod,
	__NR_mount,
	__NR_utime,
	__NR_rename,
	__NR_rmdir,
	__NR_readlink,
	__NR_truncate,
	__NR_chown,
	__NR_truncate64,
	__NR_lchown32,
	__NR_mount,
	__NR_setxattr,
	__NR_lsetxattr,
	__NR_getxattr,
	__NR_lgetxattr,
	__NR_listxattr,
	__NR_llistxattr,
	__NR_removexattr,
	__NR_lremovexattr,
	__NR_utimes,
	/* __NR_openat, 3rd - ~O_CREAT */
	__NR_fchownat,
	__NR_futimesat,
	/* __NR_unlinkat, */
	__NR_renameat,
	__NR_readlinkat,
	__NR_fchmodat,
	/* __NR_socketcall (connect) */
	-1
};

/* These system calls won't follow the last component if it is a symlink, or will act on the link itself.
   If in this set, LOOKUP_FOLLOW should not be set for the name resolution */
int nosym_set[] = {
	/* __NR_open 2nd - O_NOFOLLOW */
	/* __NR_openat 3rd - O_NOFOLLOW */
	/* __NR_utimensat 4th - AT_SYMLINK_NOFOLLOW */
	/* __NR_linkat 5th - ~AT_SYMLINK_FOLLOW (for first argument) */
	/* __NR_name_to_handle_at 5th - ~AT_SYMLINK_FOLLOW */
	/* __NR_socketcall bind */
	__NR_link, /* second argument */
	__NR_unlink,
	__NR_mknod,
	__NR_rename,
	__NR_mkdir,
	__NR_rmdir,
	__NR_symlink, /* second argument */
	__NR_readlink,
	__NR_lstat,
	__NR_lstat64,
	__NR_lchown32,
	__NR_lsetxattr,
	__NR_lgetxattr,
	__NR_llistxattr,
	__NR_lremovexattr,
	__NR_mkdirat,
	__NR_mknodat,
	__NR_unlinkat,
	__NR_renameat,
	__NR_symlinkat,
	__NR_readlinkat,
	-1
};

int bind_call(int sn)
{
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int call = (int) ptregs->bx;
	if (sn == __NR_socketcall && call == SYS_BIND)
		return 1;
	else
		return 0;

}
EXPORT_SYMBOL(bind_call);

int connect_call(int sn)
{
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int call = (int) ptregs->bx;
	if (sn == __NR_socketcall && call == SYS_CONNECT)
		return 1;
	else
		return 0;

}
EXPORT_SYMBOL(connect_call);
/* Special cases */
static int in_spcs_create_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if ((((sn == __NR_open) && (((int) (ptregs->cx)) & O_CREAT))) ||
		(((sn == __NR_openat) && (((int) (ptregs->dx)) & O_CREAT))) ||
		bind_call(sn))
		return 1;

	return 0;
}

static int in_spcs_use_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if (((sn == __NR_open) && (!(((int) ptregs->cx) & O_CREAT))) ||
		((sn == __NR_openat) && (!(((int) ptregs->dx) & O_CREAT))) ||
		connect_call(sn))
		return 1;

	return 0;
}

static int in_spcs_nosym_set(struct pt_regs *ptregs)
{
	int sn = ptregs->orig_ax;

	if (((sn == __NR_open) && (!(((int) ptregs->cx) & O_NOFOLLOW))) ||
		((sn == __NR_openat) && (((int) ptregs->dx) & O_NOFOLLOW)) ||
		((sn == __NR_utimensat) && (((int) ptregs->si) & AT_SYMLINK_NOFOLLOW)) ||
		((sn == __NR_linkat) && (((int) ptregs->di) & AT_SYMLINK_NOFOLLOW)) ||
		((sn == __NR_name_to_handle_at) && (!(((int) ptregs->di) & AT_SYMLINK_FOLLOW))) ||
		bind_call(sn))
		return 1;

	return 0;
}

int in_set(int sn, int *array)
{
	int i;
	struct pt_regs *ptregs = task_pt_regs(current);

	if ((array == create_set) &&
			(in_spcs_create_set(ptregs)))
		return 1;
	else if ((array == use_set) &&
			(in_spcs_use_set(ptregs)))
		return 1;
	else if ((array == nosym_set) &&
			(in_spcs_nosym_set(ptregs)))
		return 1;

	for (i = 0; array[i] != -1; i++)
		if (sn == array[i])
			return 1;
	return 0;
}
EXPORT_SYMBOL(in_set);

char *tclass_str(u16 tclass)
{
	return secclass_map[tclass-1].name; 
}

char *requested_str(u16 tclass, u32 av)
{
	const char **perms; 
	int i = 0, perm = 1; 

	perms = secclass_map[tclass-1].perms;

	while (i < (sizeof(av) * 8)) {
		if ((perm & av) && perms[i]) {
			return perms[i]; 
		}
		i++;
		perm <<= 1;
	}

	return NULL; 
}
