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
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/cred.h>

struct pft_permission_match
{
	int flags;
};

#if 0
/* This module matches if there exists a user A such that
	A has access to the (1) file being requested, and
	(2) A is not what the current process is running as */

/* Imported sys_access to determine if the current UID has access -
	the access needed to be checked will be given as arguments,
	and depends on the system call */
static int access_wo_fsuid(const char* filename, int mode)
{
	const struct cred *old_cred;
	struct cred *override_cred;
	struct path path;
	struct inode *inode;
	int res;
	int dfd = AT_FDCWD;
	int attacker_uid;
	struct nameidata nd;

	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
		return -EINVAL;

	override_cred = prepare_creds();
	if (!override_cred)
		return -ENOMEM;


//	old_cred = override_creds(override_cred);

	foreach(potential attacker attacker_uid) {
//		override_cred->fsuid = override_cred->attacker_uid;
//		override_cred->fsgid = override_cred->attacker_uid;
//		cap_clear(override_cred->cap_effective);

//		override_creds(override_cred);

		res = do_path_lookup(dfd, filename, LOOKUP_FOLLOW, &nd);
		if (!res)
			path = nd.path;
		else
			goto out;

		inode = path.dentry->d_inode;

		if ((mode & MAY_EXEC) && S_ISREG(inode->i_mode)) {
			/*
			 * MAY_EXEC on regular files is denied if the fs is mounted
			 * with the "noexec" flag.
			 */
			res = -EACCES;
			if (path.mnt->mnt_flags & MNT_NOEXEC) {
				path_put(&path);
				continue;
			}
		}

		res = inode_permission(inode, mode | MAY_ACCESS);
		/* SuS v2 requires we report a read only fs too */
		if (res || !(mode & S_IWOTH) || special_file(inode->i_mode)) {
			path_put(&path);
			continue;
		}
		/*
		 * This is a rare case where using __mnt_is_readonly()
		 * is OK without a mnt_want/drop_write() pair.  Since
		 * no actual write to the fs is performed here, we do
		 * not need to telegraph to that to anyone.
		 *
		 * By doing this, we accept that this access is
		 * inherently racy and know that the fs may change
		 * state before we even see this result.
		 */
		if (__mnt_is_readonly(path.mnt))
			res = -EROFS;

		path_put(&path);

		if (!res) { /* Found an attacker! */
//			*attacker = attacker_uid;
			break;
		}
	}
out:
	revert_creds(old_cred);
	put_cred(override_cred);
	return res;
}
#endif

static inline int check_sticky(struct inode *dir, struct inode *inode)
{
	uid_t fsuid = current_fsuid();

	if (!(dir->i_mode & S_ISVTX))
		return 0;
	if (inode->i_uid == fsuid)
		return 0;
	if (dir->i_uid == fsuid)
		return 0;
	return !capable(CAP_FOWNER);
}

static inline int may_create_noexist(struct inode *dir, struct dentry *child)
{
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}

static int may_delete(struct inode *dir,struct dentry *victim,int isdir)
{
	int error;

	if (!victim->d_inode)
		return -ENOENT;

	BUG_ON(victim->d_parent->d_inode != dir);

	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;
	if (check_sticky(dir, victim->d_inode)||IS_APPEND(victim->d_inode)||
	    IS_IMMUTABLE(victim->d_inode) || IS_SWAPFILE(victim->d_inode))
		return -EPERM;
	if (isdir) {
		if (!S_ISDIR(victim->d_inode->i_mode))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (S_ISDIR(victim->d_inode->i_mode))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

#define ND_INODE(nd) nd.path.dentry->d_inode

/**
 * pft_get_uid_with_permission() - Does there exist a uid with @flags permission on @filename?
 * @flags: %ATTACKER_BIND, %ATTACKER_PREBIND
 * @filename: name of file to check permissions on
 *
 * Returns uid if an attacker exists, 0 if not, -errno if error.
 */

uid_t pft_get_uid_with_permission(int flags, char *filename)
{
	int ret = 0, i, f_exist = -1, match = 0;
	char *tmp;
	/* TODO: Collapse p_nd and f_nd into one */
	struct nameidata p_nd, f_nd;
	struct cred *old_cred;
	struct dentry *fdentry;

	/* If no filename, exit immediately */
	if (!filename)
		goto out;
	/* Copy userspace string to kernel */
	tmp = getname(filename);
	if (IS_ERR(tmp)) {
		ret = PTR_ERR(tmp);
		goto out;
	}

	/* If parent directory doesn't exist, exit immediately */
	ret = path_lookup(tmp, LOOKUP_PARENT, &p_nd);
	if (ret) {
		/* Error */
//		if (ret == -ENOENT)
//			printk(KERN_INFO PFWALL_PFX "Directory creation: %s required for process: %s\n", filename, current->comm);
		goto out_release_path;
	}

	/* Check if file already exists */
	ret = path_lookup(tmp, LOOKUP_FOLLOW, &f_nd);
	if (ret < 0 && ret != -ENOENT)
		goto out_unlock;
	else if (ret == -ENOENT) {
		f_exist = 0;
		/* Create a dentry for the new file */
		fdentry = lookup_create(&p_nd, 0);
		if (IS_ERR(fdentry)) {
			mutex_unlock(&p_nd.path.dentry->d_inode->i_mutex);
			ret = PTR_ERR(fdentry);
			goto out_release_path;
		}
	} else {
		fdentry = f_nd.path.dentry;
		f_exist = 1;
	}

	/* For each possible attacker */
	for (i = 0; uid_array[i][0]; i++) {
		if (current->cred->fsuid == uid_array[i][0])
			continue;

		/* Change creds to possible attacker's */
		old_cred = set_creds(uid_array[i]);

		if (flags & ATTACKER_BIND) {
			if (f_exist) {
				/* The file exists already, check delete permission */
				if (S_ISDIR(fdentry->d_inode->i_mode))
					ret = may_delete(fdentry->d_parent->d_inode, fdentry, 1);
				else
					ret = may_delete(fdentry->d_parent->d_inode, fdentry, 0);
				if (ret)
					goto next_iter;
			}
		}

		if ((flags & ATTACKER_BIND) || (flags & ATTACKER_PREBIND)) {
			/* Check creation, disregarding actual file existence */
			ret = may_create_noexist(fdentry->d_parent->d_inode, fdentry);
			if (ret)
				goto next_iter;
		}

		/* If we come here, success */
		match = 1;
next_iter:
		/* Revert original creds */
		revert_creds(old_cred);
		if (match == 1)
			break;
	}

out_unlock:
	if (!f_exist) {
		mutex_unlock(&p_nd.path.dentry->d_inode->i_mutex);
		path_put(&p_nd.path);
		dput(fdentry);
	} else if (f_exist == 1) {
		path_put(&p_nd.path);
		path_put(&f_nd.path);
	}

out_release_path:
	putname(tmp);
out:
	if (ret < 0)
		return ret;
	else if (match == 1)
		return i; /* Index in uid array */
	else /* match == 0 */
		return NO_MATCH;
}
EXPORT_SYMBOL(pft_get_uid_with_permission);

/* Check permission for any component of path for create/delete, for
	others, just the resource. */
bool pft_permission_match(struct pf_packet_context *p, void *match_specific_data)
{
	struct pft_permission_match *pm = (struct pft_permission_match *) match_specific_data;
	uid_t u = pft_get_uid_with_permission(pm->flags, p->syscall_filename);
	if (u == NO_MATCH)
		return 0;
	else if (u < 0) /* Error */
		return 0;
	else /* some uid matched */
		return 1;
}

static int __init pft_permission_match_init(void)
{
	int rc = 0;
	struct pft_match_module permission_match_module = {
		.list = {NULL, NULL},
		.name = "permission",
		.match = &pft_permission_match
	};

	printk(KERN_INFO PFWALL_PFX "permission match module initializing\n");

	rc = pf_register_match(&permission_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_match permission failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_permission_match_init);
