/*
 * Copyright (c) 2003-2011 Erez Zadok
 * Copyright (c) 2003-2006 Charles P. Wright
 * Copyright (c) 2005-2007 Josef 'Jeff' Sipek
 * Copyright (c) 2005-2006 Junjiro Okajima
 * Copyright (c) 2005      Arun M. Krishnakumar
 * Copyright (c) 2004-2006 David P. Quigley
 * Copyright (c) 2003-2004 Mohammad Nayyer Zubair
 * Copyright (c) 2003      Puja Gupta
 * Copyright (c) 2003      Harikesavan Krishnan
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "adv.h"

/*
 * Find a writeable branch to create new object in.  Checks all writeble
 * branches of the parent inode, from istart to iend order; if none are
 * suitable, also tries branch 0 (which may require a copyup).
 *
 * Return a lower_dentry we can use to create object in, or ERR_PTR.
 */
static struct dentry *find_writeable_branch(struct inode *parent,
					    struct dentry *dentry)
{
	int err = -EINVAL;
	int bindex, istart, iend;
	struct dentry *lower_dentry = NULL;

	istart = ibstart(parent);
	iend = ibend(parent);
	if (istart < 0)
		goto out;

begin:
	for (bindex = istart; bindex <= iend; bindex++) {
		/* skip non-writeable branches */
		err = is_robranch_super(dentry->d_sb, bindex);
		if (err) {
			err = -EROFS;
			continue;
		}
		lower_dentry = advfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry)
			continue;
		/*
		 * check for whiteouts in writeable branch, and remove them
		 * if necessary.
		 */
		err = advfs_check_advfs_unlink_whiteout(dentry, lower_dentry, bindex);
		if (err > 0)	/* ignore if whiteout found and removed */
			err = 0;
		if (err)
			continue;
		/* if get here, we can write to the branch */
		break;
	}
	/*
	 * If istart wasn't already branch 0, and we got any error, then try
	 * branch 0 (which may require copyup)
	 */
	if (err && istart > 0) {
		istart = iend = 0;
		goto begin;
	}

	/*
	 * If we tried even branch 0, and still got an error, abort.  But if
	 * the error was an EROFS, then we should try to copyup.
	 */
	if (err && err != -EROFS)
		goto out;

	/*
	 * If we get here, then check if copyup needed.  If lower_dentry is
	 * NULL, create the entire dentry directory structure in branch 0.
	 */
	if (!lower_dentry) {
		bindex = 0;
		lower_dentry = advfs_create_parents(parent, dentry,
					      dentry->d_name.name, bindex);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			goto out;
		}
	}
	err = 0;		/* all's well */
out:
	if (err)
		return ERR_PTR(err);
	return lower_dentry;
}

static int advfs_create(struct inode *dir, struct dentry *dentry,
			  int mode, struct nameidata *nd_unused)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *parent;
	int valid = 0;
	struct nameidata lower_nd;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;	/* same as what real_lookup does */
		goto out;
	}

	lower_dentry = find_writeable_branch(dir, dentry);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out_unlock;
	}

	err = advfs_init_lower_nd(&lower_nd, LOOKUP_CREATE);
	if (unlikely(err < 0))
		goto out_unlock;
	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode,
			 &lower_nd);
	advfs_release_lower_nd(&lower_nd, err);

	if (!err) {
		err = PTR_ERR(advfs_interpose(dentry, dir->i_sb, 0));
		if (!err) {
			advfs_copy_attr_times(dir);
			fsstack_copy_inode_size(dir,
						lower_parent_dentry->d_inode);
			/* update no. of links on parent directory */
			set_nlink(dir, advfs_get_nlinks(dir));
		}
	}

out_unlock:
	unlock_dir(lower_parent_dentry);
out:
	if (!err) {
		advfs_postcopyup_setmnt(dentry);
		advfs_check_inode(dir);
		advfs_check_dentry(dentry);
	}
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
	return err;
}

/*
 * advfs_lookup is the only special function which takes a dentry, yet we
 * do NOT want to call __advfs_d_revalidate_chain because by definition,
 * we don't have a valid dentry here yet.
 */
static struct dentry *advfs_lookup(struct inode *dir,
				     struct dentry *dentry,
				     struct nameidata *nd_unused)
{
	struct dentry *ret, *parent;
	int err = 0;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);

	/*
	 * As long as we lock/dget the parent, then can skip validating the
	 * parent now; we may have to rebuild this dentry on the next
	 * ->d_revalidate, however.
	 */

	/* allocate dentry private data.  We free it in ->d_release */
	err = advfs_new_dentry_private_data(dentry, ADVFS_DMUTEX_CHILD);
	if (unlikely(err)) {
		ret = ERR_PTR(err);
		goto out;
	}

	ret = advfs_lookup_full(dentry, parent, INTERPOSE_LOOKUP);

	if (!IS_ERR(ret)) {
		if (ret)
			dentry = ret;
		/* lookup_full can return multiple positive dentries */
		if (dentry->d_inode && !S_ISDIR(dentry->d_inode->i_mode)) {
			BUG_ON(dbstart(dentry) < 0);
			advfs_postcopyup_release(dentry);
		}
		advfs_copy_attr_times(dentry->d_inode);
	}

	advfs_check_inode(dir);
	if (!IS_ERR(ret))
		advfs_check_dentry(dentry);
	advfs_check_dentry(parent);
	advfs_unlock_dentry(dentry); /* locked in new_dentry_private data */

out:
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);

	return ret;
}

static int advfs_link(struct dentry *old_dentry, struct inode *dir,
			struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *old_parent, *new_parent;
	char *name = NULL;
	bool valid;

	advfs_read_lock(old_dentry->d_sb, ADVFS_SMUTEX_CHILD);
	old_parent = dget_parent(old_dentry);
	new_parent = dget_parent(new_dentry);
	advfs_double_lock_parents(old_parent, new_parent);
	advfs_double_lock_dentry(old_dentry, new_dentry);

	valid = __advfs_d_revalidate(old_dentry, old_parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}
	if (new_dentry->d_inode) {
		valid = __advfs_d_revalidate(new_dentry, new_parent, false);
		if (unlikely(!valid)) {
			err = -ESTALE;
			goto out;
		}
	}

	lower_new_dentry = advfs_lower_dentry(new_dentry);

	/* check for a whiteout in new dentry branch, and delete it */
	err = advfs_check_advfs_unlink_whiteout(new_dentry, lower_new_dentry,
				    dbstart(new_dentry));
	if (err > 0) {	       /* whiteout found and removed successfully */
		lower_dir_dentry = dget_parent(lower_new_dentry);
		fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
		dput(lower_dir_dentry);
		set_nlink(dir, advfs_get_nlinks(dir));
		err = 0;
	}
	if (err)
		goto out;

	/* check if parent hierachy is needed, then link in same branch */
	if (dbstart(old_dentry) != dbstart(new_dentry)) {
		lower_new_dentry = advfs_create_parents(dir, new_dentry,
						  new_dentry->d_name.name,
						  dbstart(old_dentry));
		err = PTR_ERR(lower_new_dentry);
		if (IS_COPYUP_ERR(err))
			goto docopyup;
		if (!lower_new_dentry || IS_ERR(lower_new_dentry))
			goto out;
	}
	lower_new_dentry = advfs_lower_dentry(new_dentry);
	lower_old_dentry = advfs_lower_dentry(old_dentry);

	BUG_ON(dbstart(old_dentry) != dbstart(new_dentry));
	lower_dir_dentry = lock_parent(lower_new_dentry);
	err = is_robranch(old_dentry);
	if (!err) {
		/* see Documentation/filesystems/advfs/issues.txt */
		lockdep_off();
		err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
			       lower_new_dentry);
		lockdep_on();
	}
	unlock_dir(lower_dir_dentry);

docopyup:
	if (IS_COPYUP_ERR(err)) {
		int old_bstart = dbstart(old_dentry);
		int bindex;

		for (bindex = old_bstart - 1; bindex >= 0; bindex--) {
			err = advfs_copyup_dentry(old_parent->d_inode,
					    old_dentry, old_bstart,
					    bindex, old_dentry->d_name.name,
					    old_dentry->d_name.len, NULL,
					    i_size_read(old_dentry->d_inode));
			if (err)
				continue;
			lower_new_dentry =
				advfs_create_parents(dir, new_dentry,
					       new_dentry->d_name.name,
					       bindex);
			lower_old_dentry = advfs_lower_dentry(old_dentry);
			lower_dir_dentry = lock_parent(lower_new_dentry);
			/* see Documentation/filesystems/advfs/issues.txt */
			lockdep_off();
			/* do vfs_link */
			err = vfs_link(lower_old_dentry,
				       lower_dir_dentry->d_inode,
				       lower_new_dentry);
			lockdep_on();
			unlock_dir(lower_dir_dentry);
			goto check_link;
		}
		goto out;
	}

check_link:
	if (err || !lower_new_dentry->d_inode)
		goto out;

	/* Its a hard link, so use the same inode */
	new_dentry->d_inode = igrab(old_dentry->d_inode);
	d_add(new_dentry, new_dentry->d_inode);
	advfs_copy_attr_all(dir, lower_new_dentry->d_parent->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_parent->d_inode);

	/* propagate number of hard-links */
	set_nlink(old_dentry->d_inode,
		  advfs_get_nlinks(old_dentry->d_inode));
	/* new dentry's ctime may have changed due to hard-link counts */
	advfs_copy_attr_times(new_dentry->d_inode);

out:
	if (!new_dentry->d_inode)
		d_drop(new_dentry);

	kfree(name);
	if (!err)
		advfs_postcopyup_setmnt(new_dentry);

	advfs_check_inode(dir);
	advfs_check_dentry(new_dentry);
	advfs_check_dentry(old_dentry);

	advfs_double_unlock_dentry(old_dentry, new_dentry);
	advfs_double_unlock_parents(old_parent, new_parent);
	dput(new_parent);
	dput(old_parent);
	advfs_read_unlock(old_dentry->d_sb);

	return err;
}

static int advfs_symlink(struct inode *dir, struct dentry *dentry,
			   const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *wh_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *parent;
	char *name = NULL;
	int valid = 0;
	umode_t mode;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}

	/*
	 * It's only a bug if this dentry was not negative and couldn't be
	 * revalidated (shouldn't happen).
	 */
	BUG_ON(!valid && dentry->d_inode);

	lower_dentry = find_writeable_branch(dir, dentry);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out_unlock;
	}

	mode = S_IALLUGO;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (!err) {
		err = PTR_ERR(advfs_interpose(dentry, dir->i_sb, 0));
		if (!err) {
			advfs_copy_attr_times(dir);
			fsstack_copy_inode_size(dir,
						lower_parent_dentry->d_inode);
			/* update no. of links on parent directory */
			set_nlink(dir, advfs_get_nlinks(dir));
		}
	}

out_unlock:
	unlock_dir(lower_parent_dentry);
out:
	dput(wh_dentry);
	kfree(name);

	if (!err) {
		advfs_postcopyup_setmnt(dentry);
		advfs_check_inode(dir);
		advfs_check_dentry(dentry);
	}
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
	return err;
}

static int advfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *parent;
	int bindex = 0, bstart;
	char *name = NULL;
	int valid;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;	/* same as what real_lookup does */
		goto out;
	}

	bstart = dbstart(dentry);

	lower_dentry = advfs_lower_dentry(dentry);

	/* check for a whiteout in new dentry branch, and delete it */
	err = advfs_check_advfs_unlink_whiteout(dentry, lower_dentry, bstart);
	if (err > 0)	       /* whiteout found and removed successfully */
		err = 0;
	if (err) {
		/* exit if the error returned was NOT -EROFS */
		if (!IS_COPYUP_ERR(err))
			goto out;
		bstart--;
	}

	/* check if copyup's needed, and mkdir */
	for (bindex = bstart; bindex >= 0; bindex--) {
		int i;
		int bend = dbend(dentry);

		if (is_robranch_super(dentry->d_sb, bindex))
			continue;

		lower_dentry = advfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry) {
			lower_dentry = advfs_create_parents(dir, dentry,
						      dentry->d_name.name,
						      bindex);
			if (!lower_dentry || IS_ERR(lower_dentry)) {
				printk(KERN_ERR "advfs: lower dentry "
				       " NULL for bindex = %d\n", bindex);
				continue;
			}
		}

		lower_parent_dentry = lock_parent(lower_dentry);

		if (IS_ERR(lower_parent_dentry)) {
			err = PTR_ERR(lower_parent_dentry);
			goto out;
		}

		err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry,
				mode);

		unlock_dir(lower_parent_dentry);

		/* did the mkdir succeed? */
		if (err)
			break;

		for (i = bindex + 1; i <= bend; i++) {
			/* XXX: use path_put_lowers? */
			if (advfs_lower_dentry_idx(dentry, i)) {
				dput(advfs_lower_dentry_idx(dentry, i));
				advfs_set_lower_dentry_idx(dentry, i, NULL);
			}
		}
		dbend(dentry) = bindex;

		/*
		 * Only INTERPOSE_LOOKUP can return a value other than 0 on
		 * err.
		 */
		err = PTR_ERR(advfs_interpose(dentry, dir->i_sb, 0));
		if (!err) {
			advfs_copy_attr_times(dir);
			fsstack_copy_inode_size(dir,
						lower_parent_dentry->d_inode);

			/* update number of links on parent directory */
			set_nlink(dir, advfs_get_nlinks(dir));
		}

		err = advfs_make_dir_opaque(dentry, dbstart(dentry));
		if (err) {
			printk(KERN_ERR "advfs: mkdir: error creating "
			       ".wh.__dir_opaque: %d\n", err);
			goto out;
		}

		/* we are done! */
		break;
	}

out:
	if (!dentry->d_inode)
		d_drop(dentry);

	kfree(name);

	if (!err) {
		advfs_copy_attr_times(dentry->d_inode);
		advfs_postcopyup_setmnt(dentry);
	}
	advfs_check_inode(dir);
	advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);

	return err;
}

static int advfs_mknod(struct inode *dir, struct dentry *dentry, int mode,
			 dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *wh_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *parent;
	char *name = NULL;
	int valid = 0;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}

	/*
	 * It's only a bug if this dentry was not negative and couldn't be
	 * revalidated (shouldn't happen).
	 */
	BUG_ON(!valid && dentry->d_inode);

	lower_dentry = find_writeable_branch(dir, dentry);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out_unlock;
	}

	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (!err) {
		err = PTR_ERR(advfs_interpose(dentry, dir->i_sb, 0));
		if (!err) {
			advfs_copy_attr_times(dir);
			fsstack_copy_inode_size(dir,
						lower_parent_dentry->d_inode);
			/* update no. of links on parent directory */
			set_nlink(dir, advfs_get_nlinks(dir));
		}
	}

out_unlock:
	unlock_dir(lower_parent_dentry);
out:
	dput(wh_dentry);
	kfree(name);

	if (!err) {
		advfs_postcopyup_setmnt(dentry);
		advfs_check_inode(dir);
		advfs_check_dentry(dentry);
	}
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
	return err;
}

/* requires sb, dentry, and parent to already be locked */
static int __advfs_readlink(struct dentry *dentry, char __user *buf,
			      int bufsiz)
{
	int err;
	struct dentry *lower_dentry;

	lower_dentry = advfs_lower_dentry(dentry);

	if (!lower_dentry->d_inode->i_op ||
	    !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_dentry->d_inode);

out:
	return err;
}

static int advfs_readlink(struct dentry *dentry, char __user *buf,
			    int bufsiz)
{
	int err;
	struct dentry *parent;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	if (unlikely(!__advfs_d_revalidate(dentry, parent, false))) {
		err = -ESTALE;
		goto out;
	}

	err = __advfs_readlink(dentry, buf, bufsiz);

out:
	advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);

	return err;
}

static void *advfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;
	struct dentry *parent;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = __advfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = NULL;
		goto out;
	}
	buf[err] = 0;
	nd_set_link(nd, buf);
	err = 0;

out:
	if (err >= 0) {
		advfs_check_nd(nd);
		advfs_check_dentry(dentry);
	}

	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);

	return ERR_PTR(err);
}

/* this @nd *IS* still used */
static void advfs_put_link(struct dentry *dentry, struct nameidata *nd,
			     void *cookie)
{
	struct dentry *parent;
	char *buf;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	if (unlikely(!__advfs_d_revalidate(dentry, parent, false)))
		printk(KERN_ERR
		       "advfs: put_link failed to revalidate dentry\n");

	advfs_check_dentry(dentry);
#if 0
	/* XXX: can't run this check b/c this fxn can receive a poisoned 'nd' PTR */
	advfs_check_nd(nd);
#endif
	buf = nd_get_link(nd);
	if (!IS_ERR(buf))
		kfree(buf);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
}

/*
 * This is a variant of fs/namei.c:permission() or inode_permission() which
 * skips over EROFS tests (because we perform copyup on EROFS).
 */
static int __inode_permission(struct inode *inode, int mask)
{
	int retval;

	/* nobody gets write access to an immutable file */
	if ((mask & MAY_WRITE) && IS_IMMUTABLE(inode))
		return -EACCES;

	/* Ordinary permission routines do not understand MAY_APPEND. */
	if (inode->i_op && inode->i_op->permission) {
		retval = inode->i_op->permission(inode, mask);
		if (!retval) {
			/*
			 * Exec permission on a regular file is denied if none
			 * of the execute bits are set.
			 *
			 * This check should be done by the ->permission()
			 * method.
			 */
			if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode) &&
			    !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	} else {
		retval = generic_permission(inode, mask);
	}
	if (retval)
		return retval;

	return security_inode_permission(inode,
			mask & (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND));
}

/*
 * Don't grab the superblock read-lock in advfs_permission, which prevents
 * a deadlock with the branch-management "add branch" code (which grabbed
 * the write lock).  It is safe to not grab the read lock here, because even
 * with branch management taking place, there is no chance that
 * advfs_permission, or anything it calls, will use stale branch
 * information.
 */
static int advfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode = NULL;
	int err = 0;
	int bindex, bstart, bend;
	int is_file;
	const int write_mask = (mask & MAY_WRITE) && !(mask & MAY_READ);
	struct inode *inode_grabbed;

	inode_grabbed = igrab(inode);
	is_file = !S_ISDIR(inode->i_mode);

	if (!ADVFS_I(inode)->lower_inodes) {
		if (is_file)	/* dirs can be unlinked but chdir'ed to */
			err = -ESTALE;	/* force revalidate */
		goto out;
	}
	bstart = ibstart(inode);
	bend = ibend(inode);
	if (unlikely(bstart < 0 || bend < 0)) {
		/*
		 * With branch-management, we can get a stale inode here.
		 * If so, we return ESTALE back to link_path_walk, which
		 * would discard the dcache entry and re-lookup the
		 * dentry+inode.  This should be equivalent to issuing
		 * __advfs_d_revalidate_chain on nd.dentry here.
		 */
		if (is_file)	/* dirs can be unlinked but chdir'ed to */
			err = -ESTALE;	/* force revalidate */
		goto out;
	}

	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_inode = advfs_lower_inode_idx(inode, bindex);
		if (!lower_inode)
			continue;

		/*
		 * check the condition for D-F-D underlying files/directories,
		 * we don't have to check for files, if we are checking for
		 * directories.
		 */
		if (!is_file && !S_ISDIR(lower_inode->i_mode))
			continue;

		/*
		 * We check basic permissions, but we ignore any conditions
		 * such as readonly file systems or branches marked as
		 * readonly, because those conditions should lead to a
		 * copyup taking place later on.  However, if user never had
		 * access to the file, then no copyup could ever take place.
		 */
		err = __inode_permission(lower_inode, mask);
		if (err && err != -EACCES && err != EPERM && bindex > 0) {
			umode_t mode = lower_inode->i_mode;
			if ((is_robranch_super(inode->i_sb, bindex) ||
			     __is_rdonly(lower_inode)) &&
			    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
				err = 0;
			if (IS_COPYUP_ERR(err))
				err = 0;
		}

		/*
		 * NFS HACK: NFSv2/3 return EACCES on readonly-exported,
		 * locally readonly-mounted file systems, instead of EROFS
		 * like other file systems do.  So we have no choice here
		 * but to intercept this and ignore it for NFS branches
		 * marked readonly.  Specifically, we avoid using NFS's own
		 * "broken" ->permission method, and rely on
		 * generic_permission() to do basic checking for us.
		 */
		if (err && err == -EACCES &&
		    is_robranch_super(inode->i_sb, bindex) &&
		    lower_inode->i_sb->s_magic == NFS_SUPER_MAGIC)
			err = generic_permission(lower_inode, mask);

		/*
		 * The permissions are an intersection of the overall directory
		 * permissions, so we fail if one fails.
		 */
		if (err)
			goto out;

		/* only the leftmost file matters. */
		if (is_file || write_mask) {
			if (is_file && write_mask) {
				err = get_write_access(lower_inode);
				if (!err)
					put_write_access(lower_inode);
			}
			break;
		}
	}
	/* sync times which may have changed (asynchronously) below */
	advfs_copy_attr_times(inode);

out:
	advfs_check_inode(inode);
	iput(inode_grabbed);
	return err;
}

static int advfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *parent;
	struct inode *inode;
	struct inode *lower_inode;
	int bstart, bend, bindex;
	loff_t size;
	struct iattr lower_ia;

	/* check if user has permission to change inode */
	err = inode_change_ok(dentry->d_inode, ia);
	if (err)
		goto out_err;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	if (unlikely(!__advfs_d_revalidate(dentry, parent, false))) {
		err = -ESTALE;
		goto out;
	}

	bstart = dbstart(dentry);
	bend = dbend(dentry);
	inode = dentry->d_inode;

	/*
	 * mode change is for clearing setuid/setgid. Allow lower filesystem
	 * to reinterpret it in its own way.
	 */
	if (ia->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		ia->ia_valid &= ~ATTR_MODE;

	lower_dentry = advfs_lower_dentry(dentry);
	if (!lower_dentry) { /* should never happen after above revalidate */
		err = -EINVAL;
		goto out;
	}

	/*
	 * Get the lower inode directly from lower dentry, in case ibstart
	 * is -1 (which happens when the file is open but unlinked.
	 */
	lower_inode = lower_dentry->d_inode;

	/* check if user has permission to change lower inode */
	err = inode_change_ok(lower_inode, ia);
	if (err)
		goto out;

	/* copyup if the file is on a read only branch */
	if (is_robranch_super(dentry->d_sb, bstart)
	    || __is_rdonly(lower_inode)) {
		/* check if we have a branch to copy up to */
		if (bstart <= 0) {
			err = -EACCES;
			goto out;
		}

		if (ia->ia_valid & ATTR_SIZE)
			size = ia->ia_size;
		else
			size = i_size_read(inode);
		/* copyup to next available branch */
		for (bindex = bstart - 1; bindex >= 0; bindex--) {
			err = advfs_copyup_dentry(parent->d_inode,
					    dentry, bstart, bindex,
					    dentry->d_name.name,
					    dentry->d_name.len,
					    NULL, size);
			if (!err)
				break;
		}
		if (err)
			goto out;
		/* get updated lower_dentry/inode after copyup */
		lower_dentry = advfs_lower_dentry(dentry);
		lower_inode = advfs_lower_inode(inode);
		/*
		 * check for whiteouts in writeable branch, and remove them
		 * if necessary.
		 */
		if (lower_dentry) {
			err = advfs_check_advfs_unlink_whiteout(dentry, lower_dentry,
						    bindex);
			if (err > 0) /* ignore if whiteout found and removed */
				err = 0;
		}
	}

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		size = i_size_read(inode);
		if (ia->ia_size < size || (ia->ia_size > size &&
		    inode->i_sb->s_maxbytes < lower_inode->i_sb->s_maxbytes)) {
			err = vmtruncate(inode, ia->ia_size);
			if (err)
				goto out;
		}
	}

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	/* prepare our own lower struct iattr (with our own lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE) {
		lower_ia.ia_file = advfs_lower_file(ia->ia_file);
		BUG_ON(!lower_ia.ia_file); // XXX?
	}

	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the first lower inode */
	if (ibstart(inode) >= 0)
		advfs_copy_attr_all(inode, lower_inode);
	/*
	 * advfs_copy_attr_all will copy the lower times to our inode if
	 * the lower ones are newer (useful for cache coherency).  However,
	 * ->setattr is the only place in which we may have to copy the
	 * lower inode times absolutely, to support utimes(2).
	 */
	if (ia->ia_valid & ATTR_MTIME_SET)
		inode->i_mtime = lower_inode->i_mtime;
	if (ia->ia_valid & ATTR_CTIME)
		inode->i_ctime = lower_inode->i_ctime;
	if (ia->ia_valid & ATTR_ATIME_SET)
		inode->i_atime = lower_inode->i_atime;
	fsstack_copy_inode_size(inode, lower_inode);

out:
	if (!err)
		advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
out_err:
	return err;
}

struct inode_operations advfs_symlink_iops = {
	.readlink	= advfs_readlink,
	.permission	= advfs_permission,
	.follow_link	= advfs_follow_link,
	.setattr	= advfs_setattr,
	.put_link	= advfs_put_link,
};

struct inode_operations advfs_dir_iops = {
	.create		= advfs_create,
	.lookup		= advfs_lookup,
	.link		= advfs_link,
	.unlink		= advfs_unlink,
	.symlink	= advfs_symlink,
	.mkdir		= advfs_mkdir,
	.rmdir		= advfs_rmdir,
	.mknod		= advfs_mknod,
	.rename		= advfs_rename,
	.permission	= advfs_permission,
	.setattr	= advfs_setattr,
#ifdef CONFIG_ADV_FS_XATTR
	.setxattr	= advfs_setxattr,
	.getxattr	= advfs_getxattr,
	.removexattr	= advfs_removexattr,
	.listxattr	= advfs_listxattr,
#endif /* CONFIG_ADV_FS_XATTR */
};

struct inode_operations advfs_main_iops = {
	.permission	= advfs_permission,
	.setattr	= advfs_setattr,
#ifdef CONFIG_ADV_FS_XATTR
	.setxattr	= advfs_setxattr,
	.getxattr	= advfs_getxattr,
	.removexattr	= advfs_removexattr,
	.listxattr	= advfs_listxattr,
#endif /* CONFIG_ADV_FS_XATTR */
};
