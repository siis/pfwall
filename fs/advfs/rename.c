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
 * This is a helper function for rename, used when rename ends up with hosed
 * over dentries and we need to revert.
 */
static int advfs_refresh_lower_dentry(struct dentry *dentry,
					struct dentry *parent, int bindex)
{
	struct dentry *lower_dentry;
	struct dentry *lower_parent;
	int err = 0;
	struct nameidata lower_nd;

	verify_locked(dentry);

	lower_parent = advfs_lower_dentry_idx(parent, bindex);

	BUG_ON(!S_ISDIR(lower_parent->d_inode->i_mode));

	err = advfs_init_lower_nd(&lower_nd, LOOKUP_OPEN);
	if (unlikely(err < 0))
		goto out;
	lower_dentry = lookup_one_len_nd(dentry->d_name.name, lower_parent,
					 dentry->d_name.len, &lower_nd);
	advfs_release_lower_nd(&lower_nd, err);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out;
	}

	dput(advfs_lower_dentry_idx(dentry, bindex));
	iput(advfs_lower_inode_idx(dentry->d_inode, bindex));
	advfs_set_lower_inode_idx(dentry->d_inode, bindex, NULL);

	if (!lower_dentry->d_inode) {
		dput(lower_dentry);
		advfs_set_lower_dentry_idx(dentry, bindex, NULL);
	} else {
		advfs_set_lower_dentry_idx(dentry, bindex, lower_dentry);
		advfs_set_lower_inode_idx(dentry->d_inode, bindex,
					    igrab(lower_dentry->d_inode));
	}

out:
	return err;
}

static int __advfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			    struct dentry *old_parent,
			    struct inode *new_dir, struct dentry *new_dentry,
			    struct dentry *new_parent,
			    int bindex)
{
	int err = 0;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct dentry *trap;

	lower_new_dentry = advfs_lower_dentry_idx(new_dentry, bindex);
	lower_old_dentry = advfs_lower_dentry_idx(old_dentry, bindex);

	if (!lower_new_dentry) {
		lower_new_dentry =
			advfs_create_parents(new_parent->d_inode,
				       new_dentry, new_dentry->d_name.name,
				       bindex);
		if (IS_ERR(lower_new_dentry)) {
			err = PTR_ERR(lower_new_dentry);
			if (IS_COPYUP_ERR(err))
				goto out;
			printk(KERN_ERR "advfs: error creating directory "
			       "tree for rename, bindex=%d err=%d\n",
			       bindex, err);
			goto out;
		}
	}

	/* check for and remove whiteout, if any */
	err = advfs_check_advfs_unlink_whiteout(new_dentry, lower_new_dentry, bindex);
	if (err > 0) /* ignore if whiteout found and successfully removed */
		err = 0;
	if (err)
		goto out;

	/* check of old_dentry branch is writable */
	err = is_robranch_super(old_dentry->d_sb, bindex);
	if (err)
		goto out;

	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancenstor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out_err_unlock;
	}
	/* target should not be ancenstor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out_err_unlock;
	}
	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry);
out_err_unlock:
	if (!err) {
		/* update parent dir times */
		fsstack_copy_attr_times(old_dir, lower_old_dir_dentry->d_inode);
		fsstack_copy_attr_times(new_dir, lower_new_dir_dentry->d_inode);
	}
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);

	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	dput(lower_old_dentry);
	dput(lower_new_dentry);

out:
	if (!err) {
		/* Fixup the new_dentry. */
		if (bindex < dbstart(new_dentry))
			dbstart(new_dentry) = bindex;
		else if (bindex > dbend(new_dentry))
			dbend(new_dentry) = bindex;
	}

	return err;
}

/*
 * Main rename code.  This is sufficiently complex, that it's documented in
 * Documentation/filesystems/advfs/rename.txt.  This routine calls
 * __advfs_rename() above to perform some of the work.
 */
static int do_advfs_rename(struct inode *old_dir,
			     struct dentry *old_dentry,
			     struct dentry *old_parent,
			     struct inode *new_dir,
			     struct dentry *new_dentry,
			     struct dentry *new_parent)
{
	int err = 0;
	int bindex;
	int old_bstart, old_bend;
	int new_bstart, new_bend;
	int do_copyup = -1;
	int local_err = 0;
	int eio = 0;
	int revert = 0;

	old_bstart = dbstart(old_dentry);
	old_bend = dbend(old_dentry);

	new_bstart = dbstart(new_dentry);
	new_bend = dbend(new_dentry);

	/* Rename source to destination. */
	err = __advfs_rename(old_dir, old_dentry, old_parent,
			       new_dir, new_dentry, new_parent,
			       old_bstart);
	if (err) {
		if (!IS_COPYUP_ERR(err))
			goto out;
		do_copyup = old_bstart - 1;
	} else {
		revert = 1;
	}

	/*
	 * Unlink all instances of destination that exist to the left of
	 * bstart of source. On error, revert back, goto out.
	 */
	for (bindex = old_bstart - 1; bindex >= new_bstart; bindex--) {
		struct dentry *unlink_dentry;
		struct dentry *unlink_dir_dentry;

		BUG_ON(bindex < 0);
		unlink_dentry = advfs_lower_dentry_idx(new_dentry, bindex);
		if (!unlink_dentry)
			continue;

		unlink_dir_dentry = lock_parent(unlink_dentry);
		err = is_robranch_super(old_dir->i_sb, bindex);
		if (!err)
			err = vfs_unlink(unlink_dir_dentry->d_inode,
					 unlink_dentry);

		fsstack_copy_attr_times(new_parent->d_inode,
					unlink_dir_dentry->d_inode);
		/* propagate number of hard-links */
		set_nlink(new_parent->d_inode,
			  advfs_get_nlinks(new_parent->d_inode));

		unlock_dir(unlink_dir_dentry);
		if (!err) {
			if (bindex != new_bstart) {
				dput(unlink_dentry);
				advfs_set_lower_dentry_idx(new_dentry,
							     bindex, NULL);
			}
		} else if (IS_COPYUP_ERR(err)) {
			do_copyup = bindex - 1;
		} else if (revert) {
			goto revert;
		}
	}

	if (do_copyup != -1) {
		for (bindex = do_copyup; bindex >= 0; bindex--) {
			/*
			 * copyup the file into some left directory, so that
			 * you can rename it
			 */
			err = advfs_copyup_dentry(old_parent->d_inode,
					    old_dentry, old_bstart, bindex,
					    old_dentry->d_name.name,
					    old_dentry->d_name.len, NULL,
					    i_size_read(old_dentry->d_inode));
			/* if copyup failed, try next branch to the left */
			if (err)
				continue;
			/*
			 * create whiteout before calling __advfs_rename
			 * because the latter will change the old_dentry's
			 * lower name and parent dir, resulting in the
			 * whiteout getting created in the wrong dir.
			 */
			err = advfs_create_whiteout(old_dentry, bindex);
			if (err) {
				printk(KERN_ERR "advfs: can't create a "
				       "whiteout for %s in rename (err=%d)\n",
				       old_dentry->d_name.name, err);
				continue;
			}
			err = __advfs_rename(old_dir, old_dentry, old_parent,
					       new_dir, new_dentry, new_parent,
					       bindex);
			break;
		}
	}

	/* make it opaque */
	if (S_ISDIR(old_dentry->d_inode->i_mode)) {
		err = advfs_make_dir_opaque(old_dentry, dbstart(old_dentry));
		if (err)
			goto revert;
	}

	/*
	 * Create whiteout for source, only if:
	 * (1) There is more than one underlying instance of source.
	 * (We did a copy_up is taken care of above).
	 */
	if ((old_bstart != old_bend) && (do_copyup == -1)) {
		err = advfs_create_whiteout(old_dentry, old_bstart);
		if (err) {
			/* can't fix anything now, so we exit with -EIO */
			printk(KERN_ERR "advfs: can't create a whiteout for "
			       "%s in rename!\n", old_dentry->d_name.name);
			err = -EIO;
		}
	}

out:
	return err;

revert:
	/* Do revert here. */
	local_err = advfs_refresh_lower_dentry(new_dentry, new_parent,
						 old_bstart);
	if (local_err) {
		printk(KERN_ERR "advfs: revert failed in rename: "
		       "the new refresh failed\n");
		eio = -EIO;
	}

	local_err = advfs_refresh_lower_dentry(old_dentry, old_parent,
						 old_bstart);
	if (local_err) {
		printk(KERN_ERR "advfs: revert failed in rename: "
		       "the old refresh failed\n");
		eio = -EIO;
		goto revert_out;
	}

	if (!advfs_lower_dentry_idx(new_dentry, bindex) ||
	    !advfs_lower_dentry_idx(new_dentry, bindex)->d_inode) {
		printk(KERN_ERR "advfs: revert failed in rename: "
		       "the object disappeared from under us!\n");
		eio = -EIO;
		goto revert_out;
	}

	if (advfs_lower_dentry_idx(old_dentry, bindex) &&
	    advfs_lower_dentry_idx(old_dentry, bindex)->d_inode) {
		printk(KERN_ERR "advfs: revert failed in rename: "
		       "the object was created underneath us!\n");
		eio = -EIO;
		goto revert_out;
	}

	local_err = __advfs_rename(new_dir, new_dentry, new_parent,
				     old_dir, old_dentry, old_parent,
				     old_bstart);

	/* If we can't fix it, then we cop-out with -EIO. */
	if (local_err) {
		printk(KERN_ERR "advfs: revert failed in rename!\n");
		eio = -EIO;
	}

	local_err = advfs_refresh_lower_dentry(new_dentry, new_parent,
						 bindex);
	if (local_err)
		eio = -EIO;
	local_err = advfs_refresh_lower_dentry(old_dentry, old_parent,
						 bindex);
	if (local_err)
		eio = -EIO;

revert_out:
	if (eio)
		err = eio;
	return err;
}

/*
 * We can't copyup a directory, because it may involve huge numbers of
 * children, etc.  Doing that in the kernel would be bad, so instead we
 * return EXDEV to the user-space utility that caused this, and let the
 * user-space recurse and ask us to copy up each file separately.
 */
static int may_rename_dir(struct dentry *dentry, struct dentry *parent)
{
	int err, bstart;

	err = advfs_check_empty(dentry, parent, NULL);
	if (err == -ENOTEMPTY) {
		if (is_robranch(dentry))
			return -EXDEV;
	} else if (err) {
		return err;
	}

	bstart = dbstart(dentry);
	if (dbend(dentry) == bstart || dbopaque(dentry) == bstart)
		return 0;

	dbstart(dentry) = bstart + 1;
	err = advfs_check_empty(dentry, parent, NULL);
	dbstart(dentry) = bstart;
	if (err == -ENOTEMPTY)
		err = -EXDEV;
	return err;
}

/*
 * The locking rules in advfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
int advfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		   struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *wh_dentry;
	struct dentry *old_parent, *new_parent;
	int valid = true;

	advfs_read_lock(old_dentry->d_sb, ADVFS_SMUTEX_CHILD);
	old_parent = dget_parent(old_dentry);
	new_parent = dget_parent(new_dentry);
	/* un/lock parent dentries only if they differ from old/new_dentry */
	if (old_parent != old_dentry &&
	    old_parent != new_dentry)
		advfs_lock_dentry(old_parent, ADVFS_DMUTEX_REVAL_PARENT);
	if (new_parent != old_dentry &&
	    new_parent != new_dentry &&
	    new_parent != old_parent)
		advfs_lock_dentry(new_parent, ADVFS_DMUTEX_REVAL_CHILD);
	advfs_double_lock_dentry(old_dentry, new_dentry);

	valid = __advfs_d_revalidate(old_dentry, old_parent, false);
	if (!valid) {
		err = -ESTALE;
		goto out;
	}
	if (!d_deleted(new_dentry) && new_dentry->d_inode) {
		valid = __advfs_d_revalidate(new_dentry, new_parent, false);
		if (!valid) {
			err = -ESTALE;
			goto out;
		}
	}

	if (!S_ISDIR(old_dentry->d_inode->i_mode))
		err = advfs_partial_lookup(old_dentry, old_parent);
	else
		err = may_rename_dir(old_dentry, old_parent);

	if (err)
		goto out;

	err = advfs_partial_lookup(new_dentry, new_parent);
	if (err)
		goto out;

	/*
	 * if new_dentry is already lower because of whiteout,
	 * simply override it even if the whited-out dir is not empty.
	 */
	wh_dentry = advfs_find_first_whiteout(new_dentry);
	if (!IS_ERR(wh_dentry)) {
		dput(wh_dentry);
	} else if (new_dentry->d_inode) {
		if (S_ISDIR(old_dentry->d_inode->i_mode) !=
		    S_ISDIR(new_dentry->d_inode->i_mode)) {
			err = S_ISDIR(old_dentry->d_inode->i_mode) ?
				-ENOTDIR : -EISDIR;
			goto out;
		}

		if (S_ISDIR(new_dentry->d_inode->i_mode)) {
			struct advfs_dir_state *namelist = NULL;
			/* check if this advfs directory is empty or not */
			err = advfs_check_empty(new_dentry, new_parent, &namelist);
			if (err)
				goto out;

			if (!is_robranch(new_dentry))
				err = advfs_delete_whiteouts(new_dentry,
						       dbstart(new_dentry),
						       namelist);

			advfs_free_rdstate(namelist);

			if (err)
				goto out;
		}
	}

	err = do_advfs_rename(old_dir, old_dentry, old_parent,
				new_dir, new_dentry, new_parent);
	if (err)
		goto out;

	/*
	 * force re-lookup since the dir on ro branch is not renamed, and
	 * lower dentries still indicate the un-renamed ones.
	 */
	if (S_ISDIR(old_dentry->d_inode->i_mode))
		atomic_dec(&ADVFS_D(old_dentry)->generation);
	else
		advfs_postcopyup_release(old_dentry);
	if (new_dentry->d_inode && !S_ISDIR(new_dentry->d_inode->i_mode)) {
		advfs_postcopyup_release(new_dentry);
		advfs_postcopyup_setmnt(new_dentry);
		if (!advfs_lower_inode(new_dentry->d_inode)) {
			/*
			 * If we get here, it means that no copyup was
			 * needed, and that a file by the old name already
			 * existing on the destination branch; that file got
			 * renamed earlier in this function, so all we need
			 * to do here is set the lower inode.
			 */
			struct inode *inode;
			inode = advfs_lower_inode(old_dentry->d_inode);
			igrab(inode);
			advfs_set_lower_inode_idx(new_dentry->d_inode,
						    dbstart(new_dentry),
						    inode);
		}
	}
	/* if all of this renaming succeeded, update our times */
	advfs_copy_attr_times(old_dentry->d_inode);
	advfs_copy_attr_times(new_dentry->d_inode);
	advfs_check_inode(old_dir);
	advfs_check_inode(new_dir);
	advfs_check_dentry(old_dentry);
	advfs_check_dentry(new_dentry);

out:
	if (err)		/* clear the new_dentry stuff created */
		d_drop(new_dentry);

	advfs_double_unlock_dentry(old_dentry, new_dentry);
	if (new_parent != old_dentry &&
	    new_parent != new_dentry &&
	    new_parent != old_parent)
		advfs_unlock_dentry(new_parent);
	if (old_parent != old_dentry &&
	    old_parent != new_dentry)
		advfs_unlock_dentry(old_parent);
	dput(new_parent);
	dput(old_parent);
	advfs_read_unlock(old_dentry->d_sb);

	return err;
}
