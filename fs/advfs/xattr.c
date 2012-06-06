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

/* This is lifted from fs/xattr.c */
void *advfs_xattr_alloc(size_t size, size_t limit)
{
	void *ptr;

	if (size > limit)
		return ERR_PTR(-E2BIG);

	if (!size)		/* size request, no buffer is needed */
		return NULL;

	ptr = kmalloc(size, GFP_KERNEL);
	if (unlikely(!ptr))
		return ERR_PTR(-ENOMEM);
	return ptr;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
ssize_t advfs_getxattr(struct dentry *dentry, const char *name, void *value,
			 size_t size)
{
	struct dentry *lower_dentry = NULL;
	struct dentry *parent;
	int err = -EOPNOTSUPP;
	bool valid;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}

	lower_dentry = advfs_lower_dentry(dentry);

	err = vfs_getxattr(lower_dentry, (char *) name, value, size);

out:
	advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
	return err;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
int advfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags)
{
	struct dentry *lower_dentry = NULL;
	struct dentry *parent;
	int err = -EOPNOTSUPP;
	bool valid;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}

	lower_dentry = advfs_lower_dentry(dentry);

	err = vfs_setxattr(lower_dentry, (char *) name, (void *) value,
			   size, flags);

out:
	advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
	return err;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
int advfs_removexattr(struct dentry *dentry, const char *name)
{
	struct dentry *lower_dentry = NULL;
	struct dentry *parent;
	int err = -EOPNOTSUPP;
	bool valid;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}

	lower_dentry = advfs_lower_dentry(dentry);

	err = vfs_removexattr(lower_dentry, (char *) name);

out:
	advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
	return err;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
ssize_t advfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct dentry *lower_dentry = NULL;
	struct dentry *parent;
	int err = -EOPNOTSUPP;
	char *encoded_list = NULL;
	bool valid;

	advfs_read_lock(dentry->d_sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}

	lower_dentry = advfs_lower_dentry(dentry);

	encoded_list = list;
	err = vfs_listxattr(lower_dentry, encoded_list, size);

out:
	advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(dentry->d_sb);
	return err;
}
