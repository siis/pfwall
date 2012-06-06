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
 * returns the right n_link value based on the inode type
 */
int advfs_get_nlinks(const struct inode *inode)
{
	/* don't bother to do all the work since we're unlinked */
	if (inode->i_nlink == 0)
		return 0;

	if (!S_ISDIR(inode->i_mode))
		return advfs_lower_inode(inode)->i_nlink;

	/*
	 * For directories, we return 1. The only place that could cares
	 * about links is readdir, and there's d_type there so even that
	 * doesn't matter.
	 */
	return 1;
}

/* copy a/m/ctime from the lower branch with the newest times */
void advfs_copy_attr_times(struct inode *upper)
{
	int bindex;
	struct inode *lower;

	if (!upper)
		return;
	if (ibstart(upper) < 0) {
#ifdef CONFIG_ADV_FS_DEBUG
		WARN_ON(ibstart(upper) < 0);
#endif /* CONFIG_ADV_FS_DEBUG */
		return;
	}
	for (bindex = ibstart(upper); bindex <= ibend(upper); bindex++) {
		lower = advfs_lower_inode_idx(upper, bindex);
		if (!lower)
			continue; /* not all lower dir objects may exist */
		if (unlikely(timespec_compare(&upper->i_mtime,
					      &lower->i_mtime) < 0))
			upper->i_mtime = lower->i_mtime;
		if (unlikely(timespec_compare(&upper->i_ctime,
					      &lower->i_ctime) < 0))
			upper->i_ctime = lower->i_ctime;
		if (unlikely(timespec_compare(&upper->i_atime,
					      &lower->i_atime) < 0))
			upper->i_atime = lower->i_atime;
	}
}

/*
 * A advfs/fanout version of fsstack_copy_attr_all.  Uses a
 * advfs_get_nlinks to properly calcluate the number of links to a file.
 * Also, copies the max() of all a/m/ctimes for all lower inodes (which is
 * important if the lower inode is a directory type)
 */
void advfs_copy_attr_all(struct inode *dest,
			   const struct inode *src)
{
	dest->i_mode = src->i_mode;
	dest->i_uid = src->i_uid;
	dest->i_gid = src->i_gid;
	dest->i_rdev = src->i_rdev;

	advfs_copy_attr_times(dest);

	dest->i_blkbits = src->i_blkbits;
	dest->i_flags = src->i_flags;

	/*
	 * Update the nlinks AFTER updating the above fields, because the
	 * get_links callback may depend on them.
	 */
	set_nlink(dest, advfs_get_nlinks(dest));
}
