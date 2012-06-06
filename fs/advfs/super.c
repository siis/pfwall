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
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *advfs_inode_cachep;

struct inode *advfs_iget(struct super_block *sb, unsigned long ino)
{
	int size;
	struct advfs_inode_info *info;
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	info = ADVFS_I(inode);
	memset(info, 0, offsetof(struct advfs_inode_info, vfs_inode));
	info->bstart = -1;
	info->bend = -1;
	atomic_set(&info->generation,
		   atomic_read(&ADVFS_SB(inode->i_sb)->generation));
	spin_lock_init(&info->rdlock);
	info->rdcount = 1;
	info->hashsize = -1;
	INIT_LIST_HEAD(&info->readdircache);

	size = sbmax(inode->i_sb) * sizeof(struct inode *);
	info->lower_inodes = kzalloc(size, GFP_KERNEL);
	if (unlikely(!info->lower_inodes)) {
		printk(KERN_CRIT "advfs: no kernel memory when allocating "
		       "lower-pointer array!\n");
		iget_failed(inode);
		return ERR_PTR(-ENOMEM);
	}

	inode->i_version++;
	inode->i_op = &advfs_main_iops;
	inode->i_fop = &advfs_main_fops;

	inode->i_mapping->a_ops = &advfs_aops;

	/*
	 * reset times so advfs_copy_attr_all can keep out time invariants
	 * right (upper inode time being the max of all lower ones).
	 */
	inode->i_atime.tv_sec = inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_sec = inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_sec = inode->i_ctime.tv_nsec = 0;
	unlock_new_inode(inode);
	return inode;
}

/*
 * final actions when unmounting a file system
 *
 * No need to lock rwsem.
 */
static void advfs_put_super(struct super_block *sb)
{
	int bindex, bstart, bend;
	struct advfs_sb_info *spd;
	int leaks = 0;

	spd = ADVFS_SB(sb);
	if (!spd)
		return;

	bstart = sbstart(sb);
	bend = sbend(sb);

	/* Make sure we have no leaks of branchget/branchput. */
	for (bindex = bstart; bindex <= bend; bindex++)
		if (unlikely(branch_count(sb, bindex) != 0)) {
			printk(KERN_CRIT
			       "advfs: branch %d has %d references left!\n",
			       bindex, branch_count(sb, bindex));
			leaks = 1;
		}
	WARN_ON(leaks != 0);

	/* decrement lower super references */
	for (bindex = bstart; bindex <= bend; bindex++) {
		struct super_block *s;
		s = advfs_lower_super_idx(sb, bindex);
		advfs_set_lower_super_idx(sb, bindex, NULL);
		atomic_dec(&s->s_active);
	}

	kfree(spd->dev_name);
	kfree(spd->data);
	kfree(spd);
	sb->s_fs_info = NULL;
}

/*
 * Since people use this to answer the "How big of a file can I write?"
 * question, we report the size of the highest priority branch as the size of
 * the union.
 */
static int advfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err	= 0;
	struct super_block *sb;
	struct dentry *lower_dentry;
	struct dentry *parent;
	struct path lower_path;
	bool valid;

	sb = dentry->d_sb;

	advfs_read_lock(sb, ADVFS_SMUTEX_CHILD);
	parent = advfs_lock_parent(dentry, ADVFS_DMUTEX_PARENT);
	advfs_lock_dentry(dentry, ADVFS_DMUTEX_CHILD);

	valid = __advfs_d_revalidate(dentry, parent, false);
	if (unlikely(!valid)) {
		err = -ESTALE;
		goto out;
	}
	advfs_check_dentry(dentry);

	lower_dentry = advfs_lower_dentry(sb->s_root);
	lower_path.dentry = lower_dentry;
	lower_path.mnt = advfs_mntget(sb->s_root, 0);
	err = vfs_statfs(&lower_path, buf);
	mntput(lower_path.mnt);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = ADVFS_SUPER_MAGIC;
	/*
	 * Our maximum file name can is shorter by a few bytes because every
	 * file name could potentially be whited-out.
	 *
	 * XXX: this restriction goes away with ODF.
	 */
	advfs_set_max_namelen(&buf->f_namelen);

	/*
	 * reset two fields to avoid confusing user-land.
	 * XXX: is this still necessary?
	 */
	memset(&buf->f_fsid, 0, sizeof(__kernel_fsid_t));
	memset(&buf->f_spare, 0, sizeof(buf->f_spare));

out:
	advfs_check_dentry(dentry);
	advfs_unlock_dentry(dentry);
	advfs_unlock_parent(dentry, parent);
	advfs_read_unlock(sb);
	return err;
}

/* handle mode changing during remount */
static noinline_for_stack int do_remount_mode_option(
					char *optarg,
					int cur_branches,
					struct advfs_data *new_data,
					struct path *new_lower_paths)
{
	int err = -EINVAL;
	int perms, idx;
	char *modename = strchr(optarg, '=');
	struct path path;

	/* by now, optarg contains the branch name */
	if (!*optarg) {
		printk(KERN_ERR
		       "advfs: no branch specified for mode change\n");
		goto out;
	}
	if (!modename) {
		printk(KERN_ERR "advfs: branch \"%s\" requires a mode\n",
		       optarg);
		goto out;
	}
	*modename++ = '\0';
	err = advfs_parse_branch_mode(modename, &perms);
	if (err) {
		printk(KERN_ERR "advfs: invalid mode \"%s\" for \"%s\"\n",
		       modename, optarg);
		goto out;
	}

	/*
	 * Find matching branch index.  For now, this assumes that nothing
	 * has been mounted on top of this Unionfs stack.  Once we have /odf
	 * and cache-coherency resolved, we'll address the branch-path
	 * uniqueness.
	 */
	err = kern_path(optarg, LOOKUP_FOLLOW, &path);
	if (err) {
		printk(KERN_ERR "advfs: error accessing "
		       "lower directory \"%s\" (error %d)\n",
		       optarg, err);
		goto out;
	}
	for (idx = 0; idx < cur_branches; idx++)
		if (path.mnt == new_lower_paths[idx].mnt &&
		    path.dentry == new_lower_paths[idx].dentry)
			break;
	path_put(&path);	/* no longer needed */
	if (idx == cur_branches) {
		err = -ENOENT;	/* err may have been reset above */
		printk(KERN_ERR "advfs: branch \"%s\" "
		       "not found\n", optarg);
		goto out;
	}
	/* check/change mode for existing branch */
	/* we don't warn if perms==branchperms */
	new_data[idx].branchperms = perms;
	err = 0;
out:
	return err;
}

/* handle branch deletion during remount */
static noinline_for_stack int do_remount_del_option(
					char *optarg, int cur_branches,
					struct advfs_data *new_data,
					struct path *new_lower_paths)
{
	int err = -EINVAL;
	int idx;
	struct path path;

	/* optarg contains the branch name to delete */

	/*
	 * Find matching branch index.  For now, this assumes that nothing
	 * has been mounted on top of this Unionfs stack.  Once we have /odf
	 * and cache-coherency resolved, we'll address the branch-path
	 * uniqueness.
	 */
	err = kern_path(optarg, LOOKUP_FOLLOW, &path);
	if (err) {
		printk(KERN_ERR "advfs: error accessing "
		       "lower directory \"%s\" (error %d)\n",
		       optarg, err);
		goto out;
	}
	for (idx = 0; idx < cur_branches; idx++)
		if (path.mnt == new_lower_paths[idx].mnt &&
		    path.dentry == new_lower_paths[idx].dentry)
			break;
	path_put(&path);	/* no longer needed */
	if (idx == cur_branches) {
		printk(KERN_ERR "advfs: branch \"%s\" "
		       "not found\n", optarg);
		err = -ENOENT;
		goto out;
	}
	/* check if there are any open files on the branch to be deleted */
	if (atomic_read(&new_data[idx].open_files) > 0) {
		err = -EBUSY;
		goto out;
	}

	/*
	 * Now we have to delete the branch.  First, release any handles it
	 * has.  Then, move the remaining array indexes past "idx" in
	 * new_data and new_lower_paths one to the left.  Finally, adjust
	 * cur_branches.
	 */
	path_put(&new_lower_paths[idx]);

	if (idx < cur_branches - 1) {
		/* if idx==cur_branches-1, we delete last branch: easy */
		memmove(&new_data[idx], &new_data[idx+1],
			(cur_branches - 1 - idx) *
			sizeof(struct advfs_data));
		memmove(&new_lower_paths[idx], &new_lower_paths[idx+1],
			(cur_branches - 1 - idx) * sizeof(struct path));
	}

	err = 0;
out:
	return err;
}

/* handle branch insertion during remount */
static noinline_for_stack int do_remount_add_option(
					char *optarg, int cur_branches,
					struct advfs_data *new_data,
					struct path *new_lower_paths,
					int *high_branch_id)
{
	int err = -EINVAL;
	int perms;
	int idx = 0;		/* default: insert at beginning */
	char *new_branch , *modename = NULL;
	struct path path;

	/*
	 * optarg can be of several forms:
	 *
	 * /bar:/foo		insert /foo before /bar
	 * /bar:/foo=ro		insert /foo in ro mode before /bar
	 * /foo			insert /foo in the beginning (prepend)
	 * :/foo		insert /foo at the end (append)
	 */
	if (*optarg == ':') {	/* append? */
		new_branch = optarg + 1; /* skip ':' */
		idx = cur_branches;
		goto found_insertion_point;
	}
	new_branch = strchr(optarg, ':');
	if (!new_branch) {	/* prepend? */
		new_branch = optarg;
		goto found_insertion_point;
	}
	*new_branch++ = '\0';	/* holds path+mode of new branch */

	/*
	 * Find matching branch index.  For now, this assumes that nothing
	 * has been mounted on top of this Unionfs stack.  Once we have /odf
	 * and cache-coherency resolved, we'll address the branch-path
	 * uniqueness.
	 */
	err = kern_path(optarg, LOOKUP_FOLLOW, &path);
	if (err) {
		printk(KERN_ERR "advfs: error accessing "
		       "lower directory \"%s\" (error %d)\n",
		       optarg, err);
		goto out;
	}
	for (idx = 0; idx < cur_branches; idx++)
		if (path.mnt == new_lower_paths[idx].mnt &&
		    path.dentry == new_lower_paths[idx].dentry)
			break;
	path_put(&path);	/* no longer needed */
	if (idx == cur_branches) {
		printk(KERN_ERR "advfs: branch \"%s\" "
		       "not found\n", optarg);
		err = -ENOENT;
		goto out;
	}

	/*
	 * At this point idx will hold the index where the new branch should
	 * be inserted before.
	 */
found_insertion_point:
	/* find the mode for the new branch */
	if (new_branch)
		modename = strchr(new_branch, '=');
	if (modename)
		*modename++ = '\0';
	if (!new_branch || !*new_branch) {
		printk(KERN_ERR "advfs: null new branch\n");
		err = -EINVAL;
		goto out;
	}
	err = advfs_parse_branch_mode(modename, &perms);
	if (err) {
		printk(KERN_ERR "advfs: invalid mode \"%s\" for "
		       "branch \"%s\"\n", modename, new_branch);
		goto out;
	}
	err = kern_path(new_branch, LOOKUP_FOLLOW, &path);
	if (err) {
		printk(KERN_ERR "advfs: error accessing "
		       "lower directory \"%s\" (error %d)\n",
		       new_branch, err);
		goto out;
	}
	/*
	 * It's probably safe to check_mode the new branch to insert.  Note:
	 * we don't allow inserting branches which are advfs's by
	 * themselves (advfs_check_branch returns EINVAL in that case).  This is
	 * because this code base doesn't support stacking advfs: the ODF
	 * code base supports that correctly.
	 */
	err = advfs_check_branch(&path);
	if (err) {
		printk(KERN_ERR "advfs: lower directory "
		       "\"%s\" is not a valid branch\n", optarg);
		path_put(&path);
		goto out;
	}

	/*
	 * Now we have to insert the new branch.  But first, move the bits
	 * to make space for the new branch, if needed.  Finally, adjust
	 * cur_branches.
	 * We don't release nd here; it's kept until umount/remount.
	 */
	if (idx < cur_branches) {
		/* if idx==cur_branches, we append: easy */
		memmove(&new_data[idx+1], &new_data[idx],
			(cur_branches - idx) * sizeof(struct advfs_data));
		memmove(&new_lower_paths[idx+1], &new_lower_paths[idx],
			(cur_branches - idx) * sizeof(struct path));
	}
	new_lower_paths[idx].dentry = path.dentry;
	new_lower_paths[idx].mnt = path.mnt;

	new_data[idx].sb = path.dentry->d_sb;
	atomic_set(&new_data[idx].open_files, 0);
	new_data[idx].branchperms = perms;
	new_data[idx].branch_id = ++*high_branch_id; /* assign new branch ID */

	err = 0;
out:
	return err;
}


/*
 * Support branch management options on remount.
 *
 * See Documentation/filesystems/advfs/ for details.
 *
 * @flags: numeric mount options
 * @options: mount options string
 *
 * This function can rearrange a mounted union dynamically, adding and
 * removing branches, including changing branch modes.  Clearly this has to
 * be done safely and atomically.  Luckily, the VFS already calls this
 * function with lock_super(sb) and lock_kernel() held, preventing
 * concurrent mixing of new mounts, remounts, and unmounts.  Moreover,
 * do_remount_sb(), our caller function, already called shrink_dcache_sb(sb)
 * to purge dentries/inodes from our superblock, and also called
 * fsync_super(sb) to purge any dirty pages.  So we're good.
 *
 * XXX: however, our remount code may also need to invalidate mapped pages
 * so as to force them to be re-gotten from the (newly reconfigured) lower
 * branches.  This has to wait for proper mmap and cache coherency support
 * in the VFS.
 *
 */
static int advfs_remount_fs(struct super_block *sb, int *flags,
			      char *options)
{
	int err = 0;
	int i;
	char *optionstmp, *tmp_to_free;	/* kstrdup'ed of "options" */
	char *optname;
	int cur_branches = 0;	/* no. of current branches */
	int new_branches = 0;	/* no. of branches actually left in the end */
	int add_branches;	/* est. no. of branches to add */
	int del_branches;	/* est. no. of branches to del */
	int max_branches;	/* max possible no. of branches */
	struct advfs_data *new_data = NULL, *tmp_data = NULL;
	struct path *new_lower_paths = NULL, *tmp_lower_paths = NULL;
	struct inode **new_lower_inodes = NULL;
	int new_high_branch_id;	/* new high branch ID */
	int size;		/* memory allocation size, temp var */
	int old_ibstart, old_ibend;

	advfs_write_lock(sb);

	/*
	 * The VFS will take care of "ro" and "rw" flags, and we can safely
	 * ignore MS_SILENT, but anything else left over is an error.  So we
	 * need to check if any other flags may have been passed (none are
	 * allowed/supported as of now).
	 */
	if ((*flags & ~(MS_RDONLY | MS_SILENT)) != 0) {
		printk(KERN_ERR
		       "advfs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
		goto out_error;
	}

	/*
	 * If 'options' is NULL, it's probably because the user just changed
	 * the union to a "ro" or "rw" and the VFS took care of it.  So
	 * nothing to do and we're done.
	 */
	if (!options || options[0] == '\0')
		goto out_error;

	/*
	 * Find out how many branches we will have in the end, counting
	 * "add" and "del" commands.  Copy the "options" string because
	 * strsep modifies the string and we need it later.
	 */
	tmp_to_free = kstrdup(options, GFP_KERNEL);
	optionstmp = tmp_to_free;
	if (unlikely(!optionstmp)) {
		err = -ENOMEM;
		goto out_free;
	}
	cur_branches = sbmax(sb); /* current no. branches */
	new_branches = sbmax(sb);
	del_branches = 0;
	add_branches = 0;
	new_high_branch_id = sbhbid(sb); /* save current high_branch_id */
	while ((optname = strsep(&optionstmp, ",")) != NULL) {
		char *optarg;

		if (!optname || !*optname)
			continue;

		optarg = strchr(optname, '=');
		if (optarg)
			*optarg++ = '\0';

		if (!strcmp("add", optname))
			add_branches++;
		else if (!strcmp("del", optname))
			del_branches++;
	}
	kfree(tmp_to_free);
	/* after all changes, will we have at least one branch left? */
	if ((new_branches + add_branches - del_branches) < 1) {
		printk(KERN_ERR
		       "advfs: no branches left after remount\n");
		err = -EINVAL;
		goto out_free;
	}

	/*
	 * Since we haven't actually parsed all the add/del options, nor
	 * have we checked them for errors, we don't know for sure how many
	 * branches we will have after all changes have taken place.  In
	 * fact, the total number of branches left could be less than what
	 * we have now.  So we need to allocate space for a temporary
	 * placeholder that is at least as large as the maximum number of
	 * branches we *could* have, which is the current number plus all
	 * the additions.  Once we're done with these temp placeholders, we
	 * may have to re-allocate the final size, copy over from the temp,
	 * and then free the temps (done near the end of this function).
	 */
	max_branches = cur_branches + add_branches;
	/* allocate space for new pointers to lower dentry */
	tmp_data = kcalloc(max_branches,
			   sizeof(struct advfs_data), GFP_KERNEL);
	if (unlikely(!tmp_data)) {
		err = -ENOMEM;
		goto out_free;
	}
	/* allocate space for new pointers to lower paths */
	tmp_lower_paths = kcalloc(max_branches,
				  sizeof(struct path), GFP_KERNEL);
	if (unlikely(!tmp_lower_paths)) {
		err = -ENOMEM;
		goto out_free;
	}
	/* copy current info into new placeholders, incrementing refcnts */
	memcpy(tmp_data, ADVFS_SB(sb)->data,
	       cur_branches * sizeof(struct advfs_data));
	memcpy(tmp_lower_paths, ADVFS_D(sb->s_root)->lower_paths,
	       cur_branches * sizeof(struct path));
	for (i = 0; i < cur_branches; i++)
		path_get(&tmp_lower_paths[i]); /* drop refs at end of fxn */

	/*******************************************************************
	 * For each branch command, do kern_path on the requested branch,
	 * and apply the change to a temp branch list.  To handle errors, we
	 * already dup'ed the old arrays (above), and increased the refcnts
	 * on various f/s objects.  So now we can do all the kern_path'ss
	 * and branch-management commands on the new arrays.  If it fail mid
	 * way, we free the tmp arrays and *put all objects.  If we succeed,
	 * then we free old arrays and *put its objects, and then replace
	 * the arrays with the new tmp list (we may have to re-allocate the
	 * memory because the temp lists could have been larger than what we
	 * actually needed).
	 *******************************************************************/

	while ((optname = strsep(&options, ",")) != NULL) {
		char *optarg;

		if (!optname || !*optname)
			continue;
		/*
		 * At this stage optname holds a comma-delimited option, but
		 * without the commas.  Next, we need to break the string on
		 * the '=' symbol to separate CMD=ARG, where ARG itself can
		 * be KEY=VAL.  For example, in mode=/foo=rw, CMD is "mode",
		 * KEY is "/foo", and VAL is "rw".
		 */
		optarg = strchr(optname, '=');
		if (optarg)
			*optarg++ = '\0';
		/* incgen remount option (instead of old ioctl) */
		if (!strcmp("incgen", optname)) {
			err = 0;
			goto out_no_change;
		}

		/*
		 * All of our options take an argument now.  (Insert ones
		 * that don't above this check.)  So at this stage optname
		 * contains the CMD part and optarg contains the ARG part.
		 */
		if (!optarg || !*optarg) {
			printk(KERN_ERR "advfs: all remount options require "
			       "an argument (%s)\n", optname);
			err = -EINVAL;
			goto out_release;
		}

		if (!strcmp("add", optname)) {
			err = do_remount_add_option(optarg, new_branches,
						    tmp_data,
						    tmp_lower_paths,
						    &new_high_branch_id);
			if (err)
				goto out_release;
			new_branches++;
			if (new_branches > ADVFS_MAX_BRANCHES) {
				printk(KERN_ERR "advfs: command exceeds "
				       "%d branches\n", ADVFS_MAX_BRANCHES);
				err = -E2BIG;
				goto out_release;
			}
			continue;
		}
		if (!strcmp("del", optname)) {
			err = do_remount_del_option(optarg, new_branches,
						    tmp_data,
						    tmp_lower_paths);
			if (err)
				goto out_release;
			new_branches--;
			continue;
		}
		if (!strcmp("mode", optname)) {
			err = do_remount_mode_option(optarg, new_branches,
						     tmp_data,
						     tmp_lower_paths);
			if (err)
				goto out_release;
			continue;
		}

		/*
		 * When you use "mount -o remount,ro", mount(8) will
		 * reportedly pass the original dirs= string from
		 * /proc/mounts.  So for now, we have to ignore dirs= and
		 * not consider it an error, unless we want to allow users
		 * to pass dirs= in remount.  Note that to allow the VFS to
		 * actually process the ro/rw remount options, we have to
		 * return 0 from this function.
		 */
		if (!strcmp("dirs", optname)) {
			printk(KERN_WARNING
			       "advfs: remount ignoring option \"%s\"\n",
			       optname);
			continue;
		}

		err = -EINVAL;
		printk(KERN_ERR
		       "advfs: unrecognized option \"%s\"\n", optname);
		goto out_release;
	}

out_no_change:

	/******************************************************************
	 * WE'RE ALMOST DONE: check if leftmost branch might be read-only,
	 * see if we need to allocate a small-sized new vector, copy the
	 * vectors to their correct place, release the refcnt of the older
	 * ones, and return.  Also handle invalidating any pages that will
	 * have to be re-read.
	 *******************************************************************/

	if (!(tmp_data[0].branchperms & MAY_WRITE)) {
		printk(KERN_ERR "advfs: leftmost branch cannot be read-only "
		       "(use \"remount,ro\" to create a read-only union)\n");
		err = -EINVAL;
		goto out_release;
	}

	/* (re)allocate space for new pointers to lower dentry */
	size = new_branches * sizeof(struct advfs_data);
	new_data = krealloc(tmp_data, size, GFP_KERNEL);
	if (unlikely(!new_data)) {
		err = -ENOMEM;
		goto out_release;
	}

	/* allocate space for new pointers to lower paths */
	size = new_branches * sizeof(struct path);
	new_lower_paths = krealloc(tmp_lower_paths, size, GFP_KERNEL);
	if (unlikely(!new_lower_paths)) {
		err = -ENOMEM;
		goto out_release;
	}

	/* allocate space for new pointers to lower inodes */
	new_lower_inodes = kcalloc(new_branches,
				   sizeof(struct inode *), GFP_KERNEL);
	if (unlikely(!new_lower_inodes)) {
		err = -ENOMEM;
		goto out_release;
	}

	/*
	 * OK, just before we actually put the new set of branches in place,
	 * we need to ensure that our own f/s has no dirty objects left.
	 * Luckily, do_remount_sb() already calls shrink_dcache_sb(sb) and
	 * fsync_super(sb), taking care of dentries, inodes, and dirty
	 * pages.  So all that's left is for us to invalidate any leftover
	 * (non-dirty) pages to ensure that they will be re-read from the
	 * new lower branches (and to support mmap).
	 */

	/*
	 * Once we finish the remounting successfully, our superblock
	 * generation number will have increased.  This will be detected by
	 * our dentry-revalidation code upon subsequent f/s operations
	 * through advfs.  The revalidation code will rebuild the union of
	 * lower inodes for a given advfs inode and invalidate any pages
	 * of such "stale" inodes (by calling our purge_inode_data
	 * function).  This revalidation will happen lazily and
	 * incrementally, as users perform operations on cached inodes.  We
	 * would like to encourage this revalidation to happen sooner if
	 * possible, so we like to try to invalidate as many other pages in
	 * our superblock as we can.  We used to call drop_pagecache_sb() or
	 * a variant thereof, but either method was racy (drop_caches alone
	 * is known to be racy).  So now we let the revalidation happen on a
	 * per file basis in ->d_revalidate.
	 */

	/* grab new lower super references; release old ones */
	for (i = 0; i < new_branches; i++)
		atomic_inc(&new_data[i].sb->s_active);
	for (i = 0; i < sbmax(sb); i++)
		atomic_dec(&ADVFS_SB(sb)->data[i].sb->s_active);

	/* copy new vectors into their correct place */
	tmp_data = ADVFS_SB(sb)->data;
	ADVFS_SB(sb)->data = new_data;
	new_data = NULL;	/* so don't free good pointers below */
	tmp_lower_paths = ADVFS_D(sb->s_root)->lower_paths;
	ADVFS_D(sb->s_root)->lower_paths = new_lower_paths;
	new_lower_paths = NULL;	/* so don't free good pointers below */

	/* update our advfs_sb_info and root dentry index of last branch */
	i = sbmax(sb);		/* save no. of branches to release at end */
	sbend(sb) = new_branches - 1;
	dbend(sb->s_root) = new_branches - 1;
	old_ibstart = ibstart(sb->s_root->d_inode);
	old_ibend = ibend(sb->s_root->d_inode);
	ibend(sb->s_root->d_inode) = new_branches - 1;
	ADVFS_D(sb->s_root)->bcount = new_branches;
	new_branches = i; /* no. of branches to release below */

	/*
	 * Update lower inodes: 3 steps
	 * 1. grab ref on all new lower inodes
	 */
	for (i = dbstart(sb->s_root); i <= dbend(sb->s_root); i++) {
		struct dentry *lower_dentry =
			advfs_lower_dentry_idx(sb->s_root, i);
		igrab(lower_dentry->d_inode);
		new_lower_inodes[i] = lower_dentry->d_inode;
	}
	/* 2. release reference on all older lower inodes */
	iput_lowers(sb->s_root->d_inode, old_ibstart, old_ibend, true);
	/* 3. update root dentry's inode to new lower_inodes array */
	ADVFS_I(sb->s_root->d_inode)->lower_inodes = new_lower_inodes;
	new_lower_inodes = NULL;

	/* maxbytes may have changed */
	sb->s_maxbytes = advfs_lower_super_idx(sb, 0)->s_maxbytes;
	/* update high branch ID */
	sbhbid(sb) = new_high_branch_id;

	/* update our sb->generation for revalidating objects */
	i = atomic_inc_return(&ADVFS_SB(sb)->generation);
	atomic_set(&ADVFS_D(sb->s_root)->generation, i);
	atomic_set(&ADVFS_I(sb->s_root->d_inode)->generation, i);
	if (!(*flags & MS_SILENT))
		pr_info("advfs: %s: new generation number %d\n",
			ADVFS_SB(sb)->dev_name, i);
	/* finally, update the root dentry's times */
	advfs_copy_attr_times(sb->s_root->d_inode);
	err = 0;		/* reset to success */

	/*
	 * The code above falls through to the next label, and releases the
	 * refcnts of the older ones (stored in tmp_*): if we fell through
	 * here, it means success.  However, if we jump directly to this
	 * label from any error above, then an error occurred after we
	 * grabbed various refcnts, and so we have to release the
	 * temporarily constructed structures.
	 */
out_release:
	/* no need to cleanup/release anything in tmp_data */
	if (tmp_lower_paths)
		for (i = 0; i < new_branches; i++)
			path_put(&tmp_lower_paths[i]);
out_free:
	kfree(tmp_lower_paths);
	kfree(tmp_data);
	kfree(new_lower_paths);
	kfree(new_data);
	kfree(new_lower_inodes);
out_error:
	advfs_check_dentry(sb->s_root);
	advfs_write_unlock(sb);
	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 *
 * No need to lock sb info's rwsem.
 */
static void advfs_evict_inode(struct inode *inode)
{
	int bindex, bstart, bend;
	struct inode *lower_inode;
	struct list_head *pos, *n;
	struct advfs_dir_state *rdstate;

	truncate_inode_pages(&inode->i_data, 0);
	end_writeback(inode);

	list_for_each_safe(pos, n, &ADVFS_I(inode)->readdircache) {
		rdstate = list_entry(pos, struct advfs_dir_state, cache);
		list_del(&rdstate->cache);
		advfs_free_rdstate(rdstate);
	}

	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	bstart = ibstart(inode);
	bend = ibend(inode);
	if (bstart >= 0) {
		for (bindex = bstart; bindex <= bend; bindex++) {
			lower_inode = advfs_lower_inode_idx(inode, bindex);
			if (!lower_inode)
				continue;
			advfs_set_lower_inode_idx(inode, bindex, NULL);
			/* see Documentation/filesystems/advfs/issues.txt */
			lockdep_off();
			iput(lower_inode);
			lockdep_on();
		}
	}

	kfree(ADVFS_I(inode)->lower_inodes);
	ADVFS_I(inode)->lower_inodes = NULL;
}

static struct inode *advfs_alloc_inode(struct super_block *sb)
{
	struct advfs_inode_info *i;

	i = kmem_cache_alloc(advfs_inode_cachep, GFP_KERNEL);
	if (unlikely(!i))
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct advfs_inode_info, vfs_inode));

	i->vfs_inode.i_version = 1;
	return &i->vfs_inode;
}

static void advfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(advfs_inode_cachep, ADVFS_I(inode));
}

/* advfs inode cache constructor */
static void init_once(void *obj)
{
	struct advfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int advfs_init_inode_cache(void)
{
	int err = 0;

	advfs_inode_cachep =
		kmem_cache_create("advfs_inode_cache",
				  sizeof(struct advfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (unlikely(!advfs_inode_cachep))
		err = -ENOMEM;
	return err;
}

/* advfs inode cache destructor */
void advfs_destroy_inode_cache(void)
{
	if (advfs_inode_cachep)
		kmem_cache_destroy(advfs_inode_cachep);
}

/*
 * Called when we have a dirty inode, right here we only throw out
 * parts of our readdir list that are too old.
 *
 * No need to grab sb info's rwsem.
 */
static int advfs_write_inode(struct inode *inode,
			       struct writeback_control *wbc)
{
	struct list_head *pos, *n;
	struct advfs_dir_state *rdstate;

	spin_lock(&ADVFS_I(inode)->rdlock);
	list_for_each_safe(pos, n, &ADVFS_I(inode)->readdircache) {
		rdstate = list_entry(pos, struct advfs_dir_state, cache);
		/* We keep this list in LRU order. */
		if ((rdstate->access + RDCACHE_JIFFIES) > jiffies)
			break;
		ADVFS_I(inode)->rdcount--;
		list_del(&rdstate->cache);
		advfs_free_rdstate(rdstate);
	}
	spin_unlock(&ADVFS_I(inode)->rdlock);

	return 0;
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void advfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;
	int bindex, bstart, bend;

	advfs_read_lock(sb, ADVFS_SMUTEX_CHILD);

	bstart = sbstart(sb);
	bend = sbend(sb);
	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_sb = advfs_lower_super_idx(sb, bindex);

		if (lower_sb && lower_sb->s_op &&
		    lower_sb->s_op->umount_begin)
			lower_sb->s_op->umount_begin(lower_sb);
	}

	advfs_read_unlock(sb);
}

static int advfs_show_options(struct seq_file *m, struct vfsmount *mnt)
{
	struct super_block *sb = mnt->mnt_sb;
	int ret = 0;
	char *tmp_page;
	char *path;
	int bindex, bstart, bend;
	int perms;

	/* to prevent a silly lockdep warning with namespace_sem */
	lockdep_off();
	advfs_read_lock(sb, ADVFS_SMUTEX_CHILD);
	advfs_lock_dentry(sb->s_root, ADVFS_DMUTEX_CHILD);

	tmp_page = (char *) __get_free_page(GFP_KERNEL);
	if (unlikely(!tmp_page)) {
		ret = -ENOMEM;
		goto out;
	}

	bstart = sbstart(sb);
	bend = sbend(sb);

	seq_printf(m, ",dirs=");
	for (bindex = bstart; bindex <= bend; bindex++) {
		struct path p;
		p.dentry = advfs_lower_dentry_idx(sb->s_root, bindex);
		p.mnt = advfs_lower_mnt_idx(sb->s_root, bindex);
		path = d_path(&p, tmp_page, PAGE_SIZE);
		if (IS_ERR(path)) {
			ret = PTR_ERR(path);
			goto out;
		}

		perms = branchperms(sb, bindex);

		seq_printf(m, "%s=%s", path,
			   perms & MAY_WRITE ? "rw" : "ro");
		if (bindex != bend)
			seq_printf(m, ":");
	}

out:
	free_page((unsigned long) tmp_page);

	advfs_unlock_dentry(sb->s_root);
	advfs_read_unlock(sb);
	lockdep_on();

	return ret;
}

struct super_operations advfs_sops = {
	.put_super	= advfs_put_super,
	.statfs		= advfs_statfs,
	.remount_fs	= advfs_remount_fs,
	.evict_inode	= advfs_evict_inode,
	.umount_begin	= advfs_umount_begin,
	.show_options	= advfs_show_options,
	.write_inode	= advfs_write_inode,
	.alloc_inode	= advfs_alloc_inode,
	.destroy_inode	= advfs_destroy_inode,
};
