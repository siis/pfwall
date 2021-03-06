/*
 * Copyright (c) 2003-2011 Erez Zadok
 * Copyright (c) 2003-2006 Charles P. Wright
 * Copyright (c) 2005-2007 Josef 'Jeff' Sipek
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

#ifndef _FANOUT_H_
#define _FANOUT_H_

/*
 * Inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * advfs_inode_info structure, ADVFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct advfs_inode_info *ADVFS_I(const struct inode *inode)
{
	return container_of(inode, struct advfs_inode_info, vfs_inode);
}

#define ibstart(ino) (ADVFS_I(ino)->bstart)
#define ibend(ino) (ADVFS_I(ino)->bend)

/* Dentry to private data */
#define ADVFS_D(dent) ((struct advfs_dentry_info *)(dent)->d_fsdata)
#define dbstart(dent) (ADVFS_D(dent)->bstart)
#define dbend(dent) (ADVFS_D(dent)->bend)
#define dbopaque(dent) (ADVFS_D(dent)->bopaque)

/* Superblock to private data */
#define ADVFS_SB(super) ((struct advfs_sb_info *)(super)->s_fs_info)
#define sbstart(sb) 0
#define sbend(sb) (ADVFS_SB(sb)->bend)
#define sbmax(sb) (ADVFS_SB(sb)->bend + 1)
#define sbhbid(sb) (ADVFS_SB(sb)->high_branch_id)

/* File to private Data */
#define ADVFS_F(file) ((struct advfs_file_info *)((file)->private_data))
#define fbstart(file) (ADVFS_F(file)->bstart)
#define fbend(file) (ADVFS_F(file)->bend)

/* macros to manipulate branch IDs in stored in our superblock */
static inline int branch_id(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	return ADVFS_SB(sb)->data[index].branch_id;
}

static inline void set_branch_id(struct super_block *sb, int index, int val)
{
	BUG_ON(!sb || index < 0);
	ADVFS_SB(sb)->data[index].branch_id = val;
}

static inline void new_branch_id(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	set_branch_id(sb, index, ++ADVFS_SB(sb)->high_branch_id);
}

/*
 * Find new index of matching branch with an existing superblock of a known
 * (possibly old) id.  This is needed because branches could have been
 * added/deleted causing the branches of any open files to shift.
 *
 * @sb: the new superblock which may have new/different branch IDs
 * @id: the old/existing id we're looking for
 * Returns index of newly found branch (0 or greater), -1 otherwise.
 */
static inline int branch_id_to_idx(struct super_block *sb, int id)
{
	int i;
	for (i = 0; i < sbmax(sb); i++) {
		if (branch_id(sb, i) == id)
			return i;
	}
	/* in the non-ODF code, this should really never happen */
	printk(KERN_WARNING "advfs: cannot find branch with id %d\n", id);
	return -1;
}

/* File to lower file. */
static inline struct file *advfs_lower_file(const struct file *f)
{
	BUG_ON(!f);
	return ADVFS_F(f)->lower_files[fbstart(f)];
}

static inline struct file *advfs_lower_file_idx(const struct file *f,
						  int index)
{
	BUG_ON(!f || index < 0);
	return ADVFS_F(f)->lower_files[index];
}

static inline void advfs_set_lower_file_idx(struct file *f, int index,
					      struct file *val)
{
	BUG_ON(!f || index < 0);
	ADVFS_F(f)->lower_files[index] = val;
	/* save branch ID (may be redundant?) */
	ADVFS_F(f)->saved_branch_ids[index] =
		branch_id((f)->f_path.dentry->d_sb, index);
}

static inline void advfs_set_lower_file(struct file *f, struct file *val)
{
	BUG_ON(!f);
	advfs_set_lower_file_idx((f), fbstart(f), (val));
}

/* Inode to lower inode. */
static inline struct inode *advfs_lower_inode(const struct inode *i)
{
	BUG_ON(!i);
	return ADVFS_I(i)->lower_inodes[ibstart(i)];
}

static inline struct inode *advfs_lower_inode_idx(const struct inode *i,
						    int index)
{
	BUG_ON(!i || index < 0);
	return ADVFS_I(i)->lower_inodes[index];
}

static inline void advfs_set_lower_inode_idx(struct inode *i, int index,
					       struct inode *val)
{
	BUG_ON(!i || index < 0);
	ADVFS_I(i)->lower_inodes[index] = val;
}

static inline void advfs_set_lower_inode(struct inode *i, struct inode *val)
{
	BUG_ON(!i);
	ADVFS_I(i)->lower_inodes[ibstart(i)] = val;
}

/* Superblock to lower superblock. */
static inline struct super_block *advfs_lower_super(
					const struct super_block *sb)
{
	BUG_ON(!sb);
	return ADVFS_SB(sb)->data[sbstart(sb)].sb;
}

static inline struct super_block *advfs_lower_super_idx(
					const struct super_block *sb,
					int index)
{
	BUG_ON(!sb || index < 0);
	return ADVFS_SB(sb)->data[index].sb;
}

static inline void advfs_set_lower_super_idx(struct super_block *sb,
					       int index,
					       struct super_block *val)
{
	BUG_ON(!sb || index < 0);
	ADVFS_SB(sb)->data[index].sb = val;
}

static inline void advfs_set_lower_super(struct super_block *sb,
					   struct super_block *val)
{
	BUG_ON(!sb);
	ADVFS_SB(sb)->data[sbstart(sb)].sb = val;
}

/* Branch count macros. */
static inline int branch_count(const struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	return atomic_read(&ADVFS_SB(sb)->data[index].open_files);
}

static inline void set_branch_count(struct super_block *sb, int index, int val)
{
	BUG_ON(!sb || index < 0);
	atomic_set(&ADVFS_SB(sb)->data[index].open_files, val);
}

static inline void branchget(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	atomic_inc(&ADVFS_SB(sb)->data[index].open_files);
}

static inline void branchput(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	atomic_dec(&ADVFS_SB(sb)->data[index].open_files);
}

/* Dentry macros */
static inline void advfs_set_lower_dentry_idx(struct dentry *dent, int index,
						struct dentry *val)
{
	BUG_ON(!dent || index < 0);
	ADVFS_D(dent)->lower_paths[index].dentry = val;
}

static inline struct dentry *advfs_lower_dentry_idx(
				const struct dentry *dent,
				int index)
{
	BUG_ON(!dent || index < 0);
	return ADVFS_D(dent)->lower_paths[index].dentry;
}

static inline struct dentry *advfs_lower_dentry(const struct dentry *dent)
{
	BUG_ON(!dent);
	return advfs_lower_dentry_idx(dent, dbstart(dent));
}

static inline void advfs_set_lower_mnt_idx(struct dentry *dent, int index,
					     struct vfsmount *mnt)
{
	BUG_ON(!dent || index < 0);
	ADVFS_D(dent)->lower_paths[index].mnt = mnt;
}

static inline struct vfsmount *advfs_lower_mnt_idx(
					const struct dentry *dent,
					int index)
{
	BUG_ON(!dent || index < 0);
	return ADVFS_D(dent)->lower_paths[index].mnt;
}

static inline struct vfsmount *advfs_lower_mnt(const struct dentry *dent)
{
	BUG_ON(!dent);
	return advfs_lower_mnt_idx(dent, dbstart(dent));
}

/* Macros for locking a dentry. */
enum advfs_dentry_lock_class {
	ADVFS_DMUTEX_NORMAL,
	ADVFS_DMUTEX_ROOT,
	ADVFS_DMUTEX_PARENT,
	ADVFS_DMUTEX_CHILD,
	ADVFS_DMUTEX_WHITEOUT,
	ADVFS_DMUTEX_REVAL_PARENT, /* for file/dentry revalidate */
	ADVFS_DMUTEX_REVAL_CHILD,   /* for file/dentry revalidate */
};

static inline void advfs_lock_dentry(struct dentry *d,
				       unsigned int subclass)
{
	BUG_ON(!d);
	mutex_lock_nested(&ADVFS_D(d)->lock, subclass);
}

static inline void advfs_unlock_dentry(struct dentry *d)
{
	BUG_ON(!d);
	mutex_unlock(&ADVFS_D(d)->lock);
}

static inline struct dentry *advfs_lock_parent(struct dentry *d,
						 unsigned int subclass)
{
	struct dentry *p;

	BUG_ON(!d);
	p = dget_parent(d);
	if (p != d)
		mutex_lock_nested(&ADVFS_D(p)->lock, subclass);
	return p;
}

static inline void advfs_unlock_parent(struct dentry *d, struct dentry *p)
{
	BUG_ON(!d);
	BUG_ON(!p);
	if (p != d) {
		BUG_ON(!mutex_is_locked(&ADVFS_D(p)->lock));
		mutex_unlock(&ADVFS_D(p)->lock);
	}
	dput(p);
}

static inline void verify_locked(struct dentry *d)
{
	BUG_ON(!d);
	BUG_ON(!mutex_is_locked(&ADVFS_D(d)->lock));
}

/* macros to put lower objects */

/*
 * iput lower inodes of an advfs dentry, from bstart to bend.  If
 * @free_lower is true, then also kfree the memory used to hold the lower
 * object pointers.
 */
static inline void iput_lowers(struct inode *inode,
			       int bstart, int bend, bool free_lower)
{
	struct inode *lower_inode;
	int bindex;

	BUG_ON(!inode);
	BUG_ON(!ADVFS_I(inode));
	BUG_ON(bstart < 0);

	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_inode = advfs_lower_inode_idx(inode, bindex);
		if (lower_inode) {
			advfs_set_lower_inode_idx(inode, bindex, NULL);
			/* see Documentation/filesystems/advfs/issues.txt */
			lockdep_off();
			iput(lower_inode);
			lockdep_on();
		}
	}

	if (free_lower) {
		kfree(ADVFS_I(inode)->lower_inodes);
		ADVFS_I(inode)->lower_inodes = NULL;
	}
}

/* iput all lower inodes, and reset start/end branch indices to -1 */
static inline void iput_lowers_all(struct inode *inode, bool free_lower)
{
	int bstart, bend;

	BUG_ON(!inode);
	BUG_ON(!ADVFS_I(inode));
	bstart = ibstart(inode);
	bend = ibend(inode);
	BUG_ON(bstart < 0);

	iput_lowers(inode, bstart, bend, free_lower);
	ibstart(inode) = ibend(inode) = -1;
}

/*
 * dput/mntput all lower dentries and vfsmounts of an advfs dentry, from
 * bstart to bend.  If @free_lower is true, then also kfree the memory used
 * to hold the lower object pointers.
 *
 * XXX: implement using path_put VFS macros
 */
static inline void path_put_lowers(struct dentry *dentry,
				   int bstart, int bend, bool free_lower)
{
	struct dentry *lower_dentry;
	struct vfsmount *lower_mnt;
	int bindex;

	BUG_ON(!dentry);
	BUG_ON(!ADVFS_D(dentry));
	BUG_ON(bstart < 0);

	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_dentry = advfs_lower_dentry_idx(dentry, bindex);
		if (lower_dentry) {
			advfs_set_lower_dentry_idx(dentry, bindex, NULL);
			dput(lower_dentry);
		}
		lower_mnt = advfs_lower_mnt_idx(dentry, bindex);
		if (lower_mnt) {
			advfs_set_lower_mnt_idx(dentry, bindex, NULL);
			mntput(lower_mnt);
		}
	}

	if (free_lower) {
		kfree(ADVFS_D(dentry)->lower_paths);
		ADVFS_D(dentry)->lower_paths = NULL;
	}
}

/*
 * dput/mntput all lower dentries and vfsmounts, and reset start/end branch
 * indices to -1.
 */
static inline void path_put_lowers_all(struct dentry *dentry, bool free_lower)
{
	int bstart, bend;

	BUG_ON(!dentry);
	BUG_ON(!ADVFS_D(dentry));
	bstart = dbstart(dentry);
	bend = dbend(dentry);
	BUG_ON(bstart < 0);

	path_put_lowers(dentry, bstart, bend, free_lower);
	dbstart(dentry) = dbend(dentry) = -1;
}

#endif	/* not _FANOUT_H */
