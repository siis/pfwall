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

/* This file contains the routines for maintaining readdir state. */

/*
 * There are two structures here, rdstate which is a hash table
 * of the second structure which is a filldir_node.
 */

/*
 * This is a struct kmem_cache for filldir nodes, because we allocate a lot
 * of them and they shouldn't waste memory.  If the node has a small name
 * (as defined by the dentry structure), then we use an inline name to
 * preserve kmalloc space.
 */
static struct kmem_cache *advfs_filldir_cachep;

int advfs_init_filldir_cache(void)
{
	advfs_filldir_cachep =
		kmem_cache_create("advfs_filldir",
				  sizeof(struct filldir_node), 0,
				  SLAB_RECLAIM_ACCOUNT, NULL);

	return (advfs_filldir_cachep ? 0 : -ENOMEM);
}

void advfs_destroy_filldir_cache(void)
{
	if (advfs_filldir_cachep)
		kmem_cache_destroy(advfs_filldir_cachep);
}

/*
 * This is a tuning parameter that tells us roughly how big to make the
 * hash table in directory entries per page.  This isn't perfect, but
 * at least we get a hash table size that shouldn't be too overloaded.
 * The following averages are based on my home directory.
 * 14.44693	Overall
 * 12.29	Single Page Directories
 * 117.93	Multi-page directories
 */
#define DENTPAGE 4096
#define DENTPERONEPAGE 12
#define DENTPERPAGE 118
#define MINHASHSIZE 1
static int guesstimate_hash_size(struct inode *inode)
{
	struct inode *lower_inode;
	int bindex;
	int hashsize = MINHASHSIZE;

	if (ADVFS_I(inode)->hashsize > 0)
		return ADVFS_I(inode)->hashsize;

	for (bindex = ibstart(inode); bindex <= ibend(inode); bindex++) {
		lower_inode = advfs_lower_inode_idx(inode, bindex);
		if (!lower_inode)
			continue;

		if (i_size_read(lower_inode) == DENTPAGE)
			hashsize += DENTPERONEPAGE;
		else
			hashsize += (i_size_read(lower_inode) / DENTPAGE) *
				DENTPERPAGE;
	}

	return hashsize;
}

int advfs_init_rdstate(struct file *file)
{
	BUG_ON(sizeof(loff_t) !=
	       (sizeof(unsigned int) + sizeof(unsigned int)));
	BUG_ON(ADVFS_F(file)->rdstate != NULL);

	ADVFS_F(file)->rdstate = advfs_alloc_rdstate(file->f_path.dentry->d_inode,
						 fbstart(file));

	return (ADVFS_F(file)->rdstate ? 0 : -ENOMEM);
}

struct advfs_dir_state *advfs_find_rdstate(struct inode *inode, loff_t fpos)
{
	struct advfs_dir_state *rdstate = NULL;
	struct list_head *pos;

	spin_lock(&ADVFS_I(inode)->rdlock);
	list_for_each(pos, &ADVFS_I(inode)->readdircache) {
		struct advfs_dir_state *r =
			list_entry(pos, struct advfs_dir_state, cache);
		if (fpos == rdstate2offset(r)) {
			ADVFS_I(inode)->rdcount--;
			list_del(&r->cache);
			rdstate = r;
			break;
		}
	}
	spin_unlock(&ADVFS_I(inode)->rdlock);
	return rdstate;
}

struct advfs_dir_state *advfs_alloc_rdstate(struct inode *inode, int bindex)
{
	int i = 0;
	int hashsize;
	unsigned long mallocsize = sizeof(struct advfs_dir_state);
	struct advfs_dir_state *rdstate;

	hashsize = guesstimate_hash_size(inode);
	mallocsize += hashsize * sizeof(struct list_head);
	mallocsize = __roundup_pow_of_two(mallocsize);

	/* This should give us about 500 entries anyway. */
	if (mallocsize > PAGE_SIZE)
		mallocsize = PAGE_SIZE;

	hashsize = (mallocsize - sizeof(struct advfs_dir_state)) /
		sizeof(struct list_head);

	rdstate = kmalloc(mallocsize, GFP_KERNEL);
	if (unlikely(!rdstate))
		return NULL;

	spin_lock(&ADVFS_I(inode)->rdlock);
	if (ADVFS_I(inode)->cookie >= (MAXRDCOOKIE - 1))
		ADVFS_I(inode)->cookie = 1;
	else
		ADVFS_I(inode)->cookie++;

	rdstate->cookie = ADVFS_I(inode)->cookie;
	spin_unlock(&ADVFS_I(inode)->rdlock);
	rdstate->offset = 1;
	rdstate->access = jiffies;
	rdstate->bindex = bindex;
	rdstate->dirpos = 0;
	rdstate->hashentries = 0;
	rdstate->size = hashsize;
	for (i = 0; i < rdstate->size; i++)
		INIT_LIST_HEAD(&rdstate->list[i]);

	return rdstate;
}

static void free_filldir_node(struct filldir_node *node)
{
	if (node->namelen >= DNAME_INLINE_LEN)
		kfree(node->name);
	kmem_cache_free(advfs_filldir_cachep, node);
}

void advfs_free_rdstate(struct advfs_dir_state *state)
{
	struct filldir_node *tmp;
	int i;

	for (i = 0; i < state->size; i++) {
		struct list_head *head = &(state->list[i]);
		struct list_head *pos, *n;

		/* traverse the list and deallocate space */
		list_for_each_safe(pos, n, head) {
			tmp = list_entry(pos, struct filldir_node, file_list);
			list_del(&tmp->file_list);
			free_filldir_node(tmp);
		}
	}

	kfree(state);
}

struct filldir_node *advfs_find_filldir_node(struct advfs_dir_state *rdstate,
				       const char *name, int namelen,
				       int is_whiteout)
{
	int index;
	unsigned int hash;
	struct list_head *head;
	struct list_head *pos;
	struct filldir_node *cursor = NULL;
	int found = 0;

	BUG_ON(namelen <= 0);

	hash = full_name_hash(name, namelen);
	index = hash % rdstate->size;

	head = &(rdstate->list[index]);
	list_for_each(pos, head) {
		cursor = list_entry(pos, struct filldir_node, file_list);

		if (cursor->namelen == namelen && cursor->hash == hash &&
		    !strncmp(cursor->name, name, namelen)) {
			/*
			 * a duplicate exists, and hence no need to create
			 * entry to the list
			 */
			found = 1;

			/*
			 * if a duplicate is found in this branch, and is
			 * not due to the caller looking for an entry to
			 * whiteout, then the file system may be corrupted.
			 */
			if (unlikely(!is_whiteout &&
				     cursor->bindex == rdstate->bindex))
				printk(KERN_ERR "advfs: filldir: possible "
				       "I/O error: a file is duplicated "
				       "in the same branch %d: %s\n",
				       rdstate->bindex, cursor->name);
			break;
		}
	}

	if (!found)
		cursor = NULL;

	return cursor;
}

int advfs_add_filldir_node(struct advfs_dir_state *rdstate, const char *name,
		     int namelen, int bindex, int whiteout)
{
	struct filldir_node *new;
	unsigned int hash;
	int index;
	int err = 0;
	struct list_head *head;

	BUG_ON(namelen <= 0);

	hash = full_name_hash(name, namelen);
	index = hash % rdstate->size;
	head = &(rdstate->list[index]);

	new = kmem_cache_alloc(advfs_filldir_cachep, GFP_KERNEL);
	if (unlikely(!new)) {
		err = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&new->file_list);
	new->namelen = namelen;
	new->hash = hash;
	new->bindex = bindex;
	new->whiteout = whiteout;

	if (namelen < DNAME_INLINE_LEN) {
		new->name = new->iname;
	} else {
		new->name = kmalloc(namelen + 1, GFP_KERNEL);
		if (unlikely(!new->name)) {
			kmem_cache_free(advfs_filldir_cachep, new);
			new = NULL;
			goto out;
		}
	}

	memcpy(new->name, name, namelen);
	new->name[namelen] = '\0';

	rdstate->hashentries++;

	list_add(&(new->file_list), head);
out:
	return err;
}
