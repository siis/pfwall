/*
 * Copyright (c) 2006-2011 Erez Zadok
 * Copyright (c) 2006      Charles P. Wright
 * Copyright (c) 2006-2007 Josef 'Jeff' Sipek
 * Copyright (c) 2006      Junjiro Okajima
 * Copyright (c) 2006      David P. Quigley
 * Copyright (c) 2006-2011 Stony Brook University
 * Copyright (c) 2006-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "adv.h"

/*
 * Super-user IO work Queue - sometimes we need to perform actions which
 * would fail due to the unix permissions on the parent directory (e.g.,
 * rmdir a directory which appears empty, but in reality contains
 * whiteouts).
 */

static struct workqueue_struct *superio_workqueue;

int __init advfs_init_sioq(void)
{
	int err;

	superio_workqueue = create_workqueue("advfs_siod");
	if (!IS_ERR(superio_workqueue))
		return 0;

	err = PTR_ERR(superio_workqueue);
	printk(KERN_ERR "advfs: create_workqueue failed %d\n", err);
	superio_workqueue = NULL;
	return err;
}

void advfs_stop_sioq(void)
{
	if (superio_workqueue)
		destroy_workqueue(superio_workqueue);
}

void advfs_run_sioq(work_func_t func, struct sioq_args *args)
{
	INIT_WORK(&args->work, func);

	init_completion(&args->comp);
	while (!queue_work(superio_workqueue, &args->work)) {
		/* TODO: do accounting if needed */
		schedule();
	}
	wait_for_completion(&args->comp);
}

void __advfs_create(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct create_args *c = &args->create;

	args->err = vfs_create(c->parent, c->dentry, c->mode, c->nd);
	complete(&args->comp);
}

void __advfs_mkdir(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct mkdir_args *m = &args->mkdir;

	args->err = vfs_mkdir(m->parent, m->dentry, m->mode);
	complete(&args->comp);
}

void __advfs_mknod(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct mknod_args *m = &args->mknod;

	args->err = vfs_mknod(m->parent, m->dentry, m->mode, m->dev);
	complete(&args->comp);
}

void __advfs_symlink(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct symlink_args *s = &args->symlink;

	args->err = vfs_symlink(s->parent, s->dentry, s->symbuf);
	complete(&args->comp);
}

void __advfs_unlink(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct unlink_args *u = &args->unlink;

	args->err = vfs_unlink(u->parent, u->dentry);
	complete(&args->comp);
}
