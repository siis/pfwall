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
#include <asm/syscall.h>
#include <linux/syscalls.h>
#include <linux/stat.h>

#define DICT_HASH_BITS            8
#define DICT_HTABLE_SIZE (1 << DICT_HASH_BITS)

int first_arg_set[] = {5, 8, 9, 10, /* 11,*/ 12, 14, 15, 21, 30, 38, 39, 40, 61, 83, 85, 92, 182, 193, 198, 212, 217, 271, /* check */ 106, 107, 195, 196};
#define FIRST_ARG_NR 27

int second_arg_set[] = {292, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 320 /* TODO: __NR_socketcall */};
#define SECOND_ARG_NR 15

int check_set[] = {106, 107, 195, 196, 300};
#define CHECK_NR 5


#define SYMLINK_CREATE 0x1
#define FILE_CREATE 0x2
#define DIR_CREATE 0x4
#define FILE_DELETE 0x8
#define DIR_DELETE 0x10

# if 0
char __user *get_last(char __user *filename)
{
	char __user *ptr = (char __user *) filename + strlen(filename);
	while ((*ptr != '/') && (ptr != filename))
		ptr--;
	if (*ptr == '/')
		ptr++;
	return ptr;
}

char __user *get_first(char __user *filename)
{
	char __user *ptr = (char __user *) filename;

	while (ptr && ptr != filename + strlen(filename) && (ptr[0] != '/'))
		ptr++;
	ptr++;
	return ptr;
}
#endif

/*
   Cases :
   NOTE: If attacker does not have permission, nothing happens.
   flag = SYMLINK_CREATE
   (1) Symlink when syscall is create-like points to non-existent file
   (2) Symlink is not created for check-like system calls (stat, access et al.)
   (3) Symlink in all other cases points to existing file
	TODO: Create directory along path if it doesn't exist.

   flag = FILE_CREATE
   A normal file is created, based on the type requested.

   flag = FILE_DELETE/DIR_DELETE (Use FILE_DELETE for any file type -
   symlinks also)
   The object referred to by filename is deleted.
*/

int object_action(char __user *filename, int flag)
{
	/* Not there, try creating a symlink */
	/* Try out all suitable attackers until one can create
		the symlink */
	const struct cred *old_cred;
	struct cred *override_cred;
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int sn = ptregs->orig_ax; /* Syscall number */
	int i, ret = PF_ACCEPT;
	mm_segment_t old_fs = get_fs();
	char *tmp_f = NULL;

	static int hack_ctr = 0; /* to allow /tmp after some tries */

	/* For cases where random filenames are requested in /tmp */
	if (!strcmp(current->comm, "tempfile"))
		goto out;
	if ((!strncmp(filename, "/tmp/", 5) || !strncmp(filename, "file", 4)) && !(hack_ctr++ % 8)) {
		printk(KERN_INFO "attacker: Allowing: %s: %s\n", filename, current->comm);
		goto out;
	}

	tmp_f = kzalloc(PATH_MAX, GFP_ATOMIC);
	if (!tmp_f)
		goto out;

	/* For each possible attacker */
	for (i = 0; uid_array[i]; i++) {
		if (current->cred->fsuid == uid_array[i])
			continue;
		override_cred = prepare_creds();
		if (!override_cred) {
			ret = -ENOMEM;
			goto out;
		}
		old_cred = override_creds(override_cred);
		override_cred->fsuid = uid_array[i];
		override_cred->fsgid = uid_array[i];
		cap_clear(override_cred->cap_effective);
		override_creds(override_cred);

		/* Perform syscalls */

		set_fs(KERNEL_DS);
		if (flag == SYMLINK_CREATE) {
			if (((sn == __NR_open) && (ptregs->cx & O_CREAT)
				&& ((ptregs->cx & O_NOFOLLOW) == 0)) || sn == __NR_creat
				|| sn == __NR_mknod) {
				/* Point to non-existent file */

				strcpy(tmp_f, new_target_file);
				strcat(tmp_f, "_");
				/* TODO: Possible bug page fault: use copy_from_user */
				strcat(tmp_f, get_last(filename));

				current->kernel_request++;
				ret = sys_symlink(tmp_f, filename);
				current->kernel_request--;
			} else if (sn == __NR_mkdir || sn == __NR_mkdirat) {
			} else if (sn == __NR_stat || __NR_lstat || __NR_stat64 || __NR_lstat64 || __NR_fstatat64) {
				/* Point to existing file */
				current->kernel_request++;
				ret = sys_symlink(existing_target_file, filename);
				current->kernel_request--;
			} else {
				/* Point to existing file */
				current->kernel_request++;
				ret = sys_symlink(existing_target_file, filename);
				current->kernel_request--;
			}
		} else if (flag == FILE_CREATE) {
			/* Create can be called either for coverage
			   on stat, access, or to test squatting.
			   In the latter, the type to create can be
			   determined from syscall, whereas for the
			   former, we assume a normal "file" type */
			current->kernel_request++;
			ret = sys_open(filename, O_CREAT, 0777);
			if (ret > 0) {
				sys_close(ret);
				ret = 0; /* Success */
			}
			current->kernel_request--;
		} else if (flag == DIR_CREATE) {
			current->kernel_request++;
			ret = sys_mkdir(filename, 0777);
			current->kernel_request--;
		} /* TODO: Other file types */
		else if (flag == FILE_DELETE) {
			current->kernel_request++;
			ret = sys_unlink(filename);
#if 0
			strcpy(tmp_f, filename);
			strcat(tmp_f, ".deleted_by_attacker");
			/* Check if tmp_f exists */
			ret = sys_access(tmp_f, 0); /* F_OK */
			if (ret == 0)
				ret = sys_unlink(filename);
			else if (ret == -ENOENT) {
				ret = sys_rename(filename, tmp_f);
				if (ret == 0) {
					printk(KERN_INFO "attacker: %s SUCCESS!: %s, proc euid: %d attacker uid: %d, process: %s, renamed from %s to %s\n", ((flag == SYMLINK_CREATE) ? "Symlink" : ((flag == FILE_CREATE) ? "Normal" : (flag == FILE_DELETE) ? "Delete" : "Error")), filename, current->cred->fsuid, uid_array[i], current->comm, filename, tmp_f);
				}
			}
#endif
			current->kernel_request--;
		}
		set_fs(old_fs);
		revert_creds(old_cred);
		put_cred(override_cred);

		if (ret == -ENOENT) {
//			printk(KERN_INFO "attacker: create directory: %s\n", filename);
			/* TODO: Create directory here for each path fragment */
		} else if (ret == 0) {
			/* Successfully created! */
			/* Subsequent rules can log and
			set state for detection */
			printk(KERN_INFO "attacker: %s SUCCESS!: %s, proc euid: %d attacker uid: %d, process: %s\n", ((flag == SYMLINK_CREATE) ? "Symlink" : ((flag == FILE_CREATE) ? "Normal" : "Delete")), filename, current->cred->fsuid, uid_array[i], current->comm);
			break;
		}
		/* This attacker couldn't succeed, try
		   next possible attacker */
	}
out:
	if (tmp_f)
		kfree(tmp_f);
	return ret;
}


/* Set a (k, v) pair, delete a (k, v) pair, return a verdict */
int pft_symlink_target(struct pf_packet_context *p, void *target_specific_data)
{
	/* Get the filename from syscall arguments */
	int nr_arg = 0;
	int tret = 0, i;
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int sn = ptregs->orig_ax; /* Syscall number */

	// char *tmp_str;
	char __user *filename; /* Filename from system call argument */

	mm_segment_t old_fs = get_fs();

	for (i = 0; i < FIRST_ARG_NR; i++) {
		if (sn == first_arg_set[i]) {
			nr_arg = 1;
			break;
		}
	}
	for (i = 0; i < SECOND_ARG_NR; i++) {
		if (sn == second_arg_set[i]) {
			nr_arg = 2;
			break;
		}
	}

	switch(nr_arg) {
		case 1:
			filename = (char __user *) ptregs->bx;
			break;
		case 2:
			filename = (char __user *) ptregs->cx;
			break;
		default:
			/* Not in list of syscalls performing nameres */
			return PF_ACCEPT;
	}

	/* Copy userspace string to kernel */
	#if 0
	tmp_str = __getname();
	if (tmp_str) {
		tret = do_getname(filename, tmp_str);
		if (retval < 0) {
			goto out_release_path;
			__putname(tmp_str);
		}
	}
	#endif

	/* Check if file exists */
	#if 0
	set_fs(KERNEL_DS);
	tret = sys_access(new_target_file, 0); /* F_OK */
	set_fs(old_fs);
	if (tret == 0) {
		printk(KERN_INFO "attacker: new_target_file present! Deleting ...\n");
		set_fs(KERNEL_DS);
		sys_unlink(new_target_file);
		set_fs(old_fs);
	}
	#endif

	/* Does file already exist? */

	set_fs(KERNEL_DS);
	current->kernel_request++;
	tret = sys_access(filename, 0); /* F_OK */
	current->kernel_request--;
	set_fs(old_fs);

	if (tret == -EACCES || tret == -EPERM) {
		/* Access denied, move on .. */
	} else if (tret == -ENOENT) {
		/* if (flags & SYMLINK/HARDLINK/NORMAL - syscall) */
		/* If symbolic link, then only create on non-check calls */
		/* On check-calls, create file for exploring different paths */
		for (i = 0; i < CHECK_NR; i++) {
			if (sn == check_set[i]) {
				/* TODO: Make this configurable */
				tret = object_action(filename, FILE_CREATE);
				goto out;
			}
		}
		tret = object_action(filename, SYMLINK_CREATE);
	} else if (tret < 0) {
		/* Some other error, move on .. */
	} else if (tret == 0) {
		/* Exists, try to delete and create it if it does not
		 already have the properties required */
		// if (flags & SYMLINK) {
		/* Check that it is not already a symlink */
		struct stat64 buf;
		set_fs(KERNEL_DS);
		current->kernel_request++;
		tret = sys_stat64(filename, &buf);
		current->kernel_request--;
		set_fs(old_fs);
		if (!S_ISLNK(buf.st_mode)) {
			tret = object_action(filename, FILE_DELETE);
			if (tret == 0) {
				/* if (flags & SYMLINK/HARDLINK/NORMAL - syscall) */
				tret = object_action(filename, SYMLINK_CREATE);
			}
		}
	}

out:
	if (tret == 0) /* Attacker successful in influencing namespace */
		tret = PF_CONTINUE;
	else
		tret = PF_ACCEPT;

	/*
	if (tret != PF_ACCEPT || tret != PF_CONTINUE) {
//		printk(KERN_INFO "attacker: tret not valid!\n");
		tret = PF_ACCEPT;
	}
	*/
//	putname(tmp_str);
	return tret;
}

static int __init pft_symlink_target_init(void)
{
	int rc = 0;
	int i;
	struct pft_target_module symlink_target_module = {
		.list = {NULL, NULL},
		.name = "symlink",
//		.context_mask = 0,
		.target = &pft_symlink_target
	};

	printk(KERN_INFO PFWALL_PFX "symlink target module initializing\n");
	for (i = 0; i < DICT_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&current->dict_htable[i]);

	rc = pf_register_target(&symlink_target_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_target symlink failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_symlink_target_init);
