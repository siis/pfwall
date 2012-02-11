/* Module to change the CWD of a process to the adversary's */

#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/hardirq.h>
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
#include <linux/namei.h>
#include <linux/fs_struct.h>

/* TODO: Make the attacker's home directory specifiable in the rule itself,
 * instead of hardcoding it */

/* List of utility programs for which we shouldn't change starting WD */
		/* Utility programs are run from bash scripts which chdir to
		   the right directory before forking and execing them with
		   relative paths as arguments. E.g., chdir /safe && ls . .
		   We don't want to flag these programs */
/* TODO: Decide if this also should simply appear in rules */
/* Perl is included because of it always having . as the last part of its @INC */
char *uprogs[] = { "perl", "ls", "find", "cp", "mv", "rm", "chmod",
	"grep", "tar", "mkdir", "ln", "setfiles", "awk", "sed", "touch", "pwd", 0 };

/* TODO: Make this into a dictionary if we are keeping this */
static int in_utility_programs(char *comm)
{
	int i = 0 ;
	for (i = 0; uprogs[i]; i++)
		if (!strcmp(comm, uprogs[i]))
			return 1;
	return 0;
}

static int chdir_task(struct task_struct *task, char *filename)
{
	struct path path;
	int error;
	mm_segment_t old_fs = get_fs();

	PFW_SYSCALL(error = user_path_dir(filename, &path));
	if (error)
		goto out;

	set_fs_pwd(task->fs, &path);

	path_put(&path);
out:
	return error;

}

int pft_cwd_target(struct pf_packet_context *p, void *target_specific_data)
{
	int rc = 0;

	 /* Utility programs are run from bash scripts which chdir to the right
	  * directory before forking and execing them with relative paths as
	  * arguments. E.g., chdir /safe && ls . .  We don't want to flag these
	  * programs */

	if (!in_utility_programs(current->comm)) {
		chdir_task(current, ATTACKER_HOMEDIR);
	}

	if (rc < 0)
		return rc;
	else
		return PF_CONTINUE;
}

static int __init pft_cwd_target_init(void)
{
	int rc = 0;
	struct pft_target_module cwd_target_module = {
		.list = {NULL, NULL},
		.name = "cwd",
//		.context_mask = 0,
		.target = &pft_cwd_target
	};

	printk(KERN_INFO PFWALL_PFX "cwd target module initializing\n");

	rc = pf_register_target(&cwd_target_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_target cwd failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_cwd_target_init);
