#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
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
#include <linux/lsm_audit.h>
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/time.h>

#include "../../av_permissions.h"
#include "../../flask.h"
#include "../../trusted_subjects.h"
#include <asm/ftrace.h>
#include <asm/syscall.h>
#include <asm/stacktrace.h>

#define MAX_LOG_STRLEN 256
#define MAX_PROC_HIER 256

#define PF_SYSCALL_STRING 1
#define PF_SYSCALL_INT	  2

/* For a user stack trace:
 * First, try to use .eh_frame section as loaded in memory
 * If fail, next try to use .debug_frame of separate debug file
 * Else, fall back to normal rollback (prologue analysis not yet fully
 * working) */

#define SECDEBUGFRAME_NAME ".debug_frame"
#define SECEHFRAME_NAME ".eh_frame"
#define SECSYMTAB_NAME ".symtab"
#define SECSYMTABSTRINGS_NAME ".strtab"

struct pft_target_log
{
	int context;
	char string[MAX_LOG_STRLEN];
	int arg_num;
	int offset;
	int type;
};

/*
 * Callback to create wall_interfaces file
 */

static struct dentry *create_wall_interfaces_file_callback(const char *filename,
                                              struct dentry *parent,
                                              int mode,
                                              struct rchan_buf *buf,
                                              int *is_global)
{
        return debugfs_create_file(filename, mode, parent, buf,
                                   &relay_file_operations);
}

/*
 * Callback to remove wall_interfaces file
 */

static int remove_wall_interfaces_file_callback(struct dentry* dentry)
{
	debugfs_remove(dentry);
	return 0;
}

/*
 * Callback when one subbuffer is full
 */

static int subbuf_wall_interfaces_start_callback(struct rchan_buf *buf, void *subbuf,
                                     void *prev_subbuf, size_t prev_padding)
{
	atomic_t* dropped;
	/* if (prev_subbuf)
		* ((size_t*) prev_subbuf) = prev_padding; */
        if (!relay_buf_full(buf))
                return 1;
	dropped = buf->chan->private_data;
	atomic_inc(dropped);
	if (atomic_read(dropped) % 5000 == 0)
		printk(KERN_INFO PFWALL_PFX "log: log full, dropped: %d\n", atomic_read(dropped));
        return 0;
}

/* Relay channel operations */

DEFINE_SPINLOCK(wall_lock);
unsigned long wall_lock_flags;

atomic_t dropped = ATOMIC_INIT(0);
static int subbuf_wall_interfaces_start_callback(struct rchan_buf *buf, void *subbuf, void *prev_subbuf, size_t prev_padding);
static int remove_wall_interfaces_file_callback(struct dentry* dentry);
static struct dentry *create_wall_interfaces_file_callback(const char *filename, struct dentry *parent, int mode, struct rchan_buf *buf, int *is_global);
static struct rchan_callbacks wall_interfaces_relay_callbacks =
{
	.subbuf_start		= subbuf_wall_interfaces_start_callback,
	.create_buf_file	= create_wall_interfaces_file_callback,
	.remove_buf_file	= remove_wall_interfaces_file_callback,
};
struct rchan* wall_rchan;
EXPORT_SYMBOL(wall_rchan);

int pft_type_context(struct pf_packet_context *p)
{
	/* If we are matching by string, all this context is gathered already
	 * in pfwall_selinux_details */
	char* scontext = NULL, *tcontext = NULL, *stype = NULL, *ttype = NULL, *path = NULL;
	int scontext_len, tcontext_len;
	int rc = 0;
	/* Get contexts from SIDs */
	/* Let us hold a lock so we won't be preempted -- till we finish gathering p data  -- to be done later */
	rc = security_sid_to_context (p->info.ssid, &scontext, &scontext_len);
        if (rc)
              goto end;
	rc = security_sid_to_context (p->info.tsid, &tcontext, &tcontext_len);
        if (rc)
              goto end;

	path = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (path == NULL) {
		printk(KERN_INFO PFWALL_PFX "path allocation failed\n");
		rc = -ENOMEM;
		goto end;
	}

	/* Extract type from context */
	stype = context_to_type(scontext);
	ttype = context_to_type(tcontext);

	if (stype)
		strcpy(p->info.scontext, stype);
	else
		strcpy(p->info.scontext, scontext); /* initial sid */

	if (ttype)
		strcpy(p->info.tcontext, ttype);
	else
		strcpy(p->info.tcontext, tcontext); /* initial sid */

	# if 0
	p->info.scontext	= kstrdup(stype, GFP_ATOMIC);
	if (!(p->info.scontext)) {
		rc = -ENOMEM;
		goto end;
	}
	p->info.tcontext	= kstrdup(ttype, GFP_ATOMIC);
	if (!(p->info.tcontext)) {
		rc = -ENOMEM;
		goto end;
	}
	#endif

	p->context |= PF_CONTEXT_TYPE;

end:
	if (scontext)
		kfree(scontext);
	if (tcontext)
		kfree(tcontext);
	if (stype)
		kfree(stype);
	if (ttype)
		kfree(ttype);
	if (path)
		kfree(path);
	return 0;
}
EXPORT_SYMBOL(pft_type_context);


int pft_binary_path_context(struct pf_packet_context *p)
{
	struct file* exe_file = NULL;
	int rc = 0;
	char *ptemp = NULL;
	char *path  = NULL;
	/* Get process binary path; this context is needed to check if we need to monitor this binary */
	exe_file = current->mm->exe_file;
	if (!exe_file) {
		printk(KERN_INFO PFWALL_PFX "No executable file\n");
		rc = -ENOMEM;
		goto end;
	}

	path = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (path == NULL) {
		printk(KERN_INFO PFWALL_PFX "path allocation failed\n");
		rc = -ENOMEM;
		goto end;
	}

	ptemp = d_path(&(exe_file->f_path), path, PAGE_SIZE);
	if (IS_ERR(ptemp)) {
		printk(KERN_INFO PFWALL_PFX "Path conversion failed\n");
		rc = PTR_ERR(ptemp);
		goto end;
	}

	strcpy(p->info.binary_path, ptemp);
//	p->info.binary_path = kstrdup(ptemp, GFP_ATOMIC);

	p->context |= PF_CONTEXT_BINARY_PATH;

end:
	if (path)
		kfree(path);
	return rc;
}
EXPORT_SYMBOL(pft_binary_path_context);

int pft_binary_path_inode_context(struct pf_packet_context *p)
{
	struct file* exe_file = NULL;
	int rc = 0;
	/* Get process binary path; this context is needed to check if we need to monitor this binary */
	exe_file = current->mm->exe_file;
	if (!exe_file) {
		printk(KERN_INFO PFWALL_PFX "No executable file\n");
		rc = -ENOMEM;
		goto end;
	}

	p->info.binary_inoden = exe_file->f_dentry->d_inode->i_ino;

	p->context |= PF_CONTEXT_BINARY_PATH_INODE;
end:
	return rc;
}
EXPORT_SYMBOL(pft_binary_path_inode_context);

int pft_auditdata_context(struct pf_packet_context *p)
{
	int rc = 0;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	struct common_audit_data *a = p->auditdata;

	strcpy(p->info.filename, "N/A");
//	p->info.filename = kstrdup("N/A", GFP_ATOMIC);
	if (a) {
		switch (a->type) {
			case LSM_AUDIT_DATA_DENTRY: {
				dentry = a->u.dentry;
				inode = a->u.dentry->d_inode;
				break;
			}
			case LSM_AUDIT_DATA_INODE: {
				inode = a->u.inode;
				dentry = d_find_alias(inode);
				break;
			}
			case LSM_AUDIT_DATA_PATH: {
				inode = a->u.path.dentry->d_inode;
				dentry = d_find_alias(inode);
				break;
			}
			case LSM_AUDIT_DATA_NET: {
				if (a->u.net.sk) {
					struct sock *sk = a->u.net.sk;
					struct unix_sock *u;

					if (sk->sk_family == AF_UNIX) {
						u = unix_sk(sk);
						if (u->dentry) {
							dentry = u->dentry;
							inode = dentry->d_inode;
						}
						break;
					}
				}
			}
			default:
			;
		}
	}

	p->stat_res.st_ino = 0;
	p->stat_res.st_uid = 0;
	p->stat_res.st_gid = 0;
	p->stat_res.st_mode = 0;
	p->stat_res.st_nlink = 0;
	if (dentry) {
		strcpy(p->info.filename, dentry->d_name.name);
		if (dentry->d_inode) { /* inode may not have been created yet */
			p->info.filename_inoden = dentry->d_inode->i_ino;
			p->stat_res.st_ino = dentry->d_inode->i_ino;
			p->stat_res.st_uid = dentry->d_inode->i_uid;
			p->stat_res.st_gid = dentry->d_inode->i_gid;
			p->stat_res.st_mode = dentry->d_inode->i_mode;
			p->stat_res.st_nlink = dentry->d_inode->i_nlink;
		}
		if (a->type == LSM_AUDIT_DATA_PATH ||
			a->type == LSM_AUDIT_DATA_INODE)
			dput(dentry);
	}

	/* If we are creating an inode, we don't have the
	   context of the inode unless called from proper hook. */
	if (p->info.tclass == SECCLASS_FILESYSTEM &&
			p->info.requested == FILESYSTEM__ASSOCIATE &&
			p->hook != PF_HOOK_CREATE) {
				return 0;
	}
	p->context |= PF_CONTEXT_FILENAME;
	return rc;
}
EXPORT_SYMBOL(pft_auditdata_context);

char *syscall_value_as_string(char *str, int arg_num, int offset, int type)
{
	int value = 0;
	char *value_ptr = NULL;
	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));

	switch(arg_num) {
		case -1:
			value = ptregs->ax; /* Ret val / syscall number */
			break;
		case 0:
			value = ptregs->orig_ax; /* System call number */
			break;
		case 1:
			value = ptregs->bx; /* Parameter start */
			break;
		case 2:
			value = ptregs->cx;
			break;
		case 3:
			value = ptregs->dx;
			break;
		case 4:
			value = ptregs->si;
			break;
		case 5:
			value = ptregs->di;
			break;
		case 6:
			value = ptregs->bp;
			break;
	}

	value_ptr = (char *) value + offset;

	/* TODO incorporate flags into match:
		Hack for open() system call for O_CREAT flag */
	if ((arg_num == 0) && (value == 5)) {
		if ((ptregs->cx & 0100))
			sprintf(str, "5C");
		else
			sprintf(str, "5U");
		goto end;
	}
	if (type == PF_SYSCALL_STRING) {
		if (value_ptr)
			strcpy(str, value_ptr);
		else
			strcpy(str, "null");
	} else
		sprintf(str, "%d", value);
end:
	return str;
}

char *pft_get_process_hierarchy_str(struct task_struct *t)
{
	/* 'bash', 'init' */
	struct task_struct *curr = t;
	int c = 0;

	char *s = (char *) get_zeroed_page(GFP_KERNEL);
	if (!s)
		goto out;

	while (curr->pid >= 1) { /* we don't want swapper processes */
		if (strlen(curr->comm) + c + 4 > PAGE_SIZE) {
			free_page((unsigned long) s);
			s = NULL;
			goto out;
		}
		c += sprintf(s + c, "\"%s\"", curr->comm);
		if (curr->pid == 1 || curr->parent->pid == 0) /* init process' parent is swapper */
			break;
		c += sprintf(s + c, ",");
		curr = curr->parent;
	}

out:
	return s;
}

int pft_log_duplicate(char *log_str)
{
	return 0;
}

char *pft_get_process_stack_str(struct pf_packet_context *p)
{
	/* {"entry":"0xbf000000","file":"/lib/ld.so"}, ... */
	int i = 0, sz, curr = 0;
	char entry_str[] = "\"entry\"";
	char vma_str[] = "\"file\"";
	char *s = NULL;

	if (!valid_user_stack(&p->user_stack))
		goto out;

	s = (char *) __get_free_pages(GFP_KERNEL, 2);
	if (!s)
		goto out;

	for (i = 0; i < p->user_stack.trace.nr_entries - 1; i++) {
		/* overflow check */
		sz = strlen(p->user_stack.trace.vm_area_strings[i]) +
			strlen(entry_str) + strlen(vma_str) + 20;
		if (sz + curr > PAGE_SIZE * 4) {
			free_pages((unsigned long) s, 2);
			s = NULL;
			goto out;
		}
		curr += sprintf(s + curr, "{%s:\"0x%lx\",%s:\"%s\"}", entry_str,
				us_entry_offset_get(&p->user_stack, i), vma_str,
				p->user_stack.trace.vm_area_strings[i]);

		if (i != p->user_stack.trace.nr_entries - 2)
			curr += sprintf(s + curr, ",");
	}

	s[curr] = 0;
out:
	return s;
}

char *pft_get_interpreter_stack_str(struct pf_packet_context *p)
{
	/* {'entry':'4','file':'test.sh'}, ... */
	int i = 0, sz, curr = 0;
	char entry_str[] = "\"entry\"";
	char vma_str[] = "\"file\"";
	char *s = NULL;

	s = (char *) __get_free_pages(GFP_KERNEL, 2);
	if (!s)
		goto out;

	for (i = 0; i < p->user_stack.int_trace.nr_entries; i++) {
		/* overflow check */
		sz = strlen(p->user_stack.int_trace.int_filename[i]) +
			strlen(entry_str) + strlen(vma_str) + 20;
		if (sz + curr > PAGE_SIZE * 4) {
			free_pages((unsigned long) s, 2);
			s = NULL;
			goto out;
		}
		curr += sprintf(s + curr, "{%s:\"%lu\",%s:\"%s\"}", entry_str,
				p->user_stack.int_trace.entries[i], vma_str,
				p->user_stack.int_trace.int_filename[i]);

		if (i != p->user_stack.int_trace.nr_entries - 1)
			curr += sprintf(s + curr, ",");
	}

	s[curr] = 0;
out:
	return s;
}

int pft_log(struct pf_packet_context *p, struct pft_target_log *lt)
{
	char *interpreter_str = NULL; /* String for interpreter backtrace */
	char *stack_str = NULL; /* String for stack backtrace */
	char *core_log_str = NULL; /* String to check for duplication */
	char *log_str = NULL;
	char *phier_s = NULL; /* process heirarchy string */
	struct timespec ts; /* real wall clock time */

	int rc = 0;

	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int sn = ptregs->ax;

	stack_str = pft_get_process_stack_str(p);
	if (!stack_str)
		goto end;
	interpreter_str = pft_get_interpreter_stack_str(p);
	if (!interpreter_str)
		goto end;

	phier_s = pft_get_process_hierarchy_str(current);
	if (!phier_s)
		goto end;

	ktime_get_real_ts(&ts);

	/* TODO: make everything json */
	if (lt->context & PF_CONTEXT_SYSCALL_ARGS) {
		char *str = kmalloc(MAX_LOG_STRLEN, GFP_ATOMIC);
		log_str = kasprintf(GFP_ATOMIC, "%s: %s", lt->string,
				syscall_value_as_string(str, lt->arg_num, lt->offset, lt->type));
		kfree(str);
	} else if (lt->context & PF_CONTEXT_FILENAME) {
		log_str = kasprintf(GFP_ATOMIC, "%s: %lu", lt->string,
				p->info.filename_inoden);
	} else if (lt->context & PF_CONTEXT_SYSCALL_FILENAME) {
		if (!p->syscall_filename) {
			/* Happens if request is through a file descriptor. */
			goto end;
		}
		/* TODO: Make this a match module */
		if (!strcmp(p->syscall_filename, ".") &&
			((!strcmp(p->info.binary_path, "/bin/dash")) ||
			 (!strcmp(p->info.binary_path, "/bin/bash")))
		   ) {
			/* Special case */
			goto end;
		}
		log_str = kasprintf(GFP_ATOMIC, "%s", p->syscall_filename);
	} else {
		log_str = kasprintf(GFP_ATOMIC, "\"object\": {\"filename\": \"%s\", \"mac_label\": \"%s\","
				"\"dac_label\": {\"st_uid\": \"%lu\",\"st_gid\":\"%lu\",\"st_mode\":\"0%o\"},"
				"\"st_nlink\": \"%u\", \"st_ino\": \"%lu\"}, "
				"\"operation\": {\"counter\": \"%d\", \"syscall_nr\": \"%d(%lu)\","
				"\"tclass\": \"%d\", \"requested\": \"%u\", \"time\": {\"sec\":\"%ld\", \"nsec\":\"%ld\"}}",
			(strlen(p->info.filename) != 0) ? p->info.filename : "none",
			p->info.tcontext, p->stat_res.st_uid, p->stat_res.st_gid, p->stat_res.st_mode,
			p->stat_res.st_nlink, p->info.filename_inoden,
			atomic_read(&_syscall_ctr),
			sn, (sn == __NR_socketcall) ? ptregs->bx : 0,
			p->info.tclass, p->info.requested, ts.tv_sec, ts.tv_nsec
			);
			// tclass_str(p->info.tclass), requested_str(p->info.tclass, p->info.requested));
	}

	if (!log_str)
		goto end;

	if (!pft_log_duplicate(log_str)) {
		core_log_str = kasprintf(GFP_ATOMIC, "{\"process\": {\"ancestors\": [%s],"
				"\"binary\": \"%s\", \"dac_label\": \"%u\", \"mac_label\": \"%s\", \"pid\": \"%d\","
				"\"entrypoint_index\": \"%d\", \"process_stack\": [%s], \"script_stack\": [%s]}, %s},\n",
				phier_s, p->info.binary_path, current->cred->fsuid, p->info.scontext, p->info.pid,
				p->user_stack.trace.ept_ind, stack_str, interpreter_str, log_str);
		if (!core_log_str)
			goto end;

		current->kernel_request++;
		relay_write(wall_rchan, core_log_str, strlen(core_log_str));
		current->kernel_request--;
	}

end:
	if (interpreter_str)
		free_pages((unsigned long) interpreter_str, 2);
	if (stack_str)
		free_pages((unsigned long) stack_str, 2);
	if (log_str)
		kfree(log_str);
	if (core_log_str)
		kfree(core_log_str);
	if (phier_s)
		free_page((unsigned long) phier_s);

	return rc;
}

/* The log module also has to gather the context of the VM area names
   using d_path - this is in a separate function. Should we make it into
   a separate context module with its own bit? TODO. */
int pft_log_target(struct pf_packet_context *p, void *target_specific_data)
{
	struct pft_target_log *lt = (struct pft_target_log *)
					target_specific_data;
	int rc = 0;

	/* TODO: Required context shall be given in target_specific_data.
	 * For now, we are forcing all context modules to be called
	 * as we register the log target with all contexts.
	 * If the target module is to return PF_CONTEXT_POSTPONE, logic
	 * in pft_filter has to change. */

	#if 0
	if (!(p->context & PF_CONTEXT_TYPE))
		pft_type_context(p);
	# ifdef PFWALL_MATCH_REPR
	/* Fill in vm_area_strings */
	/* TODO: What to do in case vm_area_strings is noname, copy from
	 * pft_interface_context in pfwall.c */
	pft_vm_area_name_context(p);
	# endif
	pft_auditdata_context(p);
	#endif

	if (wall_rchan == NULL) {
		printk(KERN_INFO PFWALL_PFX "log: wall_rchan is NULL!\n");
		goto end;
	}
	pft_log(p, lt);

end:
	return (rc < 0) ? rc : PF_CONTINUE;
}

static int __init pft_log_target_init(void)
{
	int rc = 0;
	struct pft_target_module log_target_module = {
		.list = {NULL, NULL},
		.name = "log",
//		.context_mask = PF_CONTEXT_TYPE | PF_CONTEXT_INTERFACE |
//			PF_CONTEXT_FILENAME | PF_CONTEXT_VM_AREA_STRINGS |
//			PF_CONTEXT_BINARY_PATH,
		/* TODO: The context needed to log is provided
			as arguments to the target module, in
			this case, only PF_CONTEXT_TYPE (default
			context) is required in all cases.  */
		.target = &pft_log_target
	};

	printk(KERN_INFO PFWALL_PFX "log target initializing\n");

	wall_rchan = relay_open("wall_interfaces", NULL, 1024 * 1024, 16, &wall_interfaces_relay_callbacks, &dropped);
	if (!wall_rchan) {
		printk(KERN_INFO PFWALL_PFX "log: relay_open() failed\n");
		return 1;
	}

	rc = pf_register_target(&log_target_module);
	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_target log failed: %d\n", rc);
	}

	return rc;
}
module_init(pft_log_target_init);
