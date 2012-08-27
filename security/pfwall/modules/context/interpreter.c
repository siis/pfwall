#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
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
#include <linux/relay.h>
#include <linux/lsm_audit.h>
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/wall.h>

#include "php_headers.h"
#include "bash_headers.h"

/* Userspace access convenience macros */

static unsigned long __uptr;
static unsigned long __kptr;
#define A(a, off) ({ \
			__uptr = (unsigned long) ((char*) a + off); \
			copy_from_user(&__kptr, (void *) __uptr, sizeof(void *)); \
			__kptr; \
		})
#define O(ps, m) (offsetof(typeof(*ps), m))

#define MAX_INT_STR 32
#define MAX_INT_VARS 32

/* necessary information from interpreter binary for backtrace */
struct int_bt_info {
	char int_id[MAX_INT_STR]; /* string identifying interpreter */

	ino_t ino; /* interpreter inode */

	/* if the user stack trace contains the loop function, then
	 * it means the call was made on behalf of a script, and
	 * a script line number can be extracted from the interpreter */
	unsigned long loop_fn; /* start address of loop fn */
	unsigned long size; /* size of loop fn */

	/* the interpreter object is traversed in ways custom
	 * to interpreters to extract the stack of script line numbers */

	/* number of variables (including interpreter object) whose addresses
	 * are fetched from the interpreter binary's symtab in userspace */
	int nr_vars;

	/* is each variable global, or local to some function? */
	int is_global[MAX_INT_VARS];

	/* details of each of these nr_vars */
	union {
		struct {
			/* local function containing interpreter object */
			unsigned long local_fn;
			unsigned long size;
			/* offset of variable on stack from stack pointer
			 * identified by above function */
			unsigned long var_off;
		} local_var;
		/* address of global interpreter obj from symtab */
		unsigned long global_var;
	} var_info[MAX_INT_VARS];
	/* function to be invoked to get trace */
	int (*unwind) (struct user_stack_info *t);
};

/* TODO: make below into list */

/*
 * bash vars:
 * var_info	[0] - shell_variables (global)
 *   		[1]	- currently_executing_command (global)
 *   		[2] - executing (global)
 *   		[3] - showing_function_line (global)
 *   		[4] - variable_context (global)
 *   		[5] - interactive_shell (global)
 *   		[6] - line_number (global)
 */

struct int_bt_info bash_bt_info;

/*
 * php vars:
 * var_info [0] - executor_globals (global)
 */

struct int_bt_info php_bt_info;

char scratch_string[INT_FNAME_MAX];

/* BASH BEGIN */

/* The `khash' check below requires that strings that compare equally with
   strcmp hash to the same value. */
unsigned int
hash_string (const char *s)
{
  register unsigned int i;

  /* This is the best string hash function I found.

     The magic is in the interesting relationship between the special prime
     16777619 (2^24 + 403) and 2^32 and 2^8. */

  for (i = 0; *s; s++)
    {
      i *= 16777619;
      i ^= *s;
    }

  return i;
}

/* Return a pointer to the hashed item.  If the HASH_CREATE flag is passed,
   create a new hash table entry for STRING, otherwise return NULL. */
BUCKET_CONTENTS *
hash_search (const char *string, HASH_TABLE *table)
{
	BUCKET_CONTENTS *list;
	int bucket;
	unsigned int hv;
	BUCKET_CONTENTS **bucket_array = NULL;

	if (table == 0 || (HASH_ENTRIES (table) == 0))
		return (BUCKET_CONTENTS *)NULL;

	bucket = HASH_BUCKET (string, table, hv);
	bucket_array = (BUCKET_CONTENTS **) A(table, O(table, bucket_array));
	if (bucket_array == NULL)
		goto end;
	/* ??? * sizeof(void *)? */
	for (list = (BUCKET_CONTENTS *) A(bucket_array, bucket * sizeof(void *));
			list; list = (BUCKET_CONTENTS *) A(list, O(list, next)))
//  for (list = table->bucket_array ? table->bucket_array[bucket] : 0; list; list = list->next)
    {
		strncpy_from_user(scratch_string, (char *) A(list, O(list, key)), INT_FNAME_MAX - 1);
		if (hv == (A(list, O(list, khash))) && (STREQ (scratch_string, string))) {
			return (list);
		}
    }
end:
  return (BUCKET_CONTENTS *)NULL;
}

static SHELL_VAR *
hash_lookup (const char *name, HASH_TABLE *hashed_vars)
{
  BUCKET_CONTENTS *bucket;

  bucket = hash_search (name, hashed_vars);
  return (bucket ? (SHELL_VAR *) A(bucket, O(bucket, data)) : (SHELL_VAR *)NULL);
}

SHELL_VAR *
var_lookup (const char *name, VAR_CONTEXT *vcontext)
{
  VAR_CONTEXT *vc;
  SHELL_VAR *v;

  v = (SHELL_VAR *)NULL;
  for (vc = vcontext; vc; vc = (VAR_CONTEXT *) A(vc, O(vc, down)))
    if ((v = hash_lookup (name, (HASH_TABLE *) A(vc, O(vc, table)))))
      break;

  return v;
}

SHELL_VAR *
find_variable_internal (const char *name, struct user_stack_info *us)
{
	SHELL_VAR *var;
	VAR_CONTEXT *shell_variables = (VAR_CONTEXT *) NULL;

	shell_variables = (VAR_CONTEXT *)
		EPT_VMA_OFFSET(bash_bt_info.var_info[0].global_var, us);

	var = (SHELL_VAR *) NULL;

	if (var == 0)
		var = var_lookup (name, (VAR_CONTEXT *) A(shell_variables, 0));

	if (var == 0)
		return ((SHELL_VAR *)NULL);

	return var;
}

/*
 * Return the value of a[i].
 */
char *
array_reference(ARRAY *a, arrayind_t i)
{
	register ARRAY_ELEMENT *ae;

	if (a == 0 || array_empty(a))
		return((char *) NULL);
	if (i > array_max_index(a))
		return((char *)NULL);

	ae = (ARRAY_ELEMENT *) element_forw(a->head);
	for ( ; ae != (ARRAY_ELEMENT *) A(a, O(a, head));
			ae = (ARRAY_ELEMENT *) element_forw(ae)) {
		if ((arrayind_t) element_index(ae) == i) {
			return ((char *) element_value(ae));
		}
	}
	return((char *) NULL);
}

/* Return the line number of the currently executing command. */
int
executing_line_number(struct user_stack_info *us)
{
	unsigned long *command_ptr, *executing_ptr, *showing_ptr, *variable_ptr,
				  *interactive_ptr, *line_ptr;
	COMMAND *currently_executing_command;
	int executing;
	int showing_function_line;
	int variable_context;
	int interactive_shell;
	int line_number;

	command_ptr = (unsigned long *)
		EPT_VMA_OFFSET(bash_bt_info.var_info[1].global_var, us);
	executing_ptr = (unsigned long *)
		EPT_VMA_OFFSET(bash_bt_info.var_info[2].global_var, us);
	showing_ptr = (unsigned long *)
		EPT_VMA_OFFSET(bash_bt_info.var_info[3].global_var, us);
	variable_ptr = (unsigned long *)
		EPT_VMA_OFFSET(bash_bt_info.var_info[4].global_var, us);
	interactive_ptr = (unsigned long *)
		EPT_VMA_OFFSET(bash_bt_info.var_info[5].global_var, us);
	line_ptr = (unsigned long *)
		EPT_VMA_OFFSET(bash_bt_info.var_info[6].global_var, us);

	/* dereference the pointer */
	currently_executing_command = (COMMAND *) A(command_ptr, 0);
	executing = A(executing_ptr, 0);
	showing_function_line = A(showing_ptr, 0);
	variable_context = A(variable_ptr, 0);
	interactive_shell = A(interactive_ptr, 0);
	line_number = A(line_ptr, 0);

	if (executing && showing_function_line == 0 &&
      (variable_context == 0 || interactive_shell == 0) &&
      currently_executing_command) {
		if (A(currently_executing_command,
					O(currently_executing_command, type)) == cm_cond)
			return A(A(currently_executing_command,
						O(currently_executing_command, value.Cond)),
					O(currently_executing_command->value.Cond, line));
		else if (A(currently_executing_command,
					O(currently_executing_command, type)) == cm_arith)
			return A(A(currently_executing_command,
						O(currently_executing_command, value.Cond)),
					O(currently_executing_command->value.Arith, line));
		else if (A(currently_executing_command,
					O(currently_executing_command, type)) == cm_arith_for)
			return A(A(currently_executing_command,
						O(currently_executing_command, value.Cond)),
					O(currently_executing_command->value.ArithFor, line));
		else
			return line_number;
    } else {
		return line_number;
	}
}

int pft_bash_context(struct user_stack_info *us)
{
	char *retval;
	int i = 0;
	SHELL_VAR *var;
	int lineno;

	while (us->int_trace.nr_entries < us->int_trace.max_entries) {
		if (i > 0) { /* LINENO is for 0 */
			var = find_variable_internal("BASH_LINENO", us);
			if (var == NULL)
				break;
			retval = array_reference (array_cell (var), i);
			if (retval == NULL)
				break;
			strncpy_from_user(scratch_string, retval, INT_FNAME_MAX - 1);
			sscanf(retval, "%d", &lineno);
			if (!strcmp(scratch_string, "0"))
				break;
		} else if (i == 0) {
			lineno = executing_line_number (us);
		}

		var = find_variable_internal("BASH_SOURCE", us);
		if (var == NULL)
			break;
		retval = array_reference (array_cell (var), i);
		if (retval == NULL)
			break;
		strncpy_from_user(scratch_string, retval, INT_FNAME_MAX - 1);

		us->int_trace.entries[us->int_trace.nr_entries] = lineno;
		strcpy(us->int_trace.int_filename[us->int_trace.nr_entries], scratch_string);
		us->int_trace.nr_entries++;
		i++;
	}

	return 0;
}
/* BASH END */

/* PHP BEGIN */
int pft_php_context(struct user_stack_info *us)
{
	int ret = 0;
	zend_executor_globals *g;
	zend_execute_data *ptr;
	void *ptr2;
	int lineno = 0;

	/* PHP-specific backtrace retrieval */
	g = (zend_executor_globals *)
		EPT_VMA_OFFSET(php_bt_info.var_info[0].global_var, us);

	/* executor_globals.current_execute_data->op_array.filename */
	/* executor_globals.current_execute_data->opline.lineno */
	/* g->current_execute_data->opline.lineno */

	ptr = (zend_execute_data *) A(g, O(g, current_execute_data));

	while (ptr) {
		if (A(ptr, O(ptr, op_array))) {
			ptr2 = (void *) A(A(ptr, O(ptr, op_array)), O(ptr->op_array, filename));
			strncpy_from_user(scratch_string, (void *) ptr2, INT_FNAME_MAX - 1);
			lineno = A(A(ptr, O(ptr, opline)), O(ptr->opline, lineno));
		}
		ptr = (zend_execute_data *) A(ptr, O(ptr, prev_execute_data));
		us->int_trace.entries[us->int_trace.nr_entries] = lineno;
		strcpy(us->int_trace.int_filename[us->int_trace.nr_entries], scratch_string);
		us->int_trace.nr_entries++;
	}

	return ret;
}
/* PHP END */

unsigned long backtrace_contains(struct user_stack_info *us,
		unsigned long fn_st, unsigned long fn_len)
{
	int i = 0;
	unsigned long addr = 0;
	while ((i < us->trace.nr_entries) && (us->trace.entries[i] != ULONG_MAX)) {
		addr = (us->trace.entries[i] - us->trace.vma_start[i]);
		if ((addr >= fn_st) && (addr < (fn_st + fn_len)))
			return 1;
		i++;
	}
	return 0;
}

struct int_bt_info *on_script_behalf(struct user_stack_info *us)
{
	if (us->trace.bin_ip_exists == 0)
		return NULL;

	if (bash_bt_info.ino && (us->trace.vma_inoden[us->trace.ept_ind] == bash_bt_info.ino))
		if (backtrace_contains(us, bash_bt_info.loop_fn, bash_bt_info.size))
			return &bash_bt_info;

	if (php_bt_info.ino && us->trace.vma_inoden[us->trace.ept_ind] == php_bt_info.ino)
		if (backtrace_contains(us, php_bt_info.loop_fn, php_bt_info.size))
			return &php_bt_info;

	return NULL;
}
EXPORT_SYMBOL(on_script_behalf);

/* TODO: locking user_stack as we are calling parent */
int is_interpreter(struct task_struct *t)
{
	ino_t exe_ino = -1;

	if (!t->mm)
		return 0;

	down_read(&t->mm->mmap_sem);
	exe_ino = t->mm->exe_file->f_dentry->d_inode->i_ino;
	up_read(&t->mm->mmap_sem);

	return (bash_bt_info.ino == exe_ino || php_bt_info.ino == exe_ino);
}
EXPORT_SYMBOL(is_interpreter);

void user_interpreter_unwind(struct pf_packet_context *p)
{
	struct int_bt_info *int_info;
	struct user_stack_info *us = &p->user_stack;

	/* conserve existing (parent's) interpreter info if we are
	 * not ourselves an interpreter */
	/* change only if this system call was done at
	 * the behest of a script */
	int_info = on_script_behalf(us);
	if (int_info) {
		us->int_trace.nr_entries = 0;
		us->int_trace.max_entries = MAX_NUM_FRAMES;
		int_info->unwind(us);
	}
}
EXPORT_SYMBOL(user_interpreter_unwind);

void copy_interpreter_info(struct task_struct *c, struct task_struct *p)
{
	if (p->p->user_stack.int_trace.nr_entries) {
		c->p->user_stack.int_trace = p->p->user_stack.int_trace;
		memcpy(c->p->user_stack.int_trace.int_filename, p->p->user_stack.int_trace.int_filename,
				MAX_NUM_FRAMES * INT_FNAME_MAX);
	}
	c->p->user_stack.int_trace.nr_entries = p->p->user_stack.int_trace.nr_entries;
}
EXPORT_SYMBOL(copy_interpreter_info);

static int __init interpreter_bt_init(void)
{
	bash_bt_info.unwind = &pft_bash_context;
	php_bt_info.unwind = &pft_php_context;

	return 0;
}
__initcall(interpreter_bt_init);

/* file /sys/kernel/debug/interpreter_info */

/* example: php5:26484420:0x08345b50:0x0000024c:1:g:0x08345b50 */
int interpreter_line_load(char *data)
{
	char **r = &data;
	char *l = NULL;
	struct int_bt_info *int_info = NULL;
	int i = 0;

	l = strsep(r, ":");
	if (!strcmp(l, "bash"))
		int_info = &bash_bt_info;
	else if (!strcmp(l, "php5"))
		int_info = &php_bt_info;
	else
		return -EINVAL;

	strcpy(int_info->int_id, l);

	l = strsep(r, ":");
	int_info->ino = simple_strtoul(l, NULL, 0);
	if (!int_info->ino)
		return -EINVAL;

	l = strsep(r, ":");
	int_info->loop_fn = simple_strtoul(l, NULL, 0);
	if (!int_info->loop_fn)
		return -EINVAL;

	l = strsep(r, ":");
	int_info->size = simple_strtoul(l, NULL, 0);
	if (!int_info->size)
		return -EINVAL;

	l = strsep(r, ":");
	int_info->nr_vars = simple_strtoul(l, NULL, 0);
	if (int_info->nr_vars <= 0)
		return -EINVAL;

	for (i = 0; i < int_info->nr_vars; i++) {
		l = strsep(r, ":");
		if (l[0] == 'g')
			int_info->is_global[i] = 1;
		else if (l[0] == 'l')
			int_info->is_global[i] = 0;
		else
			return -EINVAL;

		l = strsep(r, ":");
		if (int_info->is_global[i]) {
			int_info->var_info[i].global_var = simple_strtoul(l, NULL, 0);
			if (!int_info->var_info[i].global_var)
				return -EINVAL;
		}
	}
	return 0;
}

int interpreter_load(char *data, size_t len)
{
	char **r = &data;
	char *l = NULL;
	int ret = 0;

	/* null terminate */
	*(data + len - 1) = 0;

	/* separate into tokens */
	while ((l = strsep(r, "\n"))) {
		/* parse each line */
		ret = interpreter_line_load(l);
	}

	return (ret == 0) ? len : ret;
}

static ssize_t
interpreter_info_write(struct file *filp, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	char *page;
	ssize_t length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

	length = -EINVAL;
	length = interpreter_load(page, count);

out:
	free_page((unsigned long) page);
	return length;
}

static const struct file_operations interpreter_info_fops = {
	.write  = interpreter_info_write,
};

static int __init interpreter_info_init(void)
{
	struct dentry *interpreter_info;

	interpreter_info = debugfs_create_file("interpreter_info",
			0600, NULL, NULL, &interpreter_info_fops);
	printk(KERN_INFO PFWALL_PFX "creating interpreter_info file\n");

	if(!interpreter_info) {
		printk(KERN_INFO PFWALL_PFX "unable to create interpreter_info\n");
	}
	return 0;
}
fs_initcall(interpreter_info_init);
