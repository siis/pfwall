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
#include <linux/wall.h>
#include <linux/relay.h>
#include <linux/lsm_audit.h>
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/namei.h>

#include "php_headers.h"
#include "bash_headers.h"

#define SYMSTRTAB_NAME ".strtab"

#define PHP_INTERPRETER_PATH "/usr/bin/php5"
#define PHP_INTERPRETER 0x1
// #3  0x082fdd36 in execute
#define PHP_LOOP_FUNCTION_BASE 0x2B5D36
#define PHP_INTERPRETER_OBJECT "executor_globals"

#define BASH_INTERPRETER_PATH1 "/usr/bin/bash41"
#define BASH_INTERPRETER_PATH2 "/bin/bash"
#define BASH_INTERPRETER_PATH3 "/bin/sh"
#define BASH_INTERPRETER_PATH4 "/bin/dash"
#define BASH_INTERPRETER 0x2
/*
#0  execute_command_internal (command=0x812de08, asynchronous=0, pipe_in=-1,
    pipe_out=-1, fds_to_close=0x812de28) at execute_cmd.c:531
#1  0x080767e2 in execute_command (command=0x812de08) at execute_cmd.c:375
*/
#define BASH_LOOP_FUNCTION_BASE 0x2E7E2
#define BASH_INTERPRETER_OBJECT "shell_variables"


/* Userspace access convenience macros */
#if 0
/* DEREF(UP, KP) = (*UP) but after copying from userspace */
#define DEREF(UP, KP) \
	({ copy_from_user(KP, UP, sizeof(void *)); \
	   (char *) *KP; \
	 })

#define DOT(a, b) DEREF((char*) a + offsetof(typeof(a), b))

/* ARROW(a, b, p) = a->b = (*a).b = *((char*) (*a) + offset(a, b)) */

#define ARROW(a, b, p) DEREF(DOT(DEREF(a, p), b))
#endif

/* Userspace access convenience macros */
/* Assume everything is a pointer; the final dereference will have to fetch the value
	from userspace if it is bigger than sizeof(ptr). This is because
	we do not know when the final dereference should happen. */

static unsigned long __uptr;
static unsigned long __kptr;
#if 0
#define D(a, b, aexp) ((char*) &a + offsetof(typeof(aexp), b))
#define A(a, b, aexp) ({ \
                        copy_from_user(&__kptr, a, sizeof(void *)); \
                        __uptr = ((char*) __kptr + offsetof(typeof(*aexp), b)); \
                        (typeof(aexp->b) *) __uptr; \
                })
#endif

#define A(a, off) ({ \
			__uptr = (unsigned long) ((char*) a + off); \
			copy_from_user(&__kptr, (void *) __uptr, sizeof(void *)); \
			__kptr; \
		})
#define O(ps, m) (offsetof(typeof(*ps), m))

/* Bash-specific defines */

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


char scratch_string[100];

Elf_Sym *php_symtab;
int php_symtabsize;
char *php_symtabstrings;

Elf_Sym *bash_symtab;
int bash_symtabsize;
char *bash_symtabstrings;


/* No security-check version of kernel_read to avoid recursion
	during vfs_read */

#define MAX_RW_COUNT (INT_MAX & PAGE_CACHE_MASK)

int nosec_rw_verify_area(int read_write, struct file *file, loff_t *ppos, size_t count)
{
	struct inode *inode;
	loff_t pos;
	int retval = -EINVAL;

	inode = file->f_path.dentry->d_inode;
	if (unlikely((ssize_t) count < 0))
		return retval;
	pos = *ppos;
	if (unlikely((pos < 0) || (loff_t) (pos + count) < 0))
		return retval;

	if (unlikely(inode->i_flock && mandatory_lock(inode))) {
		retval = locks_mandatory_area(
			read_write == READ ? FLOCK_VERIFY_READ : FLOCK_VERIFY_WRITE,
			inode, file, pos, count);
		if (retval < 0)
			return retval;
	}
	/* Get rid of the security hook */
	return count > MAX_RW_COUNT ? MAX_RW_COUNT : count;
}

ssize_t nosec_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!file->f_op || (!file->f_op->read && !file->f_op->aio_read))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
		return -EFAULT;

	/* This is where the security hook is omitted */
	ret = nosec_rw_verify_area(READ, file, pos, count);
	if (ret >= 0) {
		count = ret;
		if (file->f_op->read)
			ret = file->f_op->read(file, buf, count, pos);
		else
			ret = do_sync_read(file, buf, count, pos);
		if (ret > 0) {
			fsnotify_access(file->f_path.dentry);
			add_rchar(current, ret);
		}
		inc_syscr(current);
	}

	return ret;
}

int nosec_kernel_read(struct file *file, loff_t offset,
		char *addr, unsigned long count)
{
	mm_segment_t old_fs;
	loff_t pos = offset;
	int result;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	result = nosec_vfs_read(file, (void __user *)addr, count, &pos);
	set_fs(old_fs);
	return result;
}
EXPORT_SYMBOL(nosec_kernel_read);


/* Parse ELF file to get symtab and symtab string table */
int fill_sym(struct file *exe_file, Elf_Sym **symtab, char **symtabstrings, int *symtabsize)
{
	int ret = 0;
	Elf_Ehdr *ehdr;
	Elf_Shdr *sechdrs;
	char *secstrings;
	int i;

	/* TODO: Clean up repeat patterns into macros */
	ehdr = (Elf_Ehdr *) kmalloc(sizeof(Elf_Ehdr), GFP_KERNEL);
	if (!ehdr) {
		printk(KERN_INFO PFWALL_PFX "ehdr alloc failed!\n");
		goto end;
	}

	current->kernel_request++;
	ret = nosec_kernel_read(current->mm->exe_file, 0, (char *) ehdr, sizeof(Elf_Ehdr));
	current->kernel_request--;

	if (ret != sizeof(Elf_Ehdr)) {
		if (ret < 0)
			goto end;
	}

	sechdrs = (Elf_Shdr *) kmalloc(ehdr->e_shentsize * ehdr->e_shnum, GFP_KERNEL);
	if (!sechdrs) {
		printk(KERN_INFO PFWALL_PFX "sechdrs alloc failed!\n");
		goto end;
	}

	current->kernel_request++;
	ret = nosec_kernel_read(current->mm->exe_file, ehdr->e_shoff, (char *) sechdrs, ehdr->e_shentsize * ehdr->e_shnum);
	current->kernel_request--;

	if (ret != ehdr->e_shentsize * ehdr->e_shnum) {
		if (ret < 0)
			goto end;
	}

	/* Get the section headers string table to locate symbol table
	   string table ".strtab" */
	secstrings = kmalloc(sechdrs[ehdr->e_shstrndx].sh_size, GFP_KERNEL);
	if (!secstrings) {
		printk(KERN_INFO PFWALL_PFX "secstrings alloc failed!\n");
		goto end;
	}

	current->kernel_request++;
	ret = nosec_kernel_read(current->mm->exe_file, sechdrs[ehdr->e_shstrndx].sh_offset, (char *) secstrings, sechdrs[ehdr->e_shstrndx].sh_size);
	current->kernel_request--;

	if (ret != sechdrs[ehdr->e_shstrndx].sh_size) {
		if (ret < 0)
			goto end;
	}


	for (i = 1; i < ehdr->e_shnum; i++) {
		if (sechdrs[i].sh_type == SHT_SYMTAB) {
			*symtab = (Elf_Sym *) kmalloc(sechdrs[i].sh_size, GFP_KERNEL);
			if (!*symtab) {
				printk(KERN_INFO PFWALL_PFX "symtab alloc failed!\n");
				goto end;
			}

			current->kernel_request++;
			ret = nosec_kernel_read(current->mm->exe_file, sechdrs[i].sh_offset, (char*) *symtab, sechdrs[i].sh_size);
			current->kernel_request--;

			if (ret != sechdrs[i].sh_size) {
				if (ret < 0)
					goto end;
			}
			*symtabsize = ret;
		} else if (sechdrs[i].sh_type == SHT_STRTAB) {
			if (!strcmp(SYMSTRTAB_NAME, secstrings + sechdrs[i].sh_name)) {
				*symtabstrings = (char *) kmalloc(sechdrs[i].sh_size, GFP_KERNEL);
				if (!*symtabstrings) {
					printk(KERN_INFO PFWALL_PFX "symtabstrings alloc failed!\n");
					goto end;
				}

				current->kernel_request++;
				ret = nosec_kernel_read(current->mm->exe_file, sechdrs[i].sh_offset, (char *) *symtabstrings, sechdrs[i].sh_size);
				current->kernel_request--;
				if (ret != sechdrs[i].sh_size) {
					if (ret < 0)
						goto end;
				}
			}
		}
	}
end:
	if (ehdr)
		kfree(ehdr);
	if (sechdrs)
		kfree(sechdrs);
	return ret;
}

/* Look up the address of a variable, and set the pointer to point to that
	value  */
void get_userspace_ref(char *var_name, void __user **ptr, Elf_Sym *symtab, char *symtabstrings, int symtabsize)
{
	int nr_entries = symtabsize / sizeof(Elf_Sym);
	int i;
	for (i = 0; i < nr_entries; i++) {
		if (!strcmp(symtabstrings + symtab[i].st_name, var_name)) {
			*ptr = (void *) symtab[i].st_value;
			return ;
		}
	}
	*ptr = NULL;
	return;
}

/* BASH BEGIN */

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
	for (list = A(bucket_array, bucket * sizeof(void *)); list; list = A(list, O(list, next)))
//  for (list = table->bucket_array ? table->bucket_array[bucket] : 0; list; list = list->next)
    {
	strncpy_from_user(scratch_string, A(list, O(list, key)), 100);
      if (hv == (A(list, O(list, khash))) && (STREQ (scratch_string, string)))
	{
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
  for (vc = vcontext; vc; vc = A(vc, O(vc, down)))
    if ((v = hash_lookup (name, A(vc, O(vc, table)))))
      break;

  return v;
}

SHELL_VAR *
find_variable_internal (const char *name)
{
  SHELL_VAR *var;
	VAR_CONTEXT *shell_variables = (VAR_CONTEXT *) NULL;
/* TODO: Do get_userspace_ref only once, for both php and bash */
  get_userspace_ref(BASH_INTERPRETER_OBJECT, (void **) &shell_variables, bash_symtab, bash_symtabstrings, bash_symtabsize);

  var = (SHELL_VAR *) NULL;

  if (var == 0)
    var = var_lookup (name, A(shell_variables, 0));

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

	ae = element_forw(a->head);
	for ( ; ae != A(a, O(a, head)); ae = element_forw(ae))
		if (element_index(ae) == i) {
			return(element_value(ae));
		}
	return((char *) NULL);
}



/* Return the line number of the currently executing command. */
int
executing_line_number ()
{
	static COMMAND *currently_executing_command;
	int *executing_ptr, *showing_ptr, *variable_ptr, *interactive_ptr, *line_ptr;
	int executing;
	int showing_function_line;
	int variable_context;
	int interactive_shell;
	int line_number;
	get_userspace_ref("currently_executing_command", (void **) &currently_executing_command, bash_symtab, bash_symtabstrings, bash_symtabsize);
	/* Dereference the pointer */
	currently_executing_command = A(currently_executing_command, 0);
	get_userspace_ref("executing", (void **) &executing_ptr, bash_symtab, bash_symtabstrings, bash_symtabsize);
	executing = A(executing_ptr, 0);
	get_userspace_ref("showing_function_line", (void **) &showing_ptr, bash_symtab, bash_symtabstrings, bash_symtabsize);
	showing_function_line = A(showing_ptr, 0);
	get_userspace_ref("variable_context", (void **) &variable_ptr, bash_symtab, bash_symtabstrings, bash_symtabsize);
	variable_context = A(variable_ptr, 0);
	get_userspace_ref("interactive_shell", (void **) &interactive_ptr, bash_symtab, bash_symtabstrings, bash_symtabsize);
	interactive_shell = A(interactive_ptr, 0);
	get_userspace_ref("line_number", (void **) &line_ptr, bash_symtab, bash_symtabstrings, bash_symtabsize);
	line_number = A(line_ptr, 0);

  if (executing && showing_function_line == 0 &&
      (variable_context == 0 || interactive_shell == 0) &&
      currently_executing_command)
    {
      if (A(currently_executing_command, O(currently_executing_command, type)) == cm_cond)
	return A(A(currently_executing_command, O(currently_executing_command, value.Cond)), O(currently_executing_command->value.Cond, line));
      if (A(currently_executing_command, O(currently_executing_command, type)) == cm_arith)
	return A(A(currently_executing_command, O(currently_executing_command, value.Cond)), O(currently_executing_command->value.Arith, line));
      else if (A(currently_executing_command, O(currently_executing_command, type)) == cm_arith_for)
	return A(A(currently_executing_command, O(currently_executing_command, value.Cond)), O(currently_executing_command->value.ArithFor, line));

	return line_number;
    }
  else
    return line_number;
}

int pft_bash_context(struct pf_packet_context *p)
{
	char bash_source[] = "BASH_SOURCE";
	char bash_lineno[] = "BASH_LINENO";
	char *retval;
	int i, ret = 0;
	SHELL_VAR *var;
	int lineno;
	struct interpreter_info* info = &(p->interpreter_info);

	#ifdef PFWALL_MATCH_REPR
	struct nameidata ni;
	#endif

	if (!bash_symtab || !bash_symtabstrings) {
		ret = fill_sym(current->mm->exe_file, &bash_symtab, &bash_symtabstrings, &bash_symtabsize);
		if (ret < 0)
			goto end;
	}

	for (i = 0; ; i++) {
		if (i > 0) { /* LINENO is for 0 */
			var = find_variable_internal(bash_lineno);
			if (var == NULL)
				break;
			retval = array_reference (array_cell (var), i);
			if (retval == NULL)
				break;
			strncpy_from_user(scratch_string, retval, 100);
			sscanf(retval, "%d", &lineno);
			if (!strcmp(scratch_string, "0"))
				break;
		} else if (i == 0) {
			lineno = executing_line_number ();
		}

		var = find_variable_internal(bash_source);
		if (var == NULL)
			break;
		retval = array_reference (array_cell (var), i);
		if (retval == NULL)
			break;
		strncpy_from_user(scratch_string, retval, 100);

		info->line_number[info->nr_entries] = lineno;
		strcpy(info->script_filename[info->nr_entries], scratch_string);
		info->nr_entries++;

		#ifdef PFWALL_MATCH_REPR
		ret = path_lookup(info->script_filename[info->nr_entries], LOOKUP_FOLLOW, &ni);
		if (ret < 0) {
			printk(KERN_INFO PFWALL_PFX
				"Path lookup translation failed for script path: %s: %d\n", info->script_filename, ret);
			goto end;
		}
		info->script_inoden[info->nr_entries] = ni.path.dentry->d_inode->i_ino;
		#endif
	}

end:
	return ret;
}
/* BASH END */

int pft_php_context(struct pf_packet_context *p)
{
	/* The vm_area_struct that contains the ELF binary */
	struct interpreter_info* info = &(p->interpreter_info);
	int ret = 0;
	zend_executor_globals __user *g;
	// unsigned long tptr, tptr2;
//	zend_execute_data *ptr = kmalloc(sizeof(zend_execute_data), GFP_KERNEL);
	zend_execute_data *ptr;
	void *ptr2;
//	void *ptr;
	char *filename = kmalloc(100, GFP_KERNEL);
	int lineno = 0;
	struct nameidata ni;

//	#ifdef PFWALL_MATCH_REPR
//	struct nameidata ni;
//	#endif

	if (!php_symtab || !php_symtabstrings) {
		ret = fill_sym(current->mm->exe_file, &php_symtab, &php_symtabstrings, &php_symtabsize);
		if (ret < 0)
			goto end;
	}

	/* At this point, we have both the symbol table and the symbol table strings */

	/* PHP-specific backtrace retrieval */
	get_userspace_ref(PHP_INTERPRETER_OBJECT, (void **) &g, php_symtab, php_symtabstrings, php_symtabsize);

	/* executor_globals.current_execute_data->op_array.filename */
	/* executor_globals.current_execute_data->opline.lineno */
	/* g->current_execute_data->opline.lineno */

	ptr = (zend_execute_data *) A(g, O(g, current_execute_data));

	while (ptr) {
		if (A(ptr, O(ptr, op_array))) {
			ptr2 = (void *) A(A(ptr, O(ptr, op_array)), O(ptr->op_array, filename));
			strncpy_from_user(filename, (void *) ptr2, 100);
			lineno = (void *) A(A(ptr, O(ptr, opline)), O(ptr->opline, lineno));
		}
		ptr = (zend_execute_data *) A(ptr, O(ptr, prev_execute_data));
		info->line_number[info->nr_entries] = lineno;
		strcpy(info->script_filename[info->nr_entries], filename);
		info->nr_entries++;
		#ifdef PFWALL_MATCH_REPR
		ret = path_lookup(info->script_filename[info->nr_entries], LOOKUP_FOLLOW, &ni);
		if (ret < 0) {
			printk(KERN_INFO PFWALL_PFX
				"Path lookup translation failed for script path: %s: %d\n", info->script_filename, ret);
			goto end;
		}
		info->script_inoden[info->nr_entries] = ni.path.dentry->d_inode->i_ino;
		#endif
	}

	# if 0
	/*
	tptr = (char*) g + offsetof(typeof(*g), current_execute_data);
	copy_from_user(&tptr2, (void *) tptr, sizeof(zend_execute_data *));

	copy_from_user(ptr, (void *) tptr2, sizeof(zend_execute_data));
	*/

	while (ptr) {
		if (ptr->op_array) {
			tptr = ptr->op_array;
			copy_from_user(&tptr2, (void*) tptr + offsetof(typeof(*(ptr->op_array)), filename), sizeof(void *));

			strncpy_from_user(filename, (void *) tptr2, 100);

			tptr = ptr->opline;
			copy_from_user(&tptr2, (void *) tptr + offsetof(typeof(*(ptr->opline)), lineno), sizeof(void *));

			copy_from_user(&lineno, (void *) tptr2, sizeof(lineno));
		}
		tptr = ptr->prev_execute_data;
		if (tptr == 0)
			break; /* while (ptr) */
		copy_from_user(ptr, (void *) tptr, sizeof(zend_execute_data));
		/* Write filename and lineno to array */
		info->line_number[info->nr_entries] = lineno;
		strcpy(info->script_filename[info->nr_entries], filename);
		info->nr_entries++;
		/* TODO: MATCH_REPR */
	}
	#endif
end:
	kfree(filename);
//	up_write(&current->mm->mmap_sem);
	return ret;
}

int backtrace_contains(struct pf_packet_context *p, int offset)
{
	int i = 0;
	while (i < MAX_NUM_FRAMES && p->trace.entries[i] && p->trace.entries[i] != 0xFFFFFFFF) {
		if ((p->trace.entries[i] - p->vma_start[i]) == offset)
			return 1;
		i++;
	}
	return 0;
}

int is_on_script_behalf(struct pf_packet_context *p, int interpreter)
{
	switch(interpreter) {
		case PHP_INTERPRETER:
			if (backtrace_contains(p, PHP_LOOP_FUNCTION_BASE))
				return 1;
		case BASH_INTERPRETER:
			if (backtrace_contains(p, BASH_LOOP_FUNCTION_BASE))
				return 1;
		default:
			return 0;
	}
}

/* NOTE: Getting the interpreter context means the binary
 * should contain symbol table information (even if it does
 * not have debug information)
 */

int pft_interpreter_context(struct pf_packet_context *p)
{
	int ret = 0;
	return ret;
	/* Don't bother if not an interpreter */
	/* Also, bother only if this system call was done at
	 * the behest of a script */
	/* TODO: MATCH_REPR */
	// #ifdef PFWALL_MATCH_STR
	if (!strcmp(p->info.binary_path, PHP_INTERPRETER_PATH) && is_on_script_behalf(p, PHP_INTERPRETER)) {
		if (is_on_script_behalf(p, PHP_INTERPRETER))
			return pft_php_context(p);
	}
	else if (!strcmp(p->info.binary_path, BASH_INTERPRETER_PATH1) && is_on_script_behalf(p, BASH_INTERPRETER)) {
		return pft_bash_context(p);
	}
	else if (!strcmp(p->info.binary_path, BASH_INTERPRETER_PATH2) && is_on_script_behalf(p, BASH_INTERPRETER)) {
		return pft_bash_context(p);
	}
	else if (!strcmp(p->info.binary_path, BASH_INTERPRETER_PATH3) && is_on_script_behalf(p, BASH_INTERPRETER)) {
		return pft_bash_context(p);
	}
	else if (!strcmp(p->info.binary_path, BASH_INTERPRETER_PATH4) && is_on_script_behalf(p, BASH_INTERPRETER)) {
		return pft_bash_context(p);
	}
	// #endif
	return ret;
}
EXPORT_SYMBOL(pft_interpreter_context);
