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

#include "../../av_permissions.h"
#include "../../flask.h"
#include "../../trusted_subjects.h"
#include <asm/ftrace.h>
#include <asm/syscall.h>

#define MAX_LOG_STRLEN 256
#define MAX_PROC_HIER 256

#define PF_SYSCALL_STRING 1
#define PF_SYSCALL_INT	  2

#define SECDEBUGFRAME_NAME ".debug_frame"
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
              return rc;
	rc = security_sid_to_context (p->info.tsid, &tcontext, &tcontext_len);
        if (rc)
              return rc;

	path = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (path == NULL) {
		printk(KERN_INFO PFWALL_PFX "path allocation failed\n");
		rc = -ENOMEM;
		goto end;
	}

	/* Extract type from context */
	stype = context_to_type(scontext);
	if (stype == NULL) {
		rc = -EINVAL; /* Initial SID */
		return rc;
	}
	ttype = context_to_type(tcontext);
	if (ttype == NULL) {
		rc = -EINVAL; /* Initial SID */
		return rc;
	}

	strcpy(p->info.scontext, stype);
	strcpy(p->info.tcontext, ttype);

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

/* TODO: Hacked for perf. Integrate properly with #ifdef MATCH_STR */
int pft_vm_area_inode_context(struct pf_packet_context *p)
{
	struct vm_area_struct *vma = NULL;
	int ret = 0;

	int i = 0;
	unsigned long address;

	p->trace_first_program_ip = -1;
	p->program_ip_exists = 0; /* No error */

	if (!current->mm) {
		ret = -EINVAL;
		goto end;
	}

	/* Find out and save the first program IP which is not in the library */
	while (i < MAX_NUM_FRAMES - 1) {
		address = p->trace.entries[i];
		if (address == ULONG_MAX)
			break;
		vma = find_vma(current->mm, address);
		if (vma == NULL || (vma->vm_file) == NULL || address < vma->vm_start) {
			if (vma == NULL || address < vma->vm_start) {
				/* TODO: Investigate why below happens */
//				if (i > 0) /* Not process startup */
//					printk(KERN_INFO PFWALL_PFX "vma is NULL\n");
				ret = -EINVAL;
				p->trace_first_program_ip = -1;
				goto end;
			} else if (vma->vm_file == NULL) {
				/* Why is this happening - file
				 * may not be mapped in yet */
				p->trace_first_program_ip = -1;
				ret = -EINVAL;
				goto end;
			}
		} else {
			p->vm_area_inoden[i] =
				vma->vm_file->f_dentry->d_inode->i_ino;
		}
		p->vma_start[i] = vma->vm_start;
		if (p->vm_area_inoden[i] == current->mm->exe_file->f_dentry->d_inode->i_ino) {
			/* This entry point is what we will log in
			   if we don't log the full stack backtrace */
			if (p->program_ip_exists == 0) {
				p->program_ip_exists = 1;
				p->trace_first_program_ip = i;
			}
		}
		i++;
	}

	/* If everything originates from the library, arbitrarily choose
	 * the first entry-point */
	if (p->program_ip_exists == 0) {
		p->trace_first_program_ip = 0;
	}
//	p->context |= PF_CONTEXT_VM_AREA_STRINGS;
end:
	return ret;
}
EXPORT_SYMBOL(pft_vm_area_inode_context);

int pft_vm_area_name_context(struct pf_packet_context *p)
{
	struct vm_area_struct *vma = NULL;
	char *path = NULL; /* For storing paths */
	int ret = 0;
	char *ptemp = NULL;
	int i = 0;
	unsigned long address;

	if (!current->mm) {
		ret = -EINVAL;
		goto end;
	}

	path = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (path == NULL) {
		printk(KERN_INFO PFWALL_PFX "path allocation failed\n");
		ret = -ENOMEM;
		goto end;
	}


	/* Find out and save the first program IP which is not in the library */
	while (i < MAX_NUM_FRAMES - 1) {
		address = p->trace.entries[i];
		if (address == ULONG_MAX)
			break;
		vma = find_vma(current->mm, address);
		if (vma == NULL || (vma->vm_file) == NULL || address < vma->vm_start) {
			if (vma == NULL || address < vma->vm_start) {
				/* TODO: Investigate why below happens */
//				if (i > 0) /* Not process startup */
//					printk(KERN_INFO PFWALL_PFX "vma is NULL\n");
				ret = -EINVAL;
				p->trace_first_program_ip = -1;
				strcpy(p->vm_area_strings[i], "vmanull");
				goto end;
			} else if (vma->vm_file == NULL) {
				/* Why is this happening - file
				 * may not be mapped in yet */
				p->trace_first_program_ip = -1;
				#ifdef PFWALL_MATCH_STR
				strcpy(p->vm_area_strings[i], "vmafilenull");
				# endif
				ret = -EINVAL;
				goto end;
			}
		}
		ptemp = d_path(&(vma->vm_file->f_path), path, PAGE_SIZE);
		if (IS_ERR(ptemp)) {
			printk(KERN_INFO PFWALL_PFX "prologue: d_path failure\n");
			ret = -EINVAL;
			strcpy(p->vm_area_strings[i], "d_pathfail");
		}
		strcpy(p->vm_area_strings[i], ptemp);
		i++;
	}
	p->context |= PF_CONTEXT_VM_AREA_STRINGS;
end:
	if (path)
		kfree(path);
	return ret;
}
EXPORT_SYMBOL(pft_vm_area_name_context);

/* Does the file "string" need debug unroll? */
int pft_debug_needed(char *string)
{
	#ifdef PFWALL_ADVANCED_STACKTRACE
	/* If we are in execve, the mmap_sem will already be down,
	 * and so we cannot scan userspace memory through copy_from_user
	 * anyway, so there is no point doing an advanced stacktrace */

	if (syscall_get_nr(current, task_pt_regs(current)) == __NR_execve) {
		return 0;
	}

	if (!strcmp(PFW_LIBC_PATH, string))
		return 1;
	else if (!strcmp(PFW_LD_SO_PATH, string))
		return 1;
	#endif
	return 0;
}

#if 0
/* TODO: Integrate the code for interpreter symbol table and this */
/*
 * Examine the ELF binary and return a pointer to the requested section.
 * Caller has to free pointer
 *
 * @exe_file: file object of the ELF binary to be read
 * @section_name: Name of the section required
 * @section_size: Will be filled in with the size of the section
 * Return: A pointer to the section. Caller has to free pointer.
 */

void *get_section(struct file *exe_file, char *section_name, unsigned long *section_size)
{
	int ret = 0;
	Elf_Ehdr *ehdr;
	Elf_Shdr *sechdrs;
	char *secstrings;
	int i;
	void *section;

	/* TODO: Clean up repeat patterns into macros */
	ehdr = (Elf_Ehdr *) kmalloc(sizeof(Elf_Ehdr), GFP_KERNEL);
	if (!ehdr) {
		printk(KERN_INFO PFWALL_PFX "ehdr alloc failed!\n");
		goto end;
	}

	current->kernel_request++;
	ret = kernel_read(exe_file, 0, (char *) ehdr, sizeof(Elf_Ehdr));
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
	ret = kernel_read(exe_file, ehdr->e_shoff, (char *) sechdrs, ehdr->e_shentsize * ehdr->e_shnum);
	current->kernel_request--;

	if (ret != ehdr->e_shentsize * ehdr->e_shnum) {
		if (ret < 0)
			goto end;
	}

	/* Get the section headers string table to locate debug
	 * frame section ".debug_frame" */

	secstrings = kmalloc(sechdrs[ehdr->e_shstrndx].sh_size, GFP_KERNEL);
	if (!secstrings) {
		printk(KERN_INFO PFWALL_PFX "secstrings alloc failed!\n");
		goto end;
	}

	current->kernel_request++;
	ret = kernel_read(exe_file, sechdrs[ehdr->e_shstrndx].sh_offset, (char *) secstrings, sechdrs[ehdr->e_shstrndx].sh_size);
	current->kernel_request--;

	if (ret != sechdrs[ehdr->e_shstrndx].sh_size) {
		if (ret < 0)
			goto end;
	}

	for (i = 1; i < ehdr->e_shnum; i++) {
		if (!strcmp(secstrings + sechdrs[i].sh_name, section_name)) {
			/* We've located the section we want */
			section = kmalloc(sechdrs[i].sh_size, GFP_KERNEL);
			current->kernel_request++;
			ret = kernel_read(exe_file, sechdrs[i].sh_offset, section, sechdrs[i].sh_size);
			current->kernel_request--;
			if (ret != sechdrs[i].sh_size) {
				kfree(section);
				if (ret < 0)
					goto end;
			}
			*section_size = sechdrs[i].sh_size;
			break;
		}
	}
end:
	if (ehdr)
		kfree(ehdr);
	if (sechdrs)
		kfree(sechdrs);
	if (secstrings)
		kfree(secstrings);

	if (ret < 0)
		return ERR_PTR(ret);
	else
		return section;
}

unsigned long handle_inst(unsigned long inst_pc, unsigned long *offset, unsigned int *reg)
{
	unsigned char c = *(unsigned char*) inst_pc;

	inst_pc += 1;
	switch ((c) >> 6) {
		case DW_CFA_advance_loc:
		case DW_CFA_restore:
			break;
		case DW_CFA_offset:
			inst_pc += 1; break;
		case 0:
		{
			switch((c & 0x3F)) {
				case DW_CFA_set_loc:
					inst_pc += sizeof(void*) ; break;
				case DW_CFA_advance_loc1:
					inst_pc += 1; break;
				case DW_CFA_advance_loc2:
					inst_pc += 2; break;
				case DW_CFA_advance_loc4:
					inst_pc += 4; break;
				case DW_CFA_offset_extended:
					inst_pc += 2; break;
				case DW_CFA_restore_extended:
					inst_pc += 1; break;
				case DW_CFA_undefined:
					inst_pc += 1; break;
				case DW_CFA_same_value:
					inst_pc += 1; break;
				case DW_CFA_register:
					inst_pc += 2; break;
				case DW_CFA_remember_state:
				case DW_CFA_restore_state:
					break;
				case DW_CFA_def_cfa:
					inst_pc += 2; break;
				case DW_CFA_def_cfa_register:
					*reg = (*(unsigned int*) inst_pc) & 0xff;

					inst_pc += 1; break;
				case DW_CFA_def_cfa_offset:
					c = *(unsigned char*) inst_pc;
					*offset = (unsigned long) c & 0xff;
//					printk(KERN_INFO PFWALL_PFX "Stack offset: %x", (unsigned long) c & 0xff);
					inst_pc += 1; break;
				case DW_CFA_nop:
					inst_pc += 3; break;
				default:
					printk(KERN_INFO PFWALL_PFX "DWARF instruction");
			}
		}
		break;
		default:
			printk(KERN_INFO PFWALL_PFX "DWARF basic instruction ");
	}

	return inst_pc;
}

unsigned long dwarf_get_offset(unsigned long addr, unsigned int *reg, void *sec, unsigned long slen)
{
	struct dwarf_cfie_header *h;
	struct dwarf_fde *fde;

	unsigned long offset = (unsigned long) -1; /* Default if no info available e.g., assembly code */
	char *curr_ptr = sec;

	while (curr_ptr < (char *) sec + slen) {
		unsigned long inst_pc = 0;
		h = (struct dwarf_cfie_header *) curr_ptr;
		curr_ptr += sizeof(h);
		fde = (struct dwarf_fde *) curr_ptr;
		inst_pc = &(fde->instructions);
		if (fde->magic == 0xFFFFFFFF) {
			;
		} else {
			if (addr >= (unsigned long) fde->initial_location &&
				addr <= (unsigned long) (fde->initial_location + fde->offset)) {
				offset = 0; /* Default if no instructions */
				*reg = REG_ESP;
				/* Find offset of the current frame */
				while (inst_pc < ((unsigned char*) fde) + h->length) {
					inst_pc = handle_inst(inst_pc, &offset, reg);
				}
			}
		}
		curr_ptr += h->length;
	}
	return offset;
}

/* Find the function start address and size that addr is contained in */
unsigned long get_func_start_and_size(unsigned long addr, Elf_Sym *symtab,
		int symtabsize, unsigned long *func_size)
{
	int nr_entries = symtabsize / sizeof(Elf_Sym);
	unsigned long start_addr = 0;
	int i;
	*func_size = 0;

	for (i = 0; i < nr_entries; i++) {
		if (addr > symtab[i].st_value
			&& addr <= symtab[i].st_value + symtab[i].st_size) {
			start_addr = symtab[i].st_value;
			/* We only need scan prologue till addr */
			*func_size = addr - symtab[i].st_value;
			break;
		}
	}
	return start_addr;
}

/* This function is called when DWARF CFI cannot give us the frame setup information, either because
 * DWARF is unavailable, or because it is assembly code, when CFI is not generated */
unsigned long prologue_get_offset(unsigned char __user *func, unsigned int *reg, unsigned long size, unsigned char __user **fp, unsigned char __user *sp)
{
	unsigned char __user *byte;
	int found_push_ebp = 0;
	int found_mov_esp_ebp = 0;
	int found_call = 0;
	unsigned long offset = 0;
	unsigned long ebp_offset = 0;

	for (byte = func; byte < func + size - 1; byte++) {
		/* TODO: All Push instructions */
		if (((unsigned int) *byte) == 0x55) {
			/* PUSH EBP */
			found_push_ebp = 1;
			offset += 4;
			ebp_offset = 0;
		} else if (((unsigned int) *byte) >= 0x50 && ((unsigned int) *byte) < 0x58 && ((unsigned int) *byte) != 0x54) {
			/* PUSH something */
			offset += 4;
			if (found_push_ebp)
				ebp_offset += 4;
		} else if (((unsigned int) *byte) == 0x89 &&
				((unsigned int) *(byte + 1) == 0xe5)) {
			/* MOV ESP, EBP */
			found_mov_esp_ebp = 1;
			if (found_push_ebp)
				break;
		} else if (((unsigned int) *byte) == 0x65 &&
				((unsigned int) *(byte + 1) == 0xff)) {
			found_call = 1;
			/* CALL */
			break;
		}
	}

	/* Need we update EBP? */
	if (found_push_ebp && !found_mov_esp_ebp) {
		*fp = (unsigned long) *(unsigned long *) (sp + ebp_offset);
	}
	if (found_push_ebp && found_mov_esp_ebp) {
		*reg = REG_EBP;
		offset = 8;
	} else {
		*reg = REG_ESP;
	}

	if (offset == 0 && !found_call) {
		*reg = REG_EBP;
		offset = 8;
	}

	return offset;
}

/* For the file and IP addr, get stack offset and register using prologue
 * analysis */
unsigned long prologue_get_sp_offset_and_reg(char *filename, unsigned long addr,
		unsigned long base, unsigned int *reg,
	       unsigned char __user **fp, unsigned char __user *sp)
{
	char *debug_filename = NULL;
	unsigned long offset = 0;
	struct file *debug_file;
	void *symtab = NULL;
	unsigned long symtab_size;
	unsigned char __user *func_start;
	unsigned long func_size;
	void *func = NULL;


//	printk(KERN_ALERT PFWALL_PFX "prologue_file: [%s, %d]\n", current->comm, current->pid);
	debug_filename = kasprintf(GFP_ATOMIC,
		DEBUG_PREFIX "/%s", filename);
	if (!debug_filename)
		goto out;

	current->kernel_request++;
	debug_file = filp_open(debug_filename,
				O_LARGEFILE | O_RDONLY, 0);
	current->kernel_request--;

	if (IS_ERR(debug_file))
		goto out;

	symtab = get_section(debug_file, SECSYMTAB_NAME, &symtab_size);
	if (IS_ERR(symtab)) {
		printk(KERN_INFO PFWALL_PFX "symtab failure\n");
		filp_close(debug_file, NULL);
		goto out;
	}

	filp_close(debug_file, NULL);

	func_start = get_func_start_and_size(addr, symtab, symtab_size, &func_size);
	func = kmalloc(func_size, GFP_KERNEL);
	if (!func)
		goto out;
	if (func_size == 0 || copy_from_user(func, func_start + base, func_size)) {
		/* Can't find function in symtab (Why?),
			fall back to normal unroll */
		offset = 8;
		*reg = REG_EBP;
		goto out;
	}

	/* Perform prologue analysis on func */
	offset = prologue_get_offset((unsigned char *) func, reg, func_size, fp, sp);
out:
	if (symtab && !IS_ERR(symtab))
		kfree(symtab);
	if (func)
		kfree(func);
	if (debug_filename)
		kfree(debug_filename);
	return offset;
}

/* For the file and IP, get the stack offset info, fill in the register
 * that the offset is to be applied to */
unsigned long dwarf_get_sp_offset_and_reg(char *filename, unsigned long addr,
		unsigned int *reg)
{
	char *debug_filename = NULL;
	unsigned long offset = 0;
	struct file *debug_file;
	void *sec_debugframe_ptr = NULL;
	unsigned long sec_debugframe_size;

	int ret = 0;

	#if 0
	/* Check in hash table */
	struct debug_dict_value *v;

	if ((v = pft_debug_dict_get_value(filename, addr)) != NULL) {
		offset = v->offset;
		*reg = v->reg;
		return offset;
	}
	#endif

	debug_filename = kasprintf(GFP_ATOMIC,
		DEBUG_PREFIX "/%s", filename);
	if (!debug_filename) {
		ret = -ENOMEM;
		goto out;
	}

	current->kernel_request++;
	debug_file = filp_open(debug_filename,
				O_LARGEFILE | O_RDONLY, 0);
	current->kernel_request--;

	if (IS_ERR(debug_file)) {
		ret = -ENOMEM;
		goto out;
	}

	sec_debugframe_ptr = get_section(debug_file, SECDEBUGFRAME_NAME, &sec_debugframe_size);
	if (IS_ERR(sec_debugframe_ptr)) {
		printk(KERN_INFO PFWALL_PFX "sec_debugframe_ptr failure\n");
		filp_close(debug_file, NULL);
		ret = -ENOMEM;
		goto out;
	}

	filp_close(debug_file, NULL);

	offset = dwarf_get_offset(addr, reg, sec_debugframe_ptr, sec_debugframe_size);
	#if 0
	/* Set in hash table */
	if (offset != (unsigned long) -1)
		ret = pft_debug_dict_set_value(filename, addr, offset, *reg);
	#endif
out:
	if (debug_filename)
		kfree(debug_filename);
	if (sec_debugframe_ptr)
		kfree(sec_debugframe_ptr);
	if (ret < 0)
		return ret;
	return offset;
}
#endif

/* Given an packet, fill up the VM area name (or inode) for the ith entry.
   Also update if it is the first IP within the program */
int pft_set_vm_area(struct pf_packet_context *p, int i)
{
	struct vm_area_struct *vma = NULL;
	#if defined (PFWALL_MATCH_STR) || defined (PFWALL_ADVANCED_STACKTRACE)
	char *ptemp = NULL; /* For storing paths */
	#endif
	int ret = 0;
	unsigned long address = p->trace.entries[i];
	char *path;

	path = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (path == NULL) {
		printk(KERN_INFO PFWALL_PFX "path allocation failed\n");
		ret = -ENOMEM;
		goto end;
	}

	vma = find_vma(current->mm, address);
	if (vma == NULL || (vma->vm_file) == NULL || address < vma->vm_start) {
		if (vma == NULL || address < vma->vm_start) {
			/* If we already have the program point, this is
			 * not an error! */
			/* TODO: If everything is from ld.so, will the
			 * stacktrace always end in ip=0, and terminate outside
			 * of here? */
			if (p->trace_first_program_ip > 0) {
				ret = 1; /* Just to tell caller that
						* we have ended */
				goto end;
			}

			/* TODO: Investigate why below happens */
//			if (i > 0) /* Not process startup */
//				printk(KERN_INFO PFWALL_PFX "prologue: vma is NULL\n");
			ret = -EINVAL;
			p->trace_first_program_ip = -1;
			strcpy(p->vm_area_strings[i], "vmanull");
			goto end;
		} else if (vma->vm_file == NULL) {
			/* Why is this happening - file
			 * may not be mapped in yet */
			p->trace_first_program_ip = -1;
			#if defined (PFWALL_MATCH_STR) || defined (PFWALL_ADVANCED_STACKTRACE)
			strcpy(p->vm_area_strings[i], "vmafilenull");
			# endif
			ret = -EINVAL;
			goto end;
		}
	}
	p->vma_start[i] = vma->vm_start;
	#if defined (PFWALL_MATCH_STR) || defined (PFWALL_ADVANCED_STACKTRACE)
	/* The VM area name is needed for an advanced stacktrace, to
	 * locate the debug file */
	ptemp = d_path(&(vma->vm_file->f_path), path, PAGE_SIZE);
	if (IS_ERR(ptemp)) {
		printk(KERN_INFO PFWALL_PFX "prologue: d_path failure\n");
		ret = -EINVAL;
		strcpy(p->vm_area_strings[i], "d_pathfail");
	}
	strcpy(p->vm_area_strings[i], ptemp);
	#endif

	#ifdef PFWALL_MATCH_REPR
	p->vm_area_inoden[i] =
		vma->vm_file->f_dentry->d_inode->i_ino;
	#endif

	/* Set the program entry-point */
	#ifdef PFWALL_MATCH_STR
	if (!strcmp(p->vm_area_strings[i] - strlen(current->comm) + strlen(ptemp), current->comm)) {
	#endif
	#ifdef PFWALL_MATCH_REPR
	if (p->vm_area_inoden[i] == current->mm->exe_file->f_dentry->d_inode->i_ino) {
	#endif
		/* This entry point is what we will log in
		   if we don't log the full stack backtrace */
		if (p->program_ip_exists == 0) {
			p->program_ip_exists = 1;
			p->trace_first_program_ip = i;
		}
	}
	/* If everything originates from the library, arbitrarily choose
	 * the first entry-point */
	if (p->program_ip_exists == 0) {
		p->trace_first_program_ip = 0;
	}
end:
	if (path)
		kfree(path);
	return ret;
}

/* Fill up the stack trace along with the VM area names/inodes:
   NOTE: These need be done together because for accurate
   unrolling, we need to know if the VM area has optimized functions */
#if 0
int pft_stacktrace_and_vm_area_context(struct pf_packet_context *p)
{

	int ret = 0;

	const struct pt_regs *regs = task_pt_regs(current);
	unsigned char __user *fp = (unsigned char __user *)regs->bp;
	unsigned char __user *sp = (unsigned char __user *)regs->sp;
	struct static_stack_trace *trace = &(p->trace);


	p->trace_first_program_ip = -1;
	p->program_ip_exists = 0;
	trace->nr_entries = 0;

	if (!current->mm) {
		ret = -EINVAL;
		goto end;
	}

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries] = regs->ip;
	ret = pft_set_vm_area(p, trace->nr_entries);
	if (ret < 0)
		goto end;
	trace->nr_entries++;

	/* Get the VM area names */
	/* Find out and save the first program IP which is not in the library */
	while (trace->nr_entries < trace->max_entries) {
		int prev = trace->nr_entries - 1;
		/* Check in hash table */
		struct debug_dict_value *v;
		/* Default values for normal unroll */
		unsigned long sp_offset = 8;
		unsigned int reg = REG_EBP;

#ifdef ADVANCED_STACKTRACE
		/* Have we already unrolled this frame before? */
		if ((v = pft_debug_dict_get_value(p->vm_area_strings[prev],
			trace->entries[prev] - p->vma_start[prev])) != NULL) {
			sp_offset = v->offset;
			reg = v->reg;
		} else if (pft_debug_needed(p->vm_area_strings[prev])) {
			/* If previous IP was in a fomit-frame-pointer / optimized
			 * library, the frame unwrapping needs debug info */
			/* Set the current IP and return modified sp.
			 * Increment trace->nr_entries */
			sp_offset = dwarf_get_sp_offset_and_reg(p->vm_area_strings[prev],
				trace->entries[prev] - p->vma_start[prev], &reg);
			/* Do we need prologue analysis? */
			if (sp_offset == (unsigned long) -1) {
				/* TODO: MATCH_REPR */
				sp_offset = 8;
				reg = REG_EBP;
//				goto next;
//				if (!strncmp(current->comm, "console-setup", 10) || !strcmp(current->comm, "01ifupdown") || !strncmp(current->comm, "modprobe", 5) || !strncmp(current->comm, "nm-dhcp-client", 10) || !strncmp(current->comm, "avahi-daemon", 7) || !strcmp(current->comm, "kbd_mode") || !strcmp(current->comm, "setfont") || !strcmp(current->comm, "egrep") || !strncmp(current->comm, "udisks-part", 8) || !strcmp(current->comm, "blkid") || !strcmp(current->comm, "cat") || !strcmp(current->comm, "flock") || !strcmp(current->comm, "grep")) {
//					goto next;
//				}
//				printk(KERN_ALERT PFWALL_PFX "prologue: [%s, %d]\n", current->comm, current->pid);
				sp_offset = prologue_get_sp_offset_and_reg(p->vm_area_strings[prev],
					trace->entries[prev] - p->vma_start[prev], p->vma_start[prev], &reg, &fp, sp);
//				printk(KERN_ALERT PFWALL_PFX "prologue_exit: [%s, %d]\n", current->comm, current->pid);

			} else if (((long) sp_offset) < 0) {
				/* Error */
				ret = (int) sp_offset;
				goto end;
			}
			/* Set in hash table */
			pft_debug_dict_set_value(p->vm_area_strings[prev],
				trace->entries[prev] - p->vma_start[prev],
				sp_offset, reg);
		}
// next:
#endif
		/* Unroll this frame */
		if (sp_offset == 8 && reg == REG_EBP) {
			/* Normal unroll - update fp, sp */
			struct stack_frame frame;

			frame.next_fp = NULL;
			frame.ret_addr = 0;
			if (!copy_stack_frame(fp, &frame))
				break;
			if ((unsigned long)fp < regs->sp)
				break;
			if (frame.ret_addr) {
				trace->entries[trace->nr_entries++] =
					frame.ret_addr;
			} else
				break;
			if (fp == frame.next_fp)
				break;
			fp = frame.next_fp;
			sp = (frame.next_fp) + 8;
		}
		#if 0
		else if (reg == REG_ESP) {
			/* Debug unroll */
			sp += sp_offset;
			if (copy_from_user(&(trace->entries[trace->nr_entries]),
					sp, sizeof(unsigned long)))
				break;
			if (trace->entries[trace->nr_entries] == 0x0)
				break;
			trace->nr_entries++;
			sp += 4;
		} else {
			/* Panic */
			printk(KERN_INFO PFWALL_PFX
				"sp_offset not 8 and reg == %d", reg);
		}
		#endif
		/* Get the VM area name, start, and inode of backing file
		   as needed */
		ret = pft_set_vm_area(p, trace->nr_entries - 1);
		/* If we are going upwards from the binary, stop */
		if (ret == 1) {
			trace->nr_entries--;
			break;
		} else if (ret < 0) {
			#if 0
			printk(KERN_INFO PFWALL_PFX
			"Advanced stacktrace for ip: %lu base: %lu in %s went wrong!\n",
			trace->entries[trace->nr_entries - 1], p->vma_start[trace->nr_entries - 1], current->comm);
			printk(KERN_INFO PFWALL_PFX "Basic stacktrace failed!\n");
			/* TODO: Why is this happening in mount? */
			trace->nr_entries--;
			ret = 0;
			#endif
			goto end;
		}
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;

# if 0
		if (p->trace.entries[i] == 0xffffffff || i == MAX_NUM_FRAMES - 1) {
			i--;
			if (found_program_ip == 0) {
				p->trace_first_program_ip = 0;
				p->program_ip_exists = 0; /* All IPs are in the library - there is no IP in the program. This situation occurs if code is started from ld.so, the dynamic loader, as it is not part of the program -- we consider the first frame as the entry-point to the library */
			}
			break;
		}
# endif

	#if defined (PFWALL_MATCH_STR) || defined (PFWALL_ADVANCED_STACKTRACE)
	/* Update that we have vm_area_strings context */
	p->context |= PF_CONTEXT_VM_AREA_STRINGS;
	#endif

end:
	return ret;
}
EXPORT_SYMBOL(pft_stacktrace_and_vm_area_context);
#endif

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
			case LSM_AUDIT_DATA_NET: {
				if (a->u.net.sk) {
					struct sock *sk = a->u.net.sk;
					struct unix_sock *u;

					if (sk->sk_family == AF_UNIX) {
						u = unix_sk(sk);
						dentry = u->dentry;
						inode = dentry->d_inode;
						break;
					}
				}
			}
			default:
			;
		}
	}
	if (dentry)
		strcpy(p->info.filename, dentry->d_name.name);

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

void get_proc_hier(char *s, int len)
{
	struct task_struct *curr = current;
	int b = 0;
	while (curr->pid >= 2) {
		/* We don't want swapper or init processes */
		b += sprintf(s + b, "%s,", curr->comm);
		if (b >= len)
			break;
		curr = curr->parent;
	}
}

int pft_log_duplicate(char *log_str)
{
	return 0;
}

int pft_log(struct pf_packet_context *p, struct pft_target_log *lt)
{
	char *interpreter_str = NULL; /* String for interpreter backtrace */
	char *stack_str = NULL; /* String for stack backtrace */
	char *core_log_str = NULL; /* String to check for duplication */
	char *log_str = NULL;

	int i;
	int rc = 0;
	int pos = 0; /* Position in strings */

	struct pt_regs *ptregs = (struct pt_regs *)
			(current->thread.sp0 - sizeof (struct pt_regs));
	int sn = ptregs->ax;

	/* Userstack backtrace - limited by MAX_NUM_FRAMES */
	# if 0
	/* TODO: There is some bug here or in freeing stack_str */
	stack_str = kzalloc(256, GFP_ATOMIC); /* 11 commas, 2 number, 8 * 32 entries, 1 \0 = 270*/
	if (!stack_str) {
		printk(KERN_INFO PFWALL_PFX "stack_str allocation failed\n");
		rc = -ENOMEM;
		goto end;
	}
	if (p->trace_first_program_ip == 0) {
		/* Go on */
		sprintf(stack_str, "0");
		goto interpreter;
	}
	i = p->trace_first_program_ip;
	while (p->trace.entries[i] != 0xffffffff)
		i++;
	num_frames = i - p->trace_first_program_ip;

	pos += sprintf(stack_str, "%u,", (num_frames <= 10) ? num_frames : 10);

	i = p->trace_first_program_ip;
	while (p->trace.entries[i] != 0xffffffff) {
//		if (i == p->trace_first_program_ip)
		pos += sprintf(stack_str + pos, GFP_ATOMIC, "%lx,", p->trace.entries[i] - p->vma_start[i]);
//		else
//			tmp_stack_str = kasprintf(GFP_ATOMIC, "%lx,", p->trace.entries[i]); /* Don't care -- FIXME */
		i++;
		/* Stop entries whose stack trace goes on forever. Why does this happen? */
		if (i - p->trace_first_program_ip > MAX_NUM_FRAMES)
			break;
	}

interpreter:
	#endif

	/* Interpreter stack backtrace - limited by MAX_INT_LOG */
	if (p->interpreter_info.nr_entries > 0) {
		pos = 0;
		interpreter_str = kzalloc(MAX_INT_LOG, GFP_ATOMIC);
		if (!interpreter_str) {
			printk(KERN_INFO PFWALL_PFX "interpreter_str allocation failed\n");
			rc = -ENOMEM;
			goto end;
		}

		pos += sprintf(interpreter_str, "%u,", p->interpreter_info.nr_entries);
		i = 0;
		while (i < p->interpreter_info.nr_entries) {
			int len;
			len = strlen(p->interpreter_info.script_filename[i]) + 10;
			if (pos + len >= MAX_INT_LOG)
				break;
			pos += sprintf(interpreter_str + pos,
			"%s:%lu,", p->interpreter_info.script_filename[i],
			p->interpreter_info.line_number[i]);
			i++;
		}
	}

	/* Core log string */

//	if (p->trace_first_program_ip != -1 && p->program_ip_exists != 0 && p->trace.entries[p->trace_first_program_ip] != 0 && (p->trace.entries[p->trace_first_program_ip] >= 0x8048000)) /* Not concerned with failure in parsing IPs or IPs which are < 0x8048000 (?) */ {
	if (p->trace_first_program_ip != -1) {
		/* Log the details in the relay channel */
//		rdtscl(time_end);
//		printk(KERN_INFO "time_wall: time to get stack backtrace: %d", time_end - time_strt);

		/* String to log is determined by the context
		 * requested */
		if (lt->context & PF_CONTEXT_SYSCALL_ARGS) {
			char *str = kmalloc(MAX_LOG_STRLEN, GFP_ATOMIC);
			log_str = kasprintf(GFP_ATOMIC, "%s: %s", lt->string, syscall_value_as_string(str, lt->arg_num, lt->offset, lt->type));
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
			log_str = kasprintf(GFP_ATOMIC, "(%s,%s,%u,%u),%s,%lu,%d:%s,%s", // ,%d,%d,%d\n",

				p->info.scontext, p->info.tcontext, p->info.tclass, p->info.requested,
				(strlen(p->info.filename) != 0) ? p->info.filename : "none",
				p->info.filename_inoden,
				p->data_count, (p->data_count > 0) ? p->data : "none",
				(p->interpreter_info.nr_entries > 0) ? interpreter_str : "none"
//				p->trace.entries[0] - p->vma_start[0],
//				p->trace.entries[1] - p->vma_start[1],
//				p->trace.entries[2] - p->vma_start[2]
				);
		}
		if (!log_str)
			goto end;
		/* PID, Interface is printed always */
		if (!pft_log_duplicate(log_str)) {
			char *phier_s = kmalloc(MAX_PROC_HIER, GFP_ATOMIC);
			if (!phier_s)
				goto end;
			get_proc_hier(phier_s, MAX_PROC_HIER);
			core_log_str = kasprintf(GFP_ATOMIC, "TR%d(%d)-[%d,%d],%lu),%d,%s:%s,1,%lx,%s,%s\n",
			sn, (sn == __NR_socketcall) ? ptregs->bx : 0,
			current->cred->fsuid,
			(p->context & PF_CONTEXT_DAC_BINDERS) ? p->sys_fname_attacker_uid : -1,
			_current_trace,
			p->info.pid,
			p->info.binary_path,
			p->vm_area_strings[p->trace_first_program_ip],
			p->trace.entries[p->trace_first_program_ip] - p->vma_start[p->trace_first_program_ip],
			log_str,
			phier_s);
			kfree(phier_s);
			if (!core_log_str)
				goto end;
			current->kernel_request++;
			relay_write(wall_rchan, core_log_str, strlen(core_log_str) + 1);
			current->kernel_request--;
		}
	}

end:
	if (interpreter_str)
		kfree(interpreter_str);
	if (stack_str)
		kfree(stack_str);
	if (log_str)
		kfree(log_str);
	if (core_log_str)
		kfree(core_log_str);
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

	wall_rchan = relay_open("wall_interfaces", NULL, 1024 * 1024, 8, &wall_interfaces_relay_callbacks, &dropped);
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
