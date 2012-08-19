#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/debugfs.h>
#include <linux/user_unwind.h>
#include <linux/dwarf.h>
#include <linux/wall.h>

#include <asm/syscall.h>

/* Load ld.so's inode number */

/* Uninitialized value */
ino_t ld_inode = -1;
EXPORT_SYMBOL(ld_inode);

static ssize_t
pft_ld_inode_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
	/* TODO: 12??? */
	char tmpbuf[12];
	ssize_t length;

	length = scnprintf(tmpbuf, 12, "%lx\n", ld_inode);
	return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, length);
}

static ssize_t
pft_ld_inode_write(struct file *filp, const char __user *buf,
                   size_t count, loff_t *ppos)
{
	char *page;
	ssize_t length;
	int new_value;

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
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	ld_inode = new_value;
	length = count;
out:
	free_page((unsigned long) page);
	return length;
}


static const struct file_operations pft_ld_inode_fops = {
       .write  = pft_ld_inode_write,
       .read   = pft_ld_inode_read,
};

struct table_entry {
	int32_t start_ip_offset;
	int32_t fde_offset;
};

static struct table_entry*
lookup(dwarf_word_t ip, struct eh_table_data *ed)
{
	struct table_entry *fde = NULL;
	unsigned long lo, hi, mid;

	ip -= ed->table_base;

	/* Do a binary search for right entry. */
	for (lo = 0, hi = ed->table_count; lo < hi;)
	{
		mid = (lo + hi) / 2;
		fde = ed->table_data + mid;

		if (ip < fde->start_ip_offset)
			hi = mid;
		else
			lo = mid + 1;
	}

	if (hi <= 0)
		return NULL;

	fde = ed->table_data + hi - 1;
	return fde;
}

static void dwarf_regs_get(struct unw_t *u, struct dwarf_regs *regs)
{
	regs->cfa = u->cfa;
	dwarf_regs_pt2dwarf(&u->regs, regs);
}

static void dwarf_regs_set(struct unw_t *u, struct dwarf_regs *regs)
{
	u->cfa = regs->cfa;
	dwarf_regs_dwarf2pt(regs, &u->regs);
}

int unw_step(struct unw_t *u, struct eh_table_data *ed,
		unsigned long st_high, unsigned long st_low)
{
	struct table_entry *entry;
	struct dwarf_fde fde;
	struct dwarf_regs regs;
	void *data;
	int ret;

	entry = lookup(u->regs.ip, ed);
	if (!entry)
		return -ENOENT;

	data = (void *) (ed->table_base + entry->fde_offset);

	ret = dwarf_fde_init(&fde, data);
	if (ret)
		return ret;

	dwarf_regs_get(u, &regs);

	ret = dwarf_fde_process(&fde, &regs, st_high, st_low);
	if (!ret)
		dwarf_regs_set(u, &regs);

	return ret;
}

void unw_regs(struct unw_t *u, struct pt_regs *regs)
{
	memcpy(regs, &u->regs, sizeof(u->regs));
}



#ifdef CONFIG_X86_64
void __show_unw_regs(struct unw_t *u)
{
	struct pt_regs *regs = &u->regs;
	printk(KERN_INFO "RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->ip);
	printk(KERN_INFO "RSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss,
			regs->sp, regs->flags);
	printk(KERN_INFO "RAX: %016lx RBX: %016lx RCX: %016lx\n",
	       regs->ax, regs->bx, regs->cx);
	printk(KERN_INFO "RDX: %016lx RSI: %016lx RDI: %016lx\n",
	       regs->dx, regs->si, regs->di);
	printk(KERN_INFO "RBP: %016lx R08: %016lx R09: %016lx\n",
	       regs->bp, regs->r8, regs->r9);
	printk(KERN_INFO "R10: %016lx R11: %016lx R12: %016lx\n",
	       regs->r10, regs->r11, regs->r12);
	printk(KERN_INFO "R13: %016lx R14: %016lx R15: %016lx\n",
	       regs->r13, regs->r14, regs->r15);

	printk(KERN_INFO "CFA: %08lx\n", (unsigned long) u->cfa);
}
#endif
#ifdef CONFIG_X86_32
void __show_unw_regs(struct unw_t *u)
{
	struct pt_regs *regs = &u->regs;
	printk("EIP %08lx\n", regs->ip);

	printk(KERN_INFO "EAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx\n",
		regs->ax, regs->bx, regs->cx, regs->dx);
	printk(KERN_INFO "ESI: %08lx EDI: %08lx EBP: %08lx ESP: %08lx\n",
		regs->si, regs->di, regs->bp, regs->sp);
	printk(KERN_INFO " DS: %04x ES: %04x FS: %04x GS: %04lx SS: %04lx\n",
	       (u16)regs->ds, (u16)regs->es, (u16)regs->fs, regs->gs, regs->ss);

	printk(KERN_INFO "CFA: %08lx\n", (unsigned long) u->cfa);
}
#endif

void eh_frame_data(char *base, struct eh_table_data *ed)
{
	struct eh_frame_hdr *hdr;
	dwarf_word_t addr, eh_frame_start;

	hdr = (struct eh_frame_hdr *) base;
	addr = (dwarf_word_t) (hdr + 1);

	if (dwarf_read_pointer(&addr, hdr->eh_frame_ptr_enc,
			       &eh_frame_start)) {
		PFWALL_ERR(1, "Failed to read eh_frame_start\n");
		goto failed;
	}

	if (dwarf_read_pointer(&addr, hdr->fde_count_enc,
			       &ed->table_count)) {
		PFWALL_ERR(1, "Failed to read fde_count\n");
		goto failed;
	}

	if (hdr->table_enc != (DW_EH_PE_datarel | DW_EH_PE_sdata4)) {
		PFWALL_ERR(1, "Unexpected table_enc\n");
		goto failed;
	}

	ed->table_data = (struct table_entry *) addr;
	ed->table_base = (dwarf_word_t) hdr;

failed:
	return;
}

int get_user_pages_range(struct task_struct *t, unsigned long start,
		unsigned long len, struct page ***pgs)
{
	int nr, nm = 0, ret = 0;
	unsigned long end;
	struct page **pages = NULL;

	nr = (len / PAGE_SIZE) + 1;
	end = start + (nr << PAGE_SHIFT);
	*pgs = kmalloc(sizeof(struct page *) *
			nr, GFP_ATOMIC);
	pages = *pgs;
	nm = __get_user_pages_fast(start, nr, 0, pages);
	PFWALL_DBG("__get_user_pages_fast: [%d out of %d]\n", nm, nr);
	if (nm < nr) {
		start += nm << PAGE_SHIFT;
		pages += nm;
		if (down_read_trylock(&t->mm->mmap_sem)) {
			ret = get_user_pages(t, t->mm,
					start,
					(end - start) >> PAGE_SHIFT,
					0, 0, pages, NULL);
			up_read(&t->mm->mmap_sem);
		}
	}
	PFWALL_DBG("get_user_pages: [%d out of %d]\n", ret, nr);

	if (nm > 0) {
		if (ret < 0)
			ret = nm;
		else
			ret += nm;
	}
	PFWALL_DBG("total: [%d out of %d]\n", ret, nr);

	if (nr != nm)
		PFWALL_DBG("Pinned pages less than requested: "
				"%d out of %d! [%s at %lx]\n",
			nm, nr, current->comm, start);

	return ret;
}

void put_user_pages_range(struct page **pgs, unsigned long sz)
{
	int i;
	for (i = 0; i < sz; i++)
		put_page(pgs[i]);
	kfree(pgs);
}

#define EHDR(n) ((struct elfhdr *) n)
#define SHDR(n) ((struct elf_shdr *) n)

/**
 * get_eh_section() - Pointer to ELF eh_frame_hdr + eh_frame sections.
 * @vma:		VM area where code is mapped in
 *
 * Caller has to free allocated buffer
 */

unsigned long get_eh_section(struct vm_area_struct *vma, unsigned long *eh_start)
{
	struct elfhdr *ehdr, *ehdr_buf;
	struct elf_phdr *phdr = NULL, *phdr_buf = NULL;
	int i = 0, ret = 0;
	unsigned long len = 0;

	/* Code for fde Taken from kernel/dwarf-fde.c */
	uint64_t u64val;
	uint32_t u32val;

	char *tp = NULL;

	ehdr = (struct elfhdr *) vma->vm_start;
	PFWALL_DBG("exec start: [%s at %p]\n", current->comm, ehdr);

	/* TODO: Should we convert copy_from_user to get_user_pages?
	 		If so, we won't know eh_frame section length beforehand. */
	ehdr_buf = (struct elfhdr *) kmalloc(sizeof(struct elfhdr), GFP_ATOMIC);
	if (!ehdr_buf) {
		PFWALL_ERR(1, "struct elfhdr alloc failed!\n");
		ret = -ENOMEM;
		goto fail;
	}

	ret = __copy_from_user_inatomic(ehdr_buf, (void *)ehdr, sizeof(struct elfhdr));
	if (ret != 0) {
		PFWALL_ERR(1, "struct elfhdr copy failed!\n");
		ret = -ENOMEM;
		goto fail;
	}

	if (memcmp(ehdr_buf->e_ident, ELFMAG, SELFMAG) != 0) {
		ret = -EINVAL;
		goto fail;
	}

	phdr = (struct elf_phdr *) ((void *) ehdr + ehdr->e_phoff);
	phdr_buf = (struct elf_phdr *) kmalloc(ehdr->e_phentsize * ehdr->e_phnum, GFP_ATOMIC);

	if (!phdr) {
		PFWALL_ERR(1, "struct elf_phdr alloc failed!\n");
		ret = -ENOMEM;
		goto fail;
	}
	ret = copy_from_user(phdr_buf, (void *) phdr,
			ehdr_buf->e_phentsize * ehdr_buf->e_phnum);
	if (ret != 0) {
		PFWALL_ERR(1, "struct elf_phdr copy failed!\n");
		ret = -ENOMEM;
		goto fail;
	}

	/* Search for the needed section */
	for (i = 1; i < ehdr_buf->e_phnum; i++) {
		if (phdr_buf[i].p_type == PT_GNU_EH_FRAME) {
			/* The length to be copied should be calculated based on
			   eh_frame also -- traverse its records till you reach NOP */
			*eh_start = (unsigned long) ((char *) ehdr + phdr_buf[i].p_offset);
			len += phdr_buf[i].p_filesz;

			/* Get start of eh_frame */
			tp = ((char *) (ehdr)) + phdr_buf[i].p_offset + len;

			/* Go through each CIE and FDE, */
			while (1) {
				if (copy_from_user(&u32val, tp, sizeof(uint32_t)) != 0) {
					PFWALL_ERR(1, "copy_from_user32 failed [%s at %p]\n", current->comm, tp);
					ret = -ENOMEM;
					goto fail;
				}
				tp += sizeof(uint32_t);
				len += sizeof(uint32_t);
				if (u32val == 0)
					break;
				else if (u32val != 0xffffffff) {
					tp += u32val;
					len += u32val;
				} else {
					if (copy_from_user(&u64val, tp, sizeof(uint64_t)) != 0) {
						PFWALL_ERR(1, "copy_from_user64 failed [%s at %p]\n", current->comm, tp);
						ret = -ENOMEM;
						goto fail;
					}
					tp += sizeof(uint64_t);
					tp += u64val;
					len += sizeof(uint64_t);
					len += u64val;
				}
			}
			break;
		}
	}
fail:

	if (ehdr_buf)
		kfree(ehdr_buf);
	if (phdr_buf)
		kfree(phdr_buf);
	if (ret < 0)
		len = 0;
	return len;
}

/* find_vma returns the first vma where ip < vma->vm_end. We
   also need ip >= vma->vm_start */

struct vm_area_struct *find_in_vma(struct mm_struct *mm, unsigned long ip)
{
	struct vm_area_struct *vma = NULL;
	vma = find_vma(mm, ip);
	if (vma == NULL || ip < vma->vm_start)
		vma = NULL;
	return vma;
}

static inline void dump_memory_areas(struct task_struct *t)
{
	unsigned long addr = 0;
	struct vm_area_struct *vma = NULL;
	struct file *file = NULL;
	char *name = NULL;
	char *buf = (char *)__get_free_page(GFP_KERNEL);

	PFWALL_DBG("memory dump for [%s]:\n", t->comm);
	for (vma = find_vma(t->mm, addr); vma; vma = vma->vm_next) {
		file = vma->vm_file;
		if (file) {
			name = vma->vm_file->f_path.dentry->d_iname;
		} else {
			name = (char *) arch_vma_name(vma);
			if (!name) {
				pid_t tid;

				if (!t->mm) {
					name = "[vdso]";
					goto done;
				}

				if (vma->vm_start <= t->mm->brk &&
					vma->vm_end >= t->mm->start_brk) {
					name = "[heap]";
					goto done;
				}

				tid = vm_is_stack(t, vma, 1);

				if (tid != 0) {
					if ((vma->vm_start <= t->mm->start_stack &&
						vma->vm_end >= t->mm->start_stack)) {
						name = "[stack]";
					}
				}
			}
		}
done:
		PFWALL_DBG("%lx-%lx\t\t%s\n", vma->vm_start, vma->vm_end, name);
	}
	free_page((unsigned long) buf);
}

static inline int stack_guard_page(struct vm_area_struct *vma, unsigned long addr)
{
	return ((vma->vm_start <= addr) && (vma->vm_start + PAGE_SIZE > addr));
}

int is_stack_ip(struct vm_area_struct *vma, unsigned long ip, struct task_struct *t)
{
	unsigned long start;
	if (!(vma->vm_start <= t->mm->start_stack &&
		vma->vm_end >= t->mm->start_stack)) {
		PFWALL_ERR(2, "sp not within stack\n");
		return -EINVAL;
	}

	start = vma->vm_start;
	if (stack_guard_page(vma, ip)) {
		PFWALL_ERR(1, "sp in guard page! [%lx]\n", ip);
		return -EINVAL;
	}
	return 0;
}

int is_exec_ip(struct vm_area_struct *vma, unsigned long ip, struct task_struct *t)
{
	if (!(vma->vm_flags & VM_EXEC))
		return -EINVAL;
	return 0;
}

struct vm_area_struct *vma_if_exec_ip(unsigned long ip, struct task_struct *t)
{
	struct vm_area_struct *vma = NULL;
	int ret = 0;

	vma = find_in_vma(t->mm, ip);
	if (vma == NULL) {
		PFWALL_ERR(2, "exec vma not found: [%s]\n", t->comm);
		ret = -ENOENT;
		goto fail;
	}

	ret = is_exec_ip(vma, ip, t);
	if (ret < 0)
		PFWALL_ERR(2, "[%lx] not executable: [%s]\n", (unsigned long) ip, t->comm);

fail:
	if (ret < 0)
		return ERR_PTR(ret);
	return vma;
}
EXPORT_SYMBOL(vma_if_exec_ip);

struct vm_area_struct *vma_if_stack_ip(unsigned long ip, struct task_struct *t)
{
	struct vm_area_struct *vma = NULL;
	int ret = 0;

	vma = find_in_vma(t->mm, ip);
	if (vma == NULL) {
		PFWALL_ERR(1, "stack vma not found: [%s]\n", t->comm);
		ret = -ENOENT;
		goto fail;
	}

	ret = is_stack_ip(vma, ip, t);
	if (ret < 0)
		PFWALL_ERR(1, "[%lx] not in stack: [%s]\n", (unsigned long) ip, t->comm);

fail:
	if (ret < 0)
		return ERR_PTR(ret);
	return vma;
}
EXPORT_SYMBOL(vma_if_stack_ip);

#define IS_BIN_VMA(t, vma) ( \
				((vma->vm_file) && (t->mm->exe_file->f_dentry->d_inode->i_ino == \
				vma->vm_file->f_dentry->d_inode->i_ino)) \
		)

static void update_us(struct task_struct *t, struct vm_area_struct *vma,
		unsigned long ip)
{
	struct user_stack_info *us;
	int c;
	ino_t vma_inode;

	if (!vma->vm_file)
		return;
	vma_inode = vma->vm_file->f_dentry->d_inode->i_ino;
	us = &(t->user_stack);
	c = us->trace.nr_entries;

	/* Do not fill first IP in next VMA region */
	if (ip < vma->vm_start || ip > vma->vm_end)
		return;

	us->trace.entries[c] = ip;
	if (t->mm->exe_file->f_dentry->d_inode->i_ino == vma_inode) {
		/* Program entry */
		if (!us->bin_ip_exists) {
			/* First program entry */
			us->ept_ind = c;
			us->bin_ip_exists = 1;
		}
	} else if (vma_inode == ld_inode) {
		/* Dynamic loader/linker */
		us->ept_ind = c;
		us->bin_ip_exists = 0;
	} else if (ld_inode == -1 && us->bin_ip_exists == 0) {
		/* Before ld_inode is loaded, assume any IP as loader IP
		 * if program IP doesn't exist, to avoid errors later */
		us->ept_ind = c;
		us->bin_ip_exists = 0;
	}
	/* VMA start and inode */
	us->vma_inoden[c] = vma_inode;
	us->vma_start[c] = vma->vm_start;
	us->trace.nr_entries++;
}

static void vma_start_ino(struct task_struct *t)
{
	struct user_stack_info *us = &(t->user_stack);
	struct vm_area_struct *vma;
	int i = 0;
	unsigned long ip;

	for (i = 0; i < us->trace.max_entries; i++) {
		ip = us->trace.entries[i];
		if (ip == ULONG_MAX) {
			us->trace.nr_entries = i;
			break;
		}
		vma = find_in_vma(t->mm, ip);
		if (vma == NULL || vma->vm_file == NULL) {
			us->trace.nr_entries = i;
			break;
		}
		update_us(t, vma, ip);
	}

	return;
}

struct stack_frame_user {
	const void __user	*next_fp;
	unsigned long		ret_addr;
};

static int copy_stack_frame_user(const void __user *fp,
			struct stack_frame_user *frame)
{
	int ret;

	if (!access_ok(VERIFY_READ, fp, sizeof(*frame)))
		return 0;

	ret = 1;
	pagefault_disable();
	if (__copy_from_user_inatomic(frame, fp, sizeof(*frame)))
		ret = 0;
	pagefault_enable();

	return ret;
}

static inline void __static_save_stack_trace_user(struct static_stack_trace *trace)
{
	const struct pt_regs *regs = task_pt_regs(current);
	const void __user *fp = (const void __user *)regs->bp;

	if (trace->nr_entries < trace->max_entries - 1)
		trace->entries[trace->nr_entries++] = regs->ip;

	while (trace->nr_entries < trace->max_entries - 1) {
		struct stack_frame_user frame;

		frame.next_fp = NULL;
		frame.ret_addr = 0;
		if (!copy_stack_frame_user(fp, &frame))
			break;
		if ((unsigned long)fp < regs->sp)
			break;
		if (frame.ret_addr) {
			trace->entries[trace->nr_entries++] =
				frame.ret_addr;
		}
		if (fp == frame.next_fp)
			break;
		fp = frame.next_fp;
	}
}

void static_save_stack_trace_user(struct static_stack_trace *trace)
{
	/*
	 * Trace user stack if we are not a kernel thread
	 */
	if (current->mm) {
		__static_save_stack_trace_user(trace);
	}
	if (trace->nr_entries == 1) {
		/* Garbage IP */
		trace->nr_entries--;
	}
	/* 
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
	*/
}

static inline void us_init(struct user_stack_info *us)
{
	us->trace.nr_entries = 0;
	us->trace.max_entries = MAX_NUM_FRAMES;
	us->bin_ip_exists = 0;
	us->ept_ind = 0;
}

#define CHECK_PRINT_EXIT(f) { \
	if (f) { \
		printk(#f); \
		goto fail; \
	} \
}

/**
 * user_unwind() - Use eh_frame to unwind user stack
 * @t:		Task struct
 *
 * Any trace should go back up to loader or program binary.
 * Successful run can be detected by checking if
 * t->user_stack.ept_ind is -1 or not.
 *
 * Do NOT call this function in improper contexts -
 * !t->mm, in_atomic(), in_irq(), in_interrupt(), irqs_disabled()
 * Call it only in process contexts with a userspace mm.
 *
 * Invariants:
 * 	On exit, trace.entries[nr_entries - 1] = ULONG_MAX.
 *  Each trace.entries up to trace.entries[nr_entries - 2]
 *  has a valid VMA. If nr_entries == 1 (=> ULONG_MAX),
 *  user stack completely invalid.
 */

void user_unwind(struct task_struct *t)
{
	struct unw_t unw;
	struct eh_table_data ed;
	struct vm_area_struct *vma;
	unsigned long eh_start, eh_len;
	struct page **eh_frame_pgs = NULL;
	struct page **stack_pgs = NULL;
	int np_ehf, np_st, ret = 0;
	struct pt_regs regs;
	unsigned long stack_start, stack_end;
	struct user_stack_info *us = &(t->user_stack);

	us_init(&(t->user_stack));

	/* Initialize first frame from kernel stack */
	PFWALL_DBG("\n==========================\n");
	memcpy(&unw.regs, task_pt_regs(t), sizeof(unw.regs));

	/* The CFA for the first frame is the stack pointer */
	unw.cfa = task_pt_regs(t)->sp;

	/* Debug: Print memory layout */
	if (PFWALL_DBG_ON)
		dump_memory_areas(t);

	/* Map in the stack */
	vma = vma_if_stack_ip(unw.cfa, t);
	if (IS_ERR(vma)) {
		/* Stack not found? */
		goto end;
	}
	stack_start = unw.regs.sp;
	stack_end = vma->vm_end;

	/* Pin stack pages */
	np_st = get_user_pages_range(t, vma->vm_start, (unw.cfa - vma->vm_start + 1), &stack_pgs);

	do {
		vma = vma_if_exec_ip(unw.regs.ip, t);
		if (IS_ERR(vma)) {
			/* Kernel thread, not executable, or legitimate end */
			goto fail_put_stack_pages;
		}
		PFWALL_DBG("VMA start: [%s, %lx]\n", t->comm, vma->vm_start);
		eh_len = get_eh_section(vma, &eh_start);
		if (eh_len == 0) {
			/* If only the binary itself doesn't have eh_frame, we can still get ept_ind */
			if (t->user_stack.trace.nr_entries > 0 && IS_BIN_VMA(t, vma) &&
				(t->user_stack.trace.nr_entries < t->user_stack.trace.max_entries - 1)) {
				update_us(t, vma, unw.regs.ip);
			} else {
				/* Else, do a full normal stack trace */

				PFWALL_ERR(2, "No eh_frame_hdr section, "
					"reverting to normal trace: [%s]\n", t->comm);
				us_init(&(t->user_stack));
				static_save_stack_trace_user(&(t->user_stack.trace));
				vma_start_ino(t);
			}
			goto fail_put_stack_pages;
		}
		PFWALL_DBG("eh_frame length: [%s, %lx]\n", t->comm, eh_len);

		/* Pin eh_frame program header pages */
		np_ehf = get_user_pages_range(t, eh_start, eh_len, &eh_frame_pgs);
		eh_frame_data((char *) eh_start, &ed);

		do {
			if (PFWALL_DBG_ON)
				__show_unw_regs(&unw);

			/* Before each virtual unwind step, check
			   validity of previous step's stack pointer */
			if (!(unw.regs.sp >= stack_start && unw.regs.sp < stack_end))
				goto fail_put_region_pages;
			unw_regs(&unw, &regs);

			/* Update IP in user stack trace */
			update_us(t, vma, unw.regs.ip);

		} while (((ret = unw_step(&unw, &ed, stack_end, stack_start)) == 0) &&
					(us->trace.nr_entries < us->trace.max_entries - 1));

		/* If unw_step failed because of anything other than
			eh_frame_hdr lookup (-ENOENT), or loop stopped due to max_entries, 
			break out. -ENOENT is ok, as it signifies the next VMA region for
			stack IPs.  -ENOENT is returned only by lookup(). */
		if (ret != -ENOENT)
			goto fail_put_region_pages;
		/* Release pinned pages */
		put_user_pages_range(eh_frame_pgs, np_ehf);
	} while (1);

fail_put_region_pages:
	put_user_pages_range(eh_frame_pgs, np_ehf);
fail_put_stack_pages:
	put_user_pages_range(stack_pgs, np_st);
end:
	PFWALL_DBG("\n==========================\n");
	/* pfwall-specific: Fill last entry. There is always space for this because
	 * nr_entries can only become at most max_entries - 2 above (and in 
	 * fp unrolling code).  */
	us->trace.entries[us->trace.nr_entries++] = ULONG_MAX;

	return;
}
EXPORT_SYMBOL(user_unwind);

static int __init user_unwind_init(void)
{
	struct dentry *ld_inode_dentry;
	ld_inode_dentry = debugfs_create_file("ld_inode", 0600, NULL, NULL, &pft_ld_inode_fops);

	if (!ld_inode_dentry) {
		PFWALL_ERR(1, "Unable to create ld_inode\n");
	}
	return 0;
}
fs_initcall(user_unwind_init);
