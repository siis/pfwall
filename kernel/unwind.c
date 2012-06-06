#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/unwind.h>
#include <linux/dwarf.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/completion.h>

struct table_entry {
	int32_t start_ip_offset;
	int32_t fde_offset;
};

static struct table_entry* 	table_data;
static dwarf_word_t 		table_count;
static dwarf_word_t		table_base;

static struct table_entry*
lookup(dwarf_word_t ip)
{
	struct table_entry *fde = NULL;
	unsigned long lo, hi, mid;

	ip -= table_base;

	/* Do a binary search for right entry. */
	for (lo = 0, hi = table_count; lo < hi;)
	{
		mid = (lo + hi) / 2;
		fde = table_data + mid;

		if (ip < fde->start_ip_offset)
			hi = mid;
		else
			lo = mid + 1;
	}

	if (hi <= 0)
		return NULL;

	fde = table_data + hi - 1;
	return fde;
}

#ifdef CONFIG_UNWIND_EH_FRAME
extern char __eh_frame_hdr_start[];
extern char __eh_frame_hdr_end[];
extern char __eh_frame_start[];
extern char __eh_frame_end[];

struct eh_frame_hdr {
	unsigned char version;
	unsigned char eh_frame_ptr_enc;
	unsigned char fde_count_enc;
	unsigned char table_enc;
};

static int __init eh_frame_init(void)
{
	struct eh_frame_hdr *hdr;
	dwarf_word_t addr, eh_frame_start;

	hdr = (struct eh_frame_hdr *) __eh_frame_hdr_start;
	addr = (dwarf_word_t) (hdr + 1);

	if (dwarf_read_pointer(&addr, hdr->eh_frame_ptr_enc,
			       &eh_frame_start)) {
		printk("unwind failed to read eh_frame_start\n");
		goto failed;
	}

	if (dwarf_read_pointer(&addr, hdr->fde_count_enc,
			       &table_count)) {
		printk("unwind failed to read fde_count\n");
		goto failed;
	}

	if (hdr->table_enc != (DW_EH_PE_datarel | DW_EH_PE_sdata4)) {
		printk("unwind unexpected table_enc\n");
		goto failed;
	}

	table_data = (struct table_entry *) addr;
	table_base = (dwarf_word_t) hdr;

	printk("unwind __eh_frame_hdr_start  %p\n", __eh_frame_hdr_start);
	printk("unwind __eh_frame_hdr_end    %p\n", __eh_frame_hdr_end);
	printk("unwind __eh_frame_start      %p\n", __eh_frame_start);
	printk("unwind __eh_frame_en         %p\n", __eh_frame_end);
	printk("unwind version               %x\n", hdr->version);
	printk("unwind eh_frame_ptr_enc      %x\n", hdr->eh_frame_ptr_enc);
	printk("unwind fde_count_enc         %x\n", hdr->fde_count_enc);
	printk("unwind table_enc             %x\n", hdr->table_enc);
	printk("unwind table_data            %p\n", table_data);
	printk("unwind table_count           %llx\n", table_count);
	printk("unwind table_base            %llx\n", table_base);

	printk("unwind eh_frame table initialized\n");
	return 0;

 failed:
	printk("unwind table initialization failed\n");
	return -EINVAL;
}
#endif /* CONFIG_UNWIND_EH_FRAME */

static int __init unw_init_table(void)
{
#ifdef CONFIG_UNWIND_EH_FRAME
	return eh_frame_init();
#endif
	return -EINVAL;
}

pure_initcall(unw_init_table);

__weak void unw_init(struct unw_t *u)
{
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

int unw_step(struct unw_t *u)
{
	struct table_entry *entry;
	struct dwarf_fde fde;
	struct dwarf_regs regs;
	void *data;
	int ret;

	entry = lookup(u->regs.ip);
	if (!entry)
		return -EINVAL;

	data = (void *) (table_base + entry->fde_offset);

	ret = dwarf_fde_init(&fde, data);
	if (ret)
		return ret;

	dwarf_regs_get(u, &regs);

	ret = dwarf_fde_process(&fde, &regs);
	if (!ret)
		dwarf_regs_set(u, &regs);

	return ret;
}

void unw_regs(struct unw_t *u, struct pt_regs *regs)
{
	memcpy(regs, &u->regs, sizeof(u->regs));
}

void unw_backtrace(void)
{
	struct unw_t unw;
	struct pt_regs regs;

	unw_init(&unw);

	printk("unwind backtrace:\n");

	do {
		unw_regs(&unw, &regs);
		printk("    [0x%lx] %pS\n", regs.ip, (void *) regs.ip);
	} while (!unw_step(&unw));

}

static DECLARE_COMPLETION(unwind_work);

static void unwind_test_irq_callback(unsigned long data)
{
	unw_backtrace();
	complete(&unwind_work);
}

static DECLARE_TASKLET(unwind_tasklet, &unwind_test_irq_callback, 0);

static void unw_test_irq(void)
{
        printk("Testing a unwind from irq context.\n");

        init_completion(&unwind_work);
        tasklet_schedule(&unwind_tasklet);
        wait_for_completion(&unwind_work);
}

static ssize_t
test_write(struct file *filp, const char __user *ubuf,
	   size_t cnt, loff_t *ppos)
{
	printk("Testing unwind from process context.\n");
	unw_backtrace();
	unw_test_irq();
	return cnt;
}

static const struct file_operations test_fops = {
	.write = test_write,
};

static int __init unwind_init_test(void)
{
	if (!debugfs_create_file("unwind_test", 0644, NULL, NULL,
				 &test_fops))
		return -ENOMEM;

	return 0;
}

late_initcall(unwind_init_test);
