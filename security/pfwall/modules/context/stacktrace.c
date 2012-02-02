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

#define DICT_HASH_BITS            8
#define DICT_HTABLE_SIZE (1 << DICT_HASH_BITS)
#define PRIME_SHIFT 251

#define PF_HASH_FILENAME 64

struct hlist_head pft_debug_htable[DICT_HTABLE_SIZE];

struct debug_dict_key {
	char *filename;  /* filename */
	unsigned long pc; /* Program counter */
};

/* debug_dict_value is in wall.h */

typedef struct pft_debug_dict_node {
	struct hlist_node list;
	/* Key Part */
	struct debug_dict_key key;
	/* Value Part */
	struct debug_dict_value value;
} debug_dict_node_t;

/* SDBM hash - given a key, find its hash */
static unsigned long dict_hash(unsigned char *str, unsigned long pc)
{
	unsigned long hash = 0;
	int c;

	while ((c = *str++))
	hash = c + (hash << 6) + (hash << 16) - hash;

	return (((hash >> (32 - DICT_HASH_BITS)) + pc % PRIME_SHIFT) %
			(DICT_HTABLE_SIZE));
}

/* Lookup the key in the hash table and return value */
struct debug_dict_value *pft_debug_dict_get_value(char *filename, unsigned long pc)
{
	debug_dict_node_t *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = dict_hash(filename, pc);
//	printk( KERN_ALERT "%s(): dict_hash[%d] = [%s, %s, %lu]\n", __FUNCTION__, index, current->comm, filename, pc);

        hlist_for_each_entry(tmp, node, &pft_debug_htable[index], list) {
		if((pc == tmp->key.pc) && !strncmp(tmp->key.filename, filename, PF_HASH_FILENAME)) {
			/* Found! */
			return &(tmp->value);
		}
        }
         return NULL;
}
EXPORT_SYMBOL(pft_debug_dict_get_value);

/* Lookup the key in the hash table and return (key, value) pair */
debug_dict_node_t *pft_debug_dict_get_entry(char *filename, unsigned long pc)
{
	debug_dict_node_t *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = dict_hash(filename, pc);

	hlist_for_each_entry(tmp, node, &pft_debug_htable[index], list) {
		if((pc == tmp->key.pc) && !strncmp(tmp->key.filename, filename, PF_HASH_FILENAME)) {
			/* Found! */
			return tmp;
		}
        }
        return NULL;
}

/* Remove key and its corresponding value from dictionary */
void pft_debug_dict_remove_key(char *filename, unsigned long pc)
{
	debug_dict_node_t *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = dict_hash(filename, pc);

        hlist_for_each_entry(tmp, node, &pft_debug_htable[index], list) {
		if((pc == tmp->key.pc) && !strncmp(tmp->key.filename, filename, PF_HASH_FILENAME)) {
			/* Found! */
			kfree(tmp->key.filename);
			hlist_del(&(tmp->list));
			kfree(tmp);
			goto out;
		}
        }
out:
         return;
}
EXPORT_SYMBOL(pft_debug_dict_remove_key);

/* Insert (key, value) pair. Overwrite value if already exists */
int pft_debug_dict_set_value(char *filename, unsigned long pc,
	unsigned long offset, unsigned long reg)
{
        debug_dict_node_t *tmp;
	int index;

	if ((tmp = pft_debug_dict_get_entry(filename, pc)) != NULL) {
		tmp->value.offset = offset;
		tmp->value.reg = reg;
	} else {
		tmp = kzalloc(sizeof(debug_dict_node_t), GFP_KERNEL);
		if (!tmp) {
			printk(KERN_ALERT "Set value tmp failed!\n");
			return -ENOMEM;
		}
		tmp->key.filename = kzalloc(PF_HASH_FILENAME, GFP_KERNEL);

		if (!tmp->key.filename) {
			printk(KERN_ALERT "Set value filename failed!\n");
			return -ENOMEM;
		}

		strncpy(tmp->key.filename, filename, PF_HASH_FILENAME);
		tmp->key.pc = pc;
		tmp->value.offset = offset;
		tmp->value.reg = reg;

		index = dict_hash(tmp->key.filename, tmp->key.pc);
//		printk( KERN_ALERT "%s(): dict_hash[%d] = [%s, %s, %lu]\n", __FUNCTION__, index, current->comm, tmp->key.filename, tmp->key.pc);
		hlist_add_head(&(tmp->list), &(pft_debug_htable[index]));
	}

      return 1;
}
EXPORT_SYMBOL(pft_debug_dict_set_value);

static int __init pft_context_stacktrace_init(void)
{
	int i = 0;
#define DICT_HASH_BITS            8
#define DICT_HTABLE_SIZE (1 << DICT_HASH_BITS)
	for (i = 0; i < DICT_HTABLE_SIZE; i++)
		memset(&pft_debug_htable[i], 0, sizeof(struct hlist_head));
	return 0;
}
module_init(pft_context_stacktrace_init);
