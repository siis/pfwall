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

#define DICT_HASH_BITS            8
#define DICT_HTABLE_SIZE (1 << DICT_HASH_BITS)

#define PF_SET 0x1
#define PF_DELETE 0x2

#define PF_STATE_NONE 0
#define PF_STATE_ADD 1
#define PF_STATE_SUBTRACT 2

#define PF_STATE_STR_MAX 128
// struct hlist_head dict_htable[DICT_HTABLE_SIZE];

#define PF_VALUE_GIVEN 0
#define PF_VALUE_FROM_CONTEXT 1

static unsigned long dict_hash(unsigned char *str)
{
	unsigned long hash = 0;
	int c;

	while ((c = *str++))
	hash = c + (hash << 6) + (hash << 16) - hash;

	return hash >> (32 - DICT_HASH_BITS);
}

struct pft_state_target
{
	char key[PF_STATE_STR_MAX];
	int value_origin; /* Whether the value is obtained
			   * from the packet or the rule */
	union {
		char value_str[PF_STATE_STR_MAX];
		int value_context;
	} value;

	int add; /* Should we add/subtract the value to the current value? */
	int flags; /* 1 - set, 2 - remove, */
	int verdict; /* Default is PF_CONTINUE */
};

/* Remove key and its corresponding value from dictionary */
void pft_dict_remove_key(char *key)
{
	dict_node_t *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = dict_hash(key);

        hlist_for_each_entry(tmp, node, &current->dict_htable[index], list) {
		if(!strcmp(tmp->key, key)) {
			/* Found! */
			kfree(tmp->key);
			kfree(tmp->value);
			hlist_del(&(tmp->list));
			kfree(tmp);
			goto out;
		}
        }
out:
         return;
}
EXPORT_SYMBOL(pft_dict_remove_key);

/* Insert (key, value) pair. Overwrite value if already exists */
int pft_dict_set_value(char *key, char *value, int operation)
{
        dict_node_t *tmp;
	int index;

	if ((tmp = pft_dict_get_entry(key)) != NULL) {
		/* Overwrite or update */
		if (operation == PF_STATE_NONE) {
			strcpy(tmp->value, value);
		} else if (operation == PF_STATE_ADD) {
			/* Get the value */
			int new_val = simple_strtol(tmp->value, NULL, 10) +
				simple_strtol(value, NULL, 10);
			sprintf(tmp->value, "%d", new_val);
		} else if (operation == PF_STATE_SUBTRACT) {
			/* Get the value */
			int new_val = simple_strtol(tmp->value, NULL, 10) -
				simple_strtol(value, NULL, 10);
			sprintf(tmp->value, "%d", new_val);
		}
	} else {
		/* In case we create, assume previous value 0
		 * for addition and subtraction */
		tmp = kmalloc(sizeof(dict_node_t), GFP_ATOMIC);
		if (!tmp)
			return -ENOMEM;
		tmp->key = kmalloc(PF_STATE_STR_MAX, GFP_ATOMIC);
		tmp->value = kmalloc(PF_STATE_STR_MAX, GFP_ATOMIC);

		if (!tmp->key || !tmp->value)
			return -ENOMEM;

		strcpy(tmp->key, key);
		strcpy(tmp->value, value);

		index = dict_hash(tmp->key);
//		printk( KERN_ALERT "%s(): dict_hash[%d] = [%s]\n", __FUNCTION__, index, key);
		hlist_add_head(&(tmp->list), &(current->dict_htable[index]));
	}

      return 1;
}
EXPORT_SYMBOL(pft_dict_set_value);

#if 0
extern struct rchan* wall_rchan;
#endif

/* Set a (k, v) pair, delete a (k, v) pair, return a verdict */
int pft_state_target(struct pf_packet_context *p, void *target_specific_data)
{
	struct pft_state_target *st = (struct pft_state_target *)
				target_specific_data;
	int rc = 0;
	char *value = NULL;

	value = kzalloc(PF_STATE_STR_MAX, GFP_ATOMIC);
	if (value == NULL) {
		printk(KERN_INFO PFWALL_PFX "value allocation failed\n");
		rc = -ENOMEM;
		goto end;
	}

	if (st->value_origin == PF_VALUE_GIVEN) {
		strcpy(value, st->value.value_str);
	} else if (st->value_origin == PF_VALUE_FROM_CONTEXT) {
		/* TODO: Other context */
		if (st->value.value_context == PF_CONTEXT_FILENAME) {
			sprintf(value, "%lu", p->info.filename_inoden);
		} else {
			printk(KERN_INFO PFWALL_PFX "Unknown context for state module!\n");
		}
	}

	if (st->flags & PF_SET)
		rc = pft_dict_set_value(st->key, value, st->add);
	else if (st->flags & PF_DELETE)
		pft_dict_remove_key(st->key);
	#if 0
	if ((st->flags & PF_SET) && (!strncmp(current->comm, "mount", 5)))
		printk(KERN_INFO PFWALL_PFX "Setting state for %s, %d: syscall: [%d]", current->comm, current->pid, syscall_get_nr(current, task_pt_regs(current)));
	if ((st->flags & PF_DELETE) && (!strncmp(current->comm, "mount", 5)))
		printk(KERN_INFO PFWALL_PFX "Unsetting state for %s, %d: syscall: [%d]", current->comm, current->pid, syscall_get_nr(current, task_pt_regs(current)));
	#endif
	#if 0
	/* Hack for signals tracing */
	if (wall_rchan) {
		char *str;
		if (!strcmp(st->value, "0")) {
			str = kasprintf(GFP_ATOMIC, "%d (%s): unsetting sig\n",
				current->pid, current->comm);
		} else if (!strcmp(st->value, "1")) {
			str = kasprintf(GFP_ATOMIC, "%d (%s): setting signo: %d\n",
				current->pid, current->comm, p->signo);
		}
		relay_write(wall_rchan, str, strlen(str));
		kfree(str);
	}
	#endif

end:
	if (value)
		kfree(value);
	if (rc < 0)
		return rc;

	return st->verdict;
}

static int __init pft_state_target_init(void)
{
	int rc = 0;
	int i;
	struct pft_target_module state_target_module = {
		.list = {NULL, NULL},
		.name = "state",
//		.context_mask = 0,
		.target = &pft_state_target
	};

	printk(KERN_INFO PFWALL_PFX "state target module initializing\n");
	for (i = 0; i < DICT_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&current->dict_htable[i]);

	rc = pf_register_target(&state_target_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_target state failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_state_target_init);
