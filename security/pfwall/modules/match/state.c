
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

#define PF_STATE_STR_MAX 128
// struct hlist_head dict_htable[DICT_HTABLE_SIZE];

#define PF_VALUE_GIVEN 0
#define PF_VALUE_FROM_CONTEXT 1
struct pft_state_match
{
	char key[PF_STATE_STR_MAX];
	int value_origin; /* Whether the value is obtained
			   * from the packet or the rule */
	union {
		char value_str[PF_STATE_STR_MAX];
		int value_context;
	} test_value;

	int equal;
	int uninit; /* Is key uninitialized? */
};

/* SDBM hash - given a key, find its hash */
static unsigned long dict_hash(unsigned char *str)
{
	unsigned long hash = 0;
	int c;

	while ((c = *str++))
	hash = c + (hash << 6) + (hash << 16) - hash;

	return hash >> (32 - DICT_HASH_BITS);
}

/* Lookup the key in the hash table and return value */
char *pft_dict_get_value(char *key)
{
	dict_node_t *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = dict_hash(key);

        hlist_for_each_entry(tmp, node, &current->dict_htable[index], list) {
		if(!strcmp(tmp->key, key)) {
			/* Found! */
			return tmp->value;
		}
        }
        return NULL;
}
EXPORT_SYMBOL(pft_dict_get_value);

/* Lookup the key in the hash table and return (key, value) pair */
dict_node_t *pft_dict_get_entry(char *key)
{
	dict_node_t *tmp;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = dict_hash(key);

        hlist_for_each_entry(tmp, node, &current->dict_htable[index], list) {
		if(!strcmp(tmp->key, key)) {
			/* Found! */
			return tmp;
		}
        }

        return NULL;
}
EXPORT_SYMBOL(pft_dict_get_entry);

/* Remove key and its corresponding value from dictionary */
# if 0
void pft_dict_remove_key(char *key)
{
	dict_node_t *tmp;
        unsigned long flags;
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
#endif

/**
 *  * dict_load - Load a trusted subject configuration.
 *  * @data: binary subject data
 *  *
 *  * Load a new set of trusted subjects.
 *  * Format: type:name,vm_area_name:,ttypes,:,ips,
 *      */
# if 0
int pft_dict_set_value(char *key, char *value)
{
        dict_node_t *tmp;
	char *key, *value;
	struct hlist_node *node;
	int index;

	if ((tmp = pft_dict_get_entry(key)) != NULL) {
		/* Overwrite */
		strcpy(tmp->value, value);
	} else {
		strcpy(tmp->key, key);
		strcpy(tmp->value, value);

		index = dict_hash(tmp->key);
		printk( KERN_ALERT "%s(): dict_hash[%d] = [%s]\n", __FUNCTION__, index, key);
		hlist_add_head(&(tmp->list), &(current->dict_htable[index]));
	}

      return 1;
}
EXPORT_SYMBOL(pft_dict_set_value);

static ssize_t
pft_dict_read(struct file *file, char __user *ubuf,
                       size_t cnt, loff_t *ppos)
{
	char *buf; /* Allocate a single page for the buf */
	int ret;
	struct hlist_node *node;
	int i;
      dict_node_t *tmp;
//      mutex_lock(&node_lock);

      ret = -EFAULT;

     if (!(buf = (char*) get_zeroed_page(GFP_KERNEL))) {
                  ret = -ENOMEM;
                  goto out;
    }
    strcpy(buf, "See printk buffer\n");
    /* Copy the current trusted subject list into buf for printing */
	for (i = 0; i < DICT_HTABLE_SIZE; i++) {
	        hlist_for_each_entry(tmp, node, &current->dict_htable[i], list) {
			printk(KERN_INFO "%d: [%s]\n", i, tmp->key);
		}
    }

    ret = simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
//    rd_out:
   out:
//          mutex_unlock(&node_lock);
         if (buf)
               free_page((unsigned long) buf);
         return ret;
}
#endif

#if 0
extern struct rchan* wall_rchan;
#endif


bool pft_state_match(struct pf_packet_context *p, void *match_specific_data)
{
	struct pft_state_match *sm = (struct pft_state_match *)
			match_specific_data;
	char *value = pft_dict_get_value(sm->key);
	char *test_value = NULL;
	int ret = 0;

	test_value = kzalloc(PF_STATE_STR_MAX, GFP_ATOMIC);
	if (test_value == NULL) {
		printk(KERN_INFO PFWALL_PFX "test_value allocation failed\n");
		ret = -ENOMEM;
		goto end;
	}

	/* Is key uninitialized? */
	if (sm->uninit) {
		if (!value)
			ret = 1;
		else
			ret = 0;
		goto end;
	}

	if (sm->value_origin == PF_VALUE_GIVEN) {
		strcpy(test_value, sm->test_value.value_str);
	} else if (sm->value_origin == PF_VALUE_FROM_CONTEXT) {
		/* TODO: Other context, and separate filename and inode for resource */
		if (sm->test_value.value_context == PF_CONTEXT_FILENAME) {
			sprintf(test_value, "%lu", p->info.filename_inoden);
		} else {
			printk(KERN_INFO PFWALL_PFX "Unknown context for state module!\n");
		}
	}

	/* If not already existing, "0" is a matching value */
	if (!value) {
		if (!strcmp(test_value, "0"))
			ret = 1;
		else
			ret = 0;
		goto end;
	}
	if ((strcmp(value, test_value) && (!sm->equal)) ||
		(!strcmp(value, test_value) && (sm->equal))) {
		ret = 1;
	}

end:
	if (test_value)
		kfree(test_value);
	return ret;
}
		# if 0
		/* Hack for signals tracing */
		if (wall_rchan) {
			char *str;
			str = kasprintf(GFP_ATOMIC, "%d (%s): already blocked, signo tried: %d!\n", current->pid, current->comm, p->signo);
			relay_write(wall_rchan, str, strlen(str));
			kfree(str);
		}
		return 1;
		#endif


static int __init pft_state_match_init(void)
{
	int rc = 0;
	struct pft_match_module state_match_module = {
		.list = {NULL, NULL},
		.name = "state",
//		.context_mask = PF_CONTEXT_DATA,
		.match = &pft_state_match
	};

	printk(KERN_INFO PFWALL_PFX "state match module initializing\n");

	rc = pf_register_match(&state_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_match state failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_state_match_init);
