/* This is a match module that has a list of (vm_area_name:interface) and
(script_name:line_number) and matches if current packet matches any in the list*/

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

#ifdef PFWALL_MATCH_STR
typedef struct ts_node {
	struct hlist_node list;
	char* type; /* SELinux type */
	char* name; /* Process name */
	char* ips; /* For now, just a string - do we want ot make it into a hash table? */
	char* ttypes; /* For now, just a string */
}ts_node_t;

static DEFINE_MUTEX(node_lock);

#define TS_RDLOCK read_lock_irqsave(&ts_rwlock, flags)
#define TS_WRLOCK write_lock_irqsave(&ts_rwlock, flags)
#define TS_RDUNLOCK read_unlock_irqrestore(&ts_rwlock, flags)
#define TS_WRUNLOCK write_unlock_irqrestore(&ts_rwlock, flags)

static ts_node_t ts_list;

#define TS_HASH_BITS            8
#define TS_HTABLE_SIZE (1 << TS_HASH_BITS)

struct hlist_head ts_htable[TS_HTABLE_SIZE];
static DEFINE_RWLOCK(ts_rwlock);


/* SDBM hash - given a trusted subject, find its hash */
static unsigned long ts_hash(unsigned char *str)
{
	unsigned long hash = 0;
	int c;

	while ((c = *str++))
	hash = c + (hash << 6) + (hash << 16) - hash;

	return hash >> (32 - TS_HASH_BITS);
}

/* Lookup the trusted subject in the hash table */
int ts_find_subject(char *subject)
{
	ts_node_t *tmp;
        unsigned long flags;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = ts_hash(subject);

        TS_RDLOCK;
        hlist_for_each_entry(tmp, node, &ts_htable[index], list) {
		if(!strcmp(tmp->type, subject)) {
			/* Found! */
			TS_RDUNLOCK;
			return 0;
		}
        }
out:
         TS_RDUNLOCK;
         return 1;
}
EXPORT_SYMBOL(ts_find_subject);

/**
 *  * ts_load - Load a trusted subject configuration.
 *  * @data: binary subject data
 *  *
 *  * Load a new set of trusted subjects.
 *  * Format: type:name,vm_area_name:,ttypes,:,ips,
 *      */
static unsigned int ts_load(void **data, size_t length)
{
        ts_node_t *tmp;
	unsigned long flags;
	char *type;
	int i;
	struct hlist_node *node;
	int index;
	static int writing = 0;

        TS_WRLOCK;

	if (writing == 0) {
		printk(KERN_INFO PFWALL_PFX "Freeing trusted subjects list\n");
		/* Empty the list */
		for (i = 0; i < TS_HTABLE_SIZE; i++) {
			hlist_for_each_entry(tmp, node, &ts_htable[i], list) {
				hlist_del(&(tmp->list));
				kfree(tmp);
			}
		}
		printk(KERN_INFO PFWALL_PFX "Initializing trusted subjects list\n");

		/* Interface table */
		for (i = 0; i < TS_HTABLE_SIZE; i++)
			INIT_HLIST_HEAD(&ts_htable[i]);
		writing = 1;
	}


        /* Null Terminate */
        *(*(char **)data + length - 1) = '\0';

	/* Parse the lines into structures */
	while((type = strsep((char **)data,"\n")) != NULL) {
		if (!strcmp("end", type)) {
			writing = 0;
			continue;
		}
                tmp = (ts_node_t*) kmalloc(sizeof(ts_node_t), GFP_ATOMIC);
                if (tmp == NULL)
		{
                        printk(KERN_ALERT PFWALL_PFX "%s(): malloc failed\n", __FUNCTION__);
			TS_WRUNLOCK;
			return -ENOMEM;
                }
		/* Duplicate the token */
		tmp->type = kstrdup(type, GFP_ATOMIC);
		if (!tmp->type) {
			printk(KERN_ALERT PFWALL_PFX "tmp_node->type allocation failed!\n");
			TS_WRUNLOCK;
			return -ENOMEM;
		}
		/* Add the new ts structure */
		index = ts_hash(tmp->type);
		printk( KERN_ALERT "%s(): ts_hash[%d] = [%s]\n", __FUNCTION__, index, type);
		hlist_add_head(&(tmp->list), &(ts_htable[index]));
	}

      TS_WRUNLOCK;
      return length;
}


static ssize_t
ts_write(struct file *filp, const char __user *ubuf,
                   size_t cnt, loff_t *ppos)
{
         ssize_t length;
         void *data = NULL;

         mutex_lock(&node_lock);

         if (*ppos != 0) {
               /* No partial writes. */
                length = -EINVAL;
                 goto out;
           }

          if ((cnt > 64 * 1024 * 1024)
              || (data = vmalloc(cnt)) == NULL) {
                   length = -ENOMEM;
                   goto out;
           }

          length = -EFAULT;
          if (copy_from_user(data, ubuf, cnt) != 0)
                   goto out;

           length = ts_load(&data, cnt);
out:
           mutex_unlock(&node_lock);
           vfree(data);
           return length;
}

static ssize_t
ts_read(struct file *file, char __user *ubuf,
                       size_t cnt, loff_t *ppos)
{
      char *buf; /* Allocate a single page for the buf */
      int ret, len = 0;
      unsigned long flags;
      int i;
	struct hlist_node *node;

      ts_node_t *tmp;
//      mutex_lock(&node_lock);

      ret = -EFAULT;

     if (!(buf = (char*) get_zeroed_page(GFP_KERNEL))) {
                  ret = -ENOMEM;
                  goto out;
    }
    strcpy(buf, "See printk buffer\n");
    /* Copy the current trusted subject list into buf for printing */
    TS_RDLOCK;
	for (i = 0; i < TS_HTABLE_SIZE; i++) {
	        hlist_for_each_entry(tmp, node, &ts_htable[i], list) {
			printk(KERN_INFO "%d: [%s]\n", i, tmp->type);
		}
    }

    ret = simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
//    rd_out:
          TS_RDUNLOCK;
   out:
//          mutex_unlock(&node_lock);
         if (buf)
               free_page((unsigned long) buf);
         return ret;
}

static const struct file_operations ts_fops = {
       .write  = ts_write,
       .read   = ts_read,
};

static __init int ts_init(void)
{
	static struct dentry *ts_dentry; /* trusted_subjects */
	ts_dentry = debugfs_create_file("trusted_subjects", 0600,NULL,
					NULL, &ts_fops);

	if(!ts_dentry) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create trusted_subjects\n");
	}

	return 0;
}
fs_initcall(ts_init);

/* Utility functions */
/* Return type given context */
char* context_to_type(char* scontext)
{
	u32 scontext_len;
	char* colon = ":";
	char* start, * end, * type;
	int i;

	scontext_len = strlen(scontext);

	if (strlen(scontext) == 0) {
		return NULL;
	}

	/* Extract type from scontext string */
	type = kmalloc(scontext_len, GFP_ATOMIC);
	if (!type)
		printk(KERN_WARNING PFWALL_PFX "type NULL\n");
	memset(type, 0, scontext_len);
	start = scontext;
	for (i = 0; i < 2; i++)
	{
	      start = strpbrk(start, colon);
	      if (start == NULL)
	      {
		      /* Name doesn't have :, probably initial sid */
		      kfree(type);
		      return NULL;
	      }
	      start++;
	}
	end = strpbrk(start, colon);
	if (end == 0x0) {
		/* Policy without secrecy label */
		memcpy(type, start, strlen(start));
	} else {
		end--;
		memcpy(type, start, end - start + 1);
		type[end - start + 2] = 0;
	}
	return type;
}
#endif

#ifdef PFWALL_MATCH_REPR
typedef struct ts_node {
	struct hlist_node list;
	u32 sid_type; /* The SIDs corresponding to system_u:system_r and
			unconfined_u:unconfined_r */
	char* name; /* Process name */
	char* ips; /* For now, just a string - do we want ot make it into a hash table? */
	char* ttypes; /* For now, just a string */
}ts_node_t;

static DEFINE_MUTEX(node_lock);

#define TS_RDLOCK read_lock_irqsave(&ts_rwlock, flags)
#define TS_WRLOCK write_lock_irqsave(&ts_rwlock, flags)
#define TS_RDUNLOCK read_unlock_irqrestore(&ts_rwlock, flags)
#define TS_WRUNLOCK write_unlock_irqrestore(&ts_rwlock, flags)

static ts_node_t ts_list;

#define TS_HASH_BITS            8
#define TS_HTABLE_SIZE (1 << TS_HASH_BITS)

struct hlist_head ts_htable[TS_HTABLE_SIZE];
static DEFINE_RWLOCK(ts_rwlock);


static unsigned long ts_hash(u32 sid)
{
	return sid % (TS_HTABLE_SIZE);
}

/* Lookup the trusted subject in the hash table */
int ts_find_subject(u32 sid)
{
	ts_node_t *tmp;
        unsigned long flags;
	int index;
	struct hlist_node *node;

	/* Get the hash index for this subject */
	index = ts_hash(sid);

        TS_RDLOCK;
        hlist_for_each_entry(tmp, node, &ts_htable[index], list) {
		if(tmp->sid_type == sid) {
			/* Found! */
			TS_RDUNLOCK;
			return 0;
		}
        }
out:
         TS_RDUNLOCK;
         return 1;
}
EXPORT_SYMBOL(ts_find_subject);

/* TODO: Find out if the policy is MLS etc, and decide the string to send accordingly, and find users and roles in policy */
int type_to_sid(char *type, int *val, int which)
{
	char *full_str = NULL;
	int rc = 0;

	if (which == 0)
		full_str = kasprintf(GFP_KERNEL, "unconfined_u:unconfined_r:%s:s0", type);
	else if (which == 1)
		full_str = kasprintf(GFP_KERNEL, "system_u:system_r:%s:s0", type);

	rc = security_context_to_sid(full_str, strlen(full_str), val);
	if (rc < 0) {
		kfree(full_str);
		if (which == 0)
			full_str = kasprintf(GFP_KERNEL, "unconfined_u:object_r:%s:s0", type);
		else if (which == 1)
			full_str = kasprintf(GFP_KERNEL, "system_u:object_r:%s:s0", type);
		rc = security_context_to_sid(full_str, strlen(full_str), val);
		if (rc < 0) {
			goto end;
		}
	}
end:
	if (full_str)
		kfree(full_str);
	return rc;
}
EXPORT_SYMBOL(type_to_sid);

/**
 *  * ts_load - Load a trusted subject configuration.
 *  * @data: binary subject data
 *  *
 *  * Load a new set of trusted subjects.
 *  * Format: type:name,vm_area_name:,ttypes,:,ips,
 *      */
static unsigned int ts_load(void **data, size_t length)
{
        ts_node_t *tmp, *tmp2;
	unsigned long flags;
	char *type;
	int i;
	struct hlist_node *node;
	int index;
	int rc = 0;
	static int writing = 0;

        TS_WRLOCK;

	if (writing == 0) {
		printk(KERN_INFO PFWALL_PFX "Freeing trusted subjects list\n");
		/* Empty the list */
		for (i = 0; i < TS_HTABLE_SIZE; i++) {
			hlist_for_each_entry(tmp, node, &ts_htable[i], list) {
				hlist_del(&(tmp->list));
				kfree(tmp);
			}
		}
		printk(KERN_INFO PFWALL_PFX "Initializing trusted subjects list\n");

		/* Interface table */
		for (i = 0; i < TS_HTABLE_SIZE; i++)
			INIT_HLIST_HEAD(&ts_htable[i]);
		writing = 1;
	}

        /* Null Terminate */
        *(*(char **)data + length - 1) = '\0';

	/* Parse the lines into structures */
	while((type = strsep((char **)data,"\n")) != NULL) {
		if (!strcmp("end", type)) {
			writing = 0;
			continue;
		}
		/* Allocate two nodes, one for unconfined SID, another for
			system SID */
		/* TODO : Cleanup code */
                tmp = (ts_node_t*) kmalloc(sizeof(ts_node_t), GFP_ATOMIC);
                tmp2 = (ts_node_t*) kmalloc(sizeof(ts_node_t), GFP_ATOMIC);
                if (tmp == NULL || tmp2 == NULL) {
                        printk(KERN_ALERT PFWALL_PFX "%s(): malloc failed\n", __FUNCTION__);
			return -ENOMEM;
                }
		/* Convert the type to SID */
		rc = type_to_sid(type, &(tmp->sid_type), 0);
		if (rc < 0) {
			printk(KERN_ALERT PFWALL_PFX "context string to SID conversion failed for unconfined:%s with %d", type, rc);
		}
		rc = type_to_sid(type, &(tmp2->sid_type), 1);
		if (rc < 0) {
			printk(KERN_ALERT PFWALL_PFX "context string to SID conversion failed for system:%s with %d", type, rc);
		}

		/* Add the new ts structure */
		index = ts_hash(tmp->sid_type);
		printk( KERN_ALERT "%s(): ts_hash[%d] = [%d]\n", __FUNCTION__, index, tmp->sid_type);
		hlist_add_head(&(tmp->list), &(ts_htable[index]));

		index = ts_hash(tmp2->sid_type);
		printk( KERN_ALERT "%s(): ts_hash[%d] = [%d]\n", __FUNCTION__, index, tmp2->sid_type);
		hlist_add_head(&(tmp2->list), &(ts_htable[index]));
	}

      TS_WRUNLOCK;
      return length;
}

static ssize_t
ts_write(struct file *filp, const char __user *ubuf,
                   size_t cnt, loff_t *ppos)
{
         ssize_t length;
         void *data = NULL;

         mutex_lock(&node_lock);

         if (*ppos != 0) {
               /* No partial writes. */
                length = -EINVAL;
                 goto out;
           }

          if ((cnt > 64 * 1024 * 1024)
              || (data = vmalloc(cnt)) == NULL) {
                   length = -ENOMEM;
                   goto out;
           }

          length = -EFAULT;
          if (copy_from_user(data, ubuf, cnt) != 0)
                   goto out;

           length = ts_load(&data, cnt);
out:
           mutex_unlock(&node_lock);
           vfree(data);
           return length;
}

static ssize_t
ts_read(struct file *file, char __user *ubuf,
                       size_t cnt, loff_t *ppos)
{
      char *buf; /* Allocate a single page for the buf */
      int ret, len = 0;
      unsigned long flags;
      int i;
	struct hlist_node *node;

      ts_node_t *tmp;
//      mutex_lock(&node_lock);

      ret = -EFAULT;

     if (!(buf = (char*) get_zeroed_page(GFP_KERNEL))) {
                  ret = -ENOMEM;
                  goto out;
    }
    strcpy(buf, "See printk buffer\n");
    /* Copy the current trusted subject list into buf for printing */
    TS_RDLOCK;
	for (i = 0; i < TS_HTABLE_SIZE; i++) {
	        hlist_for_each_entry(tmp, node, &ts_htable[i], list) {
			printk(KERN_INFO "%d: [%d]\n", i, tmp->sid_type);
		}
    }

    ret = simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
//    rd_out:
          TS_RDUNLOCK;
   out:
//          mutex_unlock(&node_lock);
         if (buf)
               free_page((unsigned long) buf);
         return ret;
}

static const struct file_operations ts_fops = {
       .write  = ts_write,
       .read   = ts_read,
};

static __init int ts_init(void)
{
	static struct dentry *ts_dentry; /* trusted_subjects */
	ts_dentry = debugfs_create_file("trusted_subjects", 0600,NULL,
					NULL, &ts_fops);

	if(!ts_dentry) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create trusted_subjects\n");
	}

	return 0;
}
fs_initcall(ts_init);

/* Utility functions */
/* Return type given context */
char* context_to_type(char* scontext)
{
	u32 scontext_len;
	char* colon = ":";
	char* start, * end, * type;
	int i;

	scontext_len = strlen(scontext);

	if (strlen(scontext) == 0) {
		return NULL;
	}

	/* Extract type from scontext string */
	type = kmalloc(scontext_len, GFP_ATOMIC);
	if (!type)
		printk(KERN_WARNING PFWALL_PFX "type NULL\n");
	memset(type, 0, scontext_len);
	start = scontext;
	for (i = 0; i < 2; i++)
	{
	      start = strpbrk(start, colon);
	      if (start == NULL)
	      {
		      /* Name doesn't have :, probably initial sid */
		      kfree(type);
		      return NULL;
	      }
	      start++;
	}
	end = strpbrk(start, colon);
	if (end == 0x0) {
		/* Policy without secrecy label */
		memcpy(type, start, strlen(start));
	} else {
		end--;
		memcpy(type, start, end - start + 1);
		type[end - start + 2] = 0;
	}

	return type;
}
#endif

bool pft_string_match(struct pf_packet_context *p, void *match_specific_data)
{
	return 1;
}


static int __init pft_string_match_init(void)
{
	int rc = 0;
	struct pft_match_module string_match_module = {
		.list = {NULL, NULL},
		.name = "string",
//		.context_mask = PF_CONTEXT_DATA,
		.match = &pft_interface_list_match
	};

	printk(KERN_INFO PFWALL_PFX "string match module initializing\n");

	rc = pf_register_match(&string_match_module);

	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "pf_register_match string failed: %d\n", rc);
	}
	return rc;
}
module_init(pft_string_match_init);
