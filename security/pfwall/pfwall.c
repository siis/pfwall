#include <linux/stop_machine.h>
#include <linux/clocksource.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
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
#include <linux/lsm_audit.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/stacktrace.h>
#include <linux/module.h>
#include <asm/stacktrace.h>

#include <trace/events/sched.h>

#include <asm/ftrace.h>
#include <asm/setup.h>

#include "av_permissions.h"
#include "flask.h"
#include "trusted_subjects.h"

struct pft_table pft_filter_table = {
	.initialized = ATOMIC_INIT(0),
	.name = "filter",
	.jumpstack = NULL,
	.stackptr = NULL
};

struct pft_table pft_mangle_table = {
	.initialized = ATOMIC_INIT(0),
	.name = "mangle",
	.jumpstack = NULL,
	.stackptr = NULL
};


EXPORT_SYMBOL(pft_filter_table);
EXPORT_SYMBOL(pft_mangle_table);

DEFINE_RWLOCK(pf_table_lock);
EXPORT_SYMBOL(pf_table_lock);

int pfwall_enabled;
EXPORT_SYMBOL(pfwall_enabled);

int pf_log_daemon_pid = -1;
EXPORT_SYMBOL(pf_log_daemon_pid);

int pf_monitor_pid = -1;
EXPORT_SYMBOL(pf_monitor_pid);

int pfwall_skip_hook_enabled = 0;
EXPORT_SYMBOL(pfwall_skip_hook_enabled);

int pfwall_context_caching_enabled = 1;
EXPORT_SYMBOL(pfwall_context_caching_enabled);

int pfwall_lazy_context_evaluation_enabled = 1;
EXPORT_SYMBOL(pfwall_lazy_context_evaluation_enabled);

static struct pft_match_module pf_match_modules_list;
static DEFINE_RWLOCK(pf_match_modules_list_lock);

static struct pft_target_module pf_target_modules_list;
static DEFINE_RWLOCK(pf_target_modules_list_lock);

int (*pf_context_array[sizeof(unsigned int) * 8]) (struct pf_packet_context *);

EXPORT_SYMBOL(pf_context_array);

DEFINE_RWLOCK(pf_context_modules_array_lock);
EXPORT_SYMBOL(pf_context_modules_array_lock);

/* Performance counters */
PFW_PERF_INIT(pft_strcmp_binary_path);
PFW_PERF_INIT(pft_strcmp_vm_area);
PFW_PERF_INIT(pft_strcmp_process_label);
PFW_PERF_INIT(pft_strcmp_object_label);
PFW_PERF_INIT(pft_strcmp_interpreter_script);
PFW_PERF_INIT(pft_strcmp_interface);
PFW_PERF_INIT(pft_default_ctxt_and_match);
PFW_PERF_INIT(pft_match);
PFW_PERF_INIT(pft_target);

PFW_PERF_EXTERN_INIT(sys_stat64);
PFW_PERF_EXTERN_INIT(sys_open);
PFW_PERF_EXTERN_INIT(sys_close);
PFW_PERF_EXTERN_INIT(sys_read);
PFW_PERF_EXTERN_INIT(sys_write);
PFW_PERF_EXTERN_INIT(sys_getpid);
PFW_PERF_EXTERN_INIT(sys_execve);
PFW_PERF_EXTERN_INIT(sys_fork);

/* same across each invocation of pfwall */
unsigned long _current_trace = 0;
EXPORT_SYMBOL(_current_trace);

/* same across each system call */
atomic_t _syscall_ctr = ATOMIC_INIT(0);
EXPORT_SYMBOL(_syscall_ctr);

/* Performance counters file */
/*
 * Callback to create pft_performance file
 */

static struct dentry *create_pft_performance_file_callback(const char *filename,
                                              struct dentry *parent,
                                              int mode,
                                              struct rchan_buf *buf,
                                              int *is_global)
{
        return debugfs_create_file(filename, mode, parent, buf,
                                   &relay_file_operations);
}

/*
 * Callback to remove pft_performance file
 */

static int remove_pft_performance_file_callback(struct dentry* dentry)
{
	debugfs_remove(dentry);
	return 0;
}

/*
 * Callback when one subbuffer is full
 */

static int subbuf_pft_performance_start_callback(struct rchan_buf *buf, void *subbuf,
                                     void *prev_subbuf, size_t prev_padding)
{
	atomic_t* num_dropped;
	/* if (prev_subbuf)
		* ((size_t*) prev_subbuf) = prev_padding; */
        if (!relay_buf_full(buf))
                return 1;
	num_dropped = buf->chan->private_data;
	atomic_inc(num_dropped);
	if (atomic_read(num_dropped) % 5000 == 0)
		printk(KERN_INFO PFWALL_PFX "log: log full, num_dropped: %d\n", atomic_read(num_dropped));
        return 0;
}

/* Relay channel operations */

atomic_t num_dropped = ATOMIC_INIT(0);
static int subbuf_pft_performance_start_callback(struct rchan_buf *buf, void *subbuf, void *prev_subbuf, size_t prev_padding);
static int remove_pft_performance_file_callback(struct dentry* dentry);
static struct dentry *create_pft_performance_file_callback(const char *filename, struct dentry *parent, int mode, struct rchan_buf *buf, int *is_global);
static struct rchan_callbacks pft_performance_relay_callbacks =
{
	.subbuf_start		= subbuf_pft_performance_start_callback,
	.create_buf_file	= create_pft_performance_file_callback,
	.remove_buf_file	= remove_pft_performance_file_callback,
};
struct rchan* pft_performance_rchan;


/* Register a new context module */
int pf_register_context(unsigned int context_mask,
			int (*func) (struct pf_packet_context *p))
{
	int log = -1, rc = 0;
	/* TODO: Use this lock for readers */
	write_lock_irq(&pf_context_modules_array_lock);

	while (context_mask) { context_mask = context_mask >> 1; log++; }
	if (pf_context_array[log] != NULL) {
		rc = -EEXIST;
		goto unlock;
	}
	pf_context_array[log] = func;

unlock:
	write_unlock_irq(&pf_context_modules_array_lock);
	return rc;
}

/*
 * Register a new pft_match module
 * Need the pft_match module, and
 * the boolean mask of the context
 * that the match needs.
 * The pft_match_module is duplicated.
 */

int pf_register_match(struct pft_match_module *m_orig)
{
	int ret = 0;
	struct pft_match_module *tmp, *m = NULL;
	struct list_head *lht;

	/* TODO: See pf_register_target below */
	write_lock_irq(&pf_match_modules_list_lock);

	/* Check if list is initialized */
	if (pf_match_modules_list.list.next == NULL) {
		printk(KERN_INFO PFWALL_PFX "Initializing pf_match_modules_list\n");
		INIT_LIST_HEAD(&pf_match_modules_list.list);
	}

	list_for_each(lht, &pf_match_modules_list.list) {
		tmp = list_entry(lht, struct pft_match_module, list);
		if (!strcmp(tmp->name, m_orig->name)) {
			ret = -EEXIST;
			goto unlock;
		}
	}

	/* Insert into list */
	m = kmemdup(m_orig, sizeof(struct pft_match_module), GFP_ATOMIC);
	if (!m) {
		ret = -ENOMEM;
		goto unlock;
	}

	list_add(&(m->list), &(pf_match_modules_list.list));
	write_unlock_irq(&pf_match_modules_list_lock);
	return ret;
unlock:
	write_unlock_irq(&pf_match_modules_list_lock);
	if (m)
		kfree(m);
	return ret;
}

/*
 * Register a new pft_target module
 * Need the pft_target module, and
 * the boolean mask of the context
 * that the target needs.
 * The pft_target_module is duplicated.
 */

int pf_register_target(struct pft_target_module *t_orig)
{
	int ret = 0;
	struct pft_target_module *tmp, *t = NULL;
	struct list_head *lht;

	/* TODO: Locking, should the caller get the lock?
	 * Also, we need GFP_KERNEL below, for which we
	 * need a sleeping lock (sem?) */

	write_lock_irq(&pf_target_modules_list_lock);

	/* Check if list is initialized */
	if (pf_target_modules_list.list.next == NULL) {
		printk(KERN_INFO PFWALL_PFX "Initializing pf_target_modules_list\n");
		INIT_LIST_HEAD(&pf_target_modules_list.list);
	}

	list_for_each(lht, &pf_target_modules_list.list) {
		tmp = list_entry(lht, struct pft_target_module, list);
		if (!strcmp(tmp->name, t_orig->name)) {
			ret = -EEXIST;
			goto unlock;
		}
	}

	/* Insert into list */
	t = kmemdup(t_orig, sizeof(struct pft_target_module), GFP_ATOMIC);
	if (!t) {
		ret = -ENOMEM;
		goto unlock;
	}

	list_add(&(t->list), &(pf_target_modules_list.list));
	write_unlock_irq(&pf_target_modules_list_lock);
	return ret;
unlock:
	write_unlock_irq(&pf_target_modules_list_lock);
	if (t)
		kfree(t);
	return ret;
}

static struct pft_match_module *pf_get_match_module(char *name)
{
	struct pft_match_module *m;
	struct list_head *lht;
	read_lock(&pf_match_modules_list_lock);

	list_for_each(lht, &pf_match_modules_list.list) {
		m = list_entry(lht, struct pft_match_module, list);
		if (!strncmp(name, m->name, PFT_NAMELEN)) {
			read_unlock(&pf_match_modules_list_lock);
			return m;
		}
	}

	read_unlock(&pf_match_modules_list_lock);
	return ERR_PTR(-ENOENT);
}

static struct pft_target_module *pf_get_target_module(char *name)
{
	struct pft_target_module *m;
	struct list_head *lht;
	read_lock(&pf_target_modules_list_lock);

	list_for_each(lht, &pf_target_modules_list.list) {
		m = list_entry(lht, struct pft_target_module, list);
		if (!strncmp(name, m->name, PFT_NAMELEN)) {
			read_unlock(&pf_target_modules_list_lock);
			return m;
		}
	}

	read_unlock(&pf_target_modules_list_lock);
	return ERR_PTR(-ENOENT);
}

int pft_get_chain_offset(struct pft_table *tbl, char *c_name)
{
	int i;
	for (i = 0; i < tbl->num_chains; i++) {
		if (!strcmp(tbl->pft_chains[i].name, c_name))
			return tbl->pft_chains[i].chain_offset;
	}
	return -ENOENT;
}

static int pf_translate_matches(struct pft_entry *e)
{
	struct pft_match *m;
	struct pft_match_module *mm;
	int ret = 0;

	pf_foreach_match(m, e) {
		mm = pf_get_match_module(m->name);
		if (IS_ERR(mm)) {
			ret = PTR_ERR(mm);
			goto end;
		}

		m->match = mm->match;
		/* Let userspace specify the context */
		// m->context_mask = mm->context_mask;
	}

end:
	return ret;
}

/* The target name might either indicate a chain, or a target module */
static int pf_translate_target(struct pft_entry *e, struct pft_table *tbl)
{
	struct pft_target *t;
	struct pft_target_module *tm;
	int ret = 0;
	int offset = 0;

	t = (struct pft_target *) (e->beg_mat_tar + e->target_offset);
	tm = pf_get_target_module(t->name);
	if (IS_ERR(tm)) {
		ret = PTR_ERR(tm);
		if (ret == -ENOENT) {
			/* Might be jump to a chain */
			ret = 0; /* Reset error */
			offset = pft_get_chain_offset(tbl, t->name);
			if (offset < 0) {
				ret = offset;
				printk(KERN_INFO PFWALL_PFX
				"Critical: No chain or target matches: %s",
					t->name);
				goto end;
			}
			/* TODO: next_offset patch for hashing traversal */
			e->jump_offset = offset -
				(e->beg_mat_tar - tbl->table_base);
		}
	} else { /* No error */
		t->target = tm->target;
		/* Let userspace specify the context */
		// t->context_mask = tm->context_mask;
	}

end:
	return ret;
}

static int pf_translate_inode(struct pft_entry *e)
{
	#ifdef PFWALL_MATCH_REPR
	struct path bin_p;
	int ret = 0;

	if (strlen(e->def.binary_path) > 0) {
		/* Get inode given path and store that in the union */
		ret = kern_path(e->def.binary_path, LOOKUP_FOLLOW, &bin_p);
		if (ret < 0) {
			printk(KERN_INFO PFWALL_PFX
				"Path lookup translation failed for binary path: %s: %d\n", e->def.binary_path, ret);
			return ret;
		}
		e->def.binary_inoden = bin_p.dentry->d_inode->i_ino;
	} else {
		e->def.binary_inoden = 0;
	}

	if (strlen(e->def.vm_area_name) > 0) {
		ret = kern_path(e->def.vm_area_name, LOOKUP_FOLLOW, &bin_p);
		if (ret < 0) {
			printk(KERN_INFO PFWALL_PFX
				"Path lookup translation failed for vm area file\n");
			return ret;
		}
		e->def.vm_area_inoden = bin_p.dentry->d_inode->i_ino;
	} else {
		e->def.vm_area_inoden = 0;
	}

	if (strlen(e->def.script_path) > 0) {
		ret = kern_path(e->def.script_path, LOOKUP_FOLLOW, &bin_p);
		if (ret < 0) {
			printk(KERN_INFO PFWALL_PFX
				"Path lookup translation failed for script file\n");
			return ret;
		}
		e->def.script_inoden = bin_p.dentry->d_inode->i_ino;
	} else {
		e->def.script_inoden = 0;
	}
//	path_put(&bin_p);

	return ret;
	#endif
	#ifdef PFWALL_MATCH_STR
	return 0;
	#endif
}

static int pf_translate_sid(struct pft_entry *e)
{
	#ifdef PFWALL_MATCH_REPR
	int ret = 0;

	if (strlen(e->def.process_label) == 0)
		e->def.ssid[0] = PFWALL_SID_DONT_CARE;
	else if (!strcmp(e->def.process_label, "SYSHIGH"))
		e->def.ssid[0] = PFWALL_SID_SYSHIGH;
	else if (!strcmp(e->def.process_label, "SYSLOW"))
		e->def.ssid[0] = PFWALL_SID_SYSLOW;
	else {
		ret = security_context_to_sid(e->def.process_label,
			strlen(e->def.process_label), &(e->def.ssid[0]));
		if (ret < 0) {
			printk(KERN_INFO PFWALL_PFX "failed label to SID conversion: "
					"%s\n", e->def.process_label);
			goto out;
		}
		// ret = type_to_sid(e->def.process_label, &(e->def.ssid[0]), 0);
		// ret = type_to_sid(e->def.process_label, &(e->def.ssid[1]), 1);
	}

	if (strlen(e->def.object_label) == 0)
		e->def.tsid[0] = PFWALL_SID_DONT_CARE;
	else if (!strcmp(e->def.object_label, "SYSHIGH"))
		e->def.tsid[0] = PFWALL_SID_SYSHIGH;
	else if (!strcmp(e->def.object_label, "SYSLOW"))
		e->def.tsid[0] = PFWALL_SID_SYSLOW;
	else {
		ret = security_context_to_sid(e->def.object_label,
			strlen(e->def.object_label), &(e->def.tsid[0]));
		if (ret < 0) {
			printk(KERN_INFO PFWALL_PFX "failed label to SID conversion: "
					"%s\n", e->def.object_label);
			goto out;
		}
		// ret = type_to_sid(e->def.object_label, &(e->def.tsid[0]), 0);
		// ret = type_to_sid(e->def.object_label, &(e->def.tsid[1]), 1);
	}
out:
	return ret;
	#endif
	#ifdef PFWALL_MATCH_STR
	return 0;
	#endif
}

static int pf_translate_chain(struct pft_table *t, struct pft_entry *chain_start)
{
	int ret = 0, break_l = 0;
	struct pft_entry *e, *e_lookahead = NULL;
	e = (struct pft_entry *) chain_start;
	do {
		if (e->next_offset == 0)
			break_l = 1;
		else
			e_lookahead = pf_getnext_entry(e);
		ret = pf_translate_matches(e);
		if (ret < 0)
			goto end;
		ret = pf_translate_target(e, t);
		if (ret < 0)
			goto end;
		#ifdef PFWALL_MATCH_REPR
		ret = pf_translate_inode(e);
		if (ret < 0)
			goto end;
		ret = pf_translate_sid(e);
		if (ret < 0)
			goto end;
		#endif
		e = e_lookahead;
	} while (!break_l);
end:
	return ret;
}

/* Look up match and target modules and replace functions
   - caller must hold table lock */

static int pf_translate_table(struct pft_table *t)
{
	int ret = 0;
	int i;
#ifdef SEQUENTIAL_TRAVERSAL
	/* Translate default chains */
	for (i = 0; i < PF_NR_HOOKS; i++) {
		ret = pf_translate_chain(t,
			pf_get_ith_default_chain(t, i));
		if (ret < 0)
			goto end;
	}

	/*
	ret = pf_translate_chain(t, (struct pft_entry *) (
			t->table_base + t->hook_entries[PF_HOOK_INPUT]));
	ret = pf_translate_chain(t, (struct pft_entry *) (
			t->table_base + t->hook_entries[PF_HOOK_OUTPUT]));
	ret = pf_translate_chain(t, (struct pft_entry *) (
			t->table_base + t->hook_entries[PF_HOOK_READ]));
	ret = pf_translate_chain(t, (struct pft_entry *) (
			t->table_base + t->hook_entries[PF_HOOK_CREATE]));
	*/

	/* Translate user-defined chains */
	for (i = 0; i < t->num_chains; i++) {
		ret = pf_translate_chain(t,
			pf_get_ith_user_chain(t, i));
		if (ret < 0)
			goto end;
	}
#endif

#ifdef HASHING_TRAVERSAL
	for (i = 0; i < PF_HTABLE_SIZE; i++) {
		ret = pf_translate_chain(t, t->input_chain[i]);
		if (ret < 0)
			goto end;
	}

	for (i = 0; i < PF_HTABLE_SIZE; i++) {
		ret = pf_translate_chain(t, t->output_chain[i]);
		if (ret < 0)
			goto end;
	}
#endif
end:
	return ret;
}

/* Default modules */
int pft_accept_target(struct pf_packet_context *p, void *target_specific_data)
{
	return PF_ACCEPT;
}

int pft_drop_target(struct pf_packet_context *p, void *target_specific_data)
{
	return PF_DROP;
}

int pft_continue_target(struct pf_packet_context *p, void *target_specific_data)
{
	return PF_CONTINUE;
}

int pft_return_target(struct pf_packet_context *p, void *target_specific_data)
{
	return PF_RETURN;
}

static inline int log(unsigned int num)
{
	int l = 0;
	while (num) {
		l++;
		num = num >> 1;
	}
	return l - 1;
}


int pft_default_ctxt_and_match(struct pf_packet_context *p, void *match_specific_data)
{
	struct pft_default_matches *def = (struct pft_default_matches *) match_specific_data;
	int ret;

	if (!pfwall_lazy_context_evaluation_enabled) {
		/* Calculate all context beforehand */
		if (!(p->context & PF_CONTEXT_INTERFACE)) {
			ret = pf_context_array[log(PF_CONTEXT_INTERFACE)](p);
			if (ret < 0) {
				/* Error gathering interface, return packet not matched */
				return 0;
			}
		}
		#ifdef PFWALL_MATCH_STR
		if (!(p->context & PF_CONTEXT_BINARY_PATH)) {
			pf_context_array[log(PF_CONTEXT_BINARY_PATH)](p);
		}
		#endif
		#ifdef PFWALL_MATCH_REPR
		if (!(p->context & PF_CONTEXT_BINARY_PATH_INODE)) {
			pf_context_array[log(PF_CONTEXT_BINARY_PATH_INODE)](p);
		}
		#endif
	}
//	PFW_PERF_EXTERN_INIT(pft_strcmp);

	/* TODO: Totally lazy matching; don't match anything unless needed */
	/* This function will go away then */
	/* For now, manually validate the check using the hook */

	#if 0
	#ifdef PFWALL_MATCH_STR
	if (!(p->context & PF_CONTEXT_TYPE)) {
	#endif
	#ifdef PFWALL_MATCH_REPR
	if (!(p->context & PF_CONTEXT_TYPE_SID)) {
	#endif
		/* During syscall entry hook, or
		 * if these details are unavailable yet */
		/* TODO: Details of binary path and
		 * userspace interface are available at
		 * any hook. E.g., syscall hook should
		 * be able to use this context. So, have
		 * as separate context module */
		return 1;
	}
	#endif

	PFW_PERF_START(pft_strcmp_binary_path);
	/* Match binary path */
	#ifdef PFWALL_MATCH_STR
	if (!(p->context & PF_CONTEXT_BINARY_PATH)) {
		pf_context_array[log(PF_CONTEXT_BINARY_PATH)](p);
	}
	if (!(!strcmp(def->binary_path, "") ||
		!strcmp(def->binary_path, p->info.binary_path)))

	#endif
	#ifdef PFWALL_MATCH_REPR
	if (!(p->context & PF_CONTEXT_BINARY_PATH_INODE)) {
		pf_context_array[log(PF_CONTEXT_BINARY_PATH_INODE)](p);
	}
	if (!(def->binary_inoden == 0 || def->binary_inoden == p->info.binary_inoden))
	#endif
		return 0;
	PFW_PERF_END(pft_strcmp_binary_path);
	/* VM area name will be matched along with the stack trace */

	if (p->hook == PF_HOOK_INPUT || p->hook == PF_HOOK_OUTPUT) {
		#ifdef PFWALL_MATCH_REPR
		/* Match source and object SID */
		if (!(def->ssid[0] == PFWALL_SID_DONT_CARE /* Don't care */ ||
			def->ssid[0] == p->info.ssid || def->ssid[1] == p->info.ssid ||
			(def->ssid[0] == PFWALL_SID_SYSHIGH && !ts_find_subject(p->info.ssid)) ||
			(def->ssid[0] == PFWALL_SID_SYSLOW  && ts_find_subject(p->info.ssid))
		))
			return 0;

		if (!(def->tsid[0] == PFWALL_SID_DONT_CARE /* Don't care */ ||
			def->tsid[0] == p->info.tsid || def->tsid[1] == p->info.tsid ||
			(def->tsid[0] == PFWALL_SID_SYSHIGH && !ts_find_subject(p->info.tsid)) ||
			(def->tsid[0] == PFWALL_SID_SYSLOW  && ts_find_subject(p->info.tsid))
		))
			return 0;

		#endif
		#ifdef PFWALL_MATCH_STR
		/* Match source and object label */
		PFW_PERF_START(pft_strcmp_process_label);
		if (def->process_label)
			if ( !(
				(!strcmp(def->process_label, "")) ||
				(!strcmp(def->process_label, p->info.scontext)) ||
				(!strcmp("SYSHIGH", def->process_label) && (!ts_find_subject(p->info.scontext))) ||
				(!strcmp("SYSLOW", def->process_label) && (ts_find_subject(p->info.scontext)))
			     )
			   ) {
				return 0;
		}
		PFW_PERF_END(pft_strcmp_process_label);

		PFW_PERF_START(pft_strcmp_object_label);
		if (def->object_label)
			if (!(
				(!strcmp(def->object_label, "")) ||
				(!strcmp(def->object_label, p->info.tcontext)) ||
				(!strcmp("SYSHIGH", def->object_label) && (!ts_find_subject(p->info.tcontext))) ||
				(!strcmp("SYSLOW", def->object_label) && (ts_find_subject(p->info.tcontext)))
			     )
			   ) {
				return 0;
		}
		PFW_PERF_END(pft_strcmp_object_label);
		#endif

		/* Match tclass */
		if (!(def->tclass == 0 || p->info.tclass == def->tclass))
			return 0;

		/* Match requested */
		if (!((def->requested == 0) || ((p->info.requested & def->requested) == def->requested)))
			return 0;
	}

	/* Now, match interface - either script, or interface */
	/* Match interpreter context */

	PFW_PERF_START(pft_strcmp_interpreter_script);
	#ifdef PFWALL_MATCH_STR
	if (strcmp(def->script_path, "")) {
	#endif
	#ifdef PFWALL_MATCH_REPR
	if (def->script_inoden != 0) {
	#endif
		int i = 0;

#ifdef SEQUENTIAL_TRAVERSAL /* For hashing traversal, the context is
				already present */

		/* We have to get the context of the interface */
		if (!(p->context & PF_CONTEXT_INTERFACE)) {
			ret = pf_context_array[log(PF_CONTEXT_INTERFACE)](p);
			if (ret < 0) {
				/* Error gathering interface, return packet not matched */
				return 0;
			}
		}

#endif
		while (i < p->user_stack.int_trace.nr_entries) {
			if (!strcmp(def->script_path, p->user_stack.int_trace.int_filename[i])) {
			/* TODO: no reliable way of resolving script filename into inode? */
			#if 0
			#ifdef PFWALL_MATCH_REPR
			if (def->script_inoden == p->user_stack.int_trace.[i]) {
			#endif
			#endif
				if ((def->script_line_number == 0) || (def->script_line_number == p->user_stack.int_trace.entries[i]))
					return 1;
			}
			i++;
		}
		/* Did not match specific script */
		PFW_PERF_END(pft_strcmp_interpreter_script);
		return 0;
	}
	PFW_PERF_END(pft_strcmp_interpreter_script);

	PFW_PERF_START(pft_strcmp_interface);
	/* Match interface */
	if (def->interface != 0x0) {
		int i = 0;

#ifdef SEQUENTIAL_TRAVERSAL /* For hashing traversal, the context is
				already present */

		/* We have to get the context of the interface */
		if (!(p->context & PF_CONTEXT_INTERFACE)) {
			ret = pf_context_array[log(PF_CONTEXT_INTERFACE)](p);
			if (ret < 0) {
				/* Error gathering interface, return packet not matched */
				return 0;
			}
		}

#endif
		#ifdef PFWALL_MATCH_STR
		if (!strcmp(def->vm_area_name, "")) {
		#endif
		#ifdef PFWALL_MATCH_REPR
		if (def->vm_area_inoden == 0) {
		#endif
			printk(KERN_INFO PFWALL_PFX "Rule with interface but without VM area name for interface: %lx", def->interface);
			return 0;
		}

		#ifdef PFWALL_MATCH_STR
		if (strcmp(def->vm_area_name, "")) {
		#endif
		#ifdef PFWALL_MATCH_REPR
		if (def->vm_area_inoden != 0) {
		#endif
			/* There is a vm area name that is different
			 * from the binary. We need to match that */
			/* Backtrack until the VM area name is the
			 * one we are looking for */
			while (i < MAX_NUM_FRAMES && p->user_stack.trace.entries[i] && p->user_stack.trace.entries[i] != 0xFFFFFFFF) {
				#ifdef PFWALL_MATCH_STR
				if (!strcmp(p->vm_area_strings[i], "")) {
				#endif
				#ifdef PFWALL_MATCH_REPR
				if (p->user_stack.trace.vma_inoden[i] == 0) {
				#endif
					return 0;
				}
				#ifdef PFWALL_MATCH_STR
				PFW_PERF_START(pft_strcmp_vm_area);
				if (!strcmp(def->vm_area_name, p->vm_area_strings[i])) {
				PFW_PERF_END(pft_strcmp_vm_area);
				#endif
				#ifdef PFWALL_MATCH_REPR
				if (def->vm_area_inoden == p->user_stack.trace.vma_inoden[i]) {
				#endif
					if (def->interface == (p->user_stack.trace.entries[i] - p->user_stack.trace.vma_start[i])) {
					PFW_PERF_END(pft_strcmp_interface);
						return 1;
					}
				}
				i++;
			}
		}
		PFW_PERF_END(pft_strcmp_interface);
		/* Did not match specific interface */
		return 0;
	}
	PFW_PERF_END(pft_strcmp_interface);

	/* Matched everything that was specified */
	return 1;
}

/* END Default modules */

int pft_register_default_modules(void)
{
	/* Default Target modules */
	struct pft_target_module accept_target_module = {
		.list = {NULL, NULL},
		.name = "accept",
		.target = &pft_accept_target
	};

	struct pft_target_module drop_target_module = {
		.list = {NULL, NULL},
		.name = "drop",
		.target = &pft_drop_target
	};

	struct pft_target_module continue_target_module = {
		.list = {NULL, NULL},
		.name = "continue",
		.target = &pft_continue_target
	};

	struct pft_target_module return_target_module = {
		.list = {NULL, NULL},
		.name = "return",
		.target = &pft_return_target
	};

	pf_register_target(&accept_target_module);
	pf_register_target(&drop_target_module);
	pf_register_target(&continue_target_module);
	pf_register_target(&return_target_module);

	/* TODO: We are calling pft_interface_context manually, so this is of no
	use. Instead, register data and syscall modules */
	pf_register_context(PF_CONTEXT_FILENAME, &pft_auditdata_context);
	pf_register_context(PF_CONTEXT_TYPE, &pft_type_context);
	pf_register_context(PF_CONTEXT_BINARY_PATH, &pft_binary_path_context);
	pf_register_context(PF_CONTEXT_BINARY_PATH_INODE, &pft_binary_path_inode_context);

	return 0;
}

void pft_array_map_insert(struct pft_array_map *m, unsigned long interface, int index)
{
	struct pft_array_map *n = (struct pft_array_map *) kmalloc(sizeof(struct pft_array_map), GFP_ATOMIC);
	n->interface = interface;
	n->index = index;

	if ((m)->list.next == NULL) {
		INIT_LIST_HEAD(&((m)->list));
	}
	list_add_tail(&(n->list), &((m)->list));
}

int pft_array_map_get(struct pft_array_map m, unsigned long interface)
{
	/* TODO: Clean up this traversal -- why is it going circularly forever? */
	struct pft_array_map *t;
	unsigned long first = -1;
	if (m.list.next == NULL)
		return -1;
	list_for_each_entry(t, &m.list, list) {
		if (first == -1)
			first = t->interface;
		else if (t->interface == first) /* Break loop */
			return -1;
		if(t->interface == interface)
			return t->index;
	}
	return -1;
}

#ifdef HASHING_TRAVERSAL
static unsigned long pft_hash(unsigned long interface)
{
	return hash_64(interface, PF_HASH_BITS) + 1;
}
#endif

void pft_append(struct pft_entry *a, struct pft_entry **chain, int index)
{
	struct pft_entry *e, *prev_e;
	struct pft_entry *null = kzalloc(sizeof(struct pft_entry), GFP_ATOMIC);
	int size = 0;
	if (!null) {
		printk(KERN_INFO PFWALL_PFX "null entry allocation failed\n");
		return;
	}

	/* NOTE: At the end of the chain is a "NULL" pft_entry, with all
	   fields zero */
	/* Calculate the size of the existing chain */
	pf_foreach_entry(e,(chain)[index]) {
		size += (sizeof(struct pft_entry) + e->next_offset);
	}
	size += sizeof(struct pft_entry); /* NULL entry */
	/* Add and realloc to new size */
	(chain)[index] = krealloc((chain)[index], size + sizeof(struct pft_entry) + a->next_offset, GFP_KERNEL);

	/* Traverse to the last element before the NULL, to insert */
	prev_e = (chain)[index];
	pf_foreach_entry(e,(chain)[index]) {
		size += (sizeof(struct pft_entry) + e->next_offset);
		prev_e = e;
	}

	/* Insert new rule at the end */
	if (prev_e->id == 0) /* NULL chain */ {
		memcpy(prev_e, a, sizeof(struct pft_entry) + a->next_offset);
		/* Insert NULL pft_entry after the newly inserted rule */
		memcpy(prev_e->beg_mat_tar + prev_e->next_offset, null, sizeof(struct pft_entry));
	} else {
		memcpy(prev_e->beg_mat_tar + prev_e->next_offset, a, sizeof(struct pft_entry) + a->next_offset);
		/* Insert NULL pft_entry after the newly inserted rule */
		memcpy(prev_e->beg_mat_tar + prev_e->next_offset + sizeof(struct pft_entry) + a->next_offset, null, sizeof(struct pft_entry));
	}

	kfree(null);
}

#if 0
/* Returns the new size of the array */
int pft_attach_rule(struct pft_entry *e, struct pft_entry ***chain, struct pft_array_map *m, int size)
{
	/* Get the index in the array that this interface should be in */
	int i;
	unsigned long interface = e->def.interface;

	if (e->def.interface == 0x0) {
		/* This belongs to "general" chain */
		pft_append(e, chain, 0);
		return size;
	}

	/* The first element in the array is for the "general" chain */
	for (i = 1; i < size; i++) {
		if (((*chain)[i])->def.interface == interface) {
			break; /* Insert into this chain */
		}
	}
	if (i == size) /* Array has to be extended */ {
		*chain = (struct pft_entry **) krealloc((*chain), (size + 1) * sizeof (struct pft_entry *), GFP_KERNEL);
		/* Allocate a zeroed element as the first one */
		(*chain)[size] = (struct pft_entry *) kzalloc(sizeof(struct pft_entry), GFP_KERNEL);
		pft_append(e, chain, size);
		pft_array_map_insert(m, e->def.interface, size);
	} else {
		/* Insert into same "chain" */
		pft_append(e, chain, i);
		return size;
	}

	return size + 1;
}
#endif

static int pf_allocate_jumpstack(struct pft_table *t)
{
	unsigned int cpu;
	/* De-allocate already existing */

	if (t->stackptr)
		free_percpu(t->stackptr);
	if (t->jumpstack) {
		for_each_possible_cpu(cpu) {
			if (t->jumpstack[cpu])
				vfree(t->jumpstack[cpu]);
		}
		kfree(t->jumpstack);
	}

	/* Allocate new */
	t->stackptr = alloc_percpu(unsigned int);
	if (t->stackptr == NULL)
		return -ENOMEM;

	t->jumpstack = vmalloc(nr_cpu_ids * sizeof(void **));
	for_each_possible_cpu(cpu) {
		t->jumpstack[cpu] = vmalloc_node(t->num_chains + 4,
			cpu_to_node(cpu));
		if (t->jumpstack[cpu] == NULL)
			return -ENOMEM;
	}
	return 0;
}

static ssize_t
pftable_write(struct file *filp, const char __user *ubuf,
                   size_t cnt, loff_t *ppos)
{
	/* Used to store incoming writes in chunks of page size
	 * until they end */
	static int size = 0;
	static int done = 0;

	/* Copy user buffer into pft_entries */
	char* data = NULL;
	static struct pft_table *to_replace;

	static int already_init;

	int err = 0;

	printk(KERN_INFO PFWALL_PFX "received: %d\n", cnt);

        if (0 // (cnt > 64 * 1024 * 1024)
            || (data = vmalloc(cnt)) == NULL) {
		err = -ENOMEM;
                 goto out;
         }

        if (copy_from_user(data, ubuf, cnt) != 0) {
		cnt = 0;
		err = -ENOMEM;
		goto out;
	}


	if (size == 0) {
		/* Starting new input */
		/* TODO: We assume that the first write gives at least
		 * sizeof(struct pft_table) bytes */
		struct pft_table *new_tbl = ((struct pft_table *) data);

		size = new_tbl->size;
		if (!strcmp(new_tbl->name, "filter")) {
			to_replace = &pft_filter_table;
		} else if (!strcmp(new_tbl->name, "mangle")) {
			to_replace = &pft_mangle_table;
		} else {
			printk(KERN_INFO PFWALL_PFX
				"Invalid table name: %s\n", to_replace->name);
			return -EINVAL;
		}

		already_init = atomic_read(&to_replace->initialized);
		atomic_set(&to_replace->initialized, 0);

		/* Free existing table chain, if any */
		if (already_init) {
			vfree(to_replace->table_base);
		}
		/* Copy the new table */
		memcpy(to_replace, new_tbl, sizeof(struct pft_table));

		/* Allocate table chain */
		to_replace->table_base = vmalloc(size);
		if (to_replace->table_base == NULL) {
			printk(KERN_ALERT PFWALL_PFX "Failed to allocate table chain\n");
			err = -ENOMEM;
			goto out;
		}

		/* Fill in whatever data we have into chains */
		memcpy(to_replace->table_base,
			((char *) data + sizeof(struct pft_table)),
			cnt - sizeof(struct pft_table));
		done += (cnt - sizeof(struct pft_table));
	} else if (done < size) {
		/* Continuing with input */
		memcpy(to_replace->table_base + done, data, cnt);
		done += cnt;
	}

	if (done == size) {
		/* Done with input */

		/* Allocate jumpstack */
		err = pf_allocate_jumpstack(to_replace);
		if (err < 0)
			goto out;
		err = pf_translate_table(to_replace);
		if (err < 0)
			goto out;
		done = size = 0;

		/* Unlock the table for access by the firewall */
		atomic_set(&to_replace->initialized, 1);
	}
out:
	vfree(data);
//	write_unlock_irqrestore(&pf_table_lock, flags);
	if (err < 0)
		return err;
	return cnt;
}

# if 0
#ifdef HASHING_TRAVERSAL
		/* Initialize all array entries to NULL entry */
		for (i = 0; i < PF_HTABLE_SIZE; i++) {
			if (already_init) {
				kfree(to_replace->output_chain[i]);
				kfree(to_replace->input_chain[i]);
			}
			to_replace->input_chain[i] = (struct pft_entry *) kzalloc(sizeof(struct pft_entry), GFP_KERNEL);
			to_replace->output_chain[i] = (struct pft_entry *) kzalloc(sizeof(struct pft_entry), GFP_KERNEL);
		}

		/* Traverse each rule in input and output and put them in
		   appropriate array positions */

		/* TODO: do we want to clean up this traversal, and not
			include nr_entries at all? But use the
			"NULL" entry?
		*/
		pf_foreach_entry(e, &buf[pft_r.input_chain_offset + sizeof(struct pft_replace)]) {
		if (input_chain_nr_entries == 0)
			break;
		if (e->def.interface == 0 && !strcmp(e->def.script_path, "")) {
			/* Attach to index 0, general chain */
			pft_append(e, to_replace->input_chain, 0);
			printk(KERN_INFO PFWALL_PFX "Rule %d --> input index %d\n", e->id, 0);
		} else if (e->def.interface) {
			index = pft_hash(e->def.interface);
			pft_append(e, to_replace->input_chain, index);
			printk(KERN_INFO PFWALL_PFX "Rule %d --> input index %d\n", e->id, index);
		} else {
			index = pft_hash(pfwall_hash(e->def.script_path));
			pft_append(e, to_replace->input_chain, index);
			printk(KERN_INFO PFWALL_PFX "Rule %d --> input index %d\n", e->id, index);
		}
		input_chain_nr_entries--;
		if (input_chain_nr_entries == 0)
			break;
//		if ((e->beg_mat_tar + e->next_offset) >= &buf[sizeof(struct pft_replace)] + input_chain_size)
//			break;
		}

		pf_foreach_entry(e, &buf[pft_r.output_chain_offset + sizeof(struct pft_replace) + output_chain_size]) {
//		if (e >= &buf[sizeof(struct pft_replace)] + input_chain_size + output_chain_size)
//			break;
		if (output_chain_nr_entries == 0)
			break;
		if (e->def.interface == 0 && !strcmp(e->def.script_path, "")) {
			/* Attach to index 0, general chain */
			pft_append(e, to_replace->input_chain, 0);
			printk(KERN_INFO PFWALL_PFX "Rule %d --> input index %d\n", e->id, 0);
		} else if (e->def.interface) {
			index = pft_hash(e->def.interface);
			pft_append(e, to_replace->input_chain, index);
			printk(KERN_INFO PFWALL_PFX "Rule %d --> input index %d\n", e->id, index);
		} else {
			index = pft_hash(pfwall_hash(e->def.script_path));
			pft_append(e, to_replace->input_chain, index);
			printk(KERN_INFO PFWALL_PFX "Rule %d --> input index %d\n", e->id, index);
		}
		output_chain_nr_entries--;
		if (output_chain_nr_entries == 0)
			break;
//		if ((e->beg_mat_tar + e->next_offset) >= &buf[sizeof(struct pft_replace)] + input_chain_size + output_chain_size)
//			break;
		}

# endif
#endif

static ssize_t
pftable_read(struct file *file, char __user *ubuf,
                       size_t cnt, loff_t *ppos)
{
	char* buf = kasprintf(GFP_ATOMIC, "See printk buffer\n");
	/*
	int i;
	printk(KERN_INFO "INPUT CHAIN\n");
	for (i = 0; i < pft_filter_table->nr_input_chain_entries; i++)
	{
		struct pft_entry* e = (struct pft_entry*) &(pft_filter_table->input_chain_entries[i]);
		printk(KERN_INFO "[%lu, %s, %s, %s, %s, %u, %u, %d, %d]\n", e->interface, e->binary_path, e->vm_area_name, e->process_label, e->object_label, e->tclass, e->requested, e->known, e->verdict);
	}
	printk(KERN_INFO "OUTPUT CHAIN\n");
	for (i = 0; i < pft_filter_table->nr_output_chain_entries; i++)
	{
		struct pft_entry* e = (struct pft_entry*) &(pft_filter_table->input_chain_entries[i]);
		printk(KERN_INFO "[%lu, %s, %s, %s, %s, %u, %u, %d, %d]\n", e->interface, e->binary_path, e->vm_area_name, e->process_label, e->object_label, e->tclass, e->requested, e->known, e->verdict);
	} */
	return simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
}

static ssize_t
pft_rule_counter_write(struct file *filp, const char __user *ubuf,
                   size_t cnt, loff_t *ppos)
{
	struct pft_entry *e;
	int i;
	printk(KERN_INFO PFWALL_PFX "Resetting counters\n");
	read_lock_irq(&pf_table_lock);

	/* Writing any value to this file simply resets the counters */
#ifdef SEQUENTIAL_TRAVERSAL
	/* FILTER TABLE */
	for (i = 0; i < PF_NR_HOOKS; i++) {
		pf_foreach_entry(e,
			pf_get_ith_default_chain(&pft_filter_table, i)) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
	}

	for (i = 0; i < pft_filter_table.num_chains; i++) {
		pf_foreach_entry(e,
			pf_get_ith_user_chain(&pft_filter_table, i)) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
	}

	/* MANGLE TABLE */
	for (i = 0; i < PF_NR_HOOKS; i++) {
		pf_foreach_entry(e,
			pf_get_ith_default_chain(&pft_mangle_table, i)) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
	}

	for (i = 0; i < pft_mangle_table.num_chains; i++) {
		pf_foreach_entry(e,
			pf_get_ith_user_chain(&pft_mangle_table, i)) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
	}
#endif

#ifdef HASHING_TRAVERSAL
	/* FILTER TABLE */
	for (i = 0; i < PF_HTABLE_SIZE; i++)
	{
		/* FILTER TABLE */
		pf_foreach_entry(e, pft_filter_table.input_chain[i]) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
		pf_foreach_entry(e, pft_filter_table.output_chain[i]) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
	}


	for (i = 0; i < PF_HTABLE_SIZE; i++)
	{
		/* MANGLE TABLE */
		pf_foreach_entry(e, pft_mangle_table.input_chain[i]) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
		pf_foreach_entry(e, pft_mangle_table.output_chain[i]) {
			e->counter = 0;
			if (e->next_offset == 0)
				break;
		}
	}
#endif

	/* Performance counters */

	PFW_PERF_RESET(pft_strcmp_vm_area);
	PFW_PERF_RESET(pft_strcmp_binary_path);
	PFW_PERF_RESET(pft_strcmp_process_label);
	PFW_PERF_RESET(pft_strcmp_object_label);
	PFW_PERF_RESET(pft_default_ctxt_and_match);
	PFW_PERF_RESET(pft_match);
	PFW_PERF_RESET(pft_target);

	read_unlock_irq(&pf_table_lock);
	return cnt;
}

static ssize_t
pft_rule_counter_read(struct file *file, char __user *ubuf,
                       size_t cnt, loff_t *ppos)
{
	struct pft_entry *e;
	char *buf;
	int i;
	int filter_init, mangle_init;

	filter_init = atomic_read(&pft_filter_table.initialized);
	mangle_init = atomic_read(&pft_mangle_table.initialized);
	read_lock_irq(&pf_table_lock);

#ifdef SEQUENTIAL_TRAVERSAL
	/* FILTER TABLE */
	if (filter_init) {
		printk(KERN_INFO PFWALL_PFX "********\nCOUNTERS\nFilter table: \n");
		for (i = 0; i < PF_NR_HOOKS; i++) {
			pf_foreach_entry(e,
				pf_get_ith_default_chain(&pft_filter_table, i)) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}

		for (i = 0; i < pft_filter_table.num_chains; i++) {
			printk(KERN_INFO PFWALL_PFX "%s chain: \n",
				pft_filter_table.pft_chains[i].name);
			pf_foreach_entry(e,
				pf_get_ith_user_chain(&pft_filter_table, i)) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}
	}

	/* MANGLE TABLE */
	if (mangle_init) {
		printk(KERN_INFO PFWALL_PFX "********\nCOUNTERS\nMangle table: \n");
		for (i = 0; i < PF_NR_HOOKS; i++) {
			pf_foreach_entry(e,
				pf_get_ith_default_chain(&pft_mangle_table, i)) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}

		for (i = 0; i < pft_mangle_table.num_chains; i++) {
			printk(KERN_INFO PFWALL_PFX "%s chain: \n",
				pft_mangle_table.pft_chains[i].name);
			pf_foreach_entry(e,
				pf_get_ith_user_chain(&pft_mangle_table, i)) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}
	}
	printk(KERN_INFO PFWALL_PFX "********\n");
#endif

#ifdef HASHING_TRAVERSAL
	if (filter_init) {
		/* FILTER TABLE */
		printk(KERN_INFO PFWALL_PFX "********\nCOUNTERS\nFilter table: \n");
		printk(KERN_INFO PFWALL_PFX "INPUT CHAIN: \n");
		for (i = 0; i < PF_HTABLE_SIZE; i++) {
			pf_foreach_entry(e, pft_filter_table.input_chain[i]) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}
		printk(KERN_INFO PFWALL_PFX "OUTPUT CHAIN: \n");
		for (i = 0; i < PF_HTABLE_SIZE; i++) {
			pf_foreach_entry(e, pft_filter_table.output_chain[i]) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}
	}

	/* MANGLE TABLE */
	if (mangle_init) {
		printk(KERN_INFO PFWALL_PFX "\nMangle table: \n");
		for (i = 0; i < PF_HTABLE_SIZE; i++) {
			pf_foreach_entry(e, pft_mangle_table.input_chain[i]) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}
		printk(KERN_INFO PFWALL_PFX "OUTPUT CHAIN: \n");
		for (i = 0; i < PF_HTABLE_SIZE; i++) {
			pf_foreach_entry(e, pft_mangle_table.output_chain[i]) {
				printk(KERN_INFO "%u:%u ", e->id, e->counter);
				if (e->next_offset == 0)
					break;
			}
		}
		printk(KERN_INFO PFWALL_PFX "********\n");
	}
#endif

	/* Print Performance counters */


	buf = kasprintf(GFP_ATOMIC, "See printk buffer\n");
	read_unlock_irq(&pf_table_lock);
	return simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
}

void pfw_perf_print(char *marker, unsigned long *marker_array, unsigned long marker_counter)
{
	char * _marker_log_str;
	unsigned long _marker_cur_ptr;
	int i;
	_marker_log_str = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (!_marker_log_str) {
		printk(KERN_INFO PFWALL_PFX "Error printing performance numbers\n");
		goto end;
	}
	_marker_cur_ptr = 0;
	_marker_cur_ptr += sprintf(_marker_log_str, "\n%s: %lu: ",
			marker, marker_counter);
	for (i = 0; i < marker_counter && i < MAX_CTR; i++) {
		_marker_cur_ptr +=
		sprintf(_marker_log_str + _marker_cur_ptr, "%lu ",
			marker_array[i]);
		if (_marker_cur_ptr > PAGE_SIZE - 12) {
			_marker_log_str[strlen(_marker_log_str)] = 0;
			relay_write(pft_performance_rchan, _marker_log_str,
				strlen(_marker_log_str));
			_marker_cur_ptr = 0;
		}
	}
	_marker_log_str[strlen(_marker_log_str)] = 0;
	relay_write(pft_performance_rchan, _marker_log_str,
			strlen(_marker_log_str));
end:
	if (_marker_log_str)
		kfree(_marker_log_str);
}

static ssize_t
pft_perf_read(struct file *file, char __user *ubuf,
                       size_t cnt, loff_t *ppos)
{
	char *buf;

	/* This is used to fire the relay_fs for pft_performance */
	PFW_PERF_PRINT(pft_strcmp_vm_area);
	PFW_PERF_PRINT(pft_strcmp_binary_path);
	PFW_PERF_PRINT(pft_strcmp_process_label);
	PFW_PERF_PRINT(pft_strcmp_object_label);
	PFW_PERF_PRINT(pft_default_ctxt_and_match);
	PFW_PERF_PRINT(pft_match);
	PFW_PERF_PRINT(pft_target);


	PFW_PERF_PRINT(sys_stat64);
	PFW_PERF_PRINT(sys_open);
	PFW_PERF_PRINT(sys_close);
	PFW_PERF_PRINT(sys_read);
	PFW_PERF_PRINT(sys_write);
	PFW_PERF_PRINT(sys_getpid);
	PFW_PERF_PRINT(sys_execve);
	PFW_PERF_PRINT(sys_fork);

	/* Any statistic that we want to present to userspace */
	buf = kasprintf(GFP_ATOMIC, "Now cat pft_performance\n"); //pfwall_check_time);
	return simple_read_from_buffer(ubuf, cnt, ppos, buf, strlen(buf) + 1);
}

static ssize_t
pft_monitor_pid_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
	/* TODO: 12??? */
	char tmpbuf[12];
	ssize_t length;

	length = scnprintf(tmpbuf, 12, "%d\n", pf_monitor_pid);
	return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, length);
}

unsigned long _pfwall_counter = 0;
unsigned long _nfwall_counter = 0;
EXPORT_SYMBOL(_nfwall_counter);

static ssize_t
pft_monitor_pid_write(struct file *filp, const char __user *buf,
                   size_t count, loff_t *ppos)
{
	char *page;
	ssize_t length;
	int new_value, i;

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

	/* Overloading the negative space of pf_monitor_pid */
	if (new_value == -2) {
		_pfwall_counter = 0;
		_nfwall_counter = 0;
		new_value = -1;
	} else if (new_value == -3) {
		printk(KERN_INFO PFWALL_PFX "pfwall_counter: %lu\n", _pfwall_counter);
		printk(KERN_INFO PFWALL_PFX "nfwall_counter: %lu\n", _nfwall_counter);
		new_value = -1;
	} else if (new_value == -4) {
		pfwall_skip_hook_enabled = 1;
		new_value = -1;
	} else if (new_value == -5) {
		pfwall_skip_hook_enabled = 0;
		new_value = -1;
	} else if (new_value == -8) {
		pfwall_context_caching_enabled = 1;
		new_value = -1;
	} else if (new_value == -9) {
		pfwall_context_caching_enabled = 0;
		new_value = -1;
	} else if (new_value == -10) {
		pfwall_lazy_context_evaluation_enabled = 1;
		new_value = -1;
	} else if (new_value == -11) {
		pfwall_lazy_context_evaluation_enabled = 0;
		new_value = -1;
	} else if (new_value == -12) {
		/* reset syscall_list target module */
		for (i = 0; i <= NR_syscalls; i++)
			atomic_set(&pfw_syscalls_invoked[i], 0);
		for (i = 0; i <= NR_socketcalls; i++)
			atomic_set(&pfw_socketcalls_invoked[i], 0);
		new_value = -1;
	} else if (new_value == -13) {
		for (i = 1; i <= NR_syscalls; i++)
			printk(KERN_INFO PFWALL_PFX "syscall count: %d: %d\n", i, atomic_read(&pfw_syscalls_invoked[i]));
		for (i = 1; i <= NR_socketcalls; i++)
			printk(KERN_INFO PFWALL_PFX "socketcall count: %d: %d\n", i, atomic_read(&pfw_socketcalls_invoked[i]));
		new_value = -1;
	}
	pf_monitor_pid = new_value;
	length = count;
out:
	free_page((unsigned long) page);
	return length;
}

static ssize_t
pft_log_daemon_pid_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
	/* TODO: 12??? */
	char tmpbuf[12];
	ssize_t length;

	length = scnprintf(tmpbuf, 12, "%d\n", pf_log_daemon_pid);
	return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, length);
}

static ssize_t
pft_log_daemon_pid_write(struct file *filp, const char __user *buf,
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

	pf_log_daemon_pid = new_value;
	length = count;
out:
	free_page((unsigned long) page);
	return length;
}

static ssize_t
pft_enabled_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
	/* TODO: 12??? */
	char tmpbuf[12];
	ssize_t length;

	length = scnprintf(tmpbuf, 12, "%d\n", pfwall_enabled);
	return simple_read_from_buffer(ubuf, count, ppos, tmpbuf, length);
}

static ssize_t
pft_enabled_write(struct file *filp, const char __user *buf,
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

	pfwall_enabled = new_value;
	length = count;
out:
	free_page((unsigned long) page);
	return length;
}

static const struct file_operations pftable_fops = {
       .write  = pftable_write,
       .read   = pftable_read,
};

static const struct file_operations pft_rule_counter_fops = {
       .write  = pft_rule_counter_write,
       .read   = pft_rule_counter_read,
};

static const struct file_operations pft_perf_fops = {
       .read   = pft_perf_read,
};

static const struct file_operations pft_enabled_fops = {
       .write  = pft_enabled_write,
       .read   = pft_enabled_read,
};

static const struct file_operations pft_log_daemon_fops = {
       .write  = pft_log_daemon_pid_write,
       .read   = pft_log_daemon_pid_read,
};

static const struct file_operations pft_monitor_fops = {
       .write  = pft_monitor_pid_write,
       .read   = pft_monitor_pid_read,
};

struct kmem_cache *pf_packet_context_cache;


static int __init pf_pfwall_init(void)
{
	struct dentry *pftable_dentry;
	struct dentry *pft_rule_counters;
	struct dentry *pft_perf;
	struct dentry *pft_enabled;
	struct dentry *pft_log_daemon_pid;
	struct dentry *pft_monitor_pid;

	printk(KERN_INFO PFWALL_PFX "Process firewall initialization\n");

	/* Enabling pfwall */
	printk(KERN_INFO PFWALL_PFX "Enabling\n");
	pfwall_enabled = 0;

	/* cache for packet context */
	pf_packet_context_cache = kmem_cache_create("pf_packet_context", sizeof(struct pf_packet_context), PAGE_SIZE, 0, NULL);
	BUG_ON(pf_packet_context_cache == NULL);

	/* Process firewall file to load rules -- we don't use a system call like iptables */
	pftable_dentry = debugfs_create_file("pftable_rules", 0600, NULL, NULL, &pftable_fops);

	if(!pftable_dentry) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create pftable_rules\n");
	}

	/* Export the rule stat counters using this file */
	pft_rule_counters = debugfs_create_file("pft_rule_counters", 0600, NULL, NULL, &pft_rule_counter_fops);

	if(!pft_rule_counters) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create pft_rule_counters\n");
	}

	/* Export performance counters through this file */
	pft_performance_rchan = relay_open("pft_performance", NULL, 1024 * 1024, 8, &pft_performance_relay_callbacks, &num_dropped);
	if (!pft_performance_rchan) {
		printk(KERN_INFO PFWALL_PFX "log: relay_open() pft_perf failed\n");
		return 1;
	}
	pft_perf = debugfs_create_file("pft_perf", 0600, NULL, NULL, &pft_perf_fops);

	if(!pft_perf) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create pft_perf\n");
	}

	/* Enable/disable the process firewall through this file */
	/* TODO: Provide a kernel command line option */
	pft_enabled = debugfs_create_file("pfwall_enabled", 0600, NULL, NULL, &pft_enabled_fops);

	if(!pft_enabled) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create pfwall_enabled\n");
	}

	/* Register userspace logging daemon PID so
	it won't be subject to our checks */
	pft_log_daemon_pid = debugfs_create_file("pft_log_daemon_pid", 0601, NULL, NULL, &pft_log_daemon_fops);

	if(!pft_enabled) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create pft_log_daemon_fops\n");
	}

	/* Monitoring a particular PID */
	pft_monitor_pid = debugfs_create_file("pft_monitor_pid", 0601, NULL, NULL, &pft_monitor_fops);

	if(!pft_enabled) {
		printk(KERN_ALERT PFWALL_PFX "Unable to create pft_monitor_pid\n");
	}

	/* Register default modules */
	pft_register_default_modules();

	/* Initialize tables */
	atomic_set(&pft_filter_table.initialized, 0);
	atomic_set(&pft_mangle_table.initialized, 0);

	return 0;
}
fs_initcall(pf_pfwall_init);

int read_like(u16 tclass, u32 requested)
{
	switch(tclass)
	{
		case SECCLASS_PROCESS:
			switch(requested)
			{
				case PROCESS__PTRACE:
				case PROCESS__GETSCHED:
				case PROCESS__GETSESSION:
				case PROCESS__GETPGID:
				case PROCESS__GETCAP:
				case PROCESS__SHARE:
				case PROCESS__GETATTR:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_FILESYSTEM:
			switch(requested)
			{
				case FILESYSTEM__GETATTR:
				case FILESYSTEM__RELABELFROM:
				case FILESYSTEM__QUOTAGET:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_FILE:
			switch(requested)
			{
				case FILE__EXECUTE_NO_TRANS:
				case FILE__ENTRYPOINT:
				case FILE__READ:
				case FILE__GETATTR:
				case FILE__RELABELFROM:
				case FILE__EXECUTE:
				case FILE__SWAPON:
				case FILE__QUOTAON:
				case FILE__MOUNTON:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_DIR:
			switch(requested)
			{
				case DIR__SEARCH:
				case DIR__RMDIR:
				case DIR__READ:
				case DIR__GETATTR:
				case DIR__RELABELFROM:
				case DIR__EXECUTE:
				case DIR__SWAPON:
				case DIR__QUOTAON:
				case DIR__MOUNTON:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_FD:
			switch(requested)
			{
				 case FD__USE:
					return 1;
					break;
				 default:
					return 0;
			}
			break;
		case SECCLASS_LNK_FILE:
			switch(requested)
			{
				case LNK_FILE__READ:
				case LNK_FILE__GETATTR:
				case LNK_FILE__RELABELFROM:
				case LNK_FILE__EXECUTE:
				case LNK_FILE__SWAPON:
				case LNK_FILE__QUOTAON:
				case LNK_FILE__MOUNTON:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_CHR_FILE:
			switch(requested)
			{
				case CHR_FILE__EXECUTE_NO_TRANS:
				case CHR_FILE__ENTRYPOINT:
				case CHR_FILE__READ:
				case CHR_FILE__GETATTR:
				case CHR_FILE__RELABELFROM:
				case CHR_FILE__EXECUTE:
				case CHR_FILE__SWAPON:
				case CHR_FILE__QUOTAON:
				case CHR_FILE__MOUNTON:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_BLK_FILE:
			switch(requested)
			{
				case BLK_FILE__READ:
				case BLK_FILE__GETATTR:
				case BLK_FILE__RELABELFROM:
				case BLK_FILE__EXECUTE:
				case BLK_FILE__SWAPON:
				case BLK_FILE__QUOTAON:
				case BLK_FILE__MOUNTON:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_SOCK_FILE:
			switch(requested)
			{
				case SOCK_FILE__READ:
				case SOCK_FILE__GETATTR:
				case SOCK_FILE__RELABELFROM:
				case SOCK_FILE__EXECUTE:
				case SOCK_FILE__SWAPON:
				case SOCK_FILE__QUOTAON:
				case SOCK_FILE__MOUNTON:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_FIFO_FILE:
			switch(requested)
			{
				case FIFO_FILE__READ:
				case FIFO_FILE__GETATTR:
				case FIFO_FILE__RELABELFROM:
				case FIFO_FILE__EXECUTE:
				case FIFO_FILE__SWAPON:
				case FIFO_FILE__QUOTAON:
				case FIFO_FILE__MOUNTON:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_SOCKET:
			switch(requested)
			{
				case SOCKET__READ:
				case SOCKET__GETATTR:
				case SOCKET__RELABELFROM:
				case SOCKET__LISTEN:
				case SOCKET__ACCEPT:
				case SOCKET__GETOPT:
				case SOCKET__RECVFROM:
				case SOCKET__RECV_MSG:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_TCP_SOCKET:
			switch(requested)
			{
				case TCP_SOCKET__ACCEPTFROM:
				case TCP_SOCKET__READ:
				case TCP_SOCKET__GETATTR:
				case TCP_SOCKET__RELABELFROM:
				case TCP_SOCKET__LISTEN:
				case TCP_SOCKET__ACCEPT:
				case TCP_SOCKET__GETOPT:
				case TCP_SOCKET__RECVFROM:
				case TCP_SOCKET__RECV_MSG:
				case TCP_SOCKET__CONNECTTO:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_UDP_SOCKET:
			switch(requested)
			{
				case UDP_SOCKET__READ:
				case UDP_SOCKET__GETATTR:
				case UDP_SOCKET__RELABELFROM:
				case UDP_SOCKET__LISTEN:
				case UDP_SOCKET__ACCEPT:
				case UDP_SOCKET__GETOPT:
				case UDP_SOCKET__RECVFROM:
				case UDP_SOCKET__RECV_MSG:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_RAWIP_SOCKET:
			switch(requested)
			{
				case RAWIP_SOCKET__READ:
				case RAWIP_SOCKET__GETATTR:
				case RAWIP_SOCKET__RELABELFROM:
				case RAWIP_SOCKET__LISTEN:
				case RAWIP_SOCKET__ACCEPT:
				case RAWIP_SOCKET__GETOPT:
				case RAWIP_SOCKET__RECVFROM:
				case RAWIP_SOCKET__RECV_MSG:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_NODE:
			switch(requested)
			{
				case NODE__TCP_RECV:
				case NODE__UDP_RECV:
				case NODE__RAWIP_RECV:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_NETIF:
			switch(requested)
			{
				case NETIF__TCP_RECV:
				case NETIF__UDP_RECV:
				case NETIF__RAWIP_RECV:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_NETLINK_SOCKET:
			switch(requested)
			{
				case NETLINK_SOCKET__READ:
				case NETLINK_SOCKET__GETATTR:
				case NETLINK_SOCKET__RELABELFROM:
				case NETLINK_SOCKET__LISTEN:
				case NETLINK_SOCKET__ACCEPT:
				case NETLINK_SOCKET__GETOPT:
				case NETLINK_SOCKET__RECVFROM:
				case NETLINK_SOCKET__RECV_MSG:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_PACKET_SOCKET:
			switch(requested)
			{
				case PACKET_SOCKET__READ:
				case PACKET_SOCKET__GETATTR:
				case PACKET_SOCKET__RELABELFROM:
				case PACKET_SOCKET__LISTEN:
				case PACKET_SOCKET__ACCEPT:
				case PACKET_SOCKET__GETOPT:
				case PACKET_SOCKET__RECVFROM:
				case PACKET_SOCKET__RECV_MSG:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_KEY_SOCKET:
			switch(requested)
			{
				case KEY_SOCKET__READ:
				case KEY_SOCKET__GETATTR:
				case KEY_SOCKET__RELABELFROM:
				case KEY_SOCKET__LISTEN:
				case KEY_SOCKET__ACCEPT:
				case KEY_SOCKET__GETOPT:
				case KEY_SOCKET__RECVFROM:
				case KEY_SOCKET__RECV_MSG:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_UNIX_STREAM_SOCKET:
			switch(requested)
			{
				case UNIX_STREAM_SOCKET__ACCEPTFROM:
				case UNIX_STREAM_SOCKET__READ:
				case UNIX_STREAM_SOCKET__GETATTR:
				case UNIX_STREAM_SOCKET__RELABELFROM:
				case UNIX_STREAM_SOCKET__LISTEN:
				case UNIX_STREAM_SOCKET__ACCEPT:
				case UNIX_STREAM_SOCKET__GETOPT:
				case UNIX_STREAM_SOCKET__RECVFROM:
				case UNIX_STREAM_SOCKET__RECV_MSG:
				case UNIX_STREAM_SOCKET__CONNECTTO:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_UNIX_DGRAM_SOCKET:
			switch(requested)
			{
				case UNIX_DGRAM_SOCKET__READ:
				case UNIX_DGRAM_SOCKET__GETATTR:
				case UNIX_DGRAM_SOCKET__RELABELFROM:
				case UNIX_DGRAM_SOCKET__LISTEN:
				case UNIX_DGRAM_SOCKET__ACCEPT:
				case UNIX_DGRAM_SOCKET__GETOPT:
				case UNIX_DGRAM_SOCKET__RECVFROM:
				case UNIX_DGRAM_SOCKET__RECV_MSG:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_SEM:
			switch(requested)
			{
				case SEM__GETATTR:
				case SEM__READ:
				case SEM__UNIX_READ:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_MSG:
			switch(requested)
			{
				case MSG__RECEIVE:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_MSGQ:
			switch(requested)
			{
				case MSGQ__GETATTR:
				case MSGQ__READ:
				case MSGQ__UNIX_READ:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_SHM:
			switch(requested)
			{
				case SHM__GETATTR:
				case SHM__READ:
				case SHM__UNIX_READ:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_IPC:
			switch(requested)
			{
				case IPC__GETATTR:
				case IPC__READ:
				case IPC__UNIX_READ:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_NETLINK_ROUTE_SOCKET:
		case SECCLASS_NETLINK_FIREWALL_SOCKET:
		case SECCLASS_NETLINK_TCPDIAG_SOCKET:
		case SECCLASS_NETLINK_NFLOG_SOCKET:
		case SECCLASS_NETLINK_XFRM_SOCKET:
		case SECCLASS_NETLINK_SELINUX_SOCKET:
		case SECCLASS_NETLINK_AUDIT_SOCKET:
		case SECCLASS_NETLINK_IP6FW_SOCKET:
		case SECCLASS_NETLINK_DNRT_SOCKET:
			return 1;
			break;
		case SECCLASS_ASSOCIATION:
			switch(requested)
			{
				case ASSOCIATION__RECVFROM:
				case ASSOCIATION__POLMATCH:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_PACKET:
			switch(requested)
			{
				case PACKET__RECV:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		case SECCLASS_KEY:
			switch(requested)
			{
				case KEY__VIEW:
				case KEY__READ:
				case KEY__SEARCH:
					return 1;
					break;
				default:
					return 0;
			}
			break;
		default:
			return 1; /* Be conservative */
			break;
	}
	return 1;
}
EXPORT_SYMBOL(read_like);

/* pfwall core */
/* Audit of denial */
void pfwall_audit(struct pf_packet_context *p)
{
	return;
}

/* TODO: The two functions below perform the same function, only,
 * for pft_entry and pft_match. Is there a generic way to do this? */

int update_match_context(struct pft_match *m, struct pf_packet_context *p)
{
	int ret = 0;

	if (m->context_mask != 0) {
		if (((m->context_mask) & (m->context_mask - 1)) == 0) {
			/* m->context_mask is the only bit set */
			if (!(m->context_mask & (p->context))) {
				ret = pf_context_array[log(m->context_mask)](p);
				if (ret < 0)
					goto end;
			}
		} else {
			unsigned int pow = 1, num = sizeof(unsigned int) * 8;
			int i = 0;
			for (; i < num; i++, pow = pow << 1) {
				if (!(m->context_mask & (p->context))) {
					ret = pf_context_array[i](p);
					if (ret < 0)
						goto end;
				}
			}
		}
	}
end:
	return ret;
}

int update_target_context(struct pft_target *t, struct pf_packet_context *p)
{
	int ret = 0;

	if (t->context_mask != 0) {
		if (((t->context_mask) & (t->context_mask - 1)) == 0) {
			/* Only one context bit set */
			if (!(t->context_mask & p->context)) {
				ret = pf_context_array[log(t->context_mask)](p);
				if (ret < 0)
					goto end;
				t->context_mask |= p->context;
			}
		} else {
			unsigned int pow = 1, num = sizeof(unsigned int) * 8;
			int i = 0;
			for (; i < num; i++, pow = pow << 1) {
				if ((t->context_mask & pow) && !(p->context & pow)) {
					ret = pf_context_array[i](p);
					if (ret < 0)
						goto end;
					t->context_mask |= (p->context & pow);
				}
			}
		}
	}
end:
	return ret;
}


/* Given a chain's first element, return the verdict for this packet */
int pft_filter(struct pf_packet_context *p, struct pft_entry *first, struct pft_table *tbl)
{
	struct pft_entry *e;
	struct pft_match *m;
	struct pft_target *t;

	int verdict = PF_ACCEPT; /* Verdict : PF_ACCEPT, PF_DROP, ... */
	int ret = 0; /* Error */

//	unsigned int cpu = smp_processor_id();
//	unsigned int *cpu_stackptr = per_cpu_ptr(tbl->stackptr, cpu);
//	struct ipt_entry **cpu_jumpstack = tbl->jumpstack[cpu];

	if (first == NULL) /* The chain hasn't been initialized yet */
		return verdict;
	/* TODO: More intelligent locking for table */
//	read_lock_irq(&pf_table_lock);

	e = (struct pft_entry *) first;

//	pf_foreach_entry(e, first) {
	p->stackptr = 0;
	_pfwall_counter++;
	do {
		# if 0
		if ((p->hook == PF_HOOK_SYSCALL_RETURN) && (e->id != 0))
			printk(KERN_INFO PFWALL_PFX "Trying: %d\n", e->id);
		#endif

		/* First, match default match */
		PFW_PERF_START(pft_default_ctxt_and_match);
		ret = pft_default_ctxt_and_match(p, &(e->def));
		PFW_PERF_END(pft_default_ctxt_and_match);
		if (!ret)
			goto next_rule; /* To next rule */
		else if (ret < 0)
			goto end; /* Error gathering some context */

		PFW_PERF_START(pft_match);
		/* Next, match with each match in the rule */
		pf_foreach_match(m, e) {
			/* Check and fill required context for match module
				- Lazy Context Evaluation */
			ret = update_match_context(m, p);
			/* An error, or this hook has not sufficient context */
			if (ret < 0) {
				printk(KERN_INFO PFWALL_PFX "Error (%d) in getting match context for rule: %d\n", ret, e->id);
				goto next_rule;
				// goto end;
			}

			/* Match */
			if (!m->match(p, m->match_specific))
				goto next_rule; /* To next rule */
		}
		PFW_PERF_END(pft_match);

		/* At this point, the rule is matched; call target function */
		e->counter++;

		PFW_PERF_START(pft_target);
		t = pf_get_target(e);

		#if 0
		if ((p->hook == PF_HOOK_SYSCALL_RETURN) && (e->id != 0))
			printk(KERN_INFO PFWALL_PFX "Matched: %d, calling target: %s\n", e->id, t ? t->name : "null");
		#endif
		if (t->target == NULL) {
			if (p->stackptr == PF_MAX_CHAINS) {
				printk(KERN_INFO PFWALL_PFX
				"Cycle in chain traversal detected!\n");
				verdict = PF_DROP;
				goto decided;
			}

			/* Push return on stack */
			p->jumpstack[(p->stackptr)++] = pf_getnext_entry(e);

			/* Jump to new chain */
			e = pf_getjump_entry(e);

			goto jumped;
		}

		/* Check and fill required context for target module
			- Lazy Context Evaluation */
		ret = update_target_context(t, p);

		if (ret < 0) {
			// printk(KERN_INFO PFWALL_PFX "Error (%d) in getting target context for rule: %d\n", ret, e->id);
			goto next_rule;
			// goto end;
		}

		verdict = t->target(p, t->target_specific);
		PFW_PERF_END(pft_target);

		if (verdict < 0) {
			ret = verdict;
			goto end;
		} else if (verdict == PF_RETURN ||
			(verdict == PF_ACCEPT && p->stackptr > 0)) {
			/* We don't allow user-chains to
			return verdict of ACCEPT */
			/* Pop stack */
			e = (struct pft_entry *)
				p->jumpstack[--(p->stackptr)];
			goto jumped;
		} else if (verdict == PF_CONTINUE) {
			goto next_rule;
		} else {
			goto decided;
		}

next_rule:
		e = pf_getnext_entry(e);
jumped:
		;
	} while (1);


	/* No rule matches, or no rule has a decider target.
	 * Return builtin chain default target (policy)
	 * TODO: HACK: For now, return deny if selinux_enforcing */
	verdict = PF_ACCEPT;

//	verdict = selinux_enforcing ? PF_DROP : PF_ACCEPT;
decided:
end:
//	read_unlock_irq(&pf_table_lock);
	return (ret < 0) ? ret : verdict;
}

/* Do packet filtering */
/* This code gets a bit ugly for hashing traversal, because
we have to calculate the chains to match on */

int pft_do_filter(int hook, struct pf_packet_context *p)
{
	int verdict = PF_ACCEPT;
#ifdef HASHING_TRAVERSAL
	int index = 0;
	int i = 0;
	int ret;
#endif
	// printk(KERN_DEBUG PFWALL_PFX "[%s]\n", __FUNCTION__);
	/* Find out whether we need to filter on the input chain
	 * or the output chain, and do the filtering appropriately */

	/* TODO: Put repetitions below in a separate function */

	if (!atomic_read(&pft_filter_table.initialized))
		goto end;
	#ifdef SEQUENTIAL_TRAVERSAL
	verdict = pft_filter(p,
			pf_get_ith_default_chain(&pft_filter_table, hook),
			&pft_filter_table);
	#endif
	#ifdef HASHING_TRAVERSAL
	/* General match */
	verdict = pft_filter(p, pft_filter_table.input_chain[0]);

//		if (verdict == PF_ACCEPT)
//			goto end;

	/* We have to get the interface context now, and
		select chains for each interface on the
		backtrace */
	if (!(p->context & PF_CONTEXT_INTERFACE)) {
		ret = pf_context_array[log(PF_CONTEXT_INTERFACE)](p);
		if (ret < 0) {
			verdict = PF_ACCEPT;
			goto end;
		}
	}

	while (i < MAX_NUM_FRAMES && p->user_stack.trace.entries[i] && p->user_stack.trace.entries[i] != 0xFFFFFFFF) {
		#ifdef PFWALL_MATCH_STR
		if (!strcmp(p->vm_area_strings[i], "")) {
		#endif
		#ifdef PFWALL_MATCH_REPR
		if (p->user_stack.trace.vma_inoden[i] == 0) {
		#endif
			goto end;
		}
		index = pft_hash(p->user_stack.trace.entries[i] - p->user_stack.trace.vma_start[i]);
		verdict = pft_filter(p, pft_filter_table.input_chain[index]);
//			if (verdict == PF_ACCEPT || verdict == PF_DROP)
//				goto end;

		i++;
	}
	#endif
	if (verdict == PF_DROP || verdict < 0)
		goto end;
	# if 0
	/* TODO: write_like */
	if (!read_like(p->info.tclass, p->info.requested)) {
		if (!atomic_read(&pft_filter_table.initialized))
			goto end;
		#ifdef SEQUENTIAL_TRAVERSAL
		verdict = pft_filter(p,
			pf_get_ith_default_chain(&pft_filter_table, PF_HOOK_OUTPUT), &pft_filter_table);
		#endif

		#ifdef HASHING_TRAVERSAL
		/* General match */
		verdict = pft_filter(p, pft_filter_table.output_chain[0]);
		if (verdict == PF_ACCEPT)
			goto end;

		/* We have to get the interface context now, and
			select chains for each interface on the
			backtrace */
		if (!(p->context & PF_CONTEXT_INTERFACE))
			pft_interface_context(p);
		p->context |= PF_CONTEXT_INTERFACE;

		while (i < MAX_NUM_FRAMES && p->user_stack.trace.entries[i] && p->user_stack.trace.entries[i] != 0xFFFFFFFF) {
			#ifdef PFWALL_MATCH_STR
			if (!strcmp(p->vm_area_strings[i], "")) {
			#endif
			#ifdef PFWALL_MATCH_REPR
			if (p->user_stack.trace.vma_inoden[i] == 0) {
			#endif
				goto end;
			}
			index = pft_hash(p->user_stack.trace.entries[i] - p->user_stack.trace.vma_start[i]);
			verdict = pft_filter(p, pft_filter_table.output_chain[index]);
//			if (verdict == PF_ACCEPT || verdict == PF_DROP)
//				goto end;
			i++;
		}
		#endif

	}
	#endif
end:
	return verdict;
}

int pfwall_post_create_details(struct dentry *dentry, struct inode *created_inode)
{
	int rc = 0;
	char *tcontext = NULL, *ttype = NULL;
	// u32 tcontext_len;
	struct pf_packet_context *p = current->p;

	strcpy(p->info.filename, dentry->d_name.name);
	if (!dentry || !dentry->d_inode) /* TODO: Why? */
		p->info.filename_inoden = 0;
	else
		p->info.filename_inoden = dentry->d_inode->i_ino;
	p->context |= PF_CONTEXT_FILENAME;

	# if 0
	rc = security_sid_to_context (
		((struct inode_security_struct_pfwall *)
			created_inode->i_security)->sid,
			&tcontext, &tcontext_len);
        if (rc)
              goto end;

	ttype = context_to_type(tcontext);
	if (ttype == NULL) {
		rc = -EINVAL; /* Initial SID */
		goto end;
	}

	strcpy(p->info.tcontext, ttype);
	p->info.tcontext	= kstrdup(ttype, GFP_ATOMIC);
	if (!p->info.tcontext) {
		rc = -ENOMEM;
		return rc;
	}
	#endif

		# if 0
	dentry = d_find_alias(created_inode);
	if (dentry) {
		if (p->info.filename)
			kfree(p->info.filename);
		p->info.filename = kstrdup(dentry->d_name.name, GFP_ATOMIC);
	}
		# endif
// end:
	if (tcontext)
		kfree(tcontext);
	if (ttype)
		kfree(ttype);
	return rc;
}

int pfwall_selinux_details(u32 ssid, u32 tsid, u16 tclass,
		u32 requested, struct common_audit_data* auditdata)

{
	char* scontext = NULL, *tcontext = NULL, *stype = NULL, *ttype = NULL;
	#ifdef PFWALL_MATCH_STR
	char *ptemp = NULL;
	#endif
	// u32 scontext_len, tcontext_len;
	struct file* exe_file = NULL;
	// char* path = NULL; /* For storing paths */
	struct pf_packet_context *p = current->p;
	int rc = 0; /* Return code */

	#ifdef PFWALL_MATCH_STR
	/* Get contexts from SIDs */
	/* Let us hold a lock so we won't be preempted -- till we finish gathering p data  -- to be done later */
	rc = security_sid_to_context (ssid, &scontext, &scontext_len);
        if (rc)
              return rc;
	rc = security_sid_to_context (tsid, &tcontext, &tcontext_len);
        if (rc)
              return rc;

	/* Extract type from context */
	stype = context_to_type(scontext);
	if (stype == NULL) {
		rc = -EINVAL; /* Initial SID */
		goto end;
	}
	ttype = context_to_type(tcontext);
	if (ttype == NULL) {
		rc = -EINVAL; /* Initial SID */
		goto end;
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

	/* Get process binary path; this context is needed to check if we need to monitor this binary */
	/*
	path = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	if (path == NULL) {
		printk(KERN_INFO PFWALL_PFX "path allocation failed\n");
		rc = -ENOMEM;
		goto end;
	}
	*/
	#endif

	exe_file = current->mm->exe_file;
	if (!exe_file) {
		printk(KERN_INFO PFWALL_PFX "No executable file\n");
		rc = -ENOMEM;
		goto end;
	}

	#ifdef PFWALL_MATCH_STR
	ptemp = d_path(&(exe_file->f_path), p->path, PAGE_SIZE);
	if (IS_ERR(ptemp)) {
		printk(KERN_INFO PFWALL_PFX "Path conversion failed\n");
		rc = PTR_ERR(ptemp);
		goto end;
	}

	strcpy(p->info.binary_path, ptemp);
//	p->info.binary_path = kstrdup(ptemp, GFP_ATOMIC);

	/* Update the packet context */
	p->context |= PF_CONTEXT_TYPE;
	p->context |= PF_CONTEXT_BINARY_PATH;
	#endif

	/* Construct the "packet" p */

	#ifdef PFWALL_MATCH_REPR
	p->info.binary_inoden = exe_file->f_dentry->d_inode->i_ino;
	p->context |= PF_CONTEXT_BINARY_PATH_INODE;
	#endif

	p->info.pid		= current->pid;
	p->info.ssid 		= ssid;
	p->info.tsid		= tsid;

	p->info.tclass		= tclass;
	p->info.requested	= requested;

	#ifdef PFWALL_MATCH_REPR
	p->context |= PF_CONTEXT_TYPE_SID;
	#endif

	/* Fill any module-specific contexts that we only have here */
	if (auditdata) {
		p->auditdata = auditdata;
	}
	/* If we are doing a directory search, update last_dir_searched */
	# if 0
	if (p->info.tclass == SECCLASS_DIR && p->info.requested == DIR__SEARCH) {
		pft_auditdata_context(p);
		p->context |= PF_CONTEXT_FILENAME;
		p->last_dir_searched = p->info.filename_inoden;
	}
	#endif
end:
	if (scontext)
		kfree(scontext);
	if (tcontext)
		kfree(tcontext);
	if (stype)
		kfree(stype);
	if (ttype)
		kfree(ttype);
//	if (path)
//		kfree(path);
	return rc;
}

// static spinlock_t pf_packet_lock = SPIN_LOCK_UNLOCKED;

void pf_packet_allocate(void)
{
	/* TODO: Called from assembly when entering a syscall.
		How to do error handling? */
	# if 0
	current->p = kzalloc(sizeof(struct pf_packet_context), GFP_ATOMIC);
	memset(current->p, 0, sizeof(struct pf_packet_context));
	return 0;
	# endif
//	static unsigned long flags;
//	spin_lock_irqsave(&current->pf_packet_lock, flags);
	/* The following is done only once - when the process is created and first LSM access is done */
	# if 0
	if (current->p == NULL) {
		current->p = kmalloc(sizeof(struct pf_packet_context), GFP_ATOMIC);
		if (!current->p) {
//			spin_unlock_irqrestore(&current->pf_packet_lock, flags);
			return;
//			return -ENOMEM;
		}
	}
	# endif
	/* Packet is allocated when process is created */
	/* TODO: Why is it NULL sometimes? */
	atomic_inc(&_syscall_ctr);
	if (current->p) {
		current->p->user_stack.trace.nr_entries = 0;
		current->p->auditdata = NULL; /* TODO: where getting set? */
	}
		// memset(current->p, 0, sizeof(struct pf_packet_context));
	/* TODO: Call pfwall_check sysentry hook directly from assembly in entry_32.S */
	pfwall_check(PF_HOOK_SYSCALL_BEGIN);

//	spin_unlock_irqrestore(&current->pf_packet_lock, flags);
	return;
}

void pf_packet_free(void)
{
//	int i;
//	static unsigned long flags;
	/* Reinitialize the packet - do not free it */
	/* TODO: Put below in correct place */
	#ifdef PFWALL_MATCH_STR
	#endif

	# if 0
	if (!current->p)
		return;
	else {
		if (current->p->info.binary_path != NULL) {
			kfree (current->p->info.binary_path);
			current->p->info.binary_path = NULL;
		}
		if (current->p->info.scontext != NULL) {
			kfree (current->p->info.scontext);
			current->p->info.scontext = NULL;
		}
	}
	current->p->data = NULL;
	current->p->data_count = 0;
	current->p->user_stack.int_trace.nr_entries = 0;
	current->p->user_stack.trace.nr_entries = 0;
	current->p->context = 0;
	# endif
	/* Packet is destroyed when process exits */
	if (current->p)  {
		/* In case already exited, skip hook */
		pfwall_check(PF_HOOK_SYSCALL_RETURN);
	}

	return;


	/* Preserve current->p->last_dir_searched */

//	spin_lock_irqsave(&current->pf_packet_lock, flags);
//	# if 0
	if (current->p) {
//		memset(current->p, 0, sizeof(struct static_stack_trace));
//		current->p->user_stack.trace.entries[0] = 0xFFFFFFFF;
//		for (i = 0; i < MAX_NUM_FRAMES; i++)
//			current->p->vm_area_strings[i][0] = '\0';
//		memset(current->p, 0, sizeof(struct pf_packet_context));
		// kmem_cache_free(pf_packet_context_cache, &(current->p));
		# if 0
		if (current->p->info.binary_path != NULL) {
			kfree (current->p->info.binary_path);
			current->p->info.binary_path = NULL;
		}
		if (current->p->info.scontext != NULL) {
			kfree (current->p->info.scontext);
			current->p->info.scontext = NULL;
		}
		kfree(current->p);
		current->p = NULL; ;
		#endif
		# if 0
		for (i = 0; i < MAX_NUM_FRAMES; i++)
			if (current->p->vm_area_strings && current->p->vm_area_strings[i])
				kfree(current->p->vm_area_strings[i]);
		# endif
//		kmem_cache_free(pf_packet_context_cache, current->p);
//		current->p = NULL;
	}
//	# endif
//	current->p = NULL;
//	spin_unlock_irqrestore(&current->pf_packet_lock, flags);
}


/**
 * skip_lsm_hook() - Should LSM (SELinux) hook given by (@tclass, @requested) be skipped?
 *			True if only default rule is registered for hook on @t.
 * @tclass:		SELinux class
 * @requested:		SELinux requested
 * @t:			Table containing rules
 *
 */

int skip_lsm_hook(int hook, u16 tclass, u32 requested, struct pft_table *t)
{
	int j, skip = 1;
	struct pft_lsm_hook h;

	if (t->hooks_enabled[hook] == 1) {
		/* There is a rule registered on the input/output hook in general */
		skip = 0;
	} else {
		/* Scan LSM hooks enabled */
		for (j = 0; j < PF_MAX_LSM_HOOKS; j++) {
			h = t->lsm_hooks_enabled[j];
			if (h.tclass == 0 && h.requested == 0)
				break;
			/* If either tclass or requested match, or one is 0 and the other matches,
			 * we have a match */
			if ((tclass == h.tclass && requested == h.requested) ||
				(tclass == h.tclass && requested == 0) ||
				(tclass == 0 && requested == h.requested)) {
				skip = 0; /* Don't skip */
				break;
			}
		}
	}
	return skip;
}

/**
 * skip_hook() - Should @hook be skipped? True if only default rule is registered for @hook on @t.
 * @hook:	Current hook
 * @t:		Table containing rules
 */

int skip_hook(int hook, struct pft_table *t)
{
	if (t->hooks_enabled[hook] == 0)
		if (hook != PF_HOOK_INPUT && hook != PF_HOOK_OUTPUT)
			return 1; /* Skip hook */
	return 0; /* Don't skip */

}

/* This function scans the ruleset and returns the verdict.
 * Hook-specific context is supplied.
 * Hooks should use this as their entry point */

int pfwall_check(int hook, ...)
{
	struct pf_packet_context *p = NULL; /* Details of current "packet" */

	int decision = PF_DROP, rc = 0;
	int sn;

	if (!pfwall_enabled)
		goto end;
	if (current->kernel_request > 0)
		goto end;

	/* for now, only deal with name resolution calls */
	sn = syscall_get_nr(current, task_pt_regs(current));
	if (!in_set(sn, first_arg_set) && !in_set(sn, second_arg_set))
		goto end;

	/* Ignore the log daemon */
	if (current->pid == pf_log_daemon_pid)
		goto end;

	/* Do we have to monitor a specific process?
	 * Mainly for debugging purposes */
	/* Negative values used for specific purposes */
	if (pf_monitor_pid >= 0 && current->pid != pf_monitor_pid)
		goto end;

	if (in_atomic()) {
//		printk(KERN_INFO PFWALL_PFX "in_atomic: %s: %s, %s, %c, %c\n", p->info.binary_path, p->info.scontext, p->info.tcontext, p->info.tclass, p->info.requested);
		goto end;
	}
//	if (in_atomic())
//		goto end;

	/* no process context for kernel threads */
	if (current->mm == NULL)
		goto end;

	/* for paths that already hold mmap_sem, we cannot introspect into userspace, as a page
	 * fault may cause a deadlock (see note arch/x86/mm/fault.c:1092 in do_page_fault) */
	if (!down_read_trylock(&current->mm->mmap_sem)) {
		goto end;
	}
	up_read(&current->mm->mmap_sem);


	/* Skip-hook optimization */
	if (pfwall_skip_hook_enabled)
		if (skip_hook(hook, &pft_filter_table))
			goto end;

	/* Packet is allocated at the start of the system call, and
	 * destroyed just before return */

//	if (hook == PF_HOOK_INPUT || hook == PF_HOOK_OUTPUT) /* First entry hook, allocate packet */
//		rc = pf_packet_allocate();
//	if (rc < 0)
//		goto end;

	/* Increment trace counter - used to mark performance results */
	_current_trace++;

	p = current->p;

	if (current->p == NULL) { /* TODO: Why does allocation fail? */
		decision = 0;
		goto end;
	}

	p->hook = hook;

	/* We are into this hook */
	p->hook_mask &= ~(p->hook);

	/* For each hook, fill in the packet with context that is
	 * available at that hook only */

	if (hook == PF_HOOK_INPUT || hook == PF_HOOK_OUTPUT) {
		va_list argp;
		struct common_audit_data *auditdata;
		u32 ssid, tsid, requested;
		u32 tclass; /* Forced to promote by va_args, why? */

		va_start(argp, hook);
		ssid = va_arg(argp, u32);
		tsid = va_arg(argp, u32);
		tclass = va_arg(argp, u32);
		requested = va_arg(argp, u32);
		auditdata = va_arg(argp, struct common_audit_data *);

		va_end(argp);

		/* Skip-hook optimization */
		/* Is this valid, given some hooks have to invalidate context? */
		if (pfwall_skip_hook_enabled) {
			if (skip_lsm_hook(hook, tclass, requested, &pft_filter_table))
				goto end;
		}

		/* Gather the selinux context, this context module's arguments
		 * have to be hardcoded here because
		 * the context is not available elsewhere
		 */
//		printk(KERN_DEBUG PFWALL_PFX "pfwall_selinux_details: [%s]\n", __FUNCTION__);
		rc = pfwall_selinux_details(ssid, tsid, tclass,
				requested, auditdata);
		if (rc < 0) {
			/*
			 * ENOMEM - Memory error
			 * EINVAL - Initial SID
			 */
			goto end;
		}

	} else if (hook == PF_HOOK_READ) {
		va_list argp;
		char *data; /* Pointer to the kernel structure holding data */
		size_t count; /* Number of bytes actually read */
		va_start(argp, hook);
		data = va_arg(argp, char *);
		count = va_arg(argp, size_t);
		va_end(argp);

		/* Fill in the details in the packet */
		p->data = data;
		p->data_count = count;
	} else if (hook == PF_HOOK_CREATE) {
		va_list argp;
		struct dentry *dentry;
		struct inode *inode;
		va_start(argp, hook);
		dentry = va_arg(argp, struct dentry *);
		inode = va_arg(argp, struct inode *);
		va_end(argp);

		rc = pfwall_post_create_details(dentry, inode);
	} else if (hook == PF_HOOK_SIGNAL_DELIVER) {
		va_list argp;
		va_start(argp, hook);
		p->signo = va_arg(argp, int);
		p->signal_queue = va_arg(argp, int);
		p->context |= PF_CONTEXT_SIGINFO;
		va_end(argp);
	}

	/* Now that we have the packet, send it through the firewall and get the decision */
	/* TODO: Mangle traversal - this should be first */
	// do_pft_mangle(p);
//	printk(KERN_DEBUG PFWALL_PFX "before pft_do_filter:[%s]\n", __FUNCTION__);
	if (atomic_read(&pft_filter_table.initialized) != 0)
		decision = pft_do_filter(hook, p);
	else /* Table not initialized, allow through */
		decision = PF_ACCEPT;

	/* Decision can be < 0 (error), or allow/drop */
	if (decision < 0) { /* Error */
		if (decision != -EINVAL) {
			/* This happens when finding vma strings, not finding
			 * a VM area, and setting to vmafilenull */
			/* Legitimate because the VM area might not be mapped
			 * in yet */
			printk(KERN_INFO PFWALL_PFX "Error in decision: %d\n", decision);
		}
		decision = 0; /* Allow it */
		goto end;
	} else { /* Allow, Deny */
		if (decision == PF_DROP)
			decision = -EACCES;
		else if (decision == PF_ACCEPT)
			decision = 0;
		goto decided_here;
	}

	if (decision == -EACCES)
		pfwall_audit (p);
decided_here:
	if (!pfwall_context_caching_enabled)
		p->context = 0;
	else {
		/* Free the context that is invalid after these hooks */
		if (hook == PF_HOOK_INPUT || hook == PF_HOOK_OUTPUT) {
			current->p->data = NULL;
			current->p->data_count = 0;
			current->p->auditdata = NULL;
			p->context &= ~PF_CONTEXT_FILENAME;
			p->context &= ~PF_CONTEXT_TYPE;
			p->context &= ~PF_CONTEXT_TYPE_SID;
			p->context &= ~PF_CONTEXT_DATA;

			# if 0
			if (current->p->info.tcontext != NULL) {
				kfree (current->p->info.tcontext);
				current->p->info.tcontext = NULL;
			}
			if (current->p->info.filename != NULL) {
				kfree (current->p->info.filename);
				current->p->info.filename = NULL;
				current->p->info.filename_inoden = 0;
			}
			#endif
		} else if (hook == PF_HOOK_SYSCALL_RETURN) {
			p->context &= ~PF_CONTEXT_INTERFACE;
			p->context &= ~PF_CONTEXT_VM_AREA_STRINGS;
			p->context &= ~PF_CONTEXT_SYSCALL_FILENAME;
			p->user_stack.trace.nr_entries = 0;
			p->context = 0; /* Binary path context available till exec hook */
		} else if (hook == PF_HOOK_SYSCALL_BEGIN) {
			p->user_stack.trace.nr_entries = 0;
			p->context = 0;
			/* TODO: If we do invalidation properly, we don't need this.
			   Also, binary path context available till exec hook */
		} else if (hook == PF_HOOK_SIGNAL_DELIVER) {
			p->context &= ~PF_CONTEXT_SIGINFO;
		} else if (hook == PF_HOOK_CREATE) {
			p->context &= ~PF_CONTEXT_FILENAME;
		}
	}

//	pf_packet_free();
	;
end:
	if (rc < 0)
		decision = 0;  /* If there was a problem with us, or
				* if the subject was not to be monitored,
				* allow it through */
	return decision;
}
EXPORT_SYMBOL(pfwall_check);
