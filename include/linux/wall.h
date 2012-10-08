#include <linux/limits.h>
#include <linux/signal.h>
#include <asm/syscall.h>
#include <linux/net.h>
#include <linux/module.h>

#define NETLINK_WALL_VIOLATIONS 28

#define NL_VIOLATIONS_TYPE_REGISTER_DAEMON 0
#define NL_VIOLATIONS_TYPE_REQUEST_DECISION 1
#define NL_VIOLATIONS_TYPE_REQUEST_RESPONSE 2

#define NL_VIOLATIONS_RESPONSE_ALLOW 0
#define NL_VIOLATIONS_RESPONSE_DENY 1
#define NL_VIOLATIONS_RESPONSE_KILL 2

#define NL_VIOLATIONS_STATE_PENDING 0
#define NL_VIOLATIONS_STATE_FINISHED 1
#define MAX_LOG 1024 /* Maximum size of a wall_violations_msg.payload */

#define PF_ACCEPT 0x1
#define PF_DROP 0x0
#define PF_CONTINUE 0x2
#define PF_RETURN 0x4

#define PF_MAX_CHAINS 32 /* Maximum number of user-defined chains in a table */
// #define PF_CONTEXT_POSTPONE -255

/* Contexts */
#define PF_CONTEXT_DATA 0x1
#define PF_CONTEXT_SIGNAL 0x2 /* Available readily */
#define PF_CONTEXT_SYSCALL_ARGS 0x4
#define PF_CONTEXT_STATE 0x8 /* Available readily */
#define PF_CONTEXT_INTERFACE 0x10 /* Also includes interpreter context, if indeed a script is in execution */
#define PF_CONTEXT_FILENAME 0x20 /* The filename and inode of the object being accessed */
#define PF_CONTEXT_VM_AREA_STRINGS 0x40 /* The VM area name strings context */
#define PF_CONTEXT_TYPE 0x80 /* The source, target context strings */
#define PF_CONTEXT_TYPE_SID 0x100 /* The source, target context SID */
#define PF_CONTEXT_BINARY_PATH 0x200 /* The process binary filename */
#define PF_CONTEXT_BINARY_PATH_INODE 0x400 /* The process binary file inode */
#define PF_CONTEXT_SIGINFO 0x800 /* Signal information */
#define PF_CONTEXT_SYSCALL_FILENAME 0x1000 /* Filename from syscall args */
#define PF_CONTEXT_DAC_BINDERS 0x2000 /* Possible attacker UID */

/* Hooks */
#define PF_NR_HOOKS 7 /* input, output, data read, inode create */
#define PF_HOOK_INPUT 0 /* LSM input */
#define PF_HOOK_OUTPUT 1 /* LSM output */
#define PF_HOOK_READ 2 /* input post-read */
#define PF_HOOK_CREATE 3 /* output post-create inode */
#define PF_HOOK_SYSCALL_BEGIN 4 /* System call begin */
#define PF_HOOK_SYSCALL_RETURN 5 /* System call return */
#define PF_HOOK_SIGNAL_DELIVER 6 /* System call return */

/* Maximum number of LSM hooks that we can register on */
/* TODO: Artificial limit for skip-hook optimization */
#define PF_MAX_LSM_HOOKS 32


/* Compile-time options */

// #define HASHING_TRAVERSAL
#define SEQUENTIAL_TRAVERSAL

// #define PFWALL_MATCH_STR
#define PFWALL_MATCH_REPR

/* Advanced stacktrace - Remember to change paths of libraries */
// #define PFWALL_ADVANCED_STACKTRACE

#define PFW_UBUNTU_10_04_LIBC_PATH "/lib/tls/i686/cmov/libc-2.11.1.so"
#define PFW_UBUNTU_10_04_LD_SO_PATH "/lib/ld-2.11.1.so"

#define PFW_UBUNTU_11_10_LIBC_PATH "/lib/i386-linux-gnu/libc-2.13.so"
#define PFW_UBUNTU_11_10_LD_SO_PATH "/lib/i386-linux-gnu/ld-2.13.so"

#define PFW_LIBC_PATH PFW_UBUNTU_11_10_LIBC_PATH
#define PFW_LD_SO_PATH PFW_UBUNTU_11_10_LD_SO_PATH

/* SID definitions */
#define PFWALL_SID_DONT_CARE -1
#define PFWALL_SID_SYSHIGH -2
#define PFWALL_SID_SYSLOW -3

/* Maximum number of frames in the userspace backtrace */
#define MAX_NUM_FRAMES 32
#define MAX_INT_LOG 1024

/* Signal queue where the signal is dequeued from, so we get
   additional information about the queued signals */
#define SIGNAL_QUEUE_PRIVATE 0
#define SIGNAL_QUEUE_SHARED 1

/* e->next_offset = 0 will signify termination */
#define pf_foreach_entry(pos, first) \
	for ((pos) = (struct pft_entry *) (first); \
	     ; \
	     (pos) = (struct pft_entry *) ((char *) ((pos)->beg_mat_tar) + \
		     (pos)->next_offset))

#define pf_foreach_match(pos, e) \
	for ((pos) = (struct pft_match *) (e->beg_mat_tar); \
	     (pos) < (struct pft_match *) ((char *) (e->beg_mat_tar) + \
		     (e)->target_offset); \
	     (pos) = (struct pft_match *) ((char *) (pos) + \
		     (pos)->match_size) )

#define pf_getnext_entry(pos) (struct pft_entry *) ((char *) ((pos)->beg_mat_tar) + \
		     (pos)->next_offset)

#define pf_getjump_entry(pos) (struct pft_entry *) ((char *) ((pos)->beg_mat_tar) + \
		     (pos)->jump_offset)
#define pf_get_target(e) ((struct pft_target *) ((e)->beg_mat_tar + (e)->target_offset))

#define pf_get_ith_default_chain(table, i) \
	((struct pft_entry *) ((table)->table_base + \
		(table)->hook_entries[(i)]))

#define pf_get_ith_user_chain(table, i) \
	((struct pft_entry *) ((table)->table_base + \
		(table)->pft_chains[(i)].chain_offset))

#define PFWALL_PFX "pfwall: "
#define PFWALL_MAX_PENDING 16

#define PFWALL_DBG_ON 0
#define PFWALL_ERR_LVL 0

#define PFWALL_DBG(s, ...) \
	do { \
		if (PFWALL_DBG_ON == 1) { \
			printk(KERN_INFO PFWALL_PFX "debug: [%s:%05d]: " s, \
					__FUNCTION__, __LINE__, ## __VA_ARGS__); \
		} \
	} while (0)

#define PFWALL_ERR(l, s, ...) \
	do { \
			if (l <= PFWALL_ERR_LVL) { \
				printk(KERN_INFO PFWALL_PFX "error: [%s:%05d]: " s, \
						__FUNCTION__, __LINE__, ## __VA_ARGS__); \
			} \
	} while (0)

/* Is the process firewall enabled or not? */
extern int pfwall_enabled;

/* Is fine-grained performance enabled or not? */
extern int pfwall_perf_enabled;

/* Is skip-hook optimization enabled or not? */
extern int pfwall_skip_hook_enabled;

struct wall_violations_msg
{
	unsigned int index; /* Used to retrieve reference to ctx object when a message is
		      received from userspace. Currently, the kernel pointer itself.
		      Userspace does not need to be concerned with this */
	union
	{
		pid_t pid; /* PID of userspace daemon when type is NL_VIOLATIONS_TYPE_REGISTER_DAEMON */
		int response; /* NL_VIOLATIONS_RESPONSE_[ALLOW]/[DENY] */
		char request[MAX_LOG]; /* Details about the violation */
	} payload;
};

struct wall_violations_msg_ctx
{
	int state; /* NL_VIOLATIONS_STATE_[PENDING]/[FINISHED] */
	pid_t pid; /* PID of process that generated this request and has to be
		      woken up on receipt of this message */
	struct wall_violations_msg msg;
};


/* Process firewall tables */

#define SYSHIGH 0
#define SYSLOW 1

// #define PF_ACCEPT 0
// #define PF_DROP 1
// #define PF_QUEUE 2 /* Send to userspace */

/* Maximum lengths of match module, target module, and table names */
#define PFT_NAMELEN 16

/* TODO: All packet context is allocated statically. This does make it huge;
 * but there is no concern of memory leaks */

struct proc_info {
	pid_t pid;

	char scontext[PATH_MAX];
	u32 ssid;

	char tcontext[PATH_MAX];
	u32 tsid;

	u16 tclass;
	u32 overall_requested; /* May have more than one bit set */
	u32 requested; /* The request currently under process */
	char filename[PATH_MAX];
	unsigned long filename_inoden;

	char binary_path[PATH_MAX];
	unsigned long binary_inoden;
};

#define INT_FNAME_MAX 64

/* Same as stack_trace except static size */
struct static_stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long entries[MAX_NUM_FRAMES]; /* ip */
	unsigned long stack_bases[MAX_NUM_FRAMES]; /* sp - for local vars */

	int bin_ip_exists; /* Does entrypoint exist in program? */
	int ept_ind; /* Entrypoint index */
	/* inode and start address for each VMA in program trace */
	ino_t vma_inoden[MAX_NUM_FRAMES];
	unsigned long vma_start[MAX_NUM_FRAMES];
	char vm_area_strings[MAX_NUM_FRAMES][PATH_MAX];
};

/* interpreter stack trace */
struct interpreter_stack_trace {
	unsigned int nr_entries, max_entries;
	/* line numbers */
	unsigned long entries[MAX_NUM_FRAMES];
	/* filename for each script file in the stack trace */
	char int_filename[MAX_NUM_FRAMES][INT_FNAME_MAX];
};

struct user_stack_info {
	struct static_stack_trace trace;
	struct interpreter_stack_trace int_trace;
};

#define VMA_INO(vma) (vma->vm_file->f_dentry->d_inode->i_ino)
#define EXE_INO(t) (t->mm->exe_file->f_dentry->d_inode->i_ino)

#define EPT_VMA_OFFSET(addr, us) ((addr) + (us->trace.vma_start[us->trace.ept_ind]))
#define EPT_INO(t) (t->user_stack.trace.vma_inoden[t->user_stack.trace.ept_ind])

static inline ino_t ept_inode_get(struct user_stack_info *us)
{
    return us->trace.vma_inoden[us->trace.ept_ind];
}

static inline unsigned long us_entry_offset_get(struct user_stack_info *us, int i)
{
    return us->trace.entries[i] - us->trace.vma_start[i];
}

static inline unsigned long ept_offset_get(struct user_stack_info *us)
{
    return us_entry_offset_get(us, us->trace.ept_ind);
}

static inline int valid_user_stack(struct user_stack_info *us)
{
    return (us->trace.nr_entries > 0);
}

static inline char *int_ept_filename_get(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0) ? (us->int_trace.int_filename[0]) : NULL;
}

static inline int int_ept_lineno_get(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0) ? (us->int_trace.entries[0]) : 0;
}

static inline int int_ept_exists(struct user_stack_info *us)
{
	return (us->int_trace.nr_entries > 0);
}

extern int is_interpreter(struct task_struct *t);
extern void user_interpreter_unwind(struct pf_packet_context *p);
extern struct int_bt_info *on_script_behalf(struct user_stack_info *us);
extern void copy_interpreter_info(struct task_struct *c, struct task_struct *p);

#if 0
struct static_stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long entries[MAX_NUM_FRAMES]; /* Address in memory */
	int skip;
};

struct interpreter_info {
	unsigned int nr_entries, max_entries;
	char script_filename[MAX_NUM_FRAMES][PATH_MAX];
	unsigned long script_inoden[MAX_NUM_FRAMES];
	unsigned long line_number[MAX_NUM_FRAMES];
};
#endif

struct stack_frame_user {
	const void __user	*next_fp;
	unsigned long		ret_addr;
};

struct pft_entry;
/*
   This is the "packet" that the process firewall acts on.
   Any context that the packet should contain (including all
   of the context modules), should be in this packet.

   TODO: Make additional module context extensible (by providing
   a linked list, for example). The task_struct has a reference
   to the "packet" currently under process, as there may be
   more than one place where this context is needed.
*/

struct pf_packet_context {
	/* userstack and interpreter entrypoints */
	struct user_stack_info user_stack;

	struct proc_info info;

	int hook; /* Current hook being traversed */
	int hook_mask; /* Which hooks decisions need be made on
	* as context becomes available */
	int context; /* Context mask for available contexts in this packet */

	/* Module-Specific contexts TODO: Make this generic */
	struct common_audit_data *auditdata; /* SELinux auditdata */
	char *data; /* Pointer to data context in the kernel */
	size_t data_count; /* Actual number of bytes read */

	/* Signal information */
	int signo;
	int signal_queue; /* Shared or private? */

	/* Traversal information */
	unsigned int stackptr;
	struct pft_entry *jumpstack[PF_MAX_CHAINS];

	/* filename from syscall */
	char __user *syscall_filename;

	/* UID of user that can attack filename resource
		syscall_filename */
	uid_t sys_fname_attacker_uid;
};

extern struct kmem_cache *pf_packet_context_cachep;

struct pft_default_matches
{
	/* Interface address as offset from binary */
	unsigned long interface;

	/* Interpreter address as filename, lineno */
	char script_path[PATH_MAX]; /* Script filename path */
	unsigned long script_inoden; /* The script file inode number */
	unsigned long script_line_number; /* script line number */

	/* The default matches contain both the userspace way of representing
	things, and the kernel way. Both are retained inside the kernel
	for ease of logging
	*/

	char binary_path[PATH_MAX]; /* eg. /usr/sbin/sshd */
	unsigned long binary_inoden; /* The executable file inode number */

	char vm_area_name[PATH_MAX]; /* Defaults to binary; can specify library eg. /usr/lib/libc.so */
	unsigned long vm_area_inoden; /* The vm area backing file inode number */

	char process_label[256]; /* SELinux process label, predefined values SYSHIGH, SYSLOW */
	u32 ssid[2]; /* For unconfined_u:unconfined_r:type and system_u:system_r:type */

	char object_label[256]; /* SELinux object label */
	u32 tsid[2]; /* For unconfined_u:unconfined_r:type and system_u:system_r:type */

	u16 tclass; /* SELinux object class */
	u32 requested; /* SELinux operation */
};

/* Map of interface to index in array */

struct pft_array_map {
	struct list_head list;
	unsigned long interface;
	int index;
};

/* Firewall rule - contains default matches, followed by module-specific matches, and finally the target */
struct pft_entry
{
	/* the ID for this rule, that userspace can use to match counters
	   and other info */
	unsigned int id;

	/* The "class" of this rule -- used in indexing the array */
	unsigned int rule_class;

	/* The default matches - match function for this is hardcoded */
	struct pft_default_matches def;

	/* Size of pft_entry + pft_matches */
	unsigned int target_offset;

	/* Size of pft_match(s) + pft_target - As this is contiguous, we can overcome overhead of list traversal to get to the next rule */
	unsigned int next_offset;

	/* Jump offset to user-defined chain, if target function is NULL */
	unsigned int jump_offset;

	/* How many times has this rule been satisfied? */
	unsigned int counter;

	/* The beginning of the matches and the target are pointed to by this element */
	unsigned char beg_mat_tar[0];
};

/* Structure for linking pft_entries together */
/*
struct pft_indirect_entry
{
	struct list_head list;
	struct pft_entry *entry;
};
*/

/* Match module extensions -
	when a rule is pushed in with a certain match,
	the kernel fills in the match
	function using the name of the match module, in
	the function pf_translate_match.
	The match module should already be registered */
struct pft_match
{
	/* Size of this match - variable due to last field */
	unsigned int match_size;

	/* Name of module used in the match */
	char name[PFT_NAMELEN];

	/* Bitmask of the context needed by this match module */
	unsigned int context_mask;

	/* Match function for the module above
	  - used for fast access, and only by the kernel
	  - will be filled in by kernel, and
	  given the context of
		- the incoming "packet"
		- the part of the rule corresponding to this match module
	  - function has to return if the current "packet" p matches with
	  - the rule given in the match-specific data */
	bool (*match) (struct pf_packet_context *p, void *match_specific_data);

	/* Module-specific match data in the rule (e.g., --string "test") */
	unsigned char match_specific[0];
};

#define PF_HASH_BITS		8
#define PF_HTABLE_SIZE (1 << PF_HASH_BITS) + 1

/* Target module extensions -
	when a rule is pushed in with a certain target,
	the kernel fills in the target
	function using the name of the target module, in
	the function pf_translate_target.
	The target module should already be registered */
struct pft_target
{
	/* Size of this target - variable due to last field
		- filled in by userspace */
	unsigned int target_size;

	/* Name of the target to invoke
		- filled in by userspace */
	char name[PFT_NAMELEN];

	/* Bitmask of the context needed by this target module
		- filled in by userspace */
	int context_mask;

	/* Function that will be called if this target is requested in a rule
		- filled in by kernel */
	/* If this is NULL, it means that next_offset will jump to a new chain.
	 * For hashing traversal, this means an absolute address.
	 * For sequential traversal, this means an offset.
	 */
	int (*target) (struct pf_packet_context *p, void *target_specific_data);

	/* Module-specific target data in the rule
		- custom arguments, filled in by userspace */
	unsigned char target_specific[0];
};

# if 0

struct pft_table
{
	atomic_t initialized;
	char name[PFT_NAMELEN]; /* Name of table, inbuilt filter */
#ifdef SEQUENTIAL_TRAVERSAL
	struct pft_entry *input_chain; /* Pointer to start of entries for input chain */
#endif
#ifdef HASHING_TRAVERSAL
	struct pft_entry *input_chain[PF_HTABLE_SIZE + 1];
//	struct pft_array_map input_map;
//	int pft_input_array_size;
#endif
#ifdef SEQUENTIAL_TRAVERSAL
	struct pft_entry *output_chain; /* Pointer to start of entries for output chain */
#endif
#ifdef HASHING_TRAVERSAL
	struct pft_entry *output_chain[PF_HTABLE_SIZE + 1];
//	struct pft_array_map output_map;
//	int pft_output_array_size;
#endif
};

#endif

/* Information about chains is needed in pfwall, unlike iptables, because
 * we need to setup hashing traversal */
struct pft_chain
{
	/* Name of chain */
	char name[PFT_NAMELEN];

	/* Offset from base of table */
	unsigned int chain_offset;
};

/* TODO: Hashing traversal */

struct pft_lsm_hook {
	u16 tclass; /* SELinux object class */
	u32 requested; /* SELinux operation */
};

struct pft_table /* Replace an entire table - the total size and number of
		      rules for each chain of the the ruleset is specified so
		      we know what is coming up */
{
	/* Is table initialized? */
	atomic_t initialized;

	/* Which table. */
	char name[PFT_NAMELEN];

	/* Total size of table chains (starting from table_base).
	 * Does NOT include this struct pft_table */
	unsigned int size;

	/* Skip-hook : Enabled hooks */
	unsigned int hooks_enabled[PF_NR_HOOKS];

	/* Enabled LSM hooks */
	struct pft_lsm_hook lsm_hooks_enabled[PF_MAX_LSM_HOOKS];

	/* Entry points of the input and output hooks, as offset
	 * from table base */
	unsigned int hook_entries[PF_NR_HOOKS];

	/* Information about user-defined (non-default) chains in this table */
	unsigned int num_chains;
	struct pft_chain pft_chains[PF_MAX_CHAINS];

	/* Per-CPU pointer containing value of top of stack
		- 0 to nr_cpus */
	unsigned int __percpu *stackptr;

	/* Per-CPU jumpstack */
	unsigned char ***jumpstack;

	unsigned char *table_base;
};


extern int (*pf_context_array[sizeof(unsigned int) * 8]) (struct pf_packet_context *);
extern rwlock_t pf_table_lock;

extern int read_like(u16, u32);
extern int pft_default_ctxt_and_match(struct pf_packet_context*, void*);
extern int pfwall_check(int hook, ...);

extern struct pft_indirect_entry **pft_chain_array;
extern int pft_array_map_get(struct pft_array_map, unsigned long);
/* The function below needs to be exported as interface needs to be
   calculated in do_pft_filter itself for selecting matching chains */
// extern int pft_interface_context(struct pf_packet_context *p);

extern struct kmem_cache *pf_packet_context_cache;

/* Module structures */
struct pft_match_module {
	struct list_head list;
	char name[PFT_NAMELEN];
	bool (*match) (struct pf_packet_context *p, void *match_specific_data);
};

struct pft_target_module {
	struct list_head list;
	char name[PFT_NAMELEN];
	int (*target) (struct pf_packet_context *p, void *target_specific_data);
};


/* Module registration */
extern int pf_register_context(unsigned int, int (*func) (struct pf_packet_context *));
extern int pf_register_match(struct pft_match_module *);
extern int pf_register_target(struct pft_target_module *);

/* Other */
extern int selinux_enforcing;
extern int security_sid_to_context(u32, char **, u32 *);
extern int security_context_to_sid(const char *, u32, u32 *);

/* Make each context module have its own header, so we don't put everything here */

extern int pft_interpreter_context(struct pf_packet_context *p);
extern int pft_auditdata_context(struct pf_packet_context *p);
extern int pft_stacktrace_and_vm_area_context(struct pf_packet_context *p);
extern int pft_type_context(struct pf_packet_context *p);
extern int pft_binary_path_context(struct pf_packet_context *p);
extern int pft_binary_path_inode_context(struct pf_packet_context *p);
extern int pft_vm_area_name_context(struct pf_packet_context *p);
extern int pft_vm_area_inode_context(struct pf_packet_context *p);

/* State module hash */
char *pft_dict_get_value(char *);
void pft_dict_remove_key(char *);
int pft_dict_set_value(char *, char *, int);

typedef struct dict_node {
	struct hlist_node list;
	char* key;
	char* value;
}dict_node_t;

dict_node_t *pft_dict_get_entry(char *);

/* Utility functions and definitions */
#define TYPE_HARDLINK 0x1
#define TYPE_SYMLINK 0x2


/* Hashing helper utility function */
extern unsigned long pfwall_hash(unsigned char *str);
int in_set(int, int *);
char __user *get_last(char __user *);
char *get_existing_target_file(uid_t uid, char *filename, char *fname, int type);
char *get_existing_target_dir(uid_t uid, char *filename, char *fname);
char *get_new_target_file(uid_t uid, char *filename, char *fname);

/* Interpreter debug info hash */
int pft_debug_dict_set_value(char *filename, unsigned long pc,
	unsigned long offset, unsigned long reg);
struct debug_dict_value *pft_debug_dict_get_value(char *filename,
	unsigned long pc);

struct debug_dict_value {
	unsigned long offset; /* offset to sp */
	unsigned long reg; /* Register */
};

/* TODO: Fix these taken from selinux-specific headers */

/* From objsec.h */

struct inode_security_struct_pfwall {
	struct inode *inode;	/* back pointer to inode object */
	struct list_head list;	/* list of inode_security_struct */
	u32 task_sid;		/* SID of creating task */
	u32 sid;		/* SID of this object */
	u16 sclass;		/* security class of this object */
	unsigned char initialized;	/* initialization flag */
	struct mutex lock;
};

/* Number of socket calls that are demultiplexed by the single sys_socketcalls */
#define NR_socketcalls (SYS_RECVMMSG) /* See linux/net.h */

/* permissions module */
#define ATTACKER_EXEC 0x1
#define ATTACKER_READ 0x2
#define ATTACKER_WRITE 0x4
#define EXISTS 0x8
#define ATTACKER_CREATE 0x20
#define ATTACKER_DELETE 0x40
// #define ATTACKER_SETATTR 0x10
/* In case attacker cannot delete an existing file,
	could attacker have created the file before the victim?
	Check for squat (e.g., IPC). */
#define ATTACKER_PREBIND 0x80
/* If exists, then delete and create permissions, else just create permission */
#define ATTACKER_BIND 0x100
int pft_get_uid_with_permission(int flags, const char __user *filename);

/* syscall_invoked module */
extern atomic_t pfw_syscalls_invoked[NR_syscalls + 1];
extern atomic_t pfw_socketcalls_invoked[NR_socketcalls + 1];

/* global system call counter */
extern atomic_t _syscall_ctr;

/* Basic Performance macros */

#define MAX_CTR 100000

/* To use the API below, you must have a trace counter named
	_current_trace that is updated whenever needed. This is
	used to "mark" the values, so they can be associated
	later. */
extern unsigned long _current_trace;

#define PFW_PERF_INIT(marker) \
	unsigned long _##marker##_time_strt, _##marker##_time_end; \
	unsigned long _##marker##_counter = 0; \
	unsigned long _##marker##_array[MAX_CTR]; \
	unsigned long _##marker##_trace[MAX_CTR]; \
	EXPORT_SYMBOL(_##marker##_time_strt); \
	EXPORT_SYMBOL(_##marker##_time_end); \
	EXPORT_SYMBOL(_##marker##_counter); \
	EXPORT_SYMBOL(_##marker##_array);


#define PFW_PERF_EXTERN_INIT(marker) \
	extern unsigned long _##marker##_time_strt, _##marker##_time_end;  \
	extern unsigned long _##marker##_counter; \
	extern unsigned long _##marker##_array[MAX_CTR]; \
	extern unsigned long _##marker##_trace[MAX_CTR]; \

#define PFW_PERF_START_ENABLED(marker) \
	if (pfwall_perf_enabled) \
	rdtscl(_##marker##_time_strt);

#define PFW_PERF_END_ENABLED(marker) \
	rdtscl(_##marker##_time_end); \
	_##marker##_trace[(_##marker##_counter) % MAX_CTR] = \
		_current_trace; \
	_##marker##_array[(_##marker##_counter++) % MAX_CTR] = \
		(_##marker##_time_end - _##marker##_time_strt);

#define PFW_PERF_START(marker) 	;
#define PFW_PERF_END(marker)	;


#define PFW_PERF_PRINT_INIT(marker) \
	char * _##marker##_log_str; \
	int _##marker##_cur_ptr; \

#define PFW_PERF_PRINT(marker) \
	pfw_perf_print(#marker, _##marker##_array, _##marker##_counter);

#define PFW_PERF_RESET(marker) \
	_##marker##_counter = 0;

#define PFW_PERF_WRAP(marker, fn) \
	PFW_PERF_START(marker); \
	fn; \
	PFW_PERF_END(marker); \
	PFW_PERF_PRINT(marker);


/* Network-firewall invocation counter */
extern unsigned long _nfwall_counter;

/* Advanced Performance macros
#define PFWALL_PERF_MARKER_INIT(marker) \
	double marker_avg = 0; \
	int marker_n = 0; \
	unsigned long marker_time_strt, marker_time_end;

#define PFWALL_PERF_START(marker) \
	rdtscl(marker_time_strt);

#define PFWALL_PERF_END(marker) \
	rdtscl(marker_time_end); \
	marker_avg = (marker_avg * (double) marker_n) + (marker_time_end - marker_time_start)/ (double) ((double) marker_n + 1) \
	marker_n++;

#define PFWALL_PERF_PRINT(marker, throttle) \
	if (!(marker_n % throttle)) { \
		printk(KERN_INFO PFWALL_PFX "%s: %f over %d", marker, marker_avg, marker_n); \
	}
*/

/* attacker */
/* Maximum number of users in the system */
#define MAX_USERS 256
/* Maximum number of groups a user can be a member of */
#define GRP_MEMB_MAX 32

/* Return value space augment */
#define PFW_UID_NO_MATCH MAX_USERS

/* Extended attributes */
#define ATTACKER_XATTR_PREFIX "security."
#define ATTACKER_XATTR_SUFFIX "attacker"
#define ATTACKER_XATTR_STRING ATTACKER_XATTR_PREFIX ATTACKER_XATTR_SUFFIX
#define ATTACKER_XATTR_VALUE "1"

extern uid_t uid_array[MAX_USERS][GRP_MEMB_MAX];
extern char *existing_target_file;
extern char *new_target_file;

/* System call from within kernel ignoring process firewall.
   Requires mm_segment_t old_fs = get_fs(); */
#define PFW_SYSCALL(call) { \
	set_fs(KERNEL_DS); \
	current->kernel_request++; \
	call; \
	current->kernel_request--; \
	set_fs(old_fs); \
}

#define ATTACKER_HOMEDIR "/home/attacker"

/* Credentials export user function */
extern struct cred *set_creds(uid_t *);

/* Information about system calls */

extern int first_arg_set[];
extern int second_arg_set[];
extern int check_set[];
extern int create_set[];
extern int use_set[];
extern int nosym_set[];
extern int in_set(int sn, int *array);
int bind_call(int sn);
int connect_call(int sn);

/* selinux helper utility functions */
extern char *tclass_str(u16 tclass);
extern char *requested_str(u16 tclass, u32 requested);

#if 0
/* system call sets -- to identify name resolution calls */
static int first_arg_set[] = {
    __NR_open,
    __NR_creat,
    __NR_link,
    /* __NR_unlink, */
    /* __NR_execve, */
    __NR_chdir,
    __NR_mknod,
    __NR_chmod,
    __NR_mount,
    __NR_utime,
    __NR_access,
    /* __NR_rename, */
    __NR_mkdir,
    /* __NR_rmdir, */
    __NR_chroot,
    __NR_symlink,
    __NR_readlink,
    __NR_uselib,
    __NR_swapon,
    __NR_truncate,
    __NR_statfs,
    __NR_swapoff,
    __NR_chown,
    __NR_truncate64,
    __NR_lchown32,
    __NR_mount,
    __NR_pivot_root,
    __NR_utimes,
    __NR_stat,
    __NR_lstat,
    __NR_stat64,
    __NR_lstat64,
    __NR_setxattr,
    __NR_lsetxattr,
    __NR_getxattr,
    __NR_lgetxattr,
    __NR_listxattr,
    __NR_llistxattr,
    __NR_removexattr,
    __NR_lremovexattr,
    __NR_statfs64,
    __NR_symlinkat,
    -1
};

static int second_arg_set[] = {
    __NR_quotactl,
    __NR_inotify_add_watch,
    __NR_openat,
    __NR_mkdirat,
    __NR_mknodat,
    __NR_fchownat,
    __NR_futimesat,
    __NR_fstatat64,
    __NR_unlinkat,
    __NR_renameat,
    __NR_linkat,
    __NR_readlinkat,
    __NR_fchmodat,
    __NR_faccessat,
    __NR_utimensat,
    __NR_name_to_handle_at,
    -1
};

static inline int in_set(int sn, int *array)
{
	int i;
	for (i = 0; array[i] != -1; i++)
		if (sn == array[i])
			return 1;
	return 0;
}

#endif
