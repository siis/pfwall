
typedef unsigned char zend_bool;
typedef unsigned char zend_uchar;
typedef unsigned int zend_uint;
typedef unsigned long zend_ulong;
typedef unsigned short zend_ushort;
typedef unsigned int zend_object_handle;

#define ZEND_MAX_RESERVED_RESOURCES	4
struct _zend_op_array {
	/* Common elements */
	zend_uchar type;
	char *function_name;
	void *scope;
	zend_uint fn_flags;
	void *prototype;
	zend_uint num_args;
	zend_uint required_num_args;
	void *arg_info;
	zend_bool pass_rest_by_reference;
	unsigned char return_reference;
	/* END of common elements */

	zend_bool done_pass_two;

	zend_uint *refcount;

	void *opcodes;
	zend_uint last, size;

	void *vars;
	int last_var, size_var;

	zend_uint T;

	void *brk_cont_array;
	int last_brk_cont;
	int current_brk_cont;

	void *try_catch_array;
	int last_try_catch;

	/* static variables support */
	void *static_variables;

	void *start_op;
	int backpatch_count;

	zend_uint this_var;

	char *filename;
	zend_uint line_start;
	zend_uint line_end;
	char *doc_comment;
	zend_uint doc_comment_len;
	zend_uint early_binding; /* the linked list of delayed declarations */

	void *reserved[ZEND_MAX_RESERVED_RESOURCES];
};
typedef struct _zend_op_array zend_op_array;

typedef struct _zend_object_value {
	zend_object_handle handle;
	void *handlers;
} zend_object_value;

typedef union _zvalue_value {
	long lval;					/* long value */
	double dval;				/* double value */
	struct {
		char *val;
		int len;
	} str;
	void *ht;				/* hash table value */
	zend_object_value obj;
} zvalue_value;

struct _zval_struct {
	/* Variable information */
	zvalue_value value;		/* value */
	zend_uint refcount__gc;
	zend_uchar type;	/* active type */
	zend_uchar is_ref__gc;
};
typedef struct _zval_struct zval;



typedef struct _znode {
	int op_type;
	union {
		zval constant;

		zend_uint var;
		zend_uint opline_num; /*  Needs to be signed */
		zend_op_array *op_array;
		void *jmp_addr;
		struct {
			zend_uint var;	/* dummy */
			zend_uint type;
		} EA;
	} u;
} znode;

typedef int (*opcode_handler_t) (void*, void***);
struct _zend_op {
	opcode_handler_t handler;
	znode result;
	znode op1;
	znode op2;
	ulong extended_value;
	uint lineno;
	zend_uchar opcode;
};
typedef struct _zend_op zend_op;

typedef struct _zend_function_state {
	void *function;
	void **arguments;
} zend_function_state;

struct _zend_execute_data {
	struct _zend_op *opline;
	zend_function_state function_state;
	void *fbc; /* Function Being Called */
	void *called_scope;
	zend_op_array *op_array;
	void *object;
	union _temp_variable *Ts;
	void ***CVs;
	void *symbol_table;
	struct _zend_execute_data *prev_execute_data;
	void *old_error_reporting;
	zend_bool nested;
	void **original_return_value;
	void *current_scope;
	void *current_called_scope;
	void *current_this;
	void *current_object;
	void *call_opline;
};
typedef struct _zend_execute_data zend_execute_data;

typedef struct _zend_ptr_stack {
	int top, max;
	void **elements;
	void **top_element;
	zend_bool persistent;
} zend_ptr_stack;

typedef void (*dtor_func_t)(void *pDest);
typedef struct _hashtable {
	uint nTableSize;
	uint nTableMask;
	uint nNumOfElements;
	ulong nNextFreeElement;
	void *pInternalPointer;	/* Used for element traversal */
	void *pListHead;
	void *pListTail;
	void **arBuckets;
	dtor_func_t pDestructor;
	zend_bool persistent;
	unsigned char nApplyCount;
	zend_bool bApplyProtection;
// #if ZEND_DEBUG
// 	int inconsistent;
// #endif
} HashTable;

struct _zend_vm_stack;
typedef struct _zend_vm_stack *zend_vm_stack;

struct _zend_vm_stack {
	void **top;
	void **end;
	zend_vm_stack prev;
};

typedef struct _zend_stack {
	int top, max;
	void **elements;
} zend_stack;

typedef enum {
	EH_NORMAL = 0,
	EH_SUPPRESS,
	EH_THROW
} zend_error_handling_t;

typedef struct _zend_property_info {
	zend_uint flags;
	char *name;
	int name_length;
	ulong h;
	char *doc_comment;
	int doc_comment_len;
	void *ce;
} zend_property_info;

typedef struct _zend_objects_store {
	void *object_buckets;
	zend_uint top;
	zend_uint size;
	int free_list_head;
} zend_objects_store;

#define SYMTABLE_CACHE_SIZE 32

struct _zend_executor_globals {
	zval **return_value_ptr_ptr;

	zval uninitialized_zval;
	zval *uninitialized_zval_ptr;

	zval error_zval;
	zval *error_zval_ptr;

	zend_ptr_stack arg_types_stack;

	/* symbol table cache */
	void *symtable_cache[SYMTABLE_CACHE_SIZE];
	void **symtable_cache_limit;
	void **symtable_cache_ptr;

	zend_op **opline_ptr;

	void *active_symbol_table;
	HashTable symbol_table;		/* main symbol table */

	HashTable included_files;	/* files already included */

	void *bailout;

	int error_reporting;
	int orig_error_reporting;
	int exit_status;

	zend_op_array *active_op_array;

	HashTable *function_table;	/* function symbol table */
	HashTable *class_table;		/* class table */
	HashTable *zend_constants;	/* constants table */

	void *scope;
	void *called_scope; /* Scope of the calling class */

	void *This;

	long precision;

	int ticks_count;

	zend_bool in_execution;
	HashTable *in_autoload;
	void *autoload_func;
	zend_bool full_tables_cleanup;

	/* for extended information support */
	zend_bool no_extensions;

	HashTable regular_list;
	HashTable persistent_list;

	zend_vm_stack argument_stack;

	int user_error_handler_error_reporting;
	void *user_error_handler;
	void *user_exception_handler;
	zend_stack user_error_handlers_error_reporting;
	zend_ptr_stack user_error_handlers;
	zend_ptr_stack user_exception_handlers;

	zend_error_handling_t  error_handling;
	void      *exception_class;

	/* timeout support */
	int timeout_seconds;

	int lambda_count;

	HashTable *ini_directives;
	HashTable *modified_ini_directives;

	zend_objects_store objects_store;
	void *exception, *prev_exception;
	zend_op *opline_before_exception;
	zend_op exception_op[3];

	void *current_execute_data;

	void *current_module;

	zend_property_info std_property_info;

	zend_bool active;

	void *saved_fpu_cw;

	void *reserved[ZEND_MAX_RESERVED_RESOURCES];
};

typedef struct _zend_executor_globals zend_executor_globals;
