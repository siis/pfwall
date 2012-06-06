
typedef struct variable {
  char *name;			/* Symbol that the user types. */
  char *value;			/* Value that is returned. */
  char *exportstr;		/* String for the environment. */
  void *dynamic_value;	/* Function called to return a `dynamic'
				   value for a variable, like $SECONDS
				   or $RANDOM. */
  void *assign_func; /* Function called when this `special
				   variable' is assigned a value in
				   bind_variable. */
  int attributes;		/* export, readonly, array, invisible... */
  int context;			/* Which context this variable belongs to. */
} SHELL_VAR;

typedef struct bucket_contents {
  struct bucket_contents *next;	/* Link to next hashed key in this bucket. */
  char *key;			/* What we look up. */
  void *data;			/* What we really want. */
  unsigned int khash;		/* What key hashes to */
  int times_found;		/* Number of times this item has been found. */
} BUCKET_CONTENTS;

typedef struct hash_table {
  BUCKET_CONTENTS **bucket_array;	/* Where the data is kept. */
  int nbuckets;			/* How many buckets does this table have. */
  int nentries;			/* How many entries does this table have. */
} HASH_TABLE;

/* A variable context. */
typedef struct var_context {
  char *name;		/* empty or NULL means global context */
  int scope;		/* 0 means global context */
  int flags;
  struct var_context *up;	/* previous function calls */
  struct var_context *down;	/* down towards global context */
  HASH_TABLE *table;		/* variables at this scope */
} VAR_CONTEXT;
VAR_CONTEXT *shell_variables = (VAR_CONTEXT *)NULL;

typedef long long	arrayind_t;

enum atype {array_indexed, array_assoc};

typedef struct array_element {
	arrayind_t	ind;
	char	*value;
	struct array_element *next, *prev;
} ARRAY_ELEMENT;

typedef struct array {
	enum atype	type;
	arrayind_t	max_index;
	int		num_elements;
	struct array_element *head;
} ARRAY;

struct cmd_type {
  int flags;
  int line;	/* generally used for error messages */
};

enum command_type { cm_for, cm_case, cm_while, cm_if, cm_simple, cm_select,
                    cm_connection, cm_function_def, cm_until, cm_group,
                    cm_arith, cm_cond, cm_arith_for, cm_subshell, cm_coproc };

/* What a command looks like. */
typedef struct command {
  enum command_type type;	/* FOR CASE WHILE IF CONNECTION or SIMPLE. */
  int flags;			/* Flags controlling execution environment. */
  int line;			/* line number the command starts on */
  void *redirects;		/* Special redirects for FOR CASE, etc. */
  union {
    void *For;
    void *Case;
    void *While;
    void *If;
    void *Connection;
    void *Simple;
    void *Function_def;
    void *Group;
    struct cmd_type *Select;
    struct cmd_type *Arith;
    struct cmd_type *Cond;
    struct cmd_type *ArithFor;
    void *Subshell;
    void *Coproc;
  } value;
} COMMAND;

#define HASH_ENTRIES(ht)	((ht) ? A(ht, O(ht, nentries)) : 0)
#define HASH_BUCKET(s, t, h) (((h) = hash_string (s)) & (A((t), O(t, nbuckets)) - 1))

#define STREQ(a, b) ((a)[0] == (b)[0] && strcmp(a, b) == 0)

#define array_cell(var)		(ARRAY *)(A((var), O((var), value)))

#define array_num_elements(a)	(A((a), O((a), num_elements)))
#define array_max_index(a)	(A((a), O((a), max_index)))
#define array_head(a)		(A((a), O((a), head)))
#define array_empty(a)		(A((a), O((a), num_elements)) == 0)

#define element_value(ae)	(A((ae), O((ae), value)))
#define element_index(ae)	(A((ae), O((ae), ind)))
#define element_forw(ae)	(A((ae), O((ae), next)))
#define element_back(ae)	(A((ae), O((ae), prev)))
