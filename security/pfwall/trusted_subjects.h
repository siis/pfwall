extern int read_like(u16, u32);
#ifdef PFWALL_MATCH_STR
extern int ts_find_subject(char*);
#endif
#ifdef PFWALL_MATCH_REPR
extern int ts_find_subject(u32);
extern int type_to_sid(char *type, int *sid, int which);
#endif
extern int ts_find_ttype(char*, char*, char*);
extern int ts_find_tip(char*, char*, char*, unsigned long);
extern int ts_add_tip(char*, char*, char*, unsigned long);
extern char *context_to_type (char *);
