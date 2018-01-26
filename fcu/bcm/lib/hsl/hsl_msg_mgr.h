#ifndef __HSL_LMSG_MGR_H
#define __HSL_LMSG_MGR_H

#include <netl_netlink.h>

#define HSL_SET_MAX_TABLE              100
#define HSL_SET_MAX_FUNCTIONS          4

#define HSL_DB_MAX_TABLE               100
#define HSL_DB_MAX_FUNCTIONS           4

#define HSL_EVENT_MAX_TABLE            1
#define HSL_EVENT_MAX_FUNCTIONS        1

#define HSL_MISC_MAX_TABLE             1
#define HSL_MISC_MAX_FUNCTIONS         8

typedef int (*HSL_MSG_MGR_CALLBACK) (
                                    struct socket *,
                                    struct netl_nlmsghdr *hdr,
                                    unsigned char *msgbuf,
                                    unsigned int msglen
                                    );


typedef struct HSL_MSG_MGR_CALLBACK_ENTRY_S {
    HSL_MSG_MGR_CALLBACK f;
    const char *fname;
    const char *tblname;
    const char *note;
} HSL_MSG_MGR_CALLBACK_ENTRY ;

typedef struct HSL_MSG_MGR_CALLBACK_SET_S {
    unsigned int tbl_size;
    unsigned int op_size;
    const char *setname;
    HSL_MSG_MGR_CALLBACK_ENTRY *cb;
} HSL_MSG_MGR_CALLBACK_SET ;

struct hsl_msg_mgr_handler {
    HSL_MSG_MGR_CALLBACK_SET db_set;
    HSL_MSG_MGR_CALLBACK_ENTRY db_cb[HSL_DB_MAX_TABLE][HSL_DB_MAX_FUNCTIONS];
    HSL_MSG_MGR_CALLBACK_SET misc_set;
    HSL_MSG_MGR_CALLBACK_ENTRY misc_cb[HSL_MISC_MAX_TABLE][HSL_MISC_MAX_FUNCTIONS];
};


#define HSL_MSG_CB_CHECK(mgr, obj, tbl, op) (mgr.obj && mgr.obj[tbl][op].f)
#define HSL_MSG_CB_CALL(mgr, obj, tbl, op) (mgr.obj[tbl][op].f)
#define HSL_MSG_CB_STR(mgr, obj, tbl, op) (mgr.obj[tbl][op].f)
int hsl_msg_mgr_db_cb_register_name(HSL_MSG_MGR_CALLBACK cb, unsigned short table_id, unsigned short op,
                                           char *fname, char *opname, char *note);

int hsl_msg_mgr_misc_cb_register_name(HSL_MSG_MGR_CALLBACK cb, unsigned short table_id, unsigned short op,
                                           char *fname, char *opname, char *note);
                                           


                                          
#define HSL_MSG_STR(x) #x
#define hsl_msg_mgr_db_cb_register(cb,table_id, op, note) \
    hsl_msg_mgr_db_cb_register_name(cb, table_id, op, HSL_MSG_STR(cb), HSL_MSG_STR(table_id##op), note)

#define hsl_msg_mgr_misc_cb_register(cb,table_id, op, note) \
    hsl_msg_mgr_misc_cb_register_name(cb, table_id, op, HSL_MSG_STR(cb), HSL_MSG_STR(table_id##op), note)

int hsl_msg_cb_show_all(void);

#endif
