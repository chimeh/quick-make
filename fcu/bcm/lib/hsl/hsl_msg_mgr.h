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

typedef int (*HSL_MSG_DB_CALLBACK) (
                                    struct socket *,
                                    struct netl_nlmsghdr *hdr,
                                    unsigned char *msgbuf,
                                    unsigned int msglen
                                    );
typedef int (*HSL_MSG_EVENT_CALLBACK) (
                                    struct socket *,
                                    struct netl_nlmsghdr *hdr,
                                    unsigned char *msgbuf,
                                    unsigned int msglen
                                    );
typedef int (*HSL_MSG_MISC_CALLBACK) (
                                    struct socket *,
                                    struct netl_nlmsghdr *hdr,
                                    unsigned char *msgbuf,
                                    unsigned int msglen
                                    );
                                    
struct hsl_msg_mgr_handler {
    HSL_MSG_DB_CALLBACK db_cb[HSL_DB_MAX_TABLE][HSL_DB_MAX_FUNCTIONS];
    HSL_MSG_EVENT_CALLBACK event_cb[HSL_EVENT_MAX_TABLE][HSL_EVENT_MAX_FUNCTIONS];
    HSL_MSG_MISC_CALLBACK misc_cb[HSL_MISC_MAX_TABLE][HSL_MISC_MAX_FUNCTIONS];
};


#define HSL_MSG_CB_CHECK(mgr, obj, tbl, op) (mgr.obj && mgr.obj[tbl][op])
#define HSL_MSG_CB_CALL(mgr, obj, tbl, op) (mgr.obj[tbl][op])

int hsl_msg_register_db_cb(HSL_MSG_DB_CALLBACK cb	, unsigned short table_id, unsigned short op);
int hsl_msg_register_misc_cb(HSL_MSG_MISC_CALLBACK cb	, unsigned short table_id, unsigned short op);
#endif