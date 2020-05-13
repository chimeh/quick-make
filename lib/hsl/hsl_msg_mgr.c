#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <net/ip_fib.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/igmp.h>
#include <linux/mroute.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <linux/ctype.h>

#include "hsl_tlv.h"
#include "netl_netlink.h"
#include "netlk_comm.h"
#include "hsl_msg_nl_type.h"
#include "hsl_msg_mgr.h"
#include "hsl_logger.h"
#include "hsl_msg_header.h"

static struct hsl_msg_mgr_handler hsl_msg_mgr;

static int hsl_msg_process_misc(struct socket *sock, struct netl_nlmsghdr *nlhdr, unsigned char *msg, unsigned int msglen)
{
    unsigned char  **pnt;
    u_int32_t size_var;
    u_int32_t *size;
    u_int32_t process_size;
    u_int32_t remain_size;
    unsigned char *sp;
    
    unsigned short tlv_type;
    unsigned short tlv_length;
    unsigned short table_id;
    unsigned short op_type;
    
    int ret = 0;
    size = &size_var;
    pnt = &msg;
    
    *size = msglen;
    process_size = 0;
    remain_size = msglen;
    sp = *pnt;
    
    /* Check size. */
    if (*size <  HSL_MSG_MISC_HEADER_SIZE)
        goto hsl_msg_pkt_too_small;

    TLV_DECODE_GETW(tlv_type);
    TLV_DECODE_GETW(tlv_length);
    TLV_DECODE_GETW(table_id);
    TLV_DECODE_GETW(op_type);
    
    process_size =  *pnt - sp;
    remain_size =  (msglen - process_size);
    
    if (table_id > HSL_MISC_MAX_TABLE || op_type > HSL_MISC_MAX_FUNCTIONS)
    {
        printk("invalid PTS_TLV! max table-id[%d], max[oper_type %d]; input table[%d], operation[%d]",
            HSL_MISC_MAX_TABLE, HSL_MISC_MAX_FUNCTIONS, table_id, op_type);
        goto hsl_msg_invalid_misc_id;
    }
    if (HSL_MSG_CB_CHECK(hsl_msg_mgr, misc_cb, table_id, op_type))
    {
        ret = HSL_MSG_CB_CALL(hsl_msg_mgr, misc_cb, table_id, op_type)(sock, nlhdr, *pnt,  remain_size);
    }
    return ret;
hsl_msg_pkt_too_small:
    printk("hsl_msg_pkt_too_small");
    return 0;
hsl_msg_invalid_misc_id:
    printk("hsl_msg_invalid_misc_id");
    return 0;

}

int hsl_msg_mgr_db_cb_register_name(HSL_MSG_MGR_CALLBACK cb, unsigned short table_id, unsigned short op,
                                           char *fname, char *tlbname, char *note)
{
	if (table_id >= HSL_DB_MAX_TABLE || op >= HSL_DB_MAX_FUNCTIONS)
		return -1;
		
	memset(&hsl_msg_mgr.db_cb[table_id][op], 0, sizeof(HSL_MSG_MGR_CALLBACK_ENTRY));
	hsl_msg_mgr.db_cb[table_id][op].f = cb;
	hsl_msg_mgr.db_cb[table_id][op].fname = fname;
	hsl_msg_mgr.db_cb[table_id][op].tblname = tlbname;
	hsl_msg_mgr.db_cb[table_id][op].note = note;
	return 0;
}
int hsl_msg_process_db(struct socket *sock, struct netl_nlmsghdr *nlhdr, unsigned char *msg, unsigned int msglen)
{
    unsigned char  **pnt;
    u_int32_t size_var;
    u_int32_t *size;
    u_int32_t process_size;
    u_int32_t remain_size;
    unsigned char *sp;
    
    unsigned short tlv_type;
    unsigned short tlv_length;
    unsigned short table_id;
    unsigned short op_type;
    
    int ret;
    size = &size_var;
    pnt = &msg;
    
    *size = msglen;
    process_size = 0;
    remain_size = msglen;
    sp = *pnt;
    
    /* Check size. */
    if (*size <  HSL_MSG_DB_HEADER_SIZE)
        goto hsl_msg_pkt_too_small;

    if(1) {
        printk("HSL_MSG_DB_HEADER_SIZE:\n");
        hsl_log_dump_hex8(msg, HSL_MSG_DB_HEADER_SIZE);
    }
    
    TLV_DECODE_GETW(tlv_type);
    TLV_DECODE_GETW(tlv_length);
    TLV_DECODE_GETW(table_id);
    TLV_DECODE_GETW(op_type);

    if(msglen != tlv_length) {
        printk("msglen %d, tlv_length %d, should eq\n", msglen, tlv_length);
    }
    process_size =  *pnt - sp;
    remain_size =  (msglen - process_size);
    
    if (table_id > HSL_DB_MAX_TABLE || op_type > HSL_DB_MAX_FUNCTIONS)
    {
        printk("invalid PTS_TLV! max table-id[%d], max[oper_type %d]; input table[%d], operation[%d]",
            HSL_DB_MAX_TABLE, HSL_DB_MAX_FUNCTIONS, table_id, op_type);
        goto hsl_msg_invalid_db_id;
    }
    if (HSL_MSG_CB_CHECK(hsl_msg_mgr, db_cb, table_id, op_type))
    {
        ret = HSL_MSG_CB_CALL(hsl_msg_mgr, db_cb, table_id, op_type)(sock, nlhdr, *pnt,  remain_size);
    }
    
    return 0;
    
hsl_msg_pkt_too_small:
    printk("hsl_msg_pkt_too_small");
    return 0;
hsl_msg_invalid_db_id:
    printk("hsl_msg_invalid_db");
    return 0;
}

int hsl_msg_mgr_misc_cb_register_name(HSL_MSG_MGR_CALLBACK cb, unsigned short table_id, unsigned short op,
                                           char *fname, char *tlbname, char *note)
{
	if (table_id >= HSL_MISC_MAX_TABLE || op >= HSL_MISC_MAX_FUNCTIONS)
		return -1;
		
	memset(&hsl_msg_mgr.misc_cb[table_id][op], 0, sizeof(HSL_MSG_MGR_CALLBACK_ENTRY));
	hsl_msg_mgr.misc_cb[table_id][op].f = cb;
	hsl_msg_mgr.misc_cb[table_id][op].fname = fname;
	hsl_msg_mgr.misc_cb[table_id][op].tblname = tlbname;
	hsl_msg_mgr.misc_cb[table_id][op].note = note;
	return 0;
}

int
hsl_msg_process (struct socket *sock, char *buf, int buflen)
{
    struct netl_nlmsghdr *nlhdr;
    u_char *msg;
    u_char *pnt; 
    u_int32_t msglen;
    
    nlhdr = (struct netl_nlmsghdr *)buf;
    msg = buf + sizeof (struct netl_nlmsghdr);
    pnt = (u_char *)msg;
    msglen = nlhdr->nlmsg_len - NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE);
/*
    if (sock->ops) {
        struct module *owner = sock->ops->owner;
        printk("module ref %p\n", owner);
        if(owner) {
            printk("module ref %d\n", module_refcount(owner));
        }
    }
*/
    printk("hsl_process_msg() type %d\n", nlhdr->nlmsg_type);
    switch (nlhdr->nlmsg_type) {
    case HSL_NETL_NLMSG_DB:
         hsl_msg_process_db(sock, nlhdr, msg, msglen);
         NETLK_MSG_PROCESS_RETURN_WITH_VALUE (sock, nlhdr, 0);
    break;
    case HSL_NETL_NLMSG_EVENT: /* EVENT only HSL to other */
        goto not_implement;
    break;
    case HSL_NETL_NLMSG_MISC:
        hsl_msg_process_misc(sock, nlhdr, msg, msglen);
    break;
    default:
        printk("hsl_process_msg() unknown type %d\n", nlhdr->nlmsg_type);
        NETLK_MSG_PROCESS_RETURN_WITH_VALUE (sock, nlhdr, 0);
    }
    return 0;

not_implement:
    printk("hsl_process_msg() not_implement type %d\n", nlhdr->nlmsg_type);
    return 0;
}

int hsl_msg_op_dump(      struct socket *sock,
                            struct netl_nlmsghdr *nlhdr,
                            unsigned char *msg,
                            unsigned int msglen)
{
    printk("nlmsg_len %d\n", nlhdr->nlmsg_len);
    printk("nlmsg_type %d\n", nlhdr->nlmsg_type);
    printk("nlmsg_flags %d\n", nlhdr->nlmsg_flags);
    printk("nlmsg_seq %d\n", nlhdr->nlmsg_seq);
    printk("nlmsg_pid %d\n", nlhdr->nlmsg_pid);
    
    hsl_log_dump_hex8(msg, msglen);
    return 0;
}

int hsl_msg_cb_init(void)
{
    int i;
    int j;
    memset(&hsl_msg_mgr, 0 ,sizeof(hsl_msg_mgr));
    
    hsl_msg_mgr.db_set.setname = "db_set";
    hsl_msg_mgr.db_set.cb = &hsl_msg_mgr.db_cb[0][0];
    hsl_msg_mgr.db_set.tbl_size = HSL_DB_MAX_TABLE;
    hsl_msg_mgr.db_set.op_size = HSL_DB_MAX_FUNCTIONS;
    for (i = 0; i < HSL_DB_MAX_TABLE; i++ ) {
        for (j = 0; j < HSL_DB_MAX_FUNCTIONS; j++ ) {
            hsl_msg_mgr_db_cb_register(hsl_msg_op_dump, i, j, "default cb");
        }           
    }

    hsl_msg_mgr.misc_set.setname = "misc_set";
    hsl_msg_mgr.misc_set.cb = &hsl_msg_mgr.misc_cb[0][0];
    hsl_msg_mgr.misc_set.tbl_size = HSL_MISC_MAX_TABLE;
    hsl_msg_mgr.misc_set.op_size = HSL_MISC_MAX_FUNCTIONS;
    for (i = 0; i < HSL_MISC_MAX_TABLE; i++ ) {
        for (j = 0; j < HSL_MISC_MAX_FUNCTIONS; j++ ) {
            hsl_msg_mgr_misc_cb_register(hsl_msg_op_dump, i, j, "default cb");
        }           
    }

    return 0;
}

int hsl_msg_cbset_iter(HSL_MSG_MGR_CALLBACK_SET *pset, int (*apply) (const char *setname, unsigned int tbl_id, unsigned int op_id, HSL_MSG_MGR_CALLBACK_ENTRY *cbe))
{
    int i;
    int j;
    for (i = 0; i < pset->tbl_size; i++ ) {
        for (j = 0; j < pset->op_size; j++ ) {
            if(apply) {
                (*apply)(pset->setname, i, j, &pset->cb[pset->op_size*i + j]);
            }
        }           
    }
    return 0;
}


int hsl_msg_cb_show_entry(const char *setname, unsigned int tbl_id, unsigned int op_id, HSL_MSG_MGR_CALLBACK_ENTRY *cbe)
{
    if(cbe) {
        printk("%s[%2d][%2d] = %p = {%p, %s, %s, %s}\n", setname, tbl_id, op_id, cbe, cbe->f, cbe->fname, cbe->tblname, cbe->note);
    }
    return 0;
}
int hsl_msg_cb_show_all(void)
{
    hsl_msg_cbset_iter(&hsl_msg_mgr.db_set, hsl_msg_cb_show_entry);
    hsl_msg_cbset_iter(&hsl_msg_mgr.misc_set, hsl_msg_cb_show_entry);
    return 0;
}



