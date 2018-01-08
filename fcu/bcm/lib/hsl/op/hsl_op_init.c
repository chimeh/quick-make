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
#include "hsl_msg_tlv.h"

#include "op/hsl_op_tableid.h"

extern HSL_MSG_MGR_CALLBACK hsl_xxx_add;
extern HSL_MSG_MGR_CALLBACK hsl_xxx_del;
extern HSL_MSG_MGR_CALLBACK hsl_xxx_update;

extern HSL_MSG_MGR_CALLBACK hsl_idb_add;
extern HSL_MSG_MGR_CALLBACK hsl_idb_del;
extern HSL_MSG_MGR_CALLBACK hsl_idb_update;


void hsl_op_init(void) {
    /* XXX */
    hsl_msg_mgr_db_cb_register(hsl_xxx_add, TABLE_ID_XXX, HSL_TLV_OPERATION_TYPE_ADD, "hsl op");
    hsl_msg_mgr_db_cb_register(hsl_xxx_del, TABLE_ID_XXX, HSL_TLV_OPERATION_TYPE_DEL, "hsl op");
    hsl_msg_mgr_db_cb_register(hsl_xxx_update, TABLE_ID_XXX, HSL_TLV_OPERATION_TYPE_UPDATE, "hsl op");
    
    /* IDB */
    hsl_msg_mgr_db_cb_register(hsl_idb_add, TABLE_ID_IDB, HSL_TLV_OPERATION_TYPE_ADD, "hsl op");
    hsl_msg_mgr_db_cb_register(hsl_idb_del, TABLE_ID_IDB, HSL_TLV_OPERATION_TYPE_DEL, "hsl op");
    hsl_msg_mgr_db_cb_register(hsl_idb_update, TABLE_ID_IDB, HSL_TLV_OPERATION_TYPE_UPDATE, "hsl op");
    
    
}