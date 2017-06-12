/* Copyright (C) 2004-2005 IP Infusion, Inc.  All Rights Reserved. */
#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"


/* HAL includes. */
#include "hal_netlink.h"
#include "hal_msg.h"

/* HSL includes.*/
#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"
#include "hsl_ctc_pkt.h"
#include "hsl_comm.h"
#include "hsl_msg.h"
#include "hsl_ctc_if.h"

#include <linux/kernel.h>
//#include "bcm/field.h"
//#include "bcm/types.h"
//#include "bcm/error.h"
//#include "sal/core/sync.h"
#include <linux/list.h>
#include <linux/types.h>
#include "hsl_oss.h"
#include "bcm_cap.h"
#include "bcm_l4_debug.h"
#include "hal/layer4/hal_l4_config.h"
#include "layer4/pbmp.h"
#include "ctc_api.h"
#include "ctc_if_portmap.h"
#include "auth_rule_build.h"


#include "hsl_hash.h"
#include "ctc_api.h"
#include "bcm_cap.h"
#include "auth_rule_build.h"
#include "bcm_l4_debug.h"
#include "hal_netlink.h"

  


typedef struct ctc_eap_user_info_s {
	unsigned int ip;
	unsigned int port; 
	unsigned int slot;
	char mode;
	unsigned int pri;
	int gid;
	int eid;
}ctc_eap_user_info_t;



static ctc_port_bitmap_t eap_port_map;
static struct hash *eap_user_table = NULL;
static int default_rule_gid = -1;
static int default_rule_eid = -1;

#define CTC_IS_BIT_SET(flag, bit)   (((flag) & (1 << (bit))) ? 1 : 0)
#define CTC_BIT_SET(flag, bit)      ((flag) = (flag) | (1 << (bit)))
#define CTC_BIT_UNSET(flag, bit)    ((flag) = (flag) & (~(1 << (bit))))



static u_int32_t hash_key(u_int32_t ip, u_int32_t port)
{
	return ip;
}

static int hash_cmp(void *arg1, void *arg2)
{
	ctc_eap_user_info_t *user1;
	ctc_eap_user_info_t *user2;

	if (NULL == arg1 || NULL == arg2) {
		return 0;
	}

	user1 = (ctc_eap_user_info_t *)arg1;
	user2 = (ctc_eap_user_info_t *)arg2;
	
	if (user1->ip != user2->ip) {
		return 0;
	}

	return 1;
	
}

static void *alloc_func(void *data)
{
	ctc_eap_user_info_t *user;
	ctc_eap_user_info_t *new_user;

	if (NULL == data) {
		return NULL;
	}

	user = (ctc_eap_user_info_t *)data;

	new_user = oss_malloc(sizeof(ctc_eap_user_info_t), OSS_MEM_HEAP);
	if (NULL == new_user) {
		return NULL;
	}
	memset(new_user, 0, sizeof(ctc_eap_user_info_t));

	new_user->ip = user->ip;
	new_user->port = user->port;
	new_user->slot = user->slot;
	new_user->mode = user->mode;
	new_user->pri  = user->pri;
	new_user->gid  = user->gid;
	new_user->eid  = user->eid;


	return new_user;
}

int ctc_eap_default_rule_build(ctc_port_bitmap_t *port_map)
{
	cap_sub_info_t	*sub;
	cap_info_t	*cap;
	int slot;
	int ret;
	uint32 entry_id;
	uint32 group_id;	
	uint32 block_id;	
	ctc_acl_entry_t ctc_entry;
	ctc_acl_group_info_t ctc_group;	

	if (NULL == port_map) {
		printk("param error\r\n");
		return -1;
	}

	slot = 0;	//当前代码仅运行在板卡上，不会进行slot管理，这里默认都时0.
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_EAP_ACL];

	memset(&ctc_group, 0, sizeof(ctc_group));
	memcpy(ctc_group.un.port_bitmap, port_map, sizeof(ctc_port_bitmap_t));
	ctc_group.type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;	
	//ctc_group.type = CTC_ACL_GROUP_TYPE_GLOBAL;		
	ctc_group.dir = CTC_INGRESS;
	ctc_group.lchip = 0;	

	if (-1 == default_rule_eid) {
		entry_id = cap_alloc_entry(sub, &block_id);
		if (-1 == entry_id) {
			printk("can not alloc eap entry\r\n");
			return -1;
		}
	} else {
		entry_id = default_rule_eid;
		block_id = EID_TO_IFP_BLOCK(entry_id);
	}
	ctc_group.priority = block_id;

	if (-1 == default_rule_gid) {
		group_id = eap_group_id_get(entry_id);
		if (-1 == group_id) {
			printk("get eap group id fail\r\n");
			goto FREE_ENTRY_ID;
		}
	} else {
		group_id = default_rule_gid;
	}

	ret = ctc_acl_create_group(group_id, &ctc_group);
	if (CTC_E_NONE != ret) {
		printk("ctc_acl_create_group, rc = %d\r\n", ret);
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ifp group create fail, ret = %d\n\r", ret);
		goto FREE_ENTRY_ID;		
	}

	memset(&ctc_entry, 0, sizeof(ctc_entry));
	ctc_entry.entry_id = entry_id;
	ctc_entry.key.type = CTC_ACL_KEY_IPV4;
	ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IPV4_PACKET;
	ctc_entry.key.u.ipv4_key.ipv4_packet = 1;	

	/*entry优先级*/
	ctc_entry.priority_valid = TRUE;
	ctc_entry.priority = EAP_DEFAULT_RULE_PRI;


	ctc_entry.action.flag = CTC_ACL_ACTION_FLAG_DISCARD;


	ret = ctc_acl_add_entry(group_id, &ctc_entry);
	if (CTC_E_NONE != ret) {
		printk("entry add fail, eid = %#x\r\n", entry_id);
		goto FREE_GROUP;		
	}


	ret = ctc_acl_install_entry(entry_id);
	if (ret) {
		printk("install eap entry fail, eid = %#x\r\n", entry_id);
		goto FREE_GROUP;
	}

	/*默认规则的group_id，始终不变*/
	if (-1 == default_rule_gid) {
		default_rule_gid = group_id;
	}

	/*默认规则的entry_id，始终不变*/
	if (-1 == default_rule_eid) {
		default_rule_eid = entry_id;
	}
	


	return 0;

FREE_GROUP:
	ctc_acl_uninstall_group (group_id);
	ctc_acl_destroy_group (group_id);
	
FREE_ENTRY_ID:
	cap_free_entry_id(cap, entry_id);
	return -1;	
	
}

void ctc_eap_default_rule_destroy(void)
{
	cap_sub_info_t	*sub;
	cap_info_t	*cap;
	int slot;
	int ret;

	if (-1 == default_rule_gid || -1 == default_rule_eid) {
		return ;
	}

	slot = 0;	//当前代码仅运行在板卡上，不会进行slot管理，这里默认都时0.
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_EAP_ACL];

	
	/*清除entry*/
	ret = ctc_acl_uninstall_entry(default_rule_eid);
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap uninstall eap entry failed: ret = %d\n\r", ret);
	}

	ret = ctc_acl_remove_entry(default_rule_eid);
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap remove eap entry failed: ret = %d\n\r", ret);
	}
	
	/*清除group*/
	ret = ctc_acl_uninstall_group (default_rule_gid);
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap remove eap group failed: ret = %d\n\r", ret);
	}

	ctc_acl_destroy_group (default_rule_gid);	
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap destroy eap group failed: ret = %d\n\r", ret);
	}
}


static int _ctc_eap_cond_port(void *arg1, void *arg2)
{
	int ret;
	u_int32_t port;
	ctc_eap_user_info_t	*user_info;
	if (NULL == arg1 || NULL == arg2) {
		return 0;
	}

	port = *((u_int32_t *)arg2);
	user_info = (ctc_eap_user_info_t *)(arg1);

	if (port != user_info->port) {
		return 0;
	}

	return 1;
	

}

static void _ctc_eap_free_user(void *arg)
{
	int ret;
	ctc_eap_user_info_t	*user_info;
	user_info = (ctc_eap_user_info_t *)(arg);
	
	ret = hsl_eap_user_delete(user_info->ip, user_info->mode);
	if (ret) {
		printk("delete user(%#x) fail\r\n", user_info->ip);
	}

	//printk("delete user %#x from port %d\r\n", user_info->ip, user_info->port);
}


void ctc_eap_clear_user_on_port(u_int32_t port)
{
	hash_clean_cond(eap_user_table, _ctc_eap_cond_port, &port, _ctc_eap_free_user);
}

int ctc_eap_user_rule_build(ctc_eap_user_info_t *user_info)
{
	cap_sub_info_t	*sub;
	cap_info_t	*cap;
	int slot;
	int ret;
	uint32 entry_id;
	uint32 group_id;
	uint32 block_id;	
	ctc_acl_entry_t ctc_entry;
	ctc_acl_group_info_t ctc_group;	


	if (NULL == user_info) {
		printk("param error\r\n");
		return -1;
	}

	slot = user_info->slot;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_EAP_ACL];

	memset(&ctc_group, 0, sizeof(ctc_group));
	CTC_BIT_SET(ctc_group.un.port_bitmap[user_info->port /CTC_UINT32_BITS], (user_info->port %CTC_UINT32_BITS));
	ctc_group.type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;	
	//ctc_group.type = CTC_ACL_GROUP_TYPE_GLOBAL;	
	ctc_group.dir = CTC_INGRESS;
	ctc_group.lchip = 0;	

	entry_id = cap_alloc_entry(sub, &block_id);
	if (-1 == entry_id) {
		printk("can not alloc eap entry\r\n");
		return -1;
	}
	ctc_group.priority = block_id;
	group_id = eap_group_id_get(entry_id);
	if (-1 == group_id) {
		printk("get eap group id fail\r\n");
		goto FREE_ENTRY_ID;
	}
	ret = ctc_acl_create_group(group_id, &ctc_group);
	if (CTC_E_NONE != ret) {
		printk("ctc_acl_create_group, rc = %d\r\n", ret);
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ifp group create fail, ret = %d\n\r", ret);
		goto FREE_ENTRY_ID;		
	}

	memset(&ctc_entry, 0, sizeof(ctc_entry));
	ctc_entry.entry_id = entry_id;
	ctc_entry.key.type = CTC_ACL_KEY_IPV4;
	ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IPV4_PACKET;
	ctc_entry.key.u.ipv4_key.ipv4_packet = 1;	
	
	/*entry优先级*/
	ctc_entry.priority_valid = TRUE;
	ctc_entry.priority = EAP_USER_RULE_PRI;

	/*精确匹配源IP*/
	ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IP_SA;
	ctc_entry.key.u.ipv4_key.ip_sa = user_info->ip;
	ctc_entry.key.u.ipv4_key.ip_sa_mask = 0xffffffff;



	/*修改报文内部优先级*/
	//ctc_entry.action.priority = user_info->pri;

	
	ret = ctc_acl_add_entry(group_id, &ctc_entry);
	if (CTC_E_NONE != ret) {
		printk("entry add fail, eid = %#x\r\n", entry_id);
		goto FREE_GROUP;		
	}
	printk("ctc_acl_add_entry, group_id = %#x, rc = %d\r\n", group_id, ret);

	ret = ctc_acl_install_entry(entry_id);
	if (ret) {
		printk("install eap entry fail, eid = %#x\r\n", entry_id);
		goto FREE_GROUP;
	}


	user_info->gid = group_id;
	user_info->eid = entry_id;

	return 0;

FREE_GROUP:
	ctc_acl_uninstall_group (group_id);
	ctc_acl_destroy_group (group_id);		
FREE_ENTRY_ID:
	cap_free_entry_id(cap, entry_id);
	return -1;
}

int ctc_eap_user_rule_destroy(ctc_eap_user_info_t *user_info)
{
	int ret;
	cap_sub_info_t	*sub;
	cap_info_t	*cap;
	int slot;	
	//printk("ctc_eap_user_rule_destroy\r\n");

	if (NULL == user_info) {
		printk("param error\r\n");
		return -1;
	}

	slot = user_info->slot;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_EAP_ACL];


	/*清除entry*/
	ret = ctc_acl_uninstall_entry(user_info->eid);
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap uninstall eap entry failed: ret = %d\n\r", ret);
	}

	ret = ctc_acl_remove_entry(user_info->eid);
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap remove eap entry failed: ret = %d\n\r", ret);
	}
	
	ret = ctc_acl_uninstall_group (user_info->gid);
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap remove eap group failed: ret = %d\n\r", ret);
	}

	ret = ctc_acl_destroy_group (user_info->gid);	
	if (CTC_E_NONE != ret) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap destroy eap group failed: ret = %d\n\r", ret);
	}

	/*回收entry id*/
	cap_free_entry_id(cap, user_info->eid);

	return 0;	
}





int hsl_eap_rule_init()
{
	/*初始化端口位图*/
	memset(&eap_port_map, 0, sizeof(eap_port_map));


	/*初始化在线用户表*/
	eap_user_table = hash_create_size (1024, hash_key, hash_cmp);
	if (NULL == eap_user_table) {
		printk("eap user table init fail\r\n");
		return -1;
	}
	
	return 0;
}


/*端口认证使能*/
int hsl_eap_port_enabel(int port)
{
	int ret;

	/*已经使能，直接返回*/
	if (CTC_IS_BIT_SET(eap_port_map[port /CTC_UINT32_BITS], (port %CTC_UINT32_BITS))){
		return 0;
	}

	/*加入端口位图*/
	CTC_BIT_SET(eap_port_map[port /CTC_UINT32_BITS], (port %CTC_UINT32_BITS));

	/*删除现有默认规则*/
	ctc_eap_default_rule_destroy();
	/*重新下发默认规则*/
	ret = ctc_eap_default_rule_build(&eap_port_map);
	if (ret) {
		printk("eap default rule build fault");
		return -1;
	}

	return 0;
}

/*端口认证关闭*/
int hsl_eap_port_disable(int port)
{
	int ret;

	/*未使能，直接返回*/
	if (!CTC_IS_BIT_SET(eap_port_map[port /CTC_UINT32_BITS], (port %CTC_UINT32_BITS))){
		return 0;
	}

	/*从端口位图删除*/
	CTC_BIT_UNSET(eap_port_map[port /CTC_UINT32_BITS], (port %CTC_UINT32_BITS));

	/*清空该接口上的用户*/
	ctc_eap_clear_user_on_port(port);
	
	/*删除现有默认规则*/
	ctc_eap_default_rule_destroy();
	
	/*重新下发默认规则*/
	ret = ctc_eap_default_rule_build(&eap_port_map);
	if (ret) {
		printk("eap default rule build fault");
		return -1;
	}

	return 0;
}

/*添加用户规则*/
int hsl_eap_user_add(unsigned int ip, int port, int pri, int mode)
{
	int ret;
	ctc_eap_user_info_t user_info;
	ctc_eap_user_info_t *tmp_user_info = NULL;

	memset(&user_info, 0, sizeof(user_info));
	user_info.ip = ip;
	user_info.port = port;
	user_info.pri = pri;
	user_info.mode = mode;
	user_info.slot = 0;	//当前代码运行在各板卡上，不管理slot，故slot固定为0
#if 1
	/*检查端口是否已初始化*/
	if (!CTC_IS_BIT_SET(eap_port_map[port /CTC_UINT32_BITS], (port %CTC_UINT32_BITS))){
		printk("this port is not eap port\r\n");
		return -1;
	}
#endif	
	/*下发到硬件*/
	ret = ctc_eap_user_rule_build(&user_info);
	if (ret) {
		printk("eap user rule build fail\r\n");
		return -1;
	}

	/*保存到软件表*/
	tmp_user_info = hash_get(eap_user_table, &user_info, alloc_func);
	if (NULL == tmp_user_info) {
		printk("eap user rule add faile\r\n");
		/*删除硬件表项*/
		ctc_eap_user_rule_destroy(&user_info);
		return -1;
	}

	//printk("user (id=%#x, port=%#x) rule add success\r\n");
	return 0;
}

/*删除用户规则*/
int hsl_eap_user_delete(unsigned int ip, int mode)
{
	int ret;
	ctc_eap_user_info_t user_info;
	ctc_eap_user_info_t *tmp_user_info = NULL;

	memset(&user_info, 0, sizeof(user_info));
	user_info.ip = ip;
	user_info.mode = mode;


	/*用户不存在，直接返回*/
	tmp_user_info = hash_lookup (eap_user_table, &user_info);
	if (NULL == tmp_user_info) {
		printk("user is not exist\r\n");
		return 0;
	}
		
	/*从硬件删除*/
	ret = ctc_eap_user_rule_destroy(tmp_user_info);
	if (ret) {
		printk("eap user rule remove fail\r\n");
		return -1;
	}

	/*从软件表删除*/
	tmp_user_info = hash_release(eap_user_table, &user_info);
	if (NULL != tmp_user_info) {
		oss_free(tmp_user_info, OSS_MEM_HEAP);
	}
	//printk("eap_user_table->count = %d\r\n", eap_user_table->count);
	//printk("user (id=%#x) rule delete success\r\n", ip);
	
	return 0;
}




int hsl_precedence_map_add(unsigned short precedence, unsigned short queue_index)
{
	int ret;
	ctc_qos_queue_cfg_t queue_config;

	/*precedence:0-63, queue:0-63*/
	if (precedence > 63 || queue_index > 63) {
		printk("hsl_precedence_map_add, param error !!!, precedence=%d, queue=%d\r\n",  precedence, queue_index);
		return ERROR;
	}

	memset(&queue_config, 0, sizeof(ctc_qos_queue_cfg_t));
	queue_config.type = CTC_QOS_QUEUE_CFG_PRI_MAP;
	queue_config.value.pri_map.priority = precedence;
	queue_config.value.pri_map.queue_select = queue_index;
	queue_config.value.pri_map.drop_precedence = 3;


	/*既然已经配置失败，即使恢复配置也可能失败，输出警告后，直接返回*/
	queue_config.value.pri_map.color = 1;
	ret = ctc_qos_set_queue(&queue_config);
	if (CTC_E_NONE != ret) {
		printk("precedence %d clolor red map to queue %d fail, ret = %d\r\n", precedence, queue_index, ret);		
		return ERROR;
	}
	
	queue_config.value.pri_map.color = 2;
	ret = ctc_qos_set_queue(&queue_config);
	if (CTC_E_NONE != ret) {
		printk("precedence %d clolor yellow map to queue %d fail, ret = %d\r\n", precedence, queue_index, ret);
		return ERROR;
	}

	queue_config.value.pri_map.color = 3;
	ret = ctc_qos_set_queue(&queue_config);
	if (CTC_E_NONE != ret) {
		printk("precedence %d clolor green map to queue %d fail, ret = %d\r\n", precedence, queue_index, ret);		
		return ERROR;
	}


	return OK;
}

int hsl_precedence_map_delete(unsigned short precedence)
{
	int ret;
	int queue_index;

	queue_index = precedence;

	ret = hsl_precedence_map_add(precedence, queue_index);

	return ret;
}




int hsl_msg_recv_auth_port_enable(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	int port;
	hal_msg_port_enable_t *msg;

	msg = (hal_msg_port_enable_t *)msgbuf;

	port = IFINDEX_TO_GPORT(msg->ifindex);

	ret = hsl_eap_port_enabel(port);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	return 0;	
}

int hsl_msg_recv_auth_port_disable(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	int port;
	hal_msg_port_disable_t *msg;

	msg = (hal_msg_port_disable_t *)msgbuf;

	port = IFINDEX_TO_GPORT(msg->ifindex);

	ret = hsl_eap_port_disable(port);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	return 0;
}




int hsl_msg_recv_eap_rule_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	int port;
	unsigned int srcid;
	hsl_msg_auth_add_t *msg;
	
	msg = (hsl_msg_auth_add_t *)msgbuf;

	port = IFINDEX_TO_GPORT(msg->ifindex);
	srcid = msg->srcid;

	ret = hsl_eap_user_add(srcid, port, 0, 0);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	return 0;
}


int hsl_msg_recv_eap_rule_delete(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	int port;
	unsigned int srcid;
	hsl_msg_auth_delete_t *msg;
	
	msg = (hsl_msg_auth_add_t *)msgbuf;

	port = IFINDEX_TO_GPORT(msg->ifindex);
	srcid = msg->srcid;

	ret = hsl_eap_user_delete(srcid, 0);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	return 0;
}






int hsl_msg_recv_precedence_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	unsigned short precedence;
	unsigned short queue_index;

	hsl_msg_precedence_add_t *msg;
	
	msg = (hsl_msg_precedence_add_t *)msgbuf;

	precedence = msg->precedence;
	queue_index = msg->queue_index;

	ret = hsl_precedence_map_add(precedence, queue_index);
	if (ret) {
		printk("precedence %d map queue %d failed\r\n", precedence, queue_index);
	}


	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	return 0;
	
}


int hsl_msg_recv_precedence_delete(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	unsigned short precedence;

	hsl_msg_precedence_delete_t *msg;
	
	msg = (hsl_msg_precedence_delete_t *)msgbuf;

	precedence = msg->precedence;
	//printk("hsl_msg_recv_precedence_delete, precedence=%d\r\n", precedence);

	ret = hsl_precedence_map_delete(precedence);
	if (ret) {
		printk("precedence %d map delete failed\r\n", precedence);
	}

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	return 0;
	

}




