#ifndef _BCM_CAP_H_
#define _BCM_CAP_H_
#include "hal/layer4/hal_l4_config.h"
#include "layer4/pbmp.h"
#include "ctc_api.h"
#define  MAX_LC_NUM                1
#define  BEGIN_LC_NUM              1
#define  DEFAULT_UNIT              0

#ifndef true
#define TRUE 1
#endif
#ifndef false
#define FALSE 0
#endif

#ifndef OK
#define OK 0
#endif
#ifndef ERROR
#define ERROR -1
#endif

#define	 BCM_PBMP_MASK	           0xFFFFFFFF
#define  BCM_PORT_MASK	           0xFFFFFFFF

extern int get_bits_num(int entry);
extern int get_offset_mask(int entry);

#define  GET_BITS_NUM(entry)     get_bits_num(entry)
#define  GET_OFFSET_MASK(entry)  get_offset_mask(entry) 

#define  IFP_EID_OFFSET   0x0

#define	IFP_BLOCK_TO_EID(SLICE, OFFSET) \
	(((SLICE) << 16) + (OFFSET))

#define	EID_TO_IFP_BLOCK(EID) \
	(((EID)&0xff0000)>>16)
	
#define	EID_TO_IFP_OFFSET(EID) \
	((EID)&0xffff)


/*CTC交换芯片TCAM block使用规划*/
#define CTC_ACL_DEFAULT_BLOCK_BEGIN		0
#define CTC_ACL_DEFAULT_BLOCK_END	(CTC_ACL_EAP_BLOCK_BEGIN - 1)
#define CTC_ACL_EAP_BLOCK_BEGIN	((CTC_ACL_BOLCK_PER_UNIT)-(EAP_RULE_BLOCK_NUMBER))
#define CTC_ACL_EAP_BLOCK_END	(CTC_ACL_BOLCK_PER_UNIT - 1)

/*group id 使用规划*/
#define CTC_ACL_DEFAULT_GROUP_BEGIN	(CTC_ACL_EAP_GROUP_END + 1)
#define CTC_ACL_DEFAULT_GROUP_END	CTC_ACL_GROUP_ID_MAX
#define CTC_ACL_EAP_GROUP_BEGIN	(CTC_ACL_GROUP_ID_HASH_IPV4 + 1)
#define CTC_ACL_EAP_GROUP_END	(CTC_ACL_EAP_GROUP_BEGIN + CTC_ENTRY_PER_BLOCK*EAP_RULE_BLOCK_NUMBER)

enum {
	CS_IFP_RULE,
	/* ifp rule type is here */
	CS_DEFAULT_ACL,
	CS_IFP_VLAN_IP_ACL,
	CS_IFP_IP_ACL,
	CS_EFP_IP_ACL,
	CS_VFP_IP_ACL,
	CS_IFP_MAC_ACL,
	CS_QOS_IP_IN,
	CS_QOS_IP_OUT,
	CS_QOS_IPV6_IN,
	CS_QOS_IPV6_OUT,
	CS_MIRROR_RULE,
	CS_IFP_OF_ACL,



	CS_EFP_RULE,
	/* efp rule type is here */
	
	CS_VFP_RULE,
	CS_VFP_QINQ_RULE,
    CS_VFP_OF_ACL,

	/* vfp rule type is here */


	CS_EAP_ACL,

	MAX_CAP_SUB,
};

typedef struct list_s {
	struct list_head list;
	int value;
	void *data;
} list_t;

typedef struct cap_sub_name_s {
	int	type;
	char *name;
} cap_sub_name_t;

typedef struct cap_group_s {
	int	type;
	int	gid;
	int	slice;
	int pri;
	int	free_entry;
	char used[CTC_ENTRY_PER_BLOCK];
} cap_group_t;

struct cap_info_s;
typedef struct cap_sub_info_s {
	int	type;
	struct cap_info_s	*cap;
} cap_sub_info_t;

typedef struct cap_info_s {
	int	slot;
	int	unit;

	int	ifp_max_slice;
	int	efp_max_slice;
	int	vfp_max_slice;
	

	int	entry_per_ifp_slice;
	int	entry_per_efp_slice;
	int	entry_per_vfp_slice;
	

	cap_group_t	ifp_slice[CTC_ACL_BOLCK_PER_UNIT];

	struct list_head policer;
	struct list_head group_id;
	struct list_head last_build;
	cap_sub_info_t sub[MAX_CAP_SUB];

} cap_info_t;

typedef struct cap_stat_group_s {
	int	type;
	int	entry_used;
	int	entry_free;
} cap_stat_group_t;

typedef struct cap_stat_s {
	cap_stat_group_t ifp_slice[CTC_ACL_BOLCK_PER_UNIT];
} cap_stat_t;




extern int policer_id_create(void);
extern void policer_id_reset(void);
extern int policer_list_add(cap_info_t *cap, uint32 val, void *data);
extern int policer_list_clear(struct list_head *list);

extern int group_id_list_add(cap_info_t *cap, uint32 group_id);
extern int group_id_create(void);
int eap_group_id_get(unsigned int eid);
extern void group_id_reset(void);
extern char *cap_sub_name_get(int sub_type);
extern cap_info_t *cap_info_get(int slot);
extern cap_info_t *cap_info_get_by_ifindex(u16 ifindex);
extern int cap_info_lock(void);
extern int cap_info_unlock(void);
extern int cap_init(void);
extern int cap_add_last_build(cap_info_t *cap, uint32 eid);
extern int cap_reset_last_build(cap_info_t *cap);
extern int cap_clear_last_build(cap_info_t *cap);
extern void cap_free_entry(cap_info_t *cap, uint32 eid);
extern void cap_free_entry_id(cap_info_t *cap, uint32 eid);
extern void cap_free_entry_cluster(cap_info_t *cap, struct list_head  *list);
extern void cap_free_list(struct list_head  *list);
extern void cap_clear_one(cap_info_t *cap);
extern void cap_clear_all(void);
extern uint32 cap_alloc_entry(cap_sub_info_t *sub, int *group_id);
extern uint32 cap_alloc_group(int num);
extern struct list_head *cap_alloc_entry_cluster(cap_sub_info_t *sub, int num, int *group_id);
extern int cap_get_stat(int slot, cap_stat_t *s);
extern int bcm_rule_build_begin(void);
extern int bcm_rule_build_finish(void);
extern int cap_check_free_ifp_entry(cap_sub_info_t *sub, int need_entry);
extern int cap_check_vlan_ip_acl_free_entry(cap_sub_info_t *sub, int need_entry);
extern int cap_check_ipmac_acl_free_entry(cap_sub_info_t *sub, int need_entry);

extern int hsl_layer4_init(void);
//extern int ifindexpbmp_2_lplist(l4_pbmp_t *ifindexpbmp,  bcmx_lplist_t *lplist);
extern int vlanifindex_2_vid(int vlanifindex,  u16 *vid);

#endif

