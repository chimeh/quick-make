#ifndef _BCM_CAP_H_
#define _BCM_CAP_H_
#include "bcmx/lplist.h"
#include "hal/layer4/hal_l4_config.h"
#include "layer4/pbmp.h"
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
#define  EFP_EID_OFFSET   ((BCM_IFP_SLICE_PER_UNIT - 1) << \
							GET_BITS_NUM(BCM_ENTRY_PER_IFP_SLICE) | \
							BCM_ENTRY_PER_IFP_SLICE)
#define  VFP_EID_OFFSET   ((((BCM_EFP_SLICE_PER_UNIT - 1) << \
							GET_BITS_NUM(BCM_ENTRY_PER_EFP_SLICE)) | \
							BCM_ENTRY_PER_EFP_SLICE) + EFP_EID_OFFSET)


#define	IFP_SLICE_TO_EID(SLICE, OFFSET) \
	(((SLICE) << GET_BITS_NUM(BCM_ENTRY_PER_IFP_SLICE) | \
	((OFFSET) & GET_OFFSET_MASK(BCM_ENTRY_PER_IFP_SLICE))) + \
	IFP_EID_OFFSET)
#define	EID_TO_IFP_SLICE(EID) \
	((EID - IFP_EID_OFFSET) >> GET_BITS_NUM(BCM_ENTRY_PER_IFP_SLICE))
#define	EID_TO_IFP_OFFSET(EID) \
	((EID - IFP_EID_OFFSET) & \
	GET_OFFSET_MASK(BCM_ENTRY_PER_IFP_SLICE))


#define	EFP_SLICE_TO_EID(SLICE, OFFSET) \
	(((SLICE) << GET_BITS_NUM(BCM_ENTRY_PER_EFP_SLICE) | \
	((OFFSET) & GET_OFFSET_MASK(BCM_ENTRY_PER_EFP_SLICE))) + \
	EFP_EID_OFFSET)
#define	EID_TO_EFP_SLICE(EID) \
	((EID - EFP_EID_OFFSET) >> \
	GET_BITS_NUM(BCM_ENTRY_PER_EFP_SLICE))
#define	EID_TO_EFP_OFFSET(EID) \
	((EID - EFP_EID_OFFSET) & \
	GET_OFFSET_MASK(BCM_ENTRY_PER_EFP_SLICE))



#define	VFP_SLICE_TO_EID(SLICE, OFFSET) \
	(((SLICE) << GET_BITS_NUM (BCM_ENTRY_PER_VFP_SLICE) | \
 	((OFFSET) & GET_OFFSET_MASK(BCM_ENTRY_PER_VFP_SLICE))) + \
	VFP_EID_OFFSET)
#define	EID_TO_VFP_SLICE(EID) \
	((EID - VFP_EID_OFFSET) >> \
	GET_BITS_NUM (BCM_ENTRY_PER_VFP_SLICE))
#define	EID_TO_VFP_OFFSET(EID) \
	((EID - VFP_EID_OFFSET) & \
	GET_OFFSET_MASK(BCM_ENTRY_PER_VFP_SLICE))


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

	CS_EFP_RULE,
	/* efp rule type is here */
	
	CS_VFP_RULE,
	CS_VFP_QINQ_RULE,
	/* vfp rule type is here */

	MAX_CAP_SUB,
};

typedef struct list_s {
	struct list_head list;
	int value;
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
	char used[MAX_ENTRY_PER_SLICE];
} cap_group_t;

struct cap_info_s;
typedef struct cap_sub_info_s {
	int	type;
	bcm_field_qset_t	qset;
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
	

	cap_group_t	ifp_slice[BCM_IFP_SLICE_PER_UNIT];
	cap_group_t	efp_slice[BCM_EFP_SLICE_PER_UNIT];
	cap_group_t vfp_slice[BCM_VFP_SLICE_PER_UNIT];
		
	struct list_head last_build;
	cap_sub_info_t sub[MAX_CAP_SUB];

	bcm_pbmp_t	pbmp_mask;
	bcm_port_t	port_mask;
} cap_info_t;

typedef struct cap_stat_group_s {
	int	type;
	int	entry_used;
	int	entry_free;
} cap_stat_group_t;

typedef struct cap_stat_s {
	cap_stat_group_t ifp_slice[BCM_IFP_SLICE_PER_UNIT];
	cap_stat_group_t efp_slice[BCM_EFP_SLICE_PER_UNIT];
	cap_stat_group_t vfp_slice[BCM_VFP_SLICE_PER_UNIT];
} cap_stat_t;

extern char *cap_sub_name_get(int sub_type);
extern cap_info_t *cap_info_get(int slot);
extern cap_info_t *cap_info_get_by_ifindex(u16 ifindex);
extern int cap_info_lock(void);
extern int cap_info_unlock(void);
extern int cap_init(void);
extern int cap_add_last_build(cap_info_t *cap, bcm_field_entry_t eid);
extern int cap_reset_last_build(cap_info_t *cap);
extern int cap_clear_last_build(cap_info_t *cap);
extern void cap_free_entry(cap_info_t *cap, bcm_field_entry_t eid);
extern void cap_free_entry_cluster(cap_info_t *cap, struct list_head  *list);
extern void cap_free_list(struct list_head  *list);
extern void cap_clear_one(cap_info_t *cap);
extern void cap_clear_all(void);
extern bcm_field_entry_t cap_alloc_entry(cap_sub_info_t *sub);
extern struct list_head *cap_alloc_entry_cluster(cap_sub_info_t *sub, int num);
extern int cap_get_stat(int slot, cap_stat_t *s);
extern int bcm_rule_build_begin(void);
extern int bcm_rule_build_finish(void);
extern int cap_check_free_ifp_entry(cap_sub_info_t *sub, int need_entry);
extern int cap_check_vlan_ip_acl_free_entry(cap_sub_info_t *sub, int need_entry);
extern int cap_check_ipmac_acl_free_entry(cap_sub_info_t *sub, int need_entry);

extern void hsl_layer4_init(void);
extern int ifindexpbmp_2_lplist(l4_pbmp_t *ifindexpbmp,  bcmx_lplist_t *lplist);
extern int vlanifindex_2_vid(int vlanifindex,  bcm_vlan_t *vid);

#endif

