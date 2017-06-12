#ifndef _BCM_QOS_IF_H_
#define _BCM_QOS_IF_H_


#define	BCM_FIELD_METER_KBITS_BURST_MIN		4

#define FB_DRR_KBYTES   (1)
#define FB_DRR_MBYTES   (1024)
#define FB_DRR_WEIGHT_MAX 0xf
#define FB_WRR_WEIGHT_MAX 0xf
#define BCM_HU_COS_WEIGHT_MAX 0x7f

/*
	xxx_is_dscp用来区别是DSCP还是PRECEDENCE
	xxx_value如果是-1，表示不设置值，否则要设置
*/
typedef struct qos_set_dscp_s {
	bool	green_is_dscp;
	int		green_value;
	bool	yellow_is_dscp;
	int		yellow_value;
	bool	red_is_dscp;
	int		red_value;
} qos_set_dscp_t;

//typedef int (*qualify_func)(bcm_field_entry_t, int, int);

extern int qos_build(void);
extern int qos_download(void);

extern u32 qos_cal_bandwidth(bool is_percent, u32 ifspeed, int value);
extern int qos_get_if_mtu_ispeed(u32 ifindex, u32 *pmtu, u32 *pspeed);
extern int qos_build_match_all_rule(struct cm_entry *cm_entry, 
	cap_info_t *cap, cap_sub_info_t *sub, int qid);
extern int qos_build_match_any_rule(struct cm_entry *cm_entry, 
	cap_info_t *cap, cap_sub_info_t *sub, int qid);
extern int bcm_qos_weight_to_kbps(int weight);
extern struct list_head *qos_build_class_map_internal(cap_sub_info_t *sub, int lport, 
	void *ptr, 	int type, bool dir_in, int acl_entry_num, int *group_id);
extern struct list_head *qos_cap_alloc_cluster(cap_sub_info_t *sub, int num, bool dir_in, int chip_port, int *p_group_id, ctc_acl_group_info_t *ctc_group);
extern struct list_head *qos_build_one_match_entry(cap_sub_info_t *sub,bool dir_in, int  lport, int *group_id, ctc_acl_group_info_t *ctc_group);
extern struct list_head *qos_build_acl(struct entry_msg_s *acl, cap_sub_info_t *sub,	bool dir_in, int lport, int acl_entry_num, int *group_id, ctc_acl_group_info_t *ctc_group);
extern struct list_head *qos_build_class_map(u32 ifindex, void *ptr, int type, int sub_type, bool dir_in, int acl_entry_num, int *group_id);
extern struct list_head *qos_build_match_all_list(struct cm_entry *cm_entry, cap_info_t *cap, cap_sub_info_t *sub);

extern int qualify_in_port(int eid, int lport, u8 no_use);
extern int qualify_in_vlan(int eid, u16 vid, u8 no_use);
extern struct list_head *qos_filter_build_class_map_internal(cap_sub_info_t *sub, int chip_port, void *ptr, int type, bool dir_in);
extern struct list_head *qos_filter_cap_alloc_cluster(cap_sub_info_t *sub, int num,bool dir_in,int chip_port);



#endif

