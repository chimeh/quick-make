/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved.  */

#ifndef _HSL_BRIDGE_H_
#define _HSL_BRIDGE_H_

#ifdef HAVE_L2LERN
#define HSL_MAC_ACL_NAME_SIZE           20
#define HSL_MAC_ACL_GRP_ADD         1
#define HSL_MAC_ACL_GRP_DELETE      2

#define HSL_VLAN_ACC_MAP_ADD             1
#define HSL_VLAN_ACC_MAP_DELETE          2
#endif /* HAVE_L2LERN */

struct hsl_l2_hw_callbacks;

/* 
   Bridge. 
*/
struct hsl_bridge
{
  char name[HAL_BRIDGE_NAME_LEN + 1];            /* Name. */

  u_int32_t ageing_time;                  /* Ageing time. */

  u_char flags;                       /* Flags. */
#define HSL_BRIDGE_LEARNING          (1 << 0)
#define HSL_BRIDGE_VLAN_AWARE        (1 << 1)
#define HSL_STP_INSTANCE_MAX             (8)
  
#ifdef HAVE_VLAN
  struct hsl_avl_tree  *vlan_tree;           /* Map of VLAN->ports. 
						of type 'struct hsl_vlan_port'. */
#endif /* HAVE_VLAN. */

  struct hsl_avl_tree *port_tree;            /* Tree of ports. */

  void *system_info;                         /* Platform specific information. */
};

#ifdef HAVE_L2LERN
struct hsl_acl_mac_addr
{
    u_int8_t mac[6];                        /* MAC address */
};

/* Definition of the class map structure for communication with HSL */
struct hsl_mac_access_grp
{
    char name[HSL_MAC_ACL_NAME_SIZE];          /* Class map name */

    u_int8_t deny_permit;                   /* deny or permit */
    u_int8_t l2_type;                       /* The packet format */

    struct hsl_acl_mac_addr a;                  /* Source MAC address */
    struct hsl_acl_mac_addr a_mask;             /* Source mask (prefix) */
    struct hsl_acl_mac_addr m;                  /* Destination MAC address */
    struct hsl_acl_mac_addr m_mask;             /* Destination mask (prefix) */

};

/* Definition of the class map structure for communication with HSL */
struct hsl_vlan_access_map
{
    char name[HSL_MAC_ACL_NAME_SIZE];          /* Class map name */
    char vlan_map[HSL_MAC_ACL_NAME_SIZE];      /* VLAN map name */

    u_int8_t deny_permit;                   /* deny or permit */
    u_int8_t l2_type;                       /* The packet format */

    struct hsl_acl_mac_addr a;                  /* Source MAC address */
    struct hsl_acl_mac_addr a_mask;             /* Source mask (prefix) */
    struct hsl_acl_mac_addr m;                  /* Destination MAC address */
    struct hsl_acl_mac_addr m_mask;             /* Destination mask (prefix) */

};

#endif /* HAVE_L2LERN */


/* 
   Bridge port. 
*/
struct hsl_bridge_port
{
  struct hsl_if *ifp;                        /* Backpointer to ifp. */
  struct hsl_bridge *bridge;                 /* Backpointer to bridge. */
  enum hal_vlan_port_type type;              /* Access, trunk, hybrid. */
#ifdef HAVE_L2LERN
  struct hsl_mac_access_grp *hsl_macc_grp;
  u_int32_t stp_port_state;
#endif /* HAVE_L2LERN */
#ifdef HAVE_VLAN
  struct hsl_port_vlan *vlan;                /* VLAN information. */
#endif /* HAVE_VLAN. */
#ifdef HAVE_PVLAN
  int pvlan_port_mode;
  void *system_info;
#endif /* HAVE_PVLAN */
#ifdef HAVE_MAC_AUTH
  int auth_mac_port_ctrl;
#define AUTH_MAC_ENABLE   (1<<0)
#define AUTH_MAC_DISABLE  (1<<1)  
#endif
};


#include "hsl_l2_hw.h"

/* 
   Master structure. 
*/
struct hsl_bridge_master
{
  struct hsl_bridge *bridge;                 /* Currently only 1 bridge supported. */

  ipi_sem_id mutex;                          /* Mutex. */

  struct hsl_l2_hw_callbacks *hw_cb;          /* Hardware callbacks. */
};

#define HSL_BRIDGE_LOCK        oss_sem_lock(OSS_SEM_MUTEX, p_hsl_bridge_master->mutex, OSS_WAIT_FOREVER)
#define HSL_BRIDGE_UNLOCK      oss_sem_unlock(OSS_SEM_MUTEX, p_hsl_bridge_master->mutex)

extern struct hsl_bridge_master *p_hsl_bridge_master;

/*
   Function prototypes.
*/
struct hsl_bridge * hsl_bridge_init (void);
int hsl_bridge_deinit (struct hsl_bridge *b);
struct hsl_bridge_port * hsl_bridge_port_init (void);
int hsl_bridge_port_deinit (struct hsl_bridge_port *port);
int hsl_bridge_master_init (void);
int hsl_bridge_master_deinit (void);
int hsl_bridge_add (char *name, int is_vlan_aware);
int hsl_bridge_delete (char *name);
int hsl_bridge_add_port (char *name, hsl_ifIndex_t ifindex);
int hsl_bridge_delete_port (char *name, hsl_ifIndex_t ifindex);
int hsl_bridge_age_timer_set (char *name, int age_seconds);
int hsl_bridge_learning_set (char *name, int learn);
int hsl_bridge_set_stp_port_state (char *name, hsl_ifIndex_t ifindex, int instance, int state);
int hsl_bridge_add_instance (char *name, int instance);
int hsl_bridge_delete_instance (char *name, int instance);
int hsl_bridge_add_vlan_to_inst (char *name, int instance, hsl_vid_t vid);
int hsl_bridge_delete_vlan_from_inst (char *name, int instance, hsl_vid_t vid);
int hsl_bridge_init_igmp_snooping (void);
int hsl_bridge_deinit_igmp_snooping (void);
int hsl_bridge_enable_igmp_snooping (char *name);
int hsl_bridge_disable_igmp_snooping (char *name);
int hsl_bridge_init_mld_snooping (void);
int hsl_bridge_deinit_mld_snooping (void);
int hsl_bridge_enable_mld_snooping (char *name);
int hsl_bridge_disable_mld_snooping (char *name);
int hsl_bridge_ratelimit_bcast (hsl_ifIndex_t ifindex, int level,
                                int fraction);
int hsl_bridge_ratelimit_get_bcast_discards (hsl_ifIndex_t ifindex, int *discards);
int hsl_bridge_ratelimit_mcast (hsl_ifIndex_t ifindex, int level, 
                                int fraction);
int hsl_bridge_ratelimit_get_mcast_discards (hsl_ifIndex_t ifindex, int *discards);
int hsl_bridge_flowcontrol_init (void);
int hsl_bridge_flowcontrol_deinit (void);
int hsl_bridge_ratelimit_dlf_bcast (hsl_ifIndex_t ifindex, int level,
                                    int fraction);
int hsl_bridge_ratelimit_get_dlf_bcast_discards (hsl_ifIndex_t ifindex, int *discards);
int hsl_bridge_init_flowcontrol (void);
int hsl_bridge_deinit_flowcontrol (void);
int hsl_bridge_set_flowcontrol (hsl_ifIndex_t ifindex, u_char direction);
int hsl_bridge_flowcontrol_statistics (hsl_ifIndex_t ifindex, u_char *direction, int *rxpause, int *txpause);
int hsl_bridge_init_fdb (void);
int hsl_bridge_deinit_fdb (void);
int hsl_bridge_add_fdb (char *name, hsl_ifIndex_t ifindex, char *mac, int len, hsl_vid_t vid, u_char flags, int is_forward);
int hsl_bridge_delete_fdb (char *name, hsl_ifIndex_t ifindex, char *mac, int len, hsl_vid_t vid, u_char flags);
int hsl_bridge_unicast_get_fdb (struct hal_msg_l2_fdb_entry_req *, struct hal_msg_l2_fdb_entry_resp *resp);
int hsl_bridge_multicast_get_fdb (struct hal_msg_l2_fdb_entry_req *, struct hal_msg_l2_fdb_entry_resp *resp);
int hsl_bridge_flush_fdb (char *name, hsl_ifIndex_t ifindex,hsl_vid_t vid);
int hsl_bridge_hw_cb_register (struct hsl_l2_hw_callbacks *cb);
int hsl_bridge_flush_fdb_by_mac (char *name, char *mac, int len, int flags);
int hsl_bridge_delete_port_vlan_fdb(struct hsl_if *ifp, hsl_vid_t vid);

int hsl_bridge_storm_ctl(bool ifindex_or_vlan, unsigned int ifindex, unsigned int vlan, 
					bool enable, unsigned int type, unsigned int mode,unsigned int threshold_num, bool is_discard_to_cpu);



#endif /* _HSL_BRIDGE_H_ */
