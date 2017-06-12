/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_MSG_H_
#define _HSL_MSG_H_

#define HSL_MSG_PROCESS_RETURN(SOCK,HDR,RET)                                                       \
       do {                                                                                        \
            if ((HDR)->nlmsg_flags & HAL_NLM_F_ACK)                                                \
              {                                                                                    \
                if ((RET) < 0)                                                                     \
	         hsl_sock_post_ack ((SOCK), (HDR), 0, -1);                                         \
                else                                                                               \
	         hsl_sock_post_ack ((sock), (HDR), 0, 0);                                          \
              }                                                                                    \
       } while (0)

/* 
   Function prototypes.
*/
int hsl_msg_recv_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_getlink (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_get_metric (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_get_mtu (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_set_mtu (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_get_hwaddr (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_set_hwaddr (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_flags_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_flags_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_flags_unset (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_get_duplex (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_set_duplex (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_set_autonego (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_get_bw (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_set_bw (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_get_counters (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_delete_done (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

#ifdef HAVE_L3
int hsl_msg_recv_if_get_arp_ageing_timeout (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_set_arp_ageing_timeout (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_set_port_type (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_create_svi (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_delete_svi (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_ipv4_newaddr (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_ipv4_deladdr (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_fib_create (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_fib_delete (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_uc_add (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_uc_delete (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_uc_update (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_ifnewaddr(struct socket *sock, void *param1, void *param2);
int hsl_msg_ifdeladdr(struct socket *sock, void *param1, void *param2);
int hsl_msg_recv_if_set_sec_hwaddrs(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_add_sec_hwaddrs(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_delete_sec_hwaddrs(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_get_max_multipath(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

#ifdef HAVE_MCAST_IPV4
int hsl_msg_recv_ipv4_mc_init(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_deinit(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_pim_init(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_pim_deinit(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_vif_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_vif_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_route_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_route_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv4_mc_stat_get(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_MCAST_IPV4 */

#ifdef HAVE_MCAST_IPV6
int hsl_msg_recv_ipv6_mc_init(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_deinit(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_pim_init(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_pim_deinit(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_vif_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_vif_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_route_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_route_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_mc_stat_get(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_MCAST_IPV6 */

#ifdef HAVE_IPV6
int hsl_msg_recv_if_ipv6_newaddr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_ipv6_deladdr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_uc_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_uc_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_uc_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_uc_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_uc_update (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_IPV6 */
int hsl_msg_recv_if_bind_fib (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_if_unbind_fib (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_L3 */

#ifdef HAVE_L2
int hsl_msg_recv_if_init_l2 (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_add (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_delete (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_set_ageing_time (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_set_learning (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_set_if_mac_learning (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_add_port (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_delete_port (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_add_instance (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_delete_instance (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_add_vlan_to_instance (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bridge_delete_vlan_from_instance (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#if defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD)
int hsl_msg_recv_set_port_state(struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif  /* defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD) */
int hsl_msg_recv_vlan_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_add (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_delete (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_set_port_type (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_set_default_pvid (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_add_vid_to_port (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_delete_vid_from_port (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_classifier_add (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_classifier_delete (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#ifdef HAVE_VLAN_STACK
int hsl_msg_recv_vlan_stacking_enable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_stacking_disable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_stacking_ether_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_VLAN_STACK */
int hsl_msg_recv_flow_control_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_flow_control_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_flow_control_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_flow_control_statistics (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_qos_init (struct socket *, struct hal_nlmsghdr * hdr, char *msgbuf);
int hsl_msg_recv_l2_qos_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_qos_default_user_priority_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_qos_default_user_priority_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_qos_regen_user_priority_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_qos_regen_user_priority_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_qos_traffic_class_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ratelimit_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ratelimit_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ratelimit_bcast (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_bcast_discards_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ratelimit_mcast (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_mcast_discards_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_recv_msg_igmp_snooping_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int
hsl_recv_msg_igmp_snooping_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_igmp_snooping_enable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_igmp_snooping_disable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_igmp_snooping_add_entry(struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_igmp_snooping_del_entry(struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_recv_msg_mld_snooping_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int
hsl_recv_msg_mld_snooping_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_mld_snooping_enable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_mld_snooping_disable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_mld_snooping_add_entry(struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_mld_snooping_del_entry(struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);

int hsl_msg_recv_l2_fdb_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_add (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_delete (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_unicast_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_multicast_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_count_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_flush (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_l2_fdb_flush_by_mac (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_pmirror_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_pmirror_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_pmirror_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_pmirror_unset (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#ifdef HAVE_LACPD
int hsl_msg_recv_lacp_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_add_aggregator (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_delete_aggregator (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_attach_mux_to_aggregator (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_detach_mux_from_aggregator (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_psc_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_nuc_psc_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_collecting (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_distributing (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_lacp_collecting_distributing (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_LACPD */
#endif /* HAVE_L2 */

#ifdef HAVE_AUTHD
int hsl_msg_recv_auth_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_auth_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_auth_set_port_state (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#ifdef HAVE_MAC_AUTH
int hsl_msg_recv_auth_mac_set_port_state(struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif
#endif /* HAVE_AUTHD */

#ifdef HAVE_L3
int hsl_msg_recv_arp_add (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_arp_del (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_arp_cache_get (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_arp_del_all(struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);

#ifdef HAVE_IPV6
int hsl_msg_recv_ipv6_nbr_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_nbr_del (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_nbr_del_all (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ipv6_nbr_cache_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_IPV6 */
#endif /* HAVE_L3 */

#ifdef HAVE_L2LERN
int hsl_msg_recv_mac_access_grp_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_vlan_access_map_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif

#ifdef HAVE_QOS
int hsl_msg_recv_qos_init (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_deinit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_enable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_disable (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_queue_limit (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_tail_drop_threshold (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_threshold_dscp_map (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_wred_drop_threshold (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_set_bandwidth (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_queue_cos_map_set (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_queue_cos_map_unset (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_wrr_queue_min_reserve (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_set_trust_state (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_set_default_cos (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_set_dscp_mapping_tbl (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_set_class_map (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_qos_set_cmap_cos_inner (struct socket *, struct hal_nlmsghdr *hdr, char
*msgbuf);
int hsl_msg_recv_qos_set_policy_map (struct socket *, struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_QOS */

int hsl_msg_recv_if_init_l3(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_ratelimit_dlf_bcast (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_dlf_bcast_discards_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_ifnew (struct socket *sock, void *param1, void *unused);
int hsl_msg_ifdelete (struct socket *sock, void *param1, void *param2);
int hsl_msg_ifflags (struct socket *sock, void *param1, void *param2);

int hsl_msg_ifautonego(struct socket *sock, void *param1, void *unused);
int hsl_msg_ifhwaddr(struct socket *sock, void *param1, void *unused);
int hsl_msg_ifmtu(struct socket *sock, void *param1, void *unused);
int hsl_msg_ifduplex(struct socket *sock, void *param1, void *unused);
//int hsl_msg_ifdelete (struct socket *sock, void *param1, void *param2);
#ifdef HAVE_MPLS
int hsl_msg_recv_mpls_init (struct socket *sock, struct hal_nlmsghdr *hdr,
                            char *msgbuf);
int hsl_msg_recv_mpls_if_init (struct socket *sock, struct hal_nlmsghdr *hdr,
                               char *msgbuf);
int hsl_msg_recv_mpls_vrf_init (struct socket *sock, struct hal_nlmsghdr *hdr,\
                                char *msgbuf);
int
hsl_msg_recv_mpls_vrf_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, 
			      char *msgbuf);

int hsl_msg_recv_mpls_ilm_add (struct socket *sock, struct hal_nlmsghdr *hdr,
                               char *msgbuf);
int hsl_msg_recv_mpls_ilm_del (struct socket *sock, struct hal_nlmsghdr *hdr, 
                               char *msgbuf);
int hsl_msg_recv_mpls_ftn_add (struct socket *sock, struct hal_nlmsghdr *hdr,
                               char *msgbuf);
int hsl_msg_recv_mpls_ftn_del (struct socket *sock, struct hal_nlmsghdr *hdr,
                               char *msgbuf);
int hsl_msg_recv_mpls_vc_init (struct socket *sock, struct hal_nlmsghdr *hdr, 
                               char *msgbuf);
int hsl_msg_recv_mpls_vc_deinit (struct socket *sock, struct hal_nlmsghdr *hdr,                                  char *msgbuf);
int hsl_msg_recv_mpls_vc_ftn_add (struct socket *sock, struct hal_nlmsghdr *hdr,                                  char *msgbuf);
int hsl_msg_recv_mpls_vc_ftn_del (struct socket *sock, struct hal_nlmsghdr *hdr,                                  char *msgbuf);

#ifdef HAVE_VPLS
int hsl_msg_recv_mpls_vpls_add (struct socket *sock, struct hal_nlmsghdr *hdr,
                                char *msgbuf);
int hsl_msg_recv_mpls_vpls_del (struct socket *sock, struct hal_nlmsghdr *hdr,
                                char *msgbuf);
int hsl_msg_recv_mpls_vpls_if_bind (struct socket *sock, 
                                    struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_mpls_vpls_if_unbind (struct socket *sock, 
                                    struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_mpls_vpls_fib_add (struct socket *sock, 
                                    struct hal_nlmsghdr *hdr, char *msgbuf);
int hsl_msg_recv_mpls_vpls_fib_del (struct socket *sock, 
                                    struct hal_nlmsghdr *hdr, char *msgbuf);
#endif /* HAVE_VPLS */
#endif /* HAVE_MPLS */

#ifdef HAVE_PVLAN
int
hsl_msg_recv_pvlan_set_vlan_type (struct socket *sock,
                                  struct hal_nlmsghdr *hdr,
                                  char *msgbuf);

int
hsl_msg_recv_pvlan_vlan_associate (struct socket *sock,
                                   struct hal_nlmsghdr *hdr,
                                   char *msgbuf);

int
hsl_msg_recv_pvlan_vlan_dissociate (struct socket *sock,
                                    struct hal_nlmsghdr *hdr,
                                    char *msgbuf);

int
hsl_msg_recv_pvlan_port_add (struct socket *sock,
                             struct hal_nlmsghdr *hdr,
                             char *msgbuf);

int
hsl_msg_recv_pvlan_port_delete (struct socket *sock,
                                struct hal_nlmsghdr *hdr,
                                char *msgbuf);

int
hsl_msg_recv_pvlan_set_port_mode (struct socket *sock,
                                  struct hal_nlmsghdr *hdr,
                                  char *msgbuf);

#endif /* HAVE_PVLAN */


int
hsl_msg_recv_ip_set_acl_filter(struct socket *sock,
                               struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_ip_unset_acl_filter(struct socket *sock,
                                 struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_ip_set_acl_filter_interface(struct socket *sock,
                                         struct hal_nlmsghdr *hdr,
                                         char *msgbuf);

int
hsl_msg_recv_ip_unset_acl_filter_interface(struct socket *sock,
                                           struct hal_nlmsghdr *hdr,
                                           char *msgbuf);

/* CPU and system topology related information */
int
hsl_msg_recv_cpu_get_num (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_cpu_getdb_info (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_cpu_get_master (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_cpu_get_local (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_cpu_set_master (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_cpu_get_info_index (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

int
hsl_msg_recv_cpu_get_dump_index (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);


#endif /* _HSL_MSG_H_ */
