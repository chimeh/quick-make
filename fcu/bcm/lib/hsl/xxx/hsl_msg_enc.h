/* Function prototypes. */
int hsl_msg_encode_tlv (u_char **pnt, u_int32_t *size, u_int16_t type, u_int16_t length);
int hsl_msg_encode_if (u_char **pnt, u_int32_t *size, struct hal_msg_if *msg);
int hsl_msg_decode_if (u_char **pnt, u_int32_t *size, struct hal_msg_if *msg);
int hsl_msg_decode_debug_hsl(u_char **pnt, u_int32_t *size, struct hal_msg_debug_hsl_req *msg);


int hsl_msg_encode_lacp_psc_set (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_psc_set *msg);
int hsl_msg_decode_lacp_psc_set (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_psc_set *msg);
int hsl_msg_decode_lacp_global_psc_set (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_global_psc_set *msg);
int hsl_msg_encode_lacp_id (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_identifier *msg);
int hsl_msg_decode_lacp_id (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_identifier *msg);
int hsl_msg_encode_lacp_agg_add (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_add *msg);
int hsl_msg_decode_lacp_agg_add (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_add *msg);
int hsl_msg_encode_lacp_mux(u_char **pnt, u_int32_t *size, struct hal_msg_lacp_mux *msg);
int hsl_msg_decode_lacp_mux(u_char **pnt, u_int32_t *size, struct hal_msg_lacp_mux *msg);



int hsl_msg_encode_arp_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_resp *msg);
int hsl_msg_decode_arp_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_resp *msg);
int hsl_msg_encode_arp_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_req *msg);
int hsl_msg_decode_arp_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_req *msg);
int hsl_msg_encode_ipv4_route (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4uc_route *msg);
int hsl_msg_decode_ipv4_route (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4uc_route *msg);
int hsl_msg_encode_ipv4_addr(u_char **pnt, u_int32_t *size, struct hal_msg_if_ipv4_addr *msg);
int hsl_msg_decode_if_fib_bind_unbind (u_char **pnt, u_int32_t *size, struct hal_msg_if_fib_bind_unbind *msg);

int hsl_msg_encode_ipv4_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_vif_add *msg);
int hsl_msg_decode_ipv4_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_vif_add *msg);
int hsl_msg_encode_ipv4_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_add *msg);
int hsl_msg_decode_ipv4_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_add *msg);
int hsl_msg_encode_ipv4_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_del *msg);
int hsl_msg_decode_ipv4_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_del *msg);
int hsl_msg_encode_ipv4_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_sg_stat *msg);
int hsl_msg_decode_ipv4_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_sg_stat *msg);
int hsl_msg_encode_ipv6_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_vif_add *msg);
int hsl_msg_decode_ipv6_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_vif_add *msg);
int hsl_msg_encode_ipv6_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_add *msg);
int hsl_msg_decode_ipv6_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_add *msg);
int hsl_msg_encode_ipv6_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_del *msg);
int hsl_msg_decode_ipv6_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_del *msg);
int hsl_msg_encode_ipv6_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_sg_stat *msg);
int hsl_msg_decode_ipv6_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_sg_stat *msg);

int hsl_msg_encode_vlan_classifier_rule(u_char **pnt, u_int32_t *size, struct hal_msg_vlan_classifier_rule *msg);
int hsl_msg_decode_vlan_classifier_rule(u_char **pnt, u_int32_t *size, struct hal_msg_vlan_classifier_rule *msg);

int hsl_msg_encode_ipv6_nbr_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_resp *msg);
int hsl_msg_decode_ipv6_nbr_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_resp *msg);
int hsl_msg_encode_ipv6_nbr_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_req *msg);
int hsl_msg_decode_ipv6_nbr_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_req *msg);
int hsl_msg_encode_ipv6_addr(u_char **pnt, u_int32_t *size, struct hal_msg_if_ipv6_addr *msg);
int hsl_msg_decode_ipv6_route (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6uc_route *msg);
int hsl_msg_encode_l2_fdb_resp (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_resp *msg);
int hsl_msg_decode_l2_fdb_resp (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_resp *msg);
int hsl_msg_encode_l2_fdb_req (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_req *msg);
int hsl_msg_decode_l2_fdb_req (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_req *msg);

/* IGMP SNOOPING MESSAGES */
int hsl_msg_encode_igs_entry (u_char **pnt, u_int32_t *size, struct hal_msg_igmp_snoop_entry *msg);
int hsl_msg_decode_igs_entry(u_char **pnt, u_int32_t *size, struct hal_msg_igmp_snoop_entry *msg,
                             void *(*mem_alloc)(u_int32_t size));
int hsl_msg_encode_igs_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_igs_bridge *msg);
int hsl_msg_decode_igs_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_igs_bridge *msg);


/* MLD SNOOPING MESSAGES */
int hsl_msg_encode_mlds_entry (u_char **pnt, u_int32_t *size, struct hal_msg_mld_snoop_entry *msg);
int hsl_msg_decode_mlds_entry(u_char **pnt, u_int32_t *size, struct hal_msg_mld_snoop_entry *msg,
                             void *(*mem_alloc)(u_int32_t size));
int hsl_msg_encode_mlds_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_mlds_bridge *msg);
int hsl_msg_decode_mlds_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_mlds_bridge *msg);
/* Function prototypes. */
int hsl_msg_encode_tlv (u_char **pnt, u_int32_t *size, u_int16_t type, u_int16_t length);
int hsl_msg_encode_if (u_char **pnt, u_int32_t *size, struct hal_msg_if *msg);
int hsl_msg_decode_if (u_char **pnt, u_int32_t *size, struct hal_msg_if *msg);
int hsl_msg_decode_debug_hsl(u_char **pnt, u_int32_t *size, struct hal_msg_debug_hsl_req *msg);


int hsl_msg_encode_lacp_psc_set (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_psc_set *msg);
int hsl_msg_decode_lacp_psc_set (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_psc_set *msg);
int hsl_msg_decode_lacp_global_psc_set (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_global_psc_set *msg);
int hsl_msg_encode_lacp_id (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_identifier *msg);
int hsl_msg_decode_lacp_id (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_identifier *msg);
int hsl_msg_encode_lacp_agg_add (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_add *msg);
int hsl_msg_decode_lacp_agg_add (u_char **pnt, u_int32_t *size, struct hal_msg_lacp_agg_add *msg);
int hsl_msg_encode_lacp_mux(u_char **pnt, u_int32_t *size, struct hal_msg_lacp_mux *msg);
int hsl_msg_decode_lacp_mux(u_char **pnt, u_int32_t *size, struct hal_msg_lacp_mux *msg);



int hsl_msg_encode_arp_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_resp *msg);
int hsl_msg_decode_arp_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_resp *msg);
int hsl_msg_encode_arp_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_req *msg);
int hsl_msg_decode_arp_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_arp_cache_req *msg);
int hsl_msg_encode_ipv4_route (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4uc_route *msg);
int hsl_msg_decode_ipv4_route (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4uc_route *msg);
int hsl_msg_encode_ipv4_addr(u_char **pnt, u_int32_t *size, struct hal_msg_if_ipv4_addr *msg);
int hsl_msg_decode_if_fib_bind_unbind (u_char **pnt, u_int32_t *size, struct hal_msg_if_fib_bind_unbind *msg);

int hsl_msg_encode_ipv4_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_vif_add *msg);
int hsl_msg_decode_ipv4_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_vif_add *msg);
int hsl_msg_encode_ipv4_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_add *msg);
int hsl_msg_decode_ipv4_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_add *msg);
int hsl_msg_encode_ipv4_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_del *msg);
int hsl_msg_decode_ipv4_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_mrt_del *msg);
int hsl_msg_encode_ipv4_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_sg_stat *msg);
int hsl_msg_decode_ipv4_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv4mc_sg_stat *msg);
int hsl_msg_encode_ipv6_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_vif_add *msg);
int hsl_msg_decode_ipv6_vif_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_vif_add *msg);
int hsl_msg_encode_ipv6_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_add *msg);
int hsl_msg_decode_ipv6_mrt_add (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_add *msg);
int hsl_msg_encode_ipv6_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_del *msg);
int hsl_msg_decode_ipv6_mrt_del (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_mrt_del *msg);
int hsl_msg_encode_ipv6_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_sg_stat *msg);
int hsl_msg_decode_ipv6_sg_stat (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6mc_sg_stat *msg);

int hsl_msg_encode_vlan_classifier_rule(u_char **pnt, u_int32_t *size, struct hal_msg_vlan_classifier_rule *msg);
int hsl_msg_decode_vlan_classifier_rule(u_char **pnt, u_int32_t *size, struct hal_msg_vlan_classifier_rule *msg);

int hsl_msg_encode_ipv6_nbr_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_resp *msg);
int hsl_msg_decode_ipv6_nbr_cache_resp (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_resp *msg);
int hsl_msg_encode_ipv6_nbr_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_req *msg);
int hsl_msg_decode_ipv6_nbr_cache_req (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6_nbr_cache_req *msg);
int hsl_msg_encode_ipv6_addr(u_char **pnt, u_int32_t *size, struct hal_msg_if_ipv6_addr *msg);
int hsl_msg_decode_ipv6_route (u_char **pnt, u_int32_t *size, struct hal_msg_ipv6uc_route *msg);
int hsl_msg_encode_l2_fdb_resp (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_resp *msg);
int hsl_msg_decode_l2_fdb_resp (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_resp *msg);
int hsl_msg_encode_l2_fdb_req (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_req *msg);
int hsl_msg_decode_l2_fdb_req (u_char **pnt, u_int32_t *size, struct hal_msg_l2_fdb_entry_req *msg);

/* IGMP SNOOPING MESSAGES */
int hsl_msg_encode_igs_entry (u_char **pnt, u_int32_t *size, struct hal_msg_igmp_snoop_entry *msg);
int hsl_msg_decode_igs_entry(u_char **pnt, u_int32_t *size, struct hal_msg_igmp_snoop_entry *msg,
                             void *(*mem_alloc)(u_int32_t size));
int hsl_msg_encode_igs_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_igs_bridge *msg);
int hsl_msg_decode_igs_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_igs_bridge *msg);


/* MLD SNOOPING MESSAGES */
int hsl_msg_encode_mlds_entry (u_char **pnt, u_int32_t *size, struct hal_msg_mld_snoop_entry *msg);
int hsl_msg_decode_mlds_entry(u_char **pnt, u_int32_t *size, struct hal_msg_mld_snoop_entry *msg,
                             void *(*mem_alloc)(u_int32_t size));
int hsl_msg_encode_mlds_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_mlds_bridge *msg);
int hsl_msg_decode_mlds_bridge(u_char **pnt, u_int32_t *size, struct hal_msg_mlds_bridge *msg);
