/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "mpls_common.h"
#include "hal_mpls_types.h"
#include "hal_mpls.h"


int hal_mpls_clear_fib_table (u_char protocol)
{
    return 0;
}
int hal_mpls_clear_vrf_table (u_char protocol)
{
    return 0;
}
int hal_mpls_cw_capability ()
{
    return 0;
}
int hal_mpls_deinit (u_char protocol)
{
    return 0;
}
int hal_mpls_disable_interface (struct if_ident *if_ident)
{
    return 0;
}
int hal_mpls_enable_interface (struct if_ident *if_ident,
                           unsigned short label_space)
{
    return 0;
}
int hal_mpls_ftn_entry_add (int vrf,
                        u_char protocol,
                        struct hal_in4_addr *fec_addr,
                        u_char *fec_prefix_len,
                        u_char *dscp_in,
                        u_int32_t *tunnel_label,
                        struct hal_in4_addr *tunnel_nexthop_addr,
                        struct if_ident *tunnel_nexthop_if,
                        u_int32_t *vpn_label,
                        struct hal_in4_addr *vpn_nexthop_addr,
                        struct if_ident *vpn_outgoing_if,
                        u_int32_t *tunnel_id,
                        u_int32_t *qos_resource_id,
                        struct hal_mpls_diffserv *tunnel_ds_info,
                        char opcode,
                        u_int32_t nhlfe_ix,
                        u_int32_t ftn_ix,
                        u_char ftn_type,
                        struct mpls_owner_fwd *owner,
                        u_int32_t bypass_ftn_ix,
                        u_char lsp_type)
{
    return 0;
}
int hal_mpls_ftn_entry_delete (int vrf,
                           u_char protocol,
                           struct hal_in4_addr *fec_addr,
                           u_char *fec_prefix_len,
                           u_char *dscp_in,
                           struct hal_in4_addr *tunnel_nhop,
                           u_int32_t nhlfe_ix,
                           u_int32_t *tunnel_id,
                           u_int32_t ftn_ix)
{
    return 0;
}
int hal_mpls_if_update_vrf (struct if_ident *if_ident, int vrf)
{
    return 0;
}
int hal_mpls_ilm6_entry_add (u_int32_t *in_label,
                         struct if_ident *in_if,
                         u_char opcode,
                         struct hal_in6_addr *nexthop,
                         struct if_ident *out_if,
                         u_int32_t *swap_label,
                         u_int32_t nhlfe_ix,
                         u_char is_egress,
                         u_int32_t *tunnel_label,
                         u_int32_t *qos_resource_id,
                         struct hal_mpls_diffserv *ds_info,
                         struct hal_in6_addr *fec_addr,
                         unsigned char *fec_prefixlen,
                         u_int32_t vpn_id,
                         struct hal_in6_addr *vc_peer)
{
    return 0;
}
int hal_mpls_ilm_entry_add (u_int32_t *in_label,
                        struct if_ident *in_if,
                        u_char opcode,
                        struct hal_in4_addr *nexthop,
                        struct if_ident *out_if,
                        u_int32_t *swap_label,
                        u_int32_t nhlfe_ix,
                        u_char is_egress,
                        u_int32_t *tunnel_label,
                        u_int32_t *qos_resource_id,
                        struct hal_mpls_diffserv *ds_info,
                        struct hal_in4_addr *fec_addr,
                        unsigned char *fec_prefixlen,
                        u_int32_t vpn_id,
                        struct hal_in4_addr *vc_peer)
{
    return 0;
}
int hal_mpls_ilm_entry_delete (u_char protocol,
                           u_int32_t *label_id_in,
                           struct if_ident *if_info)
{
    return 0;
}
int hal_mpls_init (u_char protocol)
{
    return 0;
}
int hal_mpls_local_pkt_handle (u_char protocol,
                           int enable)
{
    return 0;
}
int hal_mpls_pw_get_perf_cntr (struct nsm_mpls_pw_snmp_perf_curr *curr)
{
    return 0;
}
int hal_mpls_qos_release (struct hal_mpls_qos *qos)
{
    return 0;
}
int hal_mpls_qos_reserve (struct hal_mpls_qos *qos)
{
    return 0;
}
int hal_mpls_send_ttl (u_char protocol,
                   u_char type,
                   int ingress,
                   int new_ttl)
{
    return 0;
}
int hal_mpls_vc_deinit (u_int32_t vc_id,
                  struct if_ident *if_info,
                  u_int16_t vlan_id)
{
    return 0;
}
int hal_mpls_vc_fib_add (u_int32_t vc_id,
                       u_int32_t vc_style,
                       u_int32_t vpls_id,
                       u_int32_t in_label,
                       u_int32_t out_label,
                       u_int32_t ac_ifindex,
                       u_int32_t nw_ifindex,
                       u_char ftn_opcode,
                       struct pal_in4_addr *ftn_vc_peer,
                       struct pal_in4_addr *ftn_vc_nhop,
                       u_int32_t ftn_tunnel_label,
                       struct pal_in4_addr *ftn_tunnel_nhop,
                       u_int32_t ftn_tunnel_ifindex,
                       u_int32_t ftn_tunnel_nhlfe_ix)
{
    return 0;
}
int hal_mpls_vc_fib_delete (u_int32_t vc_id,
                        u_int32_t vc_style,
                        u_int32_t vpls_id,
                        u_int32_t in_label,
                        u_int32_t nw_ifindex,
                        struct hal_in4_addr *ftn_vc_peer)
{
    return 0;
}
int hal_mpls_vc_init (u_int32_t vc_id,
                  struct if_ident *if_info,
                  u_int16_t vlan_id)
{
    return 0;
}
int hal_mpls_vpls_add (u_int32_t vpls_id)
{
    return 0;
}
int hal_mpls_vpls_del (u_int32_t vpls_id)
{
    return 0;
}
int hal_mpls_vpls_if_bind (u_int32_t vpls_id,
                       u_int32_t ifindex,
                       u_int16_t vlan_id)
{
    return 0;
}
int hal_mpls_vpls_if_unbind (u_int32_t vpls_id,
                         u_int32_t ifindex,
                         u_int16_t vlan_id)
{
    return 0;
}
int hal_mpls_vpls_mac_withdraw (u_int32_t vpls_id,
                            u_int16_t num,
                            u_char *mac_addrs)
{
    return 0;
}
int hal_mpls_vrf_create (int vrf)
{
    return 0;
}
int hal_mpls_vrf_destroy (int vrf)
{
    return 0;
}
