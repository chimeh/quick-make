/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_if.h"

int hal_if_bind_fib (u_int32_t ifindex, u_int32_t fib)
{
    return 0;
}
int hal_if_clear_counters (unsigned int ifindex)
{
    return 0;
}
int hal_if_delete_done(char *ifname, u_int16_t ifindex)
{
    return 0;
}
int hal_if_flags_get (char *ifname, unsigned int ifindex, u_int32_t *flags)
{
    return 0;
}
int hal_if_flags_set (char *ifname, unsigned int ifindex, unsigned int flags)
{
    return 0;
}
int hal_if_flags_unset (char *ifname, unsigned int ifindex, unsigned int flags)
{
    return 0;
}
int hal_if_get_arp_ageing_timeout (char *ifname, unsigned int ifindex, int *arp_ageing_timeout)
{
    return 0;
}
int hal_if_get_bw (char *ifname, unsigned int ifindex, u_int32_t *bandwidth)
{
    return 0;
}
int hal_if_get_counters(unsigned int ifindex, struct hal_if_counters *if_stats)
{
    return 0;
}
int hal_if_get_duplex (char *ifname, unsigned int ifindex, int *duplex)
{
    return 0;
}
int hal_if_get_hwaddr (char *ifname, unsigned int ifindex,
                   unsigned char *hwaddr, int *hwaddr_len)
{
    return 0;
}
int hal_if_get_learn_disable (unsigned int ifindex, int* enable)
{
    return 0;
}
int hal_if_get_list (void)
{
    return 0;
}
int hal_if_get_metric (char *ifname, unsigned int ifindex, int *metric)
{
    return 0;
}
int hal_if_get_mtu (char *ifname, unsigned int ifindex, int *metric)
{
    return 0;
}
int hal_if_sec_hwaddrs__delete (char *ifname, unsigned int ifindex,
                            int hw_addr_len, int nAddrs, unsigned char **addresses)
{
    return 0;
}
int hal_if_sec_hwaddrs_add (char *ifname, unsigned int ifindex,
                        int hw_addr_len, int nAddrs, unsigned char **addresses)
{
    return 0;
}
int hal_if_sec_hwaddrs_delete (char *ifname, unsigned int ifindex,
                           int hw_addr_len, int nAddrs,
                           unsigned char **addresses)
{
    return 0;
}
int hal_if_sec_hwaddrs_set (char *ifname, unsigned int ifindex,
                        int hw_addr_len, int nAddrs, unsigned char **addresses)
{
    return 0;
}
int hal_if_set_arp_ageing_timeout (char *ifname, unsigned int ifindex, int arp_ageing_timeout)
{
    return 0;
}
int hal_if_set_autonego (char *ifname, unsigned int ifindex, int autonego)
{
    return 0;
}
int hal_if_set_bw (char *ifname, unsigned int ifindex, unsigned int bandwidth)
{
    return 0;
}
int hal_if_set_cpu_default_vid (unsigned int ifindex, int vid)
{
    return 0;
}
int hal_if_set_duplex (char *ifname, unsigned int ifindex, int duplex)
{
    return 0;
}
int hal_if_set_ether_type (unsigned int ifindex, u_int16_t etype)
{
    return 0;
}
int hal_if_set_force_vlan (unsigned int ifindex, int vid)
{
    return 0;
}
int hal_if_set_hwaddr (char *ifname, unsigned int ifindex,
                   u_int8_t *hwaddr, int hwlen)
{
    return 0;
}
int hal_if_set_ipv6_l3_enable_status (int l3_status)
{
    return 0;
}
int hal_if_set_l3_enable_status (int l3_status)
{
    return 0;
}
int hal_if_set_learn_disable (unsigned int ifindex, int enable)
{
    return 0;
}
int hal_if_set_mdix(unsigned int ifindex, unsigned int mdix)
{
    return 0;
}
int hal_if_set_mtu (char *ifname, unsigned int ifindex, int mtu)
{
    return 0;
}
int hal_if_set_port_egress (unsigned int ifindex, int egress_mode)
{
    return 0;
}
int hal_if_set_port_type (char *ifname, unsigned int ifindex,
                      enum hal_if_port_type type, unsigned int *retifindex)
{
    return 0;
}
int hal_if_set_portbased_vlan (unsigned int ifindex, struct hal_port_map bitmap)
{
    return 0;
}
int hal_if_set_preserve_ce_cos (unsigned int ifindex)
{
    return 0;
}
int hal_if_set_sw_reset ()
{
    return 0;
}
int hal_if_set_wayside_default_vid (unsigned int ifindex, int vid)
{
    return 0;
}
int hal_if_stats_flush (u_int16_t ifindex)
{
    return 0;
}
int hal_if_svi_create (char *ifname, unsigned int *ifindex)
{
    return 0;
}
int hal_if_svi_delete (char *ifname, unsigned int ifindex)
{
    return 0;
}
int hal_if_unbind_fib (u_int32_t ifindex, u_int32_t fib)
{
    return 0;
}
int hal_ip_set_access_group (struct hal_ip_access_grp access_grp,
                         char *ifname, int action, int dir)
{
    return 0;
}
int hal_ip_set_access_group_interface (struct hal_ip_access_grp access_grp,
                                   char *vifname, char *ifname,
                                   int action, int dir)
{
    return 0;
}
int hal_vlan_if_get_counters(unsigned int ifindex,unsigned int vlan,
                         struct hal_vlan_if_counters *if_stats)
{
    return 0;
}
