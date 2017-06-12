/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_ipv4_mc.h"

int hal_ipv4_mc_add_mfc (struct hal_in4_addr *source, struct hal_in4_addr *group,
                     u_int32_t iif_vif_index, int num_oifs,
                     u_int16_t * olist_vifs, u_char * oifs_ttl)
{
    return 0;
}
int hal_ipv4_mc_deinit (int fib)
{
    return 0;
}
int hal_ipv4_mc_delete_mfc (struct hal_in4_addr *source,
                        struct hal_in4_addr *group, u_int32_t index)
{
    return 0;
}
int hal_ipv4_mc_get_max_rate_limit (unsigned int index, unsigned int rate_limit)
{
    return 0;
}
int hal_ipv4_mc_get_max_vifs (int *vifs)
{
    return 0;
}
int hal_ipv4_mc_get_min_ttl_threshold (unsigned int index, unsigned char ttl)
{
    return 0;
}
int hal_ipv4_mc_get_sg_count (struct hal_in4_addr *source,
                          struct hal_in4_addr *group,
                          u_int32_t iif_vif,
                          u_int32_t * pktcnt,
                          u_int32_t * bytecnt, u_int32_t * wrong_vif)
{
    return 0;
}
int hal_ipv4_mc_init (int fib)
{
    return 0;
}
int hal_ipv4_mc_pim_deinit (int fib)
{
    return 0;
}
int hal_ipv4_mc_pim_init (int fib)
{
    return 0;
}
int hal_ipv4_mc_set_max_rate_limit (unsigned int index, unsigned int rate_limit)
{
    return 0;
}
int hal_ipv4_mc_set_min_ttl_threshold (unsigned int ifindex, unsigned char ttl)
{
    return 0;
}
int hal_ipv4_mc_vif_add (u_int32_t index, u_int32_t phy_ifindex,
                     struct hal_in4_addr *loc_addr,
                     struct hal_in4_addr *rmt_addr, u_int16_t flags)
{
    return 0;
}
int hal_ipv4_mc_vif_addr_add (unsigned int index,
                          struct hal_in4_addr *addr,
                          struct hal_in4_addr *subnet,
                          struct hal_in4_addr *broadcast,
                          struct hal_in4_addr *peer)
{
    return 0;
}
int hal_ipv4_mc_vif_addr_delete (unsigned int index, struct hal_in4_addr *addr)
{
    return 0;
}
int hal_ipv4_mc_vif_delete (u_int32_t index)
{
    return 0;
}
int hal_ipv4_mc_vif_set_flags (unsigned int ifindex,
                           unsigned char is_pim_register,
                           unsigned char is_p2p,
                           unsigned char is_loopback,
                           unsigned char is_multicast,
                           unsigned char is_broadcast)
{
    return 0;
}
int hal_ipv4_mc_vif_set_physical_if (unsigned int index, unsigned int ifindex)
{
    return 0;
}
