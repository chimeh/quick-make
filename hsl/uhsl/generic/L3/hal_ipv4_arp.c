/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_ipv4_arp.h"

int hal_arp_cache_get (unsigned short fib_id, struct pal_in4_addr *ipaddr,
                   int count, struct hal_arp_cache_entry *cache)
{
    return 0;
}
int hal_arp_del_all (unsigned short fib_id, u_char clr_flag)
{
    return 0;
}
int hal_arp_entry_add (struct pal_in4_addr *ipaddr,
                   unsigned char *mac_addr,
                   u_int32_t ifindex,
                   u_int32_t lpbk_ifindex, u_int8_t is_proxy_arp)
{
    return 0;
}
int hal_arp_entry_del (struct pal_in4_addr *ipaddr,
                   unsigned char *mac_addr, u_int32_t ifindex)
{
    return 0;
}
