/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_ipv6_nbr.h"

int hal_ipv6_nbr_add (struct pal_in6_addr *addr, unsigned char *mac_addr,
                  u_int32_t ifindex)
{
    return 0;
}
int hal_ipv6_nbr_cache_get (unsigned short fib_id,
                        struct pal_in6_addr *addr, int count,
                        struct hal_ipv6_nbr_cache_entry *cache)
{
    return 0;
}
int hal_ipv6_nbr_del (struct pal_in6_addr *addr, unsigned char *mac_addr,
                      unsigned int ifindex)
{
    return 0;
}
int hal_ipv6_nbr_del_all (unsigned short fib_id, u_char clr_flag)
{
    return 0;
}
