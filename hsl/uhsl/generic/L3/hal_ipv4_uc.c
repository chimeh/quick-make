/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_ipv4_uc.h"

int hal_ipv4_uc_deinit (unsigned short fib)
{
    return 0;
}
int hal_ipv4_uc_init (unsigned short fib)
{
    return 0;
}
int hal_ipv4_uc_route_add (unsigned short fib,
                       struct pal_in4_addr *ipaddr,
                       unsigned char ipmask,
                       unsigned short num,
                       struct hal_ipv4uc_nexthop *nexthops)
{
    return 0;
}
int hal_ipv4_uc_route_delete (unsigned short fib,
                          struct pal_in4_addr *ipaddr, unsigned char ipmask)
{
    return 0;
}
int hal_ipv4_uc_route_update (unsigned short fib,
                          struct pal_in4_addr *ipaddr,
                          unsigned char ipmask,
                          unsigned short numfib,
                          struct hal_ipv4uc_nexthop *nexthopsfib,
                          unsigned short numnew,
                          struct hal_ipv4uc_nexthop *nexthopsnew)
{
    return 0;
}
int hal_ipv4_uc_route_update_new (unsigned short fib,
                              struct pal_in4_addr *ipaddr,
                              unsigned char masklen,
                              unsigned short num,
                              struct hal_ipv4uc_nexthop *nexthops)
{
    return 0;
}
