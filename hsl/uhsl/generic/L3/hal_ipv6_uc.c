/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_ipv6_uc.h"

int hal_ipv6_uc_deinit (unsigned short fib)
{
    return 0;
}
int hal_ipv6_uc_init (unsigned short fib)
{
    return 0;
}
int hal_ipv6_uc_route_add (unsigned short fib,
                       struct pal_in6_addr *ipaddr,
                       unsigned char ipmask,
                       unsigned short num,
                       struct hal_ipv6uc_nexthop *nexthops)
{
    return 0;
}
int hal_ipv6_uc_route_delete (unsigned short fib,
                          struct pal_in6_addr *ipaddr,
                          unsigned char ipmask,
                          int num, struct hal_ipv6uc_nexthop *nexthops)
{
    return 0;
}
int hal_ipv6_uc_route_update (unsigned short fib,
                          struct pal_in6_addr *ipaddr,
                          unsigned char ipmask,
                          int numfib, struct hal_ipv6uc_nexthop *nexthopsfib,
                          int numnew, struct hal_ipv6uc_nexthop *nexthopsnew)
{
    return 0;
}
