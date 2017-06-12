/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_ipv4_if.h"

int hal_create_ports (int blade_id, int port_count)
{
    return 0;
}
int hal_if_ipv4_address_add (char *ifname, unsigned int ifindex,
                         struct pal_in4_addr *ipaddr, unsigned char ipmask)
{
    return 0;
}
int hal_if_ipv4_address_delete (char *ifname, unsigned int ifindex,
                            struct pal_in4_addr *ipaddr,
                            unsigned char ipmask)
{
    return 0;
}
