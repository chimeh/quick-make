/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_pvlan.h"

int hal_pvlan_host_association (char *bridge_name, int ifindex,
                            unsigned short vid, unsigned short pvid,
                            int associate)
{
    return 0;
}
int hal_pvlan_set_port_mode (char *bridge_name, int ifindex,
                         enum hal_pvlan_port_mode mode)
{
    return 0;
}
int hal_set_pvlan_type (char *bridge_name, unsigned short vid,
                    enum hal_pvlan_type type)
{
    return 0;
}
int hal_vlan_associate (char *bridge_name, unsigned short vid,
                    unsigned short pvid, int associate)
{
    return 0;
}
