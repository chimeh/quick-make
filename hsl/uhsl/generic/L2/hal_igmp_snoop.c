/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_igmp_snoop.h"

int hal_igmp_snooping_add_entry (char *bridge_name,
                             struct hal_in4_addr *src,
                             struct hal_in4_addr *group,
                             char is_exclude,
                             int vid,
                             int svid, int count, u_int32_t * ifindexes)
{
    return 0;
}
int hal_igmp_snooping_deinit (void)
{
    return 0;
}
int hal_igmp_snooping_delete_entry (char *bridge_name,
                                struct hal_in4_addr *src,
                                struct hal_in4_addr *group,
                                char is_exclude,
                                int vid,
                                int svid, int count, u_int32_t * ifindexes)
{
    return 0;
}
int hal_igmp_snooping_disable (char *bridge_name)
{
    return 0;
}
int hal_igmp_snooping_enable (char *bridge_name)
{
    return 0;
}
int hal_igmp_snooping_if_disable (char *name, unsigned int ifindex)
{
    return 0;
}
int hal_igmp_snooping_if_enable (char *name, unsigned int ifindex)
{
    return 0;
}
int hal_igmp_snooping_init (void)
{
    return 0;
}
