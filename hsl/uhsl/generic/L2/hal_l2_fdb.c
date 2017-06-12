/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_l2_fdb.h"

int hal_bridge_flush_dynamic_fdb_by_mac (char *bridge_name,
                                     const unsigned char *const mac,
                                     int maclen)
{
    return 0;
}
int hal_bridge_flush_fdb_by_port (char *bridge_name,
                              unsigned int ifindex, unsigned int instance,
                              unsigned short vid, unsigned short svid)
{
    return 0;
}
int hal_l2_add_fdb (const char *const name, unsigned int ifindex,
                const unsigned char *const mac, int len,
                unsigned short vid, unsigned short svid,
                unsigned char flags, hal_bool_t is_forward)
{
    return 0;
}
int hal_l2_add_priority_ovr (const char *const name, unsigned int ifindex,
                         const unsigned char *const mac, int len,
                         unsigned short vid,
                         unsigned char ovr_mac_type, unsigned char priority)
{
    return 0;
}
int hal_l2_del_fdb (const char *const name, unsigned int ifindex,
                const unsigned char *const mac, int len,
                unsigned short vid, unsigned short svid, unsigned char flags)
{
    return 0;
}
int hal_l2_fdb_deinit (void)
{
    return 0;
}
int hal_l2_fdb_init (void)
{
    return 0;
}
int hal_l2_fdb_multicast_get (char *name, char *mac_addr, unsigned short vid,
                          unsigned short count,
                          struct hal_fdb_entry *fdb_entry)
{
    return 0;
}
int hal_l2_fdb_unicast_get (char *name, char *mac_addr, unsigned short vid,
                        unsigned short count,
                        struct hal_fdb_entry *fdb_entry)
{
    return 0;
}
int hal_l2_get_index_by_mac_vid (char *bridge_name, int *ifindex, char *mac,
                             u_int16_t vid)
{
    return 0;
}
