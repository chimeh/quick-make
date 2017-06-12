/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_vlan.h"


int hal_vlan_disable (char *bridge_name, enum hal_vlan_type type,
                  unsigned short vid)
{
    return 0;
}
int hal_vlan_enable (char *bridge_name, enum hal_vlan_type type,
                  unsigned short vid)
{
    return 0;
}

int hal_l2_unknown_mcast_mode (int mode)
{
    return 0;
}
int hal_pro_vlan_set_dtag_mode (unsigned int ifindex,
                                unsigned short dtag_mode)
{
    return 0;
}
int hal_uni_add (char *name, unsigned int port_no, u_char uni_type,
             u_int16_t svid)
{
    return 0;
}
int hal_vlan_add (char *name, enum hal_vlan_type type, enum hal_evc_type evc_type,
              unsigned short vid)
{
    return 0;
}
int hal_vlan_add_cvid_to_port (char *name, unsigned int ifindex,
                           unsigned short cvid,
                           unsigned short svid,
                           enum hal_vlan_egress_type egress)
{
    return 0;
}
int hal_vlan_add_pro_edge_port (char *name, unsigned int ifindex,
                            unsigned short svid)
{
    return 0;
}
int hal_vlan_add_vid_to_port (char *name, unsigned int ifindex,
                          unsigned short vid,
                          enum hal_vlan_egress_type egress)
{
    return 0;
}
int hal_vlan_create_cvlan (char *name, unsigned short cvid, unsigned short svid)
{
    return 0;
}
int hal_vlan_create_cvlan_registration_entry (char *name, unsigned int ifindex,
                                          unsigned short cvid,
                                          unsigned short svid)
{
    return 0;
}
int hal_vlan_create_vlan_trans_entry (char *name, unsigned int ifindex,
                                  unsigned short vid,
                                  unsigned short trans_vid)
{
    return 0;
}
int hal_vlan_deinit (void)
{
    return 0;
}
int hal_vlan_del_pro_edge_port (char *name, unsigned int ifindex,
                            unsigned short svid)
{
    return 0;
}
int hal_vlan_delete (char *name, enum hal_vlan_type type, unsigned short vid)
{
    return 0;
}
int hal_vlan_delete_cvid_from_port (char *name, unsigned int ifindex,
                                unsigned short cvid, unsigned short svid)
{
    return 0;
}
int hal_vlan_delete_cvlan (char *name, unsigned short cvid, unsigned short svid)
{
    return 0;
}
int hal_vlan_delete_cvlan_registration_entry (char *name, unsigned int ifindex,
                                          unsigned short cvid,
                                          unsigned short svid)
{
    return 0;
}
int hal_vlan_delete_vid_from_port (char *name, unsigned int ifindex,
                               unsigned short vid)
{
    return 0;
}
int hal_vlan_delete_vlan_trans_entry (char *name, unsigned int ifindex,
                                  unsigned short vid,
                                  unsigned short trans_vid)
{
    return 0;
}
int hal_vlan_init (void)
{
    return 0;
}
int hal_vlan_port_set_dot1q_state (unsigned int ifindex, unsigned short enable,
                               unsigned short enable_ingress_filter)
{
    return 0;
}
int hal_vlan_set_default_pvid (char *name, unsigned int ifindex,
                           unsigned short pvid,
                           enum hal_vlan_egress_type egress)
{
    return 0;
}
int hal_vlan_set_native_vid (char *name,
                         unsigned int ifindex, unsigned short native_vid)
{
    return 0;
}
int hal_vlan_set_port_type (char *name,
                        unsigned int ifindex,
                        enum hal_vlan_port_type port_type,
                        enum hal_vlan_port_type sub_port_type,
                        enum hal_vlan_acceptable_frame_type
                        acceptable_frame_types,
                        unsigned short enable_ingress_filter)
{
    return 0;
}
int hal_vlan_set_pro_edge_pvid (char *name, unsigned int ifindex,
                            unsigned short svid, unsigned short pvid)
{
    return 0;
}
int hal_vlan_set_pro_edge_untagged_vid (char *name, unsigned int ifindex,
                                    unsigned short svid,
                                    unsigned short untagged_vid)
{
    return 0;
}
