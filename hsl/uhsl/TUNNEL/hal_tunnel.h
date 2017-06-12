/* Copyright (C) 2003-2011 IP Infusion, Inc. All Rights Reserved.  */

/*  LAYER 2 Vlan Stacking  */
#ifndef __HAL_TUNNEL_H__
#define __HAL_TUNNEL_H__

#define HAL_TUNNEL_NAME_LEN 32
#define HAL_TUNNEL_HWADDR_MAX 20
#define HAL_TIF_MAX 64
struct hal_msg_tunnel_if
{
    char name[HAL_TUNNEL_NAME_LEN];
    unsigned int ifindex;
    unsigned int mtu;
    unsigned int bandwidth;
    unsigned int flags;
    unsigned int duplex;
    unsigned int speed;
    unsigned char hwaddr[HAL_TUNNEL_HWADDR_MAX];
    unsigned char tif[HAL_TIF_MAX];
};

int hal_msg_tunnel_add (struct hal_msg_tunnel_if *tifp);
int hal_msg_tunnel_initiator_set(struct hal_msg_tunnel_if *tifp);
int hal_msg_tunnel_initiator_clear(struct hal_msg_tunnel_if *tifp);
int hal_msg_tunnel_terminator_set(struct hal_msg_tunnel_if *tifp);
int hal_msg_tunnel_terminator_clear(struct hal_msg_tunnel_if *tifp);
int hal_msg_tunnel_delete(struct hal_msg_tunnel_if *tifp);

#endif /* __HAL_TUNNEL_H__ */
