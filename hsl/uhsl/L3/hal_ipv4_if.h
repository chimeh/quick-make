/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_IF_IPV4_H_
#define _HAL_IF_IPV4_H_

/* VIF type. */
#define HAL_IPV4_VIF_TUNNEL                        (1 << 0)
#define HAL_IPV4_VIF_REGISTER                      (1 << 1)
/* 
   Name: hal_if_ipv4_address_add 

   Description:
   This API adds a IPv4 address to a L3 interface.

   Parameters:
   IN -> ifname - interface name
   IN -> ifindex - interface ifindex
   IN -> ipaddr - ipaddress of interface
   IN -> ipmask - mask length

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int
hal_if_ipv4_address_add (char *ifname, unsigned int ifindex,
                         struct pal_in4_addr *ipaddr, unsigned char ipmask);

/* 
   Name: hal_if_ipv4_address_delete

   Description:
   This API deletes the IPv4 address from a L3 interface.

   Parameters:
   IN -> ifname - interface name
   IN -> ifindex - interface ifindex
   IN -> ipaddr - ipaddress of interface
   IN -> ipmask - mask length

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int
hal_if_ipv4_address_delete (char *ifname, unsigned int ifindex,
                            struct pal_in4_addr *ipaddr,
                            unsigned char ipmask);

int hal_create_ports (int, int);

#endif /* _HAL_IF_IPV4_H_ */
