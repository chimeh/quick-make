/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_IF_IPV6_H_
#define _HAL_IF_IPV6_H_

/* VIF type. */
#define HAL_IPV6_VIF_TUNNEL                        (1 << 0)
#define HAL_IPV6_VIF_REGISTER                      (1 << 1)

/* 
   Name: hal_if_ipv6_address_add 

   Description:
   This API adds a IPv6 address to a L3 interface.

   Parameters:
   IN -> ifname - interface name
   IN -> ifindex - interface ifindex
   IN -> ipaddr - ipaddress of interface
   IN -> ipmask - mask length
   IN -> flags - flags for the address

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int
hal_if_ipv6_address_add (char *ifname, unsigned int ifindex,
                         struct pal_in6_addr *ipaddr, int ipmask,
                         unsigned char flags);

/* 
   Name: hal_if_ipv6_address_delete

   Description:
   This API deletes the IPv6 address from a L3 interface.

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
hal_if_ipv6_address_delete (char *ifname, unsigned int ifindex,
                            struct pal_in6_addr *ipaddr, int ipmask);

#endif /* _HAL_IF_IPV6_H_ */
