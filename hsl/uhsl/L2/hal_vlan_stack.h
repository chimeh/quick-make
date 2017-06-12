/* Copyright (C) 2003-2011 IP Infusion, Inc. All Rights Reserved.  */

/*  LAYER 2 Vlan Stacking  */
#ifndef __HAL_VLAN_STACK_H__
#define __HAL_VLAN_STACK_H__

/* Vlan stack mode */
#define HAL_VLAN_STACK_MODE_NONE      0 /* disable vlan stacking */
#define HAL_VLAN_STACK_MODE_INTERNAL  1 /* Use internal/service provider tag */
#define HAL_VLAN_STACK_MODE_EXTERNAL  2 /* Use external/customer tag */

/*
   Name: hal_vlan_stacking_enable
   
   Description:
   This API enables vlan stacking on an interface
   
   Parameters:
   IN -> ifindex - Interface index
   IN -> ethtype - Ethernet type value for the vlan tag
   IN -> stack_mode - Vlan stacking mode

   Returns:
   HAL_SUCCESS on success
   < 0 on failure
*/
extern int
hal_vlan_stacking_enable (u_int32_t ifindex, u_int16_t ethtype,
                          u_int16_t stackmode);

/*
   Name: hal_vlan_stacking_disable
   
   Description:
   This API disables vlan stacking on an interface
   
   Parameters:
   IN -> ifindex - Interface index
   IN -> ethtype - Ethernet type value for the vlan tag
   IN -> stack_mode - Vlan stacking mode

   Returns:
   HAL_SUCCESS on success
   < 0 on failure
*/
extern int
hal_vlan_stacking_disable (u_int32_t ifindex,
                           u_int16_t ethtype, u_int16_t stackmode);

#endif /* __HAL_VLAN_STACK_H__ */
