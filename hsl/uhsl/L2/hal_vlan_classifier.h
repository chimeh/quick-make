/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_VLAN_CLASSIFIER_H_
#define _HAL_VLAN_CLASSIFIER_H_

/* Filter type */
#define HAL_VLAN_CLASSIFIER_MAC       1 /* filter on source MAC */
#define HAL_VLAN_CLASSIFIER_PROTOCOL  2 /* filter on protocol */
#define HAL_VLAN_CLASSIFIER_IPV4      4 /* filter on src IPv4 subnet */
#define HAL_VLAN_CLASSIFIER_IPV6      8 /* filter on src IPv6 subnet */

/* Encapsulation */
#define HAL_VLAN_CLASSIFIER_ETH        0x00020000       /* Ethernet v2 */
#define HAL_VLAN_CLASSIFIER_NOSNAP_LLC 0x00020001       /* No snap LLC */
#define HAL_VLAN_CLASSIFIER_SNAP_LLC   0x00020002       /* Snap LLC */

struct hal_vlan_classifier_rule
{
  int type;                     /* Type of classifier: Protocol/Mac/Subnet */
  unsigned short vlan_id;       /* Destination vlan_id                     */
  u_int32_t rule_id;            /* Rule identification number.             */
  u_int32_t row_status;         /* Row status for ProtocolGroupTable.      */

  union                         /* Rule criteria.                          */
  {
    unsigned char mac[ETHER_ADDR_LEN];  /* Mac address.                      */

    struct
    {
      unsigned int addr;
      unsigned char masklen;
    } ipv4;


    struct
    {
      unsigned short ether_type;        /* Protocol value                          */
      unsigned int encaps;      /* Packet L2 encapsulation.                */
    } protocol;

  } u;

  struct avl_tree *group_tree;  /* Groups rule attached to.  */
};
struct hal_msg_vlan_classifier_rule;

/*
   Name: hal_vlan_classifier_init
   
   Description:
   This API initializes the vlan classifier hardware layer.
   
   Parameters:
   None
   
   Returns:
   HAL_ERR_VLAN_CLASSIFIER_INIT
   HAL_SUCCESS
*/
int hal_vlan_classifier_init ();

/*
   Name: hal_vlan_classifier_deinit
   
   Description:
   This API deinitializes the vlan classifier hardware layer.
   
   Parameters:
   None
   
   Returns:
   HAL_ERR_VLAN_CLASSIFIER_DEINIT
   HAL_SUCCESS
*/
int hal_vlan_classifier_deinit ();


/*
   Name: hal_vlan_classifier_add
   
   Description:
   This API adds a vlan classification group.
   
   Parameters:
   IN -> rule_msg - Vlan Classification rule msg
   
   Returns:
   HAL_ERR_VLAN_CLASSIFIER_ADD
   HAL_SUCCESS
*/
int
hal_vlan_classifier_add (struct hal_vlan_classifier_rule *rule_ptr,
                         u_int32_t ifindex, u_int32_t refcount);


/*
   Name: hal_vlan_classifier_del
   
   Description:
   This API deletes a vlan classification group.
   
   Parameters:
   IN -> rule_msg     - Vlan Classification rule
   
   Returns:
   HAL_ERR_VLAN_CLASSIFIER_ADD
   HAL_SUCCESS
*/
int
hal_vlan_classifier_del (struct hal_vlan_classifier_rule *rule_ptr,
                         u_int32_t ifindex, u_int32_t refcount);

#endif /* _HAL_VLAN_CLASSIFIER_H */
