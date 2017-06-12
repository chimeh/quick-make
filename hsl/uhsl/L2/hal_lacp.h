/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_LACP_H_
#define _HAL_LACP_H_

/* Port Selection Criteria for Link Aggregation */
#define HAL_LACP_PSC_DST_MAC          1
#define HAL_LACP_PSC_SRC_MAC          2
#define HAL_LACP_PSC_SRC_DST_MAC      3
#define HAL_LACP_PSC_SRC_IP           4
#define HAL_LACP_PSC_DST_IP           5
#define HAL_LACP_PSC_SRC_DST_IP       6
#define HAL_LACP_PSC_SRC_PORT         7
#define HAL_LACP_PSC_DST_PORT         8
#define HAL_LACP_PSC_SRC_DST_PORT     9
/* 
   Name: hal_lacp_init

   Description:
   This API initializes the link aggregation hardware layer component.

   Parameters:
   None

   Returns:
   HAL_ERR_LACP_INIT
   HAL_SUCCESS
*/
int hal_lacp_init (void);

/* 
   Name: hal_lacp_deinit

   Description:
   This API deinitializes the link aggregation hardware layer component.

   Parameters:
   None

   Returns:
   HAL_ERR_LACP_DEINIT
   HAL_SUCCESS
*/
int hal_lacp_deinit (void);


/* 
   Name: hal_lacp_add_aggregator

   Description:
   This API adds a aggregator with the specified name and mac address.

   Parameters:
   IN -> name - aggregator name
   IN -> mac  - mac address of aggregator
   IN -> agg_type - aggregator type (L2/L3)

   Returns:
   HAL_ERR_LACP_EXISTS
   HAL_SUCCESS
*/
int hal_lacp_add_aggregator (char *name, unsigned char mac[], int agg_type);




/* 
   Name: hal_lacp_delete_aggregator

   Description:
   This API deletes a aggregator.

   Parameters:
   IN -> name - aggregator name
   IN -> ifindex - aggregator ifindex

   Returns:
   HAL_ERR_LACP_NOT_EXISTS
   HAL_SUCCESS
*/
int hal_lacp_delete_aggregator (char *name, unsigned int ifindex);




/* 
   Name: hal_lacp_attach_mux_to_aggregator

   Description:
   This API adds a port to a aggregator.

   Parameters:
   IN -> agg_name - aggregator name
   IN -> agg_ifindex - aggregator ifindex
   IN -> port_name - port name
   IN -> port_ifindex - port ifindex

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int
hal_lacp_attach_mux_to_aggregator (char *agg_name, unsigned int agg_ifindex,
                                   char *port_name,
                                   unsigned int port_ifindex);





/* 
   Name: hal_lacp_detach_mux_from_aggregator

   Description:
   This API deletes a port from a aggregator.

   Parameters:
   IN -> agg_name - aggregator name
   IN -> agg_ifindex - aggregator ifindex
   IN -> port_name - port name
   IN -> port_ifindex - port ifindex

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int
hal_lacp_detach_mux_from_aggregator (char *agg_name, unsigned int agg_ifindex,
                                     char *port_name,
                                     unsigned int port_ifindex);




/* 
   Name: hal_lacp_psc_set

   Description:
   This API sets load balancing mode for an aggregator

   Parameters:
   IN -> psc - port selection criteria (src mac/dst mac based)
   IN -> Ifindex - Aggregator interface ifindex.

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int hal_lacp_psc_set (unsigned int ifindex, int psc);



/* 
   Name: hal_lacp_collecting

   Description:
   This API enables or disables collecting on a port. 

   Parameters:
   IN -> name - aggregator name
   IN -> ifindex - port ifindex
   IN -> enable - enable

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int hal_lacp_collecting (char *name, unsigned int ifindex, int enable);

/* 
   Name: hal_lacp_distributing

   Description:
   This API enables or disables distributing for a port.

   Parameters:
   IN -> name - aggregator name
   IN -> ifindex - port ifindex
   IN -> enable - enable

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int hal_lacp_distributing (char *name, unsigned int ifindex, int enable);

/* 
   Name: hal_lacp_collecting_distributing

   Parameters:
   IN -> name - aggregator name
   IN -> ifindex - port ifindex
   IN -> enable - enable

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int
hal_lacp_collecting_distributing (char *name, unsigned int ifindex,
                                  int enable);


#endif /* _HAL_LACP_H_ */
