/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_lacp.h"

int hal_lacp_add_aggregator (char *name, unsigned char mac[], int agg_type)
{
    return 0;
}
int hal_lacp_attach_mux_to_aggregator (char *agg_name, unsigned int agg_ifindex,
                                   char *port_name,
                                   unsigned int port_ifindex)
{
    return 0;
}
int hal_lacp_collecting (char *name, unsigned int ifindex, int enable)
{
    return 0;
}
int hal_lacp_collecting_distributing (char *name, unsigned int ifindex,
                                  int enable)
{
    return 0;
}
int hal_lacp_deinit (void)
{
    return 0;
}
int hal_lacp_delete_aggregator (char *name, unsigned int ifindex)
{
    return 0;
}
int hal_lacp_detach_mux_from_aggregator (char *agg_name, unsigned int agg_ifindex,
                                     char *port_name,
                                     unsigned int port_ifindex)
{
    return 0;
}
int hal_lacp_distributing (char *name, unsigned int ifindex, int enable)
{
    return 0;
}
int hal_lacp_init (void)
{
    return 0;
}
int hal_lacp_psc_set (unsigned int ifindex, int psc)
{
    return 0;
}
