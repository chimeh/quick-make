/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_BCM_LACP_H_
#define _HSL_BCM_LACP_H_

#ifdef HAVE_LACPD

int hsl_bcm_lacp_init (void);
int hsl_bcm_lacp_deinit (void);
int hsl_bcm_aggregator_add (struct hsl_if *ifp, int agg_type);
int hsl_bcm_aggregator_del (struct hsl_if *ifp);
int hsl_bcm_aggregator_port_add (struct hsl_if *agg_ifp, struct hsl_if *port_ifp);
int hsl_bcm_aggregator_port_del (struct hsl_if *agg_ifp, struct hsl_if *port_ifp);
int hsl_bcm_lacp_psc_set (struct hsl_if *ifp,int psc);
int hsl_bcm_lacp_nuc_psc_set (int psc);

#endif /* HAVE_LACPD */
#endif /* _HSL_BCM_LACP_H_ */
