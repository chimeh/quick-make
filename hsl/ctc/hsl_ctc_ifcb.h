/* Copyright (C) 2004 IP Infusion, Inc.  All Rights Reserved. */

#ifndef _HSL_BCM_IFDB_H_
#define _HSL_BCM_IFDB_H_

/* Callback for port attachment message. */
int hsl_bcm_ifcb_port_attach (int gport, int unit, int port, uint32_t flags);

/* Callback for port detachment message. */
int hsl_bcm_ifcb_port_detach (int gport, int port);

/* Callback for link scan message. */
int hsl_bcm_ifcb_link_scan (int gport, void *info);

#endif /* _HSL_BCM_IFDB_H_ */
