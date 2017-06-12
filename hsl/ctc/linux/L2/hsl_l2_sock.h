/* Copyright (C) 2004 IP Infusion, Inc.  All Rights Reserved. */

#ifndef _HSL_L2_SOCK_H
#define _HSL_L2_SOCK_H

#include "ctc_api.h"


#define HSL_L2_ETH_P_PAE                0x888e
#define HSL_L2_AUTH_HDR_LEN             4

#define HSL_L2_ETH_P_LACP               0x8809

#define HSL_L2_ETH_P_8021Q              0x8100

#define ENET_UNTAGGED_HDR_LEN 14
#define ENET_TAGGED_HDR_LEN   18


#if 0
int hsl_bcm_rx_handle_bpdu (struct hsl_if *ifp, bcm_pkt_t *pkt);
int hsl_bcm_rx_handle_eapol (struct hsl_if *ifp, bcm_pkt_t *pkt);
int hsl_bcm_rx_handle_lacp (struct hsl_if *ifp, bcm_pkt_t *pkt);
int hsl_bcm_rx_handle_gmrp (struct hsl_if *ifp, bcm_pkt_t *pkt);
int hsl_bcm_rx_handle_gvrp (struct hsl_if *ifp, bcm_pkt_t *pkt);
int hsl_bcm_rx_handle_igs (struct hsl_if *ifp, bcm_pkt_t *pkt);
int hsl_bcm_rx_handle_mlds (struct hsl_if *ifp, bcm_pkt_t *pkt);
#else

int hsl_ctc_rx_handle_bpdu (struct hsl_if *ifp, ctc_pkt_buf_t *pkt_buf);
int hsl_ctc_rx_handle_lacp (struct hsl_if *ifp, ctc_pkt_buf_t *pkt_buf);

#endif

int hsl_sock_post_skb (struct sock *sk, struct sk_buff *skb);


int hsl_af_stp_post_packet (struct sk_buff *skb);
int hsl_af_lacp_post_packet (struct sk_buff *skb);
int hsl_af_of_post_packet (struct sk_buff *skb, int pkt_type);
int hsl_af_eapol_post_packet (struct sk_buff *skb);
int hsl_af_garp_post_packet (struct sk_buff *skb);
int hsl_af_igs_post_packet (struct sk_buff *skb);
int hsl_af_mlds_post_packet (struct sk_buff *skb);
int hsl_l2_sock_init (void);
int hsl_l2_sock_deinit (void);

#endif /* _HSL_L2_SOCK_H_ */
