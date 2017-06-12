/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_CTC_PKT_H_
#define _HSL_CTC_PKT_H_
/* 
   Function prototypes. 
*/
int hsl_ctc_pkt_init (void);
int hsl_ctc_pkt_deinit (void);
//ctc_pkt_tx_t* hsl_ctc_tx_pkt_alloc(int num);
//void hsl_ctc_tx_pkt_free(ctc_pkt_tx_t * pkt);
int hsl_ctc_pkt_send (u8 *buf, u32 len, u16 gport, u16 vid,bool tagged);
int hsl_ctc_pkt_vlan_flood (u8 *buf, u32 len, u32 vid, struct hsl_if *vlanifp);


#endif /* _HSL_CTC_PKT_H_ */
