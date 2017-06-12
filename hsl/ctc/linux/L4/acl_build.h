#ifndef _ACL_BUILD_H
#define _ACL_BUILD_H
#include "ctc_api.h"
#define MAX_BCM_L4_PORT	65534
#define MIN_BCM_L4_PORT 0

#define COS7	7
#define COS6	6
#define COS5	5
#define COS4	4
#define COS3	3
#define COS2	2
#define COS1	1
#define COS0	0

#define TCP_PACKET	1
#define UDP_PACKET	2

#define PROTOCOL_ICMP 1
#define PROTOCOL_UDP  17
#define PROTOCOL_TCP  6

#define FLAGS_NOT_SET		0x00
#define FLAGS_TYPE_SET		0x01	/* only set icmp type */
#define FLAGS_CODE_SET		0x02	/* both icmp type and code are set */

/* access entry hdr type */
#define ACCESS_ENTRY_TYPE_STD_IP	0x00
#define ACCESS_ENTRY_TYPE_EXT_IP	0x01
#define ACCESS_ENTRY_TYPE_EXT_ICMP	0x02
#define ACCESS_ENTRY_TYPE_EXT_UDP	0x03
#define ACCESS_ENTRY_TYPE_EXT_TCP	0x04
#define MAX_ACCESS_ENTRY_TYPE		0x05

#define ACL_DENY	    0x0
#define ACL_PERMIT  	0x1
#define ACL_NOT_MATCH	0x2
#define ACL_NOT_FOUND	0x3
#define ACL_NOT_STAND	0x4


#define IP(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]


extern int hsl_msg_recv_ifp_acl_group_build(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);
extern int hsl_msg_recv_ifp_vlan_acl_group_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf);

extern int ctc_build_acl_std(	ctc_acl_entry_t *ctc_entry, 
			struct std_access_entry *entry, cap_sub_info_t *sub);
extern int ctc_build_acl_ext_ip(	ctc_acl_entry_t *ctc_entry,
	struct ext_ip_access_entry *entry, cap_sub_info_t *sub);
extern int ctc_build_acl_udp(	ctc_acl_entry_t *ctc_entry, 
	struct ext_udp_access_entry *entry, cap_sub_info_t *sub);
extern int ctc_build_acl_tcp(	ctc_acl_entry_t *ctc_entry, 
	struct ext_tcp_access_entry *entry, cap_sub_info_t *sub);
extern int ctc_build_acl_icmp(	ctc_acl_entry_t *ctc_entry, 
	struct ext_icmp_access_entry *entry, cap_sub_info_t *sub);
extern int acl_build_action(cap_info_t *cap, ctc_acl_entry_t *ctc_entry, bool permit);
extern int ctc_default_acl_build(void);

extern int ifindexpbmp_2_gportmap(l4_pbmp_t *ifindexpbmp,  ctc_port_bitmap_t *port_map);

#endif

