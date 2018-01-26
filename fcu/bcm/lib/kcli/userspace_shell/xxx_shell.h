/**
 @file xxx_master_cli.h

 @date 2014-12-22

 @version v2.0

 This file define the types used in APIs

*/

#ifndef _XXX_MASTER_CLI_H
#define _XXX_MASTER_CLI_H
#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************
 *
 * Header Files
 *
 ***************************************************************/


/****************************************************************
*
* Defines and Macros
*
****************************************************************/
/**
 @defgroup xxx_master XXX_MASTER
 @{
*/
/**
 @brief define netlink protocol
*/
#define XXX_SDK_NETLINK 		20

/**
 @brief define netlik msg length
*/
#define XXX_SDK_NETLINK_MSG_LEN 9600

/**
 @brief define tcp port
*/
#define XXX_SDK_TCP_PORT 		8100

/**
 @brief define CMD
*/
#define XXX_SDK_CMD_QUIT        0x0001

struct xxx_msg_hdr {
	uint32_t		msg_len;		/* Length of message including header */
	uint16_t		msg_type;		/* Message content */
	uint16_t		msg_flags;		/* Additional flags */
	uint32_t		msg_turnsize;	/* Ture size */
	uint32_t		msg_pid;		/* Sending process port ID */
};

/**
 @brief packet
*/
typedef struct xxx_sdk_packet_s
{
    struct 	xxx_msg_hdr hdr;
    char 				msg[XXX_SDK_NETLINK_MSG_LEN];
}xxx_sdk_packet_t;

/**@} end of @defgroup xxx_master  */

#ifdef __cplusplus
}
#endif

#endif
