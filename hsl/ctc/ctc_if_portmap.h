/** @file    ctc_if_portmap.h
 *  @brief   convert between panel port and gport(switch 5160 port)
 *       
 *       
 *  @author  cdy
 *  @create  2016-05-12 16:24
 *  @version 0.1
 *  @note    
 *       
 *       
 *       
 *       
 *  $LastChangedDate$
 *  $LastChangedRevision$
 *  $LastChangedBy$
 *  Last modified: 2016-05-12 16:24
 */


#ifndef __IF_PORTMAP_H__
#define __IF_PORTMAP_H__

#include "ctc_api.h"

#define BOARD_TYPE_XGS   3     
#define BOARD_TYPE_GES   2

extern void hsl_set_board_type(int slot, int type);
extern uint32_t hsl_get_board_type(int slot);

#define IS_XGS_BOARD(SLOT)  (hsl_get_board_type(SLOT) == BOARD_TYPE_XGS ? 1 : 0)
#define IS_GES_BOARD(SLOT)  (hsl_get_board_type(SLOT) == BOARD_TYPE_GES ? 1 : 0)

#define CTC_PORT_MAX                60
#define CTC_FS5352_10G_MIN_LPORT    48
extern const int  (*ctc_if_portmap_lport2panel)[];  /* lport to panel port */
extern const int  (*ctc_if_portmap_panel2lport)[];  /* panel port to lport */
extern int panel_port_num;

/* according to @gport to get panel port name, return the pointer of @name */
extern void *ctc_get_portname_by_gport(int type, int gport, char *name, int name_len);

/* SDK MUST call this to init portmap, if not, no port can be used */
extern int ctc_platform_port_map_init(void);

/*******************************************************************************/
/* added by cdy, 2016/10/08, for zebm ifindex, gport, slot_id, lport, pale_prt */
/*******************************************************************************/

/* nsm calculate ifindex, slot begin from 1 */
#define CTC_GET_SLOT_FROM_GPORT(gport)  (CTC_MAP_GPORT_TO_GCHIP(gport) + 1)
#define CTC_GET_GCHIP_FROM_SLOT(slot)   ((slot) - 1)

/* panel port to ctc local phy port */
#define CTC_PORT_PANEL_TO_LPORT(panel_port) ((ctc_if_portmap_panel2lport == NULL)   \
                                           ? -1                                     \
                                           : ((*ctc_if_portmap_panel2lport)[(panel_port)]))

/* ctc local phy port to panel port */
#define CTC_PORT_LPORT_TO_PANEL(lport)      ((ctc_if_portmap_lport2panel == NULL)   \
                                           ? -1                                     \
                                           : ((*ctc_if_portmap_lport2panel)[(lport)]))

/* ifindex:
**  bit_19 to bit_31 are reserved
**  linkagg_flag: 2bit << 17
**  slot_id     : 8bit << 9
**  io_id       : 2bit << 7
**  panel_port  : 8bit << 0
*/
#define NGN_IFINDEX_BASE                200
#define NGN_IFINDEX_LINKAGG_FLAG_SHIFT  17
#define NGN_IFINDEX_LINKAGG_FLAG_MASK   0x3     /* 2-bit */
#define NGN_IFINDEX_SLOT_ID_SHIFT       9
#define NGN_IFINDEX_SLOT_ID_MASK        0xff    /* 8-bit */
#define NGN_IFINDEX_IO_ID_SHIFT         7
#define NGN_IFINDEX_IO_ID_MASK          0x3     /* 2-bit */
#define NGN_IFINDEX_PORT_SHIFT          0
#define NGN_IFINDEX_PORT_MASK           0x7f    /* 8-bit */

#define CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(ifindex)  \
    ((((ifindex) - NGN_IFINDEX_BASE) >> NGN_IFINDEX_LINKAGG_FLAG_SHIFT) & NGN_IFINDEX_LINKAGG_FLAG_MASK)

#define CTC_GET_SLOT_FROM_IFINDEX(ifindex)      \
    (((((ifindex) - NGN_IFINDEX_BASE) >> NGN_IFINDEX_SLOT_ID_SHIFT) + 1) & NGN_IFINDEX_SLOT_ID_MASK)

#define CTC_GET_IO_FROM_IFINDEX(ifindex)        \
    ((((ifindex) - NGN_IFINDEX_BASE) >> NGN_IFINDEX_IO_ID_SHIFT) & NGN_IFINDEX_IO_ID_MASK)

#define CTC_GET_PANEL_PORT_FROM_IFINDEX(ifindex)    \
    ((((ifindex) - NGN_IFINDEX_BASE) >> NGN_IFINDEX_PORT_SHIFT) & NGN_IFINDEX_PORT_MASK)


extern uint32_t port_num_to_ifindex(uint8_t linkagg_flag, uint8_t slot, uint8_t io, uint16_t panel_port);

extern int ifindex_to_port_num(uint8_t *linkagg_flag, uint8_t *slot,    \
                               uint8_t *io, uint16_t *panel_port, uint32_t ifindex);

extern int ctc_gport_to_ifindex(uint16_t gport);
extern uint16_t ctc_ifindex_to_gport(int ifindex);

/* Only can calculate linkagg_id and physical port to ifindex */
#define GPORT_TO_IFINDEX(gport)     ctc_gport_to_ifindex(gport)

/* Only can calculate linkagg port and panel port ifindex to gport */
#define IFINDEX_TO_GPORT(ifindex)   ctc_ifindex_to_gport(ifindex)

/* change gport to l3 interface port number, 1 to 1022 */
extern unsigned short ctc_gport_to_l3ifid(unsigned short gport);

#endif  /* __IF_PORTMAP_H__ */

