/** @file    ctc_if_portmap.c
 *  @brief   
 *       
 *       
 *       
 *  @author  cdy
 *  @create  2016-05-11 10:46
 *  @version 0.1
 *  @note    
 *       
 *       
 *       
 *       
 *  $LastChangedDate$
 *  $LastChangedRevision$
 *  $LastChangedBy$
 *  Last modified: 2016-05-11 10:46
 */

#include <linux/kernel.h>
#include <linux/types.h>

#include "ctc_if_portmap.h"
#include "ctc_adapter_hsl_port.h"
#include "ctc_api.h"
#include "ctc_board_macros.h"


static int32_t  board_type[8] = {-1};



void hsl_set_board_type(int slot, int type)
{
	board_type[slot] = type;
}

uint32_t hsl_get_board_type(int slot)
{
	return board_type[slot];
}

/* NOTE: chip port and panel port is from 0 to 60 */

/* panel port to lport(ctc sdk locale port), 
** panel port --> lport(5160 port) 
*/
const int (*ctc_if_portmap_panel2lport)[CTC_PORT_MAX] = NULL;

/* lport(5160 port) to panel port, 
** gport(5160 port) --> panel port 
*/
const int  (*ctc_if_portmap_lport2panel)[CTC_PORT_MAX] = NULL;

/* panel port numbers */
int panel_port_num = -1;

/* fs5352 port map */
extern int ctc_if_portmap_panel2lport_fs5352[CTC_PORT_MAX];
extern int ctc_if_portmap_lport2panel_fs5352[CTC_PORT_MAX];

/* XGS port map */
extern int ctc_if_portmap_panel2lport_xgs[CTC_PORT_MAX];
extern int ctc_if_portmap_lport2panel_xgs[CTC_PORT_MAX];

extern int ctc_if_portmap_panel2lport_ges[CTC_PORT_MAX];
extern int ctc_if_portmap_lport2panel_ges[CTC_PORT_MAX];

/* if platform_id not available, use this portmap */
extern int ctc_if_portmap_panel2lport_invalid[CTC_PORT_MAX];
extern int ctc_if_portmap_lport2panel_invalid[CTC_PORT_MAX];

#define BOARD_PANEL_PORT_NUM_FS5352     40
#define BOARD_PANEL_PORT_NUM_XGS        6
#define BOARD_PANEL_PORT_NUM_GES        48
#define BOARD_PANEL_PORT_NUM_INVALID    0

/* For ctc platform port map */
int ctc_platform_port_map_init(void)
{
    int ret = 0;

    switch(board_id) {
    case BOARD_PLATFORM_ID_FS5352:
        panel_port_num = BOARD_PANEL_PORT_NUM_FS5352;
        ctc_if_portmap_panel2lport = ctc_if_portmap_panel2lport_fs5352;
        ctc_if_portmap_lport2panel = ctc_if_portmap_lport2panel_fs5352;
        break;

    case BOARD_PLATFORM_ID_XGS:
        panel_port_num = BOARD_PANEL_PORT_NUM_XGS;
        ctc_if_portmap_panel2lport = ctc_if_portmap_panel2lport_xgs;
        ctc_if_portmap_lport2panel = ctc_if_portmap_lport2panel_xgs;
        break;

	case BOARD_PLATFORM_ID_GES:
        panel_port_num = BOARD_PANEL_PORT_NUM_GES;
        ctc_if_portmap_panel2lport = ctc_if_portmap_panel2lport_ges;
        ctc_if_portmap_lport2panel = ctc_if_portmap_lport2panel_ges;	
		break;

    default:
        ret = -1;
        panel_port_num = BOARD_PANEL_PORT_NUM_INVALID;
        ctc_if_portmap_panel2lport = ctc_if_portmap_panel2lport_invalid;
        ctc_if_portmap_lport2panel = ctc_if_portmap_lport2panel_invalid;
        break;
    }

    return ret;
}

/* if failed, return NULL, else return the pointer of @name */
void *ctc_get_portname_by_gport(int type, int gport, char *name, int name_len)
{
    int   pal_port  = -1;

    uint8_t  lport  = 0;
    uint8_t  slot   = 0;
    uint8_t  io     = 0;
    
    if(name == NULL) {
        return NULL;
    }

    if(ctc_if_portmap_panel2lport == NULL || ctc_if_portmap_lport2panel == NULL) {
        printk("[%s]: PortMap not registered \r\n", __func__);
        return NULL;
    }

    if(type == CTC_PORT_F_XE || type == CTC_PORT_F_GE) {
        lport    = CTC_MAP_GPORT_TO_LPORT(gport);
        pal_port = CTC_PORT_LPORT_TO_PANEL(lport);
        slot     = CTC_GET_SLOT_FROM_GPORT(gport);
        if(pal_port < 0) {
            return NULL;    /* this gport not existed */
        }
    }

    switch(type) {
    case CTC_PORT_F_GE:
#if 0
        if(board_id == BOARD_PLATFORM_ID_ADS) {
            snprintf(name, name_len, "ge%d", pal_port);
        } else {
            snprintf(name, name_len, "gigabitethernet %d/%d/%d", slot, io, pal_port);
        }
#else
        snprintf(name, name_len, "gigabitethernet %d/%d/%d", slot, io, pal_port);
#endif
        break;

    case CTC_PORT_F_XE:
#if 0
        if(board_id == BOARD_PLATFORM_ID_ADS) {
            snprintf(name, name_len, "xe%d", pal_port);
        } else {
            snprintf(name, name_len, "10gigabitethernet %d/%d/%d", slot, io, pal_port);
        }
#else
        snprintf(name, name_len, "10gigabitethernet %d/%d/%d", slot, io, pal_port);
#endif
        break;

    default:
        snprintf(name, name_len, "unmaped_%d", gport);
        break;
    }

    return name;
}

/* get ifindex from linkagg, slot, io, panel_port */
uint32_t port_num_to_ifindex(uint8_t linkagg_flag, uint8_t slot,     \
                             uint8_t io, uint16_t panel_port)
{
    uint32_t ifindex = 0;

    ifindex =  NGN_IFINDEX_BASE                                                                  \
            + ((linkagg_flag & NGN_IFINDEX_LINKAGG_FLAG_MASK) << NGN_IFINDEX_LINKAGG_FLAG_SHIFT) \
            + (((slot - 1)   & NGN_IFINDEX_SLOT_ID_MASK)      << NGN_IFINDEX_SLOT_ID_SHIFT)      \
            + ((io           & NGN_IFINDEX_IO_ID_MASK)        << NGN_IFINDEX_IO_ID_SHIFT)        \
            + ((panel_port   & NGN_IFINDEX_PORT_MASK)         << NGN_IFINDEX_PORT_SHIFT);

    return ifindex;
}

/* get port info from ifindex */
int ifindex_to_port_num(uint8_t *linkagg_flag, uint8_t *slot,    \
                        uint8_t *io, uint16_t *panel_port, uint32_t ifindex)
{
    *linkagg_flag = CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(ifindex);
    *slot         = CTC_GET_SLOT_FROM_IFINDEX(ifindex);
    *io           = CTC_GET_IO_FROM_IFINDEX(ifindex);
    *panel_port   = CTC_GET_PANEL_PORT_FROM_IFINDEX(ifindex);

    return 0;
}

/* Only can calculate linkagg_id and physical port to ifindex */
int ctc_gport_to_ifindex(uint16_t gport)
{
    uint8_t  slot  = CTC_GET_SLOT_FROM_GPORT(gport);
    uint8_t  io    = 0;
    uint8_t  lport = CTC_MAP_GPORT_TO_LPORT(gport);
    int      panel_port   = -1;
    /* if gport is linkagg port, set to 1 */
    int      is_linkagg   = CTC_IS_LINKAGG_PORT(gport);
    int      linkagg_flag = 0;
    int      ifindex = 0;

    if(ctc_if_portmap_panel2lport == NULL || ctc_if_portmap_lport2panel == NULL) {
        printk("[%s]: PortMap not registered \r\n", __func__);
        return -1;
    }

    if(is_linkagg) {
        /* linkagg port */
        linkagg_flag = NGN_IFINDEX_LINKAGG_FLAG_MASK;
        panel_port   = CTC_MAP_GPORT_TO_TID(gport); /* linkagg id */
    } else {
        linkagg_flag = 0;
        panel_port   = CTC_PORT_LPORT_TO_PANEL(lport);
    }

    if(panel_port < 0) {
        return -1;
    }

    ifindex = port_num_to_ifindex(linkagg_flag, slot, io, panel_port);

    return ifindex;
}

/* Only can calculate linkagg port and panel port ifindex to gport */
uint16_t ctc_ifindex_to_gport(int ifindex)
{
    uint8_t  lport  = 0;
    int      panel_port = CTC_GET_PANEL_PORT_FROM_IFINDEX(ifindex);
    uint8_t  gchip      = 0;
	uint8_t  self_gchip      = 0;
    uint16_t gport      = 0;

    uint8_t  linkagg_id = 0;
    int      is_linkagg = CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(ifindex);

    if(ctc_if_portmap_panel2lport == NULL || ctc_if_portmap_lport2panel == NULL) {
        printk("[%s]: PortMap not registered \r\n", __func__);
        return -1;
    }

    if(ifindex < 0) {
        return (uint16_t )(-1);
    }

    if(is_linkagg) {
        /* linkagg port */
        linkagg_id = panel_port;
        gport = CTC_MAP_TID_TO_GPORT(linkagg_id);
    } else {
       // lport = CTC_PORT_PANEL_TO_LPORT(panel_port);
        gchip = CTC_GET_GCHIP_FROM_SLOT(CTC_GET_SLOT_FROM_IFINDEX(ifindex));
        if (gchip < 0) {
            /* shouldn't be happened */
            gchip = 0;
            printk(KERN_ERR "[%s]: Get wrong gchip from ifindex: %#x\r\n", __func__, ifindex);
        }

		ctc_get_gchip_id(0, &self_gchip);
		if (self_gchip == gchip) {  /*±¾°å×ª»»*/
			lport = CTC_PORT_PANEL_TO_LPORT(panel_port);
		} else if (IS_XGS_BOARD(gchip)) {
			lport = ctc_if_portmap_panel2lport_xgs[panel_port];
		} else if (IS_GES_BOARD(gchip)) {
			lport = ctc_if_portmap_panel2lport_ges[panel_port];
		} else {
			return -1;
		}
        gport = CTC_MAP_LPORT_TO_GPORT(gchip, lport);
    }

    return gport;
}


unsigned short ctc_gport_to_l3ifid(unsigned short gport)
{
    uint16_t lport  = 0;
    uint16_t gchip  = 0;
    uint16_t l3ifid = 0;

    /* gchip from 0 to 7 is ok */
    if(gport & 0xf800) {
        printk("[%s]: Only support gchip from 0 to 7, gport: %#x\r\n", __func__, gport);
    }

    /* lport from 0 to 59 is ok */
    if(gport & 0x00c0) {
        printk("[%s]: Only support lport from 0 to 59, gport: %#x\r\n", __func__, gport);
    }

    gchip = CTC_MAP_GPORT_TO_GCHIP(gport) & 0x7;
    lport = CTC_MAP_GPORT_TO_LPORT(gport) & 0xff;

    /* get l3 interface id */
    l3ifid = gchip << 6 | lport;
    if(l3ifid == 0) {
        l3ifid = 1022;
    }

    if(l3ifid & 0xfc00) {
        printk("[%s]: calculate l3ifid failed: %#x\r\n", __func__, l3ifid);
    }

    return l3ifid;
}




