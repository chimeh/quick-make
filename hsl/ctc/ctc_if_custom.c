/** @file    ctc_if_custom.c
 *  @brief   
 *       
 *       
 *       
 *  @author  cdy
 *  @create  2016-06-27 17:18
 *  @version 0.1
 *  @note    
 *       
 *       
 *       
 *       
 *  $LastChangedDate$
 *  $LastChangedRevision$
 *  $LastChangedBy$
 *  Last modified: 2016-06-27 17:18
 */

#include "config.h"

#include "sal_types.h"
#include "hsl_types.h"
#include "hsl_oss.h"

#include "hsl_if_cust.h"
#include "hsl_ifmgr.h"
#include "hsl_ctc_if.h"
#include "hsl_error.h"

#include "ctc_if_portmap.h"


#define CTC_PORT_LAYER_TYPE_ETH                 0x10
#define CTC_PORT_LAYER_TYPE_LINKAGG_STA         0x11
#define CTC_PORT_LAYER_TYPE_LINKAGG_DYN         0x12

/* alloc ifindex */
static int ctc_cust_if_alloc_ifindex(struct hsl_if *ifp, hsl_ifIndex_t *ifindex)
{
    int port_type   = HSL_IF_TYPE_L2_ETHERNET;
    int linkagg_id  = -1;
    int ctc_ifindex = HSL_IFMGR_ERR_INDEX;
    struct hsl_bcm_if *ctcifp = NULL;

    if(ifindex == NULL || ifp == NULL) {
        return HSL_IFMGR_ERR_INVALID_PARAM;
    }
    
    ctcifp = (struct hsl_bcm_if *)(ifp->system_info);

    if(memcmp(ifp->name, "sa", 2) == 0) {
        port_type = CTC_PORT_LAYER_TYPE_LINKAGG_STA;
    }
    if(memcmp(ifp->name, "po", 2) == 0) {
        port_type = CTC_PORT_LAYER_TYPE_LINKAGG_DYN;
    }
    if(  port_type == CTC_PORT_LAYER_TYPE_LINKAGG_STA  \
      || port_type == CTC_PORT_LAYER_TYPE_LINKAGG_DYN) {
        sscanf(&ifp->name[2], "%d", &linkagg_id);
        if(linkagg_id < 0) {
            return ctc_ifindex;
        }
    }

    switch(port_type) {
    case HSL_IF_TYPE_L2_ETHERNET:
        ctc_ifindex = GPORT_TO_IFINDEX(ctcifp->u.l2.lport);
        break;

    case CTC_PORT_LAYER_TYPE_LINKAGG_STA:
    case CTC_PORT_LAYER_TYPE_LINKAGG_DYN:
        ctc_ifindex = GPORT_TO_IFINDEX(CTC_MAP_TID_TO_GPORT(linkagg_id));
        break;

    default:
        ctc_ifindex = HSL_IFMGR_ERR_INDEX;
        break;
    }

    if(ctc_ifindex > 0) {
        *ifindex = ctc_ifindex;
    }

    return ctc_ifindex;
}

/* free ifindex
** not alloc release, so do nothing
*/
static int ctc_cust_if_free_ifindex(hsl_ifIndex_t ifindex)
{
#if 0
    uint16_t gport = 0;
    
    gport = ifindex_to_ctc_gport_id(ifindex);
    if(gport < 0) {    /* ifindex not existed */
        return HSL_IFMGR_ERR_INDEX;
    }
#endif

    return 0;
}

static struct hsl_ifmgr_cust_callbacks hsl_ctc_cm_ifindex_cbs = {
    .cust_if_alloc_ifindex = ctc_cust_if_alloc_ifindex,
    .cust_if_free_ifindex  = ctc_cust_if_free_ifindex,
};

int hsl_if_cust_cb_init (void)
{
    if(p_hsl_if_db->cm_cb != NULL) {
        return -1000;
    }

    p_hsl_if_db->cm_cb = &hsl_ctc_cm_ifindex_cbs;

    return 0;
}

int hsl_if_cust_cb_deinit(void)
{
    if(p_hsl_if_db->cm_cb == NULL) {
        return 0;
    }

    p_hsl_if_db->cm_cb = NULL;
	
    return 0;
}



