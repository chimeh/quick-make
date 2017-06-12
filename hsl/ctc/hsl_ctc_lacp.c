/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */


#include "config.h"

#include "hsl_os.h"
#include "hsl_types.h"

#ifdef HAVE_LACPD

#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"

#include "hsl_avl.h"
#include "hsl_error.h"
#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_ctc_if.h"
#include "hsl_vlan.h"
#include "hsl_ctc_ifmap.h"

#include "ctc_api.h"
#include "ctc_if_portmap.h"
#include "hsl_bridge.h"


static int hsl_ctc_lacp_initialized = HSL_FALSE;


int hsl_ctc_lacp_init (void)
{
    int ret;
   
    HSL_FN_ENTER(); 

    if(hsl_ctc_lacp_initialized) {
        HSL_FN_EXIT (0);
    }

    hsl_ctc_lacp_initialized = HSL_TRUE;

    HSL_FN_EXIT(STATUS_OK);
}

int hsl_ctc_lacp_deinit (void)
{
    int ret;

    HSL_FN_ENTER(); 

    if(!hsl_ctc_lacp_initialized) {
        HSL_FN_EXIT (-1);
    }

    hsl_ctc_lacp_initialized = HSL_FALSE;

    HSL_FN_EXIT(STATUS_OK);
}


int hsl_ctc_aggregator_add (struct hsl_if *ifp, int agg_type)
{
    int ret;
    int trunk_id = -1;
    struct hsl_bcm_if *bcmif = NULL;
    char ifname[HSL_IFNAM_SIZE + 1];     /* Interface name.                   */
    u_char mac[HSL_ETHER_ALEN];          /* Ethernet mac address.             */
    ctc_linkagg_group_t  linkagg;

    HSL_FN_ENTER();  

    if(!ifp) {
        HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);
    }
	sal_memset(&linkagg, 0, sizeof(ctc_linkagg_group_t));

    if(ifp->name[0] == 's' && ifp->name[1] == 'a') {
        linkagg.linkagg_mode = CTC_LINKAGG_MODE_STATIC;
    } else if(ifp->name[0] == 'p' && ifp->name[1] == 'o') {
        linkagg.linkagg_mode = CTC_LINKAGG_MODE_STATIC;
    } else {    /* default static linkagg */
        linkagg.linkagg_mode = CTC_LINKAGG_MODE_STATIC;
    }

//    linkagg.tid = (uint8)ifindex_to_ctc_gport_id(ifp->ifindex);
    /* if you are sure this is linkagg port ifindex, you can call this */
    if(CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(ifp->ifindex)) {
        linkagg.tid = CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex);
    } else {    /* not linkagg ifindex */
        HSL_FN_EXIT(STATUS_ERR_IFMAP_LPORT_NOT_FOUND);
    }

    trunk_id = linkagg.tid;

    ret = ctc_linkagg_create(&linkagg);
    if (ret != 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
                "Failed to create aggregator %s in hw, bcm error %d\n", ifp->name, ret);
        HSL_FN_EXIT(HSL_IFMGR_ERR_HW_TRUNK_ADD); 
    }
    /* Register with ifmap and get name and mac address for this trunk. */
    ret = hsl_bcm_ifmap_lport_register(CTC_MAP_TID_TO_GPORT(trunk_id), HSL_PORT_F_AGG, ifname, mac);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Can't register trunk (%d) in Broadcom interface map\n", trunk_id);
        /* delete trunk from bcom */
        ctc_linkagg_destroy(linkagg.tid);
        HSL_FN_EXIT(HSL_IFMGR_ERR_HW_TRUNK_ADD);;
    }

    /* Allocate hw specific structure for L2 interfaces. */
    if(agg_type != HAL_IF_TYPE_IP) {
        ifp->system_info = hsl_ctc_if_alloc ();
        if (! ifp->system_info ) {
            HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Out of memory for allocating hardware L2 interface\n");
            hsl_bcm_ifmap_lport_unregister(CTC_MAP_TID_TO_GPORT(bcmif->trunk_id));
//            bcmx_trunk_destroy (trunk_id);
            HSL_FN_EXIT(HSL_IFMGR_ERR_MEMORY);
        }
    }
    
    /* Store bcm trunk id for aggregator interface */
    bcmif = ifp->system_info;
    bcmif->trunk_id = trunk_id;
    bcmif->type = HSL_BCM_IF_TYPE_TRUNK;

	bcmif->u.l2.lport = CTC_MAP_TID_TO_GPORT(trunk_id);
    
    /* Associate trunk to interface structure. */
    hsl_ctc_ifmap_if_set(CTC_MAP_TID_TO_GPORT(trunk_id), ifp);
    
    /* Call interface addition notifier */
    hsl_ifmgr_send_notification (HSL_IF_EVENT_IFNEW, ifp, NULL);

    HSL_FN_EXIT(STATUS_OK);
}

int hsl_ctc_aggregator_del (struct hsl_if *ifp)
{
    struct hsl_bcm_if *bcmif = NULL;
	int ret =0;

    HSL_FN_ENTER(); 

    /* Sanity check */
    if(!ifp)
        HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);
  
    bcmif = ifp->system_info;
    if(!bcmif) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Interface %s doesn't have hw specific info\n",ifp->name);
        HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);
    }

    /* get trunk id */
    if (bcmif->trunk_id == -1)
        HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);

    /* Unregister interface from ifmap. */
    hsl_bcm_ifmap_lport_unregister(CTC_MAP_TID_TO_GPORT(bcmif->trunk_id));


	struct hsl_bridge_port  *port;
	struct hsl_port_vlan *port_vlan;
	struct hsl_avl_node *node;
	struct hsl_avl_node *node_next;
	struct hsl_vlan_port_attr  *p_vlan_attr;	
	ctc_l2dflt_addr_t l2dflt_addr;
	sal_memset(&l2dflt_addr, 0, sizeof(ctc_l2dflt_addr_t));

	HSL_BRIDGE_LOCK;
	port = ifp->u.l2_ethernet.port;
	if (! port) {
		HSL_BRIDGE_UNLOCK;
		return HSL_ERR_BRIDGE_PORT_NOT_EXISTS;
	}
	
	port_vlan = port->vlan;
	if (! port_vlan) {
		HSL_BRIDGE_UNLOCK;
		return HSL_ERR_BRIDGE_PORT_NOT_EXISTS;	
	}

	for (node = hsl_avl_top (port_vlan->vlan_tree); node; node = node_next)	{
		node_next = hsl_avl_next (node);
		p_vlan_attr = (struct hsl_vlan_port_attr *) HSL_AVL_NODE_INFO (node);
		if (! p_vlan_attr)		  
		  continue;
		
		sal_memset(&l2dflt_addr, 0, sizeof(ctc_l2dflt_addr_t));
		l2dflt_addr.fid = p_vlan_attr->vid;
		l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid;
		/* remove agg member from each fib */
		l2dflt_addr.member.mem_port = (uint16)(bcmif->trunk_id) | 0x1f00;
		ret = ctc_l2_remove_port_from_default_entry(&l2dflt_addr);
		if(ret < 0) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Can't del trunk member (%d) from fdb, fib (%d)\n", bcmif->trunk_id, l2dflt_addr.fid);
		}
	

	}

    /* delete trunk from bcom */
    ctc_linkagg_destroy(bcmif->trunk_id);

    /* reset bcm trunk id */
    bcmif->trunk_id = -1;

	bcmif->u.l2.lport = -1;
	HSL_BRIDGE_UNLOCK;
	
    HSL_FN_EXIT(STATUS_OK);
}

#if 0
int hsl_ctc_trunk_membership_update (struct hsl_if *ifp)
{
  struct hsl_if *tmpif;
  struct hsl_if_list *nm, *nn;
  bcmx_trunk_add_info_t tinfo;
  bcmx_lport_t lport;
  int ret;
  struct hsl_bcm_if *sysinfo = NULL;
  HSL_BOOL update_flag = HSL_FALSE;
  int bcm_psc;


  HSL_FN_ENTER();

  /* Sanity part. */
  if(!ifp)
    HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);

  /* Make sure interface is a trunk. */
  sysinfo = (struct hsl_bcm_if *)ifp->system_info;
  if(!sysinfo)
    HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);
 
  if (sysinfo->type != HSL_BCM_IF_TYPE_TRUNK ||
      sysinfo->trunk_id == -1)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
	       "Interface is not a trunk %s\n", ifp->name);
      HSL_FN_EXIT(STATUS_ERROR);
    }

	ret = 0;    //ret = bcmx_trunk_psc_get (sysinfo->trunk_id, &bcm_psc);
    if (ret != 0) {
        tinfo.psc = 9;
	} else {
        tinfo.psc = bcm_psc;
	}
  tinfo.dlf_port = -1;
  tinfo.mc_port = -1;
  tinfo.ipmc_port = -1;

//  bcmx_lplist_init (&tinfo.ports, 0, 0);

  if (!ifp->children_list)
    HSL_FN_EXIT(STATUS_OK);
  
  /* create bcm trunk port list */
  for (nm = ifp->children_list; nm; nm = nm->next) {
      tmpif = nm->ifp;

      /* get associated bcm lport information */
      if (tmpif->type == HSL_IF_TYPE_L2_ETHERNET) {
	    sysinfo = (struct hsl_bcm_if *)tmpif->system_info;
	    if (sysinfo->type != HSL_BCM_IF_TYPE_L2_ETHERNET)
	        continue;

	    /* Set this port to accept LACP PDUs. */
	    hsl_ifmgr_set_acceptable_packet_types (tmpif, HSL_IF_PKT_LACP);
	  } else if (tmpif->type == HSL_IF_TYPE_IP) {
	    nn = tmpif->children_list;
	    if (! nn || nn->ifp->type != HSL_IF_TYPE_L2_ETHERNET)
	        continue;

	  /* for ip ports get lport informaiton from associated l2 port */
	  sysinfo = (struct hsl_bcm_if *) nn->ifp->system_info;
	  if (sysinfo->type != HSL_BCM_IF_TYPE_L2_ETHERNET)
	    continue;

	  /* Set this port to accept LACP PDUs. */
	  hsl_ifmgr_set_acceptable_packet_types (nn->ifp, HSL_IF_PKT_LACP);
	} else {
	    continue;
    }

      lport =  sysinfo->u.l2.lport;
//      bcmx_lplist_add (&tinfo.ports, lport);
      update_flag = HSL_TRUE;
    }

  if (update_flag == HSL_TRUE) {
      /* attach port to trunk */
      sysinfo = (struct hsl_bcm_if *)ifp->system_info;
//      ret = bcmx_trunk_set (sysinfo->trunk_id, &tinfo);
      if (ret != 0) {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
	           "Failed to update port membership for aggregator %s in hw, "
	           "bcm error %d\n", ifp->name, ret); 
//          bcmx_lplist_free (&tinfo.ports);
          HSL_FN_EXIT(HSL_IFMGR_ERR_HW_TRUNK_PORT_UPDATE);
        }
    }

//  bcmx_lplist_free (&tinfo.ports);

  HSL_FN_EXIT(STATUS_OK);
}
#endif

int hsl_ctc_aggregator_port_add ( struct hsl_if *agg_ifp, struct hsl_if *port_ifp )
{
    int ret = 0;
    struct hsl_bcm_if *sysinfo = NULL;
	struct hsl_if *p_hsl_if  = NULL;

    HSL_FN_ENTER();

    if(agg_ifp == NULL || port_ifp == NULL) {
        return -1;
    }

//    printk("[%s-%d]: add port<%s> ifindex<%d> to agg name: %s, ifindex: %d\r\n",   
//            __func__, __LINE__, port_ifp->name, port_ifp->ifindex, agg_ifp->name, agg_ifp->ifindex);

    sysinfo = (struct hsl_bcm_if *)agg_ifp->system_info;
    if(sysinfo->type != HSL_BCM_IF_TYPE_TRUNK   \
     || sysinfo->trunk_id < 0) {
        HSL_LOG(HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface is not a trunk %s\n", agg_ifp->name);
        HSL_FN_EXIT(STATUS_ERROR);
    }

	p_hsl_if = hsl_ifmgr_lookup_by_index(port_ifp->ifindex);
	if (!p_hsl_if) {
		HSL_LOG(HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "hsl_ifmgr_lookup_by_index, ifindex=%d\n", port_ifp->ifindex);
		HSL_FN_EXIT(STATUS_ERROR);
	}

 //   ret = ctc_linkagg_add_port(ifindex_to_ctc_gport_id(agg_ifp->ifindex), IFINDEX_TO_GPORT(port_ifp->ifindex));
    ret = ctc_linkagg_add_port(sysinfo->trunk_id, IFINDEX_TO_GPORT(port_ifp->ifindex));

	p_hsl_if->is_agg_member = TRUE;

	/* add by suk - 2016.7.19*/
	/* when add agg member, del agg member from fdb */
	struct hsl_bridge_port  *port;
	struct hsl_port_vlan *port_vlan;
	struct hsl_avl_node *node;
	struct hsl_avl_node *node_next;
	struct hsl_vlan_port_attr  *p_vlan_attr;
	int trunk_id = -1;		
	ctc_l2dflt_addr_t l2dflt_addr;
	sal_memset(&l2dflt_addr, 0, sizeof(ctc_l2dflt_addr_t));

//	trunk_id = ifindex_to_ctc_gport_id(agg_ifp->ifindex);
    if(CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(agg_ifp->ifindex)) {
        trunk_id = CTC_GET_PANEL_PORT_FROM_IFINDEX(agg_ifp->ifindex);
    } else {    /* not linkagg ifindex */
        HSL_FN_EXIT(STATUS_ERR_IFMAP_LPORT_NOT_FOUND);
    }

	HSL_BRIDGE_LOCK;	
	port = port_ifp->u.l2_ethernet.port;
	if (! port) {
		HSL_IFMGR_IF_REF_DEC(p_hsl_if);
		HSL_BRIDGE_UNLOCK;
		return HSL_ERR_BRIDGE_PORT_NOT_EXISTS;
	}
	port_vlan = port->vlan;
	if (! port_vlan) {
		HSL_IFMGR_IF_REF_DEC(p_hsl_if);
		HSL_BRIDGE_UNLOCK;
		return HSL_ERR_BRIDGE_PORT_NOT_EXISTS;
	}

	for (node = hsl_avl_top (port_vlan->vlan_tree); node; node = node_next)	{
		node_next = hsl_avl_next (node);
		p_vlan_attr = (struct hsl_vlan_port_attr *) HSL_AVL_NODE_INFO (node);
		if (! p_vlan_attr)		  
		  continue;	
		sal_memset(&l2dflt_addr, 0, sizeof(ctc_l2dflt_addr_t));
		l2dflt_addr.fid = p_vlan_attr->vid;
		l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid;
		/* remove agg member from each fib */
		l2dflt_addr.member.mem_port = IFINDEX_TO_GPORT(port_ifp->ifindex);
		ret = ctc_l2_remove_port_from_default_entry(&l2dflt_addr);
		if(ret < 0) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Can't del trunk member (%d) from fdb, fib (%d)\n", port_ifp->ifindex, l2dflt_addr.fid);
		}

	}

	HSL_IFMGR_IF_REF_DEC(p_hsl_if);
	HSL_BRIDGE_UNLOCK;
	
    HSL_FN_EXIT(ret);
}

int hsl_ctc_aggregator_port_del ( struct hsl_if *agg_ifp, struct hsl_if *port_ifp )
{
    int ret   = -1;
    int lport = -1;
    struct hsl_bcm_if *bcmifp  = NULL;
    struct hsl_bcm_if *sysinfo = NULL;
	struct hsl_if *p_hsl_if  = NULL;

    HSL_FN_ENTER();

    sysinfo = (struct hsl_bcm_if *)agg_ifp->system_info;

    /* Flush the MAC entries from this pohsl_ifmgr_lookup_by_indexrt. */
    if (port_ifp->type == HSL_IF_TYPE_L2_ETHERNET) {
        bcmifp = port_ifp->system_info;
        if(!bcmifp)
            HSL_FN_EXIT (-1);
		
		p_hsl_if = hsl_ifmgr_lookup_by_index(port_ifp->ifindex);
		if (!p_hsl_if) {
			HSL_LOG(HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "hsl_ifmgr_lookup_by_index, ifindex=%d\n", port_ifp->ifindex);
			HSL_FN_EXIT(STATUS_ERROR);
		}
		

        lport = bcmifp->u.l2.lport;
        ret = ctc_linkagg_remove_port(sysinfo->trunk_id, IFINDEX_TO_GPORT(port_ifp->ifindex));

		p_hsl_if->is_agg_member = FALSE;


		/* add by suk - 2016.7.19*/
		/* when del agg member, add agg member to fdb */
		struct hsl_bridge_port *port;
		struct hsl_port_vlan *port_vlan;
		struct hsl_avl_node *node;
		struct hsl_avl_node *node_next;
		struct hsl_vlan_port_attr  *p_vlan_attr;
		int trunk_id = -1;		
		ctc_l2dflt_addr_t l2dflt_addr;
		sal_memset(&l2dflt_addr, 0, sizeof(ctc_l2dflt_addr_t));
//		trunk_id = ifindex_to_ctc_gport_id(agg_ifp->ifindex);	
        if(CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(agg_ifp->ifindex)) {
            trunk_id = CTC_GET_PANEL_PORT_FROM_IFINDEX(agg_ifp->ifindex);
        } else {    /* not linkagg ifindex */
            HSL_FN_EXIT(STATUS_ERR_IFMAP_LPORT_NOT_FOUND);
        }

		HSL_BRIDGE_LOCK;
		port = port_ifp->u.l2_ethernet.port;
		if (! port) {
			HSL_IFMGR_IF_REF_DEC(p_hsl_if);
			HSL_BRIDGE_UNLOCK;
			return HSL_ERR_BRIDGE_PORT_NOT_EXISTS;
		}
		port_vlan = port->vlan;
		if (! port_vlan) {
			HSL_IFMGR_IF_REF_DEC(p_hsl_if);
			HSL_BRIDGE_UNLOCK;
			return HSL_ERR_BRIDGE_PORT_NOT_EXISTS;
		}
		
		for (node = hsl_avl_top (port_vlan->vlan_tree); node; node = node_next)	{
			node_next = hsl_avl_next (node);
			p_vlan_attr = (struct hsl_vlan_port_attr *) HSL_AVL_NODE_INFO (node);
			if (! p_vlan_attr)		  
			  continue;
			sal_memset(&l2dflt_addr, 0, sizeof(ctc_l2dflt_addr_t));
			l2dflt_addr.fid = p_vlan_attr->vid;
			l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid;
			/* add agg member to each fib */
			l2dflt_addr.member.mem_port = IFINDEX_TO_GPORT(port_ifp->ifindex);
			ret = ctc_l2_add_port_to_default_entry(&l2dflt_addr);
			if(ret < 0) {
				HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Can't add trunk member (%d) to fdb, fib (%d)\n", port_ifp->ifindex, l2dflt_addr.fid);
				//ctc_linkagg_destroy(trunk_id);
			}			
	
		}	

    }

    HSL_IFMGR_IF_REF_DEC(p_hsl_if);
	HSL_BRIDGE_UNLOCK;
    HSL_FN_EXIT(ret);
}

#if 0
int hsl_ctc_lacp_psc_set (struct hsl_if *ifp,int psc)
{
  struct hsl_bcm_if *sysinfo;
  int ret;
  int bcm_psc = BCM_TRUNK_PSC_DEFAULT;
  
  HSL_FN_ENTER();
  sysinfo = (struct hsl_bcm_if *)ifp->system_info;

  /* Get hw specific info. */
  if(!sysinfo)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
  	       "Interface doesn't have hw info %s\n", ifp->name);
      HSL_FN_EXIT(STATUS_ERROR);
    }

  /* Make sure interface is a trunk. */
  if (sysinfo->type != HSL_BCM_IF_TYPE_TRUNK ||
      sysinfo->trunk_id == BCM_TRUNK_INVALID)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Interface is not a trunk %s\n", ifp->name);
      HSL_FN_EXIT(STATUS_ERROR);
    }

	if (psc == HAL_LACP_PSC_DST_MAC) {
		bcm_psc = BCM_TRUNK_PSC_DSTMAC;
	} else if (psc == HAL_LACP_PSC_SRC_MAC) {
		bcm_psc = BCM_TRUNK_PSC_SRCMAC;
	} else if (psc == HAL_LACP_PSC_SRC_DST_MAC) {
		bcm_psc = BCM_TRUNK_PSC_SRCDSTMAC;
	} else if (psc == HAL_LACP_PSC_SRC_IP) {
		bcm_psc = BCM_TRUNK_PSC_SRCIP;
	} else if (psc == HAL_LACP_PSC_DST_IP) {
		bcm_psc = BCM_TRUNK_PSC_DSTIP;
	} else if (psc == HAL_LACP_PSC_SRC_DST_IP) {
		bcm_psc = BCM_TRUNK_PSC_SRCDSTIP;
	}  else if (psc == HAL_LACP_PSC_ENHANCE) {
		bcm_psc = BCM_TRUNK_PSC_PORTFLOW;
	} else {
		bcm_psc = BCM_TRUNK_PSC_DEFAULT;
	}
  /* Set psc for a trunk. */
  /*ret = bcmx_trunk_psc_set (sysinfo->trunk_id, psc == HAL_LACP_PSC_DST_MAC
			    ? BCM_TRUNK_PSC_DSTMAC : BCM_TRUNK_PSC_SRCMAC);*/

   ret = bcmx_trunk_psc_set (sysinfo->trunk_id, bcm_psc);
   
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to set psc for trunk %s, bcm error = %d\n", 
	       ifp->name, ret);
      HSL_FN_EXIT(STATUS_ERROR);
    }

  HSL_FN_EXIT(STATUS_OK);
}
#endif


/* add by suk - 2016.7.20 */
/********************************************
  *  @brief    -  covert hash from zebos cli to ctc psc struct 
  *  @input   - int psc
  *  @output - ctc_linkagg_psc_t *psc_struct
  ********************************************/
static int hsl_ctc_lacp_convert_hash(int psc, ctc_linkagg_psc_t *psc_struct)
{
  if(!psc_struct) {
  	return -1;
  }
  sal_memset(psc_struct, 0, sizeof(ctc_linkagg_psc_t));
  
  switch(psc)
  {
	case HAL_LACP_PSC_CT_VLAN:
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L2;
		psc_struct->l2_flag |= CTC_LINKAGG_PSC_L2_VLAN;
		break;
	case HAL_LACP_PSC_CT_SRC_MAC:
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L2;
		psc_struct->l2_flag |= CTC_LINKAGG_PSC_L2_MACSA;
		break;
	case HAL_LACP_PSC_CT_DST_MAC:
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L2;
		psc_struct->l2_flag |= CTC_LINKAGG_PSC_L2_MACDA;
		break;
	case HAL_LACP_PSC_CT_SRC_DST_MAC:
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L2;
		psc_struct->l2_flag |= CTC_LINKAGG_PSC_L2_MACSA;
		psc_struct->l2_flag |= CTC_LINKAGG_PSC_L2_MACDA;
		break;
	case HAL_LACP_PSC_CT_SRC_IP:
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_IP;
		psc_struct->ip_flag |= CTC_LINKAGG_PSC_IP_IPSA;	
		psc_struct->ip_flag |= CTC_LINKAGG_PSC_USE_IP;
		break;
	case HAL_LACP_PSC_CT_DST_IP:
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_IP;
		psc_struct->ip_flag |= CTC_LINKAGG_PSC_IP_IPDA;	
		psc_struct->ip_flag |= CTC_LINKAGG_PSC_USE_IP;
		break;

	case HAL_LACP_PSC_CT_SRC_DST_IP:	
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_IP;
		psc_struct->ip_flag |= CTC_LINKAGG_PSC_IP_IPSA;			
		psc_struct->ip_flag |= CTC_LINKAGG_PSC_IP_IPDA;	
		psc_struct->ip_flag |= CTC_LINKAGG_PSC_USE_IP;
		break;
	case HAL_LACP_PSC_CT_SRC_PORT:	
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L4;	
		psc_struct->l4_flag |= CTC_LINKAGG_PSC_L4_SRC_PORT;	
		psc_struct->l4_flag |= CTC_LINKAGG_PSC_USE_L4;
		break;
	case HAL_LACP_PSC_CT_DST_PORT:
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L4;	
		psc_struct->l4_flag |= CTC_LINKAGG_PSC_L4_DST_PORT;	
		psc_struct->l4_flag |= CTC_LINKAGG_PSC_USE_L4;
		break;
	case HAL_LACP_PSC_CT_SRC_DST_PORT:	
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L4;	
		psc_struct->l4_flag |= CTC_LINKAGG_PSC_L4_SRC_PORT;
		psc_struct->l4_flag |= CTC_LINKAGG_PSC_L4_DST_PORT;	
		psc_struct->l4_flag |= CTC_LINKAGG_PSC_USE_L4;
		break; 
#if 0
		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_PBB;
		psc_struct->pbb_flag |= CTC_LINKAGG_PSC_PBB_BVLAN;
		psc_struct->pbb_flag |= CTC_LINKAGG_PSC_PBB_BMACSA;
		psc_struct->pbb_flag |= CTC_LINKAGG_PSC_PBB_BMACDA;
		psc_struct->pbb_flag |= CTC_LINKAGG_PSC_PBB_ISID;
		psc_struct->pbb_flag |= CTC_LINKAGG_PSC_PBB_IPCP;

		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_MPLS;
		psc_struct->mpls_flag |= CTC_LINKAGG_PSC_MPLS_PROTOCOL;
		psc_struct->mpls_flag |= CTC_LINKAGG_PSC_MPLS_IPSA;
		psc_struct->mpls_flag |= CTC_LINKAGG_PSC_MPLS_IPDA;
		psc_struct->mpls_flag |= CTC_LINKAGG_PSC_USE_MPLS;

		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_FCOE;
		psc_struct->fcoe_flag |= CTC_LINKAGG_PSC_FCOE_SID;
		psc_struct->fcoe_flag |= CTC_LINKAGG_PSC_FCOE_DID;
		psc_struct->fcoe_flag |= CTC_LINKAGG_PSC_USE_FCOE;

		psc_struct->psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_TRILL;
		psc_struct->fcoe_flag |= CTC_LINKAGG_PSC_TRILL_INGRESS_NICKNAME;
		psc_struct->fcoe_flag |= CTC_LINKAGG_PSC_TRILL_EGRESS_NICKNAME;
		psc_struct->fcoe_flag |= CTC_LINKAGG_PSC_USE_TRILL;
#endif	
		break;
    default:		
		return -1;	
    }
  return 0;
}

int hsl_ctc_clean_lacp_global_psc(void)
{
	int ret =0;
	
	ctc_linkagg_psc_t psc_struct;
	ctc_parser_global_cfg_t global_cfg;
	sal_memset(&psc_struct, 0, sizeof(ctc_linkagg_psc_t));
	sal_memset(&global_cfg, 0, sizeof(ctc_parser_global_cfg_t));
	
	/*clean */
	psc_struct.psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_IP;
	psc_struct.psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L2;
	psc_struct.psc_type_bitmap |= CTC_LINKAGG_PSC_TYPE_L4;
	ret = ctc_linkagg_set_psc(&psc_struct);
	if (ret < 0) {
		printk ("ctc_linkagg_set_psc error , ret=%d\n", ret);
		return ret;
	}

	global_cfg.ecmp_hash_type = 1;
	global_cfg.linkagg_hash_type = 1;
	ret = ctc_parser_set_global_cfg(&global_cfg);
	if (ret < 0) {
		printk ("ctc_parser_set_global_cfg error , ret=%d\n", ret);
		return ret;
	}

	return 0;
	
}


int hsl_ctc_lacp_global_psc_set (int psc)
{
	int ret = -1;
	ctc_linkagg_psc_t psc_struct, ip_psc_struct;
	ctc_parser_global_cfg_t global_cfg;
	sal_memset(&psc_struct, 0, sizeof(ctc_linkagg_psc_t));
	sal_memset(&ip_psc_struct, 0, sizeof(ctc_linkagg_psc_t));
	sal_memset(&global_cfg, 0, sizeof(ctc_parser_global_cfg_t));

	HSL_FN_ENTER();

	
	ret = hsl_ctc_clean_lacp_global_psc();
	if (ret < 0) {
		printk("_hsl_ctc_clean_lacp_nuc_psc failed !, ret=%d\n", ret);
		HSL_FN_EXIT(ret);
	}

	global_cfg.ecmp_hash_type = 0;
	global_cfg.linkagg_hash_type = 0;
	ret = ctc_parser_set_global_cfg(&global_cfg);
	if (ret < 0) {
		printk("ctc_parser_set_global_cfg failed !, ret=%d\n", ret);
		HSL_FN_EXIT(ret);
	}
	
	ret = hsl_ctc_lacp_convert_hash(psc, &psc_struct);
	if(ret == -1) {
		HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "psc value for lacp hash is unknown\n");
		HSL_FN_EXIT(ret);
	}
	
	ret = ctc_linkagg_set_psc(&psc_struct);
	if(ret < 0) {
		HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "psc set failed\n");
		HSL_FN_EXIT(ret);
	}
	
	HSL_FN_EXIT(STATUS_OK);
}


#endif /* HAVE_LACPD */
