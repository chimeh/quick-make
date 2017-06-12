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
#include "bcm_incl.h"
#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_bcm_if.h"
#include "hsl_vlan.h"
#include "hsl_bcm_ifmap.h"

static int hsl_bcm_lacp_initialized = HSL_FALSE;

int
hsl_bcm_lacp_init (void)
{
  int ret;
   
  HSL_FN_ENTER(); 

  if (hsl_bcm_lacp_initialized)
    HSL_FN_EXIT (0);

  /* initialize the underlying bcm trunk module */
  ret = bcmx_trunk_init ();
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to initialize the trunk module, bcm error = %d\n", ret);
      HSL_FN_EXIT(ret);
    }

  hsl_bcm_lacp_initialized = HSL_TRUE;

  HSL_FN_EXIT(STATUS_OK);
}

int
hsl_bcm_lacp_deinit (void)
{
  int ret;

  HSL_FN_ENTER(); 

  if (! hsl_bcm_lacp_initialized)
    HSL_FN_EXIT (-1);

  /* uninitialize the underlying bcm trunk module */
  ret = bcmx_trunk_detach ();
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to uninitialize the trunk module, bcm error = %d\n",
	       ret);
      HSL_FN_EXIT(ret);
    }

  hsl_bcm_lacp_initialized = HSL_FALSE;

  HSL_FN_EXIT(STATUS_OK);
}


int
hsl_bcm_aggregator_add (struct hsl_if *ifp, int agg_type)
{
  int ret;
  struct hsl_bcm_if *bcmif = NULL;
  bcm_trunk_t trunk_id = BCM_TRUNK_INVALID;
  char ifname[HSL_IFNAM_SIZE + 1];     /* Interface name.                   */
  u_char mac[HSL_ETHER_ALEN];          /* Ethernet mac address.             */

  HSL_FN_ENTER();  

  if(!ifp)
    HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);

  /* Create a new trunk instance */
  ret = bcmx_trunk_create (&trunk_id);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
	       "Failed to create aggregator %s in hw, bcm error %d\n", ifp->name, ret); 
      HSL_FN_EXIT(HSL_IFMGR_ERR_HW_TRUNK_ADD); 
    }

  /* Register with ifmap and get name and mac address for this trunk. */
  ret = hsl_bcm_ifmap_lport_register (HSL_BCM_TRUNK_2_LPORT(trunk_id), HSL_PORT_F_AGG, ifname, mac);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Can't register trunk (%d) in Broadcom interface map\n", trunk_id);
      /* delete trunk from bcom */
      bcmx_trunk_destroy (trunk_id);
      HSL_FN_EXIT(HSL_IFMGR_ERR_HW_TRUNK_ADD);;
    }

  /* Allocate hw specific structure for L2 interfaces. */
  if(agg_type != HAL_IF_TYPE_IP)
    {
      ifp->system_info = hsl_bcm_if_alloc ();
      if (! ifp->system_info )
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Out of memory for allocating hardware L2 interface\n");
	  hsl_bcm_ifmap_lport_unregister (HSL_BCM_TRUNK_2_LPORT(bcmif->trunk_id));
	  bcmx_trunk_destroy (trunk_id);
	  HSL_FN_EXIT(HSL_IFMGR_ERR_MEMORY);
	}
    }

  /* Store bcm trunk id for aggregator interface */
  bcmif = ifp->system_info;
  bcmif->trunk_id = trunk_id;
  bcmif->type = HSL_BCM_IF_TYPE_TRUNK;
  /* Associate trunk to interface structure. */
  hsl_bcm_ifmap_if_set (HSL_BCM_TRUNK_2_LPORT(trunk_id), ifp);
  /* Call interface addition notifier */
  hsl_ifmgr_send_notification (HSL_IF_EVENT_IFNEW, ifp, NULL);
  HSL_FN_EXIT(STATUS_OK);
}

int
hsl_bcm_aggregator_del (struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmif;

  HSL_FN_ENTER(); 

  /* Sanity check */
  if(!ifp)
    HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);
  
  bcmif = ifp->system_info;
  if(!bcmif)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Interface %s doesn't have hw specific info\n",ifp->name);
      HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);
    }

  /* get trunk id */
  if (bcmif->trunk_id == BCM_TRUNK_INVALID)
    HSL_FN_EXIT(HSL_IFMGR_ERR_INVALID_PARAM);

  /* Unregister interface from ifmap. */
  hsl_bcm_ifmap_lport_unregister (HSL_BCM_TRUNK_2_LPORT(bcmif->trunk_id));

  /* delete trunk from bcom */
  bcmx_trunk_destroy (bcmif->trunk_id);

  /* reset bcm trunk id */
  bcmif->trunk_id = BCM_TRUNK_INVALID;

  HSL_FN_EXIT(STATUS_OK);
}

int
hsl_bcm_trunk_membership_update (struct hsl_if *ifp)
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
      sysinfo->trunk_id == BCM_TRUNK_INVALID)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
	       "Interface is not a trunk %s\n", ifp->name);
      HSL_FN_EXIT(STATUS_ERROR);
    }

	ret = bcmx_trunk_psc_get (sysinfo->trunk_id, &bcm_psc);
    if (ret != BCM_E_NONE) {
        tinfo.psc = BCM_TRUNK_PSC_DEFAULT;
	} else {
        tinfo.psc = bcm_psc;
	}
  tinfo.dlf_port = -1;
  tinfo.mc_port = -1;
  tinfo.ipmc_port = -1;

  bcmx_lplist_init (&tinfo.ports, 0, 0);

  if (!ifp->children_list)
    HSL_FN_EXIT(STATUS_OK);
  
  /* create bcm trunk port list */
  for (nm = ifp->children_list; nm; nm = nm->next)
    {
      tmpif = nm->ifp;

      /* get associated bcm lport information */
      if (tmpif->type == HSL_IF_TYPE_L2_ETHERNET)
	{
	  sysinfo = (struct hsl_bcm_if *)tmpif->system_info;
	  if (sysinfo->type != HSL_BCM_IF_TYPE_L2_ETHERNET)
	    continue;

	  /* Set this port to accept LACP PDUs. */
	  hsl_ifmgr_set_acceptable_packet_types (tmpif, HSL_IF_PKT_LACP);
	}
      else if (tmpif->type == HSL_IF_TYPE_IP)
	{
	  nn = tmpif->children_list;
	  if (! nn || nn->ifp->type != HSL_IF_TYPE_L2_ETHERNET)
	    continue;

	  /* for ip ports get lport informaiton from associated l2 port */
	  sysinfo = (struct hsl_bcm_if *) nn->ifp->system_info;
	  if (sysinfo->type != HSL_BCM_IF_TYPE_L2_ETHERNET)
	    continue;

	  /* Set this port to accept LACP PDUs. */
	  hsl_ifmgr_set_acceptable_packet_types (nn->ifp, HSL_IF_PKT_LACP);
	}
      else
	continue;

      lport =  sysinfo->u.l2.lport;
      bcmx_lplist_add (&tinfo.ports, lport);
      update_flag = HSL_TRUE;
    }

  if (update_flag == HSL_TRUE)
    {
      /* attach port to trunk */
      sysinfo = (struct hsl_bcm_if *)ifp->system_info;
      ret = bcmx_trunk_set (sysinfo->trunk_id, &tinfo);
      if (ret != BCM_E_NONE)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
	           "Failed to update port membership for aggregator %s in hw, "
	           "bcm error %d\n", ifp->name, ret); 
          bcmx_lplist_free (&tinfo.ports);
          HSL_FN_EXIT(HSL_IFMGR_ERR_HW_TRUNK_PORT_UPDATE);
        }
    }

  bcmx_lplist_free (&tinfo.ports);

  HSL_FN_EXIT(STATUS_OK);
}

int
hsl_bcm_aggregator_port_add ( struct hsl_if *agg_ifp, struct hsl_if *port_ifp )
{
  int ret;

  HSL_FN_ENTER();

  ret = hsl_bcm_trunk_membership_update (agg_ifp);

  HSL_FN_EXIT(ret);
}

int
hsl_bcm_aggregator_port_del ( struct hsl_if *agg_ifp, struct hsl_if *port_ifp )
{
  struct hsl_bcm_if *bcmifp;
  bcmx_lport_t lport;
  int ret;

  HSL_FN_ENTER();

  /* Flush the MAC entries from this port. */
  if (port_ifp->type == HSL_IF_TYPE_L2_ETHERNET)
    {
      bcmifp = port_ifp->system_info;
      if (! bcmifp)
	HSL_FN_EXIT (-1);

      lport = bcmifp->u.l2.lport;

      /* Flush from chips. */
      bcmx_l2_addr_delete_by_port (lport, 0);
    }

  /* Update membership. */
  ret = hsl_bcm_trunk_membership_update (agg_ifp);

  HSL_FN_EXIT(ret);
}

int 
hsl_bcm_lacp_psc_set (struct hsl_if *ifp,int psc)
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

int 
hsl_bcm_lacp_nuc_psc_set (int psc)
{
  int ret;
  int bcm_psc = BCM_HASH_CONTROL_TRUNK_NUC_SRC|BCM_HASH_CONTROL_TRUNK_NUC_DST;
  int bcm_psc_get = 0;
  int tmp;
   int ret1, ret2, ret3, ret4;
  HSL_FN_ENTER();

	
	if (psc == HAL_LACP_PSC_NUC_SRC) {
		bcm_psc = BCM_HASH_CONTROL_TRUNK_NUC_SRC;
	} else if (psc == HAL_LACP_PSC_NUC_DST) {
		bcm_psc = BCM_HASH_CONTROL_TRUNK_NUC_DST;
	} else if (psc == HAL_LACP_PSC_NUC_SRC_DST) {
		bcm_psc = BCM_HASH_CONTROL_TRUNK_NUC_SRC|BCM_HASH_CONTROL_TRUNK_NUC_DST;
	} else if (psc == HAL_LACP_PSC_NUC_ENHANCE) {
		bcm_psc = BCM_HASH_CONTROL_TRUNK_NUC_ENHANCE;
	} else {
		bcm_psc = BCM_HASH_CONTROL_TRUNK_NUC_SRC|BCM_HASH_CONTROL_TRUNK_NUC_DST;
	}
  /* Set psc for a trunk. */
  /*ret = bcmx_trunk_psc_set (sysinfo->trunk_id, psc == HAL_LACP_PSC_DST_MAC
			    ? BCM_TRUNK_PSC_DSTMAC : BCM_TRUNK_PSC_SRCMAC);*/

	//ret1 = bcmx_switch_control_set(bcmSwitchHashL2Field0, 0xffffffff);
	//ret2 = bcmx_switch_control_set(bcmSwitchHashL2Field1, 0xffffffff);
	//ret3 = bcmx_switch_control_set(bcmSwitchHashIP4Field0, 0xffffffff);
	//ret4 = bcmx_switch_control_set(bcmSwitchHashIP4Field1, 0xffffffff);

	//bcmx_switch_control_set(bcmSwitchHashIP4TcpUdpField0, 0xffffffff);
	//bcmx_switch_control_set(bcmSwitchHashIP4TcpUdpField1, 0xffffffff);

	//bcmx_switch_control_set(bcmSwitchHashIP4TcpUdpPortsEqualField0, 0xffffffff);
	//bcmx_switch_control_set(bcmSwitchHashIP4TcpUdpPortsEqualField1, 0xffffffff);
	
	//bcmx_switch_control_set(bcmSwitchHashIP6Field0, 0xffffffff);
	//bcmx_switch_control_set(bcmSwitchHashIP6Field1, 0xffffffff);

	//bcmx_switch_control_set(bcmSwitchHashIP6TcpUdpField0, 0xffffffff);
	//bcmx_switch_control_set(bcmSwitchHashIP6TcpUdpField1, 0xffffffff);

	//bcmx_switch_control_set(bcmSwitchHashIP6TcpUdpPortsEqualField0, 0xffffffff);
	//bcmx_switch_control_set(bcmSwitchHashIP6TcpUdpPortsEqualField1, 0xffffffff);
	
	//bcmx_switch_control_set(bcmSwitchHashMPLSField0, 0xffffffff);
	//bcmx_switch_control_set(bcmSwitchHashMPLSField1, 0xffffffff);

	//bcmx_switch_control_set(bcmSwitchHashSelectControl, 0x0);

	
	//bcmx_switch_control_set(bcmSwitchHashSeed0, 3456);
	//bcmx_switch_control_set(bcmSwitchHashSeed1, 7890);

	//bcmx_switch_control_set(bcmSwitchHashField0Config, 1);
	//bcmx_switch_control_set(bcmSwitchHashField1Config, 5);
	

	bcm_psc |= BCM_HASH_CONTROL_ECMP_ENHANCE;
   ret = bcmx_switch_control_set(bcmSwitchHashControl, bcm_psc);
   /*NON_UC_TRUNK_HASH_DST_ENABLE*/

  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to set nuc psc for trunk,bcm error = %d\n", ret);
      HSL_FN_EXIT(STATUS_ERROR);
    }
  HSL_FN_EXIT(STATUS_OK);
}

#endif /* HAVE_LACPD */
