/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

/*
	ctc include
*/

#include "ctc_api.h"
#include "sal.h"

/* 
   HAL includes.
*/
#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"

/*
  HSL includes.
*/
#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl_error.h"
#include "hsl.h"
#include "hsl_types.h"
#include "hsl_avl.h"

#include "hsl_avl.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"

#include "hsl_vlan.h"
#include "hsl_bridge.h"
#include "hsl_l2_hw.h"
#include "hsl_ctc.h"
#include "hsl_ctc_if.h"
#include "hsl_ctc_l2.h"
#include "hsl_ctc_ifmap.h"
#include "ctc_if_portmap.h"
//#include "hsl_bcm_fdb.h"
#include "hsl_ctc_fdb.h"
#include "hsl_mac_tbl.h"
//#include "hsl_bcm_vlanclassifier.h"
#include "hsl_ctc_resv_vlan.h"

#ifdef HAVE_PVLAN
#include "hsl_bcm_pvlan.h"
#endif /* HAVE_PVLAN */

static struct hsl_ctc_bridge *hsl_ctc_bridge_p = NULL;
static struct hsl_l2_hw_callbacks hsl_bcm_l2_cb;

#ifdef HAVE_IGMP_SNOOP
#define HSL_IGS_CTC_INVALID_FIELD_GRP       0xffffffff
#define HSL_IGS_CTC_INVALID_FIELD_ENTRY     0xffffffff

static int _hsl_igmp_snp_field_grp = HSL_IGS_CTC_INVALID_FIELD_GRP;
static int _hsl_igmp_snp_field_ent = HSL_IGS_CTC_INVALID_FIELD_ENTRY;
#endif

/*
  Initialize BCM bridge.
*/
static struct hsl_ctc_bridge *
_hsl_ctc_bridge_init (void)
{
  struct hsl_ctc_bridge *b;
  int i;

  b = oss_malloc (sizeof (struct hsl_ctc_bridge), OSS_MEM_HEAP);
  if (! b)
    return NULL;

  for (i = 0; i < HSL_CTC_STG_MAX_INSTANCES; i++)
    b->stg[i] = -1;

  return b;
}

/* 
   Deinitialize BCM bridge.
*/
static int
_hsl_ctc_bridge_deinit (struct hsl_ctc_bridge **b)
{
  int i;

  if (*b)
    {

      for (i = 0; i < HSL_CTC_STG_MAX_INSTANCES; i++)
	  if ((*b)->stg[i] != -1)
          {
          //by chentao change
	    //bcmx_stg_destroy ((*b)->stg[i]);
	    	(*b)->stg[i] = -1;
          }

      //ctc_stp_init(NULL);

      oss_free (*b, OSS_MEM_HEAP);
      *b = NULL;
    }
  HSL_FN_EXIT (0);
}

static int __vlan_avl_traversal_fn(void *data, void *user_data)
{
	hsl_vid_t vid = ((struct hsl_vlan_port *)data)->vid; 
	int ret = 0;
	uint8 instance = 0;
    uint16 port_id = 0;
    uint16 gport   = 0;
    uint8 gchip;
    
	ret = ctc_stp_get_vlan_stpid(vid, &instance);
	if (ret < 0)
		return ret;
    ctc_get_gchip_id(0, &gchip);

	//vlan所属实例为需要初始化的实例
	if (instance == *(uint8*)user_data) {
		ret = ctc_stp_set_vlan_stpid(vid, 0);
		if (ret < 0)
			return ret;
        //将该实例中的所有端口都设为初始状态CTC_STP_FORWARDING
        for (port_id = 0; port_id < CTC_MAX_PHY_PORT; port_id++) {
            gport = CTC_MAP_LPORT_TO_GPORT(gchip, port_id);
            ret = ctc_stp_set_state(gport, instance, CTC_STP_FORWARDING);
            if (ret < 0)
                return ret;
        }
	}
	return 0;	
}


static int
_ctc_stp_init_instance(int instance)
{
	struct hsl_bridge *bridge = NULL;
	struct hsl_vlan_port *v = NULL;
	int ret = 0;
	
	HSL_BRIDGE_LOCK;
  	bridge = p_hsl_bridge_master->bridge;	
	ret = hsl_avl_tree_traverse(bridge->vlan_tree, __vlan_avl_traversal_fn, &instance);
	if (ret < 0) {
		HSL_BRIDGE_UNLOCK;
		return ret;
	}	
	HSL_BRIDGE_UNLOCK;

	return ret;
}

static int
_ctc_stp_destroy_instance(int instance)
{
	int ret = 0;
	ret = _ctc_stp_init_instance(instance);
	if (ret < 0) {
		return ret;
	}
	return 0;
}

/* 
   STG Initialize.
*/
int
hsl_ctc_stg_init (void)
{
  int ret;

  HSL_FN_ENTER ();
  //by chentao
 // ret = bcmx_stg_init ();
  ret = 0;
  HSL_FN_EXIT (ret);
}

/* Bridge init. */
int 
hsl_ctc_bridge_init (struct hsl_bridge *b)
{
  int ret;
  int defstg = 0;
  struct hsl_if *ifp;
  struct hsl_bcm_if *ctcifp;
  uint16 gport;
  struct hsl_avl_node *node;


  HSL_FN_ENTER ();

  if (! hsl_ctc_bridge_p)
    {
      hsl_ctc_bridge_p = _hsl_ctc_bridge_init ();
      if (! hsl_ctc_bridge_p)
			HSL_FN_EXIT (-1);

      /* Get default STG. */
      //ret = bcmx_stg_default_get (&hsl_bcm_bridge_p->stg[0]);
      hsl_ctc_bridge_p->stg[0] = CTC_STP_FORWARDING;

      /* For L2 ports which are directly mapped to a L3 interface, set the port state to 
         forwarding. */
      HSL_IFMGR_LOCK;

      for (node = hsl_avl_top (HSL_IFMGR_TREE); node; node = hsl_avl_next (node)) {
	  ifp = HSL_AVL_NODE_INFO (node);
	  if (! ifp)
	    continue;
	      
	  /* If L2 port is directly mapped to a L3(router port) set the state to
	     forwarding. */
	  if (ifp->type == HSL_IF_TYPE_L2_ETHERNET 
	      && CHECK_FLAG (ifp->if_flags, HSL_IFMGR_IF_DIRECTLY_MAPPED)) {
	      ctcifp = ifp->system_info;
	      gport = ctcifp->u.l2.lport;
             
	      /* Set to forward state. */
	      //bcmx_stg_stp_set (hsl_bcm_bridge_p->stg[0], lport, BCM_STG_STP_FORWARD);
	      ctc_stp_set_state(gport, 0, CTC_STP_FORWARDING);
	      
	    }
	  }
      HSL_IFMGR_UNLOCK;

      HSL_FN_EXIT (0);
    }

  HSL_FN_EXIT (-1);
}

/* Bridge deinit. */
int 
hsl_ctc_bridge_deinit (struct hsl_bridge *b)
{
  HSL_FN_ENTER ();

  if (hsl_ctc_bridge_p)
    {
      _hsl_ctc_bridge_deinit (&hsl_ctc_bridge_p);
    }
  HSL_FN_EXIT (0);
}

/* Set L2 ageing timer. */
int 
hsl_ctc_set_age_timer (struct hsl_bridge *b, int age)
{
  int ret;

  HSL_FN_ENTER ();

  //ret = bcmx_l2_age_timer_set (age);

  //使能定时器扫描
  ret = ctc_aging_set_property (CTC_AGING_TBL_MAC, CTC_AGING_PROP_AGING_SCAN_EN, 1);
  if (ret < 0) {
  	HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set the L2 ageing timer enable\n");
  }

  //设置定时器
  ret = ctc_aging_set_property (CTC_AGING_TBL_MAC, CTC_AGING_PROP_INTERVAL, age);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set the L2 ageing timer value\n");
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

/* Learning set. */
int 
hsl_ctc_set_learning (struct hsl_bridge *b, int learn)
{
  struct hsl_avl_node *node;
  struct hsl_if *ifp;
  struct hsl_bcm_if *bcmifp;
  int  ret;

  HSL_FN_ENTER ();
#if 1
  for (node = hsl_avl_top (b->port_tree); node; node = hsl_avl_next (node))
    {
      ifp = HSL_AVL_NODE_INFO (node);

      if (! ifp)
	continue;

      if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
	continue;

      bcmifp = ifp->system_info;
      if (! bcmifp)
	continue;

      /* Set port to learning. */
      ret = ctc_port_set_learning_en(bcmifp->u.l2.lport, !learn);  	  
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Error setting port %s to learning.\n", ifp->name);
	  continue;
	}
    }
#endif
  HSL_FN_EXIT (0);
}

int
hsl_ctc_set_if_mac_learning (struct hsl_if *ifp, int disable)
{
  struct hsl_bcm_if *bcmifp;
  int  ret;

  HSL_FN_ENTER ();
 #if 1
  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }
  ret = ctc_port_set_learning_en(bcmifp->u.l2.lport, !disable);  
  if (ret < 0) {
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Error setting port %s to learning.\n", ifp->name);
	  HSL_FN_EXIT (-1);
	}  
#endif
  HSL_FN_EXIT (0);
}

int
_hsl_ctc_set_stp_port_state2 (struct hsl_if *ifp, int instance, int state)
{
  struct hsl_bcm_if *ctcifp = ifp->system_info;
  //struct hsl_bridge_port *bridge_port;
  uint16 gport;
  int ctc_port_state;
  int ret;

  HSL_FN_ENTER ();

  gport = ctcifp->u.l2.lport;

  switch (state)
    {
    case HAL_BR_PORT_STATE_LISTENING:
      ctc_port_state = CTC_STP_LEARNING;
      break;
    case HAL_BR_PORT_STATE_LEARNING:
      ctc_port_state = CTC_STP_LEARNING;
      break;
    case HAL_BR_PORT_STATE_FORWARDING:
      ctc_port_state = CTC_STP_FORWARDING;
      break;
    case HAL_BR_PORT_STATE_BLOCKING:
    case HAL_BR_PORT_STATE_DISABLED:
      ctc_port_state = CTC_STP_BLOCKING;
      break;
    default:
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Invalid port state\n");
      HSL_FN_EXIT (-1);
    }

  if (hsl_ctc_bridge_p->stg[instance] != -1)
    {
     // ret = bcmx_stg_stp_set (hsl_bcm_bridge_p->stg[instance], lport, 
      //                        bcm_port_state);
      ret = ctc_stp_set_state(gport, instance, ctc_port_state);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set STP port state %d for port %s retval %d\n", ctc_port_state, ifp->name, ret);
          HSL_FN_EXIT (-1);
        }
	  
#ifdef HAVE_L2LERN
      bridge_port = ifp->u.l2_ethernet.port;
      if (bridge_port)
        bridge_port->stp_port_state = state;
#endif /* HAVE_L2LERN */
    }
  
  HSL_FN_EXIT (0);
}



/* Set STP port state. */
int 
hsl_ctc_set_stp_port_state (struct hsl_bridge *b, struct hsl_bridge_port *port, int instance, int state)
{
  struct hsl_if *ifp, *ifp_child;
  struct hsl_if_list *ln;
  struct  hsl_bcm_if *bcmifp;
  int ret;

  HSL_FN_ENTER ();

  if (! hsl_ctc_bridge_p)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Bridge not initialized\n");
      HSL_FN_EXIT (-1);
    }

  if (instance >= HSL_CTC_STG_MAX_INSTANCES)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Instance number %d exceeds %d\n", instance, HSL_CTC_STG_MAX_INSTANCES);
      HSL_FN_EXIT (-1);
    }

  ifp = port->ifp;
  if (! ifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  if (ifp->type == HSL_IF_TYPE_L2_ETHERNET && bcmifp->trunk_id >= 0)
    {
      for (ln = ifp->children_list; ln; ln = ln->next)
        {
          ifp_child = ln->ifp;
          ret = _hsl_ctc_set_stp_port_state2 (ifp_child, instance, state);
          if (ret < 0)
            HSL_FN_EXIT (-1);
        }
    }
  else
    {
      ret = _hsl_ctc_set_stp_port_state2 (ifp, instance, state);
      if (ret < 0)
        HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

/* Add instance. */
int 
hsl_ctc_add_instance (struct hsl_bridge *b, int instance)
{
  struct hsl_avl_node *node;
  struct hsl_bcm_if *bcmifp;
  struct hsl_if *ifp;
  uint16 gport;
  int stg;
  int ret;

  HSL_FN_ENTER ();

  if (! hsl_ctc_bridge_p)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Bridge not initialized\n");
      HSL_FN_EXIT (-1);
    }

  if (instance >= HSL_CTC_STG_MAX_INSTANCES)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Instance number %d exceeds %d\n", instance, HSL_CTC_STG_MAX_INSTANCES);
      HSL_FN_EXIT (-1);
    }

  if (hsl_ctc_bridge_p->stg[instance] != -1)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "STG %d exists for this instance %d\n", hsl_ctc_bridge_p->stg[instance], instance);
      HSL_FN_EXIT (-1);
    }

  _ctc_stp_init_instance(instance);

  hsl_ctc_bridge_p->stg[instance] = CTC_STP_FORWARDING;

  /* For L2 ports which are directly mapped to a L3 interface, set the port state to 
     Blocking . */
  HSL_IFMGR_LOCK;

  for (node = hsl_avl_top (HSL_IFMGR_TREE); node; node = hsl_avl_next (node))
     {
       ifp = HSL_AVL_NODE_INFO (node);
       if (! ifp)
         continue;

       /* If L2 port is directly mapped to a L3(router port) set the state to
        forwarding. */

        if (ifp->type == HSL_IF_TYPE_L2_ETHERNET 
            && ! CHECK_FLAG (ifp->if_flags, HSL_IFMGR_IF_DIRECTLY_MAPPED))
          {
            bcmifp = ifp->system_info;
            gport = bcmifp->u.l2.lport;

            /* Set to Blocking state. */
           // bcmx_stg_stp_set (hsl_bcm_bridge_p->stg[instance], lport, BCM_STG_STP_BLOCK);
           // ctc_stp_set_state(gport, instance, CTC_STP_BLOCKING);
          }
     }

  HSL_IFMGR_UNLOCK;

  HSL_FN_EXIT (0);
}

/* Delete instance. */
int 
hsl_ctc_delete_instance (struct hsl_bridge *b, int instance)
{
  int ret;

  HSL_FN_ENTER ();

  if (! hsl_ctc_bridge_p)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Bridge not initialized\n");
      HSL_FN_EXIT (-1);
    }

  if (instance >= HSL_CTC_STG_MAX_INSTANCES)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Instance number %d exceeds %d\n", instance, HSL_CTC_STG_MAX_INSTANCES);
      HSL_FN_EXIT (-1);
    }

  if (hsl_ctc_bridge_p->stg[instance] == -1)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "STG %d doesn't exist for this instance %d\n", hsl_ctc_bridge_p->stg[instance], instance);
      HSL_FN_EXIT (-1);
    }

  ret = _ctc_stp_destroy_instance(instance);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Error deleting STG %d\n", hsl_ctc_bridge_p->stg[instance]);
      HSL_FN_EXIT (-1);
    }

  hsl_ctc_bridge_p->stg[instance] = -1;
  HSL_FN_EXIT (0);
}

#ifdef HAVE_VLAN
/* Add VID to instance. */
int 
hsl_ctc_add_vlan_to_instance (struct hsl_bridge *b, int instance, hsl_vid_t vid)
{
  struct hsl_avl_node *node;
  struct hsl_bcm_if *bcmifp;
  struct hsl_if *ifp;
  uint16 gport;
  int stg;
  int ret;

  HSL_FN_ENTER ();

  if (! hsl_ctc_bridge_p)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Bridge not initialized\n");
      HSL_FN_EXIT (-1);
    }

  if (instance >= HSL_CTC_STG_MAX_INSTANCES)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Instance number %d exceeds %d\n", instance, HSL_CTC_STG_MAX_INSTANCES);
      HSL_FN_EXIT (-1);
    }

  if (hsl_ctc_bridge_p->stg[instance] == -1)
    {
 //     ret = bcmx_stg_create (&stg);
//
 	  ret = _ctc_stp_init_instance(instance);
 	  if (ret < 0) {
           HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Error creating STG %d\n", hsl_ctc_bridge_p->stg[instance]);
           HSL_FN_EXIT (-1);
      }

      hsl_ctc_bridge_p->stg[instance] = CTC_STP_FORWARDING;

      /* For L2 ports which are directly mapped to a L3 interface, set the port state to 
         Blocking . */
      HSL_IFMGR_LOCK;

      for (node = hsl_avl_top (HSL_IFMGR_TREE); node; node = hsl_avl_next (node))
         {
           ifp = HSL_AVL_NODE_INFO (node);
           if (! ifp)
             continue;

           /* If L2 port is directly mapped to a L3(router port) set the state to
            forwarding. */

            if (ifp->type == HSL_IF_TYPE_L2_ETHERNET 
                && ! CHECK_FLAG (ifp->if_flags, HSL_IFMGR_IF_DIRECTLY_MAPPED))
              {
                bcmifp = ifp->system_info;
                gport = bcmifp->u.l2.lport;

                /* Set to Blocking state. */
               // bcmx_stg_stp_set (hsl_bcm_bridge_p->stg[instance], lport, BCM_STG_STP_BLOCK);
               //	 ctc_stp_set_state(gport, instance, CTC_STP_BLOCKING);
              }
         }

      HSL_IFMGR_UNLOCK;
    }

 // ret = bcmx_stg_vlan_add (hsl_bcm_bridge_p->stg[instance], vid);
  ret = ctc_stp_set_vlan_stpid(vid, instance);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Error adding VLAN %d to STG %d\n", vid, hsl_ctc_bridge_p->stg[instance]);
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

/* Delete VID from instance. */
int 
hsl_ctc_delete_vlan_from_instance (struct hsl_bridge *b, int instance, hsl_vid_t vid)
{
  int ret;

  HSL_FN_ENTER ();

  if (! hsl_ctc_bridge_p)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Bridge not initialized\n");
      HSL_FN_EXIT (-1);
    }

  if (instance >= HSL_CTC_STG_MAX_INSTANCES)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Instance number %d exceeds %d\n", instance, HSL_CTC_STG_MAX_INSTANCES);
      HSL_FN_EXIT (-1);
    }

  if (hsl_ctc_bridge_p->stg[instance] == -1)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "STG %d doesn't exist for this instance %d\n", hsl_ctc_bridge_p->stg[instance], instance);
      HSL_FN_EXIT (-1);
    }

//  ret = bcmx_stg_vlan_remove (hsl_bcm_bridge_p->stg[instance], vid);
/**
	从Instance中删除VLAN,盛科提供只能将VLAN加入默认Instance 0中，做覆盖操作
**/
  ret = ctc_stp_set_vlan_stpid(vid, 0);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Error adding VLAN %d to STG %d\n", vid, hsl_ctc_bridge_p->stg[instance]);
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

/* Add VLAN. */
int 
hsl_ctc_add_vlan (struct hsl_bridge *b, struct hsl_vlan_port *v)
{
  int ret;
  ctc_l2dflt_addr_t l2dflt_addr;
  
  HSL_FN_ENTER ();

  if (HSL_VLAN_DEFAULT_VID == v->vid)
    HSL_FN_EXIT (0);

  /* Check if the VID is part of the reserved vlan. */
  if (hsl_ctc_resv_vlan_is_allocated (v->vid)){
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't add VLAN %d. Reserved in hardware\n", v->vid);
      HSL_FN_EXIT (-1);
    }
  //ret = bcmx_vlan_create (v->vid);
  ret = ctc_vlan_create_vlan(v->vid);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't add VLAN %d\n", v->vid);
      HSL_FN_EXIT (-1);
    }

   sal_memset(&l2dflt_addr,0,sizeof(ctc_l2dflt_addr_t));
   l2dflt_addr.fid = v->vid;
   l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid ; /*default vlan default 's group id = fid*/
   ret = ctc_l2_add_default_entry(&l2dflt_addr);
   if (ret < 0) {
       HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_l2_add_default_entry error\n");
       HSL_FN_EXIT (-1); 
   }

  /* Add CPU port to the VLAN. */
  //hsl_bcm_add_port_to_vlan (v->vid, BCMX_LPORT_LOCAL_CPU, 1);

  HSL_FN_EXIT (0);
}

/* Delete VLAN. */
int 
hsl_ctc_delete_vlan (struct hsl_bridge *b, struct hsl_vlan_port *v)
{
  int ret;
  ctc_l2dflt_addr_t l2dflt_addr;

  HSL_FN_ENTER ();

  if (HSL_VLAN_DEFAULT_VID == v->vid)
    HSL_FN_EXIT (0);

  //ret = bcmx_vlan_destroy (v->vid);
  ret = ctc_vlan_destroy_vlan(v->vid);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't delete VLAN %d\n", v->vid);
      HSL_FN_EXIT (-1);
    }

  sal_memset(&l2dflt_addr,0,sizeof(ctc_l2dflt_addr_t));
  l2dflt_addr.fid = v->vid;
  l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid ; /*default vlan default 's group id = fid*/

  ret = ctc_l2_remove_default_entry(&l2dflt_addr);
  if (ret < 0) {
    HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_l2_remove_default_entry error vid=%d\n", v->vid);
    HSL_FN_EXIT (-1);
  }
  HSL_FN_EXIT (0);
}

/* Set port type type. */
int 
hsl_ctc_set_vlan_port_type (struct hsl_bridge *b, struct hsl_bridge_port *port, 
			    enum hal_vlan_port_type port_type, 
			    enum hal_vlan_acceptable_frame_type acceptable_frame_types, 
			    u_int16_t enable_ingress_filter)
{
  uint16 gport;
  struct hsl_if *ifp;
  struct hsl_bcm_if *bcmifp;
  int mode, ret=0;
  HSL_FN_ENTER ();

  if (((port_type == HAL_VLAN_HYBRID_PORT)
       || (port_type == HAL_VLAN_TRUNK_PORT))
      && (acceptable_frame_types == HAL_VLAN_ACCEPTABLE_FRAME_TYPE_TAGGED))
    {
        mode = CTC_VLANCTL_DROP_ALL_UNTAGGED;
    } else {
    	mode = CTC_VLANCTL_ALLOW_ALL_PACKETS;
    }

  ifp = port->ifp;
  if (! ifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  gport = bcmifp->u.l2.lport;

#ifdef HAVE_L2LERN
  port->type = port_type;
#endif /* HAVE_L2LERN */

	/*当为聚合口的时候找出聚合口成员分别操作*/
    if (CTC_IS_LINKAGG_PORT(gport)) {
		uint8 max_num =0 ;
		uint16* p_gports = NULL;
		uint8 cnt = 0;
		int idx = 0;
		ret = ctc_linkagg_get_max_mem_num(&max_num);
		if (ret < 0) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_linkagg_get_max_mem_num failed\n");
			HSL_FN_EXIT (-1);
		}
		p_gports = (uint16*)sal_malloc(sizeof(uint16) * max_num);
		if (!p_gports) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "sal_malloc failed, max_num=%d\n", max_num);
			goto link_ret;
		}
		ret = ctc_linkagg_get_member_ports (CTC_MAP_GPORT_TO_TID(gport), p_gports, &cnt);
		if (ret < 0) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_linkagg_get_member_ports failed ret=%d\n", ret);
			goto link_ret;
		}

		for (idx = 0; idx < cnt; idx++) {
			gport = p_gports[idx];
			
			//ret = bcmx_port_discard_set(lport, mode);
			ret = ctc_port_set_vlan_ctl(gport, mode);
		    if (ret < 0) {
			    HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_DEBUG, "bcmx_port_discard_set ,gport=%04x, mode = %d, ret = %d\n", gport ,mode, ret);
		        HSL_FN_EXIT (-1);
		    }

			if (enable_ingress_filter)
				ctc_port_set_vlan_filter_en (gport, CTC_INGRESS, 1);
			else
				ctc_port_set_vlan_filter_en (gport, CTC_INGRESS, 0);
		}

link_ret:
		if (p_gports) {
			sal_free(p_gports);
	    	p_gports = NULL;
		}
		HSL_FN_EXIT (ret);
    }
    

	//ret = bcmx_port_discard_set(lport, mode);
	ret = ctc_port_set_vlan_ctl(gport, mode);
    if (ret < 0) {
	    HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_DEBUG, "bcmx_port_discard_set ,gport=%04x, mode = %d, ret = %d\n", gport ,mode, ret);
        HSL_FN_EXIT (-1);
    }

  if (enable_ingress_filter)
    //bcmx_port_ifilter_set (lport, BCM_PORT_IFILTER_ON);
    ctc_port_set_vlan_filter_en (gport, CTC_INGRESS, 1);
  else
    //bcmx_port_ifilter_set (lport, BCM_PORT_IFILTER_OFF);
    ctc_port_set_vlan_filter_en (gport, CTC_INGRESS, 0);

  HSL_FN_EXIT (0);
}

/* Set default PVID. */
int 
hsl_ctc_set_default_pvid (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, int egress)
{
  uint16 gport;
  struct hsl_if *ifp;
  struct hsl_bcm_if *bcmifp;
  int ret;
  struct hsl_bridge_port *port;

  HSL_FN_ENTER ();
  port = port_vlan->port;
  if (! port)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  ifp = port->ifp;
  if (! ifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  gport = bcmifp->u.l2.lport;

  
	/*当为聚合口的时候找出聚合口成员分别操作*/
    if (CTC_IS_LINKAGG_PORT(gport)) {
		uint8 max_num =0 ;
		uint16* p_gports = NULL;
		uint8 cnt = 0;
		int idx = 0;
		ret = ctc_linkagg_get_max_mem_num(&max_num);
		if (ret < 0) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_linkagg_get_max_mem_num failed\n");
			HSL_FN_EXIT (-1);
		}
		p_gports = (uint16*)sal_malloc(sizeof(uint16) * max_num);
		if (!p_gports) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "sal_malloc failed\n");
			goto link_ret;
		}
		ret = ctc_linkagg_get_member_ports (CTC_MAP_GPORT_TO_TID(gport), p_gports, &cnt);
		if (ret < 0) {
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_linkagg_get_member_ports failed ret=%d\n", ret);
			goto link_ret;
		}

		for (idx = 0; idx < cnt; idx++) {
			gport = p_gports[idx];

			  ret = ctc_port_set_default_vlan(gport, port_vlan->pvid);
			  if (ret < 0) {
			      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set default PVID %d for port %s\n", port_vlan->pvid, ifp->name);
			      HSL_FN_EXIT (-1);
			  }

			  
			  ret = ctc_vlan_set_tagged_port(port_vlan->pvid, gport, FALSE);
			  if (ret < 0) {
			      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "set pvid untagged failed pvid=%d, gport=%d\n", port_vlan->pvid, gport);
			      HSL_FN_EXIT (-1);
 				 }

		}

link_ret:
		if (p_gports) {
			sal_free(p_gports);
	    	p_gports = NULL;
		}
		HSL_FN_EXIT (ret);
    }
 

  //ret = bcmx_port_untagged_vlan_set (lport, port_vlan->pvid);
  ret = ctc_port_set_default_vlan(gport, port_vlan->pvid);
  if (ret < 0) {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set default PVID %d for port %s\n", port_vlan->pvid, ifp->name);
      HSL_FN_EXIT (-1);
  }

  
  ret = ctc_vlan_set_tagged_port(port_vlan->pvid, gport, FALSE);
  if (ret < 0) {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "set pvid untagged failed pvid=%d, gport=%d\n", port_vlan->pvid, gport);
      HSL_FN_EXIT (-1);
  }

  /* XXX egress tagged? */
  HSL_FN_EXIT (0);
}

/* Add VID to port. */
int 
hsl_ctc_add_vlan_to_port (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, hsl_vid_t vid,
			  enum hal_vlan_egress_type egress)
{
  uint16 gport;
  struct hsl_if *ifp;
  struct hsl_bcm_if *bcmifp;
  int ret;
  struct hsl_bridge_port *port;
#ifdef HAVE_PVLAN
  struct hsl_vlan_port *vlan_port;
  struct hsl_vlan_port tv;
  struct hsl_avl_node *node;
  struct hsl_bridge_port *bridge_port;
  struct hsl_bcm_pvlan *bcm_pvlan;
  bcmx_lport_t lport_egress;
  bcmx_lplist_t plist;
  bcmx_lplist_t plist_trunk;
#endif /* HAVE_PVLAN */

  HSL_FN_ENTER ();

  port = port_vlan->port;
  if (! port) {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  ifp = port->ifp;
  if (! ifp) {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp) {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  gport = bcmifp->u.l2.lport;

  /* Add VLAN to the port. */
  if (egress == HAL_VLAN_EGRESS_TAGGED)
    ret = hsl_bcm_add_port_to_vlan (vid, gport, 1);
  else
    ret = hsl_bcm_add_port_to_vlan (vid, gport, 0);
#if 0
#ifdef HAVE_PVLAN
  /* For interlink switchports block traffic to host ports of isolated vlan */
  if (egress == HAL_VLAN_EGRESS_TAGGED)
    {
      tv.vid = vid;

      node = hsl_avl_lookup (b->vlan_tree, &tv);

      if (!node)
        {
          HSL_FN_EXIT (ret);
        }
 
      vlan_port = (struct hsl_vlan_port *) HSL_AVL_NODE_INFO (node);

      bcm_pvlan = (struct hsl_bcm_pvlan *)vlan_port->system_info;

      /* Private vlan not configured on this vlan */
      if (!bcm_pvlan)
        HSL_FN_EXIT (0);

      if (bcm_pvlan->vlan_type == HAL_PVLAN_NONE)
        HSL_FN_EXIT (0);

      bcmx_lplist_init (&plist_trunk, 0, 0);
      bcmx_port_egress_get (lport, -1, &plist_trunk);

      for (node = hsl_avl_top (vlan_port->port_tree); node; node = hsl_avl_next (node))
        {
          bcmx_lplist_init (&plist, 0, 0);
          ifp = HSL_AVL_NODE_INFO (node);
          if (!ifp)
            continue;

          bcmifp = (struct hsl_bcm_if *)ifp->system_info;
          if (!bcmifp)
            continue;

          bridge_port = ifp->u.l2_ethernet.port;
          lport_egress = bcmifp->u.l2.lport;
          if ((lport_egress != lport) && (bridge_port->pvlan_port_mode == HAL_PVLAN_PORT_MODE_HOST))
            {
              bcmx_port_egress_get (lport_egress, -1, &plist);
              bcmx_lplist_add (&plist, lport);
              bcmx_port_egress_set (lport_egress, -1, plist);
              /* Remove the isolated port from egress list of trunk port */
              bcmx_lplist_port_remove (&plist_trunk, lport_egress, 1);

            }
           bcmx_lplist_free (&plist);
        }
      bcmx_port_egress_set (lport, -1, plist_trunk);
      bcmx_lplist_free (&plist_trunk);
    }
#endif /* HAVE_PVLAN */
#endif
  HSL_FN_EXIT (ret);
}

/* Delete VID from port. */
int 
hsl_ctc_delete_vlan_from_port (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, hsl_vid_t vid)
{
  uint16 gport;
  struct hsl_if *ifp;
  struct hsl_bcm_if *bcmifp;
  int ret;
  struct hsl_bridge_port *port;
#if 0
#ifdef HAVE_PVLAN
  struct hsl_vlan_port *vlan_port;
  struct hsl_vlan_port tv;
  struct hsl_avl_node *node;
  struct hsl_bridge_port *bridge_port;
  bcmx_lport_t lport_tmp, lport_egress;
  struct hsl_bcm_pvlan *bcm_pvlan;
  bcmx_lplist_t plist_trunk;
#endif /* HAVE_PVLAN */
#endif

  HSL_FN_ENTER ();
#if 1
  port = port_vlan->port;
  if (! port)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  ifp = port->ifp;
  if (! ifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Interface not set\n");
      HSL_FN_EXIT (-1);
    }

  gport = bcmifp->u.l2.lport;



  /* Remove VLAN from port. */
  ret = hsl_bcm_remove_port_from_vlan (vid, gport);
#if 0
#ifdef HAVE_PVLAN
  tv.vid = vid;

  node = hsl_avl_lookup (b->vlan_tree, &tv);

  if (!node)
    {
      HSL_FN_EXIT (ret);
    }

  vlan_port = (struct hsl_vlan_port *) HSL_AVL_NODE_INFO (node);

  if (!vlan_port)
    HSL_FN_EXIT (-1);

  bcm_pvlan = (struct hsl_bcm_pvlan *)vlan_port->system_info;

  /* Private vlan not configured on this vlan */
  if (!bcm_pvlan)
    HSL_FN_EXIT (0);

  if (bcm_pvlan->vlan_type == HAL_PVLAN_NONE)
    HSL_FN_EXIT (0);

  /* For host, promiscuous ports, filtering is taken care before itself */
  if (port_vlan->pvlan_port_mode != HAL_PVLAN_PORT_MODE_INVALID)
    HSL_FN_EXIT (0);

  bcmx_lplist_init (&plist_trunk, 0, 0);

  /* Add all the ports for egressing */
  BCMX_FOREACH_LPORT (lport_tmp)
    {
      bcmx_lplist_add (&plist_trunk, lport_tmp);
    }
  /* Remove specific isolated vlan ports for egressing */
  for (node = hsl_avl_top (vlan_port->port_tree); node; node = hsl_avl_next (node))
    {
      ifp = HSL_AVL_NODE_INFO (node);
      if (!ifp)
        continue;

      bcmifp = (struct hsl_bcm_if *)ifp->system_info;
      if (!bcmifp)
        continue;

      bridge_port = ifp->u.l2_ethernet.port;
      lport_egress = bcmifp->u.l2.lport;

      /* Add the new trunk port to be part of egress port list for secondary vlan isolated ports */
      if ((lport_egress != lport) && (bridge_port->pvlan_port_mode == HAL_PVLAN_PORT_MODE_HOST))
        {
          /* Remove the isolated port from egress list of trunk/access port */
          bcmx_lplist_port_remove (&plist_trunk, lport_egress, 1);
        }
    }
  bcmx_port_egress_set (lport, -1, plist_trunk);
  bcmx_lplist_free (&plist_trunk);
#endif /* HAVE_PVLAN */
#endif
#endif
  HSL_FN_EXIT (ret);
}

#endif /* HAVE_VLAN */  


//先屏蔽掉IGMP部分
#if 0
#ifdef HAVE_IGMP_SNOOP

/* Init IGMP snooping. */
int
hsl_bcm_init_igmp_snooping ()
{
  //int i, bcm_unit;

  HSL_FN_ENTER ();


        //bcm_igmp_snooping_init (0);


  HSL_FN_EXIT (0);
}

/* Deinit IGMP snooping. */
int
hsl_bcm_deinit_igmp_snooping ()
{
  HSL_FN_EXIT (0);
}
#if 0
int
_hsl_bcm_install_igmp_rule (int enable_flag, int msg,
                            int router_alert_msg)
{
  bcm_filterid_t fid;
  int ret;

  HSL_FN_ENTER ();

  ret = bcmx_filter_create (&fid);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
               "Can't create IGMP Snooping filter\n");
      HSL_FN_EXIT (-1);
    }

  bcmx_filter_qualify_data8 (fid, DEST_MAC_OUI_1, IGMP_MAC_OUI_1, 0xff);
  bcmx_filter_qualify_data8 (fid, DEST_MAC_OUI_2, IGMP_MAC_OUI_2, 0xff);
  bcmx_filter_qualify_data8 (fid, DEST_MAC_OUI_3, IGMP_MAC_OUI_3, 0xff);
  bcmx_filter_qualify_data8 (fid, IP_PROTOCOL_OFFSET, IGMP_PROTOCOL, 0xff);

  if (msg >= 0)
    {
      bcmx_filter_qualify_data8 (fid, IGMP_MSG_OFFSET, msg, 0xff);
    }

  if (router_alert_msg >= 0)
    {
      /* Setup mask and option header for router alerts */
      bcmx_filter_qualify_data32 (fid, IP_OPTIONS_OFFSET,
                                  (ROUTER_ALERT1 << 24 |
                                   ROUTER_ALERT2 << 16 |
                                   ROUTER_ALERT3 << 8  |
                                   ROUTER_ALERT4),
                                  0xffffffff);
      bcmx_filter_qualify_data8 (fid, ROUTER_ALERT_IGMP_OFFSET,
                                 router_alert_msg, 0xff);
    }

  /* Define processing rules */
  bcmx_filter_action_match (fid, bcmActionCopyToCpu, 0);
  bcmx_filter_action_match (fid, bcmActionDoNotSwitch, 0);

  if (enable_flag)
    ret = bcmx_filter_install (fid);
  else
    ret = bcmx_filter_remove (fid);

  bcmx_filter_destroy (fid);

  HSL_FN_EXIT (ret);
}
#endif

void
_hsl_bcm_uninstall_igmp_field (void)
{

  if (_hsl_igmp_snp_field_ent != HSL_IGS_BCM_INVALID_FIELD_ENTRY) 
    bcmx_field_entry_destroy (_hsl_igmp_snp_field_ent);

  if (_hsl_igmp_snp_field_grp != HSL_IGS_BCM_INVALID_FIELD_GRP)
    bcmx_field_group_destroy (_hsl_igmp_snp_field_grp);

  _hsl_igmp_snp_field_ent = HSL_IGS_BCM_INVALID_FIELD_ENTRY;
  _hsl_igmp_snp_field_grp = HSL_IGS_BCM_INVALID_FIELD_GRP;
}

int
_hsl_bcm_install_igmp_field (void)
{
  int ret;
  u_int32_t pbmp = 0;
  bcm_field_qset_t qset;

  HSL_FN_ENTER ();

  BCM_FIELD_QSET_INIT(qset);

  BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyIpProtocol);
  BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyPacketFormat);

  ret = bcmx_field_group_create (qset, BCM_FIELD_GROUP_PRIO_ANY,
                                 &_hsl_igmp_snp_field_grp);

  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
               "Can't create IGMP Snooping field group\n");
      goto ERR;
    }

  ret = bcmx_field_entry_create (_hsl_igmp_snp_field_grp, &_hsl_igmp_snp_field_ent);
  if (ret != BCM_E_NONE)
   {
     HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
              "Can't create IGMP Snooping field entry\n");
      goto ERR;
   }

  /* Qualify IP Protocol */
  ret = bcmx_field_qualify_IpProtocol (_hsl_igmp_snp_field_ent,
                                       IGMP_PROTOCOL,
                                       0xff);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
               "Can't create IGMP protocol qualifier\n");
    }

  ret = bcmx_field_action_add (_hsl_igmp_snp_field_ent,
                               bcmFieldActionCopyToCpu, 0, 0);

  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
               "Can't set IGMP Snooping field entry Copy To CPU action\n");
    }

  ret = bcmx_field_action_add (_hsl_igmp_snp_field_ent,
                               bcmFieldActionRedirectPbmp, pbmp, 0);

  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
               "Can't set IGMP Snooping field entry Redirect action\n");
    }

  ret = bcmx_field_entry_install (_hsl_igmp_snp_field_ent);

  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
               "Can't install IGMP Snooping field entry\n");
    }

  HSL_FN_EXIT (0);

ERR:

  _hsl_bcm_uninstall_igmp_field ();
  HSL_FN_EXIT (ret);
}

int
hsl_bcm_igmp_snooping_set (int enable_flag)
{
  HSL_FN_ENTER ();


  if (hsl_bcm_filter_type_get() == HSL_BCM_FEATURE_FILTER)
    {
      /*  Install rules for normal IGMP messages. */
	  /*
      _hsl_bcm_install_igmp_rule (enable_flag, IGMP_V1_REPORT, -1);
      _hsl_bcm_install_igmp_rule (enable_flag, IGMP_V2_REPORT, -1);
      _hsl_bcm_install_igmp_rule (enable_flag, IGMP_V3_REPORT, -1);
      _hsl_bcm_install_igmp_rule (enable_flag, IGMP_QUERY, -1);
      _hsl_bcm_install_igmp_rule (enable_flag, IGMP_LEAVE, -1);
      */

      /* Install rules for IGMP router alert messages. */
	  /*
      _hsl_bcm_install_igmp_rule (enable_flag, -1, IGMP_V1_REPORT);
      _hsl_bcm_install_igmp_rule (enable_flag, -1, IGMP_V2_REPORT);
      _hsl_bcm_install_igmp_rule (enable_flag, -1, IGMP_V3_REPORT);
      _hsl_bcm_install_igmp_rule (enable_flag, -1, IGMP_QUERY);
      _hsl_bcm_install_igmp_rule (enable_flag, -1, IGMP_LEAVE);
      */
    }
  else if (hsl_bcm_filter_type_get() == HSL_BCM_FEATURE_FIELD)
    {
      if (enable_flag)
        _hsl_bcm_install_igmp_field ();
      else
        _hsl_bcm_uninstall_igmp_field ();
    }

  HSL_FN_EXIT (0);
}

/* Enable IGMP snooping. */
int 
hsl_bcm_enable_igmp_snooping (struct hsl_bridge *b)
{
  int ret;

  HSL_FN_ENTER ();

  ret = hsl_bcm_igmp_snooping_set (1);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't enable IGMP Snooping\n");
      HSL_FN_EXIT (-1);
    }
  HSL_FN_EXIT (0);
}

/* Disable IGMP snooping. */
int 
hsl_bcm_disable_igmp_snooping (struct hsl_bridge *b)
{
  /* XXX: Do not disable IGMP snooping for L2/L3 multicast to work 
   * properly.
   */
  HSL_FN_ENTER ();

#if 0
  int ret;

  ret = hsl_bcm_igmp_snooping_set (0);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't disable IGMP Snooping\n");
    }
#endif
  HSL_FN_EXIT (0);
}

/* Enable IGMP snooping on port. */
int
hsl_bcm_enable_igmp_snooping_port (struct hsl_bridge *b, struct hsl_if *ifp)
{
  HSL_FN_ENTER ();
  HSL_FN_EXIT (0);
}

/* Disable IGMP snooping on port. */
int
hsl_bcm_disable_igmp_snooping_port (struct hsl_bridge *b, struct hsl_if *ifp)
{
  HSL_FN_ENTER ();
  HSL_FN_EXIT (0);
}

#endif /* HAVE_IGMP_SNOOP */
#endif
#ifdef HAVE_MLD_SNOOP

/* Init MLD snooping. */
int
hsl_ctc_init_mld_snooping ()
{
  HSL_FN_EXIT (0);
}

/* Deinit MLD snooping. */
int
hsl_ctc_deinit_mld_snooping ()
{
  HSL_FN_EXIT (0);
}

int
_hsl_ctc_install_mld_rule (int enable_flag, int msg)
{
 // bcm_filterid_t fid;
  int ret;

  HSL_FN_ENTER ();
  //by chentao
#if 0
  ret = bcmx_filter_create (&fid);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR,
               "Can't create MLD Snooping filter\n");
      HSL_FN_EXIT (-1);
    }

  bcmx_filter_qualify_data8 (fid, DEST_MAC_OUI_1, MLD_MAC_OUI_1, 0xff);
  bcmx_filter_qualify_data8 (fid, DEST_MAC_OUI_2, MLD_MAC_OUI_2, 0xff);
  bcmx_filter_qualify_data8 (fid, IPV6_PROTOCOL_OFFSET, ICMPV6_PROTOCOL, 0xff);

  if (msg >= 0)
    {
      bcmx_filter_qualify_data8 (fid, MLD_OFFSET, msg, 0xff);
    }

  /* Define processing rules */
  bcmx_filter_action_match (fid, bcmActionCopyToCpu, 0);
  bcmx_filter_action_match (fid, bcmActionDoNotSwitch, 0);

  if (enable_flag)
    ret = bcmx_filter_install (fid);
  else
    ret = bcmx_filter_remove (fid);

  bcmx_filter_destroy (fid);
#endif
  HSL_FN_EXIT (0);
}

int
_hsl_ctc_mld_snooping_set (int enable_flag)
{
  HSL_FN_ENTER ();
  //by chentao
#if 0
  /*  Install rules for normal MLD messages. */
  _hsl_bcm_install_mld_rule (enable_flag, MLD_LISTENER_QUERY);
  _hsl_bcm_install_mld_rule (enable_flag, MLD_LISTENER_REPORT);
  _hsl_bcm_install_mld_rule (enable_flag, MLDV2_LISTENER_REPORT);
#endif
  HSL_FN_EXIT (0);
}

/* Enable MLD snooping. */
int
hsl_ctc_enable_mld_snooping (struct hsl_bridge *b)
{
  int ret;

  HSL_FN_ENTER ();
  ret = _hsl_bcm_mld_snooping_set (1);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't enable MLD Snooping\n");
      HSL_FN_EXIT (-1);
    }
  HSL_FN_EXIT (0);
}

/* Disable MLD snooping. */
int
hsl_ctc_disable_mld_snooping (struct hsl_bridge *b)
{
  /* XXX: Do not disable MLD snooping for L2/L3 multicast to work
   * properly.
   */
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

#endif /* HAVE_MLD_SNOOP */

/* Ratelimit init. */
int
hsl_ctc_ratelimit_init (void)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/* Ratelimit deinit. */
int
hsl_ctc_ratelimit_deinit (void)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/* Rate limiting for bcast. */
int
hsl_ctc_ratelimit_bcast (struct hsl_if *ifp, int level,
                         int fraction)
{
//  struct hsl_bcm_if *bcmifp;
//  int speed;
//  int ret;
//  unsigned int pps = 0;
//  unsigned int bps;
 // bcmx_lport_t lport;

  HSL_FN_ENTER ();
 //by chentao 
#if 0
  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }
  lport = bcmifp->u.l2.lport;

  if ( (level == 0) && (fraction == 0) )
      bcmx_rate_bandwidth_set (lport, BCM_RATE_BCAST, 1,1000);
  else if ( (level == 100) && (fraction == 0) )
    {
      /* Disable storm control */
      bcmx_rate_bandwidth_set (lport, BCM_RATE_BCAST, 0,1000);
    }
  else
    {
      /* Get speed for the port. Units are Mbps */
      ret = bcmx_port_speed_get (lport, &speed);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't get speed for port %s\n", ifp->name);
	  HSL_FN_EXIT (-1);
	}
      
      /* Use max size of packets (1512) to determine the number of packets per second(pps). */
      if (level == 0)
        {
          bps = 0;
        }
      if (fraction == 0)
        bps = ((speed * HSL_IF_BW_UNIT_MEGA) * level)/100000;
      if ( (level != 0) && (fraction != 0) )
        {
            bps = ((speed * HSL_IF_BW_UNIT_MEGA) * level)/100000;
        }

        ret = bcmx_rate_bandwidth_set(lport, BCM_RATE_BCAST, bps,1000);
    
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set ratelimit for broadcast on port %s\n", ifp->name);
	  return HSL_ERR_BRIDGE_RATELIMIT;
	}
    }
#endif
  HSL_FN_EXIT (0);
}

/*
  Get bcast discards.
*/
int
hsl_ctc_ratelimit_get_bcast_discards (struct hsl_if *ifp, int *discards)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/* Rate limiting for mcast. */
int
hsl_ctc_ratelimit_mcast (struct hsl_if *ifp, int level,
                         int fraction)
{
//  struct hsl_bcm_if *bcmifp;
//  int speed;
//  int ret;
 // bcmx_lport_t lport;

  HSL_FN_ENTER ();
#if 0
  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  lport = bcmifp->u.l2.lport;

  if ( (level == 0) && (fraction == 0) )
      bcmx_rate_bandwidth_set (lport, BCM_RATE_MCAST, 1,1000);
  else if ( (level == 100) && (fraction == 0) )
    {
      /* Disable storm control */
      bcmx_rate_bandwidth_set (lport, BCM_RATE_MCAST, 0,1000);
    }
  else
    {
      /* Get speed for the port. Units are Mbps */
      ret = bcmx_port_speed_get (lport, &speed);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't get speed for port %s\n", ifp->name);
	  HSL_FN_EXIT (-1);
	}
      
      /* Use max size of packets (1512) to determine the number of packets per second(pps). */
      if (level == 0)
        {
          bps = 0;
        }
      if (fraction == 0)
        bps = ((speed * HSL_IF_BW_UNIT_MEGA) * level)/100000;
      if ( (level != 0) && (fraction != 0) )
        {
            bps = ((speed * HSL_IF_BW_UNIT_MEGA) * level)/100000;
        }

     ret = bcmx_rate_bandwidth_set(lport, BCM_RATE_MCAST, bps,1000);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set ratelimit for multicast on port %s\n", ifp->name);
	  return HSL_ERR_BRIDGE_RATELIMIT;
	}
    }
#endif
  HSL_FN_EXIT (0);
}

/*
  Get mcast discards.
*/
int
hsl_ctc_ratelimit_get_mcast_discards (struct hsl_if *ifp, int *discards)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/* Rate limiting for dlf bcast. */
int
hsl_ctc_ratelimit_dlf_bcast (struct hsl_if *ifp, int level,
                             int fraction)
{
  struct hsl_bcm_if *bcmifp;
  int speed;
  int ret;
  unsigned int bps = 0;
 // bcmx_lport_t lport = 0;

  HSL_FN_ENTER ();
#if 0
  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  lport = bcmifp->u.l2.lport;

  if ( (level == 0) && (fraction == 0) )
      bcmx_rate_bandwidth_set (lport, BCM_RATE_DLF, 1,1000);
  else if ( (level == 100) && (fraction == 0) )
    {
      /* Disable storm control */
      bcmx_rate_bandwidth_set (lport, BCM_RATE_DLF, 0,1000);
    }
  else
    {
      /* Get speed for the port. Units are Mbps  */
      ret = bcmx_port_speed_get (lport, &speed);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, 
                   "Can't get speed for port %s\n", ifp->name);
	  HSL_FN_EXIT (-1);
	}
      
      /* Use max size of packets (1512) to determine the number of packets per second(pps). */
      if (level == 0)
        {
          bps = 0;
        }
      if (fraction == 0)
        bps = ((speed * HSL_IF_BW_UNIT_MEGA) * level)/100000;
      if ( (level != 0) && (fraction != 0) )
        {
            bps = ((speed * HSL_IF_BW_UNIT_MEGA) * level)/100000;
        }

      ret = bcmx_rate_bandwidth_set(lport, BCM_RATE_DLF, bps,1000);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, 
                   "Can't set ratelimit for DLF broadcast on port %s\n", 
                   ifp->name);
	  return HSL_ERR_BRIDGE_RATELIMIT;
	}
    }
#endif
  HSL_FN_EXIT (0);
}

/*
  Get dlf bcast discards.
*/
int
hsl_ctc_ratelimit_get_dlf_bcast_discards (struct hsl_if *ifp, int *discards)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/* Flowcontrol init. */
int
hsl_ctc_flowcontrol_init (void)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/* Flowcontrol deinit. */
int
hsl_ctc_flowcontrol_deinit (void)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/* Set flowcontrol. */
int
hsl_ctc_set_flowcontrol (struct hsl_if *ifp, u_char direction)
{
    int ret = 0;
    struct hsl_bcm_if *bcmifp = NULL;
    ctc_port_fc_prop_t ctc_fc_cfg;

    HSL_FN_ENTER ();

    if (ifp->type != HSL_IF_TYPE_L2_ETHERNET) {
        HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

    bcmifp = ifp->system_info;
    if (! bcmifp) {
        HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

    memset(&ctc_fc_cfg, 0, sizeof(ctc_fc_cfg));
    ctc_fc_cfg.gport = bcmifp->u.l2.lport;
    
    /* tx flow control */
    if (direction & HAL_FLOW_CONTROL_SEND) {
        ctc_fc_cfg.dir = CTC_EGRESS;
        ctc_fc_cfg.enable = 1;
    } else {
        ctc_fc_cfg.dir = CTC_EGRESS;
        ctc_fc_cfg.enable = 0;
    }
    ret = ctc_port_set_flow_ctl_en(&ctc_fc_cfg);
    if(ret < 0) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port<%s> egress flow control stat<%d>: %d\r\n",   \
                ifp->name, ctc_fc_cfg.enable, ret);
        HSL_FN_EXIT(ret);
    }
   
    if (direction & HAL_FLOW_CONTROL_RECEIVE) {
        ctc_fc_cfg.dir = CTC_INGRESS;
        ctc_fc_cfg.enable = 1;
    } else {
        ctc_fc_cfg.dir = CTC_INGRESS;
        ctc_fc_cfg.enable = 0;
    }
    ret = ctc_port_set_flow_ctl_en(&ctc_fc_cfg);
    if(ret < 0) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port<%s> ingress flow control stat<%d>: %d\r\n",   \
                ifp->name, ctc_fc_cfg.enable, ret);
        HSL_FN_EXIT(ret);
    }

    HSL_FN_EXIT (0);
}

/*
  Get flowcontrol statistics. ctc sdk not support this feature 
*/
int hsl_ctc_flowcontrol_statistics (struct hsl_if *ifp, u_char *direction,
				int *rxpause, int *txpause)
{
    struct hsl_bcm_if *bcmifp = NULL;
    
    HSL_FN_ENTER ();

    if (ifp->type != HSL_IF_TYPE_L2_ETHERNET) {
        HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM;);
    }

    bcmifp = ifp->system_info;
    if (! bcmifp) {
        HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }
    printk("This chip not support this feature\r\n");

    HSL_FN_EXIT (-1);
}
/* 
   FDB init.
*/
int
hsl_ctc_fdb_init (void)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/*
  FDB deinit. 
*/
int
hsl_ctc_fdb_deinit (void)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

/*
  Add multicast FDB entry.
*/
static int
_hsl_ctc_add_l2mc (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid,
		   u_char flags, int is_forward)
{
 // struct hsl_bcm_if *bcmifp, *bcmifpc;
 // bcmx_mcast_addr_t mcaddr;
 // struct hsl_if_list *nm;
 // struct hsl_if *tmpif;
 // bcmx_lport_t lport;
 // int ret;

  HSL_FN_ENTER ();
  //by chentao
  #if 0
#ifdef HAVE_L3
  /* Add static entries ONLY. */
  if (!(flags & HAL_L2_FDB_STATIC))
    HSL_FN_EXIT(STATUS_OK);
#endif /* HAVE_L3 */

  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  /* Check for trunk port. */
  if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK) 
    {
      /* Get lport of first member. If the trunk is stable, then all known
	 multicasts will go through the first port. TODO traffic distribution 
	 for known multicasts can be added later. */

      /* If no children, then something is wrong! */
      if (! ifp->children_list)
	HSL_FN_EXIT (HSL_IFMGR_ERR_NULL_IF);

      nm = ifp->children_list;
      if (! nm || ! nm->ifp)
	HSL_FN_EXIT (HSL_IFMGR_ERR_NULL_IF);
      
      tmpif = nm->ifp;
      if (tmpif->type != HSL_IF_TYPE_L2_ETHERNET || ! tmpif->system_info)
	HSL_FN_EXIT (HSL_IFMGR_ERR_NULL_IF);

      bcmifpc = tmpif->system_info;

      /* Get lport of port. */
      lport = bcmifpc->u.l2.lport;
    }
  else
    {
      /* Get lport of port. */
      lport = bcmifp->u.l2.lport;  
    }

  memset(&mcaddr, 0, sizeof(bcmx_mcast_addr_t));
  bcmx_mcast_addr_init (&mcaddr, mac, vid);

  /* Get port. */
  ret = bcmx_mcast_port_get (mac, vid, &mcaddr);
  if (ret == BCM_E_NOT_FOUND)
    {
      /* Add the multicast entry. */
      ret = bcmx_mcast_addr_add (&mcaddr);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't add multicast FDB entry : Port %s mac (%02x%02x.%02x%02x.%02x%02x) VID %d\n", ifp->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid);
	  bcmx_mcast_addr_free (&mcaddr);
	  HSL_FN_EXIT (-1);
	}
    } /* end first addr not found */

  /* Join. */
  ret = bcmx_mcast_join (mac, vid, lport, &mcaddr, NULL);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't add multicast FDB entry : Port %s mac (%02x%02x.%02x%02x.%02x%02x) VID %d\n", ifp->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid);
      bcmx_mcast_addr_free (&mcaddr);
      HSL_FN_EXIT (-1);
    }

  bcmx_mcast_addr_free (&mcaddr);
#endif
  HSL_FN_EXIT (0);
}

/*
  Add unicast FDB entry.
*/
static int
_hsl_ctc_add_l2uc (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid,
		   u_char flags, int is_forward)
{
    int32 ret = 0;
    ctc_l2_addr_t l2_addr;
	int gport;
	fdb_entry_t entry;
	fdb_entry_t eptr;	
	fdb_entry_t key;	
	int age_timer;
	struct hsl_bcm_if *bcmifp;

	HSL_FN_ENTER ();
	memset(&entry, 0, sizeof(entry));
    memset(&l2_addr, 0, sizeof(l2_addr));

	memcpy(l2_addr.mac, mac, len);

	  bcmifp = ifp->system_info;
	  if (! bcmifp)
	    {
	      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
	    }

	  gport = bcmifp->u.l2.lport; 

	l2_addr.fid = vid;
	l2_addr.gport = gport;

	printk("\r\n\tifindex = %d\r\n\tgport = %d\r\n", ifp->ifindex, gport);	

	if (!is_forward) {
		l2_addr.flag |= CTC_L2_FLAG_SRC_DISCARD ;
	} 

	if (flags) {
		l2_addr.flag |= CTC_L2_FLAG_IS_STATIC;
	}

	ret = ctc_l2_add_fdb(&l2_addr);
	if (ret < 0) {
		HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "[%s]: add CTC fdb entry failed\r\n", __func__);	
		HSL_FN_EXIT (-1);
	}
	
	/* Ageing timer */
	ret = ctc_aging_get_property(CTC_AGING_TBL_MAC, CTC_AGING_PROP_INTERVAL , &age_timer);
	if (ret) {
		age_timer = 0;		
	}


	entry.ageing_timer_value = age_timer;
	entry.is_fwd = is_forward;
	entry.is_local = 0;
	entry.is_static = flags;
	memcpy(entry.mac_addr, mac, 6);
	entry.port_no = ifp->ifindex;
	entry.vid = vid;

	ret = hsl_add_fdb_entry (&entry);
	if (ret != 0)
	{
		HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Not Added [MAC:%x:%x:%x:%x:%x:%x] [DUPLICATE_KEY]\n",
		entry.mac_addr[0], entry.mac_addr[1],
		entry.mac_addr[2], entry.mac_addr[3],
		entry.mac_addr[4], entry.mac_addr[5]);
		HSL_FN_EXIT (-1);
	}
	else
	{
		key.mac_addr[0] = entry.mac_addr[0];
		key.mac_addr[1] = entry.mac_addr[1];
		key.mac_addr[2] = entry.mac_addr[2];
		key.mac_addr[3] = entry.mac_addr[3];
		key.mac_addr[4] = entry.mac_addr[4];
		key.mac_addr[5] = entry.mac_addr[5];

		if ((ret = hsl_get_fdb_entry (&eptr, SEARCH_BY_MAC, &key)) == 0)
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "Added [MAC:%x:%x:%x:%x:%x:%x] vid=%d to FDB\n",
			eptr.mac_addr[0], eptr.mac_addr[1], eptr.mac_addr[2],
			eptr.mac_addr[3], eptr.mac_addr[4], eptr.mac_addr[5], eptr.vid);
		else
		{
			HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Get entry [DUPLICATE_KEY]\n");
			HSL_FN_EXIT (-1);
		}
	}
	
  HSL_FN_EXIT (0);
}

#define MACADDR_IS_MULTICAST(mac) (mac[0] & 0x1)

/*
  Add FDB.
*/
int
hsl_ctc_add_fdb (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid,
		 u_char flags, int is_forward)
{
  int ret;

  HSL_FN_ENTER ();
  //by chentao
  #if 1
  if (MACADDR_IS_MULTICAST (mac))
    ret = _hsl_ctc_add_l2mc (b, ifp, mac, len, vid, flags, is_forward);
  else
    ret = _hsl_ctc_add_l2uc (b, ifp, mac, len, vid, flags, is_forward);
#endif
  HSL_FN_EXIT (ret);
}

/*
  Delete multicast FDB entry.
*/
static int
_hsl_ctc_delete_l2mc (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid, u_char flags)
{
 // struct hsl_bcm_if *bcmifp, *bcmifpc;
  //bcmx_mcast_addr_t mcaddr;
 // struct hsl_if_list *nm;
  //bcmx_lport_t lport;
 // struct hsl_if *tmpif;
 // int count = 0;
 // int ret;

  HSL_FN_ENTER ();
  //by chentao
#if 0
#ifdef HAVE_L3
  /* Delete static entries ONLY. */
  if (!(flags & HAL_L2_FDB_STATIC))
    HSL_FN_EXIT(STATUS_OK);
#endif /* HAVE_L3 */

  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  bcmifp = ifp->system_info;
  if (! bcmifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  /* Check for trunk port. */
  if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK) 
    {
      /* Get lport of first member. If the trunk is stable, then all known
	 multicasts will go through the first port. TODO traffic distribution 
	 for known multicasts can be added later. */

      /* If no children, then something is wrong! */
      if (! ifp->children_list)
	HSL_FN_EXIT (HSL_IFMGR_ERR_NULL_IF);

      nm = ifp->children_list;
      if (! nm || ! nm->ifp)
	HSL_FN_EXIT (HSL_IFMGR_ERR_NULL_IF);
      
      tmpif = nm->ifp;
      if (tmpif->type != HSL_IF_TYPE_L2_ETHERNET || ! tmpif->system_info)
	HSL_FN_EXIT (HSL_IFMGR_ERR_NULL_IF);

      bcmifpc = tmpif->system_info;

      /* Get lport of port. */
      lport = bcmifpc->u.l2.lport;
    }
  else
    {
      /* Get lport of port. */
      lport = bcmifp->u.l2.lport;  
    }

  /* Leave. */
  ret = bcmx_mcast_leave (mac, vid, lport);
  switch (ret)
    {
    case BCM_MCAST_LEAVE_DELETED:
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "Multicast FDB entry : Port %s (%02x%02x.%02x%02x.%02x%02x) VID %d deleted\n", ifp->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid);
      break;
    case BCM_MCAST_LEAVE_UPDATED:
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "Multicast FDB entry : Port %s deleted from (%02x%02x.%02x%02x.%02x%02x) VID %d\n", ifp->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid);
      break;
    case BCM_MCAST_LEAVE_NOTFOUND:
    default:
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "Multicast FDB entry : Port %s (%02x%02x.%02x%02x.%02x%02x) VID %d not found\n", ifp->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid);
      break;
    }

  /* Check if we need to delete the multicast MAC entirely. */
  bcmx_mcast_addr_init (&mcaddr, mac, vid);

  /* Get multicast MAC. */
  ret = bcmx_mcast_port_get (mac, vid, &mcaddr);
  if (ret == BCM_E_NOT_FOUND)
    {
      bcmx_mcast_addr_free (&mcaddr);

      HSL_FN_EXIT (0);
    }

  /* If no ports are remaining, delete MC mac */
  BCMX_LPLIST_ITER(mcaddr.ports, lport, count)
    {
      if (!(BCMX_LPORT_FLAGS(lport) & BCMX_PORT_F_HG))
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "multicast FDB entry : mac (%02x%02x.%02x%02x.%02x%02x) VID %d still installed on lport %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid, lport);
	  bcmx_mcast_addr_free (&mcaddr);
          HSL_FN_EXIT (0); 
        }
    }

  /* Remove. */
  ret = bcmx_mcast_addr_remove (mac, vid);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't delete multicast FDB entry : mac (%02x%02x.%02x%02x.%02x%02x) VID %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid);

      bcmx_mcast_addr_free (&mcaddr);
      HSL_FN_EXIT (-1);
    }

  bcmx_mcast_addr_free (&mcaddr);

  #endif
  HSL_FN_EXIT (0);
}

/* 
   Delete unicast FDB entry. 
*/
static int
_hsl_ctc_delete_l2uc (struct hsl_bridge *b, u_char *mac, int len, hsl_vid_t vid)
{
    int32    ret  = 0;
    ctc_l2_addr_t l2_addr;
	fdb_entry_t entry;



	HSL_FN_ENTER ();
	memset(&l2_addr, 0, sizeof(ctc_l2_addr_t));

	memcpy(l2_addr.mac, mac, len);

	l2_addr.fid = vid;

    ret = ctc_l2_remove_fdb(&l2_addr);
    if (ret < 0)
    {
        HSL_FN_EXIT (-1);
    }

	entry.vid = vid;

	memcpy(entry.mac_addr, mac, 6);

	ret = hsl_delete_fdb_entry(&entry);
	if (ret != 0) {	
		HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Not Deleted [MAC:%x:%x:%x:%x:%x:%x] from FDB\n",
			entry.mac_addr[0], entry.mac_addr[1], entry.mac_addr[2],
			entry.mac_addr[3], entry.mac_addr[4], entry.mac_addr[5]);
		  HSL_FN_EXIT (-1);

	}
	else {
		HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "Deleted [MAC:%x:%x:%x:%x:%x:%x] vid=%d from FDB\n",
			entry.mac_addr[0], entry.mac_addr[1], entry.mac_addr[2],
			entry.mac_addr[3], entry.mac_addr[4], entry.mac_addr[5], entry.vid);

	}
	
  
  HSL_FN_EXIT (0);	
}


/*
  Delete FDB.
*/
int
hsl_ctc_delete_fdb (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid, u_char flags)
{
  int ret;

  HSL_FN_ENTER ();
  //by chentao
#if 1
  if (MACADDR_IS_MULTICAST (mac))
    ret = _hsl_ctc_delete_l2mc (b, ifp, mac, len, vid, flags);
  else
    ret = _hsl_ctc_delete_l2uc (b, mac, len, vid);
#endif
  HSL_FN_EXIT (ret);
}

/*
  Flush FDB by port.
*/
int
hsl_ctc_flush_fdb (struct hsl_bridge *b, struct hsl_if *ifp, hsl_vid_t vid)
{
  struct hsl_bcm_if *bcmifp;
  //bcmx_lport_t lport;
  uint16 lport;
  int ret;
  ctc_l2_flush_fdb_t flush_key;

  memset(&flush_key, 0, sizeof(flush_key));


  
  HSL_FN_ENTER ();
  //by chentao 
#if 1
  /* If no port passed delete by vlan id. */
  if((!ifp) && (vid))
   {
	hsl_flush_entry(-1, vid, NULL, -1, -1);	
	flush_key.fid= vid;
	flush_key.flush_flag = CTC_L2_FDB_ENTRY_ALL;
	flush_key.flush_type = CTC_L2_FDB_ENTRY_OP_BY_VID;
	ctc_l2_flush_fdb(&flush_key);
    HSL_FN_EXIT (0);
   }
  else if(! ifp || ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    HSL_FN_EXIT (0);

  bcmifp = ifp->system_info;
  if (! bcmifp)
    HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);

  lport = bcmifp->u.l2.lport;


  //HSL_LOG (HSL_LOG_FDB, HSL_LEVEL_INFO, "lport = %x, vid = %d, tid = %d\r\n", lport, vid, bcmifp->trunk_id);

  /* If no vlan passed delete by logical port. */
  if ((!vid) && (ifp)){

	hsl_flush_entry(GPORT_TO_IFINDEX(lport), 0, NULL, -1, -1);		
	flush_key.gport = lport;
	flush_key.flush_flag = CTC_L2_FDB_ENTRY_ALL;
	flush_key.flush_type = CTC_L2_FDB_ENTRY_OP_BY_PORT;
	ctc_l2_flush_fdb(&flush_key);
  	}
  /* Delete by logical port & vlan id. */
  else if ((ifp) && (vid)){
	hsl_flush_entry(GPORT_TO_IFINDEX(lport), vid, NULL, -1, -1);	
	flush_key.gport = lport;
	flush_key.fid= vid;
	flush_key.flush_flag = CTC_L2_FDB_ENTRY_ALL;
	flush_key.flush_type = CTC_L2_FDB_ENTRY_OP_BY_PORT_VLAN;
	ctc_l2_flush_fdb(&flush_key);
  	}
  else 
    HSL_FN_EXIT (-1);  
#endif
  HSL_FN_EXIT (0);
}

/* 
   Get unicast FDB
*/
int
hsl_ctc_unicast_get_fdb (struct hal_msg_l2_fdb_entry_req *req,
                         struct hal_msg_l2_fdb_entry_resp *resp)
{
  struct hal_fdb_entry *entry;
  fdb_entry_t result;
  struct hsl_if *ifp;
  u_int32_t count;
  int ret;

  HSL_FN_ENTER ();
#if 1
  entry = &req->start_fdb_entry;
  memcpy (&result.mac_addr[0], &entry->mac_addr[0], ETH_ADDR_LEN);
  result.vid = entry->vid;
  count = 0;

  entry = &resp->fdb_entry[0];
  /* Get entry */
  while (count < req->count &&
         STATUS_OK == hsl_getnext_fdb_entry (&result, SEARCH_BY_VLAN_MAC, &result))
    {
      /* Get interface structure. */
      ifp = hsl_ifmgr_lookup_by_index (result.port_no);
      if(!ifp)
        {
          HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Unknown ifindex %d in l2 fdb database. MAC:%x:%x:%x:%x:%x:%x vid=%d\n",result.port_no,
                 result.mac_addr[0], result.mac_addr[1], result.mac_addr[2],
                 result.mac_addr[3], result.mac_addr[4], result.mac_addr[5], result.vid);
          continue;
        }

      /* We don't need to show mac addresses learned on L3 interfaces. */ 
      if (CHECK_FLAG (ifp->if_flags, HSL_IFMGR_IF_DIRECTLY_MAPPED))
        {
           HSL_IFMGR_IF_REF_DEC (ifp);
           continue;
        }

      HSL_IFMGR_IF_REF_DEC (ifp);

      /* Interface index. */
      entry->port = result.port_no;

      /* Mac address. */
      memcpy (entry->mac_addr, result.mac_addr, ETH_ADDR_LEN);


      /* vid */
      entry->vid = result.vid;

      /* is_fwd */
      entry->is_forward = result.is_fwd;
      entry->is_static = result.is_static;

      /* ageing_timer_value */
      entry->ageing_timer_value = result.ageing_timer_value;

      entry += 1;
      count += 1;
    }

  resp->count = count;
#endif
  HSL_FN_EXIT (ret);
}

/* 
   Flush FDB by mac.
*/
int
hsl_ctc_flush_fdb_by_mac (struct hsl_bridge *b, u_char *mac, int len, int flags)
{
  int ret;
  ctc_l2_flush_fdb_t flush_key;
    memset(&flush_key, 0, sizeof(flush_key));
	memcpy(flush_key.mac, mac, 6);
	flush_key.flush_type = CTC_L2_FDB_ENTRY_OP_BY_MAC;
	
  HSL_FN_ENTER ();
  //by chentao
#if 1
  if (flags == HAL_L2_DELETE_STATIC) {
	hsl_flush_entry(-1, 0, mac, 1, -1);		
	flush_key.flush_flag = CTC_L2_FDB_ENTRY_STATIC;

  }
  else {
	hsl_flush_entry(-1, 0, mac, 0, -1);		
	flush_key.flush_flag = CTC_L2_FDB_ENTRY_DYNAMIC;
  }
  
  ctc_l2_flush_fdb(&flush_key);  
#endif
  HSL_FN_EXIT (ret);
}
#if 0
bcm_filterid_t pbit_fid;

int
hsl_bcm_pbit_copying_init(void)
{
  int ret;
  
  ret = bcmx_filter_create (&pbit_fid);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, 
               "Can't create IGMP Snooping filter\n");
      HSL_FN_EXIT (-1);
    }
  
  bcmx_filter_qualify_format (pbit_fid, BCM_FILTER_PKTFMT_INNER_TAG);
  
  /* Define processing rules */
  bcmx_filter_action_match (pbit_fid, bcmActionInsPrio, 2);
  ret = bcmx_filter_install (pbit_fid);
  
  HSL_FN_EXIT (ret);
}
#endif


 int hsl_storm_ctl_set(bool ifindex_or_vlan, unsigned int ifindex, unsigned int vlan, 
					bool enable, unsigned int type_l, unsigned int mode,unsigned int threshold_num, bool is_discard_to_cpu)
{
	uint16 gport_id = 0;
    uint16 vlan_id = 0;
    uint32 value = 0;
    int32 ret = 0;
    uint8 index = 0;
    ctc_security_storm_ctl_type_t type = 0;
    ctc_security_stmctl_cfg_t  stmctl_cfg;

	//printk("hsl: ifindex_or_vlan=%d, enable=%d, type=%d, mode=%d, threshold_num=%d\n", ifindex_or_vlan, enable, type_l, mode, threshold_num);

    sal_memset(&stmctl_cfg, 0, sizeof(stmctl_cfg));

	if (ifindex_or_vlan == STORM_CTL_IFINDEX) {
		gport_id = IFINDEX_TO_GPORT(ifindex);
		stmctl_cfg.gport = gport_id;
        stmctl_cfg.op = CTC_SECURITY_STORM_CTL_OP_PORT;
	} else if (ifindex_or_vlan == STORM_CTL_VLAN_ID) {
		vlan_id = vlan;
		stmctl_cfg.vlan_id = vlan_id;
        stmctl_cfg.op = CTC_SECURITY_STORM_CTL_OP_VLAN;
	}

	if (enable) {
		stmctl_cfg.storm_en = 1;
	} else {
		stmctl_cfg.storm_en = 0;
	}

	if (mode == STORM_CTL_MODE_PPS) {
		stmctl_cfg.mode = CTC_SECURITY_STORM_CTL_MODE_PPS;
	} else if (mode == STORM_CTL_MODE_BPS) {
		stmctl_cfg.mode = CTC_SECURITY_STORM_CTL_MODE_BPS;
	}

	value = threshold_num;
	stmctl_cfg.threshold = value;

	switch (type_l) {
		case STORM_CTL_TYPE_BROADCAST:
			type = CTC_SECURITY_STORM_CTL_BCAST;
			break;
		case STORM_CTL_TYPE_KNOWN_MULT:
			type = CTC_SECURITY_STORM_CTL_KNOWN_MCAST;
			break;
		case STORM_CTL_TYPE_KNOWN_UNIC:
			type = CTC_SECURITY_STORM_CTL_KNOWN_UCAST;
			break;
		case STORM_CTL_TYPE_ALL_UNIC:
			type = CTC_SECURITY_STORM_CTL_ALL_UCAST;
			break;
		case STORM_CTL_TYPE_ALL_MULT:
			type = CTC_SECURITY_STORM_CTL_ALL_MCAST;
			break;
		case STORM_CTL_TYPE_UNKNOWN_MULT:
			type = CTC_SECURITY_STORM_CTL_UNKNOWN_MCAST;
			break;
		case STORM_CTL_TYPE_UNKNOWN_UNIC:
			type = CTC_SECURITY_STORM_CTL_UNKNOWN_UCAST;
			break;
		default:		
			break;
	}
	stmctl_cfg.type = type;

	if (is_discard_to_cpu) {
		stmctl_cfg.discarded_to_cpu = 1;
	} else {
		stmctl_cfg.discarded_to_cpu = 0;
	}

	ret = ctc_storm_ctl_set_cfg(&stmctl_cfg);

	return ret;
}


/*
  Initialize callbacks and register.
*/
int
hsl_bridge_hw_register (void)
{
  HSL_FN_ENTER ();

  hsl_bcm_l2_cb.bridge_init = hsl_ctc_bridge_init;
  hsl_bcm_l2_cb.bridge_deinit = hsl_ctc_bridge_deinit;
  hsl_bcm_l2_cb.set_age_timer = hsl_ctc_set_age_timer;
  hsl_bcm_l2_cb.set_learning = hsl_ctc_set_learning;
  hsl_bcm_l2_cb.set_if_mac_learning = hsl_ctc_set_if_mac_learning;
  hsl_bcm_l2_cb.set_stp_port_state = hsl_ctc_set_stp_port_state;
  hsl_bcm_l2_cb.add_instance = hsl_ctc_add_instance;
  hsl_bcm_l2_cb.delete_instance = hsl_ctc_delete_instance;
#ifdef HAVE_VLAN
  hsl_bcm_l2_cb.add_vlan_to_instance = hsl_ctc_add_vlan_to_instance;
  hsl_bcm_l2_cb.delete_vlan_from_instance = hsl_ctc_delete_vlan_from_instance;
  hsl_bcm_l2_cb.add_vlan = hsl_ctc_add_vlan;
  hsl_bcm_l2_cb.delete_vlan = hsl_ctc_delete_vlan;
  hsl_bcm_l2_cb.set_vlan_port_type = hsl_ctc_set_vlan_port_type;
  hsl_bcm_l2_cb.set_default_pvid = hsl_ctc_set_default_pvid;
  hsl_bcm_l2_cb.add_vlan_to_port = hsl_ctc_add_vlan_to_port;
  hsl_bcm_l2_cb.delete_vlan_from_port = hsl_ctc_delete_vlan_from_port;
#ifdef HAVE_VLAN_CLASS
  hsl_bcm_l2_cb.vlan_mac_classifier_add     = hsl_bcm_vlan_mac_classifier_add;
  hsl_bcm_l2_cb.vlan_ipv4_classifier_add    = hsl_bcm_vlan_ipv4_classifier_add;
  hsl_bcm_l2_cb.vlan_mac_classifier_delete  = hsl_bcm_vlan_mac_classifier_delete;
  hsl_bcm_l2_cb.vlan_ipv4_classifier_delete = hsl_bcm_vlan_ipv4_classifier_delete;
  hsl_bcm_l2_cb.vlan_proto_classifier_add   = hsl_bcm_vlan_proto_classifier_add;
  hsl_bcm_l2_cb.vlan_proto_classifier_delete= hsl_bcm_vlan_proto_classifier_delete;
#endif /* HAVE_VLAN_CLASS */
#ifdef HAVE_PVLAN
  hsl_bcm_l2_cb.set_pvlan_vlan_type = hsl_bcm_pvlan_set_vlan_type;
  hsl_bcm_l2_cb.add_pvlan_vlan_association = hsl_bcm_pvlan_add_vlan_association;
  hsl_bcm_l2_cb.del_pvlan_vlan_association = hsl_bcm_pvlan_del_vlan_association;
  hsl_bcm_l2_cb.add_pvlan_port_association = hsl_bcm_pvlan_add_port_association;
  hsl_bcm_l2_cb.del_pvlan_port_association = hsl_bcm_pvlan_del_port_association;
  hsl_bcm_l2_cb.set_pvlan_port_mode = hsl_bcm_pvlan_set_port_mode;
#endif /* HAVE_PVLAN */
#endif /* HAVE_VLAN */

  /* Register L2 fdb manager. */
  hsl_fdb_hw_cb_register ();

#if 0
#ifdef HAVE_IGMP_SNOOP
  hsl_bcm_l2_cb.enable_igmp_snooping = hsl_bcm_enable_igmp_snooping;
  hsl_bcm_l2_cb.disable_igmp_snooping = hsl_bcm_disable_igmp_snooping;
  hsl_bcm_l2_cb.enable_igmp_snooping_port = hsl_bcm_enable_igmp_snooping_port;
  hsl_bcm_l2_cb.disable_igmp_snooping_port = hsl_bcm_disable_igmp_snooping_port;
#endif /* HAVE_IGMP_SNOOP */
#else
  hsl_bcm_l2_cb.enable_igmp_snooping = NULL;
  hsl_bcm_l2_cb.disable_igmp_snooping = NULL;
  hsl_bcm_l2_cb.enable_igmp_snooping_port = NULL;
  hsl_bcm_l2_cb.disable_igmp_snooping_port = NULL;
 #endif


#ifdef HAVE_MLD_SNOOP
  hsl_bcm_l2_cb.enable_mld_snooping = hsl_bcm_enable_mld_snooping;
  hsl_bcm_l2_cb.disable_mld_snooping = hsl_bcm_disable_mld_snooping;
#endif /* HAVE_MLD_SNOOP */

  hsl_bcm_l2_cb.ratelimit_bcast = hsl_ctc_ratelimit_bcast;
  hsl_bcm_l2_cb.ratelimit_mcast = hsl_ctc_ratelimit_mcast;
  hsl_bcm_l2_cb.ratelimit_dlf_bcast = hsl_ctc_ratelimit_dlf_bcast;
  hsl_bcm_l2_cb.ratelimit_bcast_discards_get = hsl_ctc_ratelimit_get_bcast_discards;
  hsl_bcm_l2_cb.ratelimit_mcast_discards_get = hsl_ctc_ratelimit_get_mcast_discards;
  hsl_bcm_l2_cb.ratelimit_dlf_bcast_discards_get = hsl_ctc_ratelimit_get_dlf_bcast_discards;
  hsl_bcm_l2_cb.set_flowcontrol = hsl_ctc_set_flowcontrol;
  hsl_bcm_l2_cb.get_flowcontrol_statistics = hsl_ctc_flowcontrol_statistics;
  hsl_bcm_l2_cb.add_fdb = hsl_ctc_add_fdb;
  hsl_bcm_l2_cb.delete_fdb = hsl_ctc_delete_fdb;
  hsl_bcm_l2_cb.get_uni_fdb = hsl_ctc_unicast_get_fdb;
  hsl_bcm_l2_cb.flush_port_fdb = hsl_ctc_flush_fdb;
  hsl_bcm_l2_cb.flush_fdb_by_mac = hsl_ctc_flush_fdb_by_mac;

  /*storm ctl*/
  hsl_bcm_l2_cb.storm_ctl_set = hsl_storm_ctl_set;
  /* Register with bridge manager. */
  hsl_bridge_hw_cb_register (&hsl_bcm_l2_cb);

  HSL_FN_EXIT (0);
}

