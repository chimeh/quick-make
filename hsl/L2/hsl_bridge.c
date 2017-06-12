/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"
#include "hsl.h"

#ifdef HAVE_L2
#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"

#include "hsl_avl.h"
#include "hsl_oss.h"
#include "hsl_error.h"

#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_vlan.h"
#include "hsl_bridge.h"
#include "hsl_mac_tbl.h"

struct hsl_bridge_master *p_hsl_bridge_master = NULL;

/*
  Forward declarations. 
*/
int hsl_bridge_hw_register(void);

/*
  VLAN compare.
*/
static int
_hsl_bridge_vlan_cmp (void *param1, void *param2)
{
  struct hsl_vlan_port *p1 = (struct hsl_vlan_port *) param1;
  struct hsl_vlan_port *p2 = (struct hsl_vlan_port *) param2;

  /* Less than. */
  if (p1->vid < p2->vid)
    return -1;

  /* Greater than. */
  if (p1->vid > p2->vid)
    return 1;

  /* Equals to. */
  return 0;
}

/*
  Port compare routine.
*/
int
_hsl_bridge_port_cmp (void *param1, void *param2)
{
  /* The port is of type hsl_if. Just compare the pointers as integers. */
  unsigned int p1 = (unsigned int)((long)param1);
  unsigned int p2 = (unsigned int)((long)param2);

  /* Less than. */
  if (p1 < p2)
    return -1;

  /* Greater than. */
  if (p1 > p2)
    return 1;

  /* Equals to. */
  return 0;
}

/*
  Init bridge.
*/
struct hsl_bridge *
hsl_bridge_init ()
{
  struct hsl_bridge *b = NULL;
  int ret;

  HSL_FN_ENTER ();

  b = oss_malloc (sizeof (struct hsl_bridge), OSS_MEM_HEAP);
  if (! b)
    HSL_FN_EXIT (b);

#ifdef HAVE_VLAN
  /* Create vlan tree. */
  ret = hsl_avl_create (&b->vlan_tree, 0, _hsl_bridge_vlan_cmp);
  if (ret < 0)
    goto ERR;
#endif /* HAVE_VLAN. */

  /* Create tree of ports. */
  ret = hsl_avl_create (&b->port_tree, 0, _hsl_bridge_port_cmp);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT (b);

 ERR:
  if (b && b->port_tree)
    hsl_avl_tree_free (&b->port_tree, NULL);

#ifdef HAVE_VLAN
  if (b && b->vlan_tree)
    hsl_avl_tree_free (&b->vlan_tree, hsl_free);
#endif /* HAVE_VLAN */

  if (b)
    oss_free (b, OSS_MEM_HEAP);

  HSL_FN_EXIT (NULL);
}

/* 
   Deinit bridge.
*/
int
hsl_bridge_deinit (struct hsl_bridge *b)
{
#ifdef HAVE_VLAN
  struct hsl_vlan_port *vlan;
  struct hsl_avl_node *node;
#endif /* HAVE_VLAN. */

  HSL_FN_ENTER ();

  if (! b)
    HSL_FN_EXIT (0);
   
#ifdef HAVE_VLAN
  for (node = hsl_avl_top (b->vlan_tree); node; node = hsl_avl_next (node))
    {
      vlan = HSL_AVL_NODE_INFO (node);
      
      /* Deinit vlan. */
      hsl_vlan_port_map_deinit (vlan);    
    }
  /* Free vlans tree. */
  hsl_avl_tree_free (&b->vlan_tree, NULL);

  /* Free ports tree. */
  hsl_avl_tree_free (&b->port_tree, NULL);
#endif /* HAVE_VLAN. */  

  HSL_FN_EXIT (0);
}

/*
  Initialize bridge port.
*/
struct hsl_bridge_port *
hsl_bridge_port_init (void)
{
  return oss_malloc (sizeof (struct hsl_bridge_port), OSS_MEM_HEAP);
}

/*
  Deinit bridge port.
*/
int
hsl_bridge_port_deinit (struct hsl_bridge_port *port)
{
  if (port)
    {
#ifdef HAVE_VLAN
      if (port->vlan)
	{
	  hsl_port_vlan_map_deinit (port->vlan);
          port->vlan = NULL;
	}
     
#endif /* HAVE_VLAN. */
      oss_free (port, OSS_MEM_HEAP);
    }
  return 0;
}

/*
  Init master. 
*/
int
hsl_bridge_master_init (void)
{
  int ret;
  int rv;
  char *msg;

  HSL_FN_ENTER ();

  if (! p_hsl_bridge_master)
    {
      p_hsl_bridge_master = oss_malloc (sizeof (struct hsl_bridge_master), OSS_MEM_HEAP);
      if (! p_hsl_bridge_master)
	return HSL_ERR_BRIDGE_NOMEM;

      /* Create mutex. */
      ret = oss_sem_new ("Bridge mutex", OSS_SEM_MUTEX, 0, NULL, &p_hsl_bridge_master->mutex);
      if (ret < 0)
	{
	  oss_free (p_hsl_bridge_master, OSS_MEM_HEAP);

	  HSL_FN_EXIT (HSL_ERR_BRIDGE_NOMEM);
	}

      /* Call HW to set callbacks.  */
      SYSTEM_INIT_CHECK(hsl_bridge_hw_register(), "bridge hw register");
    }

  HSL_FN_EXIT (0);
}

/* 
   Deinit master.
*/
int
hsl_bridge_master_deinit (void)
{
  HSL_FN_ENTER ();

  if (p_hsl_bridge_master)
    {
      /* Deinit bridge. */
      if (p_hsl_bridge_master->bridge)
        {
	  hsl_bridge_deinit (p_hsl_bridge_master->bridge);
          oss_free (p_hsl_bridge_master->bridge, OSS_MEM_HEAP);
          p_hsl_bridge_master->bridge = NULL;
        }

      /* Delete mutex. */
      oss_sem_delete (OSS_SEM_MUTEX, p_hsl_bridge_master->mutex);
      
      oss_free (p_hsl_bridge_master, OSS_MEM_HEAP);

      p_hsl_bridge_master = NULL;
    }

  HSL_FN_EXIT (0);
}

/*
  Bridge add.
*/
int
hsl_bridge_add (char *name, int is_vlan_aware)
{
  struct hsl_bridge *b;

  HSL_FN_ENTER ();
  HSL_BRIDGE_LOCK;

  if (p_hsl_bridge_master->bridge)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_EEXISTS);
    }

  b = hsl_bridge_init ();
  if (! b)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_NOMEM);
    }
  
  if (is_vlan_aware)
    SET_FLAG (b->flags, HSL_BRIDGE_VLAN_AWARE);
  SET_FLAG (b->flags, HSL_BRIDGE_LEARNING);

  memcpy (b->name, name, HAL_BRIDGE_NAME_LEN + 1);
  p_hsl_bridge_master->bridge = b;

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->bridge_init)
    (*p_hsl_bridge_master->hw_cb->bridge_init) (b);
  
  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Bridge delete.
*/
int
hsl_bridge_delete (char *name)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  
  if (p_hsl_bridge_master->bridge)
    {
      if (memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
	{
	  HSL_BRIDGE_UNLOCK;
	  HSL_FN_EXIT (HSL_ERR_BRIDGE_NOTFOUND);
	}

      hsl_bridge_deinit (p_hsl_bridge_master->bridge);

      if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->bridge_deinit)
	(*p_hsl_bridge_master->hw_cb->bridge_deinit) (p_hsl_bridge_master->bridge);
           
      oss_free (p_hsl_bridge_master->bridge, OSS_MEM_HEAP);
      p_hsl_bridge_master->bridge = NULL;
    }

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Add port to a bridge.
*/
int
hsl_bridge_add_port (char *name, hsl_ifIndex_t ifindex)
{
  struct hsl_if *ifp;
  struct hsl_bridge_port *port;

  HSL_FN_ENTER ();
  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge || memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (ifp->u.l2_ethernet.port)
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_PORT_EXISTS);
    }

  port = hsl_bridge_port_init ();
  if (! port)
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_NOMEM);
    }

  ifp->u.l2_ethernet.port = port;
  port->ifp = ifp;

  port->bridge = p_hsl_bridge_master->bridge;

  /* Add port to the bridge. */
  hsl_avl_insert (p_hsl_bridge_master->bridge->port_tree, ifp);

  /* Set acceptable packet types for this interface. */
  hsl_ifmgr_set_acceptable_packet_types (ifp, HSL_IF_PKT_L2); 

#ifdef HAVE_IGMP_SNOOP
  /* Enable IGMP snooping on port */
  if (p_hsl_bridge_master->hw_cb
      && p_hsl_bridge_master->hw_cb->enable_igmp_snooping_port)
      (*p_hsl_bridge_master->hw_cb->enable_igmp_snooping_port)
         (p_hsl_bridge_master->bridge, ifp);
#endif /* HAVE_IGMP_SNOOP */

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}
/* 
   Flush port fdb 
 */ 
int 
hsl_bridge_delete_port_vlan_fdb(struct hsl_if *ifp, hsl_vid_t vid)
{
  int ret = 0;
#ifdef HAVE_L3
  //by chentao delete
 // struct hsl_if *ifp2;
//  struct hsl_if_list *node;
#endif /* HAVE_L3 */
  HSL_FN_ENTER();

#if 0
  /* 
     We don't flush fdb becase arps might be hanging 
     on top of some fdb entries 
  */
  if ((ifp) && (ifp->parent_list))
  {
    node = ifp->parent_list;
    while (node)
    {
      ifp2 = node->ifp;
      if (ifp2->type == HSL_IF_TYPE_IP)
      {
        if(ifp2->u.ip.ipv4.ucAddr) 
          HSL_FN_EXIT(0);
#ifdef HAVE_IPV6                   
        if(ifp2->u.ip.ipv6.ucAddr)
          HSL_FN_EXIT(0);
#endif /* HAVE_IPV6 */
      }
      node = node->next;
    }
  }
#endif /* HAVE_L3 */

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->flush_port_fdb)
    ret = (*p_hsl_bridge_master->hw_cb->flush_port_fdb) (p_hsl_bridge_master->bridge, ifp, vid);
  
  HSL_FN_EXIT(ret);
}

/*
  Delete port to a bridge.
*/
int
hsl_bridge_delete_port (char *name, hsl_ifIndex_t ifindex)
{
  struct hsl_if *ifp;
  struct hsl_bridge_port *port;

  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (! ifp->u.l2_ethernet.port)
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_PORT_NOT_EXISTS);
    }

#ifdef HAVE_IGMP_SNOOP
  /* Disable IGMP snooping on port */
  if (p_hsl_bridge_master->hw_cb
      && p_hsl_bridge_master->hw_cb->disable_igmp_snooping_port)
      (*p_hsl_bridge_master->hw_cb->disable_igmp_snooping_port)
         (p_hsl_bridge_master->bridge, ifp);
#endif /* HAVE_IGMP_SNOOP */

  /* Don't accept any L2 packets from this port. */
  hsl_ifmgr_unset_acceptable_packet_types (ifp, HSL_IF_PKT_L2); 

  /* Port could still want authd and lacpd packets. */
  hsl_ifmgr_set_acceptable_packet_types (ifp, 
                                         HSL_IF_PKT_EAPOL | HSL_IF_PKT_LACP); 
  /* Flush mac addresses learned from deleted port. */
  hsl_bridge_delete_port_vlan_fdb(ifp, 0);

  /* Delete interface from bridge port tree. */
  hsl_avl_delete (p_hsl_bridge_master->bridge->port_tree, ifp);

  /* Deinitialize port vlan map. */
  port = ifp->u.l2_ethernet.port;

#ifdef HAVE_VLAN
  hsl_port_vlan_map_deinit (port->vlan);
  port->vlan = NULL;
#endif /* HAVE_VLAN */

  /* Deinitialize bridge port. */
  hsl_bridge_port_deinit (port);
  ifp->u.l2_ethernet.port = NULL;

  HSL_IFMGR_IF_REF_DEC (ifp);
  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Set L2 age timer in seconds.
*/
int
hsl_bridge_age_timer_set (char *name, int age_seconds)
{
  int ret = 0;

  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->set_age_timer)
    ret = (*p_hsl_bridge_master->hw_cb->set_age_timer) (p_hsl_bridge_master->bridge, age_seconds);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (ret);
}


/*
  Set L2 learning for a bridge.
*/
int
hsl_bridge_learning_set (char *name, int learn)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->set_learning)
    (*p_hsl_bridge_master->hw_cb->set_learning) (p_hsl_bridge_master->bridge, learn);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

int
hsl_if_mac_learning_set (hsl_ifIndex_t ifindex, int disable)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->set_if_mac_learning)
    (*p_hsl_bridge_master->hw_cb->set_if_mac_learning) (ifp, disable);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}


/*
  Set port state.
*/
int
hsl_bridge_set_stp_port_state (char *name, hsl_ifIndex_t ifindex, int instance, int state)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (! ifp->u.l2_ethernet.port)
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_PORT_NOT_EXISTS);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->set_stp_port_state)
    (*p_hsl_bridge_master->hw_cb->set_stp_port_state) (p_hsl_bridge_master->bridge, ifp->u.l2_ethernet.port, instance, state);

  HSL_IFMGR_IF_REF_DEC (ifp);
  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Add instance to a bridge.
*/
int
hsl_bridge_add_instance (char *name, int instance)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->add_instance)
    (*p_hsl_bridge_master->hw_cb->add_instance) (p_hsl_bridge_master->bridge, instance);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Delete instance.
*/
int
hsl_bridge_delete_instance (char *name, int instance)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->delete_instance)
    (*p_hsl_bridge_master->hw_cb->delete_instance) (p_hsl_bridge_master->bridge, instance);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Add VLAN to instance.
*/
int
hsl_bridge_add_vlan_to_inst (char *name, int instance, hsl_vid_t vid)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

#ifdef HAVE_VLAN
  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->add_vlan_to_instance)
    (*p_hsl_bridge_master->hw_cb->add_vlan_to_instance) (p_hsl_bridge_master->bridge, instance, vid);
#endif /* HAVE_VLAN */

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Delete VLAN to instance.
*/
int
hsl_bridge_delete_vlan_from_inst (char *name, int instance, hsl_vid_t vid)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

#ifdef HAVE_VLAN
  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->delete_vlan_from_instance)
    (*p_hsl_bridge_master->hw_cb->delete_vlan_from_instance) (p_hsl_bridge_master->bridge, instance, vid);
#endif /* HAVE_VLAN */

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Initialize IGMP Snooping.
*/
int
hsl_bridge_enable_igmp_snooping (char *name)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->enable_igmp_snooping)
    (*p_hsl_bridge_master->hw_cb->enable_igmp_snooping) (p_hsl_bridge_master->bridge);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Disable IGMP Snooping.
*/
int
hsl_bridge_disable_igmp_snooping (char *name)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->disable_igmp_snooping)
    (*p_hsl_bridge_master->hw_cb->disable_igmp_snooping) (p_hsl_bridge_master->bridge);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Initialize MLD Snooping.
*/
int
hsl_bridge_enable_mld_snooping (char *name)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->enable_mld_snooping)
    (*p_hsl_bridge_master->hw_cb->enable_mld_snooping) (p_hsl_bridge_master->bridge);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Disable MLD Snooping.
*/
int
hsl_bridge_disable_mld_snooping (char *name)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      return HSL_ERR_BRIDGE_INVALID_PARAM;
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->disable_mld_snooping)
    (*p_hsl_bridge_master->hw_cb->disable_mld_snooping) (p_hsl_bridge_master->bridge);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (0);
}

/*
  Rate limiting for broadcast. 
*/
int
hsl_bridge_ratelimit_bcast (hsl_ifIndex_t ifindex, int level,
                            int fraction)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->ratelimit_bcast)
    (*p_hsl_bridge_master->hw_cb->ratelimit_bcast) (ifp, level, fraction);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}

/*
  Get broadcast discards.
*/
int
hsl_bridge_ratelimit_get_bcast_discards (hsl_ifIndex_t ifindex, int *discards)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->ratelimit_bcast_discards_get)
    (*p_hsl_bridge_master->hw_cb->ratelimit_bcast_discards_get) (ifp, discards);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}

/*
  Rate limiting for multicast. 
*/
int
hsl_bridge_ratelimit_mcast (hsl_ifIndex_t ifindex, int level,
                            int fraction)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->ratelimit_mcast)
    (*p_hsl_bridge_master->hw_cb->ratelimit_mcast) (ifp, level, fraction);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}

/*
  Get multicast discards.
*/
int
hsl_bridge_ratelimit_get_mcast_discards (hsl_ifIndex_t ifindex, int *discards)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->ratelimit_mcast_discards_get)
    (*p_hsl_bridge_master->hw_cb->ratelimit_mcast_discards_get) (ifp, discards);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}

/*
  Rate limiting for dlf broadcast. 
*/
int
hsl_bridge_ratelimit_dlf_bcast (hsl_ifIndex_t ifindex, int level,
                                int fraction)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->ratelimit_dlf_bcast)
    (*p_hsl_bridge_master->hw_cb->ratelimit_dlf_bcast) (ifp, level, fraction);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}

/*
  Get dlf broadcast discards.
*/
int
hsl_bridge_ratelimit_get_dlf_bcast_discards (hsl_ifIndex_t ifindex, int *discards)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->ratelimit_dlf_bcast_discards_get)
    (*p_hsl_bridge_master->hw_cb->ratelimit_dlf_bcast_discards_get) (ifp, discards);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}


int hsl_bridge_storm_ctl(bool ifindex_or_vlan, unsigned int ifindex, unsigned int vlan, 
					bool enable, unsigned int type, unsigned int mode,unsigned int threshold_num, bool is_discard_to_cpu)
{
	int ret = 0;
	HSL_FN_ENTER ();
	 if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->storm_ctl_set) {
         ret = (*p_hsl_bridge_master->hw_cb->storm_ctl_set) (ifindex_or_vlan, ifindex, vlan, enable, type, mode, threshold_num, is_discard_to_cpu);
	 }
	HSL_FN_ENTER (ret);
}

/*
  Initialize flow control.
*/
int
hsl_bridge_init_flowcontrol (void)
{
  return 0;
}

/*
  Deinitialize flow control.
*/
int
hsl_bridge_deinit_flowcontrol (void)
{
  return 0;
}

/*
  Set flowcontrol direction.
*/
int
hsl_bridge_set_flowcontrol (hsl_ifIndex_t ifindex, u_char direction)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->set_flowcontrol)
    (*p_hsl_bridge_master->hw_cb->set_flowcontrol) (ifp, direction);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}

/*
  Get flowcontrol staticsics.
*/
int
hsl_bridge_flowcontrol_statistics (hsl_ifIndex_t ifindex, u_char *direction,
				   int *rxpause, int *txpause)
{
  struct hsl_if *ifp;

  HSL_FN_ENTER ();

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->get_flowcontrol_statistics)
    (*p_hsl_bridge_master->hw_cb->get_flowcontrol_statistics) (ifp, direction, rxpause, txpause);

  HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_FN_EXIT (0);
}
/*
  Add FDB entry.
*/
int
hsl_bridge_add_fdb (char *name, hsl_ifIndex_t ifindex, char *mac, int len, hsl_vid_t vid, 
		    u_char flags, int is_forward)
{
  struct hsl_if *ifp;
  int ret = 0;

  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->add_fdb)
    ret = (*p_hsl_bridge_master->hw_cb->add_fdb) (p_hsl_bridge_master->bridge, ifp, (u_char *)mac, len, vid, flags, is_forward);

  HSL_IFMGR_IF_REF_DEC (ifp);
  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (ret);
}

/* 
   Delete FDB entry.
*/
int
hsl_bridge_delete_fdb (char *name, hsl_ifIndex_t ifindex, char *mac, int len, hsl_vid_t vid,
		       u_char flags)
{
  struct hsl_if *ifp;
  int ret = 0;

  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->delete_fdb)
    ret = (*p_hsl_bridge_master->hw_cb->delete_fdb) (p_hsl_bridge_master->bridge, ifp, (u_char *)mac, len, vid, flags);

  HSL_IFMGR_IF_REF_DEC (ifp);
  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (ret);
}

/*
  Get Unicast FDB entry.
*/
int
hsl_bridge_unicast_get_fdb (struct hal_msg_l2_fdb_entry_req *req,
                            struct hal_msg_l2_fdb_entry_resp *resp)
                           
{
  int ret = 0;

  HSL_FN_ENTER ();

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->get_uni_fdb)
    ret = (*p_hsl_bridge_master->hw_cb->get_uni_fdb)(req, resp);

  HSL_FN_EXIT (ret);
}


/* TBD */
/*
  Get Multicast FDB entry.
*/
int
hsl_bridge_multicast_get_fdb (struct hal_msg_l2_fdb_entry_req *req,
                              struct hal_msg_l2_fdb_entry_resp *resp)
{
  return 0;
}

/* 
   Flush FDB for port.
*/
int
hsl_bridge_flush_fdb (char *name, hsl_ifIndex_t ifindex,  hsl_vid_t vid)
{
  struct hsl_if *ifp;
  int ret = 0;

  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge || memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  ifp = hsl_ifmgr_lookup_by_index (ifindex);

  ret = hsl_bridge_delete_port_vlan_fdb(ifp, vid);

  if(ifp)
    HSL_IFMGR_IF_REF_DEC (ifp);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (ret);
}

/* 
   Flush FDB for mac.
*/
int
hsl_bridge_flush_fdb_by_mac (char *name, char *mac, int len, int flags)
{
  int ret = 0;

  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (! p_hsl_bridge_master->bridge && memcmp (p_hsl_bridge_master->bridge->name, name, HAL_BRIDGE_NAME_LEN))
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_INVALID_PARAM);
    }

  if (p_hsl_bridge_master->hw_cb && p_hsl_bridge_master->hw_cb->flush_fdb_by_mac)
    ret = (*p_hsl_bridge_master->hw_cb->flush_fdb_by_mac) (p_hsl_bridge_master->bridge, (u_char *)mac, len, flags);

  HSL_BRIDGE_UNLOCK;

  HSL_FN_EXIT (ret);
}

/* 
   Register hardware callbacks.
*/
int
hsl_bridge_hw_cb_register (struct hsl_l2_hw_callbacks *cb)
{
  HSL_FN_ENTER ();

  HSL_BRIDGE_LOCK;
  if (p_hsl_bridge_master->hw_cb)
    {
      HSL_BRIDGE_UNLOCK;
      HSL_FN_EXIT (HSL_ERR_BRIDGE_HWCB_ALREADY_REGISTERED);
    }
  p_hsl_bridge_master->hw_cb = cb;
  HSL_BRIDGE_UNLOCK;
  HSL_FN_EXIT (0);
}

#endif /* HAVE_L2 */

