/* Copyright (C) 2004-2005 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

/* 
   Broadcom includes. 
*/
#include "bcm_incl.h"
/* 
   HAL includes.
*/
#include "hal_types.h"
#include "hal_msg.h"

#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_avl.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_bcm_if.h"
#include "hsl_bcm_ifmap.h"
#include "hsl_bcm_resv_vlan.h"
#include "hsl_table.h"
#include "hsl_ether.h"
#ifdef HAVE_LACPD
#include "hsl_bcm_lacp.h"
#endif /* HAVE_LACPD */
#ifdef HAVE_L3
#include "hsl_fib.h"
#endif /* HAVE_L3 */
#include "hsl_bcm.h"

/* 
    Exported from Broadcom sdk (not in header)
*/
extern int
bcmx_l3_route_delete_by_interface(bcmx_l3_route_t *info);

extern int hsl_bcmx_l3_host_delete(bcmx_l3_host_t *host);
extern int hsl_bcmx_l3_host_add(bcmx_l3_host_t *host, void *sys_info);
/*  
    Externs. 
*/
int hsl_bcm_prefix_exception (struct hsl_route_node *rnp);

#ifdef HAVE_MPLS
extern struct hsl_bcm_resv_vlan *bcm_mpls_vlan;
#endif /* HAVE_MPLS */

/*
  Hardware callbacks.
*/
struct hsl_ifmgr_hw_callbacks hsl_bcm_if_callbacks;
#define BCMIF_CB(cb)          hsl_bcm_if_callbacks.cb

/* 
   Alloc interface. 
*/
struct hsl_bcm_if *
hsl_bcm_if_alloc ()
{
  struct hsl_bcm_if *ifp;

  ifp = (struct hsl_bcm_if *)oss_malloc (sizeof (struct hsl_bcm_if), OSS_MEM_HEAP);
  if (ifp)
    {
      memset (ifp, 0, sizeof (struct hsl_bcm_if));

      ifp->u.l2.lport = -1; //BCMX_LPORT_INVALID;
      ifp->trunk_id = -1;   //BCM_TRUNK_INVALID;
      return ifp;
    }
  else
    return NULL;
}

/* 
   Free interface. 
*/
void
hsl_bcm_if_free (struct hsl_bcm_if *ifp)
{
  oss_free (ifp, OSS_MEM_HEAP);
}

/*
  Dump hardware interface data.
*/
void
hsl_bcm_if_dump (struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;

  if (! ifp)
    return;

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", ifp->name, ifp->ifindex);
      return;
    }

  switch (ifp->type)
    {
    case HSL_IF_TYPE_L2_ETHERNET:
      {
	if (bcmifp->trunk_id  >= 0)
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_INFO, "  Trunk ID : %d\n", bcmifp->trunk_id);
	HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_INFO, "   Lport: %d\n", bcmifp->u.l2.lport);
      }
      break;
    case HSL_IF_TYPE_IP:
      {

      }
      break;
    default:
      break;
    }
}

/* 
   Set L2 port flags. 

   Parameters:
   IN -> ifp - interface pointer
   IN -> flags - flags

   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_l2_flags_set (struct hsl_if *ifp, unsigned long flags)
{
  struct hsl_bcm_if *bcmifp;
  bcmx_lport_t lport;

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    return -1;

  lport = BCMIFP_L2(bcmifp).lport;

  if (flags & IFF_UP)
    bcmx_port_enable_set (lport, 1);
  else
    bcmx_port_enable_set (lport, 0);

  HSL_FN_EXIT (0);
}

/* 
   Unset L2 port flags. 

   Parameters:
   IN -> ifp - interface pointer
   IN -> flags - flags

   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_l2_flags_unset (struct hsl_if *ifp, unsigned long flags)
{
  struct hsl_bcm_if *bcmifp;
  bcmx_lport_t lport;

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    return -1;

  lport = BCMIFP_L2(bcmifp).lport;

  /* Delete all addresses learn't from this port. */
  bcmx_l2_addr_delete_by_port (lport, 0);

  if (flags & IFF_UP)
    bcmx_port_enable_set (lport, 0);
  else
    bcmx_port_enable_set (lport, 1);

  HSL_FN_EXIT (0);
}

/*
  Unregister L2 port.
*/
int
hsl_bcm_if_l2_unregister (struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;
  int ret;

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    HSL_FN_EXIT (-1);

  if (ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    {
      /* Wrong type. */
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Wrong interface type specified %s %d for L2 port unregistration\n", ifp->name, ifp->ifindex);
      HSL_FN_EXIT (-1);
    }

  /* Check for trunk. */
  if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
    {
      if (bcmifp->trunk_id >= 0)
	{
	  ret = bcmx_trunk_destroy (bcmifp->trunk_id);
	  if (ret < 0)
	    {
 	      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Error destroying trunk %s %d from hardware\n", ifp->name, ifp->ifindex); 
	    }
	}
    }
  else
    {
      /* Unregister this lport from ifmap. */
      hsl_bcm_ifmap_lport_unregister (BCMIFP_L2(bcmifp).lport);
    }

  /* Free HW ifp. */
  hsl_bcm_if_free (bcmifp);
  ifp->system_info = NULL;

  HSL_FN_EXIT (0);
}

/* Function to add port to a VLAN. 

   Parameters:
   IN -> vid - VLAN id
   IN -> lport - logical port
   IN -> egress - whether egress is tagged or untagged
   
   Returns:
   0 on success
   < 0 on error
*/
int
hsl_bcm_add_port_to_vlan (hsl_vid_t vid, bcmx_lport_t lport, 
			  int egress)
{
  bcmx_lplist_t t, u;
  int ret;

  HSL_FN_ENTER ();

  if (bcmx_lplist_init (&t, 1, 0) < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Out of memory\n");
      HSL_FN_EXIT (-1);
    }

  if (bcmx_lplist_init (&u, 1, 0) < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Out of memory\n");
      bcmx_lplist_free (&t);
      HSL_FN_EXIT (-1);
    }

  bcmx_lplist_add (&t, lport);
  
  /* Egress tagged. */
  if (! egress)
    bcmx_lplist_add (&u, lport);
  
  /* Add port to VLAN. */
  ret = bcmx_vlan_port_add (vid, t, u);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't add VLAN %d to port %d\n", vid, lport);
      bcmx_lplist_free (&t);
      bcmx_lplist_free (&u);
      HSL_FN_EXIT (-1);
    }

  bcmx_lplist_free (&t);
  bcmx_lplist_free (&u);

  HSL_FN_EXIT (0);
}

/* Function to delete port from a VLAN. 

   Parameters:
   IN -> vid - VLAN id
   IN -> lport - logical port

   Returns:
   0 on success
   < 0 on error
*/
int
hsl_bcm_remove_port_from_vlan (hsl_vid_t vid, bcmx_lport_t lport)
			     
{
  bcmx_lplist_t t;
  int ret;

  HSL_FN_ENTER ();

  if (bcmx_lplist_init (&t, 1, 0) < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Out of memory\n");
      HSL_FN_ENTER (-1);
    }

  /* Set port. */
  bcmx_lplist_add (&t, lport);

  /* Remove port from VLAN. */
  ret = bcmx_vlan_port_remove (vid, t);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't add VLAN %d to port %d\n", vid, lport);
      bcmx_lplist_free (&t);
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

/* Perform any post configuration. This can typically be done
   after some interface binding is performed.
   
   Parameters:
   IN -> ifp - interface pointer
   IN -> ifp - interface pointer
   
   Returns:
   0 on success
   < 0 on error
*/
int 
hsl_bcm_if_post_configure (struct hsl_if *ifpp, struct hsl_if *ifpc)
{
  int ret = 0;
  struct hsl_bcm_if *bcmifpp, *bcmifpc;

  HSL_FN_ENTER ();

  /* Perform post configuration pure L3 ports(non-aggregated or non-SVI) */
  if (ifpp->type == HSL_IF_TYPE_IP && ifpc->type == HSL_IF_TYPE_L2_ETHERNET &&
      memcmp (ifpp->name, "vlan", 4))
    {
      /* Add the reserved VID assigned for the L3 port as the default port VID
	 on the port. */
      bcmifpp = (struct hsl_bcm_if *)ifpp->system_info;
      bcmifpc = (struct hsl_bcm_if *)ifpc->system_info;

      if (!bcmifpp || !bcmifpc)
	{
	  ret = -1;
	  HSL_FN_EXIT (ret);
	}

      /* Add port to VLAN. */      
      ret = hsl_bcm_add_port_to_vlan (bcmifpp->u.l3.vid, bcmifpc->u.l2.lport, 0);
      if (ret < 0)
        {
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't add port %d to vlan %d\n", bcmifpc->u.l2.lport, bcmifpp->u.l3.vid);
	  HSL_FN_EXIT (ret);   
        }

      /* Set PVID. */
      ret = bcmx_port_untagged_vlan_set (bcmifpc->u.l2.lport, bcmifpp->u.l3.vid);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Could not set default PVID for port %s\n", ifpp->name);

          /* Delete port from vlan. */
          hsl_bcm_remove_port_from_vlan (bcmifpp->u.l3.vid, bcmifpc->u.l2.lport);
   
	  HSL_FN_EXIT (ret);   
	}

       /* Delete port from default VID. */
       hsl_bcm_remove_port_from_vlan (HSL_DEFAULT_VID, bcmifpc->u.l2.lport);
    }

  HSL_FN_EXIT (ret);
}

/* Perform any pre unconfiguration. This can typically be done
   before some interface unbinding is performed.
   
   Parameters:
   IN -> ifp - interface pointer
   IN -> ifp - interface pointer
   
   Returns:
   0 on success
   < 0 on error
*/
int 
hsl_bcm_if_pre_unconfigure (struct hsl_if *ifpp, struct hsl_if *ifpc)
{
  int ret = 0;
  struct hsl_bcm_if *bcmifpc, *bcmifpp;

  HSL_FN_ENTER ();

  /* Perform post configuration pure L3 ports(non-aggregated or non-SVI) */
  if (ifpp->type == HSL_IF_TYPE_IP && ifpc->type == HSL_IF_TYPE_L2_ETHERNET &&
      memcmp (ifpp->name, "vlan", 4))
    {
      /* Add the reserved VID assigned for the L3 port as the default port VID
	 on the port. */
      bcmifpc = (struct hsl_bcm_if *)ifpc->system_info;
      bcmifpp = (struct hsl_bcm_if *)ifpp->system_info;

      if (!bcmifpc)
	{
	  ret = -1;
	  HSL_FN_EXIT (ret);
	}
      
      /* Delete port from vlan. */
      hsl_bcm_remove_port_from_vlan (bcmifpp->u.l3.vid, bcmifpc->u.l2.lport);

      /* Flush all entries for the VLAN. */
      bcmx_l2_addr_delete_by_vlan (bcmifpp->u.l3.vid, 0);

      /* Add port to default VID. */
      hsl_bcm_add_port_to_vlan (HSL_DEFAULT_VID, bcmifpc->u.l2.lport, 0);

      /* Set PVID to default VLAN. */
      ret = bcmx_port_untagged_vlan_set (bcmifpc->u.l2.lport, HSL_DEFAULT_VID);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Could not set default PVID for port %s\n", ifpp->name);
	  HSL_FN_EXIT (ret);   
	}
    }

  HSL_FN_EXIT (ret);
}

#ifdef HAVE_L3

static int
_hsl_bcm_if_l3_intf_create (struct hsl_if *ifp, 
			    bcmx_l3_intf_t *intf, hsl_vid_t vid, u_char *mac, 
			    int mtu, hsl_fib_id_t fib_id)
{
  int ret;

  ret = 0;

  HSL_FN_ENTER ();

  /* Sanity checks. */
  if ((intf == NULL) || (mac == NULL))
    return -1;

  /* Initialize entry. */
  bcmx_l3_intf_t_init (intf);
  
  /* Set fib id */
  intf->l3a_vrf = (bcm_vrf_t)fib_id;

  /* Set flags. */
  intf->l3a_flags |= BCM_L3_ADD_TO_ARL;

  /* Set VID. */
  intf->l3a_vid = vid;
      
  /* Set MAC. */
  memcpy (intf->l3a_mac_addr, mac, sizeof (bcm_mac_t));

  /* Set MTU. */
  intf->l3a_mtu = mtu;

  /* Configure a L3 interface in BCM. 
     Add static entry in L2 table with L3 bit set. */
  ret = bcmx_l3_intf_create (intf);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
		   "  Could not create L3 interface in hardware for interface %s %d ret(%d)\n", 
	       ifp->name, ifp->ifindex, ret);
      HSL_FN_EXIT (-1);
    }
  
  HSL_FN_EXIT (0);
}

static int
_hsl_bcm_if_l3_intf_delete_by_index (struct hsl_if *ifp, int index, hsl_fib_id_t fib_id)
{
  bcmx_l3_intf_t intf;
  int ret;

  ret = 0;

  HSL_FN_ENTER ();

  /* Sanity check. */
  if (ifp == NULL)
    HSL_FN_EXIT (-1);

  /* Initialize interface. */
  bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  intf.l3a_vrf = (bcm_vrf_t)fib_id;

  /* Set index. */
  intf.l3a_intf_id = index;
  
  /* Destroy the L3 interface. */
  ret = bcmx_l3_intf_delete (&intf);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "  Could not delete L3 interface %s from hardware\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

static int
_hsl_bcm_if_l3_intf_delete_by_mac_and_vid (struct hsl_if *ifp, u_char *mac, hsl_vid_t vid)
{
  bcmx_l3_intf_t intf;
  int ret;

  HSL_FN_ENTER ();

  /* Sanity check. */
  if ((ifp == NULL) || (mac == NULL))
    HSL_FN_EXIT (-1);

  /* Initialize entry. */
  bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  intf.l3a_vrf = (bcm_vrf_t)ifp->fib_id;
  
  /* Set VID. */
  intf.l3a_vid = vid;
      
  /* Set MAC. */
  memcpy (intf.l3a_mac_addr, mac, sizeof (bcm_mac_t));

  /* Find the entry. */
  ret = bcmx_l3_intf_find (&intf);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "  Could not find L3 interface %s in hardware\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  /* Delete the interface. */
  ret = bcmx_l3_intf_delete (&intf);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "  Could not delete L3 interface %s in hardware\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

#define HSL_BCMX_V4_SET_HOST(host,ifindex,prefix, fib_id)                                           \
  do {                                                                                              \
    bcmx_l3_host_t_init (&(host));                                                                  \
    (host).l3a_ip_addr = ntohl((prefix)->u.prefix4);                                                       \
    (host).l3a_intf = (ifindex);	                                                            \
    (host).l3a_vrf = (bcm_vrf_t)(fib_id);                                                           \
    (host).l3a_lport = BCMX_LPORT_LOCAL_CPU;				                            \
    (host).l3a_flags |= BCM_L3_L2TOCPU;   /* To get original headers. */                            \
  } while (0)
#ifdef HAVE_IPV6
#define HSL_BCMX_V6_SET_HOST(host, ifindex,prefix, fib_id)		                            \
  do {                                                                                              \
    bcmx_l3_host_t_init (&host);                                                                    \
    BCM_IP6_WORD((host).l3a_ip6_addr, 0) = (prefix)->u.prefix6.word[0];                             \
    BCM_IP6_WORD(host.l3a_ip6_addr, 1) = (prefix)->u.prefix6.word[1];                               \
    BCM_IP6_WORD(host.l3a_ip6_addr, 2) = (prefix)->u.prefix6.word[2];                               \
    BCM_IP6_WORD(host.l3a_ip6_addr, 3) = (prefix)->u.prefix6.word[3];                               \
                                                                                                    \
    /* Set flags for IPv6. */                                                                       \
    host.l3a_flags |= BCM_L3_IP6;                                                                   \
                                                                                                    \
    host.l3a_intf = (ifindex);                                                                      \
    (host).l3a_vrf = (bcm_vrf_t)(fib_id);                                                           \
    host.l3a_lport = BCMX_LPORT_LOCAL_CPU;				                            \
    host.l3a_flags |= BCM_L3_L2TOCPU;   /* To get original headers. */                              \
  } while (0)
#endif /* HAVE_IPV6 */    

static int
_hsl_bcm_if_addresses (struct hsl_if *ifp, int add, int connected_route)
{
  hsl_prefix_list_t *ifaddr, *nifaddr;
  struct hsl_bcm_if *bcmifp;
  bcmx_l3_host_t host;
  int rb1, rb2;
  int ret;

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", ifp->name, ifp->ifindex);
      return -1;
    }

  ret = 0;
  rb1 = 0; /* Rollback for IPv4. */
  rb2 = 0; /* Rollback for IPv6. */

  /* IPv4 addresses. */
  ifaddr = IFP_IP(ifp).ipv4.ucAddr;
  while (ifaddr)
    {
      /* Set next. */
      nifaddr = ifaddr->next;

      HSL_BCMX_V4_SET_HOST (host, bcmifp->u.l3.ifindex, &ifaddr->prefix, ifp->fib_id);
      
      if (add)
        {
          /* Add L3 interface host route. */
          ret = hsl_bcmx_l3_host_add (&host, NULL);
        }
      else
        {
          /* Destroy L3 interface host route. */
          ret = hsl_bcmx_l3_host_delete (&host);
        }

      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
              "  Error %d %s L3 interface address %d from hw\n",
              ret, (add ? "adding" : "deleting"), ifaddr->prefix.u.prefix4);
          rb1 = 1;
          ret = -1;
          goto ERR;
        }
      
      if (connected_route)
	{
	  if (add)
	    hsl_fib_add_connected (&ifaddr->prefix, ifp);
	  else
	    hsl_fib_delete_connected (&ifaddr->prefix, ifp);
	}

      /* Goto next. */
      ifaddr = nifaddr;
    }
#ifdef HAVE_IPV6
  ifaddr = IFP_IP(ifp).ipv6.ucAddr;
  while (ifaddr)
    {
      /* Set next. */
      nifaddr = ifaddr->next;

      HSL_BCMX_V6_SET_HOST(host, bcmifp->u.l3.ifindex, &ifaddr->prefix, ifp->fib_id);

      if (add)
	{
	  /* Add L3 interface host route. */
	  ret = bcmx_l3_host_add (&host);
	}
      else
	{
	  /* Destroy L3 interface host route. */
	  ret = bcmx_l3_host_delete (&host);
	}
      
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
                   "  Error %d %s L3 interface address %d from hw\n",
                   ret, (add ? "adding" : "deleting"), ifaddr->prefix.u.prefix4);
	  rb2 = 1;
	  ret = -1;
	  goto ERR;
	}

      if (connected_route)
	{
	  if (add)
	    hsl_fib_add_connected (&ifaddr->prefix, ifp);
	  else
	    hsl_fib_delete_connected (&ifaddr->prefix, ifp);
	}

      /* Goto next. */
      ifaddr = nifaddr;
    }
#endif /* HAVE_IPV6 */

  HSL_FN_EXIT (ret);

 ERR:

  /* Rollback IPv4 addresses. */
  if (rb1)
    {
      ifaddr = IFP_IP(ifp).ipv4.ucAddr;
      while (ifaddr)
	{
	  /* Set next. */
	  nifaddr = ifaddr->next;

	  HSL_BCMX_V4_SET_HOST(host, bcmifp->u.l3.ifindex, &ifaddr->prefix, ifp->fib_id);

          if (! add)
            {
              /* Add L3 interface host route. */
              hsl_bcmx_l3_host_add (&host, NULL);
            }
          else
            {
              /* Destroy L3 interface host route. */
              hsl_bcmx_l3_host_delete (&host);
            }
	  
	  if (connected_route)
	    {
	      /* Notice this is reverse. */
	      if (! add)
		hsl_fib_add_connected (&ifaddr->prefix, ifp);
	      else
		hsl_fib_delete_connected (&ifaddr->prefix, ifp);
	    }

	  /* Goto next. */
	  ifaddr = nifaddr;
	}
    }

#ifdef HAVE_IPV6
  if (rb2)
    {
      ifaddr = IFP_IP(ifp).ipv6.ucAddr;
      while (ifaddr)
	{
	  /* Set next. */
	  nifaddr = ifaddr->next;
	  
	  HSL_BCMX_V6_SET_HOST(host, bcmifp->u.l3.ifindex, &ifaddr->prefix, ifp->fib_id);
	  
	  /* Notice this is reverse. */
	  if (! add)
	    {
	      /* Add L3 interface host route. */
	      bcmx_l3_host_add (&host);
	    }
	  else
	    {
	      /* Destroy L3 interface host route. */
	      bcmx_l3_host_delete (&host);
	    }
	  
	  if (connected_route)
	    {
	      /* Notice this is reverse. */
	      if (! add)
		hsl_fib_add_connected (&ifaddr->prefix, ifp);
	      else
		hsl_fib_delete_connected (&ifaddr->prefix, ifp);
	    }
	  
	  /* Goto next. */
	  ifaddr = nifaddr;
	}
    }
#endif /* HAVE_IPV6 */

  HSL_FN_EXIT (ret);
}
  
static int
_hsl_bcm_if_add_addresses (struct hsl_if *ifp, int connected_route)
{
  return _hsl_bcm_if_addresses (ifp, 1, connected_route);
}

static int
_hsl_bcm_if_delete_addresses (struct hsl_if *ifp, int connected_route)
{
  return _hsl_bcm_if_addresses (ifp, 0, connected_route);
}

/* Create L3 interface.

Parameters:
IN -> ifp - interface pointer
IN -> unsed - unused parameter
     
Returns:
HW L3 interface pointer as void *
NULL on error
*/
void *
hsl_bcm_if_l3_configure (struct hsl_if *ifp, void *unused)
{
  int ret = -1;
  int br, v;
  hsl_vid_t vid;
  struct hsl_bcm_if *bcmifp;
  bcmx_l3_intf_t intf;
  struct hsl_bcm_resv_vlan *entry;

  HSL_FN_ENTER ();

  /* Create the structure to store BCM L3 interface data. */
  bcmifp = hsl_bcm_if_alloc ();
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Out of memory for allocating hardware L3 interface\n");
      HSL_FN_EXIT (NULL);
    }

  /* Set type as IP. */
  bcmifp->type = HSL_BCM_IF_TYPE_L3_IP;

  /* Set MAC. */
  memcpy (bcmifp->u.l3.mac, IFP_IP(ifp).mac, HSL_ETHER_ALEN);

  /* Not a trunk. */
  bcmifp->trunk_id = -1;

  bcmifp->u.l3.resv_vlan = NULL;

  /* Check for the VLAN. If it is a pure L3 router port, then use the 
     default VLAN. */
  if (! memcmp (ifp->name, "vlan", 4))
    {
      /* Get VLAN from name. */
      sscanf (ifp->name, "vlan%d.%d", (int *) &br, (int *)&v);
      vid = (hsl_vid_t) v;
    }
  else
    {
      ret = hsl_bcm_resv_vlan_allocate (&entry);
      if (ret < 0)
	{
	  /* Free Broadcom interface. */
	  hsl_bcm_if_free (bcmifp);
	  HSL_FN_EXIT (NULL);
	}	

      vid = entry->vid;

      /* Store etry. */
      bcmifp->u.l3.resv_vlan = entry;     
    }

  /* Set VID. */
  bcmifp->u.l3.vid = vid;
  IFP_IP(ifp).vid = vid;

  if (ifp->flags & IFF_UP)
    {
      /* Create L3 interface. */
      ret = _hsl_bcm_if_l3_intf_create (ifp, &intf, vid, IFP_IP(ifp).mac, IFP_IP(ifp).mtu, ifp->fib_id);
      if (ret < 0)
	{
	  HSL_FN_EXIT (NULL);
	}
      
      /* Set ifindex. */
      bcmifp->u.l3.ifindex = intf.l3a_intf_id;
    }

  {
      bcm_gport_t gport = 0;
      BCM_GPORT_MODPORT_SET(gport, vid, 255);
      
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "add gport %x map.\n",gport);

      hsl_bcm_ifmap_if_map (gport | 0, ifp);
  }

  HSL_FN_EXIT (bcmifp);
}

/* 
   Delete L3 interface.

   Parameters:
   IN -> ifp - interface pointer
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_l3_unconfigure (struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;
  int ret;
  int i;

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware L3 interface not found for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  if (ifp->type != HSL_IF_TYPE_IP)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Invalid interface type fpr hardware L3 unconfiguration for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  /* Check for trunk. */
  if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
    {
      /* Destroy the trunk. */
      if (bcmifp->trunk_id >= 0)
	{
	  ret = bcmx_trunk_destroy (bcmifp->trunk_id);
	  if (ret < 0)
	    {
	      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
                       "  Error %d deleting trunk from hardware for %s\n", 
                       ret, ifp->name);
	    }
	}
    }

  /* Delete host entries for the addreses. */
  _hsl_bcm_if_delete_addresses (ifp, 0);

  if (BCMIFP_L3(bcmifp).ifindex > 0)
    {
      /* Delete the primary L3 interface. */
      ret = _hsl_bcm_if_l3_intf_delete_by_index (ifp, BCMIFP_L3(bcmifp).ifindex, ifp->fib_id);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
		   "  Error deleting L3 interface %d from hardware\n", BCMIFP_L3(bcmifp).ifindex);  
	}

      BCMIFP_L3(bcmifp).ifindex = -1;

      /* Delete the secondary L3 interfaces. */
      for (i = 0; i < IFP_IP(ifp).nAddrs; i++)
	{
	  ret = _hsl_bcm_if_l3_intf_delete_by_mac_and_vid (ifp, IFP_IP(ifp).addresses[i], IFP_IP(ifp).vid);
	  if (ret < 0)
	    {
	      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
		       "  Error deleting L3 interface from hardware\n");
	    }
	}      
    }

  /* Free reserved vlan if configured. */
  if (BCMIFP_L3(bcmifp).resv_vlan)
    {
      hsl_bcm_resv_vlan_deallocate (BCMIFP_L3(bcmifp).resv_vlan);
    }

  /* Free HW ifp. */
  hsl_bcm_if_free (bcmifp);
  ifp->system_info = NULL;

  HSL_FN_EXIT (0);
}

/* 
   Add a IP address to the interface.

   Parameters:
   IN -> ifp - interface pointer
   IN -> prefix - interface address and prefix
   IN -> flags - flags
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_l3_address_add (struct hsl_if *ifp,
			       hsl_prefix_t *prefix, u_char flags)
{
  struct hsl_bcm_if *bcmifp; 
  bcmx_l3_host_t host;
  int ret;
  
  HSL_FN_ENTER ();

  /* Connected route will be added by hsl_fib_add_connected() so just return
     from here. */
  ret = 0;
  if (ifp->if_property == HSL_IF_CPU_ONLY_INTERFACE)
    HSL_FN_EXIT (ret);

  /* Ignore loopback addresses */
  if (((prefix->family == AF_INET) && (ntohl(prefix->u.prefix4) == INADDR_LOOPBACK))
#ifdef HAVE_IPV6
      || ((prefix->family == AF_INET6) && (IPV6_IS_ADDR_LOOPBACK (&prefix->u.prefix6)))
#endif /* HAVE_IPV6 */
     )
    HSL_FN_EXIT (ret);

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware interface information not found for interface %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  /* If interface is UP, add it to interface. */
  if (BCMIFP_L3(bcmifp).ifindex != -1)
    {
      if (prefix->family == AF_INET)
	{
	  HSL_BCMX_V4_SET_HOST(host, bcmifp->u.l3.ifindex, prefix, ifp->fib_id);     
	}
#ifdef HAVE_IPV6
      else if (prefix->family == AF_INET6)
	{
	  HSL_BCMX_V6_SET_HOST(host, bcmifp->u.l3.ifindex, prefix, ifp->fib_id);
	}
#endif /* HAVE_IPV6. */
      else
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  IP address type is not valid\n");
	  HSL_FN_EXIT (-1);
	}
      
      /* Add the host entry. */
      ret = hsl_bcmx_l3_host_add (&host, NULL);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Host entry for interface address could not be added %s\n", ifp->name);
          HSL_FN_EXIT (-1);
        }
    }

  HSL_FN_EXIT (0);
}

/* 
   Delete a IP address from the interface. 

   Parameters:
   IN -> ifp - interface pointer
   IN -> prefix - interface address and prefix
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_l3_address_delete (struct hsl_if *ifp,
				  hsl_prefix_t *prefix)
{
  struct hsl_bcm_if *bcmifp; 
  bcmx_l3_host_t host;
  int ret;

  HSL_FN_ENTER ();

  /* Connected route will be deleted by hsl_fib_connected_delete() */
  ret = 0;
  if (ifp->if_property == HSL_IF_CPU_ONLY_INTERFACE)
    HSL_FN_EXIT (ret);

  /* Ignore loopback addresses */
  if (((prefix->family == AF_INET) && (ntohl(prefix->u.prefix4) == INADDR_LOOPBACK))
#ifdef HAVE_IPV6
      || ((prefix->family == AF_INET6) && (IPV6_IS_ADDR_LOOPBACK (&prefix->u.prefix6)))
#endif /* HAVE_IPV6 */
     )
    HSL_FN_EXIT (ret);

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware interface information not found for interface (%s)\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  
  if (prefix->family == AF_INET)
    {
      HSL_BCMX_V4_SET_HOST(host, bcmifp->u.l3.ifindex, prefix, ifp->fib_id);     
    }
#ifdef HAVE_IPV6
  else if (prefix->family == AF_INET6)
    {
      HSL_BCMX_V6_SET_HOST(host, bcmifp->u.l3.ifindex, prefix, ifp->fib_id);
    }
#endif /* HAVE_IPV6. */
  else
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  IP address type is not valid\n");
      HSL_FN_EXIT (-1);
    }
  
  /* Delete the host entry. */
  ret = hsl_bcmx_l3_host_delete (&host);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Host entry for interface %s address could not be deleted (%d)\n", ifp->name, ret);
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

/* 
   Bind a interface to FIB. 

   Parameters:
   IN -> ifp - interface pointer
   IN -> fib_id - FIB id
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_l3_bind_fib (struct hsl_if *ifp,
				  hsl_fib_id_t fib_id)
{
  struct hsl_bcm_if *bcmifp; 
  bcmx_l3_intf_t intf;
  int ret = 0;

  HSL_FN_ENTER ();

  if (ifp->if_property == HSL_IF_CPU_ONLY_INTERFACE)
    HSL_FN_EXIT (ret);

  if (ifp->type != HSL_IF_TYPE_IP)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Invalid interface type for hardware L3 FIB bind for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware interface information not found for interface (%s)\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  ret = _hsl_bcm_if_l3_intf_create (ifp, &intf, 
      BCMIFP_L3(bcmifp).vid, IFP_IP(ifp).mac, IFP_IP(ifp).mtu,
      fib_id);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error binding interface %s to FIB %d\n", ifp->name, fib_id);
      HSL_FN_EXIT (ret);
    }
  
  BCMIFP_L3(bcmifp).ifindex = intf.l3a_intf_id;

  
  HSL_FN_EXIT (ret);
}

/* 
   Unbind a interface from FIB. 

   Parameters:
   IN -> ifp - interface pointer
   IN -> fib_id - FIB id
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_l3_unbind_fib (struct hsl_if *ifp,
				  hsl_fib_id_t fib_id)
{
  struct hsl_bcm_if *bcmifp; 
  int ret = 0;

  HSL_FN_ENTER ();

  if (ifp->if_property == HSL_IF_CPU_ONLY_INTERFACE)
    HSL_FN_EXIT (ret);

  if (ifp->type != HSL_IF_TYPE_IP)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Invalid interface type for hardware L3 FIB unbind for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware interface information not found for interface (%s)\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  ret = _hsl_bcm_if_l3_intf_delete_by_index (ifp, BCMIFP_L3(bcmifp).ifindex, fib_id);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error unbinding interface %s to FIB %d\n", ifp->name, fib_id);
      HSL_FN_EXIT (ret);
    }
  
  BCMIFP_L3(bcmifp).ifindex = -1;

  HSL_FN_EXIT (ret);
}

/* 
   Set interface to UP. 
*/
static int
_hsl_bcm_if_l3_up (struct hsl_if *ifp)
{
  int rb_addr, rb_sec, rb_pri;
  struct hsl_bcm_if *bcmifp; 
  bcmx_l3_intf_t intf;
  int ret;
  int i;

  HSL_FN_ENTER ();

  ret = 0;
  rb_addr = 0;
  rb_pri = 0;
  rb_sec = 0;

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    HSL_FN_EXIT (-1);

  if (BCMIFP_L3(bcmifp).ifindex != -1)
    {
      /* Interface is not up. */
      HSL_FN_EXIT (-1);
    }

  /* Initialize interface. */
  bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  intf.l3a_vrf = (bcm_vrf_t)ifp->fib_id;

  /* Set flags. */
  intf.l3a_flags |= BCM_L3_ADD_TO_ARL;
  
  /* Set MAC. */
  memcpy (intf.l3a_mac_addr, IFP_IP(ifp).mac, sizeof (bcm_mac_t));

  /* Set VID. */
  intf.l3a_vid = BCMIFP_L3(bcmifp).vid;

  /* Set MTU. */
  intf.l3a_mtu = 1500;

  /* Create a new interface. */
  ret = bcmx_l3_intf_create (&intf);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error creating interface\n");
      ret = -1;
      goto ERR;
    }
  
  BCMIFP_L3(bcmifp).ifindex = intf.l3a_intf_id;

  /* Create interfaces for secondary addresses, if any. */
  for (i = 0; i < IFP_IP(ifp).nAddrs; i++)
    {
      /* Create L3 interface. */
      ret = _hsl_bcm_if_l3_intf_create (ifp, &intf, IFP_IP(ifp).vid, IFP_IP(ifp).addresses[i], IFP_IP(ifp).mtu, ifp->fib_id);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error creating secondary interface\n");
	  ret = -1;
	  rb_pri = rb_sec = 1;
	  goto ERR;
	}
    }

  /* Process the addresses and add them. */
  ret = _hsl_bcm_if_add_addresses (ifp, 1);
  if (ret < 0)
    {
      ret = -1;
      rb_pri = rb_sec = 1;
      goto ERR;
    }

  HSL_FN_EXIT (ret);

 ERR:

  /* Perform primary L3 interface rollbacks. */
  if (rb_pri)
    {
      /* Initialize interface. */
      bcmx_l3_intf_t_init (&intf);

      _hsl_bcm_if_l3_intf_delete_by_index (ifp, BCMIFP_L3(bcmifp).ifindex, ifp->fib_id);
    }

  /* Perform secondary L3 interface rollbacks. */
  if (rb_sec)
    {
      for (i = 0; i < IFP_IP(ifp).nAddrs; i++)
	{
	  _hsl_bcm_if_l3_intf_delete_by_mac_and_vid (ifp, IFP_IP(ifp).addresses[i], IFP_IP(ifp).vid);
	}
    }

  HSL_FN_EXIT (ret);
}

static int
l3_egress_obj_delete_by_intf(int unit, int index, bcm_l3_egress_t *info, void *cookie)
{
	if (info->intf == (int)cookie)
		bcmx_l3_egress_destroy(index);

    return BCM_E_NONE;
}

/* 
   Set interface to down. 
*/
static int
_hsl_bcm_if_l3_down (struct hsl_if *ifp)
{
  int ret;
  struct hsl_bcm_if *bcmifp; 
  bcmx_l3_intf_t intf;
  bcmx_l3_route_t route;

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    HSL_FN_EXIT (-1);

  if (BCMIFP_L3(bcmifp).ifindex == -1)
    {
      /* Interface is already down. */
      HSL_FN_EXIT (-1);
    }

  /* Initialize interface. */
  bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  intf.l3a_vrf = (bcm_vrf_t)ifp->fib_id;

  /* Initialize route. */
  bcmx_l3_route_t_init (&route);

  /* Set interface index. */
  intf.l3a_intf_id = route.l3a_intf = BCMIFP_L3(bcmifp).ifindex;

  /* Set fib id */
  route.l3a_vrf = (bcm_vrf_t)ifp->fib_id;

  /* Delete all routes pointing to this interface including the connected
     routes. */
  ret = bcmx_l3_route_delete_by_interface (&route);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting prefix routes from hardware on interface down event\n");
    }

  bcmx_l3_egress_traverse(l3_egress_obj_delete_by_intf, (void*)route.l3a_intf);

  /* Process the addresses and add them. */
  ret = _hsl_bcm_if_delete_addresses (ifp, 1);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting interface addresses from hardware.\n");
    }

  /* Delete L3 interface from hardware. */
  ret = bcmx_l3_intf_delete (&intf);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting L3 interface from hardware\n");
    }

  BCMIFP_L3(bcmifp).ifindex = -1;
  
  HSL_FN_EXIT (0);
}
#endif /* HAVE_L3 */

/* 
 * Get interface mtu. 
 */ 
int
hsl_bcm_get_port_mtu(bcmx_lport_t lport, int *mtu)
{
  int  mtu_size;           /* Interface mtu */
  int       ret;            /* sdk operation status.  */

  HSL_FN_ENTER();
  
  /* Input parameters validation. */   
  if(NULL == mtu)
    {
      HSL_FN_EXIT(STATUS_WRONG_PARAMS); 
    }

  /* Get interface frame max. */
  ret = bcmx_port_frame_max_get(lport, &mtu_size);
  if (ret != BCM_E_NONE)
    {
      *mtu = 1500;
      HSL_FN_EXIT(-1);
    }
 
  if (mtu_size == HSL_ETHER_MAX_LEN) 
    *mtu = HSL_ETHER_MAX_DATA;
  else
  	*mtu = mtu_size;
     
  HSL_FN_EXIT(0);
}

/* 
 * Set interface mtu. 
 */ 
int
hsl_bcm_set_port_mtu (int gport, int mtu)
{
  int       ret;            /* sdk operation status.  */

  HSL_FN_ENTER();
  
  /* Get interface frame max. */
  ret = bcmx_port_frame_max_set(lport, mtu);
  if (ret != BCM_E_NONE)
      HSL_FN_EXIT(-1);
 
  HSL_FN_EXIT(0);
}

/* 
 * Get interface duplex. 
 */
#if 0
int
hsl_bcm_get_port_duplex(int gport, u_int32_t *duplex)
{
  int       dup;            /* Interface duplex.      */
  int       ret;            /* sdk operation status.  */

  HSL_FN_ENTER();
  
    /* Input parameters validation. */   
    if(NULL == duplex) {
        HSL_FN_EXIT(STATUS_WRONG_PARAMS); 
    }

  /* Get interface duplex. */
  ret = bcmx_port_duplex_get(lport, &dup);
  if (ret != BCM_E_NONE)
    {
      *duplex = HSL_IF_DUPLEX_HALF;
      HSL_FN_EXIT(-1);
    }

  switch (dup)  
    {  
    case BCM_PORT_DUPLEX_FULL:
      *duplex = HSL_IF_DUPLEX_FULL;
      break;
    case BCM_PORT_DUPLEX_HALF:
    default:
      *duplex = HSL_IF_DUPLEX_HALF;
    }

  HSL_FN_EXIT(0);
}
#endif

/* Set MTU for interface.

Parameters:
IN -> ifp - interface pointer
IN -> mtu - mtu
   
Returns:
0 on success
< 0 on error
*/
int hsl_bcm_if_mtu_set (struct hsl_if *ifp, int mtu)
{
  struct hsl_bcm_if *bcmifp;
  int ret;

  HSL_FN_ENTER ();

  if (! ifp)
    HSL_FN_EXIT (-1);

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
               "Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", 
               ifp->name, ifp->ifindex);
      HSL_FN_EXIT (-1);
    }

  ret = bcmx_port_frame_max_set (BCMIFP_L2(bcmifp).lport, mtu);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s set mtu failed\n", ifp->name);
      HSL_FN_EXIT (-1);
    } 
  
  ifp->u.l2_ethernet.mtu = mtu;
  HSL_FN_EXIT (ret);
}

/* Set DUPLEX for interface.

Parameters:
IN -> ifp - interface pointer
IN -> duplex - duplex
(0: half-duplex, 1: full-duplex, 2: auto-negotiate)

Returns:
0 on success
< 0 on error
*/
int hsl_bcm_if_duplex_set (struct hsl_if *ifp, int duplex)
{
  struct hsl_bcm_if *bcmifp;
  int ret;

  HSL_FN_ENTER ();

  if (! ifp)
    HSL_FN_EXIT (-1);

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
               "Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", 
               ifp->name, ifp->ifindex);
      HSL_FN_EXIT (-1);
    }

  if (duplex == HSL_IF_DUPLEX_AUTO)
    {
      ret = bcmx_port_autoneg_set (BCMIFP_L2(bcmifp).lport, HSL_IF_AUTONEGO_ENABLE);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s set auto-nego failed\n", ifp->name);
          HSL_FN_EXIT (-1);
        }
    }
  else
    {
      ret = bcmx_port_duplex_set (BCMIFP_L2(bcmifp).lport, duplex);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s set duplex failed\n", ifp->name);
          HSL_FN_EXIT (-1);
        } 

      ifp->u.l2_ethernet.duplex = duplex;
    }

  HSL_FN_EXIT (ret);
}

/* Set AUTO-NEGOTIATE for interface.

Parameters:
IN -> ifp - interface pointer
IN -> autonego - autonego
(0: disable, 1: enable)

Returns:
0 on success
< 0 on error
*/
int hsl_bcm_if_autonego_set (struct hsl_if *ifp, int autonego)
{
  struct hsl_bcm_if *bcmifp;
  int ret;

  HSL_FN_ENTER ();

  if (! ifp)
    HSL_FN_EXIT (-1);

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
               "Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n",
               ifp->name, ifp->ifindex);
      HSL_FN_EXIT (-1);
    }

  ret = bcmx_port_autoneg_set (BCMIFP_L2(bcmifp).lport, autonego);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s(%d) set autonego failed\n", ifp->name, ifp->ifindex);
      return -1;
    }

  HSL_FN_EXIT (ret);
}

/* Set BANDWIDTH for interface.

Parameters:
IN -> ifp - interface pointer
IN -> bandwidth - bandwidth 

Returns:
0 on success
< 0 on error
*/
int hsl_bcm_if_bandwidth_set (struct hsl_if *ifp, long long unsigned int bandwidth)
{
  struct hsl_bcm_if *bcmifp;
  int ret;
  int speed;

  HSL_FN_ENTER ();

  if (! ifp)
    HSL_FN_EXIT (-1);
  //printk("\nhsl_bcm_if_bandwidth_set to band %u\n", bandwidth);
  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
               "Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n",
               ifp->name, ifp->ifindex);
      HSL_FN_EXIT (-1);
    }
 
  
  /* Broadcom allowed input value of bandwidth with 10,100, 1000, 10000 
     megabits/sec. Bandwidth value coming from nsm is bytes/sec */
  speed = (int)(bandwidth / HSL_BCM_BW_UNIT_MEGA * 8) + 
  			(int)((bandwidth % HSL_BCM_BW_UNIT_MEGA) * 8 / HSL_BCM_BW_UNIT_MEGA);
			
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
               "%s got bandwidth= l: %l, ll: %ll, Byte/s, speed = %d Mbits/s \n",
               bandwidth, bandwidth, speed);
  if ((speed != HSL_BCM_BW_UNIT_10M) && (speed != HSL_BCM_BW_UNIT_100M) && 
      (speed != HSL_BCM_BW_UNIT_1G) && (speed != HSL_BCM_BW_UNIT_10G) && (speed != HSL_BCM_BW_UNIT_40G))
    {
	  printk("\nInterface %s bandwidth value is not allowed\n", ifp->name);
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s bandwidth value is not allowed\n", ifp->name);
      HSL_FN_EXIT (-1);
    }
  //printk("\nhsl_bcm_if_bandwidth_set before bcmx_port_speed_set\n");
  
  ret = bcmx_port_speed_set (BCMIFP_L2(bcmifp).lport, speed);
  if (ret < 0) {
    HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s set bandwidth failed\n", ifp->name);
	printk("\nInterface %s set bandwidth failed\n", ifp->name);
  }  else {
    ifp->u.l2_ethernet.speed = speed;
  }
  
  HSL_FN_EXIT (ret);
}

#ifdef HAVE_L3
/* Set HW address for a interface.

Parameters:
IN -> ifp - interface pointer
IN -> hwadderlen - address length
IN -> hwaddr - address
     
Returns:
0 on success
< 0 on error
*/
int 
hsl_bcm_if_hwaddr_set (struct hsl_if *ifp, int hwaddrlen, u_char *hwaddr)
{
  struct hsl_bcm_if *bcmifp; 

  HSL_FN_ENTER ();

  if (ifp->type != HSL_IF_TYPE_IP)
    HSL_FN_EXIT (0);

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    HSL_FN_EXIT (-1);

  /* Bring down the interface. */
  _hsl_bcm_if_l3_down (ifp);

  /* Set new MAC. */
  memcpy (BCMIFP_L3(bcmifp).mac, hwaddr, hwaddrlen);

  /* Bring up the interface. */
  _hsl_bcm_if_l3_up (ifp);

  HSL_FN_EXIT (0);
}

/* 
   Set L3 port flags. 

   Parameters:
   IN -> ifp - interface pointer
   IN -> flags - flags

   Returns:
   0 on success
   < 0 on error
*/
int 
hsl_bcm_if_l3_flags_set (struct hsl_if *ifp, unsigned long flags)
{
  HSL_FN_ENTER ();

  if (flags & IFF_UP)
    {
      /* Set interface to UP. */
      _hsl_bcm_if_l3_up (ifp);

      HSL_FN_EXIT (0);
    }

  HSL_FN_EXIT (0);
}

/* 
   Unset L3 port flags. 

   Parameters:
   IN - ifp - interface pointer
   IN -> flags - flags

   Returns:
   0 on success
   < 0 on error
*/
int 
hsl_bcm_if_l3_flags_unset (struct hsl_if *ifp, unsigned long flags)
{
  struct hsl_bcm_if *bcmifp; 

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    HSL_FN_EXIT (-1);
     
  if (flags & IFF_UP)
    {
      /* Set interface to down. */
      _hsl_bcm_if_l3_down (ifp);

      HSL_FN_EXIT (0);
    }
  
  HSL_FN_EXIT (0);
}
#endif /* HAVE_L3 */

/* Set packet types acceptable from this port.

Parameters:
IN -> ifp - interface pointer
IN -> pkt_flags
   
Returns:
0 on success
< 0 on error   
*/
int hsl_bcm_if_packet_types_set (struct hsl_if *ifp, unsigned long pkt_flags)
{
  struct hsl_bcm_if *bcmifp;

  HSL_FN_ENTER ();

  if (! ifp)
    HSL_FN_EXIT (-1);

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", ifp->name, ifp->ifindex);
      HSL_FN_EXIT (-1);
    }

  /* For EAPOL, LACP on L3 ports, we need to enable this always. */
  bcmx_port_bpdu_enable_set (BCMIFP_L2(bcmifp).lport, 1);

  HSL_FN_EXIT (0);
}

/* Unset packet types acceptable from this port.

Parameters:
IN -> ifp - interface pointer
IN -> pkt_flags
   
Returns:
0 on success
< 0 on error   
*/
int hsl_bcm_if_packet_types_unset (struct hsl_if *ifp, unsigned long pkt_flags)
{
  struct hsl_bcm_if *bcmifp;

  HSL_FN_ENTER ();

  if (! ifp)
    HSL_FN_EXIT (-1);

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", ifp->name, ifp->ifindex);
      HSL_FN_EXIT (-1);
    }

  /* For EAPOL, LACP on L3 ports, we need to enable this always. */
  bcmx_port_bpdu_enable_set (BCMIFP_L2(bcmifp).lport, 1);

  HSL_FN_EXIT (0);
}

/* Get Layer 2 port counters 

Parameters:
IN -> lport - interface pointer
OUT-> Mac counters for interface.  
   
Returns:
0 on success
< 0 on error   
*/
int
_hsl_bcm_get_lport_counters(bcmx_lport_t lport,struct hal_if_counters *res) 
{

   static struct hal_if_counters cnts; 
   const struct snmp_stat 
   {
     bcm_stat_val_t bcm_stattype;
     ut_int64_t *zbt;
   } stat_maptb[] = {
     {snmpIfOutErrors , &cnts.out_errors,                                     },
     {snmpIfInDiscards, &cnts.out_discards,                                   },
     {snmpIfOutMulticastPkts, &cnts.out_mc_pkts,                              },
     {snmpIfOutUcastPkts, &cnts.out_uc_pkts,                                  },
     {snmpIfInDiscards, &cnts.in_discards,                                    },
     {snmpIfInOctets, &cnts.good_octets_rcv,                                  },
   /*{ , &cnts.bad_octets_rcv; not support by bcm sdk                         },*/
     {snmpDot3StatsInternalMacTransmitErrors, &cnts.mac_transmit_err,         },
     {snmpDot1dTpPortInFrames, &cnts.good_pkts_rcv,                           },
     {snmpIfInErrors, &cnts.bad_pkts_rcv,                                     },
     {snmpIfInBroadcastPkts, &cnts.brdc_pkts_rcv,                             },
     {snmpIfInMulticastPkts, &cnts.mc_pkts_rcv,                               },
     {snmpEtherStatsPkts64Octets, &cnts.pkts_64_octets_rcv,                   },
     {snmpEtherStatsPkts65to127Octets, &cnts.pkts_65_127_octets_rcv,          },
     {snmpEtherStatsPkts128to255Octets, &cnts.pkts_128_255_octets_rcv,        },
     {snmpEtherStatsPkts256to511Octets, &cnts.pkts_256_511_octets_rcv,        },
     {snmpEtherStatsPkts1024to1518Octets, &cnts.pkts_512_1023_octets_rcv,     },
     {snmpEtherStatsPkts1024to1518Octets, &cnts.pkts_1024_1518_octets_rcv,    },
     {snmpIfOutOctets, &cnts.good_octets_sent,                                },
     {snmpDot1dTpPortOutFrames, &cnts.good_pkts_sent,                         },
     {snmpDot3StatsExcessiveCollisions, &cnts.excessive_collisions,           },
     {snmpIfHCOutMulticastPkts, &cnts.mc_pkts_sent,                           },
     {snmpIfOutBroadcastPkts, &cnts.brdc_pkts_sent,                           },
     {snmpIfInUnknownProtos, &cnts.unrecog_mac_cntr_rcv,                      },
     {snmpIeee8021PfcRequests, &cnts.fc_sent,                                 }, /* is it correct ? */ 
     {snmpIeee8021PfcIndications, &cnts.good_fc_rcv,                          }, /* is it correct ? */ 
     {snmpEtherStatsDropEvents, &cnts.drop_events,                            },
     {snmpEtherStatsUndersizePkts, &cnts.undersize_pkts,                      },
     {snmpEtherStatsFragments, &cnts.fragments_pkts,                          },
     {snmpDot1dBasePortMtuExceededDiscards, &cnts.oversize_pkts,              },
     {snmpEtherStatsJabbers, &cnts.jabber_pkts,                               },
     {snmpDot3StatsInternalMacReceiveErrors, &cnts.mac_rcv_error,             },
     {snmpEtherStatsCRCAlignErrors, &cnts.bad_crc,                            },
     {snmpEtherStatsCollisions, &cnts.collisions,                             },
     {snmpDot3StatsLateCollisions, &cnts.late_collisions,                     },
   /*{   , &cnts.bad_fc_rcv,                 not support by bcm sdk           },*/
   /*{   , &cnts.port_in_overflow_frames,    not support by bcm sdk           },*/
   /*{   , &cnts.port_out_overflow_frames,   not support by bcm sdk           },*/
   /*{   , &cnts.port_in_overflow_discards,  not support by bcm sdk           },*/
   /*{   , &cnts.in_filtered,                not support by bcm sdk           },*/
   /*{   , &cnts.out_filtered,               not support by bcm sdk           },*/
     {snmpDot1dBasePortMtuExceededDiscards, &cnts.mtu_exceed,                 },
 };
  
  const unsigned int tblsz = sizeof(stat_maptb)/sizeof(struct snmp_stat);
  int retarr[sizeof(stat_maptb)/sizeof(struct snmp_stat)];
  struct timeval current_time;
  int okcnt = 0;
  long long unsigned int tmpvar;
  int i = 0;
  int try = 2;
  
  /* first try */
  for (i = 0; i<tblsz; i++)
  {
    retarr[i] = bcmx_stat_get(lport, stat_maptb[i].bcm_stattype, &tmpvar);
    hsl_bcm_copy_64_int(&tmpvar, stat_maptb[i].zbt);
    if(retarr[i] == BCM_E_NONE) 
    {
      okcnt++;
    }
  }
  /* Get current time */
  do_gettimeofday(&current_time);
  tmpvar = current_time.tv_sec * 1000 + current_time.tv_usec / 1000;
  /* those no succeed, try x times more */
  if(okcnt < tblsz)
  {
    for(try = 2; try >0; try--)
   {
      for(i = 0; i<tblsz; i++)
      {
        if(retarr[i] !=BCM_E_NONE)
        {
          retarr[i] = bcmx_stat_get(lport, stat_maptb[i].bcm_stattype, &tmpvar);
          hsl_bcm_copy_64_int(&tmpvar, stat_maptb[i].zbt);
          if(retarr[i] == BCM_E_NONE) 
		  {
		    okcnt++;
		  }
        }
      }
    }
  }
  memcpy(res, &cnts, sizeof(struct hal_if_counters));
  hsl_bcm_copy_64_int(&tmpvar, &res->last_sample_time);
  
  if (okcnt != tblsz) 
  { 
    printk("tblsz(%d), okcnt(%d) time %lld (%lld)\r\n", tblsz, okcnt, 
      tmpvar, hsl_bcm_convert_to_64_int(&res->last_sample_time));
    for (i = 0; i<tblsz; i++)
    {
      if(retarr[i] < 0) 
	  {
	    HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Err bcmx_stat_get %s\n", 
	      bcm_errmsg(retarr[i]));
	  }
    }
  }
  return (okcnt == tblsz) ? 0:-1;
  
}

/* Get Interface counters.

Parameters:
INOUT -> ifp - interface pointer
   
Returns:
0 on success
< 0 on error   
*/
int
hsl_bcm_get_if_counters(struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;
  int ret;

  HSL_FN_ENTER ();

  /* Sanity */
  if(!ifp )
      return (STATUS_WRONG_PARAMS);

  /* Interface should be a layer 2 port. */ 
  if(ifp->type != HSL_IF_TYPE_L2_ETHERNET)
      return (STATUS_WRONG_PARAMS); 

  /* Get broadcom specified data. */
  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if(!bcmifp)
    {
      return (STATUS_ERROR);
    }

   /* Ignore trunks. */
   if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
      HSL_FN_EXIT (STATUS_WRONG_PARAMS); 
 

  /* Read counters from hw. */
  ret = _hsl_bcm_get_lport_counters(BCMIFP_L2(bcmifp).lport,&ifp->mac_cntrs);
  if (0 != ret) {
  	HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Get %s(%d) get stat error.\r\n", 
  	ifp->name, ifp->ifindex);
    return (STATUS_ERROR);
  }

  HSL_FN_EXIT (STATUS_OK);
}

/* Clear Interface counters.

Parameters:
INOUT -> ifp - interface pointer
   
Returns:
0 on success
< 0 on error   
*/
int
hsl_bcm_clear_if_counters(struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;

  HSL_FN_ENTER ();

  /* Sanity */
  if(!ifp )
      HSL_FN_EXIT (STATUS_WRONG_PARAMS);

  /* Interface should be a layer 2 port. */ 
  if(ifp->type != HSL_IF_TYPE_L2_ETHERNET)
      HSL_FN_EXIT (STATUS_WRONG_PARAMS); 

  /* Get broadcom specified data. */
  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if(!bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", ifp->name, ifp->ifindex);
      HSL_FN_EXIT (STATUS_ERROR);
    }

   /* Ignore trunks. */
   if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
      HSL_FN_EXIT (STATUS_WRONG_PARAMS); 
 
 
  /* Read counters from hw. */
  if (0 != bcm_stat_clear(bcmx_lport_bcm_unit(BCMIFP_L2(bcmifp).lport), BCMIFP_L2(bcmifp).lport))
    HSL_FN_EXIT (STATUS_ERROR);
  
  HSL_FN_EXIT (STATUS_OK);
}
/* Set switching type for a port.

Parameters:
IN -> ifp 

Returns:
0 on success
< 0 on error
*/
int
hsl_bcm_if_set_switching_type (struct hsl_if *ifp, hsl_IfSwitchType_t type)
{
  struct hsl_bcm_if *bcmifp;
  bcmx_lport_t lport;
  bcm_stg_t stg;
  int unit;
  int port;
  int ret;

  HSL_FN_ENTER ();

  if (! ifp || ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    HSL_FN_EXIT (STATUS_ERROR);

  bcmifp = ifp->system_info;
  lport = BCMIFP_L2(bcmifp).lport;

  switch (type)
    {
    case HSL_IF_SWITCH_L2:
    case HSL_IF_SWITCH_L2_L3:
      {
	/* Enable learning. */
	bcmx_port_learn_modify (lport, BCM_PORT_LEARN_ARL, 0);

#ifdef HAVE_L2LERN
       /* Enable cpu based learning */
       bcmx_port_learn_modify (lport, BCM_PORT_LEARN_CPU, BCM_PORT_LEARN_ARL);
#endif /* HAVE_L2LERN */

        /* Enable BPDU. */
        bcmx_port_bpdu_enable_set (lport, 1);

        /* Control flooding to the CPU. */
        bcmx_lport_to_unit_port (lport, &unit, &port);
        ret = bcm_port_flood_block_set (unit, port, CMIC_PORT(unit),
					BCM_PORT_FLOOD_BLOCK_BCAST
					| BCM_PORT_FLOOD_BLOCK_UNKNOWN_UCAST
					| BCM_PORT_FLOOD_BLOCK_UNKNOWN_MCAST);
        if (ret < 0)
           HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Port flood blocking failed.\n");

	/* Set this port to disable by default. */
	bcmx_stg_default_get (&stg);
	bcmx_stg_stp_set (stg, lport, BCM_STG_STP_BLOCK);
      }
      break;
    case HSL_IF_SWITCH_L3:
      {
	/* Enable learning. */
	bcmx_port_learn_modify (lport, BCM_PORT_LEARN_ARL, 0);

#ifdef HAVE_L2LERN
       /* Enable cpu based learning */
       bcmx_port_learn_modify (lport, BCM_PORT_LEARN_CPU, BCM_PORT_LEARN_ARL);
#endif /* HAVE_L2LERN */

        /* Delete addresses learn't from this port. */
        bcmx_l2_addr_delete_by_port (lport, 0);
	
        /* Enable BPDU for EAPOL and LACP. */
        bcmx_port_bpdu_enable_set (lport, 1);

        /* Control flooding to the CPU. */
        bcmx_lport_to_unit_port (lport, &unit, &port);
        ret = bcm_port_flood_block_set (unit, port, CMIC_PORT(unit),
					BCM_PORT_FLOOD_BLOCK_BCAST
					| BCM_PORT_FLOOD_BLOCK_UNKNOWN_UCAST
					| BCM_PORT_FLOOD_BLOCK_UNKNOWN_MCAST);
        if (ret < 0)
           HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Port flood blocking failed.\n");

	/* Set this port to forward. */
	bcmx_stg_default_get (&stg);
	bcmx_stg_stp_set (stg, lport, BCM_STG_STP_FORWARD);
      }
      break;
    default:
      break;

    }

  HSL_FN_EXIT (0);
}

/* 
   Port mirror init.
*/
int
hsl_bcm_port_mirror_init (void)
{
  int ret;

  HSL_FN_ENTER();

  /* Set mode. */
#ifdef HAVE_L3
  ret = bcmx_mirror_mode_set (BCM_MIRROR_L2_L3);
#else /* HAVE_L3 */
  ret = bcmx_mirror_mode_set (BCM_MIRROR_L2);
#endif /* HAVE_L3 */
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port mirroring mode to L2/L3\n");
      HSL_FN_EXIT (-1);
    }
  HSL_FN_EXIT(0);
}

/*
  Port mirror deinit. 
*/
int
hsl_bcm_port_mirror_deinit (void)
{
  HSL_FN_ENTER();
  bcmx_mirror_mode_set(BCM_MIRROR_DISABLE);
  HSL_FN_EXIT(0);
}

/*
  Port mirror set.
*/
int
hsl_bcm_port_mirror_set (struct hsl_if *to_ifp, struct hsl_if *from_ifp, enum hal_port_mirror_direction direction)
{
  struct hsl_bcm_if *to_bcmifp, *from_bcmifp;
  int ret;
  bcmx_lport_t to_lport, from_lport;
  int mirror_flags = 0;
  HSL_FN_ENTER ();

  if (to_ifp->type != HSL_IF_TYPE_L2_ETHERNET 
      || from_ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    HSL_FN_EXIT (STATUS_WRONG_PARAMS);

  to_bcmifp = to_ifp->system_info;
  if (! to_bcmifp)
    HSL_FN_EXIT (STATUS_WRONG_PARAMS);
  
  to_lport = to_bcmifp->u.l2.lport;

  from_bcmifp = from_ifp->system_info;
  if (! from_bcmifp)
    HSL_FN_EXIT (STATUS_WRONG_PARAMS);

  from_lport = from_bcmifp->u.l2.lport;

  /* Set mirroring directions. */
  if (direction & HAL_PORT_MIRROR_DIRECTION_TRANSMIT)
    {
		mirror_flags |= BCM_MIRROR_PORT_EGRESS;
    }
  if (direction & HAL_PORT_MIRROR_DIRECTION_RECEIVE)
    {
		mirror_flags |= BCM_MIRROR_PORT_INGRESS;
    }
  ret = bcmx_mirror_port_set(from_lport, to_lport, mirror_flags);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port mirrored port to %s\n", to_ifp->name);
      HSL_FN_EXIT (-1);
    }
  HSL_FN_EXIT (0);

  #if 0
   /* Set mirrored to port. */
  ret = bcmx_mirror_to_set (to_lport);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port mirrored port to %s\n", to_ifp->name);
      HSL_FN_EXIT (-1);
    }

  /* Set mirroring directions. */
  if (direction & HAL_PORT_MIRROR_DIRECTION_TRANSMIT)
    {
      ret = bcmx_mirror_egress_set (from_lport, 1);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port mirror for port %s transmit\n", from_ifp->name);
	}
    }
  if (direction & HAL_PORT_MIRROR_DIRECTION_RECEIVE)
    {
      ret = bcmx_mirror_ingress_set (from_lport, 1);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port mirror for port %s receive\n", from_ifp->name);
	}
    }
  
  HSL_FN_EXIT (0);
#endif
}

/*
  Port mirror unset.
*/
int
hsl_bcm_port_mirror_unset (struct hsl_if *to_ifp, struct hsl_if *from_ifp, enum hal_port_mirror_direction direction)
{
  struct hsl_bcm_if *to_bcmifp, *from_bcmifp;
  int ret;
  bcmx_lport_t to_lport, from_lport;
  int mirror_flags = 0;
  
  HSL_FN_ENTER ();

  if (to_ifp->type != HSL_IF_TYPE_L2_ETHERNET 
      || from_ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    HSL_FN_EXIT (STATUS_WRONG_PARAMS);

  to_bcmifp = to_ifp->system_info;
  if (! to_bcmifp)
    HSL_FN_EXIT (STATUS_WRONG_PARAMS);

  to_lport = to_bcmifp->u.l2.lport;

  from_bcmifp = from_ifp->system_info;
  if (! from_bcmifp)
    HSL_FN_EXIT (STATUS_WRONG_PARAMS);

  from_lport = from_bcmifp->u.l2.lport;

  /* Set mirroring directions. */
  if (direction & HAL_PORT_MIRROR_DIRECTION_TRANSMIT)
    {
		mirror_flags &= ~BCM_MIRROR_PORT_EGRESS;
    }
  if (direction & HAL_PORT_MIRROR_DIRECTION_RECEIVE)
    {
		mirror_flags &= ~BCM_MIRROR_PORT_INGRESS;
    }
  ret = bcmx_mirror_port_set(from_lport, to_lport, mirror_flags);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't unset port mirrored port to %s\n", to_ifp->name);
      HSL_FN_EXIT (-1);
    }
  HSL_FN_EXIT (0);


 #if 0
  /* Set mirroring directions. */
  if (direction & HAL_PORT_MIRROR_DIRECTION_TRANSMIT)
    {
      ret = bcmx_mirror_egress_set (from_lport, 0);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't unset port mirror for port %s transmit\n", from_ifp->name);
	}
    }
  if (direction & HAL_PORT_MIRROR_DIRECTION_RECEIVE)
    {
      ret = bcmx_mirror_ingress_set (from_lport, 0);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't unset port mirror for port %s receive\n", from_ifp->name);
	}
    }
  
  HSL_FN_EXIT (0);
#endif
}

/* Delete secondary HW addresses for a interface.

   Parameters:
   IN -> ifp - interface pointer
   IN -> hwaddrlen - address length
   IN -> num - number of secondary addresses
   IN -> addresses - array of secondary addresses

   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_hw_if_secondary_hwaddrs_delete (struct hsl_if *ifp, int hwaddrlen, int num, u_char **addresses)
{
  struct hsl_bcm_if *bcmifp;
  int ret;
  int i;

  HSL_FN_ENTER ();

  /* Sanity check. */
  if (ifp == NULL)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Invalid parameter\n");
      HSL_FN_EXIT (-1);
    }

  /* Hardware interface. */
  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (bcmifp == NULL)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware L3 interface not found for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

#ifdef HAVE_L3
  /* VID is assigned for this interface. Just create a L3 interface for
     ingress L3 processing to occur.
     NOTE: The interface index is not remembered as it is not required. */
  for (i = 0; i < num; i++)
    {
      /* Delete L3 interfaces. */
      ret = _hsl_bcm_if_l3_intf_delete_by_mac_and_vid (ifp, addresses[i], IFP_IP(ifp).vid);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
		   "  Error deleting L3 interface from hardware\n");
	}
    }
#endif /* HAVE_L3 */

  HSL_FN_EXIT (0);
}

/* Set secondary HW addresses for a interface.

   Parameters:
   IN -> ifp - interface pointer
   IN -> hwaddrlen - address length
   IN -> num - number of secondary addresses
   IN -> addresses - array of secondary addresses
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_hw_if_secondary_hwaddrs_set (struct hsl_if *ifp, int hwaddrlen, int num, u_char **addresses)
{
  struct hsl_bcm_if *bcmifp;
  bcmx_l3_intf_t intf;
  int ret;
  int i;

  HSL_FN_ENTER ();

  /* Sanity check. */
  if (ifp == NULL || addresses == NULL)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Invalid parameter\n");
      HSL_FN_EXIT (-1);
    }

  /* Hardware interface. */
  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (bcmifp == NULL)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware L3 interface not found for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

#ifdef HAVE_L3
  /* VID is assigned for this interface. Just create a L3 interface for
     ingress L3 processing to occur.
     NOTE: The interface index is not remembered as it is not required. */
  if (ifp->flags & IFF_UP)
    {
      for (i = 0; i < num; i++)
	{
	  /* Create L3 interface. */
          ret = _hsl_bcm_if_l3_intf_create (ifp, &intf, IFP_IP(ifp).vid, addresses[i], IFP_IP(ifp).mtu, ifp->fib_id);
	  if (ret < 0)
	    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Failed adding secondary hardware address %s\n", ifp->name);
	      goto ERR;
	    }
	}
    }
#endif /* HAVE_L3 */

  HSL_FN_EXIT (0);

 ERR:

  /* Delete all added interface aka rollback. */
  hsl_bcm_hw_if_secondary_hwaddrs_delete (ifp, hwaddrlen, num, addresses);

  HSL_FN_EXIT (-1);
}

/* Add secondary HW addresses for a interface.

   Parameters:
   IN -> ifp - interface pointer
   IN -> hwaddrlen - address length
   IN -> num - number of secondary addresses
   IN -> addresses - array of secondary addresses
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_hw_if_secondary_hwaddrs_add (struct hsl_if *ifp, int hwaddrlen, int num, u_char **addresses)
{
  int ret;

  HSL_FN_ENTER ();

  ret = hsl_bcm_hw_if_secondary_hwaddrs_set (ifp, hwaddrlen, num, addresses);

  HSL_FN_EXIT (ret);
}



#ifdef HAVE_MPLS
int
hsl_bcm_if_mpls_up (struct hsl_if *ifp)
{
  bcmx_l3_intf_t intf;
  struct hsl_bcm_if *bcmifp;
  struct hsl_bcm_if *bcmifpc;
  struct hsl_if *ifpc;
  int ret;

  /* Initialize interface. */
  bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  intf.l3a_vrf = (bcm_vrf_t)ifp->fib_id;
  
  /* Set VID. */
  intf.l3a_vid = bcm_mpls_vlan->vid;
  
  /* Set MAC. */
  memcpy (intf.l3a_mac_addr, ifp->u.mpls.mac, sizeof (bcm_mac_t));
  
  /* Set MTU. */
  intf.l3a_mtu = 1500;
  
  /* Configure a L3 MPLS interface in BCM. */
  ret = bcmx_l3_intf_create (&intf);
  if (ret < 0)
    {
      return -1;
    }

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    return -1;

  /* Set ifindex. */
  bcmifp->u.mpls.ifindex = intf.l3a_intf_id;

  ifpc = hsl_ifmgr_get_first_L2_port (ifp);
  if (! ifpc)
    return -1;

  bcmifpc = (struct hsl_bcm_if *)ifpc->system_info;
  if (! bcmifpc)
    return -1;

  if (ifpc->type == HSL_IF_TYPE_L2_ETHERNET) 
    {
      /* Add port to VLAN. */
      ret = hsl_bcm_add_port_to_vlan (bcm_mpls_vlan->vid, bcmifpc->u.l2.lport, 0);
      if (ret < 0)
        {
          HSL_IFMGR_IF_REF_INC (ifpc);
          return ret;
        }

      HSL_IFMGR_IF_REF_INC (ifpc);
    }

  return 0;
}


/* Create MPLS interface.

Parameters:
IN -> ifp - interface pointer
IN -> unsed - unused parameter
     
Returns:
HW MPLS interface pointer as void *
NULL on error
*/
void *
hsl_bcm_if_mpls_configure (struct hsl_if *ifp, void *data)
{
  int ret = -1;
  struct hsl_bcm_if *bcmifp;

  HSL_FN_ENTER ();

  /* Create the structure to store BCM L3 interface data. */
  bcmifp = hsl_bcm_if_alloc ();
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Out of memory for allocating hardware MPLS interface\n");
      HSL_FN_EXIT (NULL);
    }

  /* Set type as IP. */
  bcmifp->type = HSL_BCM_IF_TYPE_MPLS;

  /* Not a trunk. */
  bcmifp->trunk_id = -1;
  
  if (ifp->flags & IFF_UP)
    {
      ret = hsl_bcm_if_mpls_up (ifp);
      if (ret < 0)
	HSL_FN_EXIT (NULL);
    }

  HSL_FN_EXIT (bcmifp);
}

/* 
   Delete L3 interface.

   Parameters:
   IN -> ifp - interface pointer
   
   Returns:
   0 on success
   < 0 on error
*/
int hsl_bcm_if_mpls_unconfigure (struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;
  int ret;
  bcmx_l3_intf_t intf;

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware L3 interface not found for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  if (ifp->type != HSL_IF_TYPE_MPLS)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Invalid interface type fpr hardware L3 unconfiguration for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  if (bcmifp->u.mpls.ifindex > 0)
    {
      /* Initialize interface. */
      bcmx_l3_intf_t_init (&intf);

      /* Set fib id */
      intf.l3a_vrf = (bcm_vrf_t)ifp->fib_id;

      intf.l3a_intf_id = bcmifp->u.mpls.ifindex;

      /* Destroy the L3 interface. */
      ret = bcmx_l3_intf_delete (&intf);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
              "  Error deleting MPLS interface %d from hardware\n", bcmifp->u.mpls.ifindex);  
        }

      bcmifp->u.mpls.ifindex = -1;
    }

  /* Free HW ifp. */
  hsl_bcm_if_free (bcmifp);
  ifp->system_info = NULL;

  HSL_FN_EXIT (0);
}
#endif /* HAVE_MPLS */




/* 
   Initialize HSL BCM callbacks.
*/
int
hsl_if_hw_cb_register (void)
{
  HSL_FN_ENTER ();

  BCMIF_CB(hw_if_init)                     = NULL;
  BCMIF_CB(hw_if_deinit)                   = NULL;
  BCMIF_CB(hw_if_dump)                     = hsl_bcm_if_dump;
  BCMIF_CB(hw_l2_unregister)               = hsl_bcm_if_l2_unregister;
  BCMIF_CB(hw_l2_if_flags_set)             = hsl_bcm_if_l2_flags_set;
  BCMIF_CB(hw_l2_if_flags_unset)           = hsl_bcm_if_l2_flags_unset;

  BCMIF_CB(hw_if_post_configure)           = hsl_bcm_if_post_configure;
  BCMIF_CB(hw_if_pre_unconfigure)          = hsl_bcm_if_pre_unconfigure;

#ifdef HAVE_L3 
  BCMIF_CB(hw_l3_if_configure)             = hsl_bcm_if_l3_configure;
  BCMIF_CB(hw_l3_if_unconfigure)           = hsl_bcm_if_l3_unconfigure;
  BCMIF_CB(hw_if_hwaddr_set)               = hsl_bcm_if_hwaddr_set;
  BCMIF_CB(hw_if_secondary_hwaddrs_delete) = hsl_bcm_hw_if_secondary_hwaddrs_delete;
  BCMIF_CB(hw_if_secondary_hwaddrs_add)    = hsl_bcm_hw_if_secondary_hwaddrs_add;
  BCMIF_CB(hw_if_secondary_hwaddrs_set)    = hsl_bcm_hw_if_secondary_hwaddrs_set;
  BCMIF_CB(hw_l3_if_flags_set)             = hsl_bcm_if_l3_flags_set;
  BCMIF_CB(hw_l3_if_flags_unset)           = hsl_bcm_if_l3_flags_unset;
  BCMIF_CB(hw_l3_if_address_add)           = hsl_bcm_if_l3_address_add;
  BCMIF_CB(hw_l3_if_address_delete)        = hsl_bcm_if_l3_address_delete;
  BCMIF_CB(hw_l3_if_bind_fib)              = hsl_bcm_if_l3_bind_fib;
  BCMIF_CB(hw_l3_if_unbind_fib)            = hsl_bcm_if_l3_unbind_fib;
#endif /* HAVE_L3 */
  BCMIF_CB(hw_set_switching_type)          = hsl_bcm_if_set_switching_type;
  BCMIF_CB(hw_if_mtu_set)                  = hsl_bcm_if_mtu_set;
  BCMIF_CB(hw_if_l3_mtu_set)               = NULL;
  BCMIF_CB(hw_if_packet_types_set)         = hsl_bcm_if_packet_types_set;
  BCMIF_CB(hw_if_packet_types_unset)       = hsl_bcm_if_packet_types_unset;
  BCMIF_CB(hw_if_get_counters)             = hsl_bcm_get_if_counters;
  BCMIF_CB(hw_if_clear_counters)           = hsl_bcm_clear_if_counters;
  BCMIF_CB(hw_if_duplex_set)               = hsl_bcm_if_duplex_set;
  BCMIF_CB(hw_if_autonego_set)             = hsl_bcm_if_autonego_set;
  BCMIF_CB(hw_if_bandwidth_set)            = hsl_bcm_if_bandwidth_set;
  BCMIF_CB(hw_if_init_portmirror)          = hsl_bcm_port_mirror_init;
  BCMIF_CB(hw_if_deinit_portmirror)        = hsl_bcm_port_mirror_deinit;
  BCMIF_CB(hw_if_set_portmirror)           = hsl_bcm_port_mirror_set;
  BCMIF_CB(hw_if_unset_portmirror)         = hsl_bcm_port_mirror_unset;
#ifdef HAVE_MPLS
  BCMIF_CB(hw_mpls_if_configure) = hsl_bcm_if_mpls_configure;
  BCMIF_CB(hw_mpls_if_unconfigure) = hsl_bcm_if_mpls_unconfigure;
#endif /* HAVE_MPLS */
#ifdef HAVE_LACPD
  BCMIF_CB(hw_if_lacp_agg_add)             = hsl_bcm_aggregator_add;
  BCMIF_CB(hw_if_lacp_agg_del)             = hsl_bcm_aggregator_del;
  BCMIF_CB(hw_if_lacp_agg_port_attach)     = hsl_bcm_aggregator_port_add;
  BCMIF_CB(hw_if_lacp_agg_port_detach)     = hsl_bcm_aggregator_port_del;
  BCMIF_CB(hw_if_lacp_psc_set)             = hsl_bcm_lacp_psc_set;
  BCMIF_CB(hw_if_lacp_nuc_psc_set)         = hsl_bcm_lacp_nuc_psc_set;
#endif /* HAVE_LACPD */ 

  /* Register with interface manager. */
  hsl_ifmgr_set_hw_callbacks (&hsl_bcm_if_callbacks);

  HSL_FN_EXIT (0);
}

/* 
   Deinitialize HSL BCM callbacks.
*/
int
hsl_if_hw_cb_unregister (void)
{
  HSL_FN_ENTER ();

  /* Unregister with interface manager. */
  hsl_ifmgr_unset_hw_callbacks ();

  HSL_FN_EXIT (0);
}


/* Translate bcm 64 bit structure to ipi format.

Parameters:
IN -> src - Source value
OUT-> dst - counters for interface.  
   
Returns:
0 on success
< 0 on error   
*/
int
hsl_bcm_copy_64_int(long long unsigned int *src,ut_int64_t *dst)
{
	
  long long unsigned int tmp;  
  dst->l[0] = (*src & 0xffffffff);
  tmp = (*src >>1);
  dst->l[1] = (tmp >> 31);
  
  return 0;
}

/* Convert bcm ipi format to 64 bit structure.

Parameters:
IN -> src - Source value

Returns:
unit64 value
*/
long long unsigned int
hsl_bcm_convert_to_64_int(ut_int64_t *src)
{
  long long unsigned int tmp = 0,dst = 0;
  dst = ( src->l[0] & 0xffffffff);
  tmp = (src->l[1] << 1);
  dst = (tmp << 31) + (dst);
  
  return dst;
}

