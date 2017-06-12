/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"

#include "bcm_incl.h"

#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_avl.h"
#include "hsl_logger.h"
#include "hsl_error.h"
#include "hsl_table.h"
#include "hsl_ether.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_bcm_if.h"
#include "hsl_bcm_ifmap.h"
#include "hsl_fib.h"
#include "hsl_fib_hw.h"
#ifdef HAVE_L2
#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"
#include "hsl_vlan.h"
#include "hsl_bridge.h"
#endif /* HAVE_L2 */
#ifdef HAVE_MPLS
#include "hsl_mpls.h"
#include "hsl_bcm_mpls.h"
#endif /* HAVE_MPLS */

static struct hsl_fib_hw_callbacks hsl_bcm_fib_callbacks;
static int _hsl_bcm_nh_get (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh, bcmx_l3_host_t *ip);

int _hsl_l3_route_clean(bcmx_l3_route_t *route)
{
	bcmx_l3_egress_t egress_object;
	bcm_if_t egr_objs[8] = {0};
	int count = 8, i;
	int rv;

	rv = bcmx_l3_route_delete (route);
	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "bcmx_l3_route_delete object_id = %d, rv = %d\n", route->l3a_intf, rv);
	
	rv = bcmx_l3_egress_get(route->l3a_intf, &egress_object);
	if(rv == BCM_E_NONE){
		bcmx_l3_egress_destroy(route->l3a_intf);
	} else {
		rv = bcmx_l3_egress_multipath_get(route->l3a_intf, count, egr_objs, &count);
		if(rv == BCM_E_NONE){
			bcmx_l3_egress_multipath_destroy(route->l3a_intf);
			for ( i = 0; i < count; i++){
				rv = bcmx_l3_egress_destroy(egr_objs[i]);
				HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "bcmx_l3_egress_destroy object_id = %d, rv = %d\n", egr_objs[i], rv);
			}
		}
	}
	return BCM_E_NONE;
}

int hsl_bcmx_l3_route_add(bcmx_l3_route_t *route)
{
	bcmx_l3_egress_t egress_object;
	int egress_flags;
	bcm_if_t object_id, multipath_intf = 0;
	bcmx_l3_route_t route_find;
	int rv;

	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_bcmx_l3_route_add (%x/%x)%x, vlan=%d, intf=%d, flags=%x\n", 
		route->l3a_subnet, route->l3a_ip_mask, route->l3a_nexthop_ip, route->l3a_vid, route->l3a_intf, route->l3a_flags);

	bcmx_l3_egress_t_init(&egress_object);
	memcpy (egress_object.mac_addr, route->l3a_nexthop_mac, HSL_ETHER_ALEN);
	egress_object.vlan = route->l3a_vid;
	egress_object.intf = route->l3a_intf;
	egress_object.trunk = route->l3a_trunk;
	egress_object.lport = route->l3a_lport;
	egress_object.flags = route->l3a_flags;

	rv = bcmx_l3_egress_find(&egress_object, &object_id);
	if (rv < 0)	{
		object_id = 0;
		egress_flags = egress_object.flags;
		rv = bcmx_l3_egress_create(egress_flags, &egress_object, &object_id);
		if (rv < 0)	{
			HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR,"bcmx_l3_egress_create ERROR ret = %d\n", rv);
			return rv;
		}
	} 

	memcpy(&route_find, route, sizeof(route_find));

	rv = bcmx_l3_route_get(&route_find);
	if(rv == BCM_E_NONE){
		rv = bcmx_l3_egress_get(route_find.l3a_intf, &egress_object);
		if(rv == BCM_E_NONE){
			bcm_if_t object_id_tmp;

			if ( (egress_object.mac_addr[0] == 0) &&
				(egress_object.mac_addr[1] == 0) &&
				(egress_object.mac_addr[2] == 0) &&
				(egress_object.mac_addr[3] == 0) &&
				(egress_object.mac_addr[4] == 0) &&
				(egress_object.mac_addr[5] == 0)){
				HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "remove old route, object_id = %d\n", route_find.l3a_intf);
				_hsl_l3_route_clean(&route_find);
				
			} else {

				HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ecmp change old route, object_id = %d\n", route_find.l3a_intf);

				if (route_find.l3a_intf == object_id)
					return BCM_E_NONE;
				
				object_id_tmp = route_find.l3a_intf;
				egress_flags = 0;
				rv = bcmx_l3_egress_multipath_create(egress_flags, 1, &object_id_tmp, &multipath_intf);
				HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "bcmx_l3_egress_multipath_create, multipath_intf = %d, rv = %d\n", multipath_intf, rv);
				if (rv < 0) {
					bcmx_l3_egress_destroy(object_id);
					return BCM_E_NONE;
				}

				bcmx_l3_route_delete (&route_find);
				route_find.l3a_intf = multipath_intf;
				route_find.l3a_flags |= BCM_L3_MULTIPATH;
				rv = bcmx_l3_route_add (&route_find);
			}
		} else {
			bcm_if_t egr_objs[8] = {0};
			int count = 8, i;
			
			multipath_intf = route_find.l3a_intf;
			HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "old route multipath_intf = %d\n", multipath_intf);

			rv = bcmx_l3_egress_multipath_get(multipath_intf, count, egr_objs, &count);
			if(rv == BCM_E_NONE){
				for ( i = 0; i < count; i++){
					if (object_id == egr_objs[i]){
						HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "find exist egress object_id = %\n", object_id);
						return BCM_E_NONE;
					}
				}
			} else {
				HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "%d is invalid obj id\n", multipath_intf);
				return -1;
			}
		}
	}

	if (multipath_intf) {
		rv = bcmx_l3_egress_multipath_add(multipath_intf, object_id);
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "bcmx_l3_egress_multipath_add multipath_intf = %d, object_id = %d, rv = %d\n", multipath_intf, object_id, rv);
		return rv;
	}
	
	route->l3a_intf = object_id;

	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "bcmx_l3_egress_create object_id = %d\n", object_id);

	rv = bcmx_l3_route_add (route);

	if(rv < 0){
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR,"bcmx_l3_route_add ERROR ret = %d\n", rv);
		bcmx_l3_egress_destroy(object_id);
		return rv;
	}

	return rv;
}

int hsl_bcmx_l3_route_delete(bcmx_l3_route_t *route)
{
	int rv;
	
	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_bcmx_l3_route_delete (%x/%x)%x, vlan=%d, intf=%d, flags=%x\n", 
		route->l3a_subnet, route->l3a_ip_mask, route->l3a_nexthop_ip, route->l3a_vid, route->l3a_intf, route->l3a_flags);

	rv = bcmx_l3_route_get(route);
	if(rv == BCM_E_NONE){
		_hsl_l3_route_clean(route);
	} else {
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_bcmx_l3_route_delete (%x/%x)%x, vlan=%d, intf=%d, flags=%x, not found\n", 
			route->l3a_subnet, route->l3a_ip_mask, route->l3a_nexthop_ip, route->l3a_vid, route->l3a_intf, route->l3a_flags);

	}

	return BCM_E_NONE;
}

int hsl_bcmx_l3_host_add(bcmx_l3_host_t *host, void *sys_info)
{
	bcmx_l3_egress_t egress_object;
	int egress_flags;
	bcm_if_t object_id;
	bcmx_l3_host_t host_find;
	int rv;

	bcmx_l3_egress_t_init(&egress_object);
	memcpy (egress_object.mac_addr, host->l3a_nexthop_mac, HSL_ETHER_ALEN);
	egress_object.intf = host->l3a_intf;
	egress_object.trunk = host->l3a_trunk;
	egress_object.lport = host->l3a_lport;
	egress_object.flags = host->l3a_flags;
	
	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_bcmx_l3_host_add (%x) intf = %d, flags = %x\n", host->l3a_ip_addr, host->l3a_intf, host->l3a_flags);

	memcpy(&host_find, host, sizeof(host_find));
	rv = bcmx_l3_host_find(&host_find);
	if(rv == BCM_E_NONE){
		rv = bcmx_l3_host_delete (&host_find);
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "remove old host, object_id = %d\n", host_find.l3a_intf);
		bcmx_l3_egress_destroy(host_find.l3a_intf);
	}

	rv = bcmx_l3_egress_find(&egress_object, &object_id);
	if (rv < 0)	{
		object_id = 0;
		egress_flags = egress_object.flags;
		rv = bcmx_l3_egress_create(egress_flags, &egress_object, &object_id);
		if (rv < 0)	{
			HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR,"bcmx_l3_egress_create ERROR ret = %d\n", rv);
			return rv;
		}
	} 
	host->l3a_intf = object_id;

	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "bcmx_l3_egress_create object_id = %d\n", object_id);

	rv = bcmx_l3_host_add (host);

	if(rv < 0){
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR,"bcmx_l3_host_add ERROR ret = %d\n", rv);
		bcmx_l3_egress_destroy(object_id);
		return rv;
	}

	if(sys_info) {
		*(bcm_if_t*)sys_info = object_id;
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "object_id = %d saved\n", object_id);
	}

	return rv;
	
}

int hsl_bcmx_l3_host_delete(bcmx_l3_host_t *host)
{
	int rv;

	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_bcmx_l3_host_delete (%x) flags = %x\n", host->l3a_ip_addr, host->l3a_flags);

	rv = bcmx_l3_host_find(host);
	if(rv == BCM_E_NONE){
		rv = bcmx_l3_host_delete (host);
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "bcmx_l3_host_delete object_id = %d, rv = %d\n", host->l3a_intf, rv);
		bcmx_l3_egress_destroy(host->l3a_intf);
	} else {
		HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "ERROR: hsl_bcmx_l3_host_delete (%x) flags = %x, not found\n", host->l3a_ip_addr, host->l3a_flags);

	}

	return rv;
}

/* 
   Initialization. 
*/
int 
hsl_bcm_fib_init (hsl_fib_id_t fib_id)
{
  return 0;
}

/* 
   Deinitialization. 
*/
int 
hsl_bcm_fib_deinit (hsl_fib_id_t fib_id)
{
  return 0;
}

/* 
   Dump. 
*/
void 
hsl_bcm_fib_dump (hsl_fib_id_t fib_id)
{
  return;
}
#ifdef HAVE_IPV6
/* 
   Fill up bcmx host add/delete request structure from rnp, nh.
*/
static int
_hsl_bcm_get_host (hsl_fib_id_t fib_id, hsl_prefix_t *p, struct hsl_nh_entry *nh,
		   bcmx_l3_host_t *ip, int connected)
{
  int ret;

  if (((p->family == AF_INET) && (nh && (nh->rn->p.family != AF_INET)))
#ifdef HAVE_IPV6
      || ((p->family == AF_INET6) && (nh && (nh->rn->p.family != AF_INET6)))
#endif /* HAVE_IPV6 */
      )
    return HSL_FIB_ERR_INVALID_PARAM;

  if (nh)
    {
      ret = _hsl_bcm_nh_get (fib_id, nh, ip);
      return ret;
    }

  /* No nexthop. */
  /* Initialize route. */
  bcmx_l3_host_t_init (ip);

  ip->l3a_vrf = (bcm_vrf_t)fib_id;

  if (p->family == AF_INET)
    {
      ip->l3a_ip_addr = ntohl(p->u.prefix4);
    }
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    { 
      BCM_IP6_WORD(ip->l3a_ip6_addr, 0) = p->u.prefix6.word[0];
      BCM_IP6_WORD(ip->l3a_ip6_addr, 1) = p->u.prefix6.word[1];
      BCM_IP6_WORD(ip->l3a_ip6_addr, 2) = p->u.prefix6.word[2];
      BCM_IP6_WORD(ip->l3a_ip6_addr, 3) = p->u.prefix6.word[3];
                                                                                
      ip->l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  ip->l3a_lport = BCMX_LPORT_LOCAL_CPU;
  ip->l3a_flags |= BCM_L3_L2TOCPU; /* To get original headers. */
  if (connected)
    {
      ip->l3a_flags |= BCM_L3_DEFIP_LOCAL;
    }
  
  return 0;
}
#endif
/* 
   Fill up bcmx route add/delete request structure. 
*/
static int
_hsl_bcm_get_route (hsl_fib_id_t fib_id, struct hsl_route_node *rnp, struct hsl_nh_entry *nh , bcmx_l3_route_t *r, int oper)
{
  hsl_ipv4Address_t mask;
  struct hsl_bcm_if *bcmifp;
  struct hsl_if *ifp;
  struct hsl_nh_entry *nh1;
  struct hsl_nh_entry_list_node *nhlist;
  struct hsl_prefix_entry *pe;
  int count = 0;
#ifdef HAVE_L2
  int tagged = 0;
  bcmx_l2_addr_t l2addr;
  struct hsl_if_list *node = NULL;
#endif /* HAVE_L2 */
	int rv;

  pe = rnp->info;

  if (! pe || ! nh)
    return HSL_FIB_ERR_INVALID_PARAM;

  if (((rnp->p.family == AF_INET) && (nh->rn->p.family != AF_INET))
#ifdef HAVE_IPV6
      || ((rnp->p.family == AF_INET6) && (nh->rn->p.family != AF_INET6))
#endif /* HAVE_IPV6 */
      )
    return HSL_FIB_ERR_INVALID_PARAM;

  /* Initialize route. */
  bcmx_l3_route_t_init (r);

  r->l3a_vrf = (bcm_vrf_t)fib_id;

  /* Set hit bit for updation. */
  r->l3a_flags |= BCM_L3_HIT;

  /* Set VID. */
#ifdef HAVE_MPLS
  if (nh->ifp->type == HSL_IF_TYPE_MPLS)
    r->l3a_vid = nh->ifp->u.mpls.vid;
  else
#endif /* HAVE_MPLS */
    r->l3a_vid = nh->ifp->u.ip.vid;
  
  /* Check for ECMP. */
  nhlist = pe->nhlist;
  while (nhlist)
    {
      if (nhlist->entry)
	{
          nh1 = nhlist->entry;
          if (nh1)
            {
              if (CHECK_FLAG(nh1->flags, HSL_NH_ENTRY_VALID))
	        count++;
            }
	}
      nhlist = nhlist->next;
    } 
  //if (count > 1)
  //  r->l3a_flags |= BCM_L3_MULTIPATH;
 
  /* Set prefix. */
  if (rnp->p.family == AF_INET)
    {
      r->l3a_subnet = ntohl(rnp->p.u.prefix4);
      hsl_masklen2ip (rnp->p.prefixlen, &mask);
      r->l3a_ip_mask = ntohl(mask);
    }
#ifdef HAVE_IPV6
  else if (rnp->p.family == AF_INET6)
    {
      BCM_IP6_WORD(r->l3a_ip6_net, 0) = rnp->p.u.prefix6.word[0];
      BCM_IP6_WORD(r->l3a_ip6_net, 1) = rnp->p.u.prefix6.word[1];
      BCM_IP6_WORD(r->l3a_ip6_net, 2) = rnp->p.u.prefix6.word[2];
      BCM_IP6_WORD(r->l3a_ip6_net, 3) = rnp->p.u.prefix6.word[3];

      /* Get mask. */
      bcm_ip6_mask_create (r->l3a_ip6_mask, rnp->p.prefixlen);

      /* Set flags for IPv6. */
      r->l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  /* Set nexthop. */
  if (rnp->p.family == AF_INET)
    {
      r->l3a_nexthop_ip = ntohl(nh->rn->p.u.prefix4);
    }

  /* Set nexthop MAC. */
  memcpy (r->l3a_nexthop_mac, nh->mac, HSL_ETHER_ALEN);

  /* Interface valid? */
  if (nh->ifp->type != HSL_IF_TYPE_IP
#ifdef HAVE_MPLS 
      && nh->ifp->type != HSL_IF_TYPE_MPLS
#endif /* HAVE_MPLS */
      )
    return -1;

  bcmifp = nh->ifp->system_info;
  if (! bcmifp)
    return -1;

  /* Set L3 interface. */
#ifdef HAVE_MPLS
  if (nh->ifp->type == HSL_IF_TYPE_MPLS)
    r->l3a_intf = bcmifp->u.mpls.ifindex;
  else
#endif /* HAVE_MPLS */
  r->l3a_intf = bcmifp->u.l3.ifindex;

  if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
    {
      /* Egress is a trunk. Set the trunk id. */
      r->l3a_flags |= BCM_L3_TGID;
      r->l3a_trunk = bcmifp->trunk_id;
    }
  else
    {
      /* Egress is a non-trunk port. */
      r->l3a_flags &= ~BCM_L3_TGID;
    }


    /* 
     * If we are planning to detele a route we don't need any extra info. 
     */
    if(HSL_OPER_DELETE == oper)
      return 0;

#ifdef HAVE_L2
  if (! memcmp (nh->ifp->name, "vlan", 4))
    {

		bcmx_l3_egress_t egress_object;
		
      /* If the NH interface is a vlan IP(SVI) do a L2 lookup to find the lport. */
	  /*
      if (bcmx_l2_addr_get ((void *) nh->mac, nh->ifp->u.ip.vid, &l2addr, NULL) == 0)
	{
	  r->l3a_lport = l2addr.lport;
	}
      else
	{
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding the NH destination port from L2 table for mac(%02x%02x.%02x%02x.%02x%02x)\n", nh->mac[0], nh->mac[1], nh->mac[2], nh->mac[3], nh->mac[4], nh->mac[5]);
	    return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	}
	*/

	HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "egr obj = %d\n", *(bcm_if_t*)&(nh->system_info));
	  rv = bcmx_l3_egress_get(*(bcm_if_t*)&(nh->system_info), &egress_object);
		if(rv == BCM_E_NONE){
			r->l3a_trunk = egress_object.trunk;
			r->l3a_lport = egress_object.lport;
			if(egress_object.flags & BCM_L3_TGID)
				r->l3a_flags |= BCM_L3_TGID;
			else
				r->l3a_flags &= ~BCM_L3_TGID;
		} else
	{
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding egr obj = %d\n", *(bcm_if_t*)&(nh->system_info));
	    return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	}

	  
      /* Get information whether the port is egress tagged. */
      if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
	{
	  /* 
	     The hierarchy for this case is as follows:

	     +-----------+
	     |  vlanX.X  |
	     +-----------+
	     |
	     +-----------+
	     |   L2 agg  |
	     +-----------+
	     |
	     +-----------+
	     |    L2     |
	     +-----------+

	     For this case, get the L2 port from the lport.
	     From lport get L2 agg, 
	     From L2 agg, get the hsl_if
	     For the hsl_if, find if the VLAN is egress tagged.
	  */

	  ifp = hsl_bcm_ifmap_if_get (l2addr.lport);
	  if (! ifp)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	    }

	  /* Its a aggregate, should have only one parent. */
	  node = ifp->parent_list;	  
	  if (! node)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	    }

	  ifp = node->ifp;
	  if (! ifp)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	    }

	  tagged = hsl_vlan_get_egress_type (ifp, nh->ifp->u.ip.vid);
	  if (tagged < 0)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;    
	    }  
	}
      else
	{
	  /* 
	     This is for the following hierarchy

	     +-----------+
	     |  vlanX.X  |
	     +-----------+
	     |
	     +-----------+
	     |     L2    |
	     +-----------+
		 
	     For this case, get the L2 port.
	     From the L2 port if the VID is tagged/untagged
	  */

	  //ifp = hsl_bcm_ifmap_if_get (l2addr.lport);
	  if(egress_object.flags & BCM_L3_TGID)
        ifp = hsl_bcm_ifmap_if_get (HSL_BCM_TRUNK_2_LPORT(egress_object.trunk));
      else
        ifp = hsl_bcm_ifmap_if_get (egress_object.lport);
	  if (! ifp)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	    }

	  tagged = hsl_vlan_get_egress_type (ifp, nh->ifp->u.ip.vid);
	  if (tagged < 0)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;    
	    } 
	}

      /* Set tagged/untagged. */
      if (! tagged)
	r->l3a_flags |= BCM_L3_UNTAG;
      else
	r->l3a_flags &= ~BCM_L3_UNTAG;
    }
  else
#endif /* HAVE_L2 */
    {
      ifp = hsl_ifmgr_get_first_L2_port (nh->ifp);
      if (! ifp)
	{
	  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	  return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	}
      HSL_IFMGR_IF_REF_DEC (ifp);
	  
      /* Get the lport. */
      bcmifp = ifp->system_info;
      if (! bcmifp)
	{
	  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	  return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	}

      r->l3a_lport = bcmifp->u.l2.lport;
    
      /* Pure router port. Egress always untagged. */
      r->l3a_flags |= BCM_L3_UNTAG;
    }  

  return 0;  
}

/* 
   Add prefix. 
*/
int 
hsl_bcm_prefix_add (hsl_fib_id_t fib_id, struct hsl_route_node *rnp, struct hsl_nh_entry *nh)
{
  struct hsl_prefix_entry *pe;
  bcmx_l3_route_t r;
  //bcmx_l3_host_t ip;
  //char buf[256];
  int ret;

  pe = rnp->info;

  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_bcm_prefix_add prefix = %x, mask = %d, nh = %x\n",
  	rnp->p.u.prefix4, rnp->p.prefixlen, nh->rn->p.u.prefix4);

#ifdef HAVE_IPV6
  if (rnp->p.family == AF_INET6 && rnp->p.prefixlen == IPV6_MAX_PREFIXLEN)
    {
      ret = _hsl_bcm_get_host (fib_id, &rnp->p, nh, &ip, 0);
      if (ret < 0)
	return HSL_FIB_ERR_HW_OPERATION_FAILED;

      ret = bcmx_l3_host_add (&ip);

      if (ret < 0)
	{
	  hsl_prefix2str (&rnp->p, buf, sizeof(buf));
	  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error adding nexthop %s to hardware\n", buf);
	  return HSL_FIB_ERR_HW_OPERATION_FAILED;
	}
  
      if (pe)
	{
	  pe->flags = 0;
	  SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_IN_HW);
	}
      return 0;
    }
#endif /* HAVE_IPV6 */

  /* Map route. */
  ret = _hsl_bcm_get_route (fib_id, rnp, nh, &r, HSL_OPER_ADD);
  if (ret < 0)
    return ret;

  /* Add the route. */
  ret = hsl_bcmx_l3_route_add (&r);
  if (ret < 0)
    {
      return HSL_FIB_ERR_HW_OPERATION_FAILED;
    }

  if (pe)
    {
      pe->flags = 0;
      SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_IN_HW);
    }

  return 0;
}

/* 
   Delete prefix. 
*/
int
hsl_bcm_prefix_delete (hsl_fib_id_t fib_id, struct hsl_route_node *rnp, struct hsl_nh_entry *nh)
{
  bcmx_l3_route_t r;
  //bcmx_l3_host_t ip;
  //char buf[256];
  int ret;
  hsl_ipv4Address_t mask;
  struct hsl_prefix_entry *pe;


  pe = rnp->info;

#ifdef HAVE_IPV6
  if (rnp->p.family == AF_INET6 && rnp->p.prefixlen == IPV6_MAX_PREFIXLEN)
    {
      ret = _hsl_bcm_get_host (fib_id, &rnp->p, nh, &ip, 0);
      if (ret < 0)
	return HSL_FIB_ERR_HW_OPERATION_FAILED;

      ret = bcmx_l3_host_delete (&ip);

      if (ret < 0)
	{
	  hsl_prefix2str (&rnp->p, buf, sizeof(buf));
	  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error deleting nexthop %s to hardware\n", buf);
	  return HSL_FIB_ERR_HW_OPERATION_FAILED;
	}
  
      if (pe)
	{
	  pe->flags = 0;
	}
      return 0;
    }
#endif /* HAVE_IPV6 */


  if (nh)
    {
      ret = _hsl_bcm_get_route (fib_id, rnp, nh, &r, HSL_OPER_DELETE);
      if (ret < 0)
	return ret;
    }
  else
    {
      bcmx_l3_route_t_init (&r);

      r.l3a_vrf = (bcm_vrf_t)fib_id;

      if (rnp->p.family == AF_INET)
	{
	  /* Set prefix. */
	  r.l3a_subnet = ntohl(rnp->p.u.prefix4);
	  hsl_masklen2ip (rnp->p.prefixlen, &mask);
	  r.l3a_ip_mask = ntohl(mask);
	}
#ifdef HAVE_IPV6
      else if (rnp->p.family == AF_INET6)
	{
	  BCM_IP6_WORD(r.l3a_ip6_net, 0) = rnp->p.u.prefix6.word[0];
	  BCM_IP6_WORD(r.l3a_ip6_net, 1) = rnp->p.u.prefix6.word[1];
	  BCM_IP6_WORD(r.l3a_ip6_net, 2) = rnp->p.u.prefix6.word[2];
	  BCM_IP6_WORD(r.l3a_ip6_net, 3) = rnp->p.u.prefix6.word[3];
	  
	  /* Get mask. */
	  bcm_ip6_mask_create (r.l3a_ip6_mask, rnp->p.prefixlen);
	  
	  /* Set flags for IPv6. */
	  r.l3a_flags |= BCM_L3_IP6;
	}
#endif /* HAVE_IPV6 */
    }

  /* Add the route. */
  ret = hsl_bcmx_l3_route_delete (&r);
  if ((ret != BCM_E_NONE) && (ret != BCM_E_NOT_FOUND))
    {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error deleting DEFIP entry (%x/%x) from  hardware %d\n",
	       r.l3a_subnet, r.l3a_ip_mask, ret);
      return HSL_FIB_ERR_HW_OPERATION_FAILED;
    }

  if (! nh)
    {
      if (pe)
	{
	  pe->flags = 0;
	}
    }

  return 0;
}

/*
  Set prefix as exception to CPU.
*/
int
hsl_bcm_prefix_exception (hsl_fib_id_t fib_id, struct hsl_route_node *rnp)
{
  bcmx_l3_route_t route;
  //bcmx_l3_host_t ip;
  hsl_prefix_t *p;
  hsl_ipv4Address_t addr, mask;
  int ret;
  struct hsl_prefix_entry *pe;

  pe = rnp->info;

  p = &rnp->p;

#ifdef HAVE_IPV6
  if (rnp->p.family == AF_INET6 && rnp->p.prefixlen == IPV6_MAX_PREFIXLEN)
    {
      ret = _hsl_bcm_get_host (fib_id, &rnp->p, NULL, &ip, 0);
      if (ret < 0)
	return HSL_FIB_ERR_HW_OPERATION_FAILED;

      ret = bcmx_l3_host_add (&ip);

      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error adding connected route to hardware\n");
	  return -1;
	}
  
      if (pe)
	{
	  pe->flags = 0;
	  SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_IN_HW);
	  SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_EXCEPTION);
	}
      return 0;
    }
#endif /* HAVE_IPV6 */

  /* Initialize route. */
  bcmx_l3_route_t_init (&route);

  route.l3a_vrf = (bcm_vrf_t)fib_id;

  if (rnp->p.family == AF_INET)
    {
      hsl_masklen2ip (p->prefixlen, (hsl_ipv4Address_t *) &mask);
      addr = p->u.prefix4;
      //addr |= ~mask;
	  addr &= mask;
      route.l3a_subnet = ntohl(addr);
      route.l3a_ip_mask = ntohl(mask);
    }
#ifdef HAVE_IPV6
  else
    {
      BCM_IP6_WORD(route.l3a_ip6_net, 0) = rnp->p.u.prefix6.word[0];
      BCM_IP6_WORD(route.l3a_ip6_net, 1) = rnp->p.u.prefix6.word[1];
      BCM_IP6_WORD(route.l3a_ip6_net, 2) = rnp->p.u.prefix6.word[2];
      BCM_IP6_WORD(route.l3a_ip6_net, 3) = rnp->p.u.prefix6.word[3];
      
      /* Get mask. */
      bcm_ip6_mask_create (route.l3a_ip6_mask, rnp->p.prefixlen);
      
      /* Set flags for IPv6. */
      route.l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  /* Delete any previous route. */

  route.l3a_intf = 0; /* As we are setting the exception to CPU with BCM_L3_L2TOCPU, this can
			 be ignored, I guess. */
  route.l3a_lport = BCMX_LPORT_LOCAL_CPU;
  route.l3a_flags |= BCM_L3_DEFIP_LOCAL;
  route.l3a_flags |= BCM_L3_L2TOCPU; /* To get original headers. */
  
  /* Add connected route to prefix table. */
  ret = hsl_bcmx_l3_route_add (&route);
  if (ret < 0)
    {

      return -1;
    }

  if (pe)
    {
      SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_IN_HW);
      SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_EXCEPTION);
    }

  return 0;
}

/*
  Fill up ip host route.
*/
static int
_hsl_bcm_nh_get (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh, bcmx_l3_host_t *ip)
{
  struct hsl_bcm_if *bcmifp;
  struct hsl_if *ifp;
#ifdef HAVE_L2
  struct hsl_if_list *node = NULL;
  int tagged;
  bcmx_l2_addr_t l2addr;
#endif /* HAVE_L2 */

  if (! nh)
    return HSL_FIB_ERR_INVALID_PARAM;

  /* Initialize host route. */
  bcmx_l3_host_t_init (ip);

  ip->l3a_vrf = (bcm_vrf_t)fib_id;

  /* Set address. */
  if (nh->rn->p.family == AF_INET)
    {
      ip->l3a_ip_addr = ntohl(nh->rn->p.u.prefix4); 
    }
#ifdef HAVE_IPV6
  else if (nh->rn->p.family == AF_INET6)
    {
      BCM_IP6_WORD(ip->l3a_ip6_addr, 0) = nh->rn->p.u.prefix6.word[0];
      BCM_IP6_WORD(ip->l3a_ip6_addr, 1) = nh->rn->p.u.prefix6.word[1];
      BCM_IP6_WORD(ip->l3a_ip6_addr, 2) = nh->rn->p.u.prefix6.word[2];
      BCM_IP6_WORD(ip->l3a_ip6_addr, 3) = nh->rn->p.u.prefix6.word[3];

      /* Set flags for IPv6. */
      ip->l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  /* Set hit flags. */
  ip->l3a_flags |= BCM_L3_HIT;
 
  /* Set nexthop address. */
  memcpy (ip->l3a_nexthop_mac, nh->mac, HSL_ETHER_ALEN);

  /* Set l3_intf. */
  bcmifp = nh->ifp->system_info;
  if (! bcmifp)
    return -1;

  /* Set L3 interface. */
  ip->l3a_intf = bcmifp->u.l3.ifindex;

#ifdef HAVE_L2
  if (! memcmp (nh->ifp->name, "vlan", 4))
    {
      /* If the NH interface is a vlan IP(SVI) do a L2 lookup to find the lport. */
      if (bcmx_l2_addr_get ((void *) nh->mac, nh->ifp->u.ip.vid, &l2addr, NULL) == 0)
	{
	  ip->l3a_lport = l2addr.lport;
	}
      else
	{
	  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding the NH destination port from L2 table for mac(%02x%02x.%02x%02x.%02x%02x)\n", nh->mac[0], nh->mac[1], nh->mac[2], nh->mac[3], nh->mac[4], nh->mac[5]);
	  return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	}

      if (BCMX_LPORT_INVALID == l2addr.lport)
        ifp = hsl_bcm_ifmap_if_get (HSL_BCM_TRUNK_2_LPORT(l2addr.tgid));
      else
        ifp = hsl_bcm_ifmap_if_get (l2addr.lport);
      if (! ifp)
        {
          HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port"
                   " information for interface %s\n", nh->ifp->name);
          return HSL_FIB_ERR_HW_NH_NOT_FOUND;
        }
       
       bcmifp = ifp->system_info;
       if (! bcmifp)
         {
           HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port"
                    " information for interface %s\n", nh->ifp->name);
           return HSL_FIB_ERR_HW_NH_NOT_FOUND;
         } 
      /* Get information whether the port is egress tagged. */
      if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
	{
	  /* 
	     The hierarchy for this case is as follows:

	     +-----------+
	     |  vlanX.X  |
	     +-----------+
	     |
	     +-----------+
	     |   L2 agg  |
	     +-----------+
	     |
	     +-----------+
	     |    L2     |
	     +-----------+

	     For this case, get the L2 port from the lport.
	     From lport get L2 agg, 
	     From L2 agg, get the hsl_if
	     For the hsl_if, find if the VLAN is egress tagged.
	  */

	  /* Its a aggregate, should retreive the children*/
	  node = ifp->children_list;	  
	  if (! node)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	    }

	  ifp = node->ifp;
	  if (! ifp)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	    }

	  tagged = hsl_vlan_get_egress_type (ifp, nh->ifp->u.ip.vid);
	  if (tagged < 0)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;    
	    }  
	}
      else
	{
	  /* 
	     This is for the following hierarchy
	     
	     +-----------+
	     |  vlanX.X  |
	     +-----------+
	     |
	     +-----------+
	     |     L2    |
	     +-----------+
		 
	     For this case, get the L2 port.
	     From the L2 port if the VID is tagged/untagged
	  */

	  tagged = hsl_vlan_get_egress_type (ifp, nh->ifp->u.ip.vid);
	  if (tagged < 0)
	    {
	      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	      return HSL_FIB_ERR_HW_NH_NOT_FOUND;    
	    } 
	}
      
      /* Set tagged/untagged. */
      if (! tagged)
	ip->l3a_flags |= BCM_L3_UNTAG;
      else
	ip->l3a_flags &= ~BCM_L3_UNTAG;
    }
  else
#endif /* HAVE_L2 */
    {
      ifp = hsl_ifmgr_get_first_L2_port (nh->ifp);
      if (! ifp)
	{
	  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	  return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	}
      HSL_IFMGR_IF_REF_DEC (ifp);
	  
      /* Get the lport. */
      bcmifp = ifp->system_info;
      if (! bcmifp)
	{
	  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error finding L2 port information for interface %s\n", nh->ifp->name);
	  return HSL_FIB_ERR_HW_NH_NOT_FOUND;
	}

      /* Set lport. */
      ip->l3a_lport = bcmifp->u.l2.lport;

      /* Set untagged. */
      ip->l3a_flags |= BCM_L3_UNTAG;
    }  

  if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
    {
      /* Egress is a trunk. Set the trunk id. */
      ip->l3a_flags |= BCM_L3_TGID;
      ip->l3a_trunk = bcmifp->trunk_id;
    }
  else
    {
      /* Egress is a non-trunk port. */
      ip->l3a_flags &= ~BCM_L3_TGID;
    }  

  return 0;
}

/* 
   Add nexthop. 
*/
int 
hsl_bcm_nh_add (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh)
{
  bcmx_l3_host_t ip;
  int ret;
  char buf[256];
  struct hsl_avl_node *node;
  struct hsl_route_node *rnp;

  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_bcm_nh_add %x, mac %02x:%02x:%02x:%02x:%02x:%02x\n", 
  	nh->rn->p.u.prefix4, nh->mac[0], nh->mac[1], nh->mac[2], nh->mac[3], nh->mac[4], nh->mac[5]);

  if (! nh)
    return HSL_FIB_ERR_INVALID_PARAM;

  /* Map nexthop. */
  ret = _hsl_bcm_nh_get (fib_id, nh, &ip);
  if (ret < 0)
    return ret;

  /* Add the host route. */
  ret = hsl_bcmx_l3_host_add (&ip, (void*)&(nh->system_info));
  if (ret < 0)
    {
      hsl_prefix2str (&nh->rn->p, buf, sizeof(buf));     
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error adding nexthop %s from hardware\n", buf);
      return HSL_FIB_ERR_HW_OPERATION_FAILED;
    }

#if 0
  /* Activate all prefixes dependant on this NH. */
  for (node = hsl_avl_top (nh->prefix_tree); node; node = hsl_avl_next (node))
    {
      rnp = HSL_AVL_NODE_INFO (node);
      
      /* Add prefix. */
      hsl_bcm_prefix_add (fib_id, rnp, nh);
    }
#endif

  return 0;
}

/*
  Nexthop delete. 
*/
int 
hsl_bcm_nh_delete (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh)
{
  int ret;
  char buf[256];
  bcmx_l3_host_t ip;

  if (! nh)
    return HSL_FIB_ERR_INVALID_PARAM;

  /* Initialize host route. */
  bcmx_l3_host_t_init (&ip);

  ip.l3a_vrf = (bcm_vrf_t)fib_id;

  if (nh->rn->p.family == AF_INET)
    {
      ip.l3a_ip_addr = ntohl(nh->rn->p.u.prefix4); 
    }
#ifdef HAVE_IPV6
  else if (nh->rn->p.family == AF_INET6)
    {
      BCM_IP6_WORD(ip.l3a_ip6_addr, 0) = nh->rn->p.u.prefix6.word[0];
      BCM_IP6_WORD(ip.l3a_ip6_addr, 1) = nh->rn->p.u.prefix6.word[1];
      BCM_IP6_WORD(ip.l3a_ip6_addr, 2) = nh->rn->p.u.prefix6.word[2];
      BCM_IP6_WORD(ip.l3a_ip6_addr, 3) = nh->rn->p.u.prefix6.word[3];

      ip.l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  /* Delete the host route. */
  ret = hsl_bcmx_l3_host_delete (&ip);
  if (ret < 0)
    {
      hsl_prefix2str (&nh->rn->p, buf, sizeof(buf));     
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error adding nexthop %s to hardware\n", buf);
      return HSL_FIB_ERR_HW_OPERATION_FAILED;
    }

  return 0;
}

/*
  Get maximum number of multipaths. 
*/
int
hsl_bcm_get_max_multipath(u_int32_t *ecmp)
{
   HSL_FN_ENTER();

   if(!ecmp)
     HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
 
   *ecmp = 8;

   HSL_FN_EXIT(STATUS_OK); 
}


/*
  Check if nexthop entry has been hit.
*/
int
hsl_bcm_nh_hit (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh)
{
  bcmx_l3_host_t ip;
  int ret;

  /* Initialize host route. */
  bcmx_l3_host_t_init (&ip);

  ip.l3a_vrf = (bcm_vrf_t)fib_id;

  /* Clearing l3 hit bit here might lead to hit bit being cleared when router
   * is a transit router for the traffic and thus the entry will be aged out.
   * ARP must be relearned for hardware to avoid traffic going to CPU
   * (in slow path). ARP (control) packets need to be prioritized to/from CPU
   * to handle the case of wire rate traffic blocking ARP learning and causing
   * all packets going to CPU slow path.
   *
   * Not clearing will keep stale l3 arp entries forever in l3 table and
   * may cause l3 table full with stale entries.
   * Hence clearing is necessary here (Defect Id ZebOS00031567) though one can
   * use static arp to avoid ARP timeout and slow path issue.
   */
  ip.l3a_flags |= BCM_L3_HIT_CLEAR;

  if (nh->rn->p.family == AF_INET)
    {
      ip.l3a_ip_addr = ntohl(nh->rn->p.u.prefix4);
    }
#ifdef HAVE_IPV6
  else
    {
      BCM_IP6_WORD(ip.l3a_ip6_addr, 0) = nh->rn->p.u.prefix6.word[0];
      BCM_IP6_WORD(ip.l3a_ip6_addr, 1) = nh->rn->p.u.prefix6.word[1];
      BCM_IP6_WORD(ip.l3a_ip6_addr, 2) = nh->rn->p.u.prefix6.word[2];
      BCM_IP6_WORD(ip.l3a_ip6_addr, 3) = nh->rn->p.u.prefix6.word[3];
      
      ip.l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  /* Find host route. */
  ret = bcmx_l3_host_find (&ip);
  if (ret < 0)
    return 0; /* Invalid. */

  if (ip.l3a_flags & BCM_L3_HIT)
    return 1; /* Valid. */
  else
    return 0; /* Invalid. */
}

/*
  Add connected route as exception to prefix table.
*/
int
hsl_bcm_add_connected_route (hsl_fib_id_t fib_id, hsl_prefix_t *prefix, struct hsl_if *ifp)
{
  bcmx_l3_route_t route;
  //bcmx_l3_host_t ip;
  hsl_ipv4Address_t addr, mask;
  int ret;
#ifdef HAVE_IPV6
  hsl_prefix_t p;
#endif /* HAVE_IPV6 */

  HSL_FN_ENTER();

  /* Reject lookback address. */
  if (prefix->family == AF_INET && ntohl(prefix->u.prefix4) == INADDR_LOOPBACK)
      return 0;

  /* For all other connected addresses add a prefix route going to the
     CPU. */
#ifdef HAVE_IPV6
  /* For IPV6_MAX_PREFIXLEN, add to host table since for easyrider box,
     prefix table do not allow IPV6_MAX_PREFIXLEN route to be added. */
  if (prefix->family == AF_INET6 &&
      prefix->prefixlen == IPV6_MAX_PREFIXLEN)
    {
      /* No need to add a linklocal route */
      if (IPV6_IS_ADDR_LINKLOCAL (&prefix->u.prefix6))
        return 0;

      ret = _hsl_bcm_get_host (fib_id, prefix, NULL, &ip, 1);
      if (ret < 0)
	return -1;                                                                          
      ret = bcmx_l3_host_add (&ip);
                                                                                
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error adding connected route to hardware: %s\n", bcm_errmsg(ret));
          return -1;
        }
      return 0;
    }
#endif /* HAVE_IPV6 */

  /* Initialize route. */
  bcmx_l3_route_t_init (&route);

  route.l3a_vrf = (bcm_vrf_t)fib_id;

  if (prefix->family == AF_INET)
    {
      hsl_masklen2ip (prefix->prefixlen, (hsl_ipv4Address_t *) &mask);
      addr = prefix->u.prefix4;
      addr &= mask;
      route.l3a_subnet = ntohl(addr);
      route.l3a_ip_mask = ntohl(mask);
    }
#ifdef HAVE_IPV6
  else if (prefix->family == AF_INET6)
    {
      /* No need to add a linklocal route */
      if (IPV6_IS_ADDR_LINKLOCAL (&prefix->u.prefix6))
        return 0;

      /* Apply mask to prefix. */
      memcpy (&p, prefix, sizeof (hsl_prefix_t));
      hsl_apply_mask_ipv6 (&p);

      BCM_IP6_WORD(route.l3a_ip6_net, 0) = p.u.prefix6.word[0];
      BCM_IP6_WORD(route.l3a_ip6_net, 1) = p.u.prefix6.word[1];
      BCM_IP6_WORD(route.l3a_ip6_net, 2) = p.u.prefix6.word[2];
      BCM_IP6_WORD(route.l3a_ip6_net, 3) = p.u.prefix6.word[3];

      bcm_ip6_mask_create (route.l3a_ip6_mask, p.prefixlen);
      
      /* Set flags for IPv6. */
      route.l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  route.l3a_lport = BCMX_LPORT_LOCAL_CPU;

  if (ifp != NULL) {
  	route.l3a_flags |= BCM_L3_DEFIP_LOCAL;
  	route.l3a_flags |= BCM_L3_L2TOCPU; /* To get original headers. */
  } else {
  	route.l3a_flags |= BCM_L3_DST_DISCARD;
  }

  /* Add connected route to prefix table. */
  ret = hsl_bcmx_l3_route_add (&route);
  if (ret < 0)
    {
      return -1;
    }

  return 0;
}

/* 
   Delete connected route as exception to prefix table.
*/
int
hsl_bcm_delete_connected_route (hsl_fib_id_t fib_id, hsl_prefix_t *prefix, struct hsl_if *ifp)
{
  bcmx_l3_route_t route;
  //bcmx_l3_host_t ip;
  hsl_ipv4Address_t addr, mask;
  int ret;
#ifdef HAVE_IPV6
  hsl_prefix_t p;
#endif /* HAVE_IPV6 */

  /* For all other connected addresses delete the prefix route going to the
     CPU. */
#ifdef HAVE_IPV6
  /* For IPV6_MAX_PREFIXLEN, delete to host table since for easyrider box,
     prefix table do not allow IPV6_MAX_PREFIXLEN route to be added. */
  if (prefix->family == AF_INET6 &&
      prefix->prefixlen == IPV6_MAX_PREFIXLEN)
    {
      /* No need to add a linklocal route */
      if (IPV6_IS_ADDR_LINKLOCAL (&prefix->u.prefix6))
        return 0;

      ret = _hsl_bcm_get_host (fib_id, prefix, NULL, &ip, 1);
      if (ret < 0)
	return -1;

      ret = bcmx_l3_host_delete (&ip);
 
      if ((ret != BCM_E_NONE) && (ret != BCM_E_NOT_FOUND))
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting connected route to hardware: %s\n", bcm_errmsg(ret));
          return -1;
        }
      return 0;
    }
#endif /* HAVE_IPV6 */

  /* Initialize route. */
  bcmx_l3_route_t_init (&route);

  route.l3a_vrf = (bcm_vrf_t)fib_id;

  if (prefix->family == AF_INET)
    {
      hsl_masklen2ip (prefix->prefixlen, (hsl_ipv4Address_t *) &mask);
      addr = prefix->u.prefix4;
      addr &= mask;
      route.l3a_subnet = ntohl(addr);
      route.l3a_ip_mask = ntohl(mask);
    }
#ifdef HAVE_IPV6
  else if (prefix->family == AF_INET6)
    {
      /* No need to add a linklocal route */
      if (IPV6_IS_ADDR_LINKLOCAL (&prefix->u.prefix6))
        return 0;

      /* Apply mask to prefix. */
      memcpy (&p, prefix, sizeof (hsl_prefix_t));
      hsl_apply_mask_ipv6 (&p);

      BCM_IP6_WORD(route.l3a_ip6_net, 0) = p.u.prefix6.word[0];
      BCM_IP6_WORD(route.l3a_ip6_net, 1) = p.u.prefix6.word[1];
      BCM_IP6_WORD(route.l3a_ip6_net, 2) = p.u.prefix6.word[2];
      BCM_IP6_WORD(route.l3a_ip6_net, 3) = p.u.prefix6.word[3];

      bcm_ip6_mask_create (route.l3a_ip6_mask, p.prefixlen);

      /* Set flags for IPv6. */
      route.l3a_flags |= BCM_L3_IP6;
    }
#endif /* HAVE_IPV6 */

  route.l3a_lport = BCMX_LPORT_LOCAL_CPU;

  if (ifp != NULL) {
	  route.l3a_flags |= BCM_L3_L2TOCPU; /* To get original headers. */
	  route.l3a_flags |= BCM_L3_DEFIP_LOCAL;
  } else {
	  route.l3a_flags |= BCM_L3_DST_DISCARD;
  }

  /* Delete connected route to prefix table. */
  ret = hsl_bcmx_l3_route_delete (&route);
  if ((ret != BCM_E_NONE) && (ret != BCM_E_NOT_FOUND)) 
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting connected route from hardware\n");
      return -1;
    }

  return 0;
}

/*
  Register callbacks.
*/
void
hsl_fib_hw_cb_register (void)
{
  hsl_bcm_fib_callbacks.hw_fib_init = hsl_bcm_fib_init;
  hsl_bcm_fib_callbacks.hw_fib_deinit = hsl_bcm_fib_deinit;
  hsl_bcm_fib_callbacks.hw_fib_dump = hsl_bcm_fib_dump;
  hsl_bcm_fib_callbacks.hw_prefix_add = hsl_bcm_prefix_add;
  hsl_bcm_fib_callbacks.hw_prefix_delete = hsl_bcm_prefix_delete;
  hsl_bcm_fib_callbacks.hw_prefix_add_exception = hsl_bcm_prefix_exception;
  hsl_bcm_fib_callbacks.hw_nh_add = hsl_bcm_nh_add;
  hsl_bcm_fib_callbacks.hw_nh_delete = hsl_bcm_nh_delete;
  hsl_bcm_fib_callbacks.hw_nh_hit = hsl_bcm_nh_hit;
  hsl_bcm_fib_callbacks.hw_add_connected_route = hsl_bcm_add_connected_route;
  hsl_bcm_fib_callbacks.hw_delete_connected_route = hsl_bcm_delete_connected_route;
  hsl_bcm_fib_callbacks.hw_get_max_multipath = hsl_bcm_get_max_multipath;

  hsl_fibmgr_hw_cb_register (&hsl_bcm_fib_callbacks);
}

