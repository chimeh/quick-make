/* Copyright (C) 2004-2005 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

#include "ctc_api.h"
#include "sal.h"

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
#include "hsl_ctc_if.h"
#include "hsl_ctc_ifmap.h"
#include "hsl_ctc_resv_vlan.h"
#include "hsl_table.h"
#include "hsl_ether.h"
#include "hsl_bridge.h"
#include "hsl_ctc_l2.h"

#ifdef HAVE_LACPD
#include "hsl_ctc_lacp.h"
#endif /* HAVE_LACPD */

#ifdef HAVE_L3
#include "hsl_fib.h"
#endif /* HAVE_L3 */

#include "hsl_ctc.h"
#include "vsc8512.h"
#include "ctc_if_portmap.h"


#define MIRROR_ID_MAX   4
typedef struct hsl_mirror {
    bool is_use;
   /* uint16 s_port;*/
    uint16 d_port;
    uint16 member_count;
}hsl_mirror_t;

static hsl_mirror_t mirror_session_id[MIRROR_ID_MAX];

void init_mirror_id(void)
{
    int i;
    for (i=0; i<MIRROR_ID_MAX; i++) {
        mirror_session_id[i].is_use = FALSE;
		mirror_session_id[i].member_count = 0;
    }
}

int get_id_by_port(uint16 s_port, uint16 d_port, uint8 *id)
{
    int i;
    for (i=0; i<MIRROR_ID_MAX; i++) {
        if ((mirror_session_id[i].is_use == TRUE) && 
           /* (mirror_session_id[i].s_port == s_port) &&*/
            (mirror_session_id[i].d_port == d_port)) {
            *id  = (uint8)i;
            return 0;
        }
    }
    return -1;
}


int alloc_mirror_id(uint16 s_port, uint16 d_port)
{ 
    int i = 0; 
    uint8 session_id;
    int ret = 0;
    ret = get_id_by_port (s_port, d_port, &session_id);
    if (ret == 0){
        /*session_id exist */
        return session_id;
    }
    for (i=0; i<MIRROR_ID_MAX; i++) { 
        if (mirror_session_id[i].is_use == FALSE) { 
            mirror_session_id[i].is_use = TRUE; 
           /* mirror_session_id[i].s_port = s_port;*/
            mirror_session_id[i].d_port = d_port;
            return i; 
        } 
    } 
    return -1; 
}



int free_mirror_id(uint8 i)
{
   if (i >= MIRROR_ID_MAX) {
        return -1;
   }
   mirror_session_id[i].is_use = FALSE;
   return 0;
}


int mirror_member_inc(uint8 i)
{
   if (i >= MIRROR_ID_MAX) {
        return -1;
   }
   mirror_session_id[i].member_count++;
   return 0;
}

int mirror_member_dec(uint8 i)
{
   if (i >= MIRROR_ID_MAX) {
        return -1;
   }
   mirror_session_id[i].member_count--;
   return mirror_session_id[i].member_count;
}



#if 0
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
#endif
extern void hsl_fib_process_nh_ageing (void);


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
hsl_ctc_if_alloc ()
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
hsl_ctc_if_free (struct hsl_bcm_if *ifp)
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
  uint16 gport;

  HSL_FN_ENTER ();

  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    return -1;

  gport = BCMIFP_L2(bcmifp).lport;

    if (flags & IFF_UP) {
        ctc_port_set_port_en(gport, 1);
        phy_port_noshutdown(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex));
    } else {
        ctc_port_set_port_en(gport, 0);
        phy_port_shutdown(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex));
    }
    hsl_bridge_delete_port_vlan_fdb(ifp, 0);
    hsl_fib_process_nh_ageing();
  
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
  uint16 gport;

  HSL_FN_ENTER ();
#if 1
  bcmifp = (struct hsl_bcm_if *) ifp->system_info;
  if (! bcmifp)
    return -1;

  gport = BCMIFP_L2(bcmifp).lport;

  /* Delete all addresses learn't from this port. */
  //bcmx_l2_addr_delete_by_port (lport, 0);
  
  
    if (flags & IFF_UP) {
        ctc_port_set_port_en(gport, 0);
        phy_port_shutdown(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex));
    } else {
        ctc_port_set_port_en(gport, 1);
        phy_port_noshutdown(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex));
    }
    hsl_bridge_delete_port_vlan_fdb(ifp, 0);
    hsl_fib_process_nh_ageing();
    
#endif
  HSL_FN_EXIT (0);
}

/*
  Unregister L2 port.
*/
int
hsl_bcm_if_l2_unregister (struct hsl_if *ifp)
{
    struct hsl_bcm_if *bcmifp;
    int ret = 0;

    HSL_FN_ENTER ();

    bcmifp = (struct hsl_bcm_if *) ifp->system_info;
    if (! bcmifp)
        HSL_FN_EXIT (-1);

    if (ifp->type != HSL_IF_TYPE_L2_ETHERNET) {
        /* Wrong type. */
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Wrong interface type specified %s %d for L2 port unregistration\n", ifp->name, ifp->ifindex);
        HSL_FN_EXIT (-1);
    }

    /* Check for trunk. */
    if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK) {
        if (bcmifp->trunk_id >= 0) {
            //  ret = bcmx_trunk_destroy (bcmifp->trunk_id);
            if (ret < 0) {
                HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Error destroying trunk %s %d from hardware\n", ifp->name, ifp->ifindex); 
            }
        }
    } else {
        /* Unregister this lport from ifmap. */
        hsl_bcm_ifmap_lport_unregister (BCMIFP_L2(bcmifp).lport);
    }

    /* Free HW ifp. */
    hsl_ctc_if_free (bcmifp);
    ifp->system_info = NULL;

    HSL_FN_EXIT (0);
}


static int 
_hsl_add_port_to_vlan(hsl_vid_t vid, uint16 gport)
{
    int ret = 0;
    ctc_l2dflt_addr_t l2dflt_addr;
	struct hsl_if *p_hsl_if = NULL;
	bool is_agg_member = FALSE;

    HSL_FN_ENTER ();
			/*当为聚合口的时候*/
    if (CTC_IS_LINKAGG_PORT(gport)) {		
		goto link_agg_do;
    }
    
     /* Add port to VLAN. */
    ret = ctc_vlan_add_port(vid, gport);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't add VLAN %d to port %d\n", vid, gport);
        HSL_FN_EXIT (-1);
    }
	
link_agg_do:
	
	p_hsl_if = hsl_bcm_ifmap_if_get (gport);
	if (p_hsl_if) {
		is_agg_member = p_hsl_if->is_agg_member;
	}

	/*非聚合组成员才做这个操作*/
	if (!is_agg_member) {
	    sal_memset (&l2dflt_addr, 0, sizeof(l2dflt_addr));
	    l2dflt_addr.fid = vid;
	    l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid;
	    l2dflt_addr.member.mem_port = gport;
	    ret = ctc_l2_add_port_to_default_entry(&l2dflt_addr);
	    if (ret < 0) {
	        HSL_LOG(HSL_LOG_IFMGR, HSL_LEVEL_ERROR,"Can't add port default entry, vid=%d, gport=%d\n", vid, gport);
	        HSL_FN_EXIT (-1);
	    }
	}
	  
    HSL_FN_EXIT (0);
}

static int
_hsl_remove_port_from_vlan(hsl_vid_t vid, uint16 gport)
{
    int ret = 0;
    ctc_l2dflt_addr_t l2dflt_addr;
	struct hsl_if *p_hsl_if = NULL;
	bool is_agg_member = FALSE;

    HSL_FN_ENTER ();

	CTC_GLOBAL_PORT_CHECK(gport) 

				/*当为聚合口的时候*/
    if (CTC_IS_LINKAGG_PORT(gport)) {		
		goto link_agg_do;
    }
    
     /* Remove port from VLAN. */
    ret = ctc_vlan_remove_port(vid,  gport);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't remove  port %d from vlan %d\n", gport, vid);
        HSL_FN_EXIT (-1);
    }

link_agg_do:

	p_hsl_if = hsl_bcm_ifmap_if_get (gport);
	if (p_hsl_if) {
		is_agg_member = p_hsl_if->is_agg_member;
	}
	
    sal_memset (&l2dflt_addr, 0, sizeof(l2dflt_addr));
    l2dflt_addr.fid = vid;
    l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid;
    l2dflt_addr.member.mem_port = gport;
    
    ret = ctc_l2_remove_port_from_default_entry(&l2dflt_addr);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't remove port %d from default entry,vid=%d, ret=%d\n", gport,vid, ret);
        //HSL_FN_EXIT (-1);  /*不再错误返回，可能其他地方已经删除，其他地方没有删除的话 再删除一次*/
    }


#if 0	  
	/*当为聚合口的时候找出聚合口成员分别操作*/
    if (CTC_IS_LINKAGG_PORT(gport)) {
		int max_num =0 ;
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

			     /* Remove port from VLAN. */
		    ret = ctc_vlan_remove_port(vid,  gport);
		    if (ret < 0) {
		        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't remove  port %d from vlan %d\n", gport, vid);
		        //HSL_FN_EXIT (-1);
		    }

		    sal_memset (&l2dflt_addr, 0, sizeof(l2dflt_addr));
		    l2dflt_addr.fid = vid;
		    l2dflt_addr.l2mc_grp_id = l2dflt_addr.fid;
		    l2dflt_addr.member.mem_port = gport;
		    
		    ret = ctc_l2_remove_port_from_default_entry(&l2dflt_addr);
		    if (ret < 0) {
		        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Can't remove port %d from default entry,vid=%d, ret=%d\n", gport,vid, ret);
		        //HSL_FN_EXIT (-1);
		    }


		}

link_ret:
		if (p_gports) {
			sal_free(p_gports);
	    	p_gports = NULL;
		}
		HSL_FN_EXIT (0);
    }
 
 #endif   
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
hsl_bcm_add_port_to_vlan (hsl_vid_t vid, uint16 gport, int egress)
{
    int ret;
    int flags;
  
    HSL_FN_ENTER ();

	
    ret = _hsl_add_port_to_vlan(vid, gport);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,"Can't add port %d to vlan %d \n", gport, vid);
        HSL_FN_EXIT (-1);
    }

	if (CTC_IS_LINKAGG_PORT(gport)) {
		HSL_FN_EXIT (0);
	}
  
    /* Egress tagged. */
    if (! egress) {
        ret = ctc_vlan_set_tagged_port(vid, gport, 0);   //untagged
        if (ret < 0) {
            HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,"Can't set port %d stag \n", gport);
            HSL_FN_EXIT (-1);
        }
    } else {
        ret = ctc_vlan_set_tagged_port(vid, gport, 1);   //tagged
        if (ret < 0) {
            HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,"Can't set port %d stag \n", gport);
            HSL_FN_EXIT (-1);
        }
    }

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
hsl_bcm_remove_port_from_vlan (hsl_vid_t vid, uint16 gport)
{
    int ret;
    
    HSL_FN_ENTER ();

    ret = _hsl_remove_port_from_vlan(vid, gport);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,"_hsl_remove_port_from_vlan error\n");
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
     // ret = bcmx_port_untagged_vlan_set (bcmifpc->u.l2.lport, bcmifpp->u.l3.vid);
     ret = ctc_port_set_default_vlan(bcmifpc->u.l2.lport, bcmifpp->u.l3.vid);
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
#if 1
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
     // bcmx_l2_addr_delete_by_vlan (bcmifpp->u.l3.vid, 0);

     

      /* Add port to default VID. */
      hsl_bcm_add_port_to_vlan (HSL_DEFAULT_VID, bcmifpc->u.l2.lport, 0);

      /* Set PVID to default VLAN. */
    //  ret = bcmx_port_untagged_vlan_set (bcmifpc->u.l2.lport, HSL_DEFAULT_VID);
      ret = ctc_port_set_default_vlan(bcmifpc->u.l2.lport, HSL_DEFAULT_VID);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Could not set default PVID for port %s\n", ifpp->name);
	  HSL_FN_EXIT (ret);   
	}
    }
#endif
  HSL_FN_EXIT (ret);
}

#ifdef HAVE_L3
/*
Greatbelt support 2 types of interface : Vlan L3if and Phy L3if. These two types of L3if share 1022 L3
interface ID , and the range from 1~1022.
*/

/* Use linear mapping */
/* |1 ... vid         ... |   ... pannel number  ... | */
/* |1 ... vlan l3ifid ... |   ... phy l3ifid     ... | */

#define HSL_CTC_IF_L3IFID_MAXNUM 1022U
#define HSL_CTC_IF_L3IFID_MIN 1U
#define HSL_CTC_IF_L3IFID_MAX 1022U
#define HSL_CTC_IF_L3IFID_INVALID 0xFFFFFFFFU

#define HSL_CTC_IF_PHY_L3IFID_NUM  52U
#define HSL_CTC_IF_PHY_L3IFID_BASE (HSL_CTC_IF_L3IFID_MAX - HSL_CTC_IF_PHY_L3IFID_NUM)
#define HSL_CTC_IF_PHY_L3IFID_MAX HSL_CTC_IF_L3IFID_MAX
#define HSL_CTC_IF_PHY_L3IFID_VALID(gport) (l3ifid >= HSL_CTC_IF_PHY_L3IFID_BASE && l3ifid <= HSL_CTC_IF_PHY_L3IFID_MAX)

#define HSL_CTC_IF_VLAN_L3IFID_BASE HSL_CTC_IF_L3IFID_MIN
#define HSL_CTC_IF_VLAN_L3IFID_MAX  HSL_CTC_IF_PHY_L3IFID_BASE
#define HSL_CTC_IF_VLAN_L3IFID_VALID(l3ifid) (l3ifid >= HSL_CTC_IF_VLAN_L3IFID_BASE && l3ifid <= HSL_CTC_IF_VLAN_L3IFID_MAX)

#define HSL_CTC_IF_L3IFID_PHYIF(pannelport) (HSL_CTC_IF_L3IFID_PHYIF_BASE+ pannelport)


unsigned int hsl_ctc_if_map_phy_l3ifid(unsigned int pannelport/* from 0 to maxpanel port */)
{
    unsigned int l3ifid;
    l3ifid = HSL_CTC_IF_PHY_L3IFID_BASE + pannelport;
    if (HSL_CTC_IF_PHY_L3IFID_VALID(l3ifid)) {
        return l3ifid;
    }
    return HSL_CTC_IF_L3IFID_INVALID;
}
unsigned int hsl_ctc_if_map_vlan_l3ifid(unsigned int vid)
{
    unsigned int l3ifid;
    l3ifid = vid;
    if (HSL_CTC_IF_VLAN_L3IFID_VALID(l3ifid)) {
        return l3ifid;
    }
    return HSL_CTC_IF_L3IFID_INVALID;
}

#if 0
#define HSL_CTC_L3IFID_MAXNUM 1022U
#define HSL_CTC_L3IFID_MIN 1U
#define HSL_CTC_L3IFID_MAX 1022U
#define HSL_CTC_L3IFID_INVALID 0xffffU
#define HSL_CTC_L3IFID_ALLOCATED 1U
#define HSL_CTC_L3IFID_DEALLOCATED 0U

#define HSL_CTC_L3IFID_IS_UNALLOCATED(l3if_id) (HSL_CTC_L3IFID_MIN <= (l3if_id)\
                                     && (l3if_id) <= HSL_CTC_L3IFID_MAX\
                                     && (hsl_ctc_l3_ifid_desc.l3ifids[l3if_id]) != HSL_CTC_L3IFID_ALLOCATED)
  
#define HSL_CTC_L3IFID_DESC_INITIALIZED 0xffff
#define HSL_CTC_L3IFID_DESC_HAVE_BEEN_INITIALIZED (hsl_ctc_l3_ifid_desc.initialized == HSL_CTC_L3IFID_DESC_INITIALIZED)
static struct hsl_ctc_l3_ifid_desc_s {
    int initialized;
    int l3ifids[HSL_CTC_L3IFID_MAXNUM+1];
 } hsl_ctc_l3_ifid_desc = {0};



static int
hsl_ctc_if_l3_ifid_alloc(void)
{
    int i;
    if (!(HSL_CTC_L3IFID_DESC_HAVE_BEEN_INITIALIZED)) {
        hsl_ctc_l3_ifid_desc.l3ifids[0] = HSL_CTC_L3IFID_ALLOCATED;
        for (i = HSL_CTC_L3IFID_MIN; i <= HSL_CTC_L3IFID_MAX; i++) {
            hsl_ctc_l3_ifid_desc.l3ifids[i] = HSL_CTC_L3IFID_DEALLOCATED;
        }
        hsl_ctc_l3_ifid_desc.initialized = HSL_CTC_L3IFID_DESC_INITIALIZED;
    }
    
    for (i = HSL_CTC_L3IFID_MIN; HSL_CTC_L3IFID_IS_UNALLOCATED(i); i++) {
        hsl_ctc_l3_ifid_desc.l3ifids[i] = HSL_CTC_L3IFID_ALLOCATED;
        return i;
    }
    return HSL_CTC_L3IFID_INVALID;
}

static void
hsl_ctc_if_l3_ifid_dealloc(void)
{
    int i;
    if(!(HSL_CTC_L3IFID_DESC_HAVE_BEEN_INITIALIZED)) {
        hsl_ctc_l3_ifid_desc.l3ifids[0] = HSL_CTC_L3IFID_ALLOCATED;
        for (i = HSL_CTC_L3IFID_MIN; i <= HSL_CTC_L3IFID_MAX; i++) {
            hsl_ctc_l3_ifid_desc.l3ifids[i] = HSL_CTC_L3IFID_DEALLOCATED;
        }
        hsl_ctc_l3_ifid_desc.initialized = HSL_CTC_L3IFID_DESC_INITIALIZED;
    }
    hsl_ctc_l3_ifid_desc.l3ifids[i] = HSL_CTC_L3IFID_DEALLOCATED;  
    return;
} 

#endif

static int 
_hsl_ctc_if_l3_intf_create (struct hsl_if *ifp, struct hsl_bcm_if *bcmifp)
{
    int ret;
    /* Create L3 interface. */
    /* Configure a L3 interface in BCM. 
     Add static entry in L2 table with L3 bit set. */

    //ret = _hsl_bcm_if_l3_intf_create (ifp, &intf, vid, IFP_IP(ifp).mac, IFP_IP(ifp).mtu, ifp->fib_id);
     ret = ctc_l3if_create (bcmifp->u.l3.ifindex, &bcmifp->u.l3.l3if);
     if (ret < 0)
    {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
                 "  Could not create L3 interface in hardware for interface %s ifindex %d  ret(%d)\n", 
                 ifp->name, ifp->ifindex, ret);
          
    HSL_FN_EXIT (-1);
    }
    /* Set fib id */
    ctc_l3if_set_property(bcmifp->u.l3.ifindex, CTC_L3IF_PROP_VRF_ID, (uint32)ifp->fib_id);
    
    /* Set VID. */
    // setted when create
    
    /* Set MAC. */
    ctc_l3if_set_router_mac(IFP_IP(ifp).mac);
    
    /* Set MTU. */
    ctc_l3if_set_property(bcmifp->u.l3.ifindex, CTC_L3IF_PROP_MTU_SIZE, IFP_IP(ifp).mtu);
    
    /* Set ifindex. */
    bcmifp->u.l3.ifindex = bcmifp->u.l3.ifindex;
	
	/*arp copy to cpu enable*/
	if (bcmifp->u.l3.l3if.l3if_type == CTC_L3IF_TYPE_VLAN_IF) {
		ctc_vlan_set_arp_excp_type(bcmifp->u.l3.l3if.vlan_id, CTC_EXCP_FWD_AND_TO_CPU);
	}
    return 0;
}



static int
_hsl_ctc_if_l3_intf_delete (struct hsl_if *ifp, struct hsl_bcm_if *bcmifp)
{
  //bcmx_l3_intf_t intf;
  int ret;

  ret = 0;

  HSL_FN_ENTER ();

  /* Sanity check. */
  if (ifp == NULL)
    HSL_FN_EXIT (-1);

  /* Initialize interface. */
  //bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  //intf.l3a_vrf = (bcm_vrf_t)fib_id;

  /* Set index. */
  //intf.l3a_intf_id = index;
  
  /* Destroy the L3 interface. */
  //ret = bcmx_l3_intf_delete (&intf);
  ret = ctc_l3if_destory (bcmifp->u.l3.ifindex, &bcmifp->u.l3.l3if);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "  Could not delete L3 interface %s from hardware\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}


/* 
   Set interface to UP. 
*/
static int
_hsl_ctc_if_l3_up (struct hsl_if *ifp)
{
  int rb_addr, rb_sec, rb_pri;
  struct hsl_bcm_if *bcmifp; 
  //bcmx_l3_intf_t intf;
  int ret;
  int i;

  HSL_FN_ENTER ();

  ret = 0;
  rb_addr = 0;
  rb_pri = 0;
  rb_sec = 0;

  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Hardware L3 interface not found for %s\n", ifp->name);
      HSL_FN_EXIT (-1);
    }

  /* Initialize interface. */
  //bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  //intf.l3a_vrf = (bcm_vrf_t)ifp->fib_id;

  /* Set flags. */
  //intf.l3a_flags |= BCM_L3_ADD_TO_ARL;
  
  /* Set MAC. */
  //memcpy (intf.l3a_mac_addr, IFP_IP(ifp).mac, sizeof (bcm_mac_t));

  /* Set VID. */
  //intf.l3a_vid = BCMIFP_L3(bcmifp).vid;

  /* Set MTU. */
  //intf.l3a_mtu = 1500;

  /* Create a new interface. */
  ret = ctc_l3if_create (bcmifp->u.l3.ifindex, &bcmifp->u.l3.l3if);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error creating interface\n");
      ret = -1;
    }

  /* Create interfaces for secondary addresses, if any. */
  /* Not support now */
  if (ret < 0)
  {
    HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error creating secondary interface\n");
  }
  
  HSL_FN_EXIT (ret);
}



/* 
   Set interface to down. 
*/
static int
_hsl_ctc_if_l3_down (struct hsl_if *ifp)
{
  int ret;
  struct hsl_bcm_if *bcmifp; 
  //bcmx_l3_intf_t intf;
  //bcmx_l3_route_t route;

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
  //bcmx_l3_intf_t_init (&intf);
  
  /* Set fib id */
  //intf.l3a_vrf = (bcm_vrf_t)ifp->fib_id;

  /* Initialize route. */
  //bcmx_l3_route_t_init (&route);

  /* Set interface index. */
  //intf.l3a_intf_id = route.l3a_intf = BCMIFP_L3(bcmifp).ifindex;

  /* Set fib id */
  //route.l3a_vrf = (bcm_vrf_t)ifp->fib_id;

  /* Delete all routes pointing to this interface including the connected
     routes. */
  //ret = bcmx_l3_route_delete_by_interface (&route);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting prefix routes from hardware on interface down event\n");
    }

  //bcmx_l3_egress_traverse(l3_egress_obj_delete_by_intf, (void*)route.l3a_intf);

  /* Process the addresses and add them. */
  //ret = _hsl_bcm_if_delete_addresses (ifp, 1);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting interface addresses from hardware.\n");
    }

  /* Delete L3 interface from hardware. */
  //ret = bcmx_l3_intf_delete (&intf);
  ret = _hsl_ctc_if_l3_intf_delete(ifp, bcmifp);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error deleting L3 interface from hardware\n");
    }

  BCMIFP_L3(bcmifp).ifindex = -1;
  
  HSL_FN_EXIT (0);
}


static int
_hsl_ctc_if_addresses (struct hsl_if *ifp, int add, int connected_route)
{

  int ret = 0;
 HSL_FN_EXIT (ret);
}


/* Create L3 interface.

Parameters:
IN -> ifp - interface pointer
IN -> unsed - unused parameter
     
Returns:
HW L3 interface pointer as void *
NULL on error
*/
//void * hsl_ctc_if_l3_configure (struct hsl_if *ifp, void *unused)
void *
hsl_ctc_if_l3_configure (struct hsl_if *ifp, void *unused)
{
  int ret = -1;
  int br, v;
  hsl_vid_t vid;
  struct hsl_bcm_if *bcmifp;
  struct hsl_bcm_resv_vlan *entry;
  int lport;
  unsigned int panneln;
  
  HSL_FN_ENTER ();

  /* Create the structure to store CTC L3 interface data. */
  bcmifp = hsl_ctc_if_alloc ();
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
  if (! strncmp (ifp->name, "vlan", 4))
    {
      /* Get VLAN from name. */
      sscanf (ifp->name, "vlan%d.%d", (int *) &br, (int *)&v);
      vid = (hsl_vid_t) v;
      //l3if create ifid $vid type vlan-if vlan $vid
      bcmifp->u.l3.l3if.l3if_type = CTC_L3IF_TYPE_VLAN_IF;
      bcmifp->u.l3.l3if.vlan_id = vid;
      bcmifp->u.l3.ifindex = hsl_ctc_if_map_vlan_l3ifid(vid);
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "%s()%d\n", __FUNCTION__, __LINE__);
     /* Set VID. */
     bcmifp->u.l3.vid = vid;
     IFP_IP(ifp).vid = vid;
    }
  else
    {
      ret = hsl_ctc_resv_vlan_allocate (&entry);
      if (ret < 0)
	  {
	    /* Free Broadcom interface. */
	    hsl_ctc_if_free (bcmifp);
	    HSL_FN_EXIT (NULL);
	  }

      /* in NGN, port name not ge, be careful */
	  sscanf(ifp->name, "ge%u",  &panneln);
	  
	  vid = entry->vid;
	  bcmifp->u.l3.resv_vlan = entry;
      bcmifp->u.l3.l3if.l3if_type = CTC_L3IF_TYPE_PHY_IF;
      bcmifp->u.l3.l3if.gport = IFINDEX_TO_GPORT(ifp->ifindex);    /* @TODO ifindex map to gport, one-one map */
      bcmifp->u.l3.ifindex = hsl_ctc_if_map_phy_l3ifid(panneln);
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "%s()%d panneln %u gport %d\n", __FUNCTION__, __LINE__,panneln, bcmifp->u.l3.l3if.gport);
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "%s()%d\n", __FUNCTION__, __LINE__);
 
    }
  
 // HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "%s()%d\n", __FUNCTION__, __LINE__);

  if (ifp->flags & IFF_UP)
    {
       _hsl_ctc_if_l3_intf_create(ifp, bcmifp);
     //  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "%s()%d\n", __FUNCTION__, __LINE__);
    }

  {
      //bcm_gport_t gport = 0;
      //BCM_GPORT_MODPORT_SET(gport, vid, 255);
      
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "add l3ifid %x map.\n",bcmifp->u.l3.ifindex);
      //lport = (bcmifp->u.l3.l3if.vlan_id<<16 | bcmifp->u.l3.l3if_id);
      //hsl_ctc_ifmap_if_map(lport, ifp);
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
//int hsl_ctc_if_l3_unconfigure (struct hsl_if *ifp)
int hsl_ctc_if_l3_unconfigure (struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;
  int ret;
  int i;

  HSL_FN_ENTER ();
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 

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
	  ret = -1; /* current not support */
	  if (ret < 0)
	    {
	      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
                       "  Error %d deleting trunk from hardware for %s\n", 
                       ret, ifp->name);
	    }
	}
    }

  /* Delete host entries for the addreses. */
  //_hsl_bcm_if_delete_addresses (ifp, 0);
  _hsl_ctc_if_addresses(ifp, /* del */0, /* not connect route */0);

  if (BCMIFP_L3(bcmifp).ifindex > 0)
    {
      /* Delete the primary L3 interface. */
      //ret = _hsl_bcm_if_l3_intf_delete_by_index (ifp, BCMIFP_L3(bcmifp).ifindex, ifp->fib_id);
      ret = ctc_l3if_destory(BCMIFP_L3(bcmifp).ifindex, &BCMIFP_L3(bcmifp).l3if);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
		   "  Error deleting L3 interface %d from hardware\n", BCMIFP_L3(bcmifp).ifindex);  
	}

      BCMIFP_L3(bcmifp).ifindex = -1;

      /* Delete the secondary L3 interfaces. */
      /* current not support secondary L3 interfaces */
	  if (IFP_IP(ifp).nAddrs > 1)
	    {
	      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
		       "  Error deleting L3 interface from hardware, not Support secondary L3 interfaces\n");
	    }     
    }

  /* Free reserved vlan if configured. */
  if (BCMIFP_L3(bcmifp).resv_vlan)
    {
      hsl_ctc_resv_vlan_deallocate (BCMIFP_L3(bcmifp).resv_vlan);
    }

  /* Free HW ifp. */
  hsl_ctc_if_free (bcmifp);
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
int hsl_ctc_if_l3_address_add (struct hsl_if *ifp,
			       hsl_prefix_t *prefix, u_char flags)
{
  struct hsl_bcm_if *bcmifp; 
  //bcmx_l3_host_t host;
  int ret;
  ctc_ipuc_param_t ipuc_info = {0};
  //ctc_ip_nh_param_t nh_param = {0};
  
  HSL_FN_ENTER ();
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 

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
	  /*
          bcmx_l3_host_t_init (&(host));                                                                  \
          (host).l3a_ip_addr = ntohl((prefix)->u.prefix4);                                                       \
          (host).l3a_intf = (ifindex);                                                                \
          (host).l3a_vrf = (bcm_vrf_t)(fib_id);                                                           \
          (host).l3a_lport = BCMX_LPORT_LOCAL_CPU;                                            \
          (host).l3a_flags |= BCM_L3_L2TOCPU;  
      */
	  //HSL_BCMX_V4_SET_HOST(host, bcmifp->u.l3.ifindex, prefix, ifp->fib_id); 
	  ipuc_info.vrf_id = ifp->fib_id;
	  ipuc_info.ip.ipv4 = ntohl((prefix)->u.prefix4);
      ipuc_info.masklen =32;
      ipuc_info.nh_id = 2; /* To CPU */
      ipuc_info.ip_ver = CTC_IP_VER_4;
      
	}
      else
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  IP address type is not valid\n");
	  HSL_FN_EXIT (-1);
	}
      
      /* Add the host entry. */
      //ret = hsl_ctc_l3_host_add (&host, NULL);
      //ret = hsl_ctc_l3_host_add(&ipuc_info, NULL);
      ret = ctc_ipuc_add(&ipuc_info);
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
int hsl_ctc_if_l3_address_delete (struct hsl_if *ifp,
				  hsl_prefix_t *prefix)
{
  struct hsl_bcm_if *bcmifp; 
  int ret;
  ctc_ipuc_param_t ipuc_info = {0};

  HSL_FN_ENTER ();
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 

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
      //HSL_BCMX_V4_SET_HOST(host, bcmifp->u.l3.ifindex, prefix, ifp->fib_id);
      ipuc_info.vrf_id = ifp->fib_id;
	  ipuc_info.ip.ipv4 = ntohl((prefix)->u.prefix4);
      ipuc_info.masklen =32;
      ipuc_info.nh_id = 2; /* To CPU */
      ipuc_info.ip_ver = CTC_IP_VER_4;
      
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
  //ret = hsl_bcmx_l3_host_delete (&host);
  //ipuc remove VRFID A.B.C.D MASK_LEN NHID
  ret = ctc_ipuc_add(&ipuc_info);
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
int hsl_ctc_if_l3_bind_fib (struct hsl_if *ifp,
				  hsl_fib_id_t fib_id)
{
  struct hsl_bcm_if *bcmifp; 
  //bcmx_l3_intf_t intf;
  int ret = 0;

  HSL_FN_ENTER ();
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 

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

  //ret = _hsl_bcm_if_l3_intf_create (ifp, &intf, 
  //    BCMIFP_L3(bcmifp).vid, IFP_IP(ifp).mac, IFP_IP(ifp).mtu,
  //    fib_id);
  //ret = ctc_l3if_set_property(bcmifp->u.l3.l3if_id, CTC_L3IF_PROP_VRF_ID, fib_id);
  ret = -1;
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error binding interface %s to FIB %d\n", ifp->name, fib_id);
      HSL_FN_EXIT (ret);
    }
  
  //BCMIFP_L3(bcmifp).ifindex = intf.l3a_intf_id;

  
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
int hsl_ctc_if_l3_unbind_fib (struct hsl_if *ifp,
				  hsl_fib_id_t fib_id)
{
  struct hsl_bcm_if *bcmifp; 
  int ret = 0;

  HSL_FN_ENTER ();
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 

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

  //ret = _hsl_bcm_if_l3_intf_delete_by_index (ifp, BCMIFP_L3(bcmifp).ifindex, fib_id);
  ret = -1;
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error unbinding interface %s to FIB %d\n", ifp->name, fib_id);
      HSL_FN_EXIT (ret);
    }
  
  BCMIFP_L3(bcmifp).ifindex = -1;

  HSL_FN_EXIT (ret);
}
#endif /* HAVE_L3 */

/* 
 * Get interface mtu. 
 */ 
int
hsl_bcm_get_port_mtu(uint16 gport, int *mtu)
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
 // ret = bcmx_port_frame_max_get(lport, &mtu_size);
  ret = ctc_port_get_max_frame(gport, &mtu_size);
  if (ret != CTC_E_NONE)
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
hsl_bcm_set_port_mtu (uint16 gport, int mtu)
{
  int       ret;            /* sdk operation status.  */

  HSL_FN_ENTER();
  
  /* Get interface frame max. */
  //ret = bcmx_port_frame_max_set(lport, mtu);
  ret = ctc_port_set_max_frame(gport, mtu);
  if (ret != CTC_E_NONE)
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

  //ret = bcmx_port_frame_max_set (BCMIFP_L2(bcmifp).lport, mtu);
  ret = ctc_port_set_max_frame(BCMIFP_L2(bcmifp).lport, mtu);
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
int hsl_ctc_if_duplex_set (struct hsl_if *ifp, int duplex)
{
    struct hsl_bcm_if *bcmifp = NULL;
    int ret = 0;

    HSL_FN_ENTER ();

    if (! ifp)
        HSL_FN_EXIT (-1);

    bcmifp = (struct hsl_bcm_if *) ifp->system_info;
    if (! bcmifp) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
                "Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", 
                ifp->name, ifp->ifindex);
        HSL_FN_EXIT (-1);
    }

    if (duplex == HSL_IF_DUPLEX_AUTO) {
//        ret = bcmx_port_autoneg_set (BCMIFP_L2(bcmifp).lport, HSL_IF_AUTONEGO_ENABLE);
        vs8512_port_set_property(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex), VSC8512_PROP_PORT_AUTONEG, 1);
        ret = ctc_port_set_auto_neg(BCMIFP_L2(bcmifp).lport, 1);   /* enable auto */
        if (ret < 0) {
            HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s set auto-nego failed\n", ifp->name);
            HSL_FN_EXIT (-1);
        }
    } else {
        ret = vs8512_port_set_property(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex), VSC8512_PROP_PORT_DUPLEX, duplex);
        if (ret < 0) {
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
int hsl_ctc_if_autonego_set (struct hsl_if *ifp, int autonego)
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

    vs8512_port_set_property(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex), VSC8512_PROP_PORT_AUTONEG, autonego);
  //ret = bcmx_port_autoneg_set (BCMIFP_L2(bcmifp).lport, autonego);
  ret = ctc_port_set_auto_neg (BCMIFP_L2(bcmifp).lport, autonego);
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
int hsl_ctc_if_bandwidth_set (struct hsl_if *ifp, long long unsigned int bandwidth)
{
    int ret = 0;
    int speed = 0;
    struct hsl_bcm_if *bcmifp = NULL;
    ctc_port_speed_t ctc_speed = CTC_PORT_SPEED_1G;

    HSL_FN_ENTER ();

    if (! ifp) {
        HSL_FN_EXIT (-1);
    }

    bcmifp = (struct hsl_bcm_if *) ifp->system_info;
    if (! bcmifp) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
                "Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n",
                ifp->name, ifp->ifindex);
        HSL_FN_EXIT (-1);
    }
 
    /* Broadcom allowed input value of bandwidth with 10,100, 1000, 10000 
    ** megabits/sec. Bandwidth value coming from nsm is bytes/sec */
    speed = (int)(bandwidth / HSL_BCM_BW_UNIT_MEGA * 8) + 
            (int)((bandwidth % HSL_BCM_BW_UNIT_MEGA) * 8 / HSL_BCM_BW_UNIT_MEGA);
			
//    HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
//            "%s got  bandwidth= l: %ll, ll: %ll, Byte/s, speed = %d Mbits/s \n",
//            ifp->name, bandwidth, bandwidth, speed);
    
    if((speed != HSL_BCM_BW_UNIT_10M) && (speed != HSL_BCM_BW_UNIT_100M) && 
       (speed != HSL_BCM_BW_UNIT_1G) && (speed != HSL_BCM_BW_UNIT_10G) && (speed != HSL_BCM_BW_UNIT_40G)) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s bandwidth value is not allowed\r\n", ifp->name);
        HSL_FN_EXIT (-1);
    }
    
    switch(speed) {
    case HSL_BCM_BW_UNIT_10M:
        ctc_speed = CTC_PORT_SPEED_10M;
        break;
        
    case HSL_BCM_BW_UNIT_100M:
        ctc_speed = CTC_PORT_SPEED_100M;
        break;
        
    case HSL_BCM_BW_UNIT_1G:
        ctc_speed = CTC_PORT_SPEED_1G;
        break;
        
    case HSL_BCM_BW_UNIT_10G:
        ctc_speed = CTC_PORT_SPEED_10G;
        break;
        
    default:
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "\r\nInterface %s bandwidth only support: 10M, 100M, 1G, 10G\r\n", ifp->name);
        HSL_FN_EXIT (-1);
        break;
    }

    vs8512_port_set_property(CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex), VSC8512_PROP_PORT_SPEED, ctc_speed);
    ret = ctc_port_set_speed(BCMIFP_L2(bcmifp).lport, ctc_speed);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "Interface %s set bandwidth failed\r\n", ifp->name);
    }  else {
        ifp->u.l2_ethernet.speed = speed * 1000;    /* make M to K */
    }

    HSL_FN_EXIT (ret);
}



/* Set HW address for a interface.

Parameters:
IN -> ifp - interface pointer
IN -> hwadderlen - address length
IN -> hwaddr - address
     
Returns:
0 on success
< 0 on error
*/
#if 0
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
  _hsl_ctc_if_l3_down (ifp);

  /* Set new MAC. */
  memcpy (BCMIFP_L3(bcmifp).mac, hwaddr, hwaddrlen);

  /* Bring up the interface. */
  _hsl_ctc_if_l3_up (ifp);
  HSL_FN_EXIT (0);
}
#endif 
int hsl_ctc_if_hwaddr_set (struct hsl_if *ifp, int hwaddrlen, u_char *hwaddr)
{
    //HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 
    
    return 0;
}


#ifdef HAVE_L3

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
hsl_ctc_if_l3_flags_set (struct hsl_if *ifp, unsigned long flags)
{
  struct hsl_bcm_if *bcmifp; 
  int ret;
  
  HSL_FN_ENTER ();
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "%s()%d index %d ifname %s\n", __FUNCTION__, __LINE__, ifp->ifindex, ifp->name);
  if (flags & IFF_UP)
    {
      /* Set interface to UP. */
      //_hsl_ctc_if_l3_up (ifp);
      bcmifp = (struct hsl_bcm_if *)ifp->system_info;
      if (! bcmifp)
        HSL_FN_EXIT (-1);
      
      if (BCMIFP_L3(bcmifp).ifindex != -1)
        {
          /* Interface is not up. */
          HSL_FN_EXIT (-1);
        }
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "%s() ifindex %u ifname %s\n", __FUNCTION__, ifp->ifindex, ifp->name); 
      //l3if create ifid 1 type phy-if gport 20 
      //port 20 phy-if enable
      /* Create a new interface. */
      ret = _hsl_ctc_if_l3_intf_create (ifp, bcmifp);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, " Error creating interface\n");
        }
      
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
hsl_ctc_if_l3_flags_unset (struct hsl_if *ifp, unsigned long flags)
{
  struct hsl_bcm_if *bcmifp; 

  HSL_FN_ENTER ();
  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 
  bcmifp = (struct hsl_bcm_if *)ifp->system_info;
  if (! bcmifp)
    HSL_FN_EXIT (-1);
     
  if (flags & IFF_UP)
    {
      /* Set interface to down. */
      //_hsl_ctc_if_l3_down (ifp);

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
  //bcmx_port_bpdu_enable_set (BCMIFP_L2(bcmifp).lport, 1);

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
 // bcmx_port_bpdu_enable_set (BCMIFP_L2(bcmifp).lport, 1);

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
_hsl_bcm_get_lport_counters(uint16 gport,struct hal_if_counters *res) 
{
    int ret = 0;
    uint64_t tmpvar = 0;
    
    struct hal_if_counters cnts; 
    struct timeval current_time;
    
    ctc_stats_port_t stats;
    ctc_mac_stats_t rx_stats;
    ctc_mac_stats_t tx_stats;

    memset(&cnts,     0, sizeof(cnts));
    memset(&rx_stats, 0, sizeof(rx_stats));
    memset(&tx_stats, 0, sizeof(tx_stats));
    
    rx_stats.stats_mode = CTC_STATS_MODE_PLUS;
    tx_stats.stats_mode = CTC_STATS_MODE_PLUS;

    ret = ctc_stats_get_mac_stats(gport, CTC_STATS_MAC_STATS_RX, &rx_stats);
    if(ret != CTC_E_NONE) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "[%s]: get gport<%d> RX counter failed: %d\r\n", __func__, gport, ret);
        return ret;
    }

    ret = ctc_stats_get_mac_stats(gport, CTC_STATS_MAC_STATS_TX, &tx_stats);
    if(ret != CTC_E_NONE) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_DEBUG, "[%s]: get gport<%d> TX counter failed: %d\r\n", __func__, gport, ret);
        return ret;
    }

#if 0
    /* total recv */
    hsl_ctc_copy_64_int(&rx_stats.u.stats_plus.stats.rx_stats_plus.all_octets, &cnts.good_octets_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_plus.stats.rx_stats_plus.all_pkts,   &cnts.good_pkts_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_plus.stats.rx_stats_plus.bcast_pkts, &cnts.brdc_pkts_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_plus.stats.rx_stats_plus.mcast_pkts, &cnts.mc_pkts_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_plus.stats.rx_stats_plus.error_pkts, &cnts.bad_pkts_rcv);

    /* total send */
    hsl_ctc_copy_64_int(&tx_stats.u.stats_plus.stats.tx_stats_plus.error_pkts, &cnts.out_errors);
    hsl_ctc_copy_64_int(&tx_stats.u.stats_plus.stats.tx_stats_plus.mcast_pkts, &cnts.out_mc_pkts);
    hsl_ctc_copy_64_int(&tx_stats.u.stats_plus.stats.tx_stats_plus.ucast_pkts, &cnts.out_uc_pkts);
    
    hsl_ctc_copy_64_int(&tx_stats.u.stats_plus.stats.tx_stats_plus.all_octets, &cnts.good_octets_sent);
    hsl_ctc_copy_64_int(&tx_stats.u.stats_plus.stats.tx_stats_plus.all_pkts,   &cnts.good_pkts_sent);
    hsl_ctc_copy_64_int(&tx_stats.u.stats_plus.stats.tx_stats_plus.mcast_pkts, &cnts.mc_pkts_sent);
    hsl_ctc_copy_64_int(&tx_stats.u.stats_plus.stats.tx_stats_plus.bcast_pkts, &cnts.brdc_pkts_sent);
#else
    memcpy(&cnts.rx_plus, &rx_stats.u.stats_plus.stats.rx_stats_plus, sizeof(cnts.rx_plus));
    memcpy(&cnts.tx_plus, &tx_stats.u.stats_plus.stats.tx_stats_plus, sizeof(cnts.tx_plus));
#endif

//    rx_stats.stats_mode = CTC_STATS_MAC_STATS_RX;
    memset(&rx_stats, 0, sizeof(rx_stats));
    memset(&tx_stats, 0, sizeof(tx_stats));
    /* rx, tx detail */
    rx_stats.stats_mode = CTC_STATS_MODE_DETAIL;
    tx_stats.stats_mode = CTC_STATS_MODE_DETAIL;

    ctc_stats_get_mac_stats(gport, CTC_STATS_MAC_STATS_RX, &rx_stats);
    ctc_stats_get_mac_stats(gport, CTC_STATS_MAC_STATS_TX, &rx_stats);
    
#if 0
    hsl_ctc_copy_64_int(&rx_stats.u.stats_detail.stats.rx_stats.bytes_64,           &cnts.pkts_64_octets_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_detail.stats.rx_stats.bytes_65_to_127,    &cnts.pkts_65_127_octets_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_detail.stats.rx_stats.bytes_128_to_255,   &cnts.pkts_128_255_octets_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_detail.stats.rx_stats.bytes_256_to_511,   &cnts.pkts_256_511_octets_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_detail.stats.rx_stats.bytes_512_to_1023,  &cnts.pkts_512_1023_octets_rcv);
    hsl_ctc_copy_64_int(&rx_stats.u.stats_detail.stats.rx_stats.bytes_1024_to_1518, &cnts.pkts_1024_1518_octets_rcv);
#else
    memcpy(&cnts.rx_detail, &rx_stats.u.stats_detail.stats.rx_stats, sizeof(cnts.rx_detail));
    memcpy(&cnts.tx_detail, &tx_stats.u.stats_detail.stats.tx_stats, sizeof(cnts.tx_detail));
#endif

    memcpy(res, &cnts, sizeof(struct hal_if_counters));

    do_gettimeofday(&current_time);
    tmpvar = current_time.tv_sec * 1000 + current_time.tv_usec / 1000;
    hsl_ctc_copy_64_int(&tmpvar, &res->last_sample_time);

    return 0;
}

/* Get Interface counters.

Parameters:
INOUT -> ifp - interface pointer
   
Returns:
0 on success
< 0 on error   
*/
int
hsl_ctc_get_if_counters(struct hsl_if *ifp)
{
  struct hsl_bcm_if *bcmifp;
  int ret;

  //HSL_FN_ENTER ();

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
      return (STATUS_WRONG_PARAMS); 
 

  /* Read counters from hw. */
  ret = _hsl_bcm_get_lport_counters(BCMIFP_L2(bcmifp).lport,&ifp->mac_cntrs);
  if (0 != ret) {
  	HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Get %s(%d) get stat error.\r\n", 
  	ifp->name, ifp->ifindex);
    return (STATUS_ERROR);
  }

  return (STATUS_OK);
}

/* Clear Interface counters.

Parameters:
INOUT -> ifp - interface pointer
   
Returns:
0 on success
< 0 on error   
*/
int
hsl_ctc_clear_if_counters(struct hsl_if *ifp)
{
    int ret = 0;
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
    if(!bcmifp) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) doesn't have a corresponding Broadcom interface structure\n", ifp->name, ifp->ifindex);
        HSL_FN_EXIT (STATUS_ERROR);
    }

    /* Ignore trunks. */
    if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
        HSL_FN_EXIT (STATUS_WRONG_PARAMS); 
 
 
    /* Read counters from hw. */
  
 // if (0 != bcm_stat_clear(bcmx_lport_bcm_unit(BCMIFP_L2(bcmifp).lport), BCMIFP_L2(bcmifp).lport))
  //  HSL_FN_EXIT (STATUS_ERROR);

    /* clean rx, tx counter */
    ctc_stats_clear_mac_stats(BCMIFP_L2(bcmifp).lport, CTC_STATS_MAC_STATS_RX);
    ctc_stats_clear_mac_stats(BCMIFP_L2(bcmifp).lport, CTC_STATS_MAC_STATS_TX);
  
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
  uint16 gport;
  int stg;
  int unit;
  int port;
  int ret;

  HSL_FN_ENTER ();

  if (! ifp || ifp->type != HSL_IF_TYPE_L2_ETHERNET)
    HSL_FN_EXIT (STATUS_ERROR);

  bcmifp = ifp->system_info;
  gport = BCMIFP_L2(bcmifp).lport;

  switch (type)
    {
    case HSL_IF_SWITCH_L2:
    case HSL_IF_SWITCH_L2_L3:
      {
	/* Enable learning. */
    #if 0
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
    #endif
    
      }
      break;
    case HSL_IF_SWITCH_L3:
      {
    #if 0
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
   #endif
        
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

  //init mirror id malloc
  init_mirror_id();

  HSL_FN_EXIT(0);
}

/*
  Port mirror deinit. 
*/
int
hsl_bcm_port_mirror_deinit (void)
{
  HSL_FN_ENTER();
 // bcmx_mirror_mode_set(BCM_MIRROR_DISABLE);
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
  uint16 to_lport, from_lport;
  int mirror_flags = 0;
  uint8 session_id = -1;
  ctc_mirror_dest_t mirror;
  HSL_FN_ENTER ();

  sal_memset(&mirror, 0, sizeof(ctc_mirror_dest_t));
  
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

  ret = alloc_mirror_id(from_lport, to_lport); 
  if (ret < 0) {
    printk("[%s, %d]mirror_id = %d\n", __func__, __LINE__, ret);
    HSL_FN_EXIT (-1);
  } else {
    session_id = ret;
  }

	direction |= from_bcmifp->mirror_flag;  /*由于nsm中配置不是覆盖的*/
	
  /* Set mirroring directions. */
  if (direction == HAL_PORT_MIRROR_DIRECTION_TRANSMIT)
    {
		mirror_flags = CTC_EGRESS;
    }
  if (direction == HAL_PORT_MIRROR_DIRECTION_RECEIVE)
    {
		mirror_flags = CTC_INGRESS;
    }
  if (direction == HAL_PORT_MIRROR_DIRECTION_BOTH)
  {
    mirror_flags = CTC_BOTH_DIRECTION;
  }

	/*先将配置ingress和Egress都不使能*/
  ret = ctc_mirror_set_port_en(from_lport, CTC_BOTH_DIRECTION, FALSE, session_id);
  if (ret < 0) {
  	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port mirrored port to %s, ret=%d\n", to_ifp->name, ret);
      HSL_FN_EXIT (-1);
  }
  //ret = bcmx_mirror_port_set(from_lport, to_lport, mirror_flags);
  ret = ctc_mirror_set_port_en(from_lport, mirror_flags, TRUE, session_id);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't set port mirrored port to %s, ret=%d\n", to_ifp->name, ret);
      HSL_FN_EXIT (-1);
    }

  mirror.dir = mirror_flags;
  mirror.type = CTC_MIRROR_L2SPAN_SESSION;
  mirror.acl_priority = 0;   /*0 or 1*/
  mirror.dest_gport = to_lport;

  ret = ctc_mirror_add_session(&mirror);
  if (ret < 0) {
    printk ("ctc_mirror_add_session error, ret=%d\n", ret);
    HSL_FN_EXIT (-1);
  }
  
 /*如果该接口已经配置到会话里面则不需要再次配置*/
  if (from_bcmifp->mirror_flag == HAL_PORT_MIRROR_DISABLE) {
  	mirror_member_inc(session_id);
  }
  
  from_bcmifp->mirror_flag = direction;
    
  HSL_FN_EXIT (0);

}

/*
  Port mirror unset.
*/
int
hsl_bcm_port_mirror_unset (struct hsl_if *to_ifp, struct hsl_if *from_ifp, enum hal_port_mirror_direction direction)
{

  struct hsl_bcm_if *to_bcmifp, *from_bcmifp;
  int ret;
  uint16 to_lport, from_lport;
  int mirror_flags = 0;
  uint8 session_id;
  ctc_mirror_dest_t mirror;
  int mirror_member;
  
  HSL_FN_ENTER ();

  sal_memset(&mirror, 0, sizeof(ctc_mirror_dest_t));

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

  ret = get_id_by_port(from_lport, to_lport, &session_id);
  if (ret < 0) {
    printk ("get_id_by_port error, ret=%d\n", ret);
    HSL_FN_EXIT (-1);
  }

  /* Set mirroring directions. */
  if (direction == HAL_PORT_MIRROR_DIRECTION_TRANSMIT)
    {
		mirror_flags = CTC_EGRESS;
    }
  if (direction == HAL_PORT_MIRROR_DIRECTION_RECEIVE)
    {
		mirror_flags = CTC_INGRESS;
    }
  if (direction == HAL_PORT_MIRROR_DIRECTION_BOTH)
  {
    mirror_flags = CTC_BOTH_DIRECTION;
  }

  mirror.dir = mirror_flags;
  mirror.type = CTC_MIRROR_L2SPAN_SESSION;
  mirror.acl_priority = 0;
  

  ret = ctc_mirror_set_port_en(from_lport, mirror_flags, FALSE, session_id);
  if (ret < 0) {
    printk ("ctc_mirror_set_port_en error, ret=%d\n", ret);
    HSL_FN_EXIT (-1);
  }


  /*判断,当会话中没有成员的时候删除会话*/
  from_bcmifp->mirror_flag &= ~direction;
  if (from_bcmifp->mirror_flag == HAL_PORT_MIRROR_DISABLE) {
	  mirror_member = mirror_member_dec(session_id);
	  if (mirror_member == 0) {
	  	    ret = free_mirror_id(session_id);
			if (ret < 0) {
				printk ("free_mirror_id error, ret=%d\n", ret);
				HSL_FN_EXIT (-1);
			}
			//ret = bcmx_mirror_port_set(from_lport, to_lport, mirror_flags);
			ret = ctc_mirror_remove_session(&mirror);
			if (ret < 0)
			{
				HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Can't unset port mirrored port to %s\n", to_ifp->name);
				HSL_FN_EXIT (-1);
			}
	  }
  }
  
  HSL_FN_EXIT (0);
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
#if 0
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
#endif
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
#if 0
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
#endif
  HSL_FN_EXIT (0);
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
  int ret = 0;

  HSL_FN_ENTER ();

  //ret = hsl_bcm_hw_if_secondary_hwaddrs_set (ifp, hwaddrlen, num, addresses);

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
  bcmifp = hsl_ctc_if_alloc ();
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
  hsl_ctc_if_free (bcmifp);
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
#if 1
#ifdef HAVE_L3 
  BCMIF_CB(hw_l3_if_configure)             = NULL;//hsl_ctc_if_l3_configure;
  BCMIF_CB(hw_l3_if_unconfigure)           = NULL;//hsl_ctc_if_l3_unconfigure;
  BCMIF_CB(hw_if_hwaddr_set)               = NULL;//hsl_bcm_if_hwaddr_set; // not support now
  BCMIF_CB(hw_if_secondary_hwaddrs_delete) = NULL;//hsl_bcm_hw_if_secondary_hwaddrs_delete;
  BCMIF_CB(hw_if_secondary_hwaddrs_add)    = NULL;//hsl_bcm_hw_if_secondary_hwaddrs_add;
  BCMIF_CB(hw_if_secondary_hwaddrs_set)    = NULL;//hsl_bcm_hw_if_secondary_hwaddrs_set;
  BCMIF_CB(hw_l3_if_flags_set)             = NULL;//hsl_ctc_if_l3_flags_set;  //hsl_bcm_if_l3_flags_set;
  BCMIF_CB(hw_l3_if_flags_unset)           = NULL;//hsl_ctc_if_l3_flags_unset;  //hsl_bcm_if_l3_flags_unset;
  BCMIF_CB(hw_l3_if_address_add)           = NULL;//hsl_ctc_if_l3_address_add;  //hsl_bcm_if_l3_address_add; 
  BCMIF_CB(hw_l3_if_address_delete)        = NULL;//hsl_ctc_if_l3_address_delete;  //hsl_bcm_if_l3_address_delete;
  BCMIF_CB(hw_l3_if_bind_fib)              = NULL;//hsl_ctc_if_l3_bind_fib;//hsl_bcm_if_l3_bind_fib; // not support now
  BCMIF_CB(hw_l3_if_unbind_fib)            = NULL;//hsl_ctc_if_l3_unbind_fib;//hsl_bcm_if_l3_unbind_fib; // not support now
#endif /* HAVE_L3 */
#else
#ifdef HAVE_L3
  BCMIF_CB(hw_l3_if_configure)             = NULL;
  BCMIF_CB(hw_l3_if_unconfigure)           = NULL;
  BCMIF_CB(hw_if_hwaddr_set)               = NULL;
  BCMIF_CB(hw_if_secondary_hwaddrs_delete) = NULL;
  BCMIF_CB(hw_if_secondary_hwaddrs_add)    = NULL;
  BCMIF_CB(hw_if_secondary_hwaddrs_set)    = NULL;
  BCMIF_CB(hw_l3_if_flags_set)             = NULL;
  BCMIF_CB(hw_l3_if_flags_unset)           = NULL;
  BCMIF_CB(hw_l3_if_address_add)           = NULL;
  BCMIF_CB(hw_l3_if_address_delete)        = NULL;
  BCMIF_CB(hw_l3_if_bind_fib)              = NULL;
  BCMIF_CB(hw_l3_if_unbind_fib)            = NULL;             
#endif
#endif
  BCMIF_CB(hw_set_switching_type)          = hsl_bcm_if_set_switching_type;
  BCMIF_CB(hw_if_mtu_set)                  = hsl_bcm_if_mtu_set;
  BCMIF_CB(hw_if_l3_mtu_set)               = NULL;
  BCMIF_CB(hw_if_packet_types_set)         = hsl_bcm_if_packet_types_set;
  BCMIF_CB(hw_if_packet_types_unset)       = hsl_bcm_if_packet_types_unset;
  BCMIF_CB(hw_if_get_counters)             = hsl_ctc_get_if_counters;
  BCMIF_CB(hw_if_clear_counters)           = hsl_ctc_clear_if_counters;
  BCMIF_CB(hw_if_duplex_set)               = hsl_ctc_if_duplex_set;
  BCMIF_CB(hw_if_autonego_set)             = hsl_ctc_if_autonego_set;
  BCMIF_CB(hw_if_bandwidth_set)            = hsl_ctc_if_bandwidth_set;
  BCMIF_CB(hw_if_init_portmirror)          = hsl_bcm_port_mirror_init;
  BCMIF_CB(hw_if_deinit_portmirror)        = hsl_bcm_port_mirror_deinit;
  BCMIF_CB(hw_if_set_portmirror)           = hsl_bcm_port_mirror_set;
  BCMIF_CB(hw_if_unset_portmirror)         = hsl_bcm_port_mirror_unset;
#ifdef HAVE_MPLS
  BCMIF_CB(hw_mpls_if_configure) = hsl_bcm_if_mpls_configure;
  BCMIF_CB(hw_mpls_if_unconfigure) = hsl_bcm_if_mpls_unconfigure;
#endif /* HAVE_MPLS */
#if 1
#ifdef HAVE_LACPD
  BCMIF_CB(hw_if_lacp_agg_add)             = hsl_ctc_aggregator_add;
  BCMIF_CB(hw_if_lacp_agg_del)             = hsl_ctc_aggregator_del;
  BCMIF_CB(hw_if_lacp_agg_port_attach)     = hsl_ctc_aggregator_port_add;
  BCMIF_CB(hw_if_lacp_agg_port_detach)     = hsl_ctc_aggregator_port_del;
  BCMIF_CB(hw_if_lacp_global_psc_set)         = hsl_ctc_lacp_global_psc_set;
  BCMIF_CB(hw_if_lacp_psc_set)             = NULL;
#endif /* HAVE_LACPD */ 
#else
#ifdef HAVE_LACPD
  BCMIF_CB(hw_if_lacp_agg_add)             = NULL;
  BCMIF_CB(hw_if_lacp_agg_del)             = NULL;
  BCMIF_CB(hw_if_lacp_agg_port_attach)     = NULL;
  BCMIF_CB(hw_if_lacp_agg_port_detach)     = NULL;
  BCMIF_CB(hw_if_lacp_psc_set)             = NULL;
  BCMIF_CB(hw_if_lacp_nuc_psc_set)         = NULL;
#endif /* HAVE_LACPD */ 

#endif

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

/* big edian */
int hsl_ctc_copy_64_int(uint64_t *src, ut_int64_t *dst)
{
    long long unsigned int tmp = 0;

    if(src == NULL || dst == NULL) {
        return -1;
    }

    dst->ll[0] = *src;

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

uint64_t hsl_ctc_convert_to_64_int(ut_int64_t *src)
{
    if(src == NULL) {
        return 0;
    }

    return src->ll[0];
}


