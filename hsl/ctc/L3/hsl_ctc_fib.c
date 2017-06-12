/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"

//#include "ctc_incl.h"
#include "ctc_nexthop.h"

#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_avl.h"
#include "hsl_logger.h"
#include "hsl_error.h"
#include "hsl_table.h"
#include "hsl_ether.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_ctc_if.h"
#include "hsl_ctc_ifmap.h"
#include "hsl_fib.h"
#include "hsl_fib_hw.h"
#ifdef HAVE_L2
#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"
#include "hsl_vlan.h"
#include "hsl_bridge.h"
#endif /* HAVE_L2 */
#include "fwdu_hal_id_uc.h"
#include "fwdu_hal_id_nbr.h"
#ifdef HAVE_MPLS
#include "hsl_mpls.h"
#include "hsl_ctc_mpls.h"
#endif /* HAVE_MPLS */
#include "hsl_ctc_nh.h"
#include "ctc_ipuc.h"
#include "ctc_l2.h"
#include "ctc_api.h"
#include "ctc_if_portmap.h"
#include "sys_greatbelt_nexthop_api_extend.h"

static struct hsl_fib_hw_callbacks hsl_ctc_fib_callbacks;

#define CTC_FUNC_CALL(op) \
{ \
    int rv = (op); \
    if (rv) \
    { \
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "%s():%u: %s\n", __FUNCTION__, __LINE__, ctc_get_error_desc(rv)); \
    } \
}



/* 
   Initialization. 
*/
#define HSL_CTC_IPUC_NHID_MIN  3U
#define HSL_CTC_IPUC_NHID_MAX  (HSL_CTC_IPUC_NHID_MIN + 4096U)

#define HSL_CTC_NHID_MIN (HSL_CTC_IPUC_NHID_MAX + 1U)
#define HSL_CTC_NHID_MAX (HSL_CTC_NHID_MIN + 4096U)
#define HSL_CTC_NHID_MAXNUM (HSL_CTC_NHID_MAX - HSL_CTC_NHID_MIN + 1U)
#define HSL_CTC_NHID_INVALID  0xFFFFFFU
#define HSL_CTC_NHID_ALLOCATED 1U
#define HSL_CTC_NHID_DEALLOCATED 0U
  
#define HSL_CTC_NHID_DESC_INITIALIZED 0x1U

static struct hsl_ctc_nhid_desc_s {
    int initialized;
    struct {
    unsigned int alloc;
    unsigned int nhid;
    hsl_ipv4Address_t addr;
    unsigned char masklen;
    } nhids[HSL_CTC_NHID_MAX + 1];
 } hsl_ctc_nhid_desc = {0};
#define HSL_CTC_NHID_IS_UNALLOCATED(nhid) ((nhid) >= HSL_CTC_NHID_MIN\
                                     && (nhid) <= HSL_CTC_NHID_MAX\
                                     && (hsl_ctc_nhid_desc.nhids[nhid].alloc) != HSL_CTC_NHID_ALLOCATED)

static void hsl_ctc_nhid_init(void)
{
    unsigned int i;
    if (hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
       memset(&hsl_ctc_nhid_desc, 0,  sizeof(hsl_ctc_nhid_desc));
       for (i = 0; i <HSL_CTC_NHID_MIN; i++) {
           hsl_ctc_nhid_desc.nhids[i].alloc = HSL_CTC_NHID_ALLOCATED;
       }
      hsl_ctc_nhid_desc.initialized = HSL_CTC_NHID_DESC_INITIALIZED;
      //printk("%s() %d\n", __FUNCTION__, __LINE__);
    }
}
static unsigned int
hsl_ctc_nhid_alloc(hsl_ipv4Address_t addr, unsigned char masklen)
{
    unsigned int i;
    if (hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    for (i = HSL_CTC_NHID_MIN; i <= HSL_CTC_NHID_MAX; i++) {
        //printk("%u, alloc=%u\n", i, hsl_ctc_nhid_desc.nhids[i].alloc);
        //printk("HSL_CTC_NHID_IS_UNALLOCATED(%u)=%u\n", i, HSL_CTC_NHID_IS_UNALLOCATED(i));
        if (HSL_CTC_NHID_IS_UNALLOCATED(i)) {
            hsl_ctc_nhid_desc.nhids[i].alloc = HSL_CTC_NHID_ALLOCATED;
            hsl_ctc_nhid_desc.nhids[i].addr = addr;
            hsl_ctc_nhid_desc.nhids[i].nhid = i;
            hsl_ctc_nhid_desc.nhids[i].masklen = masklen;
            //printk ("%s() %d alloc %u\n", __FUNCTION__, __LINE__, i);
            return i;
        }
    }
    return HSL_CTC_NHID_INVALID;
}                                  

static unsigned int
hsl_ctc_nhid_find_alloced(hsl_ipv4Address_t addr, unsigned char masklen)
{
    unsigned int i;
    if(hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    for (i = HSL_CTC_NHID_MIN; i<= HSL_CTC_NHID_MAX; i++) {
        if (hsl_ctc_nhid_desc.nhids[i].addr == addr
            && hsl_ctc_nhid_desc.nhids[i].masklen == masklen
            && hsl_ctc_nhid_desc.nhids[i].alloc == HSL_CTC_NHID_ALLOCATED) {
            return i;
        }
       
    }
    return HSL_CTC_NHID_INVALID;
} 


static void
hsl_ctc_nhid_dealloc(hsl_ipv4Address_t addr, unsigned char masklen)
{
    unsigned int i;
    if(hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    for (i = HSL_CTC_NHID_MIN; i<= HSL_CTC_NHID_MAX; i++) {
        if (hsl_ctc_nhid_desc.nhids[i].addr == addr
            && hsl_ctc_nhid_desc.nhids[i].masklen == masklen) {
            
            hsl_ctc_nhid_desc.nhids[i].alloc = HSL_CTC_NHID_DEALLOCATED;
            hsl_ctc_nhid_desc.nhids[i].addr = 0;
            hsl_ctc_nhid_desc.nhids[i].nhid = 0;
            hsl_ctc_nhid_desc.nhids[i].masklen = 0;
            return;
        }
       
    }
    return;
} 

static void
hsl_ctc_nhid_dealloc_by_id(unsigned int nhid)
{
    if(hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    if (hsl_ctc_nhid_desc.nhids[nhid].alloc == HSL_CTC_NHID_ALLOCATED) {    
        hsl_ctc_nhid_desc.nhids[nhid].alloc = HSL_CTC_NHID_DEALLOCATED;
    }
    return;
}



static int hsl_ctc_l3_route_add(struct hsl_prefix_entry *pe, ctc_ipuc_param_t *ipuc_route, struct hsl_nh_entry *nh)
{
    ctc_ipuc_param_t ipuc_host = {0};
    ctc_nh_info_t nh_host = {0};
    ctc_ipuc_param_t ipuc_route_find = {0};
    ctc_nh_info_t nh_route_find = {0};
    int ecmp_nhid;
    ctc_nh_ecmp_nh_param_t ecmp_member;
    struct hsl_if *ifp;
    struct hsl_bcm_if *bcmifp;
    int ret;
    
    HSL_FN_ENTER();
    if (!ipuc_route) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "NULL PARAM!\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }  
    if (!nh) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "NULL PARAM!\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    ifp = nh->ifp;
    if (!ifp) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "WRONG PARAM\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    } 
    bcmifp = ifp->system_info;
    if (! bcmifp) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "HSL_FIB_ERR_INVALID_PARAM\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    if (bcmifp->type != HSL_BCM_IF_TYPE_L3_IP) {
         HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Unsupport IF type %u!\n", bcmifp->type);
         HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }

    ipuc_host.vrf_id = ipuc_route->vrf_id;
    ipuc_host.ip.ipv4 = ntohl(nh->rn->p.u.prefix4);
    ipuc_host.masklen = 32;
    ipuc_host.nh_id = 0; /* will ignored nh_id, when finding, i think */
    ipuc_host.ip_ver = CTC_IP_VER_4;

    /* check nh IN HW or not */
    ret = ctc_ipuc_get(&ipuc_host);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "getting ipuc by %0#x/%d FAILED\n",
                ipuc_host.ip.ipv4, ipuc_host.masklen);
        HSL_FN_EXIT(HSL_FIB_ERR_HW_NH_NOT_FOUND);   
    }
    /* 已确认host route 存在 */

    /* one ip only corresponding one nhid */
    if (ipuc_host.nh_id != nh->system_info.nhid) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nhid confict\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    /* nhid should not tocpu or drop */
    if (nh->system_info.nhid <= 2) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nhid <=2 \n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }

    /* nhid should exist in nexthop table */
    ret = ctc_nh_get_nh_info(nh->system_info.nhid, &nh_host);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "getting nexthop info by nhid FAILED\n",
                nh->system_info.nhid);
        HSL_FN_EXIT(HSL_FIB_ERR_HW_NH_NOT_FOUND);   
    }

    /* check prefix route IN HW or not  */
    memcpy(&ipuc_route_find, ipuc_route, sizeof(ipuc_route_find));
    ipuc_route_find.nh_id = 0;
    ret = ctc_ipuc_get(&ipuc_route_find);
    if (ret < 0 || (ipuc_route_find.nh_id == 2)) {/* first to install prefix into hw */ 
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_get %s\n", ctc_get_error_desc(ret)); 
        ipuc_route->nh_id = nh->system_info.nhid;
        ret = ctc_ipuc_add(ipuc_route);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_add %s\n", ctc_get_error_desc(ret));       
            HSL_FN_EXIT(ret);
        }
        goto OK;
    }
    /* check prefix route already IN HW */
    /* for debug, pe->system_info.nhid alway should be eq to ipuc_route_find.nh_id */
    if (pe->system_info.nhid != ipuc_route_find.nh_id) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "Warn, pe->system_info.nhid(%d) != ipuc_route_find.nh_id(%d)\n",
        pe->system_info.nhid, ipuc_route_find.nh_id);
    }

    ret = ctc_nh_get_nh_info(ipuc_route_find.nh_id, &nh_route_find);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "ctc_nh_get_nh_info %s\n", ctc_get_error_desc(ret));
        HSL_FN_EXIT(-1);
    }

    /* deal with ecmp */
    /* same nexthop install again */ 
    if (ipuc_route_find.nh_id == nh->system_info.nhid) {
        if (ipuc_route_find.is_ecmp_nh) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "Warn, should not be ecmp\n");
        }
        HSL_FN_EXIT(0);
    }

    if (!(nh_route_find.flag & CTC_NH_INFO_FLAG_IS_ECMP)){ /*route_find nhid neq nhid and not ecmp route */
        /* create ecmp */
        memset(&ecmp_member, 0, sizeof(ecmp_member));
        ecmp_member.nhid[0] = ipuc_route_find.nh_id;
        ecmp_member.nhid[1] = nh->system_info.nhid;
        ecmp_member.nh_num = 2;
        ecmp_nhid = hsl_ctc_nhid_alloc(0, 0);
        ret = ctc_nh_add_ecmp(ecmp_nhid, &ecmp_member);
        if (ret < 0)
        {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "ecmp create error %s\n", ctc_get_error_desc(ret));
            HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);
        }
        ipuc_route->nh_id = ecmp_nhid;
        /* Question, should we del before add? i think there are no necessary */
        ret = ctc_ipuc_add(ipuc_route);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_add %s\n", ctc_get_error_desc(ret));       
            HSL_FN_EXIT(ret);
        }
        goto OK;
    } else {        /* ecmp route, add nh to its member */
         memset(&ecmp_member, 0, sizeof(ecmp_member));
         ecmp_member.nhid[0] = nh->system_info.nhid;
         ecmp_member.nh_num = 1;
         ecmp_member.upd_type = CTC_NH_ECMP_ADD_MEMBER;
         
         ret = ctc_nh_update_ecmp(pe->system_info.nhid, &ecmp_member);
        if (ret < 0 && (ret != CTC_E_NH_EXIST))
        {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_nh_update_ecmp %s\n", ctc_get_error_desc(ret));       
            HSL_FN_EXIT(ret);
        }
        ipuc_route->nh_id = pe->system_info.nhid;
    }
    
  OK:  
    if (pe) {
        pe->system_info.nhid = ipuc_route->nh_id;
        pe->flags = 0;
        SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_IN_HW);
    }
    HSL_FN_EXIT(0);
}


/* 注意处理查询ipuc表条目的nexthop nhid==2的情况 */
static int hsl_ctc_l3_route_delete(struct hsl_prefix_entry *pe, ctc_ipuc_param_t *ipuc_route, struct hsl_nh_entry *nh)
{
    ctc_ipuc_param_t ipuc_host = {0};
    ctc_nh_info_t nh_host = {0};
    ctc_ipuc_param_t ipuc_route_find = {0};
    ctc_nh_info_t nh_route_find = {0};
    int ecmp_nhid;
    ctc_nh_ecmp_nh_param_t ecmp_member;
    struct hsl_if *ifp;
    struct hsl_bcm_if *bcmifp;


    int ret;
    HSL_FN_ENTER();
    if (!ipuc_route) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "NULL PARAM!\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }  
    if (!nh) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "NULL PARAM!\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    ifp = nh->ifp;
    if (!ifp) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "WRONG PARAM\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    } 
    bcmifp = ifp->system_info;
    if (! bcmifp) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "HSL_FIB_ERR_INVALID_PARAM\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    if (bcmifp->type != HSL_BCM_IF_TYPE_L3_IP) {
         HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Unsupport IF type %u!\n", bcmifp->type);
         HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }

    
    /* nhid should not tocpu or drop */
    if (nh->system_info.nhid <= 2) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nhid <=2 \n");
        HSL_FN_EXIT(0);
    }
    
    memcpy(&ipuc_route_find, ipuc_route, sizeof(ipuc_route_find));
    ipuc_route_find.nh_id = 0;
    ret = ctc_ipuc_get(&ipuc_route_find);
    if (ret < 0 || ipuc_route_find.nh_id == 2) {/*  prefix not in hw or just to CPU */ 
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_get %s, ipuc_route_find.nh_id %d\n",
                ctc_get_error_desc(ret), ipuc_route_find.nh_id);
        goto OK;
    }
    
    ret = ctc_nh_get_nh_info(ipuc_route_find.nh_id, &nh_route_find);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_nh_get_nh_info %s\n", ctc_get_error_desc(ret));
        HSL_FN_EXIT(-1);
    }
    
    /* for debug, pe->system_info.nhid alway should be eq to ipuc_route_find.nh_id */
    if (pe->system_info.nhid != ipuc_route_find.nh_id) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "Warn, pe->system_info.nhid(%d) != ipuc_route_find.nh_id(%d)\n",
        pe->system_info.nhid, ipuc_route_find.nh_id);
    }

    
    if (!(nh_route_find.flag & CTC_NH_INFO_FLAG_IS_ECMP)){ /* not ecmp route */
        /* ipuc nexthop remove again */ 
        if (ipuc_route_find.nh_id == nh->system_info.nhid) {
            ipuc_route->nh_id = ipuc_route_find.nh_id;
            hsl_ctc_nhid_dealloc_by_id(ipuc_route->nh_id);
            ret = ctc_ipuc_remove (ipuc_route);
            if (ret < 0) {
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_remove %s\n", ctc_get_error_desc(ret));
                //HSL_FN_EXIT(ret);
            }
        } else {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ipuc_route_find.nh_id(%d) should eq nh->system_info.nhid(%d)\n",
                ipuc_route_find.nh_id, nh->system_info.nhid);  
        }
        goto OK;
    } else if (nh_route_find.flag & CTC_NH_INFO_FLAG_IS_ECMP) { /* ecmp route */
        if (nh_route_find.valid_ecmp_cnt > 2) { /* ecmp route, just del nh from its member */
             memset(&ecmp_member, 0, sizeof(ecmp_member));
             ecmp_member.nhid[0] = nh->system_info.nhid;
             ecmp_member.nh_num = 1;
             ecmp_member.upd_type = CTC_NH_ECMP_REMOVE_MEMBER;
            
             ret = ctc_nh_update_ecmp(ipuc_route_find.nh_id, &ecmp_member);
            if (ret < 0 && (ret != CTC_E_NH_EXIST))
            {
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_nh_update_ecmp %s\n", ctc_get_error_desc(ret));       
                //HSL_FN_EXIT(ret);
            }
            HSL_FN_EXIT(0);
        } else if (nh_route_find.valid_ecmp_cnt == 2) { /* ecmp route, del nh from its member, convert to ipuc route */
            ipuc_route->nh_id = nh_route_find.ecmp_mem_nh[0];
            ret = ctc_ipuc_add (ipuc_route);
            if (ret < 0) {
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_add %s\n", ctc_get_error_desc(ret));
                //HSL_FN_EXIT(ret);
            }
            ret = ctc_nh_remove_ecmp(ipuc_route_find.nh_id);
            if (ret < 0) {
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_nh_remove_ecmp %d %s\n", ipuc_route_find.nh_id, ctc_get_error_desc(ret));
                //HSL_FN_EXIT(ret);
            }
            hsl_ctc_nhid_dealloc_by_id(ipuc_route_find.nh_id);
            pe->system_info.nhid = ipuc_route->nh_id;
            HSL_FN_EXIT(0);
        } else {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "Warn Illegal state!\n"); 
        }
    }
    
  OK:  
    if (pe) {
        pe->system_info.nhid = 0;
        pe->flags = 0;
    }
    HSL_FN_EXIT(0);
}


/* 
 */
static int hsl_ctc_l3_host_add(ctc_ipuc_param_t *ipuc_host, u_char *hostmac, struct hsl_if *ifp)
{
  ctc_ipuc_param_t ipuc_info = {0};
  int ret;
  struct hsl_bcm_if *bcmifp;
  
  HSL_FN_ENTER();
  if (!ipuc_host) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "NULL PARAM!\n");
      HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }
  
  if (ipuc_host->ip_ver != CTC_IP_VER_4) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "WRONG PARAM!\n");
      HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }
  if (!ifp) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "WRONG PARAM\n");
      HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  } 
  bcmifp = ifp->system_info;
  if (! bcmifp) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "HSL_FIB_ERR_INVALID_PARAM\n");
      HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }
  if (bcmifp->type != HSL_BCM_IF_TYPE_L3_IP) {
       HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Unsupport IF type %u!\n", bcmifp->type);
       HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }


  if (ipuc_host->nh_id == 2){
      
  } else  {
      {
            ctc_ip_nh_param_t nh_param;
            ctc_l2_fdb_query_rst_t q_rst = {0};
            ctc_l2_fdb_query_t q_req;
            ctc_l2_addr_t qbuf[10];
            int ret;
            int nhid_tmp;
            
            
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "adding nexthop %0#x mac %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ipuc_host->ip.ipv4, hostmac[0], hostmac[1], hostmac[2], hostmac[3], hostmac[4], hostmac[5]); 
            
            memset(&nh_param, 0, sizeof(nh_param));
            memcpy(nh_param.mac, hostmac, HSL_ETHER_ALEN);
            nh_param.oif.vid = 0; /* Not use */
            nh_param.oif.oif_type = CTC_NH_OIF_TYPE_ROUTED_PORT; /* ctc_nh_oif_type_t */
            nh_param.oif.gport = ifp->ifindex; /* @TODO ifindex to ctc gport */

            nhid_tmp = hsl_ctc_nhid_alloc(ipuc_host->ip.ipv4, ipuc_host->masklen);
            /* 不用判断nhid合法性，非法时调api会出错 */
            ret = ctc_nh_add_ipuc(nhid_tmp, &nh_param);
            if (ret < 0) {
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Failed add ctc_nh_add_ipuc %s\n",
                         ctc_get_error_desc(ret));
               hsl_ctc_nhid_dealloc_by_id(nhid_tmp);
                HSL_FN_EXIT(ret);
            } else {
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "add ipuc, nhid %d for %#0x(%02x:%02x:%02x:%02x:%02x:%02x) on ifindex%d, gport %d\n",
                       nhid_tmp, ipuc_host->ip.ipv4, hostmac[0], hostmac[1], hostmac[2], hostmac[3], hostmac[4], hostmac[5],
                       ifp->ifindex, nh_param.oif.gport);
               ipuc_host->nh_id = nhid_tmp;
            }
        
        } /* code block */
  }
   ret = ctc_ipuc_add(ipuc_host);
   if (ret < 0) {
       HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_add %s\n",
                ctc_get_error_desc(ret));
       hsl_ctc_nhid_dealloc_by_id(ipuc_host->nh_id);         
       HSL_FN_EXIT(ret);
   }
  
  HSL_FN_EXIT(0);
}

static int hsl_ctc_l3_host_delete(ctc_ipuc_param_t *ipuc_host, u_char *hostmac, struct hsl_if *ifp)
{
    ctc_ipuc_param_t ipuc_info = {0};
    int ret;
    struct hsl_bcm_if *bcmifp;
	
    HSL_FN_ENTER();
    if (!ipuc_host) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "NULL PARAM!\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    
    if (ipuc_host->ip_ver != CTC_IP_VER_4) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "WRONG PARAM!\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    if (!ifp) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "WRONG PARAM!\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    } 
    bcmifp = ifp->system_info;
    if (!bcmifp) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "HSL_FIB_ERR_INVALID_PARAM\n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    if (bcmifp->type != HSL_BCM_IF_TYPE_L3_IP) {
         HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Unsupport IF type %u!\n", bcmifp->type);
         HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }

    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "deleting nexthop %0#x mac %02x:%02x:%02x:%02x:%02x:%02x\n",
            ipuc_host->ip.ipv4, hostmac[0], hostmac[1], hostmac[2], hostmac[3], hostmac[4], hostmac[5]); 
            

    /* 不用判断nhid合法性，非法时调api会出错 */
    ret = ctc_ipuc_remove(ipuc_host);
    if (ret < 0){
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "deleting connected route FAILD %s\n", ctc_get_error_desc(ret));
    }

    ret = ctc_nh_remove_ipuc (ipuc_host->nh_id);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Failed add ctc_nh_add_ipuc %s\n", ctc_get_error_desc(ret));
    }
    hsl_ctc_nhid_dealloc_by_id(ipuc_host->nh_id);

    /* 对ipuc及nexthop表 扫描是否继续引用这个nhid以及这个ip或mac的，有则告警 */
    
    HSL_FN_EXIT(0);
}

extern void ctc_app_usr_l3if_init(void);


static void _hsl_ctc_unrov_nhid(unsigned int nhid) 
{
    int ret;
    ctc_ip_nh_param_t nh_param;
    unsigned char gchip;
    unsigned short gport;

    return 0;
    ctc_get_gchip_id(0, &gchip);
    gport = CTC_MAP_LPORT_TO_GPORT(gchip, 59);

    memset(&nh_param, 0, sizeof(nh_param));
    nh_param.flag = CTC_IP_NH_FLAG_UNROV;
    nh_param.oif.oif_type = CTC_NH_OIF_TYPE_ROUTED_PORT;
    nh_param.oif.gport = gport; /* default unrov to this gport */
    ret = ctc_nh_add_ipuc(nhid, &nh_param);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "Initial nexthop table err nhid%d to %u %s\n", nhid, gport, ctc_get_error_desc(ret));
    }
}

int 
hsl_ctc_fib_init (hsl_fib_id_t fib_id)
{
    //ctc_ip_nh_param_t nh_param;
    unsigned int i;
    //int ret;
    //int default_oif_l3ifid;
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 
    //ctc_app_usr_l3if_init();
#if 0
    {
        int gchip;
        int gport;
        ctc_get_gchip_id(0, &gchip);
        gport = CTC_MAP_LPORT_TO_GPORT(gchip, ctc_if_ads_portmap[port_id]);
        ctc_l3if_t l3if_tmp;

        /* create one use l3if */
        ctc_get_gchip_id(0, &gchip);
        gport = CTC_MAP_LPORT_TO_GPORT(gchip, ctc_if_ads_portmap[port_id]);
        ctc_port_set_property(gport, CTC_PORT_PROP_MAC_EN, 1); //port GPORT mac enable
        ctc_port_set_property(gport, CTC_PORT_PROP_PORT_EN, 1); //port GPORT port-en enable
		sal_memset (&l3if_tmp, 0, sizeof(l3if_tmp));  
		l3if_tmp.gport = gport;
		l3if_tmp.l3if_type = CTC_L3IF_TYPE_PHY_IF;
		CTC_FUNC_CALL(ctc_l3if_create(gport, &l3if_tmp)); //l3if create ifid L3IFID type phy-if gport GPORT
		CTC_FUNC_CALL(ctc_l3if_set_property(gport, CTC_L3IF_PROP_ROUTE_EN, 1));
		CTC_FUNC_CALL(ctc_l3if_set_property(gport, CTC_L3IF_PROP_IPV4_UCAST, 1));
		CTC_FUNC_CALL(ctc_l3if_set_property(gport, CTC_L3IF_PROP_IPV4_MCAST, 1));
		CTC_FUNC_CALL(ctc_port_set_phy_if_en(gport, 1));

    }
#endif
    {
        //unsigned char gchip;
        //unsigned int gport;
        //ctc_l3if_t l3if_tmp;
        //int ret;
        //ctc_get_gchip_id(0, &gchip);
        //gport = CTC_MAP_LPORT_TO_GPORT(gchip, 28);
        //sal_memset (&l3if_tmp, 0, sizeof(l3if_tmp));
        //l3if_tmp.gport = gport;
        //l3if_tmp.l3if_type = CTC_L3IF_TYPE_PHY_IF;
        //ret = ctc_l3if_create(gport, &l3if_tmp);
        //if (ret < 0) {
        //    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "ctc_l3if_create  %d %s\n", gport, ctc_get_error_desc(ret));
        //}
        //
        //default_oif_l3ifid = gport;
    
    
    }

    //memset(&nh_param, 0, sizeof(nh_param));
    for (i = HSL_CTC_IPUC_NHID_MIN; i <= HSL_CTC_IPUC_NHID_MAX; i++) {
        //nh_param.flag = CTC_IP_NH_FLAG_UNROV;
        //nh_param.oif.oif_type = CTC_NH_OIF_TYPE_ROUTED_PORT;
        //nh_param.oif.gport = default_oif_l3ifid;
        //ret = ctc_nh_add_ipuc(i, &nh_param);
        //if (ret < 0) {
        //    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "Initial nexthop table err %d %s\n", i, ctc_get_error_desc(ret));
        //}
        //_hsl_ctc_unrov_nhid(i);
    }
    
  return 0;
}

/* 
   Deinitialization. 
*/
int 
hsl_ctc_fib_deinit (hsl_fib_id_t fib_id)
{
  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 

  return 0;
}

/* 
   Dump. 
*/
void 
hsl_ctc_fib_dump (hsl_fib_id_t fib_id)
{
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "Entering %s()\n", __FUNCTION__); 

  return;
}

int 
hsl_ctc_prefix_add (hsl_fib_id_t fib_id, struct hsl_route_node *rnp, struct hsl_nh_entry *nh)
{
      ctc_ipuc_param_t ipuc_info = {0};
      struct hsl_prefix_entry *pe;
      int ret;
      char buf[256];
      
      HSL_FN_ENTER();
      if (!rnp) {
          HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "rnp NULL \n");
          HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
      }
      pe = rnp->info;
      if (!nh) {
          HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "nh NULL \n");
          HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
      }
      
      hsl_prefix2str (&rnp->p, buf, sizeof(buf)); 
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_ctc_prefix_add %s, nh=%#0x\n", buf, nh->rn->p.u.prefix4);

      ipuc_info.vrf_id = fib_id;
      ipuc_info.ip.ipv4 = ntohl(rnp->p.u.prefix4);
      ipuc_info.masklen = rnp->p.prefixlen;
      ipuc_info.nh_id = nh->system_info.nhid;
      ipuc_info.ip_ver = CTC_IP_VER_4;
      ipuc_info.route_flag = CTC_IPUC_FLAG_CONNECT;
      

      /* Add the prefix route. */
      ret = hsl_ctc_l3_route_add(pe, &ipuc_info, nh);
      HSL_FN_EXIT(ret);
}


/* 
   Delete prefix. 
*/

int
hsl_ctc_prefix_delete (hsl_fib_id_t fib_id, struct hsl_route_node *rnp, struct hsl_nh_entry *nh)
{ 
    struct hsl_prefix_entry *pe;
    ctc_ipuc_param_t ipuc_info = {0};
    int ret;
    
    HSL_FN_ENTER();
    if (!rnp) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "rnp NULL \n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    } 
    if (!nh) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "nh NULL \n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_ctc_prefix_delete prefix = %x, mask = %d, nh = %#x\n",
      rnp->p.u.prefix4, rnp->p.prefixlen, nh->rn->p.u.prefix4);   
    pe = rnp->info;

    ipuc_info.vrf_id = fib_id;
    ipuc_info.ip.ipv4 = ntohl(rnp->p.u.prefix4);
    ipuc_info.masklen = rnp->p.prefixlen;
    ipuc_info.nh_id = nh->system_info.nhid;
    ipuc_info.ip_ver = CTC_IP_VER_4;
    ipuc_info.route_flag = CTC_IPUC_FLAG_CONNECT;
    
    /* Remove the route. */
    ret = hsl_ctc_l3_route_delete(pe, &ipuc_info, nh);
    if (ret < 0)
    {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "deleting FAILED\n");
    }
    
    if (pe) {
        pe->flags = 0;
    } 
    
    HSL_FN_EXIT(0);
}


/*
  Set prefix as exception to CPU.
*/

int
hsl_ctc_prefix_exception (hsl_fib_id_t fib_id, struct hsl_route_node *rnp)
{
    hsl_prefix_t *p;
    hsl_ipv4Address_t addr, mask;
    struct hsl_prefix_entry *pe;
    ctc_ip_nh_param_t nh_param = {0};
    ctc_ipuc_param_t ipuc_info = {0};
    int ret;
    char buf[256];

    HSL_FN_ENTER();
    pe = rnp->info;
    p = &rnp->p;
    hsl_prefix2str (p, buf, sizeof(buf)); 
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_ctc_prefix_exception add %s\n", buf);
    
    ipuc_info.vrf_id = fib_id;
    ipuc_info.ip_ver = CTC_IP_VER_4;
    if (p->family == AF_INET)
    {
        hsl_masklen2ip (p->prefixlen, (hsl_ipv4Address_t *) &mask);
        addr = p->u.prefix4;
        addr &= mask;
        ipuc_info.ip.ipv4 = ntohl(addr);
        ipuc_info.masklen = p->prefixlen;
    }
    if (CTC_E_NONE == ctc_ipuc_get(&ipuc_info)) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "ipuc %s nexthop %d exist!\n", buf, ipuc_info.nh_id);
    }
    ipuc_info.nh_id = 2; /* TO CPU */
    
    /* Add connected route to prefix table. */
    ret = ctc_ipuc_add(&ipuc_info);
    if (ret < 0)
      {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Add prefix_exception for %s Failed %s\n",
                 buf, ctc_get_error_desc(ret));
       HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);
      }
    
    if (pe)
      {
        pe->system_info.nhid = ipuc_info.nh_id;
        SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_IN_HW);
        SET_FLAG (pe->flags, HSL_PREFIX_ENTRY_EXCEPTION);
      }
    HSL_FN_EXIT(0);
}

/* 
   Add nexthop. 
*/

int 
hsl_ctc_nh_add (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh)
{
  ctc_ipuc_param_t ipuc_info = {0};
  int ret;
  char buf[256];
  struct hsl_avl_node *node;
  struct hsl_route_node *rnp;
  
  HSL_FN_ENTER();
  if (!nh) {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "HSL_FIB_ERR_INVALID_PARAM\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }

  if (nh->rn->p.family != AF_INET)
  {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "HSL_FIB_ERR_INVALID_PARAM\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);    
  }

  hsl_prefix2str (&nh->rn->p, buf, sizeof(buf)); 
  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_ctc_nh_add %s, mac %02x:%02x:%02x:%02x:%02x:%02x\n", 
  	buf, nh->mac[0], nh->mac[1], nh->mac[2], nh->mac[3], nh->mac[4], nh->mac[5]);

  
  ipuc_info.vrf_id = fib_id;
  ipuc_info.ip.ipv4 = ntohl(nh->rn->p.u.prefix4);
  ipuc_info.masklen = 32;
  ipuc_info.nh_id = 0; /*to be alloced by  hsl_ctc_l3_host_add */
  ipuc_info.ip_ver = CTC_IP_VER_4;
  ipuc_info.route_flag = CTC_IPUC_FLAG_NEIGHBOR;

  ret = hsl_ctc_l3_host_add(&ipuc_info, nh->mac, nh->ifp);
  if (ret < 0) { 
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error adding nexthop %s from hardware %s\n", buf);
      HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);
  }
  nh->system_info.nhid = ipuc_info.nh_id;

  HSL_FN_EXIT(0);
}

/*
  Nexthop delete. 
*/
int 
hsl_ctc_nh_delete (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh)
{
  int ret;
  char buf[256];
  ctc_ip_nh_param_t nh_param = {0};
  ctc_ipuc_param_t ipuc_info = {0};

  HSL_FN_ENTER();

  if (!nh) {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "nh NULL\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }
  if (nh->rn->p.family != AF_INET)
  {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "HSL_FIB_ERR_INVALID_PARAM\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);    
  }

  hsl_prefix2str (&nh->rn->p, buf, sizeof(buf)); 
  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "hsl_ctc_nh_delete %s, mac %02x:%02x:%02x:%02x:%02x:%02x\n", 
  	buf, nh->mac[0], nh->mac[1], nh->mac[2], nh->mac[3], nh->mac[4], nh->mac[5]);

  /* Delete the host route. */
  if (nh->system_info.nhid < 2) {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "HSL_CTC_NHID_INVALID\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }
  
  ipuc_info.vrf_id = fib_id;
  ipuc_info.ip.ipv4 = ntohl(nh->rn->p.u.prefix4);
  ipuc_info.masklen =nh->rn->p.prefixlen;
  ipuc_info.nh_id = nh->system_info.nhid;
  ipuc_info.ip_ver = CTC_IP_VER_4;
  ipuc_info.route_flag = CTC_IPUC_FLAG_NEIGHBOR;
    
  ret = hsl_ctc_l3_host_delete(&ipuc_info, nh->mac, nh->ifp);
  if (ret < 0) {    
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "Error deleting ipuc %s to hardware %s\n",
              buf, ctc_get_error_desc(ret));
  }
  nh->system_info.nhid = 0;

  HSL_FN_EXIT(0);

}

/*
  Get maximum number of multipaths. 
*/
int
hsl_ctc_get_max_multipath(u_int32_t *ecmp)
{
   HSL_FN_ENTER();

   if(!ecmp) {
     HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
   }
   
   *ecmp = 8;
   HSL_FN_EXIT(STATUS_OK); 
}


/*
  Check if nexthop entry has been hit.
*/
int
hsl_ctc_nh_hit (hsl_fib_id_t fib_id, struct hsl_nh_entry *nh)
{
    unsigned int flags = 1;
    char buf[256];  
   
    if (flags) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "nexthop %s hit Valid\n", buf); 
      return 1; /* Valid. */
    } else {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "nexthop %s hit Invalid\n", buf); 
      return 0; /* Invalid. */
    }
}


/*
  Add connected route as exception to prefix table.
*/
int
hsl_ctc_add_connected_route (hsl_fib_id_t fib_id, hsl_prefix_t *prefix, struct hsl_if *ifp)
{
  hsl_ipv4Address_t addr, mask;
  int ret;
  ctc_ipuc_param_t ipuc_info = {0};
  char buf[256];

  HSL_FN_ENTER();
  if (!prefix) {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "NULL PARAM\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);  
  }
  if (!ifp)
  {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "NULL PARAM\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);    
  }

  hsl_prefix2str (prefix, buf, sizeof(buf));
  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "adding connected route %s to hardware\n", buf);

  /* Reject lookback address. */
  if (prefix->family == AF_INET && ntohl(prefix->u.prefix4) == INADDR_LOOPBACK) {
      HSL_FN_EXIT(0);
  }

  /* For all other connected addresses add a prefix route going to the
     CPU. */
     
  ipuc_info.vrf_id = fib_id;
  ipuc_info.ip_ver = CTC_IP_VER_4;
  if (prefix->family == AF_INET)
  {
      hsl_masklen2ip (prefix->prefixlen, (hsl_ipv4Address_t *) &mask);
      addr = prefix->u.prefix4;
      addr &= mask;
      ipuc_info.ip.ipv4 = ntohl(addr);
      ipuc_info.masklen = prefix->prefixlen;
  }

  ipuc_info.nh_id = 2; /* ToCpu Nexthop */
  /* Add connected route to prefix table. */
  ret = ctc_ipuc_add(&ipuc_info);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "adding connected route FAILED %s\n", ctc_get_error_desc(ret));
      HSL_FN_EXIT(-1);
    }

  HSL_FN_EXIT(0);
}

/* 
   Delete connected route as exception to prefix table.
*/
int
hsl_ctc_delete_connected_route (hsl_fib_id_t fib_id, hsl_prefix_t *prefix, struct hsl_if *ifp)
{
  hsl_ipv4Address_t addr, mask;
  ctc_ipuc_param_t ipuc_info = {0};
  int ret;
  char buf[256];

  HSL_FN_ENTER();
  if (!prefix) {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "NULL PARAM\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);  
  }
  if (!ifp)
  {
    HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "NULL PARAM\n");
    HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);    
  }

  hsl_prefix2str (prefix, buf, sizeof(buf));
  HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "deleting connected route %s to hardware\n", buf);
  
  /* For all other connected addresses delete the prefix route going to the
     CPU. */

  ipuc_info.vrf_id = fib_id;
  ipuc_info.ip_ver = CTC_IP_VER_4;

  if (prefix->family == AF_INET)
    {
      hsl_masklen2ip (prefix->prefixlen, (hsl_ipv4Address_t *) &mask);
      addr = prefix->u.prefix4;
      addr &= mask;
      ipuc_info.ip.ipv4 = ntohl(addr);
      ipuc_info.masklen = prefix->prefixlen;
    }
  
  ipuc_info.nh_id = 2; /* ToCpu Nexthop */
  ret = ctc_ipuc_remove(&ipuc_info);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "deleting connected route FAILD %s\n", ctc_get_error_desc(ret));
      HSL_FN_EXIT(-1);
    }

  HSL_FN_EXIT(0);
}

static void fwdu_hal_iduc_route_dump_buf(fwdu_hal_ufib4_t *iduc)
{
#define _DUMP_BUF_SZ 1024
    int len = 0;
    char buf[_DUMP_BUF_SZ];
    int i;
    
    
    len =  sprintf(buf+len, "\nprefix       :%#8x\n", iduc->prefix);
    len += sprintf(buf+len, "prefix_len   :%u\n", iduc->prefix_len);
    len += sprintf(buf+len, "fib          :%u\n", iduc->fib);
    len += sprintf(buf+len, "cmd          :%s(%u)\n", iduc->cmd == HAL_FWDU_UFIB4_ADD ? "HAL_FWDU_UFIB4_ADD":"HAL_FWDU_UFIB4_DEL",iduc->cmd);
    len += sprintf(buf+len, "nexthops     :\n");
    for(i=0;i < FWDU_HAL_MAX_ECMP_COUNT;i++) {
        if(iduc->nexthops.nh[i].valid != 0) {
            len += sprintf(buf+len, "nexthops.nh[%d]: valid nbr_index %u, blade %u\n", i, iduc->nexthops.nh[i].nbr_index, iduc->nexthops.nh[i].target_blade);
        }
    }
    len += sprintf(buf+len, "\r\n");
    HSL_ASSERT(len <_DUMP_BUF_SZ);
    buf[len] = '\0';
    printk("%s", buf);
    return;
#undef _DUMP_BUF_SZ
}

int hsl_ctc_direct_prefix_del (void *data)
{
    fwdu_hal_ufib4_t *entry = data;
    int ret;
    ctc_ipuc_param_t ipuc_route_find = {0};
    ctc_nh_info_t nh_route_find = {0};
    

    HSL_FN_ENTER();
    if (!entry) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "entry NULL \n");
        HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
    }
    
  //fwdu_hal_iduc_route_dump_buf(entry);  

  ipuc_route_find.vrf_id = entry->fib;
  ipuc_route_find.ip.ipv4 = entry->prefix;
  ipuc_route_find.masklen = entry->prefix_len;
  ipuc_route_find.nh_id = 0;
  ipuc_route_find.ip_ver = CTC_IP_VER_4;
  ipuc_route_find.route_flag = 0;
  
  ret = ctc_ipuc_get(&ipuc_route_find);
  if (ret < 0) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_nh_get_nh_info %s\n", ctc_get_error_desc(ret));
      HSL_FN_EXIT(0);
  }

  ret = ctc_nh_get_nh_info(ipuc_route_find.nh_id, &nh_route_find);
  if (ret < 0) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_nh_get_nh_info %s\n", ctc_get_error_desc(ret));
      HSL_FN_EXIT(-1);
  }
  
  if (!(nh_route_find.flag & CTC_NH_INFO_FLAG_IS_ECMP)) { /* not ecmp route */
       ret = ctc_ipuc_remove (&ipuc_route_find);
      if (ret < 0) {
              HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_remove %s\n", ctc_get_error_desc(ret));
      }
  } else if (nh_route_find.flag & CTC_NH_INFO_FLAG_IS_ECMP) { /* ecmp route */
      ret = ctc_ipuc_remove (&ipuc_route_find);
      if (ret < 0) {
              HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_remove %s\n", ctc_get_error_desc(ret));
      }
      ret = ctc_nh_remove_ecmp(ipuc_route_find.nh_id);
      if (ret < 0) {
          HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_nh_remove_ecmp %d %s\n", ipuc_route_find.nh_id, ctc_get_error_desc(ret));
      }
      hsl_ctc_nhid_dealloc(ipuc_route_find.ip.ipv4, ipuc_route_find.masklen);
  }
  
OK:
  HSL_FN_EXIT(0);
}

int hsl_ctc_direct_prefix_add (void *data)
{
  fwdu_hal_ufib4_t *entry = data;
  ctc_ipuc_param_t ipuc_route = {0};
  int ret;
  int ecmp_nhid;
  ctc_nh_ecmp_nh_param_t ecmp_member;
  int ecmp_cnt = 0;
  int i;
  
  HSL_FN_ENTER();
  if (!entry) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "entry NULL \n");
      HSL_FN_EXIT(HSL_FIB_ERR_INVALID_PARAM);
  }

  //fwdu_hal_iduc_route_dump_buf(entry);
  {
      /* check exist or not, del first when exist */
      ctc_ipuc_param_t ipuc_route_find;
      int ret1;
      
      ipuc_route_find.vrf_id = entry->fib;
      ipuc_route_find.ip.ipv4 = entry->prefix;
      ipuc_route_find.masklen = entry->prefix_len;
      ipuc_route_find.nh_id = 0;
      ipuc_route_find.ip_ver = CTC_IP_VER_4;
      ipuc_route_find.route_flag = 0;
      
      ret1 = ctc_ipuc_get(&ipuc_route_find);
      if (ret1 >= 0) {
            hsl_ctc_direct_prefix_del(entry);  
      }
  }
  
  memset(&ecmp_member, 0, sizeof(ecmp_member));
  for(i=0;i < FWDU_HAL_MAX_ECMP_COUNT;i++) {
      if(entry->nexthops.nh[i].valid != 0) {
        //len += sprintf(buf+len, "nexthops.nh[%d]: valid nbr_index %u, blade %u\n", i, iduc->nexthops.nh[i].nbr_index, iduc->nexthops.nh[i].target_blade);
        ecmp_member.nhid[ecmp_cnt] = entry->nexthops.nh[i].nbr_index;
        ecmp_cnt++;
      }
  }

  if(ecmp_cnt > 1) {   /* ecmp route */
      ecmp_member.nh_num = ecmp_cnt;
      ecmp_member.upd_type = CTC_NH_ECMP_ADD_MEMBER;
      ecmp_nhid = hsl_ctc_nhid_alloc(entry->prefix, entry->prefix_len);
      ret = ctc_nh_add_ecmp(ecmp_nhid, &ecmp_member);
      if (ret < 0)
      {
          hsl_ctc_nhid_dealloc_by_id(ecmp_nhid);
          HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "ecmp create error %s\n", ctc_get_error_desc(ret));
          HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);
      }
      ipuc_route.vrf_id = entry->fib;
      ipuc_route.ip.ipv4 = entry->prefix;
      ipuc_route.masklen = entry->prefix_len;
      ipuc_route.nh_id = ecmp_nhid;
      ipuc_route.ip_ver = CTC_IP_VER_4;
      ipuc_route.route_flag = CTC_IPUC_FLAG_CONNECT;
      
      ret = ctc_ipuc_add(&ipuc_route);
      if (ret < 0) {
          hsl_ctc_nhid_dealloc_by_id(ecmp_nhid);
          HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_DEBUG, "ctc_ipuc_add %s\n", ctc_get_error_desc(ret));
          HSL_FN_EXIT(0); 
      }
  } else if(ecmp_cnt == 1) {
      memset(&ipuc_route, 0, sizeof(ipuc_route));
      ipuc_route.vrf_id = entry->fib;
      ipuc_route.ip.ipv4 = entry->prefix;
      ipuc_route.masklen = entry->prefix_len;
      ipuc_route.nh_id = ecmp_member.nhid[0];
      ipuc_route.ip_ver = CTC_IP_VER_4;
      ipuc_route.route_flag = CTC_IPUC_FLAG_CONNECT;
       
      ret = ctc_ipuc_add(&ipuc_route);
      if (ret < 0) {
          HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "ctc_ipuc_add %s\n",
                   ctc_get_error_desc(ret));    
          HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);
      }


  } else {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "none valid route\n");
      HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);  
  }
  HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);
}

/* 
 根据需要del的nhid，使之最终变成unrov 的ipuc unrov nhid
 */
int hsl_ctc_direct_nh_del (void *data)
{
    fwdu_hal_nbr_data_t *nbr = data;
    ctc_ipuc_param_t ipuc_host = {0};
    ctc_ipuc_param_t ipuc_host_find = {0};
    ctc_ip_nh_param_t nh_fwd_param;
    api_extend_sys_greatbelt_nh_type_t nhtype;
    int ret;
    int rm_nhid_flag = 0;

#if 0
    /* hsl_ctc_direct_nh_add 也可能调用，只有在npas直接调用邻居删除时才打印 */
    if(nbr->cmd == HAL_FWDU_NBR_DEL) {
        printk("HAL_FWDU_NBR_DEL\n"
              "nbr_index    : %u\n"
              "nbr_type     : %u\n"
              "outif_index  : %u\n"
              "nexthop.addr4: %#0x\n"
              "nexthop.dmac : %02x%02x.%02x%02x.%02x%02x\n"
              "vrfid        : %u\n"
              "cmd          : %u\n",
              nbr->nbr_index,
              nbr->nbr_type,
              nbr->outif_index,
              nbr->nexthop.addr4,
              nbr->nexthop.dmac[0],
              nbr->nexthop.dmac[1],
              nbr->nexthop.dmac[2],
              nbr->nexthop.dmac[3],
              nbr->nexthop.dmac[4],
              nbr->nexthop.dmac[5],
              nbr->vrfid,
              nbr->cmd);
    }
 #endif
          
    if (nbr->nbr_index <=2) {
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "illegal nbr_index %u\n",
                 nbr->nbr_index);    
        HSL_FN_EXIT(HSL_FIB_ERR_HW_OPERATION_FAILED);
    }

    /* check nhid exist ornot and its type */
    ret = api_extend_sys_greatbelt_nh_get_type(nbr->nbr_index /* ipuc nhid */, &nhtype);
    if (ret < 0) {
        if (ret == CTC_E_NH_NOT_EXIST) {
            /* nhid not exist */
            rm_nhid_flag = 0;
        } else { /* nhid exist, some other err */
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "api_extend_sys_greatbelt_nh_get_type err %s\n",
                     ctc_get_error_desc(ret));
            rm_nhid_flag = 1;
        }
    } else { /* nhid exist */
        rm_nhid_flag = 1;
    }

    /* check ipuc and try to rm host in ipuc */
    memset(&ipuc_host, 0, sizeof(ipuc_host));
    ipuc_host.vrf_id = nbr->vrfid;
    ipuc_host.ip.ipv4 = nbr->nexthop.addr4;
    ipuc_host.masklen = 32;
    ipuc_host.nh_id = nbr->nbr_index;
    ipuc_host.ip_ver = CTC_IP_VER_4;
    ipuc_host.route_flag = CTC_IPUC_FLAG_NEIGHBOR;
    
    memcpy(&ipuc_host_find, &ipuc_host, sizeof(ipuc_host_find));
    ipuc_host_find.nh_id = 0;
    ret = ctc_ipuc_get(&ipuc_host_find);
    if (ret >= 0) {
        /* exist */
        ret = ctc_ipuc_remove(&ipuc_host);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "ctc_ipuc_remove %s\n",
                ctc_get_error_desc(ret));    
        }
    } else {
      ; /* do nothing */
    }

    /* del nhid base on its type */
    if (rm_nhid_flag) {
        switch(nhtype) {
            case API_EXTEND_SYS_NH_TYPE_IPUC:
               ret = ctc_nh_remove_ipuc(nbr->nbr_index);
               _hsl_ctc_unrov_nhid(nbr->nbr_index);
            break;
            case API_EXTEND_SYS_NH_TYPE_MISC:
               ret = ctc_nh_remove_misc(nbr->nbr_index); 
               _hsl_ctc_unrov_nhid(nbr->nbr_index);
            break;
            case API_EXTEND_SYS_NH_TYPE_UNROV: /* 不处理，不是hsl_ctc_direct_nh_add分配的 */
               HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nbr_index %u is API_EXTEND_SYS_NH_TYPE_UNROV type\n", nbr->nbr_index);
               ret = 0;  
            break;
            case API_EXTEND_SYS_NH_TYPE_DROP: /* 不处理，不是hsl_ctc_direct_nh_add分配的 */
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nbr_index %u is API_EXTEND_SYS_NH_TYPE_DROP type\n", nbr->nbr_index);
                ret = 0;
            break;
            case API_EXTEND_SYS_NH_TYPE_TOCPU:
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nbr_index %u is API_EXTEND_SYS_NH_TYPE_TOCPU type\n", nbr->nbr_index);
                ret = 0;
            break;
            default:
                HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nbr_index %u is %u type\n", nbr->nbr_index, nhtype);
                ret = 0;
        }
        
        if (ret < 0) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "nhid remove err %s\n", ctc_get_error_desc(ret));  
        }
    }


    HSL_FN_EXIT(0);
ERR:
  
    HSL_FN_EXIT(-1);
}

int hsl_ctc_direct_nh_add (void *data)
{
  fwdu_hal_nbr_data_t *nbr = data;
  ctc_ipuc_param_t ipuc_host = {0};
  ctc_misc_nh_param_t misc_nh_param;
  int ret;

#if 0
  if(nbr->cmd == HAL_FWDU_NBR_ADD) {
    printk("HAL_FWDU_NBR_ADD\n"
          "nbr_index    : %u\n"
          "nbr_type     : %u\n"
          "outif_index  : %u\n"
          "nexthop.addr4: %#0x\n"
          "nexthop.dmac : %02x%02x.%02x%02x.%02x%02x\n"
          "vrfid        : %u\n"
          "cmd          : %u\n",
          nbr->nbr_index,
          nbr->nbr_type,
          nbr->outif_index,
          nbr->nexthop.addr4,
          nbr->nexthop.dmac[0],
          nbr->nexthop.dmac[1],
          nbr->nexthop.dmac[2],
          nbr->nexthop.dmac[3],
          nbr->nexthop.dmac[4],
          nbr->nexthop.dmac[5],
          nbr->vrfid,
          nbr->cmd);

  }
#endif
  
  //{
      //int ret1;
      //ctc_ipuc_param_t ipuc_route_find = {0};
      
      //ipuc_route_find.vrf_id = 0;
      //ipuc_route_find.ip.ipv4 = nbr->nexthop.addr4;
      //ipuc_route_find.masklen = 32;
      //ipuc_route_find.nh_id = 0;//nbr->nbr_index;
      //ipuc_route_find.ip_ver = CTC_IP_VER_4;
      //ipuc_route_find.route_flag = 0;//CTC_IPUC_FLAG_NEIGHBOR;

      //ret1 = ctc_ipuc_get(&ipuc_route_find);
      //if (ret1 >= 0) {
      /* exist */
      //    hsl_ctc_direct_nh_del(data);
      //} else {
      //  ; /* do nothing */
      //}
  
  //}

  /* first try to del host nh */
  hsl_ctc_direct_nh_del(data);
  /* del with nhid */
  switch(nbr->nbr_type) {
    case FWDU_ADJ_REDIRECT:
    {
        ret = ctc_nh_remove_ipuc(nbr->nbr_index);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "ctc_ipuc_remove Failed %s\n",
                     ctc_get_error_desc(ret));
        }
        memset(&misc_nh_param, 0 , sizeof(misc_nh_param));
        misc_nh_param.type = CTC_MISC_NH_TYPE_TO_CPU;
        misc_nh_param.misc_param.cpu_reason.cpu_reason_id = 127/* 127 fwd to cpu */;
        ret = ctc_nh_add_misc(nbr->nbr_index, &misc_nh_param);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "ctc_nh_add_misc Failed %s\n",
                     ctc_get_error_desc(ret));
            goto ERR;
        
        }

    }   
    break;
    case FWDU_ADJ_BLACKHOLE:
        /* default nhid is unrov(drop), do nothing */
        
    break;
    case FWDU_ADJ_GLEAN:
        /* default nhid is unrov(drop), do nothing */
    break;
    case FWDU_ADJ_CACHED:
    {
        ctc_ip_nh_param_t nh_fwd_param;
        nh_fwd_param.upd_type = CTC_NH_UPD_UNRSV_TO_FWD;
        memset(&nh_fwd_param, 0, sizeof(nh_fwd_param));
        memcpy(nh_fwd_param.mac, &nbr->nexthop.dmac[0], HSL_ETHER_ALEN);
        nh_fwd_param.oif.vid = 0; /* Not use */
        nh_fwd_param.oif.oif_type = CTC_NH_OIF_TYPE_ROUTED_PORT; /* ctc_nh_oif_type_t */
        nh_fwd_param.oif.gport = IFINDEX_TO_GPORT(nbr->outif_index);  /* assume l3ifid eq gport */
        
        ret = ctc_nh_update_ipuc(nbr->nbr_index /* ipuc nhid */, &nh_fwd_param);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "ctc_nh_update_ipuc Failed %s,nbr->outif_index=%d, gport=%d\n",
                     ctc_get_error_desc(ret),nbr->outif_index, IFINDEX_TO_GPORT(nbr->outif_index));
            goto ERR;
        
        }
    }
    break;
    default:
        HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_WARN, "not support nbr_type %u\n", nbr->nbr_type);
        goto ERR;
  }
  
  /* binding host id and nhid(provide fwd info) */
  memset(&ipuc_host, 0, sizeof(ipuc_host));
  ipuc_host.vrf_id = nbr->vrfid;
  ipuc_host.ip.ipv4 = nbr->nexthop.addr4;
  ipuc_host.masklen = 32;
  ipuc_host.nh_id = nbr->nbr_index;
  ipuc_host.ip_ver = CTC_IP_VER_4;
  ipuc_host.route_flag = CTC_IPUC_FLAG_NEIGHBOR;
  
  ret = ctc_ipuc_add(&ipuc_host);
  if (ret < 0) {
      HSL_LOG (HSL_LOG_FIB, HSL_LEVEL_ERROR, "ctc_ipuc_add %s\n",
               ctc_get_error_desc(ret));    
      goto ERR;
  }

  HSL_FN_EXIT(0);
ERR:

  HSL_FN_EXIT(-1);
  
}




/*
  Register callbacks.
*/
void
hsl_fib_hw_cb_register (void)
{
  hsl_ctc_fib_callbacks.hw_fib_init = NULL; /*ok */
  hsl_ctc_fib_callbacks.hw_fib_deinit = NULL; /*ok */
  hsl_ctc_fib_callbacks.hw_fib_dump = NULL;//hsl_ctc_fib_dump; /*ok */
  hsl_ctc_fib_callbacks.hw_prefix_add = NULL;//hsl_ctc_prefix_add; /*ok */
  hsl_ctc_fib_callbacks.hw_prefix_delete = NULL;//hsl_ctc_prefix_delete; /*ok */
  hsl_ctc_fib_callbacks.hw_prefix_add_exception = NULL;//hsl_ctc_prefix_exception; /*ok */
  hsl_ctc_fib_callbacks.hw_nh_add = NULL;//hsl_ctc_nh_add; /*ok */
  hsl_ctc_fib_callbacks.hw_nh_delete = NULL;//hsl_ctc_nh_delete; /*ok */
  hsl_ctc_fib_callbacks.hw_nh_hit = NULL;//hsl_ctc_nh_hit; /*ok */
  hsl_ctc_fib_callbacks.hw_add_connected_route = NULL;//hsl_ctc_add_connected_route; /*ok */
  hsl_ctc_fib_callbacks.hw_delete_connected_route = NULL;//hsl_ctc_delete_connected_route; /*ok */
  hsl_ctc_fib_callbacks.hw_get_max_multipath = NULL;//hsl_ctc_get_max_multipath; /*ok */
  hsl_ctc_fib_callbacks.hw_direct_prefix_add = hsl_ctc_direct_prefix_add;
  hsl_ctc_fib_callbacks.hw_direct_prefix_del = hsl_ctc_direct_prefix_del;
  hsl_ctc_fib_callbacks.hw_direct_nh_add = hsl_ctc_direct_nh_add;
  hsl_ctc_fib_callbacks.hw_direct_nh_del = hsl_ctc_direct_nh_del;

  hsl_fibmgr_hw_cb_register (&hsl_ctc_fib_callbacks);
}

