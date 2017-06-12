/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */


#include "config.h"

#include "hsl_os.h"

#include "hsl_types.h"

#ifdef HAVE_QOS

#include "hal_types.h"
#ifdef HAVE_L2
#include "hal_l2.h"
#endif /* HAVE_L2 */

#include "hal_msg.h"

#include "hsl_avl.h"
#include "hsl_error.h"
#include "bcm_incl.h"
#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_bcm.h"
#include "hsl_bcm_if.h"

#include "hal_qos.h"
#include "hsl_bcm_qos.h"

static int hsl_bcm_qos_initialized = HSL_FALSE;

int
hsl_bcm_cosq_detach ()
{
  int ret;

  int max_unit;
  int bcm_unit;

  HSL_FN_ENTER ();

  /* Find the attahed max units */
  bcm_attach_max (&max_unit);

  /* FFS, Check the max unit value in the later */
  for (bcm_unit = 0; bcm_unit <= max_unit; bcm_unit++ )
    {
      ret = bcm_cosq_detach (bcm_unit);
      if (ret != BCM_E_NONE)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error detaching cosq from unit(%d)\n", bcm_unit);
	  HSL_FN_EXIT (-1);
	}
    }

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_init ()
{
  int ret;

  HSL_FN_ENTER ();

  if (hsl_bcm_qos_initialized)
    HSL_FN_EXIT (0);

  /* Initialize cosq */
  ret = bcmx_cosq_init ();
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error clearing all COS schedule/mapping states in hardware\n");
      HSL_FN_EXIT (-1);
    }

  /* Set configure cosq */
  ret = bcmx_cosq_config_set (HSL_BCM_COS_QUEUES);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error initializing %d COS queues\n", HSL_BCM_COS_QUEUES);
      HSL_FN_EXIT (-1);
    }

  if(HSL_BCM_FEATURE_FILTER == hsl_bcm_filter_type_get())
    { 
        /* Initialize metering */
        ret = bcmx_meter_init();
        if (ret != BCM_E_NONE)
          {
	      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error initializing metering in hardware\n");
	      HSL_FN_EXIT (-1);
          }
    }

  /* Initialize DSCP */
  ret = bcmx_ds_init();
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error initializing diffserv in hardware\n");
      HSL_FN_EXIT (-1);
    }

  hsl_bcm_qos_initialized = HSL_TRUE;

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_deinit ()
{
  int ret;
  int max_unit;
  int bcm_unit;

  HSL_FN_ENTER ();

  if (! hsl_bcm_qos_initialized)
    HSL_FN_EXIT (-1);

  /* Find the attahed max units */
  ret = bcm_attach_max (&max_unit);

  /* FFS, Check the max unit value in the later */
  for (bcm_unit = 0; bcm_unit <= max_unit; bcm_unit++ )
    {
      ret = bcm_cosq_detach (bcm_unit);
      if (ret != BCM_E_NONE)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error detaching cosq from unit(%d)\n", bcm_unit);
	  HSL_FN_EXIT (-1);
	}
    }

  hsl_bcm_qos_initialized = HSL_FALSE;

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_enable (char *q0, char *q1, char *q2, char *q3, char *q4, char *q5, char *q6, char *q7)
{
  int max_unit;
  int bcm_unit;
  int ret;
  int weights[8];

  HSL_FN_ENTER ();

  weights[0] = *q0++;
  weights[1] = *q1++;
  weights[2] = *q2++;
  weights[3] = *q3++;
  weights[4] = *q4++;
  weights[5] = *q5++;
  weights[6] = *q6++;
  weights[7] = *q7++;

  /* Set prio to cosq */
  ret = bcmx_cosq_mapping_set (*q0,0);   /* prio=7, cosq=7 */
  if (ret != BCM_E_NONE)
    goto ERR;
  ret = bcmx_cosq_mapping_set (*q1,1);   /* prio=6, cosq=6 */
  if (ret != BCM_E_NONE)
    goto ERR;
  ret = bcmx_cosq_mapping_set (*q2,2);   /* prio=5, cosq=5 */
  if (ret != BCM_E_NONE)
    goto ERR;
  ret = bcmx_cosq_mapping_set (*q3,3);   /* prio=4, cosq=4 */
  if (ret != BCM_E_NONE)
    goto ERR;
  ret = bcmx_cosq_mapping_set (*q4,4);   /* prio=3, cosq=3 */
  if (ret != BCM_E_NONE)
    goto ERR;
  ret = bcmx_cosq_mapping_set (*q5,5);   /* prio=2, cosq=2 */
  if (ret != BCM_E_NONE)
    goto ERR;
  ret = bcmx_cosq_mapping_set (*q6,6);   /* prio=1, cosq=1 */
  if (ret != BCM_E_NONE)
    goto ERR;
  ret = bcmx_cosq_mapping_set (*q7,7);   /* prio=0, cosq=0 */
  if (ret != BCM_E_NONE)
    goto ERR;

  /* Set scheduling of cosq */
  ret = bcmx_cosq_sched_set (BCM_COSQ_WEIGHTED_ROUND_ROBIN, weights, 0);
  if (ret != 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Cannot set scheduling algorithm for COS queues to weighted round robin (%d)\n", ret);
      goto ERR;
    }

  HSL_FN_EXIT (0);

 ERR:
  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "COS Queue mapping setting error (%d)\n", ret);
  bcm_attach_max (&max_unit);
  for (bcm_unit = 0; bcm_unit <= max_unit; bcm_unit++ )
    bcm_cosq_detach (bcm_unit);

  HSL_FN_EXIT (-1);
}

int
hsl_bcm_qos_disable (int num_queue)
{
  struct hsl_if *ifp = NULL, *ifp2 = NULL;
  struct hsl_bcm_if *bcmif;
  int ifindex;

  int max_unit;
  int bcm_unit;
  int ret;

  HSL_FN_ENTER ();

  /* Clear all dpid filed of QoS of bcmif */
  for (ifindex = HSL_L2_IFINDEX_START ; ifindex < HSL_L2_IFINDEX_MAX; ifindex++)
    {
      ifp = NULL;
      ifp2 = NULL;
      bcmif = NULL;

      /* Get the ifp */
      ifp = hsl_ifmgr_lookup_by_index (ifindex);
      if (! ifp)
	continue;

      /* Get logical port */
      if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
	{
	  bcmif = ifp->system_info;
	}
      else if (ifp->type == HSL_IF_TYPE_IP)
	{
	  ifp2 = hsl_ifmgr_get_first_L2_port (ifp);
	  if (ifp2)
	    {
	      bcmif = ifp2->system_info;
	    }
	}
      
      if (! bcmif)
	continue;
      
      hsl_bcm_qos_if_filter_delete_all (bcmif);
      hsl_bcm_qos_if_meter_delete_all (bcmif);

      if (ifp)
	HSL_IFMGR_IF_REF_DEC (ifp);

      if (ifp2)
	HSL_IFMGR_IF_REF_DEC (ifp2);
    }

  /* Find the attahed max units */
  ret = bcm_attach_max (&max_unit);

  /* FFS, Check the max unit value in the later */
  for (bcm_unit = 0; bcm_unit <= max_unit; bcm_unit++ )
    {
      ret = bcm_cosq_detach (bcm_unit);
      if (ret != BCM_E_NONE)
	HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_wrr_queue_limit (int ifindex, int *ratio)
{
  int r[8];

  HSL_FN_ENTER ();

  memcpy (&r[0], ratio, 8);

  /* Get lport using ifindex */

  /* Get each queue size using ratio */
  /*
    bcmx_cosq_port_bandwidth_set ( bcmx_lport_t port,
    bcm_cos_queue_t cosq,
    uint32 kbits_sec_min,
    uint32 kbits_sec_max,
    uint32 flags);
  */
  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_wrr_tail_drop_threshold (int ifindex, int qid, int thres1, int thres2)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_wrr_threshold_dscp_map (int ifindex, int thid, int num, int *dscp)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_wrr_wred_drop_threshold (int ifindex, int qid, int thres1, int thres2)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_wrr_set_bandwidth (int ifindex, int *bw)
{
  int b[8];

  HSL_FN_ENTER ();

  memcpy (&b[0], bw, 8);

  /* Get lport using ifindex */

  /* Get each queue bandwidth using ratio */
  /*
    bcmx_cosq_port_bandwidth_set ( bcmx_lport_t port,
    bcm_cos_queue_t cosq,
    uint32 kbits_sec_min,
    uint32 kbits_sec_max,
    uint32 flags);
  */
  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_wrr_queue_cos_map (int ifindex, int qid, int cos)
{
  int ret;

  HSL_FN_ENTER ();

  /* Set COS Queeu mapping. */
  ret = bcmx_cosq_mapping_set (cos, qid);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "COS Queue mapping setting error (%d)\n", ret);
      HSL_FN_EXIT (ret);
    }

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_wrr_queue_min_reserve (int ifindex, int qid, int packets)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_set_trust_state (int ifindex,int trust_state)
{
  HSL_FN_ENTER ();

  /*
   * Use cos keyword settting if the network is composed of Ethernet LANs.
   * Use dscp or ip-precedence keyword if network is not
   * composed of only Ethernet LANs.
   */

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_set_default_cos (int ifindex, int cos_value)
{
  HSL_FN_ENTER ();

  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_set_dscp_mapping_tbl (int ifindex, int flag, 
			      struct hal_msg_dscp_map_table *map_table, 
			      int map_count)
{
  struct hsl_if *ifp = NULL, *ifp2 = NULL;
  struct hsl_bcm_if *bcmif = NULL;

  bcmx_lplist_t plist;
  bcmx_lport_t lport;

  int ret, i;

  HSL_FN_ENTER ();

  /* Initialize port list. */
  ret = bcmx_lplist_init (&plist, 0, 0);
  if (ret != BCM_E_NONE)
    HSL_FN_EXIT (-1);

  /* Get the ifp */
  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (!ifp)
    HSL_FN_EXIT (-1);

  /* Get logical port */
  if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
    {
      bcmif = ifp->system_info;
      if (! bcmif)
        {
	  HSL_IFMGR_IF_REF_DEC (ifp);
	  HSL_FN_EXIT (-1);
        }

      lport = bcmif->u.l2.lport;
    }
  else if (ifp->type == HSL_IF_TYPE_IP)
    {
      ifp2 = hsl_ifmgr_get_first_L2_port (ifp);
      if (! ifp2)
        {
	  HSL_IFMGR_IF_REF_DEC (ifp);
	  HSL_FN_EXIT (-1);
        }
      bcmif = ifp2->system_info;
      if (! bcmif)
        {
	  HSL_IFMGR_IF_REF_DEC (ifp);
	  HSL_IFMGR_IF_REF_DEC (ifp2);
        }

      lport = bcmif->u.l2.lport;
    }
  else
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_FN_EXIT (-1);
    }

  for (i=0 ; i < map_count; i++)
    {
      ret = bcmx_port_dscp_map_set (lport, map_table[i].in_dscp, 
				    map_table[i].out_dscp, map_table[i].out_pri);
      if (ret != BCM_E_NONE)
	{
	  /* reset all mutation mappings for this port */
	  bcmx_port_dscp_map_set (lport, -1, -1, -1); 
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Failed to set dscp mutation map for interface %s, errcode - (%d)\n", 
		   ifp->name, ret); 
	  HSL_FN_EXIT (-1);
	}
    }
      
  HSL_FN_EXIT (0);
}


int
hsl_qos_get_prefix_len (bcm_ip_t tmpip)
{
  int cnt = 0;

  do
    {
      if (tmpip & 0x01)
        {
	  cnt ++;
	  tmpip = tmpip >> 1;
        }
      else
	break;
    } while (tmpip);
  return cnt;
}

int
hsl_bcm_qos_clr_ds_arg (bcm_ds_clfr_t *clfr,
                        bcm_ds_inprofile_actn_t *inp_actn,
                        bcm_ds_outprofile_actn_t *outp_actn,
                        bcm_ds_nomatch_actn_t *nm_actn,
                        int *cflag,
                        int *iflag,
                        int *oflag,
                        int *nflag)
{

  HSL_FN_ENTER ();

  memset (clfr, 0, sizeof (bcm_ds_clfr_t));
  memset (inp_actn, 0, sizeof (bcm_ds_inprofile_actn_t));
  memset (outp_actn, 0, sizeof (bcm_ds_outprofile_actn_t));
  memset (nm_actn, 0, sizeof (bcm_ds_nomatch_actn_t));

  *cflag = 0;
  *iflag = 0;
  *oflag = 0;
  *nflag = 0;

  HSL_FN_EXIT (0);
}



int  
hsl_bcm_qos_vlan_qualifier_set (bcm_filterid_t filter, unsigned short vlan_id)
{
  return bcmx_filter_qualify_data16 (filter, HSL_QOS_VLAN_OFFSET, vlan_id, 
				     HSL_QOS_VLAN_MASK);
}

int
hsl_bcm_qos_dscp_qualifier_set (bcm_filterid_t filter, unsigned char dscp_val)
{
  return bcmx_filter_qualify_data8 (filter, HSL_QOS_DSCP_OFFSET, 
				    dscp_val << 2, HSL_QOS_DSCP_MASK);
}

int
hsl_bcm_qos_ip_prec_qualifier_set (bcm_filterid_t filter, 
                                   unsigned char ip_prec_val)
{
  return bcmx_filter_qualify_data8 (filter, HSL_QOS_IP_PRECEDENCE_OFFSET,
                                    ip_prec_val << 5, 
                                    HSL_QOS_IP_PRECEDENCE_MASK);
}


int
hsl_bcm_qos_l4_port_qualifier_set (bcm_filterid_t filter, u_char port_type,
				   u_int16_t port_id)
{
  if (port_type == HAL_QOS_LAYER4_PORT_SRC)
    {
      return bcmx_filter_qualify_data16 (filter, HSL_QOS_SRC_L4_PORT_OFFSET,
				       port_id, 0xffff);
    }
  else
    {
      return bcmx_filter_qualify_data16 (filter, HSL_QOS_DST_L4_PORT_OFFSET,
				       port_id, 0xffff);
    }

  return 0;
}

int
hsl_bcm_qos_dst_ip_qualifier_set (bcm_filterid_t filter, 
				  bcm_ip_t dst_prefix, 
				  bcm_ip_t dst_ip_mask)
{
  return bcmx_filter_qualify_data32 (filter, HSL_QOS_DST_IP_OFFSET,
				     dst_prefix, dst_ip_mask);
}


int
hsl_bcm_qos_src_ip_qualifier_set (bcm_filterid_t filter, 
				  bcm_ip_t src_prefix, 
				  bcm_ip_t src_ip_mask)
{
  return bcmx_filter_qualify_data32 (filter, HSL_QOS_SRC_IP_OFFSET,
				     src_prefix, src_ip_mask);
}


int
hsl_bcm_qos_src_mac_qualifier_set (bcm_filterid_t filter, 
				   unsigned char *src_mac,
				   unsigned char *src_mask)
{
  return bcmx_filter_qualify_data (filter, HSL_QOS_SRC_MAC_OFFSET,
				   sizeof (bcm_mac_t),
				   src_mac, src_mask);
}

int
hsl_bcm_qos_dst_mac_qualifier_set (bcm_filterid_t filter, 
				   unsigned char *dst_mac,
				   unsigned char *dst_mask)
{
  return bcmx_filter_qualify_data (filter, HSL_QOS_DST_MAC_OFFSET,
				   sizeof (bcm_mac_t),
				   dst_mac, dst_mask);
}

int
hsl_bcm_qos_cos_qualifier_set (bcm_filterid_t filter, unsigned char cos)
{
  int ret;
  
  ret = bcmx_filter_qualify_format (filter, BCM_FILTER_PKTFMT_INNER_TAG);
  if (ret != BCM_E_NONE)
    return ret;
  
  return bcmx_filter_qualify_data8 (filter, HSL_QOS_COS_INNER_OFFSET,
                                    cos << 5, HSL_QOS_COS_INNER_MASK); 
}

int
hsl_bcm_qos_if_filter_add (struct hsl_bcm_if *bcmif, 
			   struct hsl_bcm_qos_filter *qf)
{
  if (bcmif->u.l2.filter_num == HSL_QOS_IF_FILTER_MAX)
    return -1;

  bcmif->u.l2.filters[bcmif->u.l2.filter_num] = *qf;
  bcmif->u.l2.filter_num++;

  return 0;
}


int
hsl_bcm_qos_if_meter_add (struct hsl_bcm_if *bcmif, int meter)
{
  if (bcmif->u.l2.meter_num == HSL_QOS_IF_METER_MAX)
    return -1;

  bcmif->u.l2.meters[bcmif->u.l2.meter_num] = meter;
  bcmif->u.l2.meter_num++;

  return 0;
}

void
hsl_bcm_qos_filter_delete (struct hsl_bcm_qos_filter *qf)
{
	/*
  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      bcmx_filter_remove (qf->u.filter);
      bcmx_filter_destroy (qf->u.filter);
    }
  else if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      if (qf->u.field.meter > 0)
	{
	  bcmx_field_meter_destroy (qf->u.field.entry);
	  qf->u.field.meter = 0;
	}

      bcmx_field_entry_remove (qf->u.field.entry);
      bcmx_field_entry_destroy (qf->u.field.entry);
      bcmx_field_group_destroy (qf->u.field.group);
    }
    */
}



void  
hsl_bcm_qos_if_filter_delete_all (struct hsl_bcm_if *bcmif)
{
  int i;

  for (i = 0; i < bcmif->u.l2.filter_num; i++)
    {
      hsl_bcm_qos_filter_delete (&bcmif->u.l2.filters[i]);
      memset (&bcmif->u.l2.filters[i], 0, sizeof (struct hsl_bcm_qos_filter));
    }

  bcmif->u.l2.filter_num = 0;
}



void
hsl_bcm_qos_if_meter_delete_all (struct hsl_bcm_if *bcmif)
{
	/*
  int i;

  for (i = 0; i < bcmif->u.l2.meter_num; i++)
    {
      bcmx_meter_delete (bcmif->u.l2.lport, 
			  bcmif->u.l2.meters[i]);
      bcmif->u.l2.meters[i] = 0;
      
    }

  bcmif->u.l2.meter_num = 0;
  */
}     


int
hsl_bcm_qos_set_in_profile_action (struct hsl_bcm_qos_filter *qf,
				   struct hal_set *set)
{
  int ret = 0;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      if (set->type == HAL_QOS_SET_COS)
	{
	  ret = bcmx_filter_action_match (qf->u.filter, 
					  bcmActionInsPrio|bcmActionDoSwitch, 
					  set->val);
	}
      else if (set->type == HAL_QOS_SET_DSCP)
	{
	  ret = bcmx_filter_action_match (qf->u.filter, 
					  bcmActionInsDiffServ|bcmActionDoSwitch,
					  set->val);
	}
      else if (set->type == HAL_QOS_SET_IP_PREC)
	{
	  ret = bcmx_filter_action_match (qf->u.filter,
					  bcmActionInsDiffServ|bcmActionDoSwitch, 
					  set->val << 3);
	}
    }
  else if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      if (set->type == HAL_QOS_SET_COS)
	{
	  ret = bcmx_field_action_add (qf->u.field.entry, 
				       bcmFieldActionPrioPktAndIntNew, 
				       set->val, 0);
	}
      else if (set->type == HAL_QOS_SET_DSCP)
	{
	  ret = bcmx_field_action_add (qf->u.field.entry, bcmFieldActionDscpNew, 
				       set->val, 0);
	}
      else if (set->type == HAL_QOS_SET_IP_PREC)
	{
	  ret = bcmx_field_action_add (qf->u.field.entry, bcmFieldActionDscpNew, 
				       set->val << 3, 0);
	}
    }

  return ret;
}




int
hsl_bcm_qos_set_out_profile_action (struct hsl_bcm_qos_filter *qf,
				    struct hal_police *police,
				    int meter_id)
{
  int ret = 0;

  
  if (! police->avg)
    return 0;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      if (police->exd_act == HAL_QOS_EXD_ACT_DROP)
	{
	  ret = bcmx_filter_action_out_profile (qf->u.filter, 
						bcmActionDoNotSwitch, 
						0, meter_id);
	}
    }
  else if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      if (police->exd_act == HAL_QOS_EXD_ACT_DROP)
	{
	  ret = bcmx_field_action_add (qf->u.field.entry, bcmFieldActionRpDrop,
				       0, 0);
	}
      
    }

  return ret;;
}




int
hsl_bcm_qos_filter_apply (struct hsl_bcm_qos_filter *qf,
			  int action,
			  struct hsl_bcm_if *bcmif,
			  struct hal_set *s,
			  struct hal_police *p,
			  int meter_id)
{
  int ret;
  bcmx_lplist_t plist;

  plist.lp_ports = NULL;
  
  ret = bcmx_lplist_init (&plist, 0, 0);
  if (ret != BCM_E_NONE)
    return ret;

  ret = bcmx_lplist_add (&plist, bcmif->u.l2.lport);
  if (ret != BCM_E_NONE)
    {
      goto err_ret;
    }
  

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {/*
      ret = bcmx_filter_qualify_ingress (qf->u.filter, plist);
      if (ret != BCM_E_NONE)
	{
	  goto err_ret;
	}
      
      bcmx_lplist_free (&plist);
      
      if (action == HAL_QOS_FILTER_DENY)
	{
	  ret = bcmx_filter_action_match (qf->u.filter, bcmActionDoNotSwitch, 0);
	  if (ret < 0)
	    goto err_ret;
	}
      else
	{
	  
	  ret = hsl_bcm_qos_set_in_profile_action (qf, s);
	  if (ret < 0)
	    {
	      goto err_ret;
	    }
	  
	  
	  ret = hsl_bcm_qos_set_out_profile_action (qf, p, meter_id);
	  if (ret < 0)
	    goto err_ret;
	}
      
      ret = bcmx_filter_install (qf->u.filter);
      
      return ret;
      */
    }
  else if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      ret = bcmx_field_qualify_InPorts (qf->u.field.entry, plist);
      if (ret != BCM_E_NONE)
	{
	  goto err_ret;
	}
      
      bcmx_lplist_free (&plist);
      
      if (action == HAL_QOS_FILTER_DENY)
	{
	  ret = bcmx_field_action_add (qf->u.field.entry, bcmFieldActionDrop,
				       0, 0);
	  if (ret < 0)
	    goto err_ret;
	}
      else
	{
	  if (p->avg > 0 && qf->u.field.meter == 0)
	    {/*
	      ret = bcmx_field_meter_create (qf->u.field.entry);
	      if (ret < 0)
		goto err_ret;

	      ret = bcmx_field_meter_set (qf->u.field.entry, 
					 3, 
					 p->avg, p->burst);
	      if (ret < 0)
		{
		  bcmx_field_meter_destroy (qf->u.field.entry);
		  goto err_ret;
		}
	      qf->u.field.meter = 1;
	      */
	    }

	  /* Set in-profile */
	  ret = hsl_bcm_qos_set_in_profile_action (qf, s);
	  if (ret < 0)
	    {
	      goto err_ret;
	    }
	  
	  /* Set out-profile */
	  ret = hsl_bcm_qos_set_out_profile_action (qf, p, meter_id);
	  if (ret < 0)
	    goto err_ret;
	}
      
      ret = bcmx_field_entry_install (qf->u.field.entry);
      
      return ret;
    }

 err_ret:
  if (plist.lp_ports)
    bcmx_lplist_free (&plist);
  
  return -1;
}
			  
int 
hsl_bcm_qos_dscp_filter_create (struct hsl_bcm_qos_filter *qf,
				unsigned long filter_flags,
				unsigned char dscp_val,
				unsigned short vlan_id)
{
  int ret;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      bcm_filterid_t filter;
      int filter_created = 0;
      
      ret = bcmx_filter_create (&filter);
      if (ret != BCM_E_NONE)
	return ret;
      
      filter_created = 1;
      
      if (filter_flags & HSL_QOS_FILTER_DSCP)
	{
	  ret = hsl_bcm_qos_dscp_qualifier_set (filter, dscp_val);
	  if (ret < 0)
	    goto err_ret;
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = hsl_bcm_qos_vlan_qualifier_set (filter, vlan_id);
	  if (ret < 0)
	    goto err_ret;
	}
      
      qf->u.filter = filter;

      return 0;
      
    err_ret:
      if (filter_created)
	{
	  bcmx_filter_remove (filter);
	  bcmx_filter_destroy (filter);
	}
      
      return -1;
    }

  if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      bcm_field_qset_t qset;
      bcm_field_group_t group;
      bcm_field_entry_t entry;
      int entry_created = 0;
      int group_created = 0;
      
      BCM_FIELD_QSET_INIT (qset);

      ret = bcmx_field_group_create (qset, BCM_FIELD_GROUP_PRIO_ANY,
				     &group);
      if (ret != BCM_E_NONE)
	return ret;

      group_created = 1;

      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyInPorts);

      if (filter_flags & HSL_QOS_FILTER_DSCP)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyDSCP);
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyOuterVlan);

      ret = bcmx_field_group_set (group, qset);
      if (ret < 0)
	goto err_ret_field;
      
      ret = bcmx_field_entry_create (group, &entry);
      if (ret < 0)
	goto err_ret_field;

      entry_created = 1;

      if (filter_flags & HSL_QOS_FILTER_DSCP)
	{
	  ret = bcmx_field_qualify_DSCP (entry, dscp_val << 2, HSL_QOS_DSCP_MASK);
	  if (ret < 0)
	    goto err_ret_field;
	}
            
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = bcmx_field_qualify_OuterVlan (entry, vlan_id, HSL_QOS_VLAN_MASK);
	  if (ret < 0)
	    goto err_ret_field;
	}

      qf->u.field.entry = entry;
      qf->u.field.group = group;
      return 0;
      
    err_ret_field:
      if (entry_created)
	{
	  bcmx_field_entry_remove (entry);
	  bcmx_field_entry_destroy (entry);
	}
      
      if (group_created)
	{
	  bcmx_field_group_destroy (group);
	}
      
      return -1;
    }

  return -1;
}

int 
hsl_bcm_qos_ip_prec_filter_create (struct hsl_bcm_qos_filter *qf,
				unsigned long filter_flags,
				unsigned char ip_prec_val,
				unsigned short vlan_id)
{
int ret;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      bcm_filterid_t filter;
      int filter_created = 0;
      
      ret = bcmx_filter_create (&filter);
      if (ret != BCM_E_NONE)
	return ret;
      
      filter_created = 1;
      
      if (filter_flags & HSL_QOS_FILTER_IP_PRECEDENCE)
	{
	  ret = hsl_bcm_qos_ip_prec_qualifier_set (filter, ip_prec_val);
	  if (ret < 0)
	    goto err_ret;
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = hsl_bcm_qos_vlan_qualifier_set (filter, vlan_id);
	  if (ret < 0)
	    goto err_ret;
	}
      
      qf->u.filter = filter;

      return 0;
      
    err_ret:
      if (filter_created)
	{
	  bcmx_filter_remove (filter);
	  bcmx_filter_destroy (filter);
	}
      
      return -1;
    }

  if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      bcm_field_qset_t qset;
      bcm_field_group_t group;
      bcm_field_entry_t entry;
      int entry_created = 0;
      int group_created = 0;
      
      BCM_FIELD_QSET_INIT (qset);

      ret = bcmx_field_group_create (qset, BCM_FIELD_GROUP_PRIO_ANY,
				     &group);
      if (ret != BCM_E_NONE)
	return ret;

      group_created = 1;

      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyInPorts);

      if (filter_flags & HSL_QOS_FILTER_IP_PRECEDENCE)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyDSCP);
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyOuterVlan);

      ret = bcmx_field_group_set (group, qset);
      if (ret < 0)
	goto err_ret_field;
      
      ret = bcmx_field_entry_create (group, &entry);
      if (ret < 0)
	goto err_ret_field;

      entry_created = 1;

      if (filter_flags & HSL_QOS_FILTER_IP_PRECEDENCE)
	{
	  ret = bcmx_field_qualify_DSCP (entry, ip_prec_val << 5, HSL_QOS_IP_PRECEDENCE_MASK);
	  if (ret < 0)
	    goto err_ret_field;
	}
            
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = bcmx_field_qualify_OuterVlan (entry, vlan_id, HSL_QOS_VLAN_MASK);
	  if (ret < 0)
	    goto err_ret_field;
	}

      qf->u.field.entry = entry;
      qf->u.field.group = group;
      return 0;
      
    err_ret_field:
      if (entry_created)
	{
	  bcmx_field_entry_remove (entry);
	  bcmx_field_entry_destroy (entry);
	}
      
      if (group_created)
	{
	  bcmx_field_group_destroy (group);
	}
      
      return -1;
    }

  return -1;
}


int 
hsl_bcm_qos_l4_port_filter_create (struct hsl_bcm_qos_filter *qf,
				   unsigned long filter_flags,
				   struct hal_cmap_l4_port *cmap_l4_port,
				   unsigned short vlan_id)
{
  int ret;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      bcm_filterid_t filter;
      int filter_created = 0;
      
      ret = bcmx_filter_create (&filter);
      if (ret != BCM_E_NONE)
	return ret;
      
      filter_created = 1;
      
      if (filter_flags & HSL_QOS_FILTER_L4_PORT)
	{
	  ret = hsl_bcm_qos_l4_port_qualifier_set (filter, cmap_l4_port->port_type,
						   cmap_l4_port->port_id);
	  if (ret < 0)
	    goto err_ret;
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = hsl_bcm_qos_vlan_qualifier_set (filter, vlan_id);
	  if (ret < 0)
	    goto err_ret;
	}
      
      qf->u.filter = filter;

      return 0;
      
    err_ret:
      if (filter_created)
	{
	  bcmx_filter_remove (filter);
	  bcmx_filter_destroy (filter);
	}
      
      return -1;
    }

  if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      bcm_field_qset_t qset;
      bcm_field_group_t group;
      bcm_field_entry_t entry;
      int entry_created = 0;
      int group_created = 0;
      
      BCM_FIELD_QSET_INIT (qset);

      ret = bcmx_field_group_create (qset, BCM_FIELD_GROUP_PRIO_ANY,
				     &group);
      if (ret != BCM_E_NONE)
	return ret;

      group_created = 1;

      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyInPorts);

      if (filter_flags & HSL_QOS_FILTER_L4_PORT)
	{
	  if (cmap_l4_port->port_type == HAL_QOS_LAYER4_PORT_SRC) 
	    {
	      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyL4SrcPort);
	    }
	  else
	    {
	      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyL4DstPort);
	    }
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyOuterVlan);

      ret = bcmx_field_group_set (group, qset);
      if (ret < 0)
	goto err_ret_field;
      
      ret = bcmx_field_entry_create (group, &entry);
      if (ret < 0)
	goto err_ret_field;

      entry_created = 1;

      if (filter_flags & HSL_QOS_FILTER_L4_PORT)
	{
	  if (cmap_l4_port->port_type == HAL_QOS_LAYER4_PORT_SRC)
	    ret = bcmx_field_qualify_L4SrcPort (entry, cmap_l4_port->port_id,
						0xffff);
	  else
	    ret = bcmx_field_qualify_L4DstPort (entry, cmap_l4_port->port_id,
						0xffff);
	  if (ret < 0)
	    goto err_ret_field;
	}
            
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = bcmx_field_qualify_OuterVlan (entry, vlan_id, HSL_QOS_VLAN_MASK);
	  if (ret < 0)
	    goto err_ret_field;
	}

      qf->u.field.entry = entry;
      qf->u.field.group = group;

      return 0;
      
    err_ret_field:
      if (entry_created)
	{
	  bcmx_field_entry_remove (entry);
	  bcmx_field_entry_destroy (entry);
	}
      
      if (group_created)
	{
	  bcmx_field_group_destroy (group);
	}
      
      return -1;
    }

  return -1;
}




int
hsl_bcm_qos_set_dscp_filter (struct hal_cmap_dscp *cmap_dscp,
			     struct hal_vlan_filter *vlan, 
			     struct hsl_bcm_if *bcmif,
			     struct hal_set *s,
			     struct hal_police *p, 
			     int meter_id)
{
  int ret, i;
  unsigned long filter_flags = 0;
  struct hsl_bcm_qos_filter qf;

  filter_flags = HSL_QOS_FILTER_DSCP;

  if (vlan)
    {
      filter_flags |= HSL_QOS_FILTER_VLAN;
      for (i=0; ((i < vlan->num) && (i < HAL_MAX_VLAN_FILTER)) ; i++)
	{
	  memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
	  qf.type = hsl_bcm_filter_type_get();

	  /* create a dscp filter */
	  ret = hsl_bcm_qos_dscp_filter_create (&qf,
						filter_flags,
						cmap_dscp->dscp[0],
						vlan->vlan[i]);
	  if (ret < 0)
	    return ret;

	  ret = hsl_bcm_qos_filter_apply (&qf, HAL_QOS_FILTER_PERMIT, 
					  bcmif, s, p, meter_id);
	  if (ret < 0)
	    {
	      hsl_bcm_qos_filter_delete (&qf);
	      hsl_bcm_qos_if_filter_delete_all (bcmif);
	      return ret;
	    }

	  hsl_bcm_qos_if_filter_add (bcmif, &qf);
	} 
    } 
  else
    {
      memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
      qf.type = hsl_bcm_filter_type_get();
      
      /* create a dscp filter */
      ret = hsl_bcm_qos_dscp_filter_create (&qf,
					    filter_flags,
					    cmap_dscp->dscp[0],
					    0);
      if (ret < 0)
	return ret;
      
      ret = hsl_bcm_qos_filter_apply (&qf, HAL_QOS_FILTER_PERMIT,
				      bcmif, s, p, meter_id);
      if (ret < 0)
	{
	  hsl_bcm_qos_filter_delete (&qf);
	  hsl_bcm_qos_if_filter_delete_all (bcmif);
	  return ret;
	}
      
      hsl_bcm_qos_if_filter_add (bcmif, &qf);
    }

  return 0;
}

int
hsl_bcm_qos_set_ip_prec_filter (struct hal_cmap_ip_prec *cmap_ip_prec,
                                struct hal_vlan_filter *vlan, 
                                struct hsl_bcm_if *bcmif,
			          struct hal_set *s,
			          struct hal_police *p, 
			          int meter_id)
{
  int ret, i;
  unsigned long filter_flags = 0;
  struct hsl_bcm_qos_filter qf;

  filter_flags = HSL_QOS_FILTER_IP_PRECEDENCE;

  if (vlan)
    {
      filter_flags |= HSL_QOS_FILTER_VLAN;
      for (i=0; ((i < vlan->num) && (i < HAL_MAX_VLAN_FILTER)) ; i++)
	{
	  memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
	  qf.type = hsl_bcm_filter_type_get();
         
         /* create a ip-precedence filter */
	  ret = hsl_bcm_qos_ip_prec_filter_create (&qf,
				         	   filter_flags,
						   cmap_ip_prec->prec[0],
						   vlan->vlan[i]);
	  if (ret < 0)
	    return ret;

	  ret = hsl_bcm_qos_filter_apply (&qf, HAL_QOS_FILTER_PERMIT, 
					  bcmif, s, p, meter_id);
	  if (ret < 0)
	    {
	      hsl_bcm_qos_filter_delete (&qf);
	      hsl_bcm_qos_if_filter_delete_all (bcmif);
	      return ret;
	    }

	  hsl_bcm_qos_if_filter_add (bcmif, &qf);
	} 
    } 
  else
    {
      memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
      qf.type = hsl_bcm_filter_type_get();
      
      /* create a ip-precedence filter */
      ret = hsl_bcm_qos_ip_prec_filter_create (&qf,
					         filter_flags,
					         cmap_ip_prec->prec[0],
					         0);
      if (ret < 0)
	return ret;
      
      ret = hsl_bcm_qos_filter_apply (&qf, HAL_QOS_FILTER_PERMIT,
				      bcmif, s, p, meter_id);
      if (ret < 0)
	{
	  hsl_bcm_qos_filter_delete (&qf);
	  hsl_bcm_qos_if_filter_delete_all (bcmif);
	  return ret;
	}
      
      hsl_bcm_qos_if_filter_add (bcmif, &qf);
    }

  return 0;
}
int
hsl_bcm_qos_set_l4_port_filter (struct hal_cmap_l4_port *cmap_l4_port,
				struct hal_vlan_filter *vlan, 
				struct hsl_bcm_if *bcmif,
				struct hal_set *s,
				struct hal_police *p, 
				int meter_id)
{
  int ret, i;
  unsigned long filter_flags = 0;
  struct hsl_bcm_qos_filter qf;

  filter_flags = HSL_QOS_FILTER_L4_PORT;

  if (vlan)
    {
      filter_flags |= HSL_QOS_FILTER_VLAN;
      for (i=0; ((i < vlan->num) && (i < HAL_MAX_VLAN_FILTER)) ; i++)
	{
	  memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
	  qf.type = hsl_bcm_filter_type_get();

	  /* create a dscp filter */
	  ret = hsl_bcm_qos_l4_port_filter_create (&qf,
						   filter_flags,
						   cmap_l4_port,
						   vlan->vlan[i]);
	  if (ret < 0)
	    return ret;

	  ret = hsl_bcm_qos_filter_apply (&qf, HAL_QOS_FILTER_PERMIT, 
					  bcmif, s, p, meter_id);
	  if (ret < 0)
	    {
	      hsl_bcm_qos_filter_delete (&qf);
	      hsl_bcm_qos_if_filter_delete_all (bcmif);
	      return ret;
	    }

	  hsl_bcm_qos_if_filter_add (bcmif, &qf);
	} 
    } 
  else
    {
      memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
      qf.type = hsl_bcm_filter_type_get();
      
      /* create a dscp filter */
      ret = hsl_bcm_qos_l4_port_filter_create (&qf,
					      filter_flags,
					      cmap_l4_port,
					       0);
      if (ret < 0)
	return ret;
      
      ret = hsl_bcm_qos_filter_apply (&qf, HAL_QOS_FILTER_PERMIT,
				      bcmif, s, p, meter_id);
      if (ret < 0)
	{
	  hsl_bcm_qos_filter_delete (&qf);
	  hsl_bcm_qos_if_filter_delete_all (bcmif);
	  return ret;
	}
      hsl_bcm_qos_if_filter_add (bcmif, &qf);
    }

  return 0;
}



int 
hsl_bcm_qos_ip_filter_create (struct hsl_bcm_qos_filter *qf,
			      unsigned long filter_flags,
			      bcm_ip_t src_prefix,
			      bcm_ip_t src_ip_mask,
			      bcm_ip_t dst_prefix,
			      bcm_ip_t dst_ip_mask,
			      unsigned short vlan_id)
{
  int ret;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      bcm_filterid_t filter;
      int filter_created = 0;
      
      ret = bcmx_filter_create (&filter);
      if (ret != BCM_E_NONE)
      {
	return ret;
      }
  
      
      filter_created = 1;
      
      if (filter_flags & HSL_QOS_FILTER_DST_IP)
	{
	  ret = hsl_bcm_qos_dst_ip_qualifier_set (filter, dst_prefix, 
						  dst_ip_mask);
	  if (ret < 0)
	    goto err_ret_filter;
	}
      if (filter_flags & HSL_QOS_FILTER_SRC_IP)
	{
	  ret = hsl_bcm_qos_src_ip_qualifier_set (filter,
						  src_prefix, src_ip_mask);
	  if (ret < 0)
	    goto err_ret_filter;
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = hsl_bcm_qos_vlan_qualifier_set (filter, vlan_id);
	  if (ret < 0)
	    goto err_ret_filter;
	}

      qf->u.filter = filter;

      return 0;
      
    err_ret_filter:
      if (filter_created)
	{
	  bcmx_filter_remove (filter);
	  bcmx_filter_destroy (filter);
	}
      
      return -1;
    }
  
  if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      bcm_field_qset_t qset;
      bcm_field_group_t group;
      bcm_field_entry_t entry;
      int entry_created = 0;
      int group_created = 0;
      
      BCM_FIELD_QSET_INIT (qset);

      ret = bcmx_field_group_create (qset, BCM_FIELD_GROUP_PRIO_ANY,
				     &group);
      if (ret != BCM_E_NONE)
	return ret;

      group_created = 1;

      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyInPorts);

      if (filter_flags & HSL_QOS_FILTER_DST_IP)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyDstIp);

      if (filter_flags & HSL_QOS_FILTER_SRC_IP)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifySrcIp);

      if (filter_flags & HSL_QOS_FILTER_VLAN)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyOuterVlan);

      ret = bcmx_field_group_set (group, qset);
      if (ret < 0)
	goto err_ret_field;

      ret = bcmx_field_entry_create (group, &entry);
      if (ret < 0)
	goto err_ret_field;

      entry_created = 1;

      if (filter_flags & HSL_QOS_FILTER_DST_IP)
	{
	  ret = bcmx_field_qualify_DstIp (entry, dst_prefix,  
					  dst_ip_mask);
	  if (ret < 0)
	    goto err_ret_field;
	}
      
      if (filter_flags & HSL_QOS_FILTER_SRC_IP)
	{
	  ret = bcmx_field_qualify_SrcIp (entry, 
					  src_prefix, src_ip_mask);
	  if (ret < 0)
	    goto err_ret_field;
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = bcmx_field_qualify_OuterVlan (entry, vlan_id, HSL_QOS_VLAN_MASK);
	  if (ret < 0)
	    goto err_ret_field;
	}

      qf->u.field.entry = entry;
      qf->u.field.group = group;

      return 0;
      
    err_ret_field:
      if (entry_created)
	{
	  bcmx_field_entry_remove (entry);
	  bcmx_field_entry_destroy (entry);
	}
      
      if (group_created)
	{
	  bcmx_field_group_destroy (group);
	}
      
      return -1;
    }

  return -1;
}



int
hsl_bcm_qos_mac_filter_create (struct hsl_bcm_qos_filter *qf,
			       unsigned long filter_flags,
			       unsigned char *src_mac,
			       unsigned char *src_mask,
			       unsigned char *dst_mac,
			       unsigned char *dst_mask,
			       unsigned short vlan_id)
{
  int ret;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      int filter_created = 0;
      bcm_filterid_t filter;
      
      ret = bcmx_filter_create (&filter);
      if (ret != BCM_E_NONE)
	return ret;
      
      filter_created = 1;
      
      if (filter_flags & HSL_QOS_FILTER_DST_MAC)
	{
	  ret = hsl_bcm_qos_dst_mac_qualifier_set (filter, 
						   dst_mac, dst_mask);
	  if (ret < 0)
	    goto err_ret;
	}
      
      if (filter_flags & HSL_QOS_FILTER_SRC_MAC)
	{
	  ret = hsl_bcm_qos_src_mac_qualifier_set (filter, 
						   src_mac, src_mask);
	  if (ret < 0)
	    goto err_ret;
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = hsl_bcm_qos_vlan_qualifier_set (filter, vlan_id);
	  if (ret < 0)
	    goto err_ret;
	}


      qf->u.filter = filter;
      return 0;
      
    err_ret:
      if (filter_created)
	{
	  bcmx_filter_remove (filter);
	  bcmx_filter_destroy (filter);
	}
      
      return -1;
    }

  if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      bcm_field_qset_t qset;
      bcm_field_group_t group;
      bcm_field_entry_t entry;
      int entry_created = 0;
      int group_created = 0;
      
      BCM_FIELD_QSET_INIT (qset);

      ret = bcmx_field_group_create (qset, BCM_FIELD_GROUP_PRIO_ANY,
				     &group);
      if (ret != BCM_E_NONE)
	return ret;

      group_created = 1;

      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyInPorts);

      if (filter_flags & HSL_QOS_FILTER_DST_MAC)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyDstMac);

      if (filter_flags & HSL_QOS_FILTER_SRC_MAC)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifySrcMac);

      if (filter_flags & HSL_QOS_FILTER_VLAN)
	BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyOuterVlan);

      ret = bcmx_field_group_set (group, qset);
      if (ret < 0)
	goto err_ret_field;

      ret = bcmx_field_entry_create (group, &entry);
      if (ret < 0)
	goto err_ret_field;

      entry_created = 1;

      if (filter_flags & HSL_QOS_FILTER_DST_MAC)
	{
	  ret = bcmx_field_qualify_DstMac (entry, dst_mac,  
					  dst_mask);
	  if (ret < 0)
	    goto err_ret_field;
	}
      
      if (filter_flags & HSL_QOS_FILTER_SRC_MAC)
	{
	  ret = bcmx_field_qualify_SrcMac (entry, 
					   src_mac, src_mask);
	  if (ret < 0)
	    goto err_ret_field;
	}
      
      if (filter_flags & HSL_QOS_FILTER_VLAN)
	{
	  ret = bcmx_field_qualify_OuterVlan (entry, vlan_id, HSL_QOS_VLAN_MASK);
	  if (ret < 0)
	    goto err_ret_field;
	}

      qf->u.field.entry = entry;
      qf->u.field.group = group;
      return 0;
      
    err_ret_field:
      if (entry_created)
	{
	  bcmx_field_entry_remove (entry);
	  bcmx_field_entry_destroy (entry);
	}
      
      if (group_created)
	{
	  bcmx_field_group_destroy (group);
	}
      
      return -1;
    }

  return -1;
}



int
hsl_bcm_qos_set_mac_acl_filter (struct hal_acl_filter *acl,
				struct hal_vlan_filter *vlan, 
				struct hsl_bcm_if *bcmif,
				struct hal_set *s,
				struct hal_police *p, 
				int meter_id)
{
  int i, j;
  unsigned long filter_flags = 0;
  struct hsl_bcm_qos_filter qf;
  int ret;
  unsigned char mac_mask_all[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  for (i = 0; i < HAL_MAX_ACL_FILTER && i < acl->ace_num; i++)
    {
      filter_flags = 0;
  
      /* Destination MAC */
      if (! HSL_MAC_IS_ZERO (acl->ace[i].mfilter.m.mac))
	{
	  filter_flags |= HSL_QOS_FILTER_DST_MAC;
	}
  
      if (! HSL_MAC_IS_ZERO (acl->ace[i].mfilter.a.mac))
	{
	  filter_flags |= HSL_QOS_FILTER_SRC_MAC;
	}
  
      if (! filter_flags)
	continue;
  
      if (vlan)
	{
	  filter_flags |= HSL_QOS_FILTER_VLAN;
	  for (j=0; ((j < vlan->num) && (j < HAL_MAX_VLAN_FILTER)) ; j++)
	    {
	      memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
	      qf.type = hsl_bcm_filter_type_get();
	      
	      /* create a mac filter */
	      ret = hsl_bcm_qos_mac_filter_create (&qf,
						   filter_flags,
						   &acl->ace[i].mfilter.a.mac[0],
						   mac_mask_all,
						   &acl->ace[i].mfilter.m.mac[0],
						   mac_mask_all, 
						   vlan->vlan[j]);
	      if (ret < 0)
		return ret;
	      
	      ret = hsl_bcm_qos_filter_apply (&qf,  
					      acl->ace[i].mfilter.deny_permit,
					      bcmif, s, p, meter_id);
	      if (ret < 0)
		{
		  hsl_bcm_qos_filter_delete (&qf);
		  hsl_bcm_qos_if_filter_delete_all (bcmif);
		  return ret;
		}
	      
	      hsl_bcm_qos_if_filter_add (bcmif, &qf);
	    } 
	}
      else
	{
	  memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
	  qf.type = hsl_bcm_filter_type_get();
      	  ret = hsl_bcm_qos_mac_filter_create (&qf,
					       filter_flags,
					       &acl->ace[i].mfilter.a.mac[0],
					       mac_mask_all,
					       &acl->ace[i].mfilter.m.mac[0],
					       mac_mask_all,
					       0);
	  if (ret < 0)
	    return ret;
	  
	  ret = hsl_bcm_qos_filter_apply (&qf,  acl->ace[i].mfilter.deny_permit, 
					  bcmif, s, p, meter_id);
	  if (ret < 0)
	    {
	      hsl_bcm_qos_filter_delete (&qf);
	      hsl_bcm_qos_if_filter_delete_all (bcmif);
	      return ret;
	    }
	  
	  hsl_bcm_qos_if_filter_add (bcmif, &qf);
	}
    }

  return 0;
}
  



  
int
hsl_bcm_qos_set_ip_acl_filter (struct hal_acl_filter *acl,
			       struct hal_vlan_filter *vlan, 
			       struct hsl_bcm_if *bcmif,
			       struct hal_set *s,
			       struct hal_police *p, 
			       int meter_id)
{
  int i, j, ret;
  unsigned long filter_flags = 0;
  struct hsl_bcm_qos_filter qf;
  unsigned long src_prefix, src_ip_mask, dst_prefix, dst_ip_mask;

  for (i = 0; i < HAL_MAX_ACL_FILTER && i < acl->ace_num; i++)
    {
      /* Destination IPv4 addresss and prefix */
      dst_prefix =
	((acl->ace[i].ifilter.mask.ip[0] << 24) |
	 (acl->ace[i].ifilter.mask.ip[1] << 16) |
	 (acl->ace[i].ifilter.mask.ip[2] << 8)  |
	 (acl->ace[i].ifilter.mask.ip[3]));

      dst_ip_mask =
	((acl->ace[i].ifilter.mask_mask.ip[0] << 24) |
	 (acl->ace[i].ifilter.mask_mask.ip[1] << 16) |
	 (acl->ace[i].ifilter.mask_mask.ip[2] << 8)  |
	 (acl->ace[i].ifilter.mask_mask.ip[3]));

   if (dst_prefix != 0 || dst_ip_mask != 0)
	{
	  filter_flags |= HSL_QOS_FILTER_DST_IP;
	}
	      
      dst_ip_mask = ~dst_ip_mask;
      dst_prefix &= dst_ip_mask;

      src_prefix = 
	((acl->ace[i].ifilter.addr.ip[0] << 24) |
	 (acl->ace[i].ifilter.addr.ip[1] << 16) |
	 (acl->ace[i].ifilter.addr.ip[2] << 8)  |
	 (acl->ace[i].ifilter.addr.ip[3]));
	      
      src_ip_mask = 
	((acl->ace[i].ifilter.addr_mask.ip[0] << 24) |
	 (acl->ace[i].ifilter.addr_mask.ip[1] << 16) |
	 (acl->ace[i].ifilter.addr_mask.ip[2] << 8)  |
	 (acl->ace[i].ifilter.addr_mask.ip[3]));

      if (src_prefix != 0 || src_ip_mask != 0)
	    {
	      filter_flags |= HSL_QOS_FILTER_SRC_IP;
	    }

      if (! filter_flags)
	continue;

      src_ip_mask = ~src_ip_mask;
      src_prefix &= src_ip_mask;
	      
      if (vlan)
	{
	  memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
	  qf.type = hsl_bcm_filter_type_get();
      	  filter_flags |= HSL_QOS_FILTER_VLAN;
	  for (j=0; ((j < vlan->num) && (j < HAL_MAX_VLAN_FILTER)) ; j++)
	    {
	      ret = hsl_bcm_qos_ip_filter_create (&qf,
						  filter_flags,
						  src_prefix,
						  src_ip_mask,
						  dst_prefix,
						  dst_ip_mask,
						  vlan->vlan[j]);

	      if (ret < 0)
		return ret;
	      
	      ret = hsl_bcm_qos_filter_apply (&qf, 
					      acl->ace[i].ifilter.deny_permit,
					      bcmif, s, p, meter_id);
	      if (ret < 0)
		{
		  hsl_bcm_qos_filter_delete (&qf);
		  hsl_bcm_qos_if_filter_delete_all (bcmif);
		  return ret;
		}
	      
	      hsl_bcm_qos_if_filter_add (bcmif, &qf);
	    } 
	} 
      else
	{
	  memset (&qf, 0, sizeof (struct hsl_bcm_qos_filter));
	  qf.type = hsl_bcm_filter_type_get();
	  ret = hsl_bcm_qos_ip_filter_create (&qf,
					      filter_flags,
					      src_prefix,
					      src_ip_mask,
					      dst_prefix,
					      dst_ip_mask,
					      0);
	  if (ret < 0)
	    return ret;
	  
	  ret = hsl_bcm_qos_filter_apply (&qf, acl->ace[i].ifilter.deny_permit,
					  bcmif, s, p, meter_id);
	  if (ret < 0)
	    {
	      hsl_bcm_qos_filter_delete (&qf);
	      hsl_bcm_qos_if_filter_delete_all (bcmif);
	      return ret;
	    }
	  
	  hsl_bcm_qos_if_filter_add (bcmif, &qf);
	}
    }

  return 0;
}




int
hsl_bcm_qos_set_acl_filter (struct hal_acl_filter *acl,
			    int acl_type,
			    struct hal_vlan_filter *vlan, 
			    struct hsl_bcm_if *bcmif,
			    struct hal_set *s,
			    struct hal_police *p, 
			    int meter_id)
{
  int ret = 0;

  if (acl_type == HAL_QOS_ACL_TYPE_MAC)
    ret = hsl_bcm_qos_set_mac_acl_filter (acl, vlan,
					  bcmif, s, p, meter_id);
  else if (acl_type == HAL_QOS_ACL_TYPE_IP)
    ret = hsl_bcm_qos_set_ip_acl_filter (acl, vlan,
					 bcmif, s, p, meter_id);
  return ret;
}  




int hsl_bcm_qos_set_ingress_class_map(struct hal_msg_qos_set_class_map *msg)
{
  struct hsl_if *ifp = NULL, *ifp2 = NULL;
  struct hsl_bcm_if *bcmif = NULL;
  struct hal_class_map *hcmap = &msg->cmap;
  int ifindex = msg->ifindex;
  int ret;
  int meter_id = 0;

  HSL_FN_ENTER ();

 /* Get the ifp */
  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (!ifp)
    goto err_ret;
  
  if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
    {
      bcmif = ifp->system_info;
      if (! bcmif)
        {
	  goto err_ret;
        }
    }
  else if (ifp->type == HSL_IF_TYPE_IP)
    {
      ifp2 = hsl_ifmgr_get_first_L2_port (ifp);
      if (! ifp2)
        {
	  goto err_ret;
        }

      bcmif = ifp2->system_info;
      if (! bcmif)
        {
	  goto err_ret;
        }
    }

  if (! bcmif)
    goto err_ret;

  meter_id = 0;
  if (hcmap->p.avg > 0)
    {

      if (HSL_BCM_FEATURE_FILTER == hsl_bcm_filter_type_get())
	{
	  /* create meter */
	  ret = bcmx_meter_create (bcmif->u.l2.lport, &meter_id);
	  if (ret < 0)
	    goto err_ret;

	  ret = hsl_bcm_qos_if_meter_add (bcmif, meter_id);
	  if (ret < 0)
	    {
	      //bcmx_meter_delete (bcmif->u.l2.lport, meter_id);
	      meter_id = 0;
	      goto err_ret;
	    }
	  
	  ret = bcmx_meter_set (bcmif->u.l2.lport, meter_id, hcmap->p.avg,
				hcmap->p.burst);
	  if (ret < 0)
	    goto err_ret;
	}
    }

  /* In ACL classifier case */
  if (hcmap->clfr_type_ind & HAL_QOS_CLFR_TYPE_ACL)
    {
      ret = hsl_bcm_qos_set_acl_filter (&hcmap->acl, hcmap->acl.mac_ip_ind,
					hcmap->clfr_type_ind &
					HAL_QOS_CLFR_TYPE_VLAN 
					? &hcmap->v : NULL, bcmif, 
					&hcmap->s, 
					&hcmap->p, meter_id);
      if (ret < 0)
	goto err_ret;
    }
  else if (hcmap->clfr_type_ind & HAL_QOS_CLFR_TYPE_DSCP)
    {
      if (hcmap->d.num == 0x00)
	goto err_ret;

      ret = hsl_bcm_qos_set_dscp_filter (&hcmap->d, 
					 hcmap->clfr_type_ind &
					 HAL_QOS_CLFR_TYPE_VLAN 
					 ? &hcmap->v : NULL, 
					 bcmif, &hcmap->s, &hcmap->p, 
					 meter_id);
      if (ret < 0)
	goto err_ret;
 
    }
  else if (hcmap->clfr_type_ind & HAL_QOS_CLFR_TYPE_IP_PREC)
    {
      if (hcmap->i.num == 0x00)
        goto err_ret;  
     
      ret = hsl_bcm_qos_set_ip_prec_filter (&hcmap->i,
                                         hcmap->clfr_type_ind &
                                         HAL_QOS_CLFR_TYPE_VLAN
                                         ? &hcmap->v : NULL,
                                         bcmif, &hcmap->s, &hcmap->p,
                                         meter_id);
      if (ret < 0)
	goto err_ret;
    }
  else if (hcmap->clfr_type_ind & HAL_QOS_CLFR_TYPE_L4_PORT)
    {
      if (hcmap->l4_port.port_type == 0)
	goto err_ret;

      ret = hsl_bcm_qos_set_l4_port_filter (&hcmap->l4_port,
					    hcmap->clfr_type_ind & HAL_QOS_CLFR_TYPE_VLAN 
					    ? &hcmap->v : NULL, bcmif, 
					    &hcmap->s, &hcmap->p, 
					    meter_id);
    }
  else if (hcmap->clfr_type_ind & HAL_QOS_CLFR_TYPE_COS_INNER)
    {
      /* Nothing to do here as we're taking care of it before hand */
      ret=0;
    }
  else 
    {
      goto err_ret;
    }
  
  if (ifp)
    HSL_IFMGR_IF_REF_DEC (ifp);
  
  if (ifp2)
    HSL_IFMGR_IF_REF_DEC (ifp2);
  
  HSL_FN_EXIT (0);

 err_ret:
  hsl_bcm_qos_if_filter_delete_all (bcmif);
  hsl_bcm_qos_if_meter_delete_all (bcmif);

  if (ifp)
    HSL_IFMGR_IF_REF_DEC (ifp);
  
  if (ifp2)
    HSL_IFMGR_IF_REF_DEC (ifp2);

  HSL_FN_EXIT (-1); 
}

int
hsl_bcm_qos_set_egress_class_map (struct hal_msg_qos_set_class_map *msg)
{
  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_set_class_map (struct hal_msg_qos_set_class_map *msg)
{
  struct hsl_if *ifp = NULL;
  int ifindex = msg->ifindex;
  int direction = msg->dir;
  int ret;

  HSL_FN_ENTER ();

  /* Get the ifp */
  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (!ifp)
    HSL_FN_EXIT (-1);

  if (direction == HAL_QOS_DIRECTION_INGRESS)
    {
      ret = hsl_bcm_qos_set_ingress_class_map (msg);
      if (ret != 0)
	HSL_FN_EXIT (ret);
      HSL_FN_EXIT (0);
    }
  else if (direction == HAL_QOS_DIRECTION_EGRESS)
    {
      ret = hsl_bcm_qos_set_egress_class_map (msg);
      if (ret != 0)
	HSL_FN_EXIT (ret);
      HSL_FN_EXIT (0);
    }
  else
    HSL_FN_EXIT (-1);
}

static int
hsl_bcm_qos_cos_inner_filter_apply (struct hsl_bcm_qos_filter *qf,
                                    int action,
                                    struct hsl_bcm_if *bcmif,
                                    struct hal_set *s,
                                    unsigned char cos)
{
  int ret;
  bcmx_lplist_t plist;
  
  plist.lp_ports = NULL;
  
  ret = bcmx_lplist_init (&plist, 0, 0);
  if (ret != BCM_E_NONE)
    return ret;

  ret = bcmx_lplist_add (&plist, bcmif->u.l2.lport);
  if (ret != BCM_E_NONE)
    {
      goto err_ret;
    }

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      ret = bcmx_filter_qualify_ingress (qf->u.filter, plist);
      if (ret != BCM_E_NONE)
        goto err_ret;

      bcmx_lplist_free (&plist);
      
      ret = bcmx_filter_action_match (qf->u.filter, bcmActionInsPrio, cos);
      if (ret != BCM_E_NONE)
        return ret;
      
      ret = bcmx_filter_install (qf->u.filter);
      
      return ret;   
    }
  else if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      ret = bcmx_field_qualify_InPorts (qf->u.field.entry, plist);
      if (ret != BCM_E_NONE)
        goto err_ret;

      ret = bcmx_field_action_add (qf->u.field.entry, 
                                   bcmFieldActionPrioPktAndIntCopy, 0, 0);
      if (ret != BCM_E_NONE)
        return ret;
      
      ret = bcmx_field_entry_install (qf->u.field.entry);

      return ret;
    }

  err_ret:
    if (plist.lp_ports)
      bcmx_lplist_free (&plist);

    return -1; 
}

static int
hsl_bcm_qos_cos_inner_filter_create(struct hsl_bcm_qos_filter *qf,
                                    unsigned long filter_flags,
                                    unsigned char cos)
{
  int ret = 0;

  if (qf->type == HSL_BCM_FEATURE_FILTER)
    {
      bcm_filterid_t filter;
      int filter_created = 0;

      ret = bcmx_filter_create (&filter);
      if (ret != BCM_E_NONE)
        return ret;
      
      filter_created = 1;
      
      ret = hsl_bcm_qos_cos_qualifier_set (filter, cos);
      if (ret != BCM_E_NONE)
        {
          if (filter_created)
            {
              bcmx_filter_remove (filter);
              bcmx_filter_destroy (filter);
              return ret;
            }
        }
      
      qf->u.filter = filter;
      
      return 0;
    }
    
  if (qf->type == HSL_BCM_FEATURE_FIELD)
    {
      bcm_field_qset_t qset;
      bcm_field_group_t group;
      bcm_field_entry_t entry;
      int entry_created = 0;
      int group_created = 0;
      
      BCM_FIELD_QSET_INIT (qset);

      ret = bcmx_field_group_create (qset, BCM_FIELD_GROUP_PRIO_ANY, &group);
      if (ret != BCM_E_NONE)
        return ret;
      
      group_created = 1;
     
      BCM_FIELD_QSET_ADD (qset, bcmFieldQualifyInPorts);
 
      ret = bcmx_field_group_set (group, qset);
      if (ret < 0)
        goto err_ret_field;

      ret = bcmx_field_entry_create (group, &entry);
      if (ret < 0)
        goto err_ret_field;
      
      entry_created = 1;
      
      qf->u.field.entry = entry;
      qf->u.field.group = group;
      
      return 0;
      
    err_ret_field:
      if (entry_created)
        {
          bcmx_field_entry_remove (entry);
          bcmx_field_entry_destroy (entry);
        }
      if (group_created)
        {
          bcmx_field_group_destroy (group); 
        }

      return -1;
    }
  
  return -1;
}

static int
_hsl_bcm_qos_cos_inner_filter_set(unsigned long filter_flags,
                                  int action,
                                  struct hsl_bcm_if *bcmif,
                                  struct hal_set *s,
                                  unsigned char cos)
{
  struct hsl_bcm_qos_filter qf;
  int ret;
  
  memset (&qf, 0, sizeof(struct hsl_bcm_qos_filter));
  qf.type = hsl_bcm_filter_type_get();
  
  ret = hsl_bcm_qos_cos_inner_filter_create(&qf,
                                            filter_flags, cos);
  if (ret < 0)
    return ret;

  ret = hsl_bcm_qos_cos_inner_filter_apply(&qf, action,
                                           bcmif, s, cos);
  if (ret < 0)
    {
      hsl_bcm_qos_filter_delete (&qf);
      hsl_bcm_qos_if_filter_delete_all (bcmif);
      return ret;
    }
  
  hsl_bcm_qos_if_filter_add (bcmif, &qf);

  return 0;
}

static int
_hsl_bcm_qos_set_cos_inner_filter (struct hal_msg_qos_set_class_map *msg)
{
  struct hsl_if *ifp = NULL, *ifp2 = NULL;
  struct hsl_bcm_if *bcmif = NULL;
  struct hal_class_map *hcmap = &msg->cmap;
  int ifindex = msg->ifindex;
  struct hsl_bcm_qos_filter qf;
  unsigned long filter_flags = 0;
  int ret;
  unsigned char cos = 0;

  HSL_FN_ENTER ();

 /* Get the ifp */
  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (!ifp)
    goto err_ret;
  
  if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
    {
      bcmif = ifp->system_info;
      if (! bcmif)
        {
	  goto err_ret;
        }
    }
  else if (ifp->type == HSL_IF_TYPE_IP)
    {
      ifp2 = hsl_ifmgr_get_first_L2_port (ifp);
      if (! ifp2)
        {
	  goto err_ret;
        }

      bcmif = ifp2->system_info;
      if (! bcmif)
        {
	  goto err_ret;
        }
    }

  if (! bcmif)
    goto err_ret;
  
  memset (&qf, 0, sizeof(struct hsl_bcm_qos_filter));
  qf.type = hsl_bcm_filter_type_get();
  
  if (qf.type == HSL_BCM_FEATURE_FILTER)
    {
      for (cos = 0; cos < HAL_COS_TBL_SIZE; cos++)
        {
          ret = _hsl_bcm_qos_cos_inner_filter_set (filter_flags,
                                                   HAL_QOS_FILTER_PERMIT,
                                                   bcmif, &hcmap->s, cos);
          if (ret < 0)
            goto err_ret;
        }
    }
  else
    {
      ret = _hsl_bcm_qos_cos_inner_filter_set (filter_flags, 
                                               HAL_QOS_FILTER_PERMIT,
                                               bcmif, &hcmap->s, cos);
      if (ret < 0)
        goto err_ret;
    }
   
  if (ifp)
    HSL_IFMGR_IF_REF_DEC (ifp);

  if (ifp2)
    HSL_IFMGR_IF_REF_DEC (ifp2);
      
  HSL_FN_EXIT (0);
   
  err_ret:
    hsl_bcm_qos_if_filter_delete_all (bcmif);
    hsl_bcm_qos_if_meter_delete_all (bcmif);

    if (ifp)
      HSL_IFMGR_IF_REF_DEC (ifp);
  
    if (ifp2)
      HSL_IFMGR_IF_REF_DEC (ifp2);

    HSL_FN_EXIT (-1); 
}
 
int
hsl_bcm_qos_set_cmap_cos_inner (struct hal_msg_qos_set_class_map *msg)
{
  struct hsl_if *ifp = NULL;
  int ifindex = msg->ifindex;
  int ret;

  HSL_FN_ENTER ();

  /* Get the ifp */
  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (!ifp)
    HSL_FN_EXIT (-1);

  ret = _hsl_bcm_qos_set_cos_inner_filter (msg);
  if (ret != 0)
    HSL_FN_EXIT (ret);
  
  HSL_FN_EXIT (0);
}

int
hsl_bcm_qos_set_policy_map (struct hal_msg_qos_set_policy_map *msg)
{
  struct hsl_if *ifp = NULL, *ifp2 = NULL;
  struct hsl_bcm_if *bcmif = NULL;
  int ifindex = msg->ifindex;
  int action = msg->action;

  HSL_FN_ENTER ();

  /* Get the ifp */
  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (!ifp)
    HSL_FN_EXIT (-1);

  /* Get logical port */
  if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
    {
      bcmif = ifp->system_info;
      if (! bcmif)
	{
	  HSL_IFMGR_IF_REF_DEC (ifp);
	  HSL_FN_EXIT (-1);
	}
    }
  else if (ifp->type == HSL_IF_TYPE_IP)
    {
      ifp2 = hsl_ifmgr_get_first_L2_port (ifp);
      if (! ifp2)
	{
	  HSL_IFMGR_IF_REF_DEC (ifp);
	  HSL_FN_EXIT (-1);
	}
      bcmif = ifp2->system_info;
      if (! bcmif)
	{
	  HSL_IFMGR_IF_REF_DEC (ifp);
	  HSL_IFMGR_IF_REF_DEC (ifp2);
	}
    }
  else
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      HSL_FN_EXIT (-1);
    }

  /* Attach policy-map into the interface */
  /* Ingress-attach, Egress-attach */
  if (action == HAL_QOS_ACTION_ATTACH)
    {
      HSL_FN_EXIT (0);
    }
  
  /* Detach policy-map from the interface */
  /* Ingress-detach, Egress-detach */
  if (action == HAL_QOS_ACTION_DETACH)
    {
      hsl_bcm_qos_if_filter_delete_all (bcmif);
      hsl_bcm_qos_if_meter_delete_all (bcmif);

      HSL_FN_EXIT (0);
    }

  /* Neither attach nor detach */
  HSL_FN_EXIT (-1);
}

#endif /* HAVE_QOS */
