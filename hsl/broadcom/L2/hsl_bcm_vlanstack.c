/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

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
#include "hal_l2.h"
#include "hal_msg.h"

#ifdef HAVE_VLAN_STACK

#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl_error.h"
#include "hsl.h"
#include "hsl_ifmgr.h"
#include "hsl_logger.h"
#include "hsl_if_hw.h"
#include "hsl_bcm_if.h"

int
hsl_bcm_vlan_stacking_enable (u_int32_t ifindex, u_int16_t tpid, int mode)
{
  int ret;
  struct hsl_if *ifp = NULL;
  struct hsl_bcm_if *bcmifp = NULL;
  bcmx_lport_t lport;
  int bcm_dtag_mode;

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    return -1;

  bcmifp = ifp->system_info;
  if (! bcmifp)
  {
    HSL_IFMGR_IF_REF_DEC (ifp);
    return -1;
  }
  lport = bcmifp->u.l2.lport;   
  HSL_IFMGR_IF_REF_DEC (ifp);

  /* set default protocol tag id */
  ret = bcmx_port_tpid_set (lport, tpid);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to set default tag protocol id on interface %d, "
	       "bcm error = %d\n", ifindex, ret);

      return ret;
    }  
  
  switch (mode)
    {
      case HAL_VLAN_STACK_MODE_NONE:
        bcm_dtag_mode = BCM_PORT_DTAG_MODE_NONE;
       break;
      case HAL_VLAN_STACK_MODE_INTERNAL:
        bcm_dtag_mode = BCM_PORT_DTAG_MODE_INTERNAL;
       break;
      case HAL_VLAN_STACK_MODE_EXTERNAL:
        bcm_dtag_mode = BCM_PORT_DTAG_MODE_EXTERNAL;
       break;
      default:
        return -1;
       break;
    }
  /* enable vlan stacking */
  ret = bcmx_port_dtag_mode_set (lport, bcm_dtag_mode);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to enable vlan stacking on interface %d, "
	       "bcm error = %d\n", ifindex, ret);

      return ret;
    }
  return 0;
}

int
hsl_bcm_vlan_stacking_disable (u_int32_t ifindex)
{
  int ret;
  struct hsl_if *ifp = NULL;
  struct hsl_bcm_if *bcmifp = NULL;
  bcmx_lport_t lport;

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    return -1;

  bcmifp = ifp->system_info;
  if (! bcmifp)
  {
     HSL_IFMGR_IF_REF_DEC (ifp);
     return -1;
  }
  lport = bcmifp->u.l2.lport;   

  HSL_IFMGR_IF_REF_DEC (ifp);

  /* disable vlan stacking */
  ret = bcmx_port_dtag_mode_set (lport, BCM_PORT_DTAG_MODE_NONE);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to disable vlan stacking on interface %d, "
	       "bcm error = %d\n", ifindex, ret);

      return ret;
    }

  return 0;
}

int
hsl_bcm_vlan_stacking_ether_set (u_int32_t ifindex, u_int16_t tpid)
{
  int ret;
  struct hsl_if *ifp = NULL;
  struct hsl_bcm_if *bcmifp = NULL;
  bcmx_lport_t lport;

  ifp = hsl_ifmgr_lookup_by_index (ifindex);
  if (! ifp)
    return -1;

  bcmifp = ifp->system_info;
  if (! bcmifp)
  {
    HSL_IFMGR_IF_REF_DEC (ifp);
    return -1;
  }
  lport = bcmifp->u.l2.lport;   
  HSL_IFMGR_IF_REF_DEC (ifp);

  /* set default protocol tag id */
  ret = bcmx_port_tpid_set (lport, tpid);
  if (ret != BCM_E_NONE)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, 
	       "Failed to set default tag protocol id on interface %d, "
	       "bcm error = %d\n", ifindex, ret);

      return ret;
    }  
  return 0;
}

#endif /* HAVE_VLAN_STACK */

