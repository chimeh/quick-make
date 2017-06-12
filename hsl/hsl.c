/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"
#include "hal_if.h"
#include "hsl_oss.h"
#include "hsl_logs.h"
#include "hsl.h"
#include "hsl_table.h"
#include "hsl_ether.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"
#include "hsl_ctc_ipmc.h"

#ifdef HAVE_L2
#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"
#include "hsl_vlan.h"
#include "hsl_bridge.h"
#include "hsl_mac_tbl.h"
#endif /* HAVE_L2 */
#ifdef HAVE_L3
#include "hsl_fib.h"
#endif /* HAVE_L3 */

#if 1
#ifdef HAVE_LAYER4
#include <linux/kernel.h>
//#include "bcm/field.h"
//#include "bcm/types.h"
//#include "bcm/error.h"
//#include "sal/core/sync.h"
#include <linux/list.h>
#include <linux/types.h>
#include "bcm_cap.h"
#endif
#if defined HAVE_MCAST_IPV4 || defined HAVE_MCAST_IPV6 || defined HAVE_IGMP_SNOOP
#include "hsl_mcast_fib.h"
#endif /* HAVE_MCAST_IPV4 || HAVE_MCAST_IPV6 || HAVE_IGMP_SNOOP */

#include "hal_types.h"
#endif

static int hsl_initialized = 0;


/* Extern interfaces. */
extern void hsl_sock_ifmgr_notify_chain_register (void);
extern void hsl_sock_ifmgr_notify_chain_unregister (void);

#if 0

#if 1  /** Inserted by alfred for 2007-01-12 **/
#include <soc/feature.h>
extern int gprintk(const char* fmt, ...);

#define		HSL_MOD_NAME	"BCM_HSL"
#include <gmodule.h>

static int
gvprintk(const char* fmt, va_list args)
{
    static char _buf[256];
	
	strcpy(_buf, "");
	sprintf(_buf, "%s (%d): ", HSL_MOD_NAME, current->pid);
	vsprintf(_buf+strlen(_buf), fmt, args);
	printk(_buf); 
	
	return 0;
}   

int
gprintk(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	return gvprintk(fmt, args);
}   


#endif

void hsl_shape_init(void);

#endif



/*
  Initialize HSL.
*/
int
hsl_init (void)
{
  int rv;
  char *msg = NULL;
  
  HSL_FN_ENTER ();

  if (hsl_initialized)
    return 0;

  /* Initialize OS layer, backends, network buffers etc. */
  SYSTEM_INIT_CHECK(hsl_os_init (), "os init");

  /* Initialize interface manager. */
  SYSTEM_INIT_CHECK(hsl_ifmgr_init (), "ifmgr init");

#ifdef HAVE_L2
  /* Initialize master bridge structure. */
  SYSTEM_INIT_CHECK(hsl_bridge_master_init (), "bridge master init");

  /* Initialize FDB table */
  SYSTEM_INIT_CHECK(hsl_init_fdb_table (), "fdb init");
  if (rv < 0)
    hsl_deinit_fdb_table();

#endif /* HAVE_L2 */

#ifdef HAVE_L3
  /* Initialize FIB manager. */
  SYSTEM_INIT_CHECK(hsl_fib_init (), "fib init");
  SYSTEM_INIT_CHECK(hsl_ipmc_init (), "zw-ipmc init");
#endif /* HAVE_L3 */



#ifdef HAVE_LAYER4
  SYSTEM_INIT_CHECK(hsl_layer4_init(), "layer4 init");
#endif
#if 0

#if defined HAVE_MCAST_IPV4 || defined HAVE_IGMP_SNOOP
  hsl_ipv4_mc_db_init();
#endif /* HAVE_MCAST_IPV4 || HAVE_IGMP_SNOOP */
printk("7\r\n");
#ifdef HAVE_MCAST_IPV6
  hsl_ipv6_mc_db_init();
#endif /* HAVE_MCAST_IPV6 */
 #endif
    
    /* Initialize hardware layer. */
    SYSTEM_INIT_CHECK(hsl_hw_init (), "hw init");
    
  /* Register interface manager notifiers. */
  hsl_sock_ifmgr_notify_chain_register (); 
  hsl_initialized = 1;

  HSL_FN_EXIT (0);
}
void hsl_shape_deinit(void);

/* 
   Deinitialize HSL.
*/
int
hsl_deinit (void)
{
  HSL_FN_ENTER ();

  if (! hsl_initialized)
    HSL_FN_EXIT (-1);
#if 1
  /* Unregister interface manager notifiers. */
  hsl_sock_ifmgr_notify_chain_unregister ();
#endif

  /* Deinitialize OS layer, backends, network buffers etc. */
  hsl_os_deinit ();
  
  /* Deinitialize interface manager. */
  hsl_ifmgr_deinit ();

#ifdef HAVE_L2
  /* Deinitialize master bridge structure. */
  hsl_bridge_master_deinit ();
  /* Deinitialize FDB table */
  hsl_deinit_fdb_table();
#endif /* HAVE_L2 */

#ifdef HAVE_L3
  /* Deinitialize FIB manager. */
 // hsl_fib_deinit ();
#endif /* HAVE_L3 */
#if 0

#ifdef HAVE_L3
#ifdef HAVE_MCAST_IPV4
  hsl_ipv4_mc_db_deinit();
#endif /* HAVE_MCAST_IPV4 */
printk("9\r\n");
#ifdef HAVE_MCAST_IPV6
  hsl_ipv6_mc_db_deinit();
#endif /* HAVE_MCAST_IPV6 */
printk("10\r\n");
#endif /* HAVE_L3 */
printk("11\r\n");
  /* Deinitialize hardware layer. */
  hsl_hw_deinit ();
printk("12\r\n");
// #ifdef HAVE_NETFORD_SHAPE
  hsl_shape_deinit();
// #endif
printk("13\r\n");
#endif
  hsl_initialized = 0;

  HSL_FN_EXIT (0);
}

