/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */


#include <linux/proc_fs.h>
#include "linux/time.h"
#include "linux/random.h"

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

                                                                                
/* HAL includes. */
#include "hal_types.h"
#include "hal_netlink.h"


#ifdef HAVE_L2
#include "hal_socket.h"
#endif

#include "hal_msg.h"

#include "hsl_avl.h"
#include "hsl_error.h"
#include "hsl_table.h"
#include "hsl_ether.h"
#include "hsl.h"
#include "hsl_oss.h"
#include "hsl_comm.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_comm.h"


#ifdef HAVE_L2
#include "hsl_l2_sock.h"
#include "hsl_vlan.h"
#include "hsl_bridge.h"
#endif /* HAVE_L2 */


#ifdef HAVE_L3
#include "hsl_eth_drv.h"
#include "hsl_fib.h"
#endif /* HAVE_L3 */

#include "hsl_ctc_if.h"
#include "hsl_ctc_pkt.h"
#include "hsl_ctc.h"

extern mac_addr_t bpdu_addr;
extern mac_addr_t gmrp_addr;
extern mac_addr_t gvrp_addr;
extern mac_addr_t lacp_addr;
extern mac_addr_t eapol_addr;


extern int hsl_tcpip_init(void);
extern int hsl_tcpip_deinit(void);

extern struct hsl_fib_table *p_hsl_fib_table;
extern u_int32_t hsl_log_info;

#ifdef HAVE_L3
struct hsl_periodic_task arp_ageing_task = {HSL_ARP_AGEING_THREAD_NAME,
                                            HSL_DEFAULT_ARP_TIMER_RESOLUTION,
                                            {{NULL,NULL},0,0,NULL},
                                            HSL_ARP_AGEING_THREAD_PRIO,
                                            HSL_ARP_AGEING_STACK, HSL_ARP_AGEING_SEM_NAME,
                                            NULL, 0, hsl_fib_process_nh_ageing};
#endif /* HAVE_L3 */
struct hsl_periodic_task if_statistics_task = {HSL_IFSTAT_THREAD_NAME,
                                               HSL_IFSTAT_TIMER_RESOLUTION,
                                               {{NULL,NULL},0,0,NULL},
                                               HSL_IFSTAT_THREAD_PRIO,
                                               HSL_IFSTAT_STACK, HSL_IFSTAT_SEM_NAME,
                                               NULL, 0, hsl_ifmgr_collect_if_stat};

void
_module_remove_proc_if(struct hsl_if *ifp)
{

}

void
_module_create_proc_if(struct hsl_if *ifp)
{

}

/* 
   Periodic timer callback.
*/
static void 
_periodic_timer_callback (unsigned long tsk_ptr)
{
  struct hsl_periodic_task *tsk;

  tsk = (struct hsl_periodic_task *)tsk_ptr;
  /* Give semaphore. */
  if(tsk->sem_id != 0)
    oss_sem_unlock (OSS_SEM_BINARY, tsk->sem_id);

  /* Restart ARP ageing timer. */
  tsk->timer_id.expires = jiffies + (HZ * tsk->task_timeout);
  tsk->timer_id.function = _periodic_timer_callback;
  tsk->timer_id.data = (unsigned long)tsk;

  init_timer(&tsk->timer_id);
  add_timer (&tsk->timer_id); 
}

/*
   HSL periodic thread.
*/
static void
_hsl_periodic_thread_handler (void *param)
{
  struct hsl_periodic_task *tsk = (struct hsl_periodic_task *)param; 
  
  HSL_FN_ENTER();

  while (1)
    {
      /* Wait for semaphore. */
      oss_sem_lock (OSS_SEM_BINARY, tsk->sem_id, OSS_WAIT_FOREVER);

      /* Process the periodic function. */
      if(tsk->foo)
        tsk->foo();
    }

  HSL_FN_EXIT();
}

/*
  Deinitialize timer, thread.
*/
static int
_hsl_periodic_deinit(struct hsl_periodic_task *tsk)
{

  HSL_FN_ENTER();

  /* Cancel periodic thread. */
  if (tsk->task_id)
    {
      sal_task_destroy(tsk->task_id);
      tsk->task_id = NULL;
    }
  
  /* Cancel semaphore. */
  if (tsk->sem_id)
    {
      oss_sem_delete (OSS_SEM_BINARY, tsk->sem_id);
      tsk->sem_id = NULL;
    }

  /* Cancel timer. */
  del_timer (&tsk->timer_id);
  HSL_FN_EXIT(STATUS_OK);
}

/*
  Initialize periodic, thread.
*/
static int
_hsl_periodic_task_init (struct hsl_periodic_task *tsk)
{
  int ret;

  HSL_FN_ENTER();


  /* Create periodic thread. */
  /* Create semaphore. */
  ret = oss_sem_new (tsk->sem_name,
		     OSS_SEM_BINARY,
		     0,
		     NULL,
		     &tsk->sem_id);

  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Cannot create periodic thread %s semaphore\n",tsk->task_name);
      goto ERR;
    }
  /* Create thread for processing ARP ageing. */

  #if 0
  tsk->task_id = sal_thread_create (tsk->task_name,
				    tsk->task_stack_size,
				    tsk->task_priority,
				    _hsl_periodic_thread_handler,
				    (void*)tsk); 
  #else
    ret = sal_task_create(&tsk->task_id, 
                    tsk->task_name, 
                    tsk->task_stack_size, 
                    tsk->task_priority, 
                    _hsl_periodic_thread_handler, 
                    (void*)tsk);
  #endif
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "Cannot start periodic thread %s\n",tsk->task_name);
      goto ERR;
    }
  /* Start ARP ageing timer. */
  tsk->timer_id.expires = jiffies + (HZ * tsk->task_timeout);
  tsk->timer_id.function = _periodic_timer_callback;
  tsk->timer_id.data = (unsigned long)tsk;
  init_timer(&tsk->timer_id);
  add_timer (&tsk->timer_id); 
  HSL_FN_EXIT(STATUS_OK);
 ERR:
 	
  _hsl_periodic_deinit(tsk);
  HSL_FN_EXIT(STATUS_ERROR);
}

/* 
   Initialize OS layer. 
*/
int
hsl_os_init (void)
{
  int rv;
  char *msg = NULL;

  /* HSL Socket backend initialization. */
  SYSTEM_INIT_CHECK(hsl_sock_init (), "os sock init");

#ifdef HAVE_L2
  /* Add the other backends here. */
  SYSTEM_INIT_CHECK(hsl_l2_sock_init (), "os l2 sock init");

#endif /* HAVE_L2 */


#ifdef HAVE_L3
  /* Initialize END driver. */
  //SYSTEM_INIT_CHECK(hsl_eth_drv_init (), "os eth drv init");

  /* Initialize TCP/IP stack backends. */
   SYSTEM_INIT_CHECK(hsl_tcpip_init (), "os tcpip init");


  /* Initialize ARP ageing handler. */
  //_hsl_periodic_task_init(&arp_ageing_task);

#endif /* HAVE_L3 */
  _hsl_periodic_task_init(&if_statistics_task);

  return 0;
}

/* 
   Deinitialize OS layer.
*/
int
hsl_os_deinit (void)
{
  /* HSL Socket backend deinitialization. */
  hsl_sock_deinit ();

#ifdef HAVE_L2
  /* Add the other backends here. */
  hsl_l2_sock_deinit ();
#endif /* HAVE_L2 */

#ifdef HAVE_L3
  /* Deinitialize END drver. */
  //hsl_eth_drv_deinit ();

  /* Deinitialize TCP/IP stack backends. */
  hsl_tcpip_deinit ();

  /* Deinitialize ARP ageing handler. */
  _hsl_periodic_deinit(&arp_ageing_task);
#endif /* HAVE_L3 */
  _hsl_periodic_deinit(&if_statistics_task);


  return 0;
}

/* 
   Defines for atomic operations not part of SAL.
*/


/*
  Atomic increment.
*/
inline void 
oss_atomic_inc (oss_atomic_t *val)
{
  atomic_t *p = (atomic_t *) val;
 
  atomic_inc (p);
}

/*
  Atomic decrement.
*/
inline void
oss_atomic_dec (oss_atomic_t *val)
{
  atomic_t *p = (atomic_t *) val;

  atomic_dec (p);
}

/*
  Atomic set.
*/
inline void
oss_atomic_set (oss_atomic_t *val, int set)
{
  atomic_t *p = (atomic_t *) val;

  atomic_set (p, set);
}

/* 
   Atomic decrement and check.
*/
inline int
oss_atomic_dec_and_test (oss_atomic_t *val)
{
  atomic_t *p = (atomic_t *) val;

  return atomic_dec_and_test (p);
}

/*
  Random.
*/
int
oss_rand (void)
{
  int r;
  static int sort_of_seed;

  get_random_bytes (&r, sizeof (r)); 

  return ((r ^ sort_of_seed) & OSS_RANDOM_MAX);
}

/*
   ASCII to Integer
*/
int
hsl_atoi (char *str)
{
   return simple_strtol (str, NULL, 10);
}


extern int hsl_proc_log_init(void);
/*
  Linux kernel module init and denint registrations.
*/
int
hsl_module_init (void)
{
    int ret;

	printk("proc log init\n");
	hsl_proc_log_init();

    printk (KERN_CRIT "Hardware Services Layer\n");
	 

    /* Initialize HSL. */
    ret = hsl_init ();

    return 0;
}

void
hsl_module_deinit (void)
{
  printk (KERN_CRIT"Hardware Services Layer\n");

  /* Deinitialize HSL. */
  hsl_deinit ();
}

/* Export symbols. */
EXPORT_SYMBOL (p_hsl_if_db);
#ifdef HAVE_L2
EXPORT_SYMBOL (p_hsl_bridge_master);
#endif /* HAVE_L2 */

EXPORT_SYMBOL (bpdu_addr);
EXPORT_SYMBOL (gmrp_addr);
EXPORT_SYMBOL (gvrp_addr);
EXPORT_SYMBOL (lacp_addr);
EXPORT_SYMBOL (eapol_addr);
//EXPORT_SYMBOL (hsl_bcm_rx_cb);

