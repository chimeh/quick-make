/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

#include "bcm_incl.h"
                                                                                
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

#include "hsl_bcm_if.h"
#include "hsl_bcm_pkt.h"
#include "linux/random.h"
#include "hsl_bcm.h"

extern mac_addr_t bpdu_addr;
extern mac_addr_t gmrp_addr;
extern mac_addr_t gvrp_addr;
extern mac_addr_t lacp_addr;
extern mac_addr_t eapol_addr;

extern int hsl_tcpip_init();
extern int hsl_tcpip_deinit();

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
      sal_thread_destroy (tsk->task_id);
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
  tsk->task_id = sal_thread_create (tsk->task_name,
				    tsk->task_stack_size,
				    tsk->task_priority,
				    _hsl_periodic_thread_handler,
				    (void*)tsk); 
  if (tsk->task_id == SAL_THREAD_ERROR)
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
  /* HSL Socket backend initialization. */
  hsl_sock_init ();

#ifdef HAVE_L2
  /* Add the other backends here. */
  hsl_l2_sock_init ();

#endif /* HAVE_L2 */

#ifdef HAVE_L3
  /* Initialize END driver. */
  hsl_eth_drv_init ();

  /* Initialize TCP/IP stack backends. */
  hsl_tcpip_init ();


  /* Initialize ARP ageing handler. */
  _hsl_periodic_task_init(&arp_ageing_task);

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
  hsl_eth_drv_deinit ();

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

static int
_module_read_log_proc (char *page, char **start, off_t off, int count,
		       int *eof, void *data)
{
  int len=0;

  len += sprintf (page+len, "%u\n",hsl_log_info);
  return len;
}

static int
_module_write_log_proc (struct file *file, const char *buf, unsigned long count,
                        void *data)
{
  int len;
  int ret;
	struct net_device *dev;
	struct hsl_if *ifp = NULL;
	struct hsl_if *ifp2 = NULL;
	struct hsl_if_list *node;
	
	
  char value[HSL_WRITE_PROC_LEN];

  if( count < HSL_WRITE_PROC_LEN)
    {
      len = count;
    }
  else
    {
      len = HSL_WRITE_PROC_LEN;
    }

  if( copy_from_user ( value, buf, len))
    {
      return -1;
    }
  value[len] = '\0';

  hsl_log_info = hsl_atoi (value);

  
  dev = dev_get_by_name (&init_net, "eth0");

  printk("init dev = %p\n", dev);

  if(dev)
  	ifp = (struct hsl_if *)dev->ml_priv;

  printk("init ifp = %p\n", ifp);


  node = ifp->children_list;
  if (node)
      ifp2 = node->ifp;

  printk("node = %p, ifp2=%p\n", node, ifp2);


	if (ifp2) {
	   if (netif_carrier_ok(dev)){
			hsl_ifmgr_L2_link_up(ifp2, 100, 1);
	    } else {
	    	hsl_ifmgr_L2_link_down(ifp2, 100, 1);
	    }
	}

	printk("22ifp->u.ip.ipv4.ucAddr = %p\r\n", ifp->u.ip.ipv4.ucAddr);

  return len;
}

/*
    Read Function for /proc/hsl/arp entry
*/
#ifdef HAVE_L3
static int
_module_read_arp_proc (char *page, char **start, off_t offset, int count,
                   int *eof, void *data)
{
  struct hsl_nh_entry *nh;
  struct hsl_route_node *rnh, *rn_head;
  char buf[256];
  char mac[20];
  int len = 0;
  struct hsl_route_table *tbl;
  hsl_fib_id_t i;
  struct hsl_avl_node *node;
  struct hsl_route_node *rnp;

  HSL_FIB_LOCK;

  HSL_FIB_TBL_TRAVERSE_START (nh, tbl, i) /* nh is route table element of fib and not the local stack var */
    {
      if (len >= count)
      {
        *eof = 0;
        return count;
      }

      len += sprintf (page+len, "\n FIB# %d\n", i);
      len += sprintf (page+len, " IP Address      MAC Address   Interface  Type\n");
      rn_head = hsl_route_top (p_hsl_fib_table->nh[i]);
      if (! rn_head)
        {
          continue;
        }
      for (rnh = hsl_route_lock_node (rn_head); rnh && len < count; rnh = hsl_route_next (rnh))
        {
          nh = rnh->info;
          if (! nh )
            continue;
          hsl_prefix2str (&rnh->p, buf, sizeof (buf));
          hsl_mac_2_str (nh->mac,mac,20);
          len += sprintf(page+len, "%-15s  %-12s ref=%d, ifp=%p %-10s  %-9s  %-9s\n",buf, mac, nh->refcnt, nh->ifp, nh->ifp->name, FLAG_ISSET (nh->flags, HSL_NH_ENTRY_STATIC)? "Static" : "Dynamic", FLAG_ISSET (nh->flags, HSL_NH_ENTRY_VALID)? "Valid" : "Invalid");
		   
		  for (node = hsl_avl_top (nh->prefix_tree); node; node = hsl_avl_next (node))
		    {
		      rnp = node->info;
			   len += sprintf(page+len, "  def: %p\n", rnp);
		    }
		  
          if (len < offset) 
            {
              offset -= len;
              len = 0;
            }
        }

      hsl_route_unlock_node (rn_head);
    }
  HSL_FIB_TBL_TRAVERSE_END (prefix, tbl, i);

  HSL_FIB_UNLOCK;

  *start = page + offset;
  len -= offset;
  if (len > count) 
    {
      *eof = 0;
      return count;
    }
  *eof = 1;
  return (len<0) ? 0 : len;
}

/*
    Read Function for /proc/hsl/fib entry
*/
static int
_module_read_fib_proc (char *page, char **start, off_t offset, int count,
                   int *eof, void *data)
{
  struct hsl_nh_entry *nh;
  struct hsl_prefix_entry *pe;
  struct hsl_route_node *rnh, *rn_head;
  struct hsl_nh_entry_list_node *nhlist;
  struct hsl_nh_if_list_node *iflist;
  char buf[256];
  char flags_buf[100];
  char mac[20];
  int len = 0;
  struct hsl_route_table *tbl;
  hsl_fib_id_t i;

  HSL_FIB_LOCK;

  HSL_FIB_TBL_TRAVERSE_START (prefix, tbl, i)
    {
      if (len >= count)
      {
        *eof = 0;
        return count;
      }
      len += sprintf (page+len, "\nFIB# %d\n", i);
      len += sprintf (page+len, "L3 FIB TABLE\n");

      rn_head = hsl_route_top (p_hsl_fib_table->prefix[i]);
      if (! rn_head)
        {
          continue;
        }
      for (rnh = hsl_route_lock_node (rn_head); rnh && len < count; rnh = hsl_route_next (rnh))
        {

		  hsl_prefix2str (&rnh->p, buf, sizeof(buf));

		  len += sprintf (page+len, "prefix: %s\n",buf);

		  len += sprintf (page+len, "  parent: %p, own: %p, left: %p, right: %p\n", rnh->parent, rnh, rnh->link[0], rnh->link[1]);
		
          pe = rnh->info;
          if (! pe){
		  	
            continue;
          }

          sprintf(flags_buf,"%s %s, %x",
                          (HSL_PREFIX_ENTRY_POPULATED_IN_HW(rnh))?"Installed":"Not Installed",
                          (HSL_PREFIX_ENTRY_POPULATED_AS_EXCEPTION(rnh))?"TRAP_TO_CPU":"FORWARD", 
                          ((struct hsl_prefix_entry *)(rnh)->info)->flags);
                                                                                                                             
          len += sprintf (page+len, "  flags: %s\n", flags_buf);


          if(HSL_PREFIX_ENTRY_POPULATED_AS_EXCEPTION(rnh))
            continue;
          len += sprintf (page+len, "  NextHops:\n");

          for (nhlist = pe->nhlist; nhlist; nhlist = nhlist->next)
            {
              nh = nhlist->entry;
              if (nh)
                {
                  hsl_mac_2_str(nh->mac,mac,20);
                  hsl_prefix2str (&nh->rn->p, buf, sizeof(buf));
                  len += sprintf (page+len,"    prefix: %s mac: %s if: %s\n",
                      buf, mac, nh->ifp->name);
                }
            }
          len += sprintf (page+len, "  Intf NextHops:\n");

          for (iflist = pe->iflist; iflist; iflist = iflist->next)
            {
              len += sprintf (page+len,"    if[%p]: %s\n", iflist->ifp,
                  iflist->ifp->name);
            }
          if (len < offset)
            {
              offset -= len;
              len = 0;
            }
        }

      hsl_route_unlock_node (rn_head);
    }
  HSL_FIB_TBL_TRAVERSE_END (prefix, tbl, i);
  HSL_FIB_UNLOCK;

  *start = page + offset;
  len -= offset;
  if (len > count)
    {
      *eof = 0;
      return count;
    }
  *eof = 1;
  return (len<0) ? 0 : len;

}
#endif /* HAVE_L3 */

/*
    Read Function for interface proc entry
*/
static int
_module_read_proc_if (char *page, char **start, off_t off, int count,
                   int *eof, void *data)
{
  struct hsl_if *ifp=data;
  int len = 0;

  if (!ifp)
    {
      len += sprintf (page+len, "Interface not found\n");
      return len;
    }
  else
    {
      len += sprintf (page+len, " Name of the Interface is %s\n",ifp->name);
      len += sprintf (page+len, " index : %u    Type : %u, ifp = %p\n",ifp->ifindex,ifp->type, ifp);
      len += sprintf (page+len, " COUNTERS\n");

      len += sprintf (page+len, " good_octets_rcv : %llu  bad_octets_rcv : %llu mac_transmit_err : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.good_octets_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.bad_octets_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.mac_transmit_err));

      len += sprintf (page+len, " good_pkts_rcv : %llu  bad_pkts_rcv : %llu brdc_pkts_rcv : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.good_pkts_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.bad_pkts_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.brdc_pkts_rcv));

      len += sprintf (page+len, " mc_pkts_rcv : %llu  pkts_64_octets_rcv : %llu pkts_65_127_octets_rcv : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.mc_pkts_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.pkts_64_octets_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.pkts_65_127_octets_rcv));

      len += sprintf (page+len, " pkts_128_255_octets_rcv : %llu  pkts_256_511_octets_rcv : %llu pkts_512_1023_octets_rcv : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.pkts_128_255_octets_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.pkts_256_511_octets_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.pkts_512_1023_octets_rcv));

      len += sprintf (page+len, " pkts_1024_1518_octets_rcv : %llu  good_octets_sent : %llu good_pkts_sent : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.pkts_1024_1518_octets_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.good_octets_sent), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.good_pkts_sent));

      len += sprintf (page+len, " excessive_collisions : %llu  mc_pkts_sent : %llu brdc_pkts_sent : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.excessive_collisions), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.mc_pkts_sent), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.brdc_pkts_sent));

      len += sprintf (page+len, " unrecog_mac_cntr_rcv : %llu  fc_sent : %llu good_fc_rcv : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.unrecog_mac_cntr_rcv), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.fc_sent), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.good_fc_rcv));

      len += sprintf (page+len, " drop_events : %llu  undersize_pkts : %llu fragments_pkts : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.drop_events), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.undersize_pkts), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.fragments_pkts));

      len += sprintf (page+len, " oversize_pkts : %llu  jabber_pkts : %llu mac_rcv_error : %llu\n", \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.oversize_pkts), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.jabber_pkts), \
                                  (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.mac_rcv_error));

      len += sprintf (page+len, " bad_crc : %llu  collisions : %llu late_collisions : %llu\n", \
                                 (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.bad_crc), \
                                 (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.collisions), \
                                 (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.late_collisions));

      len += sprintf (page+len, " bad_fc_rcv : %llu\n", \
                                 (long long unsigned int)hsl_bcm_convert_to_64_int(&ifp->mac_cntrs.bad_fc_rcv));

      return len;
    }
}

int
_module_create_proc_if(struct hsl_if *ifp)
{
  struct proc_dir_entry *ent;
  char buf[20];
  int len =0;
  char tmp_name[32];
  char *tmp;

  memset(tmp_name, 0, sizeof(tmp_name));
  strncpy(tmp_name, ifp->name, sizeof(tmp_name)-1);
  if ((tmp = strchr(tmp_name,'/')) != NULL) {
	*tmp = '-';
  }

  len +=  sprintf(buf+len, "hsl/");
  len +=  sprintf(buf+len, "%s",tmp_name);

  if ((ent = create_proc_entry (buf, S_IRUGO | S_IWUGO, NULL)) != NULL)
    {
      ent->read_proc = _module_read_proc_if;
      ent->data = ifp;
      ent->write_proc = NULL;
      return 0;
    }

  return -1;
}

void
_module_remove_proc_if(struct hsl_if *ifp)
{
  char buf[20];
  int len =0;

  char tmp_name[32];
  char *tmp;

  memset(tmp_name, 0, sizeof(tmp_name));
  strncpy(tmp_name, ifp->name, sizeof(tmp_name)-1);
  if ((tmp = strchr(tmp_name,'/')) != NULL) {
	*tmp = '-';
  }

  len +=  sprintf(buf+len, "hsl/");
  len +=  sprintf(buf+len, "%s",tmp_name);

  remove_proc_entry (buf, NULL);
}

static int
_module_create_proc ()
{
  struct proc_dir_entry *ent,*hsl_dir;

  if ((hsl_dir = proc_mkdir ("hsl",NULL)) == NULL)
    {
      return -1;
    }	
#ifdef HAVE_L3
  if ((ent = create_proc_entry ("arp", S_IRUGO | S_IWUGO, hsl_dir)) != NULL)
    {
      ent->read_proc = _module_read_arp_proc;
      ent->write_proc = NULL;
    }
  else
    {
      return -1;
    }
  if ((ent = create_proc_entry ("fib", S_IRUGO | S_IWUGO, hsl_dir)) != NULL)
    {
      ent->read_proc = _module_read_fib_proc;
      ent->write_proc = NULL;
    }
  else
    {
      return -1;
    }
#endif /* HAVE_L3 */

  if ((ent = create_proc_entry ("logging", S_IRUGO | S_IWUGO, hsl_dir)) != NULL)
    {
      ent->read_proc = _module_read_log_proc;
      ent->write_proc = _module_write_log_proc;
      return 0;
    }
  else
    {
      return -1;
    }

  return 0;
}

static void
_module_remove_proc (void)
{
  remove_proc_entry ("hsl/logging", NULL);
#ifdef HAVE_L3
  remove_proc_entry ("hsl/arp", NULL);
  remove_proc_entry ("hsl/fib", NULL);
#endif /* HAVE_L3 */
  remove_proc_entry ("hsl", NULL);
}

/*
  Linux kernel module init and denint registrations.
*/
static int __init
_hsl_module_init (void)
{
  int ret;

#if 0
  printk (KERN_CRIT "IP Infusion Proprietary Hardware Services Layer\n");
#endif

  ret = _module_create_proc ();
  if (ret < 0)
    return -1;

#if 0
  printk (KERN_CRIT "IP Infusion Proprietary Hardware Services Layer Init\n");
#endif

#if 0
  hsl_log_info = 0xff;
#endif
  /* Initialize HSL. */
  hsl_init ();

  return 0;
}

static void __exit
_hsl_module_deinit (void)
{
#if 0
  printk ("IP Infusion Proprietary Hardware Services Layer\n");
#endif

  _module_remove_proc ();

  /* Deinitialize HSL. */
  hsl_deinit ();
}

module_init (_hsl_module_init);
module_exit (_hsl_module_deinit);

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("IP Infusion Inc.");
MODULE_DESCRIPTION ("IP Infusion Broadcom Hardware Services Layer");

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
EXPORT_SYMBOL (hsl_bcm_rx_cb);

