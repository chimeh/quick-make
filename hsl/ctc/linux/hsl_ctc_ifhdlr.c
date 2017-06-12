/* Copyright (C) 2004 IP Infusion, Inc.  All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"


#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_logs.h"

#include "hsl_ctc_ifcb.h"
#include "hsl_ctc_ifmap.h"
#include "hsl_ctc_ifhdlr.h"
#include "hsl_os.h"
#include "hsl_ifmgr.h"

#include "sal.h"
#include "ctc_adapter_hsl_port.h"
#include "ctc_if_portmap.h"

/* Global data for interface handler. */
static struct hsl_bcm_if_event_queue *p_hsl_bcm_if_event_queue = NULL;
static int aligned_sizeof_hsl_bcm_ifhdlr_msg;
extern struct hsl_if_db *p_hsl_if_db;

//static sal_task_t *ctc_ifhdlr_thread;

extern int _module_create_proc_if(struct hsl_if *ifp);
extern int _module_remove_proc_if(struct hsl_if *ifp);


/* Event post handler. */
static int
_hsl_bcm_if_post_event (struct hsl_bcm_ifhdlr_msg *msg)
{
  struct hsl_bcm_ifhdlr_msg *entry;

  HSL_FN_ENTER ();

  /* Queue the packet. */
  if (HSL_BCM_IF_EVENT_QUEUE_FULL)
    {
      /* Queue is full. */
      p_hsl_bcm_if_event_queue->drop++;

      HSL_FN_EXIT (-1);
    }
  else
    {
	  /*get queue opreation semaphore*/
	  oss_sem_lock (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_op_sem, OSS_WAIT_FOREVER);
//        printk("[%s-%d]: lock ifhdlr_op_sem \r\n", __func__, __LINE__);

	  /* Get entry. */
      entry = (struct hsl_bcm_ifhdlr_msg *)&p_hsl_bcm_if_event_queue->queue[p_hsl_bcm_if_event_queue->tail * aligned_sizeof_hsl_bcm_ifhdlr_msg];

      /* Copy the header contents. */
      memcpy (entry, msg, sizeof (struct hsl_bcm_ifhdlr_msg));

      /* Increment count. */
      p_hsl_bcm_if_event_queue->count++;

      /* Adjust tail. */
      p_hsl_bcm_if_event_queue->tail = HSL_BCM_IF_EVENT_QUEUE_NEXT (p_hsl_bcm_if_event_queue->tail);

	  /*give queue opreation semaphore*/
	  oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_op_sem);
//        printk("[%s-%d]: unlock ifhdlr_op_sem \r\n", __func__, __LINE__);

      /* Give semaphore. */
      oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_sem);

      HSL_FN_EXIT (0);
    }

  HSL_FN_EXIT (0);
}

/* Callback function for port creation. 
** @gport: ctc sdk gloable port,
** @lport: ctc sdk local port, 
** @unit: ctc sdk chip number
*/
void *hsl_ctc_port_attach_cb (int gport, int unit, int lport, uint32_t flags)
{
    struct hsl_bcm_ifhdlr_msg msg;
    u_int32_t uport = gport;
    int u, p, m;
    int ret = 0;

    HSL_FN_ENTER ();

    memset(&msg, 0, sizeof(msg));
    msg.type = HSL_CTC_PORT_ATTACH_NOTIFICATION;
    msg.u.port_attach.lport = gport;
    msg.u.port_attach.unit  = unit;
    msg.u.port_attach.port  = lport;
    msg.u.port_attach.flags = flags;

//    printk("[%s]: attach port: gport: %d, unit: %d, lport: %d, flags: %#x\r\n", __func__, gport, unit, lport, flags);
    
    /* Post the event. */
    ret =  _hsl_bcm_if_post_event (&msg);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Failed posting new port attachment event for port %d\n", lport);
        /* XXX Should treat this seriously than we are. */
    }

#if 0
  bcmx_lport_to_unit_port(lport, &u, &p);
  bcmx_lport_to_modid(lport, &m);

  uport = hsl_bcm_port_u2l (m, u, p);
#endif

    HSL_FN_EXIT ((void *)((long)uport));
}

/* Callback function for port deletion. */
static void
_hsl_bcm_port_detach_cb (int gport, uint8_t lport)
{
  struct hsl_bcm_ifhdlr_msg msg;
  int ret;

  HSL_FN_ENTER ();

  msg.type = HSL_CTC_PORT_DETACH_NOTIFICATION;
  msg.u.port_detach.lport = gport;
  msg.u.port_detach.uport  = lport;

  /* Post the event. */
  ret =  _hsl_bcm_if_post_event (&msg);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Failed posting port dexttachment event for port %d\n", lport);
      /* XXX Should treat this seriously than we are. */
    }

  HSL_FN_EXIT ();
}

/* Register callback for port creation. */
void
hsl_bcm_register_port_attach (void)
{
//  bcmx_uport_create_callback_set (_hsl_bcm_port_attach_cb);
    return;
}

/* Unregister callback for port deletion. */
void
hsl_bcm_unregister_port_attach (void)
{
//  bcmx_uport_create = NULL;
    return;
}

/* Register callback for port deletion. */
void
hsl_bcm_register_port_detach (void)
{
//  ctc_gport_remove_notify = _hsl_bcm_port_detach_cb;
}

/* Unregister callback for port deletion. */
void
hsl_bcm_unregister_port_detach (void)
{
//  bcmx_lport_remove_notify = NULL;
	return;
}

/* Link scan callback. */
static void
_hsl_bcm_linkscan_cb (int gport, void *info)
{
  struct hsl_bcm_ifhdlr_msg msg;
  int ret;

  HSL_FN_ENTER ();

//    printk("[%s]: gport<%d> link changed\r\n", __func__, gport);
    
  msg.type = HSL_CTC_PORT_LINKSCAN_NOTIFICATION;
  msg.u.link_scan.lport = gport;
//  memcpy (&msg.u.link_scan.info, info, sizeof (bcm_port_info_t));
    msg.u.link_scan.info = NULL;

  /* Post the event. */
  ret =  _hsl_bcm_if_post_event (&msg);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Failed posting link scan message %d\n", gport);
      /* XXX Should treat this seriously than we are. */
    }

  HSL_FN_EXIT ();
}

static void
_hsl_rescan_ports (int unit)
{

#if 0
  int   lport;
  int   port;
  uint32_t  flags;
  int          *val, value;
  void *info = NULL;
  
  BCMX_FOREACH_LPORT(lport) {
      /* check if unit is the same */
      if (BCMX_LPORT_BCM_UNIT(lport) == unit)
      {
         /* Add port now */
          bcmx_port_link_status_get (lport, &info.linkstatus);

		  /* Speed. */
		  bcmx_port_speed_get (lport, &info.speed);

		  /* Duplex */
		  hsl_bcm_get_port_duplex(lport, &info.duplex);

		  _hsl_bcm_linkscan_cb(lport, &info);
      }
  }
#else
    return;
#endif
}

/* Register callback for link scanning. */
int
hsl_bcm_register_link_scan (void)
{
    int ret = 0;
  
    HSL_FN_ENTER ();

#if 0
  ret = bcmx_linkscan_register (_hsl_bcm_linkscan_cb);

  //bcmx_linkscan_enable_set(0);

	if (bcm_attach_check (0) >= 0){
		_hsl_rescan_ports (0);
	}

	if (bcm_attach_check (1) >= 0){
		_hsl_rescan_ports (1);
	}
#endif

    HSL_FN_EXIT (ret);
}

/* Unregister callback for link scanning. */
int
hsl_bcm_unregister_link_scan ()
{
    int ret = 0;
    
    HSL_FN_ENTER ();

//  ret = bcmx_linkscan_unregister (_hsl_bcm_linkscan_cb);

    HSL_FN_EXIT (ret);
}

/* added by cdy, 2016/07/01 */
int hsl_ctc_ifcb_info_link_scan(int gport)
{
    _hsl_bcm_linkscan_cb(gport, NULL);

    return 0;
}



/* Background message processing. */
static int
_hsl_bcm_ifhdr_process_msg (struct hsl_bcm_ifhdlr_msg *msg)
{
  HSL_FN_ENTER ();

  switch (msg->type)
    {
    case HSL_CTC_PORT_ATTACH_NOTIFICATION:
      {
	/* If port is invalid, skip this port. */
	if (! (msg->u.port_attach.flags & CTC_PORT_F_VALID))
	  {
	    HSL_FN_EXIT (0);
	  }

	/* Process only data ports for interface manager. */
        if(!((CTC_PORT_F_IS_STACK_PORT (msg->u.port_attach.flags))
           || (msg->u.port_attach.flags & CTC_PORT_F_HG)
           || (msg->u.port_attach.flags & CTC_PORT_F_CPU)
           /*|| (msg->u.port_attach.flags & BCMX_PORT_F_XE)*/))
	  {
	    /* Process port attachment. */
	    hsl_bcm_ifcb_port_attach (msg->u.port_attach.lport,
				      msg->u.port_attach.unit,
				      msg->u.port_attach.port,
				      msg->u.port_attach.flags);
	  }
	else
	  {
	    HSL_FN_EXIT (0);
	  }
      }
      break;
    case HSL_CTC_PORT_DETACH_NOTIFICATION:
      {
	/* Process only data ports for interface manager. */
        if(!((CTC_PORT_F_IS_STACK_PORT (msg->u.port_attach.flags))
           || (msg->u.port_attach.flags & CTC_PORT_F_HG)
           || (msg->u.port_attach.flags & CTC_PORT_F_CPU)
           || (msg->u.port_attach.flags & CTC_PORT_F_XE)))
	  {
	    /* Process port detachment. */
	    hsl_bcm_ifcb_port_detach (msg->u.port_detach.lport,
				      msg->u.port_detach.uport);
	  }
	else
	  HSL_FN_EXIT (0);
      }
      break;
    case HSL_CTC_PORT_LINKSCAN_NOTIFICATION:
      {
	/* Process linkscan notification. */
	hsl_bcm_ifcb_link_scan (msg->u.link_scan.lport,
				&msg->u.link_scan.info);
      }
      break;
    default:
      HSL_FN_EXIT (0);
    }

  HSL_FN_EXIT (0);
}

/* Interface handler task entry function. */
static void
_hsl_ctc_ifhdlr_func (void *param)
{
  struct hsl_bcm_ifhdlr_msg *msg;
  int spl;

  HSL_FN_ENTER ();

  mdelay(200);

  while (! p_hsl_bcm_if_event_queue->thread_exit)
    {
      /* Service packets. */
      while (! HSL_BCM_IF_EVENT_QUEUE_EMPTY)
	{

	  /*get queue opreation semaphore*/
      oss_sem_lock (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_op_sem, OSS_WAIT_FOREVER);
//        printk("[%s-%d]: lock ifhdlr_op_sem \r\n", __func__, __LINE__);

          /* Set interrupt level to high. */
//          spl = sal_splhi ();

	  /* Get head event. */
	  msg = (struct hsl_bcm_ifhdlr_msg *)&p_hsl_bcm_if_event_queue->queue[p_hsl_bcm_if_event_queue->head * aligned_sizeof_hsl_bcm_ifhdlr_msg];

	  /* Increment head. */
	  p_hsl_bcm_if_event_queue->head = HSL_BCM_IF_EVENT_QUEUE_NEXT (p_hsl_bcm_if_event_queue->head);

	  /* Decrement count. */
	  p_hsl_bcm_if_event_queue->count--;

          /* Unlock interrupt level. */
//          sal_spl (spl);
	  /*give queue opreation semaphore*/
	  oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_op_sem);
//        printk("[%s-%d]: unlock ifhdlr_op_sem \r\n", __func__, __LINE__);

	  /* Process the link message. */
	  _hsl_bcm_ifhdr_process_msg (msg);
	}

      oss_sem_lock (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_sem, OSS_WAIT_FOREVER);
    }

  /* Exit packet thread. */
  oss_sem_delete (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_sem);
  oss_sem_delete (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_op_sem);

  HSL_FN_EXIT ();
}

int hsl_bridge_hw_register(void);

static int hsl_device_event(struct notifier_block *unused, unsigned long event,
                             void *ptr)
{
        struct net_device *dev = ptr;
		struct hsl_if *ifp;
		struct hsl_if *ifp2 = NULL;
		struct hsl_if_list *node;

//		bcm_port_info_t info = {0};

		if(strcmp(dev->name, "eth0"))
			return NOTIFY_DONE;


//		_hsl_bcm_linkscan_cb(0xFFFF0001, &info);

		return NOTIFY_DONE;
		
		

		ifp = (struct hsl_if *)dev->ml_priv;

		if (!ifp)
			return NOTIFY_DONE;

		 node = ifp->children_list;
		  if (node)
		      ifp2 = node->ifp;

		  if (!ifp2)
			return NOTIFY_DONE;
         
        switch (event) {
        case NETDEV_CHANGE:
            if (netif_carrier_ok(dev)){
				hsl_ifmgr_L2_link_up(ifp2, 100000, 1);
            } else {
            	hsl_ifmgr_L2_link_down(ifp2, 100000, 1);
            }
			
            break;
				
		default:
			break;
			
        }
		

	return NOTIFY_DONE;
}

static struct notifier_block hsl_notifier_block __read_mostly = {
        .notifier_call = hsl_device_event,
};

int hsl_linkscan_reg(void){
	int ret;
	struct net_device *dev;
	struct hsl_if *ifp = NULL;
	struct hsl_if *ifp2 = NULL;
	struct hsl_if_list *node;
	
	    /* Register for link scanning. */
  printk("hsl_bcm_register_link_scan\r\n");
  ret = hsl_bcm_register_link_scan ();
  printk("hsl_bcm_register_link_scan = %d\r\n", ret);

  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Cannot start link scanning thread\n");
      ret = HSL_BCM_ERR_IFHDLR_INIT;
    }


  register_netdevice_notifier(&hsl_notifier_block);

  /* Register the loopback interface. */
//  hsl_ifmgr_L3_loopback_register ("lo", dev->ifindex, 32768, dev->flags, dev);


//    hsl_bridge_hw_register();

  dev = dev_get_by_name (&init_net, "eth0");

  if(dev)
  	ifp = (struct hsl_if *)dev->ml_priv;

  node = ifp->children_list;
  if (node)
      ifp2 = node->ifp;

	if (ifp2) {
	   if (netif_carrier_ok(dev)){
			hsl_ifmgr_L2_link_up(ifp2, 100000, 1);
	    } else {
	    	hsl_ifmgr_L2_link_down(ifp2, 100000, 1);
	    }
	}


//  bcmx_switch_control_set(bcmSwitchL3EgressMode, 1);

  //bcmSwitchL3IngressMode

  return ret;
}
/* Initialize the interface handler. */
int
hsl_ctc_ifhdlr_init (void)
{
  int port_attach = 0, port_detach = 0, link_scan = 0;
  int total;
  int ret = 0;

  HSL_FN_ENTER ();

  /* Set the aligned size of struct hsl_bcm_ifhdlr_msg, so that we don;t calculate everytime. */
  aligned_sizeof_hsl_bcm_ifhdlr_msg = (((sizeof (struct hsl_bcm_ifhdlr_msg) * 3) / 4) * 4);

  if (! p_hsl_bcm_if_event_queue)
    {
      p_hsl_bcm_if_event_queue = oss_malloc (sizeof (struct hsl_bcm_if_event_queue), OSS_MEM_HEAP);
      if (! p_hsl_bcm_if_event_queue)
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Out of memory\n");
	  ret = HSL_BCM_ERR_IFHDLR_NOMEM;
	  goto ERR;
	}
    }

  /* Create interface event queue. */
  total = aligned_sizeof_hsl_bcm_ifhdlr_msg * HSL_BCM_IF_EVENT_QUEUE_SIZE;
  p_hsl_bcm_if_event_queue->queue = oss_malloc (total, OSS_MEM_HEAP);
  if (! p_hsl_bcm_if_event_queue->queue)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Out of memory\n");
      ret = HSL_BCM_ERR_IFHDLR_NOMEM;
      goto ERR;   
    }

  /* Initialize the queue. */
  memset (p_hsl_bcm_if_event_queue->queue, 0, total);

  /* Initialize counters. */
  p_hsl_bcm_if_event_queue->total = HSL_BCM_IF_EVENT_QUEUE_SIZE;
  p_hsl_bcm_if_event_queue->count = 0;
  p_hsl_bcm_if_event_queue->head = 0;
  p_hsl_bcm_if_event_queue->tail = 0;
  p_hsl_bcm_if_event_queue->drop = 0;

  /* Initialize semaphore. */
  ret = oss_sem_new ("ifhdlr_event_queue_sem",
		     OSS_SEM_BINARY,
		     0,
		     NULL,
		     &p_hsl_bcm_if_event_queue->ifhdlr_sem);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Failed creating interface event handler semaphore\n");
      ret = HSL_BCM_ERR_IFHDLR_NOMEM;
      goto ERR;
    }
  ret = oss_sem_new ("ifhdlr_event_queue_opreation_sem",
		     OSS_SEM_BINARY,
		     1,
		     NULL,
		     &p_hsl_bcm_if_event_queue->ifhdlr_op_sem);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Failed creating interface event handler opreation semaphore\n");
      ret = HSL_BCM_ERR_IFHDLR_NOMEM;
      goto ERR;
    } else {
        oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_if_event_queue->ifhdlr_op_sem);
    }



  
  p_hsl_bcm_if_event_queue->thread_exit = 0;

#if 0   /* we MUST change THIS after */
  /* Create interface event dispather thread. */
  if ((p_hsl_bcm_if_event_queue->ifhdlr_thread = 
       sal_thread_create ("zBCMIFHDLR", 
			  SAL_THREAD_STKSZ, 
			  50,
			  _hsl_bcm_ifhdlr_func,
			  (void *)0)) == SAL_THREAD_ERROR)
    {
      HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_FATAL, "Cannot start interface event dispatcher thread\n");
      ret = HSL_BCM_ERR_IFHDLR_INIT;
      goto ERR;
    }
#else
    ret = sal_task_create(&p_hsl_bcm_if_event_queue->ifhdlr_thread, "zCTC_IFHDLR", 0, 0, _hsl_ctc_ifhdlr_func, NULL);
#endif

  p_hsl_if_db->proc_if_create_cb = _module_create_proc_if;
  p_hsl_if_db->proc_if_remove_cb = _module_remove_proc_if;
//    p_hsl_if_db->proc_if_create_cb = NULL;
//    p_hsl_if_db->proc_if_remove_cb = NULL;

  /* Register for port attachments. */
  hsl_bcm_register_port_attach ();
  port_attach = 1;

  /* Register for port detachments. */
  hsl_bcm_register_port_detach ();
  port_detach = 1;

  HSL_FN_EXIT (0);

 ERR:
 	printk("hsl_ctc_ifhdlr_init error\r\n");
  if (port_attach)
    hsl_bcm_unregister_port_attach ();
  if (port_detach)
    hsl_bcm_unregister_port_detach ();
  if (link_scan)
    hsl_bcm_unregister_link_scan ();
  if (p_hsl_bcm_if_event_queue)
    {
      if (p_hsl_bcm_if_event_queue->ifhdlr_thread) {
//	        sal_thread_destroy (p_hsl_bcm_if_event_queue->ifhdlr_thread);
            ;
      }

      if (p_hsl_bcm_if_event_queue->ifhdlr_sem) {
//            sal_sem_destroy (p_hsl_bcm_if_event_queue->ifhdlr_sem);
            ;
      }

	  if (p_hsl_bcm_if_event_queue->ifhdlr_op_sem) {
//            sal_sem_destroy (p_hsl_bcm_if_event_queue->ifhdlr_op_sem);
            ;
      }

      
      oss_free (p_hsl_bcm_if_event_queue, OSS_MEM_HEAP);
      p_hsl_bcm_if_event_queue = NULL;
    }

  HSL_FN_EXIT (ret);
}

/* Deinitialize the interface handler. */
int
hsl_ctc_ifhdlr_deinit (void)
{
  HSL_FN_ENTER ();

  /* Unregister port attachment handler. */
  hsl_bcm_unregister_port_attach ();

  /* Unregister port detachment handler. */
  hsl_bcm_unregister_port_detach ();

  /* Unregister link scan handler. */
  hsl_bcm_unregister_link_scan ();

  if (p_hsl_bcm_if_event_queue)
    {
        if (p_hsl_bcm_if_event_queue->ifhdlr_thread) {
//            sal_thread_destroy (p_hsl_bcm_if_event_queue->ifhdlr_thread);
            ;
        }

        if (p_hsl_bcm_if_event_queue->ifhdlr_sem) {
//            sal_sem_destroy (p_hsl_bcm_if_event_queue->ifhdlr_sem);
            ;
        }

        if (p_hsl_bcm_if_event_queue->ifhdlr_op_sem) {
//            sal_sem_destroy (p_hsl_bcm_if_event_queue->ifhdlr_op_sem);
            ;
        }
      
      oss_free (p_hsl_bcm_if_event_queue, OSS_MEM_HEAP);
      p_hsl_bcm_if_event_queue = NULL;
    }

  HSL_FN_EXIT (0);
}
