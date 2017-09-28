
/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_OS_H_
#define _HSL_OS_H_

//#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <net/ip_fib.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/igmp.h>
#include <linux/mroute.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <linux/ctype.h>


/* Deal with CONFIG_MODVERSIONS */
#if defined (CONFIG_MODVERSIONS)
#define MODVERSIONS
/* #include <linux/modversions.h> */
#endif

#ifdef CONFIG_KERNEL_ASSERTS
/* kgdb stuff */
#define HSL_ASSERT(p) KERNEL_ASSERT(#p, p)
#else
#define HSL_ASSERT(p) do {  \
        if (!(p)) {     \
                printk(KERN_CRIT "BUG at %s:%d assert(%s)\n",   \
                       __FILE__, __LINE__, #p);                 \
                BUG();  \
        }               \
} while (0)
#endif /* CONFIG_KERNEL_ASSERTS */


#endif /* _HSL_OS_H_ */
