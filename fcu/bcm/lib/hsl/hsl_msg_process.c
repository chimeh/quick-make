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

#include "netl_netlink.h"
#include "netlk_comm.h"

int
hsl_process_msg (struct socket *sock, char *buf, int buflen)
{
    struct netl_nlmsghdr *hdr;
    char *msgbuf;
    u_char *pnt; 
    u_int32_t size;
    
    hdr = (struct netl_nlmsghdr *)buf;
    msgbuf = buf + sizeof (struct netl_nlmsghdr);
    pnt = (u_char *)msgbuf;
    size = hdr->nlmsg_len - NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE);
    if (sock->ops) {
        struct module *owner = sock->ops->owner;
        printk("module ref %p\n", owner);
        if(owner) {
            printk("module ref %d\n", module_refcount(owner));
        }
    }
    printk("hsl_process_msg() type %d\n", hdr->nlmsg_type);
    switch (hdr->nlmsg_type) {


    default:
        NETLK_MSG_PROCESS_RETURN_WITH_VALUE (sock, hdr, 0);
        return 0;
    }


    return 0;
}