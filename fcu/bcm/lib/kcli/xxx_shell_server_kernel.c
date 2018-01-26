#ifndef SDK_IN_USERMODE

#include <linux/init.h>
#include <asm/types.h>
#include <asm/atomic.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/audit.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/inotify.h>
#include <linux/freezer.h>
#include <linux/tty.h>
#include <linux/netlink.h>

#include "sal/core/libc.h"
#include "sal/core/alloc.h"
#include "xxx_types.h"
#include "xxx_sal.h"
#include "xxx_shell.h"
#include "xxx_shell_server.h"
#include "xxx_cli.h"

int
xxx_vti_read_cmd(xxx_vti_t* vty, const char* szbuf, const int buf_len);
static int
xxx_vty_sendto(xxx_vti_t* vti, const char *szPtr, const int szPtr_len);
static int
xxx_vty_send_quit(xxx_vti_t* vti);

static struct sock *xxx_master_cli_netlinkfd = NULL;

#if 0
LIST_HEAD(xxx_master_cli_vty_list);

typedef struct xxx_master_vty_item_s
{
    struct list_head    list;
    xxx_vti_t           *pvty;
}xxx_master_vty_item_t;
#endif
static xxx_vti_t* xxx_vty_lookup_by_pid_errno(unsigned int pid)
{
#if 0
    xxx_master_vty_item_t   *pitem = NULL;
    list_for_each_entry(pitem,&xxx_master_cli_vty_list,list)
    {
        if(pitem->pvty->pid == pid)
        {
            return pitem->pvty;
        }
    }

    pitem = kmalloc(sizeof(xxx_master_vty_item_t),GFP_KERNEL);

    if(pitem)
    {
        pitem->pvty = xxx_vti_create(XXX_SDK_MODE);
        pitem->pvty->pid    = pid;
        pitem->pvty->printf = xxx_vty_sendto;
        xxx_vti_prompt(pitem->pvty);
    }

    return pitem->pvty;
#endif
    if(g_xxx_vti->pid != pid)
    {
        g_xxx_vti->pid    = pid;
        g_xxx_vti->printf = xxx_vty_sendto;
        g_xxx_vti->quit   = xxx_vty_send_quit;
	    g_xxx_vti->node   = XXX_SDK_MODE;
        xxx_vti_prompt(g_xxx_vti);
    }
    return g_xxx_vti;
}

static int xxx_vty_send_quit(xxx_vti_t* vti)
{
    int size;
    struct sk_buff *skb;
    sk_buff_data_t old_tail;
    struct nlmsghdr *nlh;

    int retval;

    size = NLMSG_SPACE(XXX_SDK_NETLINK_MSG_LEN);
    skb =  alloc_skb(size, GFP_KERNEL);

	old_tail = skb->tail;
    nlh = nlmsg_put(skb, 0, 0, XXX_SDK_CMD_QUIT, NLMSG_SPACE(0), 0);
    old_tail = skb->tail;

    nlh->nlmsg_len  = skb->tail - old_tail;

    NETLINK_CB(skb).dst_group = 0;

    retval = netlink_unicast(xxx_master_cli_netlinkfd, skb, vti->pid, MSG_DONTWAIT);

    if(retval < 0)
    {
        printk(KERN_DEBUG "%s:%d netlink_unicast return: %d\n", __FUNCTION__,__LINE__,retval);
    }

    return retval;
}


static int xxx_vty_sendto(xxx_vti_t* vti, const char *szPtr, const int szPtr_len)
{
    int size;
    struct sk_buff *skb;
    sk_buff_data_t old_tail;
    struct nlmsghdr *nlh;

    int retval;

    size = NLMSG_SPACE(XXX_SDK_NETLINK_MSG_LEN);
    skb =  alloc_skb(size, GFP_KERNEL);

	old_tail = skb->tail;
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(szPtr) + 1) - sizeof(struct nlmsghdr), 0);

    old_tail = skb->tail;

    memcpy(NLMSG_DATA(nlh), szPtr, strlen(szPtr) + 1);

    nlh->nlmsg_len  = skb->tail - old_tail;
    nlh->nlmsg_seq  = szPtr_len;


    NETLINK_CB(skb).dst_group = 0;

    retval = netlink_unicast(xxx_master_cli_netlinkfd, skb, vti->pid, MSG_DONTWAIT);

    if(retval < 0)
    {
        printk(KERN_DEBUG "%s:%d netlink_unicast return: %d\n", __FUNCTION__,__LINE__,retval);
    }

    return retval;
}


static void xxx_vty_recvfrom(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;

    if(skb->len >= sizeof(struct nlmsghdr))
    {
        nlh = (struct nlmsghdr *)skb->data;
        if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
            && (skb->len >= nlh->nlmsg_len))
        {

            xxx_vti_read_cmd(xxx_vty_lookup_by_pid_errno(nlh->nlmsg_pid),
                                 (char *)NLMSG_DATA(nlh),
                                 nlh->nlmsg_seq);
        }
    }
    else
    {
        printk("%s:%d receive error\n",__FUNCTION__,__LINE__);
    }
}


int xxx_vty_socket()
{
    //struct netlink_kernel_cfg cfg = {0};
    //cfg.input = xxx_vty_recvfrom;

    xxx_master_cli_netlinkfd = netlink_kernel_create(&init_net, XXX_SDK_NETLINK, 0, xxx_vty_recvfrom, NULL, THIS_MODULE);

    //xxx_master_cli_netlinkfd = __netlink_kernel_create(&init_net, XXX_SDK_NETLINK, THIS_MODULE, NULL);
    if(!xxx_master_cli_netlinkfd){
        printk("%s:%d can't create a netlink socket\n",__FUNCTION__,__LINE__);
        return -1;
    }

    return 0;
}

void xxx_vty_close()
{
    sock_release(xxx_master_cli_netlinkfd->sk_socket);
}
#endif
