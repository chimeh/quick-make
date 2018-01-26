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
#include "ctc_types.h"
#include "ctc_sal.h"
#include "ctc_shell.h"
#include "ctc_shell_server.h"
#include "ctc_cli.h"

int
ctc_vti_read_cmd(ctc_vti_t* vty, const char* szbuf, const int buf_len);
static int
ctc_vty_sendto(ctc_vti_t* vti, const char *szPtr, const int szPtr_len);
static int
ctc_vty_send_quit(ctc_vti_t* vti);

static struct sock *ctc_master_cli_netlinkfd = NULL;

#if 0
LIST_HEAD(ctc_master_cli_vty_list);

typedef struct ctc_master_vty_item_s
{
    struct list_head    list;
    ctc_vti_t           *pvty;
}ctc_master_vty_item_t;
#endif
static ctc_vti_t* ctc_vty_lookup_by_pid_errno(unsigned int pid)
{
#if 0
    ctc_master_vty_item_t   *pitem = NULL;
    list_for_each_entry(pitem,&ctc_master_cli_vty_list,list)
    {
        if(pitem->pvty->pid == pid)
        {
            return pitem->pvty;
        }
    }

    pitem = kmalloc(sizeof(ctc_master_vty_item_t),GFP_KERNEL);

    if(pitem)
    {
        pitem->pvty = ctc_vti_create(CTC_SDK_MODE);
        pitem->pvty->pid    = pid;
        pitem->pvty->printf = ctc_vty_sendto;
        ctc_vti_prompt(pitem->pvty);
    }

    return pitem->pvty;
#endif
    if(g_ctc_vti->pid != pid)
    {
        g_ctc_vti->pid    = pid;
        g_ctc_vti->printf = ctc_vty_sendto;
        g_ctc_vti->quit   = ctc_vty_send_quit;
	    g_ctc_vti->node   = CTC_SDK_MODE;
        ctc_vti_prompt(g_ctc_vti);
    }
    return g_ctc_vti;
}

static int ctc_vty_send_quit(ctc_vti_t* vti)
{
    int size;
    struct sk_buff *skb;
    sk_buff_data_t old_tail;
    struct nlmsghdr *nlh;

    int retval;

    size = NLMSG_SPACE(CTC_SDK_NETLINK_MSG_LEN);
    skb =  alloc_skb(size, GFP_KERNEL);

	old_tail = skb->tail;
    nlh = nlmsg_put(skb, 0, 0, CTC_SDK_CMD_QUIT, NLMSG_SPACE(0), 0);
    old_tail = skb->tail;

    nlh->nlmsg_len  = skb->tail - old_tail;

    NETLINK_CB(skb).dst_group = 0;

    retval = netlink_unicast(ctc_master_cli_netlinkfd, skb, vti->pid, MSG_DONTWAIT);

    if(retval < 0)
    {
        printk(KERN_DEBUG "%s:%d netlink_unicast return: %d\n", __FUNCTION__,__LINE__,retval);
    }

    return retval;
}


static int ctc_vty_sendto(ctc_vti_t* vti, const char *szPtr, const int szPtr_len)
{
    int size;
    struct sk_buff *skb;
    sk_buff_data_t old_tail;
    struct nlmsghdr *nlh;

    int retval;

    size = NLMSG_SPACE(CTC_SDK_NETLINK_MSG_LEN);
    skb =  alloc_skb(size, GFP_KERNEL);

	old_tail = skb->tail;
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(szPtr) + 1) - sizeof(struct nlmsghdr), 0);

    old_tail = skb->tail;

    memcpy(NLMSG_DATA(nlh), szPtr, strlen(szPtr) + 1);

    nlh->nlmsg_len  = skb->tail - old_tail;
    nlh->nlmsg_seq  = szPtr_len;


    NETLINK_CB(skb).dst_group = 0;

    retval = netlink_unicast(ctc_master_cli_netlinkfd, skb, vti->pid, MSG_DONTWAIT);

    if(retval < 0)
    {
        printk(KERN_DEBUG "%s:%d netlink_unicast return: %d\n", __FUNCTION__,__LINE__,retval);
    }

    return retval;
}


static void ctc_vty_recvfrom(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;

    if(skb->len >= sizeof(struct nlmsghdr))
    {
        nlh = (struct nlmsghdr *)skb->data;
        if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
            && (skb->len >= nlh->nlmsg_len))
        {

            ctc_vti_read_cmd(ctc_vty_lookup_by_pid_errno(nlh->nlmsg_pid),
                                 (char *)NLMSG_DATA(nlh),
                                 nlh->nlmsg_seq);
        }
    }
    else
    {
        printk("%s:%d receive error\n",__FUNCTION__,__LINE__);
    }
}


int ctc_vty_socket()
{
    //struct netlink_kernel_cfg cfg = {0};
    //cfg.input = ctc_vty_recvfrom;

    ctc_master_cli_netlinkfd = netlink_kernel_create(&init_net, CTC_SDK_NETLINK, 0, ctc_vty_recvfrom, NULL, THIS_MODULE);

    //ctc_master_cli_netlinkfd = __netlink_kernel_create(&init_net, CTC_SDK_NETLINK, THIS_MODULE, NULL);
    if(!ctc_master_cli_netlinkfd){
        printk("%s:%d can't create a netlink socket\n",__FUNCTION__,__LINE__);
        return -1;
    }

    return 0;
}

void ctc_vty_close()
{
    sock_release(ctc_master_cli_netlinkfd->sk_socket);
}
#endif
