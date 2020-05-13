#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "netl_netlink.h"
#include "netl_comm.h"
#include "npas_nlmsg.h"
#include "npas_tbl_link.h"

typedef struct npas_nlmsg_req_s
{ 
    struct netl_nlmsghdr nlh;
    char data[0];
} npas_nlmsg_req_t;

int npas_nlmsg_sendto_kernel (struct netlsock *ns, void *data, unsigned int datalen, unsigned int msg_type)
{
    int ret;
    unsigned char txbuf[NPAS_NLMSG_DATA_LEN+sizeof(struct netl_nlmsghdr)];
    npas_nlmsg_req_t *req = (npas_nlmsg_req_t *)txbuf;
    
    memset (&req->nlh, 0, sizeof (struct netl_nlmsghdr));
    memset (req->data, 0, datalen);
    
    /* Set message. */
    memcpy(req->data, data, datalen);
    
    /* Set header. */
    req->nlh.nlmsg_len = NETL_NLMSG_LENGTH (datalen);
    req->nlh.nlmsg_flags = NETL_NLM_F_CREATE | NETL_NLM_F_REQUEST | NETL_NLM_F_ACK;
    req->nlh.nlmsg_type = msg_type; 
    req->nlh.nlmsg_seq = ++ns->seq;
    
    /* Send message and process acknowledgement. */
    ret = netl_talk (ns, &req->nlh, NULL, NULL);
    if (ret < 0)
      return ret;
    return 0;
}



