#ifndef _NETL_NETLINK_H
#define _NETL_NETLINK_H



/* RFC3549. Linux Netlink as a IP services Protocol. */

/*
  Address family for NETL backend.
*/
#define AF_NETL          31

/* 
   These are the groups of messages(async) that NETL provides.
*/
#define NETL_GROUP_LINK  (1 << 0)



/* Netlink message header. */
struct netl_nlmsghdr {
    /* u_int32_t */ unsigned int nlmsg_len;
    /* Length of message including header. */
    /* u_int16_t */ unsigned short nlmsg_type;
    /* Message content. */
    /* u_int16_t */ unsigned short nlmsg_flags;
    /* Flags. */
    /* u_int32_t */ unsigned int nlmsg_seq;
    /* Sequence number. */
    /* u_int32_t */ unsigned int nlmsg_pid;
    /* Sending process pid. */
};


#define NETL_NLMSGHDR_SIZE            sizeof(struct netl_nlmsghdr)

/* Netlink error response structure. */
struct netl_nlmsgerr {
    int error;
    struct netl_nlmsghdr msg;    /* Request nlmsghdr. */
};

/* Sockaddr for Netlink. */
struct netl_sockaddr_nl {
    /* u_int16_t */ unsigned short nl_family;
    /* u_int16_t */ unsigned short pad1;
    /* u_int32_t */ unsigned int nl_pid;
    /* u_int32_t */ unsigned int nl_groups;
    /* u_char   */  unsigned char padding[14];
};

/* Flags. */
#define NETL_NLM_F_REQUEST          1    /* Request message. */
#define NETL_NLM_F_MULTI            2    /* Multipart message terminated by
                                           NLMSG_DONE. */
#define NETL_NLM_F_ACK              3    /* Reply with ACK. */

/* Additional flag bits for GET requests. */
#define NETL_NLM_F_ROOT             0x100        /* Return complete table. */
#define NETL_NLM_F_MATCH            0x200        /* Return all entries matching criteria in message content. */
#define NETL_NLM_F_ATOMIC           0x400        /* Atomic snapshot of the table being referenced. */

/* Additional flag bits for NEW requests. */
#define NETL_NLM_F_REPLACE          0x100        /* Replace existing matching config object. */
#define NETL_NLM_F_EXCL             0x200        /* Don't replace the config object if it already exists. */
#define NETL_NLM_F_CREATE           0x400        /* Create config object if it doesn't exist. */
#define NETL_NLM_F_APPEND           0x800        /* Add to end of list. */

/* Convenience macros. */
#define NETL_NLMSG_ALIGNTO          4
#define NETL_NLMSG_ALIGN(len)       (((len) + NETL_NLMSG_ALIGNTO - 1) & ~(NETL_NLMSG_ALIGNTO - 1))
#define NETL_NLMSG_LENGTH(len)      (NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE) + len)
#define NETL_NLMSG_SPACE(len)       NETL_NLMSG_ALIGN(NETL_NLMSG_LENGTH(len))
#define NETL_NLMSG_DATA(nlh)        ((void*)(((char*)nlh) + NETL_NLMSG_LENGTH(0)))
#define NETL_NLMSG_NEXT(nlh,len)    ((len) -= NETL_NLMSG_ALIGN((nlh)->nlmsg_len), (struct netl_nlmsghdr*)(((char*)(nlh)) + NETL_NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NETL_NLMSG_OK(nlh,len) ((len) > 0 && (nlh)->nlmsg_len >= NETL_NLMSGHDR_SIZE && (nlh)->nlmsg_len <= (len))
#define NETL_NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NETL_NLMSG_SPACE((len)))

/* Message type. */
#define NETL_NLMSG_NOOP             0x1  /* Message is ignored. */
#define NETL_NLMSG_ERROR            0x2  /* Error. */
#define NETL_NLMSG_DONE             0x4  /* Message terminates a multipart msg. */

#endif                          /* _NETL_NETLINK_H */
