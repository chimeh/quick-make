/* Copyright 2003 IP Infusion, Inc. All Rights Reserved.  */

#ifndef _HSL_COMM_H_
#define _HSL_COMM_H_
#define NETL_MSG_PROCESS_RETURN(SOCK,HDR,RET)                                                       \
       do {                                                                                        \
            if ((HDR)->nlmsg_flags & NETL_NLM_F_ACK)                                                \
              {                                                                                    \
                if ((RET) < 0)                                                                     \
                 hsl_sock_post_ack ((SOCK), (HDR), 0, -1);                                         \
                else                                                                               \
                 hsl_sock_post_ack ((sock), (HDR), 0, 0);                                          \
              }                                                                                    \
       } while (0)


/* Structure to hold the NL control per socket. */
struct hsl_sock
{
  u_int32_t groups;       /* Multicast groups. */
  u_int32_t pid;          /* PID. */
  struct sock *sk;        /* Pointer to the sock structure. */
  struct hsl_sock *next;  /* Next pointer. */
};

/* function prototypes. */
int hsl_sock_init (void);
int hsl_sock_deinit (void);
int hsl_sock_process_msg (struct socket *sock, char *buf, int buflen);
int hsl_sock_process_msg (struct socket *sock, char *buf, int buflen);
int hsl_sock_post_buffer (struct socket *sock, char *buf, int size);
int hsl_sock_post_msg (struct socket *sock, int cmd, int flags, int seqno, char *buf, int size);
int hsl_sock_post_ack (struct socket *sock, struct netl_nlmsghdr *hdr, int flags, int error);
int hsl_sock_release (struct socket *sock);

#endif /* _HSL_COMM_H_ */

