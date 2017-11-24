/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _NETL_COMM_H_
#define _NETL_COMM_H_

/* 
   NETL transport socket structure. 
*/
struct netlsock {
    int sock;
    int seq;
    struct netl_sockaddr_nl snl;
    char *name;
    void *t_read;
    int initialized;
    void *arg_zg;
    void *arg_user;
};

enum netl_match_cmp {
    NETL_NL_CMP_NOT_MATCH = 0,
    NETL_NL_CMP_IS_MATCH = 1
};

/*
   Function prototypes.
*/
int netl_socket(struct netlsock *nl, unsigned long groups,
               unsigned char non_block);
int netl_sock_set_nonblocking(int sock, int nonblock);

int netl_close(struct netlsock *nl);
int netl_talk(struct netlsock *nl, struct netl_nlmsghdr *n,
             int (*filter) (struct netl_nlmsghdr *, void *), void *data);
enum netl_match_cmp netl_match_always(const struct netl_nlmsghdr *msgh,
                                    void *mtdata);
int netl_read_parser_invokecb(struct netlsock *nl,
                             enum netl_match_cmp (*match) (const struct netl_nlmsghdr * msgh,
                                                          void *mtdata),
                             void *mtdata,
                             int (*cb) (struct netl_nlmsghdr *, void *),
                             void *cbdata);
int netl_msg_generic_request(struct netlsock *nl, int msg,
                            int (*cb) (struct netl_nlmsghdr *, void *),
                            void *data);


#endif                          /* _NETL_COMM_H */
