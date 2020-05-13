/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_COMM_H_
#define _HAL_COMM_H_

extern void *hal_comm_zg;

/* 
   HSL transport socket structure. 
*/
struct halsock {
    int sock;
    int seq;
    struct hal_sockaddr_nl snl;
    char *name;
    void *t_read;
};

enum hal_match_cmp {
    HAL_NL_CMP_NOT_MATCH = 0,
    HAL_NL_CMP_IS_MATCH = 1
};

/*
   Function prototypes.
*/
int hal_socket(struct halsock *nl, unsigned long groups,
               unsigned char non_block);
int hal_sock_set_nonblocking(int sock, int nonblock);

int hal_close(struct halsock *nl);
int hal_talk(struct halsock *nl, struct hal_nlmsghdr *n,
             int (*filter) (struct hal_nlmsghdr *, void *), void *data);
enum hal_match_cmp hal_match_always(const struct hal_nlmsghdr *msgh,
                                    void *mtdata);
int hal_read_parser_invokecb(struct halsock *nl,
                             enum hal_match_cmp (*match) (const struct hal_nlmsghdr * msgh,
                                                          void *mtdata),
                             void *mtdata,
                             int (*cb) (struct hal_nlmsghdr *, void *),
                             void *cbdata);
int hal_msg_generic_request(struct halsock *nl, int msg,
                            int (*cb) (struct hal_nlmsghdr *, void *),
                            void *data);


#endif                          /* _HAL_COMM_H */
