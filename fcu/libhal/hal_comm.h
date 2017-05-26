/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_COMM_H_
#define _HAL_COMM_H_


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

/* 
   Asynchronous messages. 
*/
extern struct halsock hallink;

/* 
   Command channel. 
*/
extern struct halsock hallink_cmd;

/* 
   if-arbiter command channel.
*/
extern struct halsock hallink_poll;

/*
   Function prototypes.
*/
int hal_socket(struct halsock *nl, unsigned long groups, unsigned char non_block);
int hal_sock_set_nonblocking(int sock, int nonblock);

int hal_close(struct halsock *s);
int hal_talk(struct halsock *nl, struct hal_nlmsghdr *n,
             int (*filter) (struct hal_nlmsghdr *, void *), void *data);
int hal_read_parser_invokecb(struct halsock *nl,
                         int (*cb) (struct hal_nlmsghdr *, void *),
                         void *data);
int hal_comm_init(void *zg);
int hal_comm_deinit(void *zg);
int
hal_msg_generic_request(struct halsock *phalsock, int msg,
                        int (*cb) (struct hal_nlmsghdr *, void *),
                        void *data);


#endif  /* _HAL_COMM_H */
