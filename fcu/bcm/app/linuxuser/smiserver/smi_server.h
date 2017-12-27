/* Copyright (C) 2002-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _SMI_SERVER_H
#define _SMI_SERVER_H

//#include "pal.h"
//#include "lib.h"
//#include "nsm_fea.h"
//#include "hal_if.h"
#include "thread.h"
#include "smi_message.h"
#include "message.h"
#include "smi_cs_def.h"
//#include "smi_client.h"


typedef time_t pal_time_t;


/*
    +-------- smi_server --------+
    | Message Handler            |
    | SMI services bit           |
    | SMI message parser         |
    | SMI message callback       |
    +--------------|-------------+
                   |
                   v
    +------- smi_server_client ----+
    |  SMI client ID               |-+
    |  smi_server_entry for ASYNC  | |-+
    |  smi_server_entry for SYNC   | | |
    +------------------------------+ | |
      +------------------------------+ |
        +------------------------------+
*/

/* SMI server structure.  */
struct smi_server
{
  struct thread_master *zg;

  struct message_handler *ms;

  /* SMI service structure.  */
  struct smi_msg_service service;

  /* Parser functions.  */
  SMI_PARSER parser[SMI_MSG_MAX];

  /* Call back functions.  */
  SMI_CALLBACK callback[SMI_MSG_MAX];

  /* Debug flag.  */
  int debug;

  void *info;
};

/* Send/Recv data structure for server entry. */
struct smi_server_entry_buf
{
  u_char buf[SMI_MESSAGE_MAX_LEN];
  u_int16_t len;

  u_char *pnt;
  u_int16_t size;
};

/* SMI server entry for client connection.  */

struct smi_server_entry
{
  /* Pointer to message entry.  */
  struct message_entry *me;

  /* Pointer to SMI server structure.  */
  struct smi_server *as;

  /* Pointer to SMI server client.  */
  struct smi_server_client *asc;

  /* SMI service structure.  */
  struct smi_msg_service service;

  /* Send/Recv buffers. */
  struct smi_server_entry_buf send;
  struct smi_server_entry_buf recv;

  /* Send and recieved message count.  */
  u_int32_t send_msg_count;
  u_int32_t recv_msg_count;
  u_char *pnt_ipv4;
  u_int16_t len_ipv4;
  struct thread *t_ipv4;

#ifdef HAVE_IPV6
  /* Message buffer for IPv6 redistribute.  */
  u_char buf_ipv6[SMI_CS_MESSAGE_MAX_LEN];
  u_char *pnt_ipv6;
  u_int16_t len_ipv6;
  struct thread *t_ipv6;
#endif

  /* Connect time.  */
  pal_time_t connect_time;

  /* Last read time.  */
  pal_time_t read_time;

  /* Message queue.  */
  struct fifo send_queue;
  struct thread *t_write;

  /* Message id */
  u_int32_t message_id;

  /* For record.  */
  u_int16_t last_read_type;
  u_int16_t last_write_type;
};

/* SMI server client.  */
struct smi_server_client
{
  /* SMI client ID. */
  u_int32_t client_id;

};

void smi_server_set_callback (struct smi_server *as, int message_type,
                         SMI_PARSER parser, SMI_CALLBACK callback);
int smi_server_send_message (struct smi_server_entry *, u_int32_t, u_int32_t,
                             int, u_int32_t, u_int16_t);
int smi_server_send_message_msgid (struct smi_server_entry *, u_int32_t, 
    u_int32_t, int, u_int32_t *, u_int16_t);
int smi_server_unset_service (struct smi_server *, int);
int smiserver_set_service (struct smi_server *, int);
//int smi_server_send_interface_add (struct smi_server_entry *,
//                                   struct interface *);
//int smi_server_send_interface_state (struct smi_server_entry *,
//                                     struct interface *, int, cindex_t);
//int smi_server_send_interface_address (struct smi_server_entry *,
//                                       struct connected *, int);
int smi_service_check (struct smi_server_entry *, int);

int smi_server_read_header (struct message_handler *, struct message_entry *,
                            int);
int smi_server_read_msg (struct message_handler *, struct message_entry *,
                         int);
void smi_server_set_version (struct smi_server *, u_int16_t);
void smi_server_set_protocol (struct smi_server *, u_int32_t);

//struct smi_server_entry * smi_server_lookup_by_proto_id (u_int32_t);

//struct smi_server * smi_server_init (struct lib_globals *);
int smi_server_finish (struct smi_server *);

//void smi_server_if_add (struct interface *);
//void smi_server_if_delete (struct interface *);
//void smi_server_if_update (struct interface *, cindex_t);
//void smi_server_if_bind_all (struct interface *);
void smi_server_entry_free (struct smi_server_entry *ase);
int smi_server_set_service (struct smi_server *as, int service);
int smi_server_connect (struct message_handler *ms, struct message_entry *me,
                    int sock);
int smi_server_disconnect (struct message_handler *ms, struct message_entry *me,
                       int sock);
//struct smi_server * smi_nsm_server_init (struct lib_globals *zg);
//int smi_server_send_alarm_msg (struct smi_server_entry *ase,
//                               struct smi_msg_alarm *alarm_msg,
//                               int msg_type);
#endif /* _SMI_SERVER_H */
