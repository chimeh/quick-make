/* Copyright (C) 2002-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _SMI_CLIENT_H
#define _SMI_CLIENT_H

#include "zebra.h"
#include "smi_message.h"
#include "smi_client_macros.h"
#include "linklist.h"
#include "pthread.h"
#include "smi_cs_def.h"


#define TEST_AC

#define SMI_AC_NSM_INITERR      0x00000001
#define SMI_AC_LACP_INITERR     0x00000002
#define SMI_AC_MSTP_INITERR     0x00000004
#define SMI_AC_RMON_INITERR     0x00000008
#define SMI_AC_ONM_INITERR      0x00000010

#define SMI_WAYSIDE_PORT "fe7"

#define SMI_AC_NODEBUG  0
#define SMI_AC_DEBUG    1

#define SMI_AC_ALL   SMI_AC_MAX

struct message_entry;

/* Structure to hold pending message. */
struct smi_client_pend_msg
{
  /* NSM Msg Header. */
  struct smi_msg_header header;

  /* Message. */
  u_char buf[SMI_MESSAGE_MAX_LEN];
};

/* SMI client to server connection structure. */
struct smi_client_handler
{
  /* Parent. */
  struct smi_client *ac;

  /* Up or down.  */
  int up;

  /* Type of client, sync or async.  */
  int type;

  /* Message client structure. */
  struct message_handler *mc;

  /* Service bits specific for this connection.  */
  struct smi_msg_service service;

  /* Message buffer for output. */
  u_char buf[SMI_MESSAGE_MAX_LEN];
  u_int16_t len;
  u_char *pnt;
  u_int16_t size;

  /* Message buffer for input. */
  u_char buf_in[SMI_MESSAGE_MAX_LEN];
  u_int16_t len_in;
  u_char *pnt_in;
  u_int16_t size_in;

  /* Message buffer for IPv4 route updates.  */
  u_char buf_ipv4[SMI_CS_MESSAGE_MAX_LEN];
  u_char *pnt_ipv4;
  u_int16_t len_ipv4;
  struct thread *t_ipv4;
  u_int32_t vr_id_ipv4;
  u_int32_t vrf_id_ipv4;

  /* Client message ID.  */
  u_int32_t message_id;

  /* Message ID for ILM/FTN entries. */
  u_int32_t mpls_msg_id;

  /* List of pending messages of struct smi_client_pend_msg. */
  struct list pend_msg_list;

  /* Send and recieved message count.  */
  u_int32_t send_msg_count;
  u_int32_t recv_msg_count;
};

/* SMI client structure.  */
struct smi_client
{
  struct thread_master *zg;
  
  /* Service bits. */
  struct smi_msg_service service;

  /* SMI client ID. */
  u_int32_t client_id;

  /* Parser functions. */
  SMI_PARSER parser[SMI_MSG_MAX];

  /* Callback functions. */
  SMI_CALLBACK callback[SMI_MSG_MAX];

  /* Async connection. */
  struct smi_client_handler *async;

  /* Disconnect callback. */
  SMI_DISCONNECT_CALLBACK disconnect_callback;

  /* Reconnect thread. */
  struct thread *t_connect;
  
  /* Reconnect thread. */
  struct thread *t_keepalive;

  /* Reconnect thread. */
  struct thread *pend_read_thread;


  /* Reconnect interval in seconds. */
  int keepalive_interval;

  /* Reconnect interval in seconds. */
  int reconnect_interval;

  /* Debug message flag. */
  int debug;

};

struct smiclient_globals {
  u_int32_t cindex;
  struct thread_master *smi_zg;
  struct smi_client *ac[SMI_AC_MAX-1];
  int debug;
};

struct smiclient_globals *azg;
#define SMI_ZG          (azg->smi_zg)

#define SMI_AC_NSM      (azg->ac[SMI_AC_NSM_MODULE])
#define SMI_AC_LACP     (azg->ac[SMI_AC_LACP_MODULE])
#define SMI_AC_MSTP     (azg->ac[SMI_AC_MSTP_MODULE])
#define SMI_AC_RMON     (azg->ac[SMI_AC_RMON_MODULE])
#define SMI_AC_ONM      (azg->ac[SMI_AC_ONM_MODULE])

/* Function Prototypes */

int smi_client_create (struct smiclient_globals *, int);
int smi_client_delete (struct smi_client *);
void smi_client_stop (struct smi_client *);
int smi_client_set_service (struct smi_client *, int, int);
void smi_client_set_version (struct smi_client *, u_int16_t);
void smi_client_set_protocol (struct smi_client *, u_int32_t);
void smi_client_set_callback (struct smi_client *, int, SMI_CALLBACK);
void smi_client_set_disconnect_callback (struct smi_client *,
                                         SMI_DISCONNECT_CALLBACK);
int smi_client_read_sync_status_msg(struct smi_client_handler *ach);
int smi_client_send_message (struct smi_client_handler *, u_int32_t, u_int32_t,
                             int, u_int16_t, u_int32_t *);
void smi_client_pending_message (struct smi_client_handler *,
                                 struct smi_msg_header *);
int smi_client_reconnect (struct thread *);
int smi_client_reconnect_start (struct smi_client *);
int smi_client_reconnect_async (struct thread *);
int smi_client_start (struct smi_client *);
int smi_client_read_sync_msg(struct smi_client_handler *ach, int msgtype, void *getmsg);
int smi_client_recv_status (struct smi_msg_header *header, void *arg, void *message);
int smi_client_recv_mtu (struct smi_msg_header *header, void *arg, void *message);
int smi_client_process_pending_msg (struct thread *);

int smi_parse_alarm_message (unsigned char **pnt, u_int16_t *size,
                             struct smi_msg_header *header, void *arg,
                             SMI_CALLBACK callback);
int smi_process_alarm_message (struct smi_msg_header *, void *, void *);
#endif /*  _SMI_CLIENT_H */
