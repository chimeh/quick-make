/* Copyright (C) 2002-2011 IP Infusion, Inc. All Rights Reserved. */

/* SMI server implementation.  */
#include <sys/un.h>
#include "zebra.h"
#include "thread.h"
#include "vector.h"
#include "memory.h"
#include "tlv.h"

//#include "smi_message.h"
#include "smi_server.h"


#undef pal_time_sys_current
#define pal_time_sys_current(z) time(z)
#undef int
#define int int
#undef pal_ntoh32
#undef pal_hton32
#undef pal_ntoh16
#undef pal_hton16
#define pal_ntoh32 ntohl
#define pal_hton32 htonl
#define pal_ntoh16 ntohs
#define pal_hton16 htons
/* Set service type flag.  */
int
smi_server_set_service (struct smi_server *ns, int service)
{
  if (service >= SMI_SERVICE_MAX)
    return SMI_ERR_INVALID_SERVICE;

  SET_FLAG (ns->service.bits, (1 << service));

  return 0;
}

/* Unset service type flag.  */
int
smi_server_unset_service (struct smi_server *ns, int service)
{
  if (service >= SMI_SERVICE_MAX)
    return SMI_ERR_INVALID_SERVICE;

  UNSET_FLAG (ns->service.bits, (1 << service));

  return 0;
}

/* Check service type flag.  */
int
smi_service_check (struct smi_server_entry *nse, int service)
{
  if (service >= SMI_SERVICE_MAX)
    return 0;

  return CHECK_FLAG (nse->service.bits, (1 << service));
}

/* Set parser function and call back function. */
void
smi_server_set_callback (struct smi_server *ns, int message_type,
                         SMI_PARSER parser, SMI_CALLBACK callback)
{
  if (message_type >= SMI_MSG_MAX)
    return;

  ns->parser[message_type] = parser;
  ns->callback[message_type] = callback;
}

/* Client connect to SMI server.  */
int
smi_server_connect (struct message_handler *ms, struct message_entry *me,
                    int sock)
{
  struct smi_server_entry *ase;

  ase = XCALLOC (MTYPE_SMISERVER_ENTRY, sizeof (struct smi_server_entry));
  ase->send.len = SMI_MESSAGE_MAX_LEN;
  ase->recv.len = SMI_MESSAGE_MAX_LEN;
  ase->len_ipv4 = SMI_MESSAGE_MAX_LEN;
#ifdef HAVE_IPV6
  ase->len_ipv6 = SMI_MESSAGE_MAX_LEN;
#endif /* HAVE_IPV6 */

  me->info = ase;
  ase->me = me;
  ase->as = ms->info;
  ase->as->info = ase;
  ase->connect_time = pal_time_sys_current (NULL);
  FIFO_INIT (&ase->send_queue);

  return 0;
}

int
smi_server_disconnect (struct message_handler *ms, struct message_entry *me,
                       int sock)
{
  struct smi_server *as;
  struct smi_server_entry *ase;
  struct smi_server_client *asc;

  ase = me->info;
  as = ase->as;

  asc = ase->asc;

  if (asc == NULL)
    {
      return 0;
    }

  XFREE (MTYPE_SMISERVER_CLIENT, asc);

  /* Free SMI server entry.  */
  me->info = NULL;

  return 0;
}

/* De-queue SMI message.  */
int
smi_server_dequeue (struct thread *t)
{
  struct smi_server_entry *ase;
  struct smi_message_queue *queue;
  int sock;
  int nbytes;

  ase = THREAD_ARG (t);
  sock = THREAD_FD (t);
  ase->t_write = NULL;

  queue = (struct smi_message_queue *) FIFO_HEAD (&ase->send_queue);
  if (queue)
    {
      nbytes = write (sock, queue->buf + queue->written,
                               queue->length - queue->written);
      if (nbytes <= 0)
        {
          if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            {
              zlog_err (ase->as->zg, "SMI message send error socket %d %s",
                        ase->me->sock, strerror(errno));
              return -1;
            }
        }
      else if (nbytes != (queue->length - queue->written))
        {
          queue->written += nbytes;
        }
      else
        {
          FIFO_DEL (queue);
          XFREE (MTYPE_SMI_MSG_QUEUE_BUF, queue->buf);
          XFREE (MTYPE_SMI_MSG_QUEUE, queue);
        }
    }

  if (FIFO_TOP (&ase->send_queue))
    THREAD_WRITE_ON (ase->as->zg, ase->t_write, smi_server_dequeue, ase,
                     ase->me->sock);

  return 0;
}

/* Could not write the message to the socket, enqueue the message.  */
void
smi_server_enqueue (struct smi_server_entry *ase, u_char *buf,
                    u_int16_t length, u_int16_t written)
{
  struct smi_message_queue *queue;

  queue = XCALLOC (MTYPE_SMI_MSG_QUEUE, sizeof (struct smi_message_queue));
  queue->buf = XMALLOC (MTYPE_SMI_MSG_QUEUE_BUF, length);
  memcpy (queue->buf, buf, length);
  queue->length = length;
  queue->written = written;

  FIFO_ADD (&ase->send_queue, queue);

  THREAD_WRITE_ON (ase->as->zg, ase->t_write, smi_server_dequeue, ase,
                   ase->me->sock);
}
/* SMI message header encode.  */
int
smi_encode_header (u_char **pnt, u_int16_t *size,
                   struct smi_msg_header *header)
{
  u_char *sp = *pnt;

  if (*size < SMI_MSG_HEADER_SIZE)
    return SMI_ERR_PKT_TOO_SMALL;

  TLV_ENCODE_PUTW (header->type);
  TLV_ENCODE_PUTW (header->length);
  TLV_ENCODE_PUTL (header->message_id);

  return *pnt - sp;
}

/* SMI message header decode.  */
int
smi_decode_header (u_char **pnt, u_int16_t *size,
                   struct smi_msg_header *header)
{
  if (*size < SMI_MSG_HEADER_SIZE)
    return SMI_ERR_PKT_TOO_SMALL;

  TLV_DECODE_GETW (header->type);
  TLV_DECODE_GETW (header->length);
  TLV_DECODE_GETL (header->message_id);

  return SMI_MSG_HEADER_SIZE;
}
/* Send message to the client.  */
int
smi_server_send_message (struct smi_server_entry *ase,
                         u_int32_t vr_id, u_int32_t vrf_id,
                         int type, u_int32_t msg_id, u_int16_t len)
{
  struct smi_msg_header header;
  u_int16_t total_len;
  int nbytes;

  ase->send.pnt = ase->send.buf;
  ase->send.size = ase->send.len;

  /* Prepare SMI message header.  */
  header.type = type;
  header.length = len + SMI_MSG_HEADER_SIZE;
  header.message_id = msg_id;
  total_len = len + SMI_MSG_HEADER_SIZE;

  smi_encode_header (&ase->send.pnt, &ase->send.size, &header);

  if (FIFO_TOP (&ase->send_queue))
    {
      smi_server_enqueue (ase, ase->send.buf, total_len, 0);
      return 0;
    }

  /* Send message.  */
  nbytes = write (ase->me->sock, ase->send.buf, total_len);
  if (nbytes <= 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        smi_server_enqueue (ase, ase->send.buf, total_len, 0);
      else
        {
          zlog_err (ase->as->zg, "SMI message send error socket %d %s",
                    ase->me->sock, strerror(errno));
          return -1;
        }
    }
  else if (nbytes != total_len)
    smi_server_enqueue (ase, ase->send.buf, total_len, nbytes);
  else
    {
      ase->last_write_type = type;
      ase->send_msg_count++;
    }

  return 0;
}

/* SMI service encode.  */
int
smi_encode_service (u_char **pnt, u_int16_t *size, struct smi_msg_service *msg)
{
  u_char *sp = *pnt;

  if (*size < SMI_MSG_SERVICE_SIZE)
    return SMI_ERR_PKT_TOO_SMALL;

  TLV_ENCODE_PUTW (msg->version);
  TLV_ENCODE_PUTW (0);
  TLV_ENCODE_PUTL (msg->protocol_id);
  TLV_ENCODE_PUTL (msg->client_id);
  TLV_ENCODE_PUTL (msg->bits);

  return *pnt - sp;
}
/* SMI service decode.  */
int
smi_decode_service (u_char **pnt, u_int16_t *size, struct smi_msg_service *msg)
{
  u_char *sp = *pnt;
  struct smi_tlv_header tlv;

  if (*size < SMI_MSG_SERVICE_SIZE)
    return SMI_ERR_PKT_TOO_SMALL;

  TLV_DECODE_GETW (msg->version);
  TLV_DECODE_GETW (msg->reserved);
  TLV_DECODE_GETL (msg->protocol_id);
  TLV_DECODE_GETL (msg->client_id);
  TLV_DECODE_GETL (msg->bits);

  /* Optional TLV parser.  */
  while (*size)
    {
      if (*size < SMI_TLV_HEADER_SIZE)
        return SMI_ERR_PKT_TOO_SMALL;

      SMI_DECODE_TLV_HEADER (tlv);

      switch (tlv.type)
        {
        default:
          TLV_DECODE_SKIP (tlv.length);
          break;
        }
    }
  return *pnt - sp;
}
/* Send service message to SMI client.  */
int
smi_server_send_service (struct smi_server_entry *ase, u_int32_t msg_id,
                         struct smi_msg_service *service)
{
  int len;
  u_int32_t vr_id = 0;
  u_int32_t vrf_id = 0;

  /* Set encode pointer and size.  */
  ase->send.pnt = ase->send.buf + SMI_MSG_HEADER_SIZE;
  ase->send.size = ase->send.len - SMI_MSG_HEADER_SIZE;

  /* Encode SMI service.  */
  len = smi_encode_service (&ase->send.pnt, &ase->send.size, service);
  if (len < 0)
    return len;

  /* Send it to client.  */
  smi_server_send_message (ase, vr_id, vrf_id,
                           SMI_MSG_SERVICE_REPLY, msg_id, len);

  return 0;
}

/* Receive service request.  */
int
smi_server_recv_service (struct smi_msg_header *header,
                         void *arg, void *message)
{
  struct smi_server_entry *ase = arg;
  struct smi_server *as = ase->as;
  struct smi_msg_service *service = message;

  /* Dump received messsage. */
  ase->service = *service;

  /* Send back server side service bits to client.  SMI server just
     send all of service bits which server can provide to the client.
     It is up to client side to determine the service is enough or not.  */
  as->service.cindex = 0;
  as->service.client_id = ase->service.client_id;

  return 0;
}

/* Delete the message server and Free the memory */
int 
smi_server_finish (struct smi_server *as)
{
  message_server_delete (as->ms);

  XFREE (MTYPE_SMISERVER, as);

  return 0;
}

/* Set protocol ID.  */
void
smi_server_set_protocol (struct smi_server *as, u_int32_t protocol_id)
{
  as->service.protocol_id = protocol_id;
}

/* Set protocol version.  */
void
smi_server_set_version (struct smi_server *as, u_int16_t version)
{
  as->service.version = version;
}

/* Read SMI message header.  */
int
smi_server_read_header (struct message_handler *ms, struct message_entry *me, int sock)
{
  int nbytes;
  struct smi_server_entry *ase;

  /* Get SMI server entry from message entry.  */
  ase = me->info;

  /* Reset parser pointer and size. */
  ase->recv.pnt = ase->recv.buf;
  ase->recv.size = 0;

  /* Read SMI message header.  */
  nbytes = readn (sock, ase->recv.buf, SMI_MSG_HEADER_SIZE);

  /* Let message handler to handle disconnect event.  */
  if (nbytes <= 0)
    return nbytes;

  /* Check header length.  If length is smaller than SMI message
     header size close the connection.  */
  if (nbytes != SMI_MSG_HEADER_SIZE)
    return -1;

  /* Record read size.  */
  ase->recv.size = nbytes;

  return nbytes;
}

/* Call back function to read SMI message body.  */
int
smi_server_read_msg (struct message_handler *ms, struct message_entry *me, int sock)
{
  int ret;
  int type;
  int nbytes;
  struct smi_server *as;
  struct smi_server_entry *ase;
  struct smi_msg_header header;

  /* Get SMI server entry from message entry.  */
  ase = me->info;
  as = ase->as;

  /* Reset parser pointer and size. */
  ase->recv.pnt = ase->recv.buf;
  ase->recv.size = 0;

  /* Read SMI message header.  */
  nbytes = readn (sock, ase->recv.buf, SMI_MSG_HEADER_SIZE);

  /* Let message handler to handle disconnect event.  */
  if (nbytes <= 0){
    return -1;
  }

  /* Check header length.  If length is smaller than SMI message
     header size close the connection.  */
  if (nbytes != SMI_MSG_HEADER_SIZE)
   return -1;

  /* Record read size.  */
  ase->recv.size = nbytes;

  /* Parse SMI message header.  */
  ret = smi_decode_header (&ase->recv.pnt, &ase->recv.size, &header);
  if (ret < 0) {
    return -1;
  }

  /* Reset parser pointer and size. */
  ase->recv.pnt = ase->recv.buf;
  ase->recv.size = 0;

  /* Read SMI message body.  */
  nbytes = readn (sock, ase->recv.pnt, header.length - SMI_MSG_HEADER_SIZE);

  /* Let message handler to handle disconnect event.  */
  if (nbytes <= 0){
    return -1;
  }

  /* Record read size.  */
  ase->recv.size = nbytes;
  type = header.type;

  /* Increment counter.  */
  ase->recv_msg_count++;

  /* Put last read type.  */
  ase->last_read_type = type;

  /* Invoke call back function.  */
  if (type < SMI_MSG_MAX && as->parser[type] && as->callback[type])
    {
      ret = (*as->parser[type]) (&ase->recv.pnt, &ase->recv.size, &header, ase, as->callback[type]);
      if (ret < 0)
        return ret;
    }

  return nbytes;
}

///* Send Alarm message to the client */
//int
//smi_server_send_alarm_msg (struct smi_server_entry *ase,
//                           struct smi_msg_alarm *alarm_msg,
//                           int msg_type)
//{
//  int len = 0;
//
//  /* Send the msg to client */
//  ase->send.pnt = ase->send.buf + SMI_MSG_HEADER_SIZE;
//  ase->send.size = ase->send.len - SMI_MSG_HEADER_SIZE;
//
//
//  /* Encode Alarm msg.  */
//  len = smi_encode_alarm_msg (&ase->send.pnt, &ase->send.size, alarm_msg);
//  if (len < 0)
//    return len;
//
//  smi_server_send_message (ase, 0, 0, msg_type, 0, len);
//
//  return 0;
//}
