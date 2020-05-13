/* Copyright (C) 2002-2011 IP Infusion, Inc. All Rights Reserved. */

/* SMI server implementation.  */
#include <sys/un.h>
#include "zebra.h"
#include "thread.h"
#include "vector.h"
#include "memory.h"
#include "tlv.h"
#include "smi_server.h"
#include "smi_message.h"

/* Initialize XXX SMI server.  */
struct smi_server *
smi_server_init (struct thread_master *zg)
{
  int ret;
  struct smi_server *as;
  struct message_handler *ms;

  /* Create message server.  */
  ms = message_server_create (zg);
  if (! ms)
    return NULL;

#ifndef HAVE_TCP_MESSAGE
  /* Set server type to UNIX domain socket.  */
  message_server_set_style_domain (ms, "/tmp/.smi_server.sock");
#else /* HAVE_TCP_MESSAGE */
  message_server_set_style_tcp (ms, SMI_PORT_XXX);
#endif /* !HAVE_TCP_MESSAGE */

  /* Set call back functions.  */
  message_server_set_callback (ms, MESSAGE_EVENT_CONNECT,
                               smi_server_connect);
  message_server_set_callback (ms, MESSAGE_EVENT_DISCONNECT,
                               smi_server_disconnect);
  message_server_set_callback (ms, MESSAGE_EVENT_READ_MESSAGE,
                               smi_server_read_msg);

  /* Start SMI server.  */
  ret = message_server_start (ms);
  if (ret < 0)
    {
      zlog_err("Error in starting message server");
    }

  /* When message server works fine, go forward to create SMI server
     structure.  */
  as = XCALLOC (MTYPE_SMISERVER, sizeof (struct smi_server));
  as->zg = zg;
  as->ms = ms;
  ms->info = as;

  /* Set version and protocol.  */
  smi_server_set_version (as, SMI_PROTOCOL_VERSION_1);
  smi_server_set_protocol (as, SMI_PROTO_SMISERVER);

  /* Set services.  */
  smi_server_set_service (as, SMI_SERVICE_INTERFACE);

  /* Set callback functions to SMI.  */
//  smi_server_set_callback (as, SMI_MSG_IF_SETMTU,
//                           smi_parse_if,
//                           nsm_smi_server_recv_if);

  return as;
}



