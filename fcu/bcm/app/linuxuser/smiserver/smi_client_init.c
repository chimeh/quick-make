/* Copyright (C) 2002-2011 IP Infusion, Inc. All Rights Reserved. */

/* SMI client implementation.  */
#include <sys/un.h>
#include "zebra.h"
#include "thread.h"
#include "vector.h"
#include "memory.h"
#include "tlv.h"
#include "smi_message.h"
#include "smi_client.h"


/* Initialize XXX client. */

int
smi_client_init(struct smiclient_globals *azg)
{
  int ret = 0;

  ret = smi_client_create(azg, SMI_AC_NSM_MODULE);
  if (ret < 0)
    return SMI_ERROR;
  //smi_client_prop_set, prop用hash或者json传递
  smi_client_set_version (SMI_AC_NSM, SMI_PROTOCOL_VERSION_1);
  smi_client_set_protocol (SMI_AC_NSM, SMI_PROTO_SMICLIENT);
  smi_client_set_client_id (SMI_AC_NSM, 0);
  smi_client_set_service (SMI_AC_NSM, SMI_SERVICE_INTERFACE, SMI_AC_NSM_MODULE);

  /* Set Alarm parser and callback */
  smi_client_set_parser (SMI_AC_NSM, SMI_MSG_ALARM, smi_parse_alarm_message);
  smi_client_set_callback (SMI_AC_NSM, SMI_MSG_ALARM,
                           smi_process_alarm_message);

  ret = smi_client_start (SMI_AC_NSM);
  if(ret < 0)
    return ret;

  return SMI_SUCEESS;
}


