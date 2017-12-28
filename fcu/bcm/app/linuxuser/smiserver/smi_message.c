/* SMI message implementation.  This implementation is used by both
   server and client side.  */

#include "smi_client.h"
#include "tlv.h"


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


/* SMI alarm msg decode.  */
int
smi_decode_alarm_msg (u_char **pnt, u_int16_t *size, struct smi_msg_alarm *msg)
{
  struct smi_tlv_header tlv;
  u_char *sp = *pnt;

  if (*size < SMI_MESSAGE_ALARM_SIZE)
    return SMI_ERR_PKT_TOO_SMALL;

  /* Alarm TLV Parse */
  while(*size) 
  {
    SMI_DECODE_TLV_HEADER(tlv);
    switch(tlv.type)
    {
      case SMI_ALARM_CTYPE_MODULE_NAME:
        TLV_DECODE_GETL (msg->smi_module);
        SMI_SET_CTYPE(msg->cindex, tlv.type);
        break;
      case SMI_ALARM_CTYPE_ALARM_TYPE:
        TLV_DECODE_GETL (msg->alarm_type);
        SMI_SET_CTYPE(msg->cindex, tlv.type);
        break;
      case SMI_ALARM_CTYPE_DATA_NSM_CLIENT:
        TLV_DECODE_GETL (msg->nsm_client);
        SMI_SET_CTYPE(msg->cindex, tlv.type);
         break;
      case SMI_ALARM_CTYPE_DATA_TRANSPORT_DESC:
        sprintf(msg->description, (char *)*pnt);
        TLV_DECODE_SKIP(tlv.length);
        SMI_SET_CTYPE(msg->cindex, tlv.type);
         break;
      case SMI_ALARM_CTYPE_DATA_CFM_ALARM:
        memcpy (&(msg->cfm_alarm_info), *pnt, 
                     sizeof(struct cfm_alarm_info_s));
        TLV_DECODE_SKIP(tlv.length);
        SMI_SET_CTYPE(msg->cindex, tlv.type);
         break;
      default:
        break;
    }
  }
  return *pnt - sp;
}
/* Parse SMI service message.  */
int
smi_parse_service (u_char **pnt, u_int16_t *size,
                   struct smi_msg_header *header, void *arg,
                   SMI_CALLBACK callback)
{
  int ret;
  struct smi_msg_service msg;

  memset (&msg, 0, sizeof (struct smi_msg_service));

  /* Parse service.  */
  ret = smi_decode_service (pnt, size, &msg);
  if (ret < 0)
    return ret;

  /* Call callback with arg. */
  if (callback)
    {
      ret = (*callback) (header, arg, &msg);
      if (ret < 0)
        return ret;
    }
  return 0;
}

/* Parse SMI alarm message.  */
int
smi_parse_alarm_message (u_char **pnt, u_int16_t *size,
                         struct smi_msg_header *header, void *arg,
                         SMI_CALLBACK callback)
{
  int ret;
  struct smi_msg_alarm msg;

  memset (&msg, 0, sizeof (struct smi_msg_alarm));

  /* Parse service.  */
  ret = smi_decode_alarm_msg (pnt, size, &msg);
  if (ret < 0) {
    return ret;
  }

  /* Call callback with arg. */
  if (callback)
    {
      (*callback) (header, arg, &msg);
    }
  return 0;
}
