#ifndef HSL_MSG_TLV_H
#define HSL_MSG_TLV_H



#define HAL_MSG_DB_HEADER_SIZE 8 
#define HAL_MSG_MISC_HEADER_SIZE 8 

#define HSL_TLV_OPERATION_TYPE_QUERY  0
#define HSL_TLV_OPERATION_TYPE_ADD    1
#define HSL_TLV_OPERATION_TYPE_UPDATE 2
#define HSL_TLV_OPERATION_TYPE_DEL    3


/*PTS tlv header*/
typedef struct hsl_msg_header
{
  unsigned short tlv_type;
  unsigned short tlv_length;
  unsigned short table_id;
  unsigned short operation_type;
} __attribute__((packed))hsl_msg_header;

#endif
