#ifndef HSL_MSG_TLV_H
#define HSL_MSG_TLV_H

#ifndef PACK_ATTR
#define PACK_ATTR  __attribute__((packed))
#endif


#define HSL_MSG_DB_HEADER_SIZE 8 
#define HSL_MSG_MISC_HEADER_SIZE 8 
#define HSL_MSG_HEADER_SIZE   8

#define HSL_TLV_OPERATION_TYPE_QUERY  0
#define HSL_TLV_OPERATION_TYPE_ADD    1
#define HSL_TLV_OPERATION_TYPE_UPDATE 2
#define HSL_TLV_OPERATION_TYPE_DEL    3


/*PTS tlv header*/
typedef struct hsl_msg_header
{
  unsigned short type;
  unsigned short length;
  unsigned short table_id;
  unsigned short op_type;
} PACK_ATTR hsl_msg_header_t;



#endif
