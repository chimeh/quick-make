#ifndef _AUTH_RULE_BUILD_H_
#define _AUTH_RULE_BUILD_H_


#ifndef PACK_ATTR
#define PACK_ATTR  __attribute__((packed))
#endif


/*EAP规则使用两个block*/
#define EAP_RULE_BLOCK_NUMBER	2


/*认证规则和默认规则使用不同的优先级*/
#define EAP_DEFAULT_RULE_PRI	10
#define EAP_USER_RULE_PRI		20


typedef struct hal_msg_port_enable_s {
	int ifindex;       
} PACK_ATTR hal_msg_port_enable_t;;

typedef struct hal_msg_port_disable_s {
	int ifindex;       
} PACK_ATTR hal_msg_port_disable_t;;

typedef struct hsl_msg_auth_add_s {
	unsigned int ifindex;       
	unsigned int srcid;
} PACK_ATTR hsl_msg_auth_add_t;

typedef struct hsl_msg_auth_delete_s {
	unsigned int ifindex;       
	unsigned int srcid;	
} PACK_ATTR hsl_msg_auth_delete_t;

typedef struct hsl_msg_precedence_add_s {
	unsigned short precedence; 
	unsigned short queue_index;	
} PACK_ATTR hsl_msg_precedence_add_t;

typedef struct hsl_msg_precedence_delete_s {
	unsigned short precedence;
} PACK_ATTR hsl_msg_precedence_delete_t;



extern int hsl_eap_rule_init();
extern int hsl_eap_port_enabel(int port);
extern int hsl_eap_port_disable(int port);
extern int hsl_eap_user_add(unsigned int ip, int port, int pri, int mode);
extern int hsl_eap_user_delete(unsigned int ip, int mode);


#endif
