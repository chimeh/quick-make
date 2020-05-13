/****************************************************************************
 * xxx_cmd.h :         xxx_cmd header
 *
 * Copyright (C) 2010 Centec Networks Inc.  All rights reserved.
 *
 * Modify History :
 * Revision       :         V1.0
 * Date           :         2010-7-28
 * Reason         :         First Create
 ****************************************************************************/

#ifndef _XXX_CMD_H
#define _XXX_CMD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "xxx_vti_vec.h"
#include "xxx_vti.h"

#define MAX_ELEMENT_NUM 1000 /* totol cmd number for one mode */
#define HOST_NAME 32

#define MAX_OPTIONAL_CMD_NUM 100 /* max optional cmd number in {} */

#define MTYPE_VECTOR 0
#define MTYPE_VTI_HIST 0

typedef enum best_match_type_s
{
    XXX_CMD_EXACT_MATCH = 0,
    XXX_CMD_PARTLY_MATCH,
    XXX_CMD_EXTEND_MATCH,
    XXX_CMD_IMCOMPLETE_MATCH
} best_match_type_t;

/* There are some command levels which called from command node. */
enum xxx_node_type_e
{
    XXX_AUTH_NODE,              /* Authentication mode of vty interface. */
    XXX_VIEW_NODE,              /* View node. Default mode of vty interface. */
    XXX_AUTH_ENABLE_NODE,       /* Authentication mode for change enable. */
    XXX_ENABLE_NODE,            /* Enable node. */
    XXX_CONFIG_NODE,            /* Config node. Default mode of config file. */
    XXX_DEBUG_NODE,             /* Debug node. */
    XXX_AAA_NODE,               /* AAA node. */
    XXX_KEYCHAIN_NODE,          /* Key-chain node. */
    XXX_KEYCHAIN_KEY_NODE,      /* Key-chain key node. */
    XXX_INTERFACE_NODE,         /* Interface mode node. */
    XXX_MASC_NODE,              /* MASC for multicast.  */
    XXX_IRDP_NODE,              /* ICMP Router Discovery Protocol mode. */
    XXX_IP_NODE,                /* Static ip route node. */
    XXX_ACCESS_NODE,            /* Access list node. */
    XXX_PREFIX_NODE,            /* Prefix list node. */
    XXX_ACCESS_IPV6_NODE,       /* Access list node. */
    XXX_PREFIX_IPV6_NODE,       /* Prefix list node. */
    XXX_AS_LIST_NODE,           /* AS list node. */
    XXX_COMMUNITY_LIST_NODE,    /* Community list node. */
    XXX_RMAP_NODE,              /* Route map node. */
    XXX_SMUX_NODE,              /* SNMP configuration node. */
    XXX_DUMP_NODE,              /* Packet dump node. */
    XXX_FORWARDING_NODE,        /* IP forwarding node. */
    XXX_VTI_NODE                /* Vty node. */
};
typedef enum xxx_node_type_e xxx_node_type_t;

/* Completion match types. */
enum xxx_match_type_e
{
    XXX_XXX_NO_MATCH,
    XXX_EXTEND_MATCH,
    XXX_IPV4_PREFIX_MATCH,
    XXX_IPV4_MATCH,
    XXX_IPV6_PREFIX_MATCH,
    XXX_IPV6_MATCH,
    XXX_RANGE_MATCH,
    XXX_VARARG_MATCH,
    XXX_PARTLY_MATCH,
    XXX_EXACT_MATCH,
    XXX_OPTION_MATCH,
    XXX_INCOMPLETE_CMD
};
typedef enum xxx_match_type_e xxx_match_type_t;

/* Node which has some commands and prompt string and configuration
   function pointer . */
struct xxx_cmd_node_s
{
    /* Node index. */
    xxx_node_type_t node;

    /* Prompt character at vty interface. */
    char prompt[HOST_NAME];

    /* Is this node's configuration goes to vtysh ? */
    int32 vtysh;

    /* Node's configuration write function */
    int32 (* func)(xxx_vti_t*);

    /* Vector of this node's command list. */
    vector cmd_vector;
};
typedef struct xxx_cmd_node_s xxx_cmd_node_t;

/* Structure of command element. */
struct xxx_cmd_element_s
{
    char* string;       /* Command specification by string. */
    int32 (* func) (struct xxx_cmd_element_s*, xxx_vti_t*, int, char**);
    char** doc;         /* Documentation of this command. */
    int32 daemon;         /* Daemon to which this command belong. */
    vector strvec;      /* Pointing out each description vector. */
    int32 cmdsize;        /* Command index count. */
    char* config;       /* Configuration string */
    vector subconfig;   /* Sub configuration string */
};
typedef struct xxx_cmd_element_s xxx_cmd_element_t;

/* Command description structure. */
struct xxx_cmd_desc_s
{
    char* cmd;      /* Command string. */
    char* str;        /* Command's description. */
    int32 is_arg;
};
typedef struct xxx_cmd_desc_s xxx_cmd_desc_t;

/* Return value of the commands. */
#define CMD_SUCCESS              0
#define CMD_WARNING              1
#define CMD_ERR_NO_MATCH         2
#define CMD_ERR_AMBIGUOUS        3
#define CMD_ERR_INCOMPLETE       4
#define CMD_ERR_EXEED_ARGC_MAX   5
#define CMD_ERR_NOTHING_TODO     6
#define CMD_COMPLETE_FULL_MATCH  7
#define CMD_COMPLETE_MATCH       8
#define CMD_COMPLETE_LIST_MATCH  9
#define CMD_SUCCESS_DAEMON      10
#define CMD_SYS_ERROR 11

/* Argc max counts. */
#define CMD_ARGC_MAX   256

/* Turn off these macros when uisng cpp with extract.pl */
#ifndef VTISH_EXTRACT_PL

/* DEFUN for vti command interafce. Little bit hacky ;-). */
#define DEFUN(funcname, cmdname, cmdstr, helpstr) \
    int32 funcname(xxx_cmd_element_t*, xxx_vti_t*, int32, char**); \
    xxx_cmd_element_t cmdname = \
    { \
        cmdstr, \
        funcname, \
        helpstr \
    }; \
    int32 funcname \
        (xxx_cmd_element_t * self, xxx_vti_t * vty, int32 argc, char** argv)

#endif /* VTISH_EXTRACT_PL */

/* Some macroes */
#define XXX_CMD_OPTION(S)   ((S[0]) == '[')
extern int32 xxx_is_cmd_var(char* cmd);
#define XXX_CMD_VARIABLE(S) xxx_is_cmd_var(S)
#define XXX_CMD_VARARG(S)   ((S[0]) == '.')
#define XXX_CMD_RANGE(S)    ((S[0] == '<'))
#define XXX_CMD_NUMBER(S) ((S[0] <= '9') && (S[0] >= '0'))

#define XXX_CMD_IPV4(S)        ((sal_strcmp((S), "A.B.C.D") == 0))
#define XXX_CMD_IPV4_PREFIX(S) ((sal_strcmp((S), "A.B.C.D/M") == 0))
#define XXX_CMD_IPV6(S)        ((sal_strcmp((S), "X:X::X:X") == 0))
#define XXX_CMD_IPV6_PREFIX(S) ((sal_strcmp((S), "X:X::X:X/M") == 0))

#define MTYPE_VECTOR 0
#define MTYPE_VTI_HIST 0

extern char* xxx_strdup(char* str);
#define XSTRDUP(mtype, str) xxx_strdup(str)

/* Prototypes. */
void xxx_install_node(xxx_cmd_node_t*, int32 (*)(xxx_vti_t*));
void install_default(xxx_node_type_t);
void install_element(xxx_node_type_t, xxx_cmd_element_t*);
void xxx_sort_node();
vector xxx_cmd_make_strvec(char*);
void xxx_cmd_free_strvec(vector);
vector xxx_cmd_describe_command();
char** xxx_cmd_complete_command();
char* xxx_cmd_prompt(xxx_node_type_t);
int32 xxx_cmd_execute_command(vector, xxx_vti_t*, xxx_cmd_element_t * *);
int32 xxx_cmd_execute_command_strict(vector, xxx_vti_t*, xxx_cmd_element_t * *);
void xxx_config_replace_string(xxx_cmd_element_t*, char*, ...);
void xxx_cmd_init(int32);

#ifdef __cplusplus
}
#endif

#endif /* _XXX_CMD_H */

