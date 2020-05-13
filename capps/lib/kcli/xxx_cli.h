/**
 @file xxx_cli.h

 @date 2010-7-9

 @version v2.0

  The file defines Macro, stored data structure for xxx cli
*/
#ifndef _XXX_CLI_H
#define _XXX_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

#include "xxx_types.h"
#include "xxx_vti.h"
#include "xxx_cmd.h"
#include "xxx_common_cli.h"

/* CLI modes.  */

#define EXEC_MODE 0
#define XXX_SDK_MODE 1
#define XXX_CMODEL_MODE 2
#define XXX_SDK_OAM_CHAN_MODE 3
#define XXX_DEBUG_MODE 4
#define XXX_DBG_TOOL_MODE 5
#define XXX_XXXCLI_MODE 6
#define XXX_INTERNAL_MODE 7
#define XXX_APP_MODE 8

/* Return value.  */
#define CLI_SUCCESS           0
#define CLI_ERROR             1
#define CLI_AUTH_REQUIRED     2
#define CLI_EOL               3

/* Max length of each token.  */
#define MAX_TOKEN_LENGTH   256

/* Used for shield system API other than show command */
#undef SDK_INTERNAL_CLIS

/* Used for shield system API in show command */
#define SDK_INTERNAL_CLI_SHOW

/* Common descriptions. */
#define XXX_CLI_SHOW_STR "Show running system information"
#define XXX_CLI_NO_STR      "Negate a command or set its defaults"
#define XXX_CLI_CLEAR_STR   "Clear functions"
#define XXX_CLI_ENABLE      "Enable functions"
#define XXX_CLI_DISABLE     "Disable functions"
#define XXX_CLI_SHOW_SYS_MEM_STR  "Memory information"
#define XXX_CLI_DEBUG_STR  "Debugging functions"
#define XXX_CLI_BOOL_VAR_STR  "Boolean variable"

#define XXX_CLI_GET_ARGC_INDEX(str) xxx_cli_get_prefix_item(&argv[0], argc, str, sal_strlen(str))
#define XXX_CLI_GET_SPECIFIC_INDEX(str, idx) xxx_cli_get_prefix_item(&argv[idx], argc - idx, str, sal_strlen(str))
#define CLI_CLI_STR_EQUAL(str, idx)  (0 == sal_strncmp((str), argv[(idx)], sal_strlen(str)))
#define XXX_CLI_STR_EQUAL_ENHANCE(str, idx)  \
    ((0 == sal_strncmp((str), argv[(idx)], sal_strlen(str))) && (sal_strlen(argv[idx]) == sal_strlen(str)))
#define INDEX_VALID(index)  (0xFF != (index))

#define CLI_MROUTE_STR      "Configure static multicast routes"

#define UINT64_STR_LEN      21

#define XXX_MAX_UINT16_VALUE 0xFFFF
#define XXX_MAX_UINT32_VALUE 0xFFFFFFFF
#define XXX_MAX_UINT8_VALUE 0xFF

#define MAX_CPU_PKT_FILE_NAME_SIZE      256

struct xxx_l2_write_info_para_s
{
    char file[MAX_CPU_PKT_FILE_NAME_SIZE];
    void* pdata;
};
typedef struct xxx_l2_write_info_para_s xxx_l2_write_info_para_t;

typedef int (* XXX_CLI_OUT_FUNC) (const char* str, ...);
int xxx_cli_out(const char* fmt, ...);

typedef int16 (* XXX_CLI_PORT_MAP_FUNC) (uint16, uint8);
extern XXX_CLI_PORT_MAP_FUNC cli_port_map_func_ptr;

#ifdef HAVE_ISO_MACRO_VARARGS
#define XXX_CLI(func_name, cli_name, cmd_str, ...)  \
    char* cli_name ## _help[] = {__VA_ARGS__, NULL}; \
    DEFUN(func_name, cli_name, cmd_str, cli_name ## _help)
#else
#define XXX_CLI(func_name, cli_name, cmd_str, ARGS...) \
    char* cli_name ## _help[] = {ARGS, NULL}; \
    DEFUN(func_name, cli_name, cmd_str, cli_name ## _help)
#endif

extern int32
xxx_cmd_str2int(char* str, int32* ret);
extern uint32
xxx_cmd_str2uint(char* str, int32* ret);
extern void
    xxx_uint64_to_str(uint64 src, char dest[UINT64_STR_LEN]);

extern int32
xxx_cmd_judge_is_num(char* str);

extern char*
xxx_cli_get_debug_desc(unsigned char level);

#define XXX_CLI_GET_INTEGER(NAME, V, STR)                \
    {                                                  \
        int32 retv;                                      \
        (V) = xxx_cmd_str2int((STR), &retv);            \
        if (retv < 0)                                    \
        {                                              \
            xxx_cli_out("%% Invalid %s value\n", NAME); \
            return CLI_ERROR;                            \
        }                                              \
    }

#define XXX_CLI_GET_INTEGER_RANGE(NAME, V, STR, MIN, MAX)  \
    {                                                  \
        int32 retv;                                      \
        (V) = xxx_cmd_str2int((STR), &retv);            \
        if (retv < 0 || (V) < (MIN) || (V) > (MAX))      \
        {                                              \
            xxx_cli_out("%% Invalid %s value\n", NAME); \
            return CLI_ERROR;                            \
        }                                              \
    }

#define XXX_CLI_GET_INTEGER64(NAME, V, INT, STR, MIN, MAX)  \
    {                                                  \
        int32 retv;                                      \
        int32 val = 0;                                   \
        (V) = xxx_cmd_str2int((STR), &retv);            \
        sal_memcpy(&INT.l[0], &val, 4);                 \
        sal_memcpy(&INT.l[1], &(V), 4);                 \
        if (retv < 0 || (V) < (MIN) || (V) > (MAX))      \
        {                                              \
            xxx_cli_out("%% Invalid %s value\n", NAME); \
            return CLI_ERROR;                            \
        }                                              \
    }

#define XXX_CLI_GET_UINT32(NAME, V, STR)             \
    {                                                  \
        int32 retv;                                      \
        (V) = xxx_cmd_str2uint((STR), &retv);            \
        if (retv < 0)                                    \
        {                                               \
            xxx_cli_out("%% Invalid %s value\n", NAME); \
            return CLI_ERROR;                            \
        }                                               \
    }

#define XXX_CLI_GET_UINT16(NAME, V, STR)             \
    {                                                  \
        int32 retv;                                      \
        uint32 tmp = 0;                                   \
        uint16 temp_global_port = 0;                                 \
        uint8 j = 0;                                     \
        char string[100] = {0};                       \
                                                      \
        sal_memcpy(string, NAME, sal_strlen(NAME)); \
        tmp = xxx_cmd_str2uint((STR), &retv);           \
        if (retv < 0 || tmp > XXX_MAX_UINT16_VALUE)       \
        {                                               \
            xxx_cli_out("%% Invalid %s value\n", NAME); \
            return CLI_ERROR;                            \
        }                                               \
        (V) = (uint16)tmp;                               \
        for (j = 0; j < sal_strlen(string); j++)            \
        {                                                 \
            (string[j]) = sal_tolower((string[j]));      \
        }                                                 \
        if (cli_port_map_func_ptr)\
        {\
            if ((0 == sal_strncmp((string), "gport", sal_strlen(string)))||  \
               (0 == sal_strncmp((string), "port", sal_strlen(string))))\
            {                                                         \
                temp_global_port = (*cli_port_map_func_ptr)((V),1);       \
                if (temp_global_port == 0xFFFF)                                  \
                {                                                     \
                    xxx_cli_out("%% Invalid %s value\n", "port");     \
                    return CLI_ERROR;                                 \
                }                                                     \
                V = temp_global_port;                                 \
            }                                                         \
        }\
    }
#define XXX_CLI_GET_UINT8(NAME, V, STR)              \
    {                                                  \
        int32 retv;                                      \
        uint32 tmp = 0;                                   \
        uint8 j = 0;                                     \
        uint16 temp_global_port = 0;                     \
        char string[100] = {0};                       \
        sal_memcpy(string, NAME, sal_strlen(NAME)); \
        tmp = xxx_cmd_str2uint((STR), &retv);           \
        if (retv < 0 || tmp > XXX_MAX_UINT8_VALUE)       \
        {                                               \
            xxx_cli_out("%% Invalid %s value\n", NAME); \
            return CLI_ERROR;                            \
        }                                               \
        (V) = (uint8)tmp;                                \
        for (j = 0; j < sal_strlen(string); j++)            \
        {                                                 \
            (string[j]) = sal_tolower((string[j]));      \
        }                                                 \
        if (cli_port_map_func_ptr)\
        {\
            if ((0 == sal_strncmp((string), "lport", sal_strlen(string)))||  \
               (0 == sal_strncmp((string), "port", sal_strlen(string))))\
            {                                                         \
                temp_global_port = (*cli_port_map_func_ptr)((V),0);       \
                if (temp_global_port == 0xFFFF)                                  \
                {                                                     \
                    return CLI_ERROR;                                 \
                }                                                     \
                V = temp_global_port;                                 \
            }                                                         \
        }\
    }

#define XXX_CLI_GET_UINT8_RANGE(NAME, V, STR, MIN, MAX) XXX_CLI_GET_UINT8(NAME, V, STR)
#define XXX_CLI_GET_UINT16_RANGE(NAME, V, STR, MIN, MAX) XXX_CLI_GET_UINT16(NAME, V, STR)
#define XXX_CLI_GET_UINT32_RANGE(NAME, V, STR, MIN, MAX)  XXX_CLI_GET_UINT32(NAME, V, STR)

#define XXX_CLI_GET_MAC_ADDRESS(NAME, V, STR)                                                                  \
    {                                                                                                        \
        int32 retv = 0;                                                                                      \
        uint8 i = 0;                                                                                         \
        while (STR[i] != '\0')                                                                                 \
        {                                                                                                    \
            if (STR[i] == '.'){ retv++; }                                                                    \
            i++;                                                                                             \
        }                                                                                                    \
        if (retv != 2)                                                                                       \
        {                                                                                                    \
            xxx_cli_out("%% invalid %s value\n", NAME);                                                     \
            return CLI_ERROR;                                                                                \
        }                                                                                                    \
        retv = sal_sscanf((STR), "%4hx.%4hx.%4hx", (uint16*)&(V[0]), (uint16*)&(V[2]), (uint16*)&(V[4])); \
        if (retv != 3)                                                                                       \
        {                                                                                                    \
            xxx_cli_out("%% invalid %s value\n", NAME);                                                     \
            return CLI_ERROR;                                                                                \
        }                                                                                                    \
        *(uint16*)&(V[0]) = sal_htons(*(uint16*)&(V[0]));                                                  \
        *(uint16*)&(V[2]) = sal_htons(*(uint16*)&(V[2]));                                                  \
        *(uint16*)&(V[4]) = sal_htons(*(uint16*)&(V[4]));                                                  \
    }

#define XXX_CLI_GET_IPV4_ADDRESS(NAME, V, STR)               \
    {                                                      \
        int32 retv;                                          \
        retv = sal_inet_pton(AF_INET, (STR), &(V));         \
        if (!retv)                                           \
        {                                                  \
            xxx_cli_out("%% Invalid %s value\n", NAME);     \
            return CLI_ERROR;                                \
        }                                                  \
        (V) = sal_htonl(V);                                  \
    }

#define XXX_CLI_GET_IPV6_ADDRESS(NAME, V, STR)           \
    {                                                  \
        int32 retv;                                      \
        retv = sal_inet_pton(AF_INET6, (STR), &(V));    \
        if (!retv)                                       \
        {                                              \
            xxx_cli_out("%% Invalid %s value\n", NAME); \
            return CLI_ERROR;                            \
        }                                              \
    }

#define XXX_CLI_IS_NUM(STR)                           \
    {                                                 \
        int32 retv;                                   \
        retv = xxx_cmd_judge_is_num((STR));          \
        if (0 != retv)                                  \
        {                                             \
            xxx_cli_out("%% Incomplete command\n");  \
            return CLI_ERROR;                         \
        }                                             \
    }

enum cmd_token_type_s
{
    cmd_token_paren_open,
    cmd_token_paren_close,
    cmd_token_cbrace_open,
    cmd_token_cbrace_close,
    cmd_token_brace_open,
    cmd_token_brace_close,
    cmd_token_separator,
    cmd_token_keyword,
    cmd_token_var,
    cmd_token_unknown
};
typedef enum cmd_token_type_s cmd_token_type;

/* APIs, user shall also call  XXX_CLI(), install_element() */
extern xxx_vti_t* g_xxx_vti;

extern int
xxx_vti_read(char* buf, uint32 buf_size,uint32 mode);
extern int
xxx_vti_read_cmd(xxx_vti_t* vty, const char* szbuf, const int buf_len);
extern void
xxx_cmd_init(int terminal);
extern void xxx_cli_register_print_fun(XXX_CLI_OUT_FUNC func);
extern unsigned char
xxx_cli_get_prefix_item(char** argv, unsigned char argc, char* prefix, unsigned char prefix_len);
extern int
xxx_vti_command(xxx_vti_t* vti, char* buf);

extern void
set_terminal_raw_mode(uint32 mode);

extern void
restore_terminal_mode(uint32 mode);

extern void
xxx_cli_enable_cmd_debug(int enable);

extern void
xxx_cli_enable_arg_debug(int enable);

#ifdef __cplusplus
}
#endif

#endif /* _XXX_CLI_H */

