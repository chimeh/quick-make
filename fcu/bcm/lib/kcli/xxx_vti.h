/****************************************************************************
 * xxx_vti.h :         vti header
 *
 * Copyright (C) 2010 Centec Networks Inc.  All rights reserved.
 *
 * Modify History :
 * Revision       :         V1.0
 * Date           :         2010-7-28
 * Reason         :         First Create
 ****************************************************************************/

#ifndef _XXX_VTI_H
#define _XXX_VTI_H

#ifdef __cplusplus
extern "C" {
#endif

#define XXX_VTI_BUFSIZ 1536
#define XXX_VTI_MAXHIST 50

enum xxx_shell_mode_type_e
{
    XXX_VTI_SHELL_MODE_DEFAULT = 0,
    XXX_VTI_SHELL_MODE_USER,
    XXX_VTI_SHELL_MODE_MAx,
};
typedef enum xxx_shell_mode_type_e shell_mode_type_t;

/* Is this vti connect to file or not */
enum xxx_terminal_type_e
{
    XXX_VTI_TERM,
    XXX_VTI_FILE,
    XXX_VTI_SHELL,
    XXX_VTI_SHELL_SERV
};
typedef enum xxx_terminal_type_e terminal_type_t;

/* terminal status*/
enum xxx_terminal_stats_e
{
    XXX_VTI_NORMAL,
    XXX_VTI_CLOSE,
    XXX_VTI_MORE,
    XXX_VTI_MORELINE,
    XXX_VTI_START,
    XXX_VTI_CONTINUE
};
typedef enum xxx_terminal_stats_e xxx_terminal_stats_t;

/* VTI struct. */
struct xxx_vti_struct_s
{
    /* File descripter of this vty. */
    int32 fd;

    unsigned int    pid;

    int (*printf)(struct xxx_vti_struct_s* vti, const char *szPtr, const int szPtr_len);

    int (*quit)(struct xxx_vti_struct_s* vti);

    terminal_type_t type;

    /* Node status of this vty */
    int32 node;

    /* What address is this vty comming from. */
    char* address;

    /* Privilege level of this vty. */
    int32 privilege;

    /* Failure count */
    int32 fail;

    /* Command input buffer */
    char* buf;

    /* Command cursor point */
    int32 cp;

    /* Command length */
    int32 length;

    /* Command max length. */
    int32 max;

    /* Histry of command */
    char* hist[XXX_VTI_MAXHIST];

    /* History lookup current point */
    int32 hp;

    /* History insert end point */
    int32 hindex;

    /* For current referencing point of interface, route-map,
       access-list etc... */
    void* index;

    /* For multiple level index treatment such as key chain and key. */
    void* index_sub;

    /* For escape character. */
    unsigned char escape;

    /* Current vty status. */
    xxx_terminal_stats_t status;

    /* IAC handling */
    unsigned char iac;

    /* IAC SB handling */
    unsigned char iac_sb_in_progress;

    /* Window width/height. */
    int32 width;

    int32 height;

    int32 scroll_one;

    /* Configure lines. */
    int32 lines;

    /* Terminal monitor. */
    int32 monitor;

    /* In configure mode. */
    int32 config;

    /* Timeout seconds and thread. */
    unsigned long v_timeout;

};
typedef struct xxx_vti_struct_s xxx_vti_t;

/* Small macro to determine newline is newline only or linefeed needed. */
#define XXX_VTI_NEWLINE "\n\r"

/* Default time out value */
#define XXX_VTI_TIMEOUT_DEFAULT 600

/* Vty read buffer size. */
#define XXX_VTI_READ_BUFSIZ 1536

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a, b) __attribute__ ((__format__(__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a, b)
#endif /* __GNUC__ */
/* Prototypes. */
void xxx_vti_init(int32 mode);
xxx_vti_t* xxx_vti_create(int mode);
xxx_vti_t* xxx_vti_new(void);
void xxx_vti_prompt(xxx_vti_t* vti);
int32 xxx_vti_out(xxx_vti_t*, const char*, ...) PRINTF_ATTRIBUTE(2, 3);
int32 xxx_vti_config_lock(xxx_vti_t*);
int32 xxx_vti_config_unlock(xxx_vti_t*);
void xxx_vti_append_history_command(char*);
extern xxx_vti_t* g_xxx_vti;

#ifdef __cplusplus
}
#endif

#endif /* _XXX_VTI_H */

