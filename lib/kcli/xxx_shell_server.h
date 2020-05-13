/**
 @file xxx_master_cli_server.h

 @date 2009-10-27

 @version v2.0

The file define  chipset  independent common Macros and constant.
*/

#ifndef _XXX_MASTER_CLI_SERVER_H
#define _XXX_MASTER_CLI_SERVER_H
#ifdef __cplusplus
extern "C" {
#endif

extern int
xxx_vty_socket();

extern void 
xxx_vty_close();

#ifdef __cplusplus
}
#endif

#endif /* _XXX_MASTER_CLI_SERVER_H*/
