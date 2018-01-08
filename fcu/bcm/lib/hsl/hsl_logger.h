/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef  _HSL_LOG_MODULE
#define  _HSL_LOG_MODULE

#include "hsl_oss.h"
#include "hsl_logs.h"

/***************************************************************************
 * To preserve system resources and in order to keep ONLY relevant logs,   * 
 * logs are throttled. We keep only up to max logs per unit of time        *
 ***************************************************************************/                                                                            
#define HSL_LOG_TIME_UNIT            (15) /* 15 seconds          */         
#define HSL_LOG_MAX_PER_UNIT        (750) /* 750 logs per 15 sec */ 
   
/*
 * Log level 
 */
                                      
#define HSL_LEVEL_DEBUG        (5)    /* Debug trace (For example: Function calls, rx/tx packet trace). */
#define HSL_LEVEL_INFO         (4)    /* General system information,profiling    */
#define HSL_LEVEL_WARN         (3)    /* Warnings  (For example: System running out of resorces or miss configuration).*/
#define HSL_LEVEL_ERROR        (2)    /* Recoverable error (For example, configuration command failure).               */   
#define HSL_LEVEL_FATAL        (1)    /* Fatal failure occured process/system has to terminate/reboot.                 */
#define HSL_LEVEL_ADMIN        (0)    /* Administrative critical information (For example: New hw modules insertion ). */

#define HSL_LEVEL_DEFAULT      HSL_LEVEL_WARN 

/*
 * Modules 
 */
enum hsl_modules {
    HSL_LOG_COMMON = 0,   /* Common modules - like shared libraries.*/
    HSL_LOG_GENERAL,      /* General logs.                       */
    HSL_LOG_IFMGR,        /* Interface management logs.          */
    HSL_LOG_MSG,          /* HAL-HSL message logs.               */
    HSL_LOG_FIB,          /* FIB management.                     */
    HSL_LOG_FDB,          /* FDB management.                     */
    HSL_LOG_DEVDRV,       /* Device Driver logs.                 */
    HSL_LOG_PKTDRV,       /* Packet driver logs.                 */
    HSL_LOG_PLATFORM,     /* Platform(Hardware) logs.            */
    HSL_LOG_GEN_PKT,      /* Generic packet trace.               */
    HSL_LOG_BPDU_PKT,     /* BPDU packet trace.                  */
    HSL_LOG_ARP_PKT,      /* ARP  packet trace.                  */
    HSL_LOG_IGMP_PKT,     /* IGMP packet trace.                  */
    HSL_LOG_OPENFLOW,     /* OPENFLOW.                           */
    HSL_LOG_LAST_MODULE   /* Last module.                        */
};

typedef struct __hsllog_details {
   const u_int16_t module_id;            /* Module id.                            */
   const char     *module_name;          /* Module name.                          */
   u_int16_t enable;                     /* Module enable.                        */
   u_int16_t level;                      /* Log level.                            */
   u_int16_t max_logs_per_unit;          /* Maximum number of logs per time unit. */
   u_int16_t log_time_unit;              /* Log throttling time unit.             */
   unsigned long  unit_start;            /* Last unit start time.                 */
   u_int32_t   log_count;                  /* Current log count.                  */
} hsllog_detail_t;

extern hsllog_detail_t hsl_log_detail[];
void hsl_log_all_enable (void);
void hsl_log_all_disable (void);
void hsl_log_all_setlevel (u_int16_t level);
int hsl_do_log(
        const char  *cprefix,
        const enum hsl_modules m,
        const int level,
        const char* file,
        const char* func,
        const int line,
        const char* fmt, ...);
int hsl_log_conf(char module_str[], u_int16_t enable, u_int16_t level);



#define HSL_LOG_CHK(mod, ll) \
 (mod <= HSL_LOG_LAST_MODULE && hsl_log_detail[mod].enable !=0 && ll <= hsl_log_detail[mod].level)

/*
  Log macro for readability.
*/

#define HSL_LOG(M,L,...)                                                   \
    do {                                                                   \
         if (HSL_LOG_CHK(M, L) || strstr(__FILE__, "hsl_ctc_pkt.c"))                                            \
         {                                                                 \
              hsl_do_log(NULL, M, L, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);  \
         }                                                                 \
    } while (0)

void hsl_log_dump_hex8(unsigned char *data, unsigned int len);
#endif  /* _HSL_LOG_MODULE */
