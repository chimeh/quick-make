/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"
#include "hsl_logger.h"

hsllog_detail_t hsl_log_detail[] = {
  /*   module_id       module_name     enable        level               max_logs            unit_in_sec   unit_start log_count */
  {HSL_LOG_COMMON,      " COMMON  "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_GENERAL,     " GENERAL "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_MSG,         " MSG     "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_IFMGR,       " IFMGR   "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_FIB,         " FIB     "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_DEVDRV,      " DEVDRV  "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_PKTDRV,      " PKTDRV  "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_PLATFORM,    " PLATFORM"     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_GEN_PKT,     " GEN_PKT "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_BPDU_PKT,    " BPDU_PKT"     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_ARP_PKT,     " ARP_PKT "     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_IGMP_PKT,    " IGMP_PKT"     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_OPENFLOW,    " OPENFLOW"     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
  {HSL_LOG_LAST_MODULE, " LAST_MOD"     , 1, HSL_LEVEL_DEFAULT ,HSL_LOG_MAX_PER_UNIT,HSL_LOG_TIME_UNIT,     0,     0     },
};

const int hsl_log_module_num = (sizeof(hsl_log_detail)/sizeof(hsl_log_detail[0]));

int hsl_add_log_module(char *buf,u_int16_t module) {

  if(NULL == buf) {
    return 0; 
  }
  if(module >= hsl_log_module_num) {
    sprintf(buf, " illegal(module=%u) ", module);
  } else {
    sprintf(buf,"%s", hsl_log_detail[module].module_name);
  }   
  return (strlen(buf));
}

int hsl_add_log_level(char *buf,u_int16_t level) {

  if(NULL == buf)
    return 0; 

  switch (level) {
  case HSL_LEVEL_INFO:
    sprintf(buf,"%s","INFO  ");
    break; 
  case HSL_LEVEL_DEBUG:
    sprintf(buf,"%s","DEBUG ");
    break;
  case HSL_LEVEL_WARN:      
    sprintf(buf,"%s","WARN  ");
    break;
  case HSL_LEVEL_ERROR:
    sprintf(buf,"%s","ERROR ");
    break;
  case HSL_LEVEL_FATAL:
    sprintf(buf,"%s","FATAL ");
    break;
  case HSL_LEVEL_ADMIN:
    sprintf(buf,"%s","ADMIN ");
    break;
  default: 
    sprintf(buf,"%s","INFO  ");
  }
  return (strlen(buf));
}

int hsl_do_log(
        const char *cprefix,
        const enum hsl_modules m,
        const int level,
        const char* file,
        const char* func,
        const int line,
        const char* fmt, ...)
{
#define _HSL_LOG_BUFLEN 1024 /* internal use only */
    va_list list;
    int len = 0;
    char buf[_HSL_LOG_BUFLEN + 3]; /* 3 extra for '\r\n\0' */
    char* p = &buf[0];
    char* tail;
    
    len = hsl_add_log_level(buf, level);
    if(cprefix != NULL) {
        len += sprintf(buf+len, ": %s", cprefix);
    } else {
        len += sprintf(buf+len, ": @%s():%d ", func, line);
    }
    p += len;
    
    va_start(list, fmt);
    len = vsprintf(buf + len, fmt, list);
    va_end(list);

    tail = p + len;
    p = (len >= 2) ? (tail - 2) : (p);
    while(p != tail) { /* replace last 2 chars that eq CRLF with blank */
        if(*p == '\r' || *p == '\n') {
            *p = ' ';
        }
        p++;
    }
    /* append tail CRLF */
    *p = '\r';
    *(p + 1) = '\n';
    *(p + 2) = '\0';

    oss_printf("%s", buf);
    return 0;
}


void hsl_log_all_enable (void)
{
    int i;
    for (i=0; i < hsl_log_module_num; i++) {
        hsl_log_detail[i].enable = 1;
    }
    return;
}

void hsl_log_all_disable (void)
{
    int i;
    for (i=0; i < hsl_log_module_num; i++) {
        hsl_log_detail[i].enable = 0;
    }
    return;
}

void hsl_log_all_setlevel (u_int16_t level)
{
    int i;
    for (i=0; i < hsl_log_module_num; i++) {
        hsl_log_detail[i].level = level;
    }
    return;
}

int hsl_log_module_conf(u_int16_t module, u_int16_t enable, u_int16_t level)
{
  /* Validate module id */
  if(module >= hsl_log_module_num)
    return -1;

  hsl_log_detail[module].enable = enable;
  hsl_log_detail[module].level = level;
  return 0;  
}

void hsl_log_dump_cfg(void)
{
#define WS_FMT "%-10s%-10s%-s"
    unsigned int i;
    char level_str[20];
    printk("\r\n");
    printk(WS_FMT"(%u-%u)\r\n", "module", "enabling", "level", HSL_LEVEL_ADMIN, HSL_LEVEL_DEBUG);
    for (i=0; i<hsl_log_module_num; i++) {
        hsl_add_log_level(level_str, hsl_log_detail[i].level);
        printk(WS_FMT"(%u)\r\n", hsl_log_detail[i].module_name,
                                 hsl_log_detail[i].enable ? "on":"off",
                                 level_str, 
                                 hsl_log_detail[i].level);
    }
    printk("\r\n");
    
    return;
}
int hsl_log_conf(char module_str[], u_int16_t enable, u_int16_t level)
{
    enum hsl_modules module_id;
    if (!module_str) {
        return -1;
    }

    if (0 == strcmp (module_str, "all")) {
        if (enable)
            hsl_log_all_enable();
        else
            hsl_log_all_disable();
            
        hsl_log_dump_cfg();
        return 0;
    } 
    
    printk("\n\rsetting %s enable(%u) level(%u)\r\n", module_str, enable, level);
    if (0 == strcmp (module_str, "common")) {
        module_id = HSL_LOG_COMMON;
    } else if (0 == strcmp (module_str, "general")) {
        module_id = HSL_LOG_GENERAL;
    } else if (0 == strcmp (module_str, "ifmgr")) {
        module_id = HSL_LOG_IFMGR;
    } else if (0 == strcmp (module_str, "msg")) {
        module_id = HSL_LOG_MSG;
    } else if (0 == strcmp (module_str, "fib")) {
        module_id = HSL_LOG_FIB;
    } else if (0 == strcmp (module_str, "fdb")) {
        module_id = HSL_LOG_FDB;
    } else if (0 == strcmp (module_str, "devdrv")) {
        module_id = HSL_LOG_DEVDRV;
    } else if (0 == strcmp (module_str, "pktdrv")) {
        module_id = HSL_LOG_PKTDRV;
    } else if (0 == strcmp (module_str, "platform")) {
        module_id = HSL_LOG_PLATFORM;
    } else if (0 == strcmp (module_str, "gen-pkt")) {
        module_id = HSL_LOG_GEN_PKT;
    } else if (0 == strcmp (module_str, "bpdu-pkt")) {
        module_id = HSL_LOG_BPDU_PKT;
    } else if (0 == strcmp (module_str, "arp-pkt")) {
        module_id = HSL_LOG_ARP_PKT;
    } else if (0 == strcmp (module_str, "igmp-pkt")) {
        module_id = HSL_LOG_IGMP_PKT;    
    } else {
        hsl_do_log("WARN", HSL_LOG_GENERAL, HSL_LEVEL_WARN,
            NULL, NULL, 0,
            "unknow module %s", module_str);
        return -1;
    }
    hsl_log_module_conf(module_id, enable, level);
    hsl_log_dump_cfg();
    
    return 0;
}


