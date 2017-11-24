#ifndef __NPAS_DBG_H
#define __NPAS_DBG_H

#define NPAS_DBG_M_NAME_LEN 64
struct hal_msg_debug_hsl_req {
    unsigned char module_str[NPAS_DBG_M_NAME_LEN];
    u_int16_t enable;
    u_int16_t level;
};

#endif