/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_flowctrl.h"

int hal_flow_control_deinit (void)
{
    return 0;
}
int hal_flow_control_init (void)
{
    return 0;
}
int hal_flow_control_set (unsigned int ifindex, unsigned char direction)
{
    return 0;
}
int hal_flow_control_statistics (unsigned int ifindex, unsigned char *direction,
                             int *rxpause, int *txpause)
{
    return 0;
}
int hal_flow_ctrl_pause_watermark_set (u_int32_t port, u_int16_t wm_pause)
{
    return 0;
}
