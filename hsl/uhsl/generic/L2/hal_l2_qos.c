/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_l2_qos.h"

int hal_l2_qos_default_user_priority_get (unsigned int ifindex,
                                      unsigned char *user_priority)
{
    return 0;
}
int hal_l2_qos_default_user_priority_set (unsigned int ifindex,
                                      unsigned char user_priority)
{
    return 0;
}
int hal_l2_qos_deinit (void)
{
    return 0;
}
int hal_l2_qos_init (void)
{
    return 0;
}
int hal_l2_qos_regen_user_priority_get (unsigned int ifindex,
                                    unsigned char *regen_user_priority)
{
    return 0;
}
int hal_l2_qos_regen_user_priority_set (unsigned int ifindex,
                                    unsigned char recvd_user_priority,
                                    unsigned char regen_user_priority)
{
    return 0;
}
int hal_l2_qos_traffic_class_get (unsigned int ifindex,
                              unsigned char user_priority,
                              unsigned char traffic_class,
                              unsigned char traffic_class_value)
{
    return 0;
}
int hal_l2_qos_traffic_class_set (unsigned int ifindex,
                              unsigned char user_priority,
                              unsigned char traffic_class,
                              unsigned char traffic_class_value)
{
    return 0;
}
int hal_l2_traffic_class_status_set (unsigned int ifindex,
                                 unsigned int traffic_class_enabled)
{
    return 0;
}
