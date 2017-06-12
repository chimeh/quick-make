/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_ratelimit.h"

int hal_l2_bcast_discards_get (unsigned int ifindex, unsigned int *discards)
{
    return 0;
}
int hal_l2_dlf_bcast_discards_get (unsigned int ifindex, unsigned int *discards)
{
    return 0;
}
int hal_l2_mcast_discards_get (unsigned int ifindex, unsigned int *discards)
{
    return 0;
}
int hal_l2_ratelimit_bcast (unsigned int ifindex,
                        unsigned char level, unsigned char fraction)
{
    return 0;
}
int hal_l2_ratelimit_bcast_mcast (unsigned int ifindex,
                              unsigned char level, unsigned char fraction)
{
    return 0;
}
int hal_l2_ratelimit_dlf_bcast (unsigned int ifindex,
                            unsigned char level, unsigned char fraction)
{
    return 0;
}
int hal_l2_ratelimit_mcast (unsigned int ifindex,
                        unsigned char level, unsigned char fraction)
{
    return 0;
}
int hal_l2_ratelimit_only_broadcast (unsigned int ifindex,
                                 unsigned char level, unsigned char fraction)
{
    return 0;
}
int hal_ratelimit_deinit (void)
{
    return 0;
}
int hal_ratelimit_init (void)
{
    return 0;
}
