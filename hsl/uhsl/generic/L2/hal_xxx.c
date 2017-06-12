/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal.h"
#include "hal_types.h"
#include "hal_xxx.h"

int hal_xxx_add(unsigned int a, unsigned int b)
{
    int ret;
    if (HAL_OPS_CB_CHECK(hal_xxx_ops, xxx_add)) {
        ret = HAL_OPS_CB_CALL(hal_xxx_ops, xxx_add) (a, b);
        return (ret == 0) ? 0 : -1;
    }

    return 0;
}

int hal_xxx_del(unsigned int arg1, int arg2)
{
    int ret;
    if (HAL_OPS_CB_CHECK(hal_xxx_ops, xxx_del)) {
        ret = HAL_OPS_CB_CALL(hal_xxx_ops, xxx_del) (arg1, arg2);
        return (ret == 0) ? 0 : -1;
    }

    return 0;
}
