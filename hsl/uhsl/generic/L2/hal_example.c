/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal.h"
#include "hal_types.h"
#include "hal_example.h"

int hal_example_add(unsigned int a, int b)
{
    int ret;
    if (HAL_OPS_CB_CHECK(hal_example_ops, example_add)) {
        ret = HAL_OPS_CB_CALL(hal_example_ops, example_add) (a, b);
        return (ret == 0) ? 0 : -1;
    }

    return 0;
}

int hal_example_del(unsigned int arg1, int arg2)
{
    int ret;
    if (HAL_OPS_CB_CHECK(hal_example_ops, example_del)) {
        ret = HAL_OPS_CB_CALL(hal_example_ops, example_del) (arg1, arg2);
        return (ret == 0) ? 0 : -1;
    }

    return 0;
}
