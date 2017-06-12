/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_H_
#define _HAL_H_

struct hal_ops {
    struct hal_xxx_ops *hal_xxx_ops;
    struct hal_example_ops *hal_example_ops;
    struct hal_auth_ops *hal_auth_ops;
	struct hal_bridge_ops *hal_bridge_ops;
};
extern struct hal_ops hal_ops_G;
#define HAL_OPS_CB_CHECK(mOPS, FN)  (hal_ops_G.mOPS &&  hal_ops_G.mOPS->FN)
#define HAL_OPS_CB_CALL(mOPS, FN)   (hal_ops_G.mOPS->FN)



/*
   Name: hal_init

   Description:
   Initialize the HAL component.

   Parameters:
   None

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int hal_init(void *zg);

/*
   Name: hal_deinit

   Description:
   Deinitialize the HAL component.

   Parameters:
   None

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int hal_deinit(void *zg);

int hal_fwd_init(void *hal_zg, struct hal_ops *hal_ops);
int hal_fwd_deinit(void *hal_zg, struct hal_ops *hal_ops);

#endif /* _HAL_H_ */
