/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_SLOT_H_
#define _HAL_SLOT_H_

#define	HAL_FWD_SUCCESS                 0
#define	HAL_FWD_ERROR                   -1

#define HAL_FWD_MAX_MPLS_LABEL          3	/* 最大MPLS标签个数 */
#define HAL_FWD_MAX_ECMP_COUNT          3	/* 最大ECMP下一跳个数 */
#define HAL_FWD_LABEL_VALUE_INVALID     1048576

/* 下发的时候需要进行转换。如XLP平台转换函数为xlp_get_slot_mask。*/
#define HAL_FWD_SLOT_MASK_ALL           0xFFFFFFFF   /* 所有板卡 */ 
#define HAL_FWD_SLOT_MASK(slot)         (1 << slot)  /* 指定板卡 */

#define HAL_FWD_SLOT_MIM         1  /* 最小板卡 */
#define HAL_FWD_SLOT_MAX         8  /* 最大板卡 */

#define HAL_FWD_MAX_CT_NUM              8  /* DS-TE支持的最大CT个数 */
#define HAL_FWD_MAX_LSP_NUM             16 /* P2MP支持的最大LSP个数 */

#define	HAL_FWD_OP_PUSH_SWAP            0
#define	HAL_FWD_OP_POP                  1

#endif /* _HAL_SLOT_H_ */
