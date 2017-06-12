/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_SLOT_H_
#define _HAL_SLOT_H_

#define	HAL_FWD_SUCCESS                 0
#define	HAL_FWD_ERROR                   -1

#define HAL_FWD_MAX_MPLS_LABEL          3	/* ���MPLS��ǩ���� */
#define HAL_FWD_MAX_ECMP_COUNT          3	/* ���ECMP��һ������ */
#define HAL_FWD_LABEL_VALUE_INVALID     1048576

/* �·���ʱ����Ҫ����ת������XLPƽ̨ת������Ϊxlp_get_slot_mask��*/
#define HAL_FWD_SLOT_MASK_ALL           0xFFFFFFFF   /* ���а忨 */ 
#define HAL_FWD_SLOT_MASK(slot)         (1 << slot)  /* ָ���忨 */

#define HAL_FWD_SLOT_MIM         1  /* ��С�忨 */
#define HAL_FWD_SLOT_MAX         8  /* ���忨 */

#define HAL_FWD_MAX_CT_NUM              8  /* DS-TE֧�ֵ����CT���� */
#define HAL_FWD_MAX_LSP_NUM             16 /* P2MP֧�ֵ����LSP���� */

#define	HAL_FWD_OP_PUSH_SWAP            0
#define	HAL_FWD_OP_POP                  1

#endif /* _HAL_SLOT_H_ */
