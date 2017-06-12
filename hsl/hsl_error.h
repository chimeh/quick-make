/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_ERROR_H_
#define _HSL_ERROR_H_

#define HSL_ERR_BASE                                              -100
/*
  Interface manager errors.
*/
#define HSL_IFMGR_ERR_BASE                                        (HSL_ERR_BASE - 100)
#define HSL_IFMGR_ERR_INVALID_PARAM                               (HSL_IFMGR_ERR_BASE - 1)
#define HSL_IFMGR_ERR_BINDING_SAME                                (HSL_IFMGR_ERR_BASE - 2)
#define HSL_IFMGR_ERR_IF_NOT_FOUND                                (HSL_IFMGR_ERR_BASE - 3)
#define HSL_IFMGR_ERR_BIND                                        (HSL_IFMGR_ERR_BASE - 4)
#define HSL_IFMGR_ERR_MEMORY                                      (HSL_IFMGR_ERR_BASE - 5)
#define HSL_IFMGR_ERR_INDEX                                       (HSL_IFMGR_ERR_BASE - 6)
#define HSL_IFMGR_ERR_NAME                                        (HSL_IFMGR_ERR_BASE - 7)
#define HSL_IFMGR_ERR_NULL_IF                                     (HSL_IFMGR_ERR_BASE - 8)
#define HSL_IFMGR_ERR_SYSTEM_L3                                   (HSL_IFMGR_ERR_BASE - 9)
#define HSL_IFMGR_ERR_OS_L3                                       (HSL_IFMGR_ERR_BASE - 10)
#define HSL_IFMGR_ERR_INVALID_ADDRESS                             (HSL_IFMGR_ERR_BASE - 11)
#define HSL_IFMGR_ERR_IP_ADDRESS                                  (HSL_IFMGR_ERR_BASE - 12)
#define HSL_IFMGR_ERR_OS_CB_ALREADY_REGISTERED                    (HSL_IFMGR_ERR_BASE - 13)
#define HSL_IFMGR_ERR_HW_CB_ALREADY_REGISTERED                    (HSL_IFMGR_ERR_BASE - 14)
#define HSL_IFMGR_ERR_INIT                                        (HSL_IFMGR_ERR_BASE - 15)
#define HSL_IFMGR_ERR_DEINIT                                      (HSL_IFMGR_ERR_BASE - 16)
#define HSL_IFMGR_ERR_AGG_EXISTS                                  (HSL_IFMGR_ERR_BASE - 17)
#define HSL_IFMGR_ERR_INVALID_MODE                                (HSL_IFMGR_ERR_BASE - 18)
#define HSL_IFMGR_ERR_HW_TRUNK_ADD                                (HSL_IFMGR_ERR_BASE - 19)
#define HSL_IFMGR_ERR_HW_TRUNK_PORT_UPDATE                        (HSL_IFMGR_ERR_BASE - 20)
#define HSL_IFMGR_ERR_INVALID_VLAN_CLASSIFIER_TYPE                (HSL_IFMGR_ERR_BASE - 21)
#define HSL_IFMGR_ERR_NO_HW_PORT                                  (HSL_IFMGR_ERR_BASE - 22)
#define HSL_IFMGR_ERR_HW_FAILURE                                  (HSL_IFMGR_ERR_BASE - 23)
#define HSL_IFMGR_ERR_INVALID_8021x_PORT_STATE                    (HSL_IFMGR_ERR_BASE - 24)
#define HSL_IFMGR_ERR_NO_RESOURCE_AVAILABLE                       (HSL_IFMGR_ERR_BASE - 25)
#define HSL_IFMGR_ERR_DUPLICATE                                   (HSL_IFMGR_ERR_BASE - 26)
#define HSL_IFMGR_ERR_HW_SEC_HWADDR                               (HSL_IFMGR_ERR_BASE - 27)
#define HSL_IFMGR_ERR_OS_SEC_HWADDR                               (HSL_IFMGR_ERR_BASE - 28)
#define HSL_IFMGR_ERR_INVALID_FIB_ID                              (HSL_IFMGR_ERR_BASE - 29)
#define HSL_IFMGR_ERR_INVALID_FIB                                 (HSL_IFMGR_ERR_BASE - 30)
#define HSL_IFMGR_ERR_IF_FIB_MISMATCH                             (HSL_IFMGR_ERR_BASE - 31)

/*
  FIB management errors.
*/
#define HSL_ERR_FIB_BASE                                           (HSL_ERR_BASE - 200)
#define HSL_FIB_ERR_NH_ALREADY_PRESENT_FOR_PREFIX                  (HSL_ERR_FIB_BASE - 1)
#define HSL_FIB_ERR_NH_NOT_PRESENT_FOR_PREFIX                      (HSL_ERR_FIB_BASE - 2)
#define HSL_FIB_ERR_NOMEM                                          (HSL_ERR_FIB_BASE - 3)
#define HSL_FIB_ERR_LINK_NH_PREFIX                                 (HSL_ERR_FIB_BASE - 4)
#define HSL_FIB_ERR_NH_NOT_FOUND                                   (HSL_ERR_FIB_BASE - 5)
#define HSL_FIB_ERR_PREFIX_NOT_FOUND                               (HSL_ERR_FIB_BASE - 6)
#define HSL_FIB_ERR_HW_NH_NOT_FOUND                                (HSL_ERR_FIB_BASE - 7)
#define HSL_FIB_ERR_INVALID_PARAM                                  (HSL_ERR_FIB_BASE - 8)
#define HSL_FIB_ERR_HW_OPERATION_FAILED                            (HSL_ERR_FIB_BASE - 9)
#define HSL_FIB_ERR_WRONG_ND_OPT_TYPE                              (HSL_ERR_FIB_BASE -10)
#define HSL_FIB_ERR_INVALID_ARP_SRC                                (HSL_ERR_FIB_BASE -11)
#define HSL_FIB_ERR_INVALID_ND_SRC                                 (HSL_ERR_FIB_BASE -12)
#define HSL_FIB_ERR_NOT_INITIALIZED                                (HSL_ERR_FIB_BASE -13)
#define HSL_FIB_ERR_DB_OPER                                        (HSL_ERR_FIB_BASE -14)
#define HSL_FIB_ERR_INVALID_ID                                     (HSL_ERR_FIB_BASE -15)
#define HSL_FIB_ERR_TBL_EXISTS                                     (HSL_ERR_FIB_BASE -16)
#define HSL_FIB_ERR_TBL_NOT_FOUND                                  (HSL_ERR_FIB_BASE -17)
#define HSL_FIB_ERR_MISMATCH_IF_FIB_ID                             (HSL_ERR_FIB_BASE -18)

/*
  Bridging errors.
*/
#define HSL_ERR_BRIDGE_BASE                                         (HSL_ERR_BASE - 300)
#define HSL_ERR_BRIDGE_NOMEM                                        (HSL_ERR_BRIDGE_BASE - 1)
#define HSL_ERR_BRIDGE_EEXISTS                                      (HSL_ERR_BRIDGE_BASE - 2)
#define HSL_ERR_BRIDGE_NOTFOUND                                     (HSL_ERR_BRIDGE_BASE - 3)
#define HSL_ERR_BRIDGE_INVALID_PARAM                                (HSL_ERR_BRIDGE_BASE - 4)
#define HSL_ERR_BRIDGE_PORT_EXISTS                                  (HSL_ERR_BRIDGE_BASE - 5)
#define HSL_ERR_BRIDGE_PORT_NOT_EXISTS                              (HSL_ERR_BRIDGE_BASE - 5)
#define HSL_ERR_BRIDGE_VID_NOT_EXISTS                               (HSL_ERR_BRIDGE_BASE - 6)
#define HSL_ERR_BRIDGE_HWCB_ALREADY_REGISTERED                      (HSL_ERR_BRIDGE_BASE - 7)
#define HSL_ERR_BRIDGE_RATELIMIT                                    (HSL_ERR_BRIDGE_BASE - 8)
 

#endif /* _HSL_ERROR_H_ */
