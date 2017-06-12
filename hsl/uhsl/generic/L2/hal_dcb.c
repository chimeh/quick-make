/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_dcb.h"

int hal_dcb_bridge_disable (char *bridge_name)
{
    return 0;
}
int hal_dcb_bridge_enable (char *bridge_name)
{
    return 0;
}
int hal_dcb_deinit (char *bridge_name)
{
    return 0;
}
int hal_dcb_disable_pfc_priority (char *bridge, s_int32_t ifindex, s_int8_t pri)
{
    return 0;
}
int hal_dcb_enable_pfc_priority (char *bridge, s_int32_t ifindex, s_int8_t pri)
{
    return 0;
}
int hal_dcb_ets_add_pri_to_tcg (char *bridge_name, s_int32_t ifindex,
                            u_int8_t tcgid, u_int8_t pri)
{
    return 0;
}
int hal_dcb_ets_assign_bw_to_tcgs (char *bridge_name, s_int32_t ifindex,
                               u_int16_t *bw)
{
    return 0;
}
int hal_dcb_ets_bridge_disable (char *bridge_name)
{
    return 0;
}
int hal_dcb_ets_bridge_enable (char *brigde_name)
{
    return 0;
}
int hal_dcb_ets_interface_disable (char *bridge_name, s_int32_t ifindex)
{
    return 0;
}
int hal_dcb_ets_interface_enable (char *bridge_name, s_int32_t ifindex)
{
    return 0;
}
int hal_dcb_ets_remove_pri_from_tcg (char *bridge_name, s_int32_t ifindex,
                                 u_int8_t tcgid, u_int8_t pri)
{
    return 0;
}
int hal_dcb_ets_set_application_priority (char *bridge_name, s_int32_t ifindex,
                                      u_int8_t sel, u_int16_t proto_id, 
                                      u_int8_t pri)
{
    return 0;
}
int hal_dcb_ets_unset_application_priority (char *bridge_name, s_int32_t ifindex,
                                        u_int8_t sel, u_int16_t proto_id, 
                                        u_int8_t pri)
{
    return 0;
}
int hal_dcb_get_pfc_stats (char *bridge_name, s_int32_t ifindex,
                             u_int64_t *pause_sent, u_int64_t *pause_rcvd )
{
    return 0;
}
int hal_dcb_global_disable (char *bridge_name)
{
    return 0;
}
int hal_dcb_init (char *bridge_name)
{
    return 0;
}
int hal_dcb_interface_disable (char *bridge_name, s_int32_t ifindex)
{
    return 0;
}
int hal_dcb_interface_enable (char *bridge_name, s_int32_t ifindex)
{
    return 0;
}
int hal_dcb_pfc_bridge_disable (char *bridge_name)
{
    return 0;
}
int hal_dcb_pfc_bridge_enable (char *bridge_name)
{
    return 0;
}
int hal_dcb_pfc_interface_disable (char *bridge_name, s_int32_t ifindex)
{
    return 0;
}
int hal_dcb_pfc_interface_enable (char *bridge_name, s_int32_t ifindex)
{
    return 0;
}
int hal_dcb_qcn_add_cnpv (char *bridge_name, s_int8_t cnpv, u_int8_t alternate_priority)
{
    return 0;
}
int hal_dcb_qcn_cp_disable (s_int32_t ifindex, u_int8_t cnpv)
{
    return 0;
}
int hal_dcb_qcn_cp_enable (s_int32_t ifindex, u_int8_t cnpv, u_int32_t sample_base,
                       float weight, u_int32_t min_hdr_octects)
{
    return 0;
}
int hal_dcb_qcn_deinit (char *bridge_name)
{
    return 0;
}
int hal_dcb_qcn_get_config (char *bridge_name, struct hal_qcn_data *data)
{
    return 0;
}
int hal_dcb_qcn_get_config_cp (u_int32_t ifindex, struct hal_cp_if_data *data)
{
    return 0;
}
int hal_dcb_qcn_get_config_cp_cpid (char *bridge_name,
                      struct hal_cp_data *data, u_int32_t cp_id)
{
    return 0;
}
int hal_dcb_qcn_init (char *bridge_name, u_int8_t transmit_priority)
{
    return 0;
}
int hal_dcb_qcn_remove_cnpv (char *bridge_name, s_int8_t cnpv)
{
    return 0;
}
int hal_dcb_qcn_set_cnm_priority (char *bridge_name, u_int8_t priority)
{
    return 0;
}
int hal_dcb_qcn_set_defense_mode (s_int32_t ifindex, u_int8_t cnpv,
                              u_int32_t defense_mode, u_int32_t alt_priority)
{
    return 0;
}
int hal_dcb_select_ets_mode (char *bridge_name, s_int32_t ifindex,
                         enum hal_dcb_mode mode)
{
    return 0;
}
int hal_dcb_select_pfc_mode (char *bridge_name, s_int32_t ifindex,
                         enum hal_dcb_mode mode)
{
    return 0;
}
int hal_dcb_set_pfc_cap (char *bridge_name, s_int32_t ifindex, u_int8_t cap)
{
    return 0;
}
int hal_dcb_set_pfc_lda (char *bridge_name, s_int32_t ifindex, u_int32_t lda)
{
    return 0;
}
