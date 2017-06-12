/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_if.h"
#include "hal_vlan.h"
#include "hal_bridge.h"
#include "hal_oam.h"

int hal_efm_get_err_frames (unsigned int index, u_int64_t * no_of_errors)
{
    return 0;
}
int hal_efm_get_err_frames_secs (unsigned int index, u_int64_t * no_of_errors)
{
    return 0;
}
int hal_efm_reset_err_frame_second_count ()
{
    return 0;
}
int hal_efm_set_err_frame_seconds (u_int32_t no_of_error)
{
    return 0;
}
int hal_efm_set_err_frames (u_int32_t no_of_errors)
{
    return 0;
}
int hal_efm_set_frame_period_window (unsigned int index,
                                 u_int32_t frame_period_window)
{
    return 0;
}
int hal_efm_set_port_state (unsigned int index,
                        enum hal_efm_par_action local_par_action,
                        enum hal_efm_mux_action local_mux_action)
{
    return 0;
}
int hal_efm_set_symbol_period_window (unsigned int index,
                                  u_int64_t symbol_period_window)
{
    return 0;
}
int hal_set_cfm_trap_level_pdu (u_int8_t level, enum hal_cfm_pdu_type pdu)
{
    return 0;
}
int hal_set_oam_dest_addr (u_int8_t * dest_addr, enum hal_l2_proto proto)
{
    return 0;
}
int hal_set_oam_ether_type (u_int16_t ether_type, enum hal_l2_proto proto)
{
    return 0;
}
int hal_unset_cfm_trap_level_pdu (u_int8_t level, enum hal_cfm_pdu_type pdu)
{
    return 0;
}
