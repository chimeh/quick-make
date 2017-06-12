/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_DCB_H_
#define _HAL_DCB_H_


#define HAL_DCB_NUM_DEFAULT_TCGS   8
#define HAL_DCB_NUM_USER_PRIORITY    8

enum hal_dcb_mode
{
  HAL_DCB_MODE_ON = 0,
  HAL_DCB_MODE_AUTO = 1
};

struct hal_qcn_data
{
  bool master_enable; 
  int cnm_transmit_priority; 
  int discarded_frames; 
  int err_port_cnt;
  char *err_port_list[10]; 
};


struct hal_cp_data
//struct cp_data
{
  char *ifname;
  u_char cp_mac_addr [6];
  u_int32_t cp_id;
  u_int32_t qsp;
  u_int32_t qlen;
  u_int32_t qlenold;
  float weight;
  s_int32_t qoffset;
  s_int32_t qdelta;
  s_int32_t fb;
  s_int32_t enqued;
  u_int32_t samplebase;
  u_int32_t transmitted_frames;
  u_int32_t minhdroctet;
  u_int32_t transmitted_cnms;
  u_int32_t discarded_frames;
};

struct hal_cp_if_data
//struct cp_if_data
{
  struct interface *ifp;
  int cp_count;
//  struct cp_data cp_data[8];
  struct hal_cp_data cp_data[8];
};

s_int32_t
hal_dcb_init (char *bridge_name);

s_int32_t 
hal_dcb_deinit (char *bridge_name);

s_int32_t 
hal_dcb_bridge_enable (char *bridge_name);

s_int32_t 
hal_dcb_bridge_disable (char *bridge_name);

s_int32_t
hal_dcb_ets_bridge_enable (char *brigde_name);

s_int32_t
hal_dcb_ets_bridge_disable (char *bridge_name);

s_int32_t
hal_dcb_interface_enable (char *bridge_name, s_int32_t ifindex);

s_int32_t
hal_dcb_interface_disable (char *bridge_name, s_int32_t ifindex);

s_int32_t
hal_dcb_ets_interface_enable (char *bridge_name, s_int32_t ifindex);

s_int32_t
hal_dcb_ets_interface_disable (char *bridge_name, s_int32_t ifindex);

s_int32_t
hal_dcb_select_ets_mode (char *bridge_name, s_int32_t ifindex, 
                         enum hal_dcb_mode mode);

s_int32_t
hal_dcb_ets_add_pri_to_tcg (char *bridge_name, s_int32_t ifindex, 
                            u_int8_t tcgid, u_int8_t pri);

s_int32_t
hal_dcb_ets_remove_pri_from_tcg (char *bridge_name, s_int32_t ifindex, 
                                 u_int8_t tcgid, u_int8_t pri);

s_int32_t 
hal_dcb_ets_assign_bw_to_tcgs (char *bridge_name, s_int32_t ifindex, 
                               u_int16_t *bw);

s_int32_t
hal_dcb_ets_set_application_priority (char *bridge_name, s_int32_t ifindex, 
                                      u_int8_t sel, u_int16_t proto_id, 
                                      u_int8_t pri);

s_int32_t
hal_dcb_ets_unset_application_priority (char *bridge_name, s_int32_t ifindex, 
                                        u_int8_t sel, u_int16_t proto_id, 
                                        u_int8_t pri);


/* DCB-PFC related routines */
s_int32_t
hal_dcb_pfc_bridge_enable (char *bridge_name);

s_int32_t
hal_dcb_pfc_bridge_disable (char *bridge_name);

s_int32_t
hal_dcb_enable_pfc_priority (char *bridge, s_int32_t ifindex, s_int8_t pri);

s_int32_t
hal_dcb_disable_pfc_priority (char *bridge, s_int32_t ifindex, s_int8_t pri);

s_int32_t
hal_dcb_set_pfc_cap (char *bridge_name, s_int32_t ifindex, u_int8_t cap);

s_int32_t
hal_dcb_set_pfc_lda (char *bridge_name, s_int32_t ifindex, u_int32_t lda);

s_int32_t
hal_dcb_select_pfc_mode (char *bridge_name, s_int32_t ifindex,
                         enum hal_dcb_mode mode);

s_int32_t
hal_dcb_pfc_interface_enable (char *bridge_name, s_int32_t ifindex);

s_int32_t
hal_dcb_pfc_interface_disable (char *bridge_name, s_int32_t ifindex);

s_int32_t
hal_dcb_get_pfc_stats (char *bridge_name, s_int32_t ifindex,
                             u_int64_t *pause_sent, u_int64_t *pause_rcvd );
/* QCN hal functions */

s_int32_t 
hal_dcb_qcn_init (char *bridge_name, u_int8_t transmit_priority);

s_int32_t 
hal_dcb_qcn_deinit (char *bridge_name); 

s_int32_t 
hal_dcb_global_disable (char *bridge_name);

s_int32_t 
hal_dcb_qcn_set_defense_mode (s_int32_t ifindex, u_int8_t cnpv, 
                              u_int32_t defense_mode, u_int32_t alt_priority);
s_int32_t 
hal_dcb_qcn_add_cnpv (char *bridge_name, s_int8_t cnpv, u_int8_t alternate_priority);

s_int32_t 
hal_dcb_qcn_remove_cnpv (char *bridge_name, s_int8_t cnpv);

s_int32_t 
hal_dcb_qcn_cp_enable (s_int32_t ifindex, u_int8_t cnpv, u_int32_t sample_base, 
                       float weight, u_int32_t min_hdr_octects);
s_int32_t 
hal_dcb_qcn_cp_disable (s_int32_t ifindex, u_int8_t cnpv);

s_int32_t 
hal_dcb_qcn_set_cnm_priority (char *bridge_name, u_int8_t priority);

s_int32_t  
hal_dcb_qcn_get_config (char *bridge_name, struct hal_qcn_data *data);

s_int32_t  
hal_dcb_qcn_get_config_cp (u_int32_t ifindex, struct hal_cp_if_data *data);

s_int32_t
hal_dcb_qcn_get_config_cp_cpid (char *bridge_name, 
                      struct hal_cp_data *data, u_int32_t cp_id);

#endif /* __HAL_DCB_H__ */
