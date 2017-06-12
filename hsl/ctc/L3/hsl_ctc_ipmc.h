#ifndef __HSL_CTC_IPMC__
#define __HSL_CTC_IPMC__
#include "sal_types.h"
#include "fwdu/fwdu_hal_id_mc.h"
#include "ctc_api.h"

#define IPMC_GROUP_MAX  5000

int hsl_ipv4_mc_add_mfc(hal_ipmc_group_info_t* ipmc_info);
int hsl_ipv4_mc_del_mfc(hal_ipmc_group_info_t* ipmc_info);

int hsl_ipmc_init();
#endif
