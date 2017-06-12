#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"

/* Broadcom includes. */
//#include "bcm_incl.h"

/* HAL includes. */
#include "hal_netlink.h"
#include "hal_msg.h"

/* HSL includes.*/
#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"
#include "hsl_ctc_pkt.h"
#include "hsl_comm.h"
#include "hsl_msg.h"

//#include <sys/types.h>
//#include <sys/stat.h>
//#include <fcntl.h>
//#include <sys/mman.h>
//#include <string.h>
//#include <unistd.h>
//#include "bcm/field.h"
//#include "bcm/types.h"
//#include "bcm/error.h"
#include "bcm_cap.h"
#include "hal/layer4/acl/access_list_rule.h"
#include "layer4/qos/qos.h"
#include "hal/layer4/qos/qos_rule.h"
#include "hal/layer4/hal_l4_api.h"


int hsl_msg_recv_cap_info_show(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int	slot, slice;
	cap_stat_t	s;

	char cap_info[1000] = {0};
	char cap_tem[50];
	for (slot = 0; slot < MAX_LC_NUM; slot++) {
		if (OK != cap_get_stat(slot, &s))
			continue;
		memset(cap_tem, 0, 50);
		sprintf(cap_tem, "    slot%d:\n", slot);
		strcat(cap_info, cap_tem);
		memset(cap_tem, 0, 50);
		sprintf(cap_tem, "        IFP:\n");
		strcat(cap_info, cap_tem);
		if (CTC_ACL_BOLCK_PER_UNIT <= 0) {
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "            NOT SUPPORT\n");
			strcat(cap_info, cap_tem);
		}


		for (slice = 0; slice < CTC_ACL_BOLCK_PER_UNIT; slice++) {			

			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "        slice %2d used %3d, free %3d",
				slice, s.ifp_slice[slice].entry_used, s.ifp_slice[slice].entry_free);
			strcat(cap_info, cap_tem);
			if (s.ifp_slice[slice].type > 0 && s.ifp_slice[slice].type < MAX_CAP_SUB) {
				memset(cap_tem, 0, 50);
				sprintf(cap_tem, ", type %s", cap_sub_name_get(s.ifp_slice[slice].type));
				strcat(cap_info, cap_tem);
			}
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "\n");
			strcat(cap_info, cap_tem);
		
		}
#if 0
		memset(cap_tem, 0, 50);
		sprintf(cap_tem, "        EFP:\n");
		strcat(cap_info, cap_tem);
		if (BCM_EFP_SLICE_PER_UNIT <= 0) {
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "            NOT SUPPORT\n");
			strcat(cap_info, cap_tem);
		}
		for (slice = 0; slice < BCM_EFP_SLICE_PER_UNIT; slice++) {
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "        slice %2d used %3d, free %3d",
				slice, s.efp_slice[slice].entry_used, s.efp_slice[slice].entry_free);
			strcat(cap_info, cap_tem);
			if (s.efp_slice[slice].type > 0 && s.efp_slice[slice].type < MAX_CAP_SUB) {
				memset(cap_tem, 0, 50);
				sprintf(cap_tem, ", type %s", cap_sub_name_get(s.efp_slice[slice].type));
				strcat(cap_info, cap_tem);
			}
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "\n");
			strcat(cap_info, cap_tem);
		}

		memset(cap_tem, 0, 50);
		sprintf(cap_tem, "        VFP:\n");
		strcat(cap_info, cap_tem);
		if (BCM_VFP_SLICE_PER_UNIT <= 0) {
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "            NOT SUPPORT\n");
			strcat(cap_info, cap_tem);
		}
		for (slice = 0; slice < BCM_VFP_SLICE_PER_UNIT; slice++) {
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "        slice %2d used %3d, free %3d",
				slice, s.vfp_slice[slice].entry_used, s.vfp_slice[slice].entry_free);
			strcat(cap_info, cap_tem);
			if (s.vfp_slice[slice].type > 0 && s.vfp_slice[slice].type < MAX_CAP_SUB) {
				memset(cap_tem, 0, 50);
				sprintf(cap_tem, ", type %s", cap_sub_name_get(s.vfp_slice[slice].type));
				strcat(cap_info, cap_tem);
			}
			memset(cap_tem, 0, 50);
			sprintf(cap_tem, "\n");
			strcat(cap_info, cap_tem);
		}
#endif		
	}

	cap_info[strlen(cap_info)] = '\0';
	//memset(cap_tem, 0, 50);
	//sprintf(cap_tem, "\0");
	//strcat(cap_info, cap_tem);
	

	//printk("cap_info = %s\r\n", cap_info);
 	hsl_sock_post_msg (sock, HAL_L4_CAP_INFO_SHOW, hdr->nlmsg_seq, 0, cap_info, 1000);
	//HSL_MSG_PROCESS_RETURN (sock, hdr, -ENOTSUPP);
	return OK;
}

