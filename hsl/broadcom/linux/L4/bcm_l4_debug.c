#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"

/* Broadcom includes. */
#include "bcm_incl.h"

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
#include "hsl_bcm_pkt.h"
#include "hsl_comm.h"
#include "hsl_msg.h"

struct debug_s{
	int value;
};

int hsl_debug_ipcls = 0;
int hsl_msg_recv_l4_debug(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	struct debug_s *debug;

	debug = (struct debug_s *)msgbuf;

	hsl_debug_ipcls = debug->value;

	HSL_MSG_PROCESS_RETURN (sock, hdr, 0);

	return 0;
}
