#ifndef __FWDU_HAL_NLMSG_H
#define __FWDU_HAL_NLMSG_H

#define NPAS_NLMSG_DATA_LEN 2048

#define NETLK_NLMMSG_TYPE_GENERIC 1
/**
 @brief send msg to kernel
 @param[in] data
 @param[in] datalen, <= NPAS_NLMSG_DATA_LEN
 @param[in] msg_type
 @return 0, success, <0 ,failed
*/
int npas_nlmsg_sendto_kernel (struct netlsock *ns, void *data, unsigned int datalen, unsigned int  msg_type);
#endif


