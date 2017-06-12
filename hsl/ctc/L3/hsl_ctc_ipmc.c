#include "hsl_ctc_ipmc.h"
#include "fwdu/fwdu_hal_id_mc.h"
#include "ctc_api.h"
#include "hsl_oss.h"
#include "hsl_types.h"
#include "ctc_if_portmap.h"
#include "ctc_hash.h"
#include "ctc_error.h"
#include "ctc_api.h"
#include "ctc_ipuc.h"
#include "ctc_port_mapping_cli.h"
//#include "sys_greatbelt_ipmc_db.h"

#include "sal.h"

extern int32 sys_get_ipmc_group_member(ctc_ipmc_group_info_t *p_group, ctc_ipmc_member_info_t *ipmc_member, int *mem_cnt);

ipi_sem_id ipmc_mutex;
#define HSL_IPMC_LOCK        oss_sem_lock(OSS_SEM_MUTEX, ipmc_mutex, OSS_WAIT_FOREVER)
#define HSL_IPMC_UNLOCK      oss_sem_unlock(OSS_SEM_MUTEX, ipmc_mutex)

#define RET_NEED_DEL_GROUP 2000

static ctc_ipmc_group_info_t ipmc_group_info;  /*配置信息存储结构体，由于结构太大做全局变量分配*/
static ctc_ipmc_group_info_t get_ipmc_group_info;
struct ipmc_manage
{
	bool is_used;
	uint16 member;
};
static struct ipmc_manage ipmc_group[IPMC_GROUP_MAX];


int init_ipmc_group(void)
{
	int ret = 0;
	memset(ipmc_group, 0, IPMC_GROUP_MAX*sizeof(struct ipmc_manage));
	return 0;
}

int  alloc_ipmc_group(uint16 *group_id)
{
	int i = 0;
	for (i=0; i<IPMC_GROUP_MAX; i++) {
		if (!ipmc_group[i].is_used) {
			ipmc_group[i].is_used = TRUE;
			*group_id = i;
			return 0;
		}
	}
	return -1;
}

int alloc_ipmc_group_by_id(uint16 group_id)
{
	if (group_id > IPMC_GROUP_MAX-1) {
		return -1;
	}

	ipmc_group[group_id].is_used = TRUE;
	ipmc_group[group_id].member  = 0;
	return 0;
}

int ipmc_group_add_member(uint16 group_id, uint16 member)
{
	if (group_id > IPMC_GROUP_MAX-1) {
		return -1;
	}
	if (!ipmc_group[group_id].is_used) {
		return -2;
	}
	
	ipmc_group[group_id].member  += member;
	return 0;
}

int ipmc_group_del_member(uint16 group_id, uint16 member)
{
	if (group_id > IPMC_GROUP_MAX-1) {
		return -1;
	}
	if (!ipmc_group[group_id].is_used) {
		return -2;
	}

	if (ipmc_group[group_id].member == 0) {
		return RET_NEED_DEL_GROUP;
	}

	ipmc_group[group_id].member -= member;
	if (ipmc_group[group_id].member == 0) {
		return RET_NEED_DEL_GROUP;
	}

	return 0;
	
}


bool is_alloc_ipmc_group(uint16 group_id)
{
	
	return ipmc_group[group_id].is_used;
	
}

int free_ipmc_group(uint16 group_id)
{
	if (group_id > IPMC_GROUP_MAX-1) 
		return -1;
	ipmc_group[group_id].is_used = FALSE;
	ipmc_group[group_id].member  = 0;
	return 0;
}


int hsl_ipmc_init()
{
	int ret =0;
	hal_ipmc_group_info_t ipmc_info;
	init_ipmc_group();
	
	ret = oss_sem_new ("IPMU_MUTEX", OSS_SEM_MUTEX, 0, NULL, &ipmc_mutex);
	if (ret < 0) {
		printk ("hsl_ipmc_init oss_sem_new failed!\n");
		return ret;
	}

	/*ipmc_info.ip_version = 0;
	ipmc_info.group_id = 200;
	ipmc_info.address.group_addr = 0xE9010101;
	ipmc_info.group_ip_mask_len = 32;
	ipmc_info.address.src_addr = 0x0a0a0a01;
	ipmc_info.src_ip_mask_len = 32;
	ipmc_info.member_number = 4;
	ipmc_info.ifindex[0] = 5032;
	ipmc_info.ifindex[1] = 5033;
	ipmc_info.ifindex[2] = 5034;
	ipmc_info.ifindex[3] = 5035;

	ipmc_info.rpf_intf_valid[0] = 1;
	ipmc_info.rpf_intf_ifindex[0] = 5032;*/

	
	memset (&ipmc_group_info, 0,sizeof(ctc_ipmc_group_info_t));


	//hsl_ipv4_mc_add_mfc(&ipmc_info);
	return 0;
}



int hsl_ipv4_mc_add_mfc(hal_ipmc_group_info_t* ipmc_info)
{
	ctc_ipmc_group_info_t *p_group = NULL;
	int ret = 0;
	int i,j, k;
	uint8 index = 0;
	int rpf_intf_exist = 0; 
	uint8 gchip;
	ctc_ipmc_member_info_t ipmc_member[CTC_IPMC_MAX_MEMBER_PER_GROUP];
	int cnt = 0;
	int add_flag = TRUE;

	ctc_get_gchip_id(0, &gchip);
	
	HSL_IPMC_LOCK;
	
	memset(&ipmc_group_info, 0, sizeof(ctc_ipmc_group_info_t));
	if (ipmc_info->ip_version != 0) {  /*非IPV4*/
		ret = -1;
		goto out;
	}
	//printk("hsl_ipv4_mc_add_mfc: ip_version: %d, id %d, group_id %08x,source = 0x%08x, inifindex %d\r\n", ipmc_info->ip_version, ipmc_info->group_id, ipmc_info->address.group_addr, ipmc_info->address.src_addr, ipmc_info->rpf_intf_ifindex[i]);
	ipmc_group_info.ip_version  = ipmc_info->ip_version;
	ipmc_group_info.group_id    = ipmc_info->group_id;
	ipmc_group_info.address.ipv4.group_addr = ipmc_info->address.group_addr;
	ipmc_group_info.group_ip_mask_len = ipmc_info->group_ip_mask_len;
	ipmc_group_info.address.ipv4.src_addr = ipmc_info->address.src_addr;
	ipmc_group_info.src_ip_mask_len = ipmc_info->src_ip_mask_len;
	ipmc_group_info.flag |= CTC_IPMC_FLAG_RPF_CHECK;
	//ipmc_group_info.address.ipv4.vrfid = ipmc_info->address.ipv4.vrfid;

	if (is_alloc_ipmc_group(ipmc_group_info.group_id)) {
		printk("hsl_ipv4_mc_add_mfc-1-:is_alloc_ipmc_group\r\n");
		//ctc_ipmc_remove_group(&ipmc_group_info);
		//free_ipmc_group(ipmc_group_info.group_id);
		goto member_update;
	}
	
	ret = alloc_ipmc_group_by_id (ipmc_group_info.group_id); 
	if (ret < 0) {
		printk("alloc_ipmc_group_by_id failed !\n");
		goto out;
	}
	
	//printk ("ctc_ipmc_add_group, \r\n");
	ret = ctc_ipmc_add_group(&ipmc_group_info);
	if (ret < 0) {
		printk ("ctc_ipmc_add_group failed, ret=%d\n", ret);
		free_ipmc_group(ipmc_group_info.group_id);
		goto out;
	}
	
member_update:
	sal_memset(&get_ipmc_group_info,  0 , sizeof(ctc_ipmc_group_info_t));
	get_ipmc_group_info.ip_version = ipmc_info->ip_version;
	get_ipmc_group_info.address.ipv4.group_addr = ipmc_info->address.group_addr;
	get_ipmc_group_info.address.ipv4.src_addr   = ipmc_info->address.src_addr;
	get_ipmc_group_info.group_ip_mask_len = ipmc_info->group_ip_mask_len;
	get_ipmc_group_info.src_ip_mask_len   = ipmc_info->src_ip_mask_len;

	sys_get_ipmc_group_member(&get_ipmc_group_info, ipmc_member, &cnt);	

	/*add member */
	j = 0;
	if (ipmc_info->member_number > 0) {
		for (i = 0; i < ipmc_info->member_number; i++) {
			if (gchip != CTC_MAP_GPORT_TO_GCHIP(IFINDEX_TO_GPORT(ipmc_info->ifindex[i]))) {
				continue;
			}
			/*judge is already member*/
			add_flag=TRUE;
			for (k=0; k<cnt; k++) {
				if (ipmc_member[k].global_port == IFINDEX_TO_GPORT(ipmc_info->ifindex[i])) {
					add_flag=FALSE;
				}
			}
			//ipmc_group_info.member_number   = 1;//ipmc_info->member_number;
			//ipmc_group_info.ipmc_member[0].vlan_id = ipmc_info->ipmc_member[0].vlan_id
			if (add_flag) {
				ipmc_group_info.ipmc_member[j].global_port = IFINDEX_TO_GPORT(ipmc_info->ifindex[i]);
				ipmc_group_info.ipmc_member[j].l3_if_type  = CTC_L3IF_TYPE_PHY_IF;
				j++;
			}
		}
		ipmc_group_info.member_number = j;
		if (ipmc_group_info.member_number > 0) {
			//ipmc_group_info.flag = ipmc_info->flag;
			printk ("ctc_ipmc_add_member, \r\n");
			ret = ctc_ipmc_add_member(&ipmc_group_info);
			if (ret < 0) {
				printk("ctc_ipmc_add_member failed, ret=%d\n", ret);
				goto remove_member;
			}
		}
	}


	for (i = 0; i < HAL_IPMC_MAX_RPF_IF; i++) {
	    if (ipmc_info->rpf_intf_valid[i] == 1) {
	        ipmc_group_info.rpf_intf_valid[i] = 1;
			ipmc_group_info.rpf_intf[i] =  ctc_gport_to_l3ifid(IFINDEX_TO_GPORT(ipmc_info->rpf_intf_ifindex[i]));
			rpf_intf_exist = 1;
	    }
	}
	if (rpf_intf_exist == 1) {
	    ret = ctc_ipmc_update_rpf(&ipmc_group_info);
	    if (ret < 0) {
	        printk("ctc_ipmc_update_rpf failed, ret=%d\n", ret);
	        goto remove_member;
	    }
	}
	
	ret = ipmc_group_add_member(ipmc_group_info.group_id, ipmc_group_info.member_number);
	if (ret < 0) {
		printk("ipmc_group_add_member failed , ret = %d\n", ret );
		hsl_ipv4_mc_del_mfc(ipmc_info);
		goto remove_member;
	}
	
remove_member:
	sal_memset(ipmc_group_info.ipmc_member, 0, sizeof(ctc_ipmc_member_info_t)*CTC_IPMC_MAX_MEMBER_PER_GROUP);
	ipmc_group_info.member_number = 0;
	/*remove member*/
	j=0;
	for (k=0; k<cnt; k++) {
		for (i=0; i<ipmc_info->member_number; i++) {
			if (ipmc_member[k].global_port == IFINDEX_TO_GPORT(ipmc_info->ifindex[i])) {
				break;
			}
			
		}
		if (i == ipmc_info->member_number) { /*need remove*/
			ipmc_group_info.ipmc_member[j].global_port = ipmc_member[k].global_port;
			ipmc_group_info.ipmc_member[j].l3_if_type  = CTC_L3IF_TYPE_PHY_IF;
			j++;
		}
		
	}
	ipmc_group_info.member_number =j;
	ret = ctc_ipmc_remove_member(&ipmc_group_info);
	if (ret < 0) {
		printk("ctc_ipmc_remove_member , failed, g_port=%d, ret=%d\n", ipmc_group_info.ipmc_member[0].global_port, ret);
	}
	
	
out:
	HSL_IPMC_UNLOCK;
	return ret;
}

int hsl_ipv4_mc_del_mfc(hal_ipmc_group_info_t* ipmc_info)
{
	ctc_ipmc_group_info_t *p_group = NULL;
	int ret = 0;
	int i;
	HSL_IPMC_LOCK;
	sal_memset(&ipmc_group_info, 0, sizeof(ctc_ipmc_group_info_t));
	sal_memset(&get_ipmc_group_info, 0, sizeof(ctc_ipmc_group_info_t));
	if (ipmc_info->ip_version != 0) {  /*非IPV4*/
		ret = -1;
		goto out;
	}
	
	//ipmc_group_info.ip_version      = CTC_IP_VER_4;
	ipmc_group_info.ip_version  = ipmc_info->ip_version;
    //ipmc_group_info.member_number   = 1;
	printk("hsl_ipv4_mc_del_mfc: ip_version: %d,groupid:%d, group %08x, %d,source = 0x%08x, %d\r\n", ipmc_info->ip_version,ipmc_info->group_id, ipmc_info->address.group_addr,ipmc_info->group_ip_mask_len, ipmc_info->address.src_addr, ipmc_info->src_ip_mask_len);
		
	ipmc_group_info.address.ipv4.group_addr = ipmc_info->address.group_addr;
	ipmc_group_info.address.ipv4.src_addr = ipmc_info->address.src_addr;
	ipmc_group_info.group_ip_mask_len = ipmc_info->group_ip_mask_len;
	ipmc_group_info.src_ip_mask_len = ipmc_info->src_ip_mask_len;
	ipmc_group_info.address.ipv4.vrfid = 0;

	sal_memcpy (&get_ipmc_group_info, &ipmc_group_info, sizeof(ctc_ipmc_group_info_t));
	ret = ctc_ipmc_get_group_info(&get_ipmc_group_info);
	if (ret < 0) {
		printk("%% %s \n\r", ctc_get_error_desc(ret));
		return -1;
	}

#if 0
	if (ipmc_group_info.member_number > 0) {
		for (i = 0; i < ipmc_group_info.member_number; i++) {
			ipmc_group_info.ipmc_member[i].global_port = IFINDEX_TO_GPORT(ipmc_info->ifindex[i]);
			ipmc_group_info.ipmc_member[i].l3_if_type = CTC_L3IF_TYPE_PHY_IF;
		}

		ret = ctc_ipmc_remove_member(&ipmc_group_info);
		if (ret < 0) {
			printk("ctc_ipmc_remove_member failed , ret =%d\n", ret);
			goto out;
		}
	}

	ret = ipmc_group_del_member(ipmc_group_info.group_id, ipmc_group_info.member_number);
	if (ret < 0) {
		printk("ipmc_group_del_member failed , ret =%d\n", ret);
		goto out;
	}

	if (ret == RET_NEED_DEL_GROUP) { /*need to remove group*/
		ipmc_group_info.member_number   = 0;
		ret = ctc_ipmc_remove_group(&ipmc_group_info);
		if (ret < 0) {
			printk("ctc_ipmc_remove_group failed ret =%d\n", ret);
			goto out;
		}
		free_ipmc_group(ipmc_group_info.group_id);		
	}
#endif
	ret = ctc_ipmc_remove_group(&ipmc_group_info);
	if (ret < 0) {
		printk("ctc_ipmc_remove_group failed ret =%d\n", ret);
		goto out;
	}
	printk("free_ipmc_group id=%d\n", get_ipmc_group_info.group_id);
	free_ipmc_group(get_ipmc_group_info.group_id);		

out:
	HSL_IPMC_UNLOCK;
	return ret;
}



