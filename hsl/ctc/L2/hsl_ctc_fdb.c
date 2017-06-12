/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"

//#include "bcm_incl.h"

#include "hsl_oss.h"
#include "hsl_logger.h"
#include "hsl_error.h"
#include "hsl_ifmgr.h"
#include "hsl_ctc_if.h"
#include "hsl_ctc_ifmap.h"
#include "hsl_mac_tbl.h"
#include "hsl_ctc_fdb.h"
#include "ctc_api.h"
#include "ctc_if_portmap.h"

/*
  L2 address add to FDB.
*/
static void _hsl_ctc_fdb_addr_register(uint8 gchip, ctc_learning_cache_entry_t *addr)
{
	fdb_entry_t entry;
	fdb_entry_t eptr;
	fdb_entry_t key;
	int ret;
	int age_timer;
	int phy_port_to_ifindex;
	
	/* Check multicast */  	
	if (addr->cmac_sa_32to47 & 0x100) 
		return;

	/* Ageing timer */
	ret = ctc_aging_get_property(CTC_AGING_TBL_MAC, CTC_AGING_PROP_INTERVAL , &age_timer);
	if (ret) {
		age_timer = 0;		
	}


	entry.ageing_timer_value = age_timer;

	/* Mac address */
	memcpy(entry.mac_addr, &(addr->mac_sa_32to47), 2);
	memcpy(entry.mac_addr + 2, &(addr->mac_sa_0to31), 4);

	
	/* Port number */
    entry.port_no = GPORT_TO_IFINDEX(addr->global_src_port);

	/* Vlan Id */
	entry.vid = addr->mapped_vlan_id;

	/* Is static? check the flag */
	entry.is_static = 0;

	/* Is local? */
	entry.is_local = 0;

	/* Is forwarding? */
	entry.is_fwd = 1;

	/* Snmp status */
	entry.snmp_status = 0;

	/* add the forward entry */
	/* Add learned entry to FDB */
	ret = hsl_add_fdb_entry (&entry); 
	if (ret != 0)
	{
		HSL_LOG (HSL_LOG_FDB, HSL_LEVEL_INFO,"Not Added [MAC:%x:%x:%x:%x:%x:%x] [DUPLICATE_KEY]\n",
		entry.mac_addr[0], entry.mac_addr[1],
		entry.mac_addr[2], entry.mac_addr[3],
		entry.mac_addr[4], entry.mac_addr[5]);
	}
	else
	{
		key.mac_addr[0] = entry.mac_addr[0];
		key.mac_addr[1] = entry.mac_addr[1];
		key.mac_addr[2] = entry.mac_addr[2];
		key.mac_addr[3] = entry.mac_addr[3];
		key.mac_addr[4] = entry.mac_addr[4];
		key.mac_addr[5] = entry.mac_addr[5];

		if ((ret = hsl_get_fdb_entry (&eptr, SEARCH_BY_MAC, &key)) == 0) {
 			//HSL_LOG (HSL_LOG_FDB, HSL_LEVEL_INFO,
			//printk(
			//"Added [MAC:%x:%x:%x:%x:%x:%x] vid=%d to FDB\n",
			//eptr.mac_addr[0], eptr.mac_addr[1], eptr.mac_addr[2],
			//eptr.mac_addr[3], eptr.mac_addr[4], eptr.mac_addr[5], eptr.vid);       
        }
		else
		{
			HSL_LOG (HSL_LOG_FDB, HSL_LEVEL_INFO,"Get entry [DUPLICATE_KEY]\n");
		}
	}
}



/*
  L2 address delete to FDB.
*/
static void _hsl_ctc_fdb_addr_unregister(uint8 gchip, ctc_l2_addr_t *addr)
{
	int ret;
	fdb_entry_t entry;
	
	entry.vid = addr->fid;

	memcpy(entry.mac_addr, addr->mac, 6);

	ret = hsl_delete_fdb_entry(&entry);
	if (ret != 0) {
		HSL_LOG (HSL_LOG_FDB, HSL_LEVEL_INFO,"Not Deleted [MAC:%x:%x:%x:%x:%x:%x] from FDB\n",
			entry.mac_addr[0], entry.mac_addr[1], entry.mac_addr[2],
			entry.mac_addr[3], entry.mac_addr[4], entry.mac_addr[5]);

	}
	else {
		HSL_LOG (HSL_LOG_FDB, HSL_LEVEL_INFO,"Deleted [MAC:%x:%x:%x:%x:%x:%x] vid=%d from FDB\n",
			entry.mac_addr[0], entry.mac_addr[1], entry.mac_addr[2],
			entry.mac_addr[3], entry.mac_addr[4], entry.mac_addr[5], entry.vid);

	}

}




void hsl_ctc_fdb_addr_learning(unsigned char gchip, void *p_data)
{
	_hsl_ctc_fdb_addr_register(gchip, p_data);
}

void hsl_ctc_fdb_addr_ageing(unsigned char gchip, void *p_data)
{
	ctc_l2_addr_t *addr;	

	addr = (ctc_l2_addr_t *)p_data;

	_hsl_ctc_fdb_addr_unregister(gchip, addr);
}

extern void hsl_ctc_learning_cb_set(void *func);

extern void hsl_ctc_ageing_cb_set(void *func);


void hsl_fdb_hw_cb_register(void)
{
	int ret;

#if 0
	/*init fdb table*/
	if (0 != hsl_init_fdb_table ()) {
		hsl_deinit_fdb_table();
	}
#endif
	/*init mac learn*/
	hsl_ctc_learning_cb_set(hsl_ctc_fdb_addr_learning);

	/*init mac ageing*/
	hsl_ctc_ageing_cb_set(hsl_ctc_fdb_addr_ageing);
	ctc_aging_set_property(CTC_AGING_TBL_MAC, CTC_AGING_PROP_AGING_SCAN_EN, 1);
	ctc_aging_set_property(CTC_AGING_TBL_MAC, CTC_AGING_PROP_INTERVAL, 0);


	return;
}

void hsl_fdb_hw_cb_unregister(void)
{

	return;
}

