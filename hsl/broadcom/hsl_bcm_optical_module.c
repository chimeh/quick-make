/* Copyright (C) 2003 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"

/* 
   Broadcom includes. 
*/
#include "bcm_incl.h"
/* Broadcom includes. */
#include "bcm_incl.h"

/* HAL includes. */
#include "hal_netlink.h"
#include "hal_msg.h"

#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"

#include "hsl_bcm_ifmap.h"
#include "hsl_bcm_resv_vlan.h"
#include "hsl_bcm_pkt.h"
#include "hsl_bcm.h"

#include "sal/appl/config.h"
#include "appl/cputrans/ct_tun.h"
#include "math.h"

extern int soc_i2c_read_byte(int unit, uint8 saddr, uint8* data);
extern int soc_i2c_write_byte(int unit, uint8 saddr, uint8 data);
extern int soc_i2c_is_attached(int unit);
extern int soc_i2c_attach(int unit, uint32 flags, int speed);


struct pca9547_port_info {
	int saddr;
	int channel;
};

struct pca9547_port_info pca9547_port[40] = {
		{-1,		-1},
			
		{0x70,		 0},
		{0x70,		 1},
		{0x70,		 2},
		{0x70,		 3},
		{0x70,		 4},
		{0x70,		 5},
		{0x70,		 6},
		{0x70,		 7},			
};

int custom_soc_i2c_probe(int unit)
{

    /* Make sure that we're already attached, or go get attached */
    if (!soc_i2c_is_attached(unit)) {
		return soc_i2c_attach(unit, 0x08, 0); /* flags: 0x08. Do not Probe immediately after attach */
    }

    return 0;
}

void shutdown_all_channel(int unit)
{
	int rc;
	rc = soc_i2c_write_byte(unit, 0x70, 0);
	if (rc != SOC_E_NONE) {
		printk("soc_i2c_write_byte rc = %d\r\n", rc);
	}
}

int read_optical_module_register(int ifindex, struct hal_optical_module_info *info)
{
	int unit, usr_port;
	char *port_name;
	char data, value, a0data[256], a2data[256];
	int saddr, channel;
	int rc;
	int chan;
	int i;

	struct hsl_if *ifp;

	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	if (ifp == NULL)
		return -1;
	if (strncmp(ifp->name, "xe", 2))
		return -1;
	usr_port = hsl_atoi(&ifp->name[2]);
	if (usr_port < 1 || usr_port > 8)
		return -1;

	unit = 0;
	port_name = ifp->name;

	saddr = pca9547_port[usr_port].saddr;
	channel = pca9547_port[usr_port].channel;

	memset(a0data, 0, 256);
	memset(a2data, 0, 256);

	rc = custom_soc_i2c_probe(unit);
	if (rc < 0) {
		printk("soc_i2c_probe error rc = %d\r\n", rc);
		return 0;
	}

	shutdown_all_channel(unit);
	
	chan = channel | 0x8;
	rc = soc_i2c_write_byte(unit, saddr, chan);
	if (rc != SOC_E_NONE) {
		sprintf(info->info, "Write operation timed out! PCA9547 device[saddr: 0x%02x] does not exist.\r\n", saddr);
		return 0;
	}

	rc = soc_i2c_read_byte(unit, saddr, &data);
	if (rc != SOC_E_NONE) {
		sprintf(info->info, "Read operation timed out! PCA9547 device[saddr: 0x%02x] does not exist.\r\n", saddr);
		return 0;
	}
	
	sprintf(info->title, "port %s, saddr 0x%02x, channel: %d\r\n\r\n", port_name, saddr, channel);

	for (i = 0; i < 256; i++) {
		rc = soc_i2c_write_byte(unit, 0x50, i);
		if (rc != SOC_E_NONE) {
			sprintf(info->info, "Write operation timed out! Please insert the optical module.\r\n");
			return 0;
		}
		rc = soc_i2c_read_byte(unit, 0x50, &value);
		if (rc != SOC_E_NONE) {
			sprintf(info->info, "Read operation timed out! Please insert the optical module.\r\n");
			return 0;
		}
		a0data[i] = value;
		/*
		if (i % 10 == 0)
			printk("\r\n%03d: ", (i/10) * 10);
		printk("0x%02x ", (uint16)value);
		*/
	}

	for (i = 0; i < 256; i++) {
		rc = soc_i2c_write_byte(unit, 0x51, i);
		if (rc != SOC_E_NONE) {
			sprintf(info->info, "Write operation timed out! Does not support A2h.\r\n");
			return 0;
		}
		rc = soc_i2c_read_byte(unit, 0x51, &value);
		if (rc != SOC_E_NONE) {
			sprintf(info->info, "Read operation timed out! Does not support A2h.\r\n");
			return 0;
		}
		a2data[i] = value;
		/*
		if (i % 10 == 0)
			printk("\r\n%03d: ", (i/10) * 10);
		printk("0x%02x ", (uint16)value);
		*/
	}

	memcpy(info->a0data, a0data, 256);
	memcpy(info->a2data, a2data, 256);
	
	return 0;
}


