#include <gmodule.h> /* Must be included first */
#include <kconfig.h>
#include <sal/core/boot.h>
#include <appl/diag/sysconf.h>
#include <appl/cpudb/cpudb.h>
#include <appl/cputrans/atp.h>
#include <soc/drv.h>
#include <soc/mem.h>
#include <soc/debug.h>
#include <soc/cmext.h>
#include <soc/l2x.h>
#include <bcm/init.h>
#include <bcm/error.h>
#include <bcm/port.h>
#include <bcm/link.h>
#include <bcm/stat.h>
#include <bcm/stack.h>
#include <bcm/l2.h>
#include <bcm/rx.h>
#include <ibde.h>
#include <linux-bde.h>
#include <bcm-core.h>

#define BCM_VAR_LEN		64
#define CONFIG_VAR_SIZE (150*4)

struct bcm_var_s {
	char var_req[BCM_VAR_LEN];
	char var_resp[BCM_VAR_LEN];
	int  dev_id;
	int  flag;
};

static struct bcm_var_s custom_config_var[CONFIG_VAR_SIZE] = {
	{spn_BCM_NUM_COS,				"8",            		0},
	{spn_MODULE_64PORTS,			"1",           			0},

	{spn_PBMP_XPORT_XE,				"0x1ffffffffffffffff",	BCM56842_DEVICE_ID},
	{spn_PARITY_ENABLE,             "0",                    BCM56842_DEVICE_ID},
	{spn_XGXS_LCPLL_XTAL_REFCLK,    "1",                    BCM56842_DEVICE_ID},
	{spn_PORTMAP"_1", 				"13:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_2", 				"14:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_3", 				"15:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_4", 				"16:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_5", 				"17:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_6", 				"18:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_7", 				"19:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_8", 				"20:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_9", 				"41:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_10", 				"42:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_11", 				"43:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_12", 				"44:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_13", 				"45:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_14", 				"46:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_15", 				"47:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_16", 				"48:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_17", 				"57:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_18", 				"58:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_19", 				"59:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_20", 				"60:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_21", 				"61:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_22", 				"62:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_23",				"63:10", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_24", 				"64:10", 				BCM56842_DEVICE_ID},

	{spn_PBMP_XPORT_XE,				"0x1ffffffffffffffff",	BCM56844_DEVICE_ID},
	{spn_PARITY_ENABLE,             "0",                    BCM56844_DEVICE_ID},
	{spn_XGXS_LCPLL_XTAL_REFCLK,    "1",                    BCM56844_DEVICE_ID},
	{spn_PORTMAP"_1", 				"13:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_2", 				"14:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_3", 				"15:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_4", 				"16:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_5", 				"17:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_6", 				"18:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_7", 				"19:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_8", 				"20:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_9", 				"41:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_10", 				"42:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_11", 				"43:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_12", 				"44:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_13", 				"45:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_14", 				"46:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_15", 				"47:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_16", 				"48:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_17", 				"57:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_18", 				"58:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_19", 				"59:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_20", 				"60:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_21", 				"61:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_22", 				"62:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_23",				"63:10", 				BCM56844_DEVICE_ID},
	{spn_PORTMAP"_24", 				"64:10", 				BCM56844_DEVICE_ID},


	{spn_PORT_PHY_ADDR"_ge0",		"0x0",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge1",		"0x1",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge2",		"0x2",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge3",		"0x3",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge4",		"0x4",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge5",		"0x5",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge6",		"0x6",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge7",		"0x7",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge8",		"0x9",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge9",		"0xa",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge10",		"0xb",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge11",		"0xc",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge12",		"0xd",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge13",		"0xe",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge14",		"0xf",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge15",		"0x10",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge16",		"0x12",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge17",		"0x13",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge18",		"0x14",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge19",		"0x15",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge20",		"0x16",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge21",		"0x17",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge22",		"0x18",					BCM56140_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_ge23",		"0x19",					BCM56140_DEVICE_ID},

	{spn_BCM5614X_CONFIG,						"1",				BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge0",		"0x0100",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge1",		"0x0101",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge2",		"0x0102",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge3",		"0x0103",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge4",		"0x0200",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge5",		"0x0201",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge6",		"0x0202",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge7",		"0x0203",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge8",		"0x0300",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge9",		"0x0301",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge10",	"0x0302",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge11",	"0x0303",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge12",	"0x0400",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge13",	"0x0401",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge14",	"0x0402",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge15",	"0x0403",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge16",	"0x0500",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge17",	"0x0501",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge18",	"0x0502",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge19",	"0x0503",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge20",	"0x0600",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge21",	"0x0601",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge22",	"0x0602",			BCM56140_DEVICE_ID},
	{spn_PHY_PORT_PRIMARY_AND_OFFSET"_ge23",	"0x0603",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge0",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge1",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge2",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge3",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge4",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge5",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge6",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge7",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge8",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge9",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge10",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge11",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge12",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge13",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge14",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge15",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge16",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge17",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge18",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge19",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge20",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge21",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge22",		"1",			BCM56140_DEVICE_ID},
	{spn_SERDES_QSGMII_SGMII_OVERRIDE"_ge23",		"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge0",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge1",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge2",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge3",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge4",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge5",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge6",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge7",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge8",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge9",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge10",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge11",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge12",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge13",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge14",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_FIBER_PREF"_ge15",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge0",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge1",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge2",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge3",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge4",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge5",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge6",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge7",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge8",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge9",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge10",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge11",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge12",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge13",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge14",						"1",			BCM56140_DEVICE_ID},
	{spn_PHY_AUTOMEDIUM"_ge15",						"1",			BCM56140_DEVICE_ID},
	{NULL,  NULL,   0, 0},
};
/* already setted custom_config_var num */
static int custom_config_var_num = CONFIG_VAR_SIZE - 16;
static int custom_config_var_init = 0;
/* port mode */
long portmode;
LKM_MOD_PARAM(portmode, "i", long, 0);
MODULE_PARM_DESC(portmode,
"Set port mode (default 0x0)");

EXPORT_SYMBOL(portmode);
#define FORTY_GIG_PORT_NUM 2
/* 第一列是逻辑接口编号，第二列是物理接口编号，第三列是外部PHY地址编号
 * 如果没有外部phy，则外部PHY编号设置为-1 */
static int logic_to_phy_map[FORTY_GIG_PORT_NUM][3] = {
	{25, 29, 0},
    {29, 25, 4}
};

/*
	{spn_PORTMAP"_25",				"29:40", 				BCM56842_DEVICE_ID},
	{spn_PORTMAP"_26", 				"25:40", 				BCM56842_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_25",		"0x0",					BCM56842_DEVICE_ID},
	{spn_PORT_PHY_ADDR"_29",		"0x4",					BCM56842_DEVICE_ID},
*/

int dynamic_create_custom_config_var(int portmode)
{
	int i = 0;
	int port_index = 0;
    int j = 0;
    int logic_port_index, phy_port_index, extern_phy_index;
    int unit = 0;
    int found_dev_id = 0;   /* when found 56842 or 56844, set to 1 */
    uint16 bcmdev_id = 0;
    uint8  bcmrev_id = 0;

    for (i = 0; i < sizeof(custom_config_var) / sizeof(custom_config_var[0]); i++) {
        if ((custom_config_var[i].var_req[0]  == '\0')   \
         && (custom_config_var[i].var_resp[0] == '\0')   \
         && (custom_config_var[i].dev_id      ==   0)) {
            break;
        }
    }
    custom_config_var_num = i;

    found_dev_id = 0;
    for (unit = 0; unit < SOC_MAX_NUM_DEVICES; unit++) {
        if (!SOC_UNIT_VALID(unit)) {
            continue;
        }

        soc_cm_get_id(unit, &bcmdev_id, &bcmrev_id);
        /* Now only support 56842, 56844 */
        if ((bcmdev_id == BCM56842_DEVICE_ID) || (bcmdev_id == BCM56844_DEVICE_ID)) {
            found_dev_id = 1;
            break;
        }
    }
    if (!found_dev_id) {    /* not found 56842, 56844 */
       goto   jump_40g_port_init;
    }

	if((portmode >> 31) & 0x1) {
		/* The 40G Card is there */
		for (port_index = 0; port_index < FORTY_GIG_PORT_NUM; port_index++) {
            logic_port_index = logic_to_phy_map[port_index][0];
			phy_port_index = logic_to_phy_map[port_index][1];
			extern_phy_index = logic_to_phy_map[port_index][2];
			if ((portmode >> (port_index + 24)) & 0x1) { /* �moudle是10g模式 */
                for(j = 0; j < 4; j++) {
                    sprintf(custom_config_var[i].var_req,  "%s_%d",     \
                            spn_PORTMAP, logic_port_index);
                    sprintf(custom_config_var[i].var_resp, "%d:10",     \
                            phy_port_index);
                    custom_config_var[i].dev_id = bcmdev_id;
                    i++;

                    sprintf(custom_config_var[i].var_req, "%s_%d",    \
                            spn_PORT_PHY_ADDR, logic_port_index);
                    sprintf(custom_config_var[i].var_resp, "0x%x",      \
                            extern_phy_index);
                    custom_config_var[i].dev_id = bcmdev_id;
                    i++;

                    sprintf(custom_config_var[i].var_req, "%s_%d",      \
                            spn_PORT_INIT_AUTONEG, logic_port_index);
                    sprintf(custom_config_var[i].var_resp, "%d", 0);
                    custom_config_var[i].dev_id = bcmdev_id;
                    i++;

                    sprintf(custom_config_var[i].var_req, "%s_%d",      \
                            spn_PORT_INIT_SPEED, logic_port_index);
                    sprintf(custom_config_var[i].var_resp, "%d", 10000);
                    custom_config_var[i].dev_id = bcmdev_id;
                    i++;

                    logic_port_index += 1;
					phy_port_index += 1;
					extern_phy_index += 1;
                }   /* end of for (j...) */
            } else { /* 该moudle是40g模式 */
				sprintf(custom_config_var[i].var_req, "%s_%d", spn_PORTMAP, logic_port_index);
				sprintf(custom_config_var[i].var_resp, "%d:40", phy_port_index);
				custom_config_var[i].dev_id = bcmdev_id;
				i++;

				sprintf(custom_config_var[i].var_req, "%s_%d", spn_PORT_PHY_ADDR, logic_port_index);
				sprintf(custom_config_var[i].var_resp, "0x%x", extern_phy_index);
				custom_config_var[i].dev_id = bcmdev_id;
				i++;
				
				sprintf(custom_config_var[i].var_req, "%s_%d", spn_PORT_INIT_AUTONEG, logic_port_index);
				sprintf(custom_config_var[i].var_resp, "%d", 0);
				custom_config_var[i].dev_id = bcmdev_id;
				i++;

				sprintf(custom_config_var[i].var_req, "%s_%d", spn_PORT_INIT_SPEED, logic_port_index);
				sprintf(custom_config_var[i].var_resp, "%d", 40000);
				custom_config_var[i].dev_id = bcmdev_id;
				i++;				
			}
			if (i >= CONFIG_VAR_SIZE)
				break;
		}
	} else {    /* 40G card not connected */
        ;       /* Do nothing */
	}

jump_40g_port_init:

	/* disable 56140 table dma and counter dma */
	sprintf(custom_config_var[i].var_req, "%s", spn_TSLAM_DMA_ENABLE);
	sprintf(custom_config_var[i].var_resp, "%d", 0);
	custom_config_var[i].dev_id = BCM56140_DEVICE_ID;
	i++;

	sprintf(custom_config_var[i].var_req, "%s", spn_TABLE_DMA_ENABLE);
	sprintf(custom_config_var[i].var_resp, "%d", 0);
	custom_config_var[i].dev_id = BCM56140_DEVICE_ID;
	i++;

	sprintf(custom_config_var[i].var_req, "%s", spn_BCM_STAT_FLAGS);
	sprintf(custom_config_var[i].var_resp, "%d", 0);
	custom_config_var[i].dev_id = BCM56140_DEVICE_ID;
	i++;

	custom_config_var_num = i;

	return i;
}

char *custom_config_var_get(soc_cm_dev_t *dev, const char *property)
{
	int index;
	struct bcm_var_s *var;
	char var_req[BCM_VAR_LEN];

	
	if (!custom_config_var_init) {
		dynamic_create_custom_config_var(portmode);
		custom_config_var_init = 1;
	}

	for (index = 0; index < custom_config_var_num; index++) {
		var = &custom_config_var[index];

		memset(var_req, 0, BCM_VAR_LEN);
		sprintf(var_req, "%s.%d", var->var_req, dev->dev);
		if (strcmp(property, var_req) == 0) {
            
			if ((var->dev_id != 0) && (var->dev_id != dev->dev_id)) {
				continue;
			}
			//printk("[config var] %s = %s\r\n", var_req, var->var_resp);
			return var->var_resp;
		}
	}
	return NULL;
}
