#include <gmodule.h> /* Must be included first */
#include <bcm/port.h>
#include <soc/cmic.h>
#include <soc/cm.h>
#include <soc/error.h>
#include <sal/core/libc.h>
#include <bcm/error.h>
#include <bcm/link.h>
#include <soc/types.h>
#include <appl/diag/system.h>
#include <bcm/stat.h>
#include <bcm_int/esw/stat.h>
#include <sal/core/spl.h>

#include <sal/types.h>

#include <soc/drv.h>
#include <soc/debug.h>
#include <soc/error.h>
#include <soc/phyreg.h>

#include <soc/phy.h>
#include <soc/phy/phyctrl.h>
#include <soc/phy/drv.h>
#include "led_config.h"
#include "config_var.h"

#undef REG_ADD(unit, port, reg, val) 
#define REG_ADD(unit, port, reg, val)                                      \
    if (SOC_REG_IS_VALID(unit, reg) && SOC_REG_IS_COUNTER(unit, reg)) {    \
        soc_counter_get(unit, port, reg,               \
                        0, &reg_val);                 \
        COMPILER_64_ADD_64(val, reg_val);                                  \
    }
	
#define _READ_PHY_REG(_unit, _pc,  _addr, _value) \
            ((_pc->read)((_unit), (_pc->phy_id), (_addr), (_value)))
#define _WRITE_PHY_REG(_unit, _pc, _addr, _value) \
            ((_pc->write)((_unit), (_pc->phy_id), (_addr), (_value)))
            
#define CMICE_LEDUP1_DATA_RAM(_a)          (CMICE_LEDUP1_DATA_RAM_BASE + 4 * (_a))
#define CMICE_LEDUP0_DATA_RAM(_a)          (CMICE_LEDUP0_DATA_RAM_BASE + 4 * (_a))
#define CMIC_LEDUP0_PROGRAM_RAM(_a)        (CMICE_LEDUP0_PROGRAM_RAM_BASE + 4 * (_a))
#define CMIC_LEDUP1_PROGRAM_RAM(_a)        (CMICE_LEDUP1_PROGRAM_RAM_BASE + 4 * (_a))			

#define LS_LED_DATA_OFFSET_B0      			0xb0
#define LEDDRV_FLASH_LEN 					256

#define PORT_40G_INDEX_XE25     25
#define PORT_40G_INDEX_XE29     29
/****************************************************************************************************/

/* used for blink */
static u64 bytes_input[BCM_LOCAL_UNITS_MAX][BCM_PBMP_PORT_MAX];

/****************************************************************************************************/

int b2u_port_map[72] = {
	-1, 0, 1, 2, 3, 4, 5, 6, 7,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1, 8,-1,-1,-1, 9,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1
};

#if 0
static int link_10G_status = 0;
int port_link_led[10] = {
	 0, 0, 0, 0, /* 控制接口up时亮灯  */
	-1, 		 /* 控制闪灯 */
	 0, 0, 0, 0, 
	-1
};
#endif

static int max_led_port = 10;

void leddrv_linkscan_user_cb(int unit, int port, int link, int speed, unsigned int * data)
{
    if (link == 1) {
        *data |= 0x01;
		/* one led mode: 1G: orange led, 10G, 40G: green led */		
		if(speed < 10000){
        	*data &= ~0x02;
	    } else {  	
	    	*data |= 0x02;
	    }
	} else {
        *data &= ~0x01;
    }

    return ;
}

void leddrv_linkscan_cb(int unit, int port, bcm_port_info_t *info)
{
	uint32	portdata;
	int		byte;
	int i, j;

	if((b2u_port_map[port] < 0) || (b2u_port_map[port] >=max_led_port)) {
		return;
	}
	else { 
		byte =  LS_LED_DATA_OFFSET_B0 + b2u_port_map[port];
	}
		
	portdata = soc_pci_read(unit, CMICE_LEDUP0_DATA_RAM_BASE + 4 * (byte));
	leddrv_linkscan_user_cb(unit, port, info->linkstatus, info->speed, &portdata);
	soc_pci_write(unit, CMICE_LEDUP0_DATA_RAM_BASE + 4 * (byte), portdata);
	
}

static int leddrv_load(int unit, uint8 *program, int bytes)
{
    int		offset;

    for (offset = 0; offset < CMIC_LED_PROGRAM_RAM_SIZE; offset++) {
    	soc_pci_write(unit, CMIC_LEDUP0_PROGRAM_RAM(offset),
    		      (offset < bytes) ? (uint32) program[offset] : 0);
    }

    for (offset = 0x40; offset < CMIC_LED_DATA_RAM_SIZE; offset++) {
        soc_pci_write(unit, CMICE_LEDUP0_DATA_RAM(offset), 0);
    }
	
	return 0;
}

void led_blink_process(int unit, int port) 
{
    u64 bytes_tmp1 = 0;
    u64 bytes_tmp2 = 0;
    int byte = LS_LED_DATA_OFFSET_B0 + b2u_port_map[port];
    uint32  portdata = 0;

    char bool_value = 0;

	if((b2u_port_map[port] < 0) || (b2u_port_map[port] > max_led_port))
		return;

	
    COMPILER_REFERENCE(&bytes_tmp1); 
    COMPILER_64_ZERO(bytes_tmp1);  

	if(b2u_port_map[port] < max_led_port){

		 if (SOC_REG_IS_VALID(unit, TPKTr)) { 
	        if (soc_reg_read(unit,
	                  TPKTr,
	                  soc_reg_addr(unit, TPKTr, port, 0),
	                  &bytes_tmp2) != SOC_E_NONE) {
	         
	            return;
	        }
	        bytes_tmp1  += bytes_tmp2;
	            
	    }
	    
	    if (SOC_REG_IS_VALID(unit, RPKTr)) { 
	        if (soc_reg_read(unit,
	              RPKTr,
	              soc_reg_addr(unit, RPKTr, port, 0),
	              &bytes_tmp2) != SOC_E_NONE) {

	            return;
	        }
	        bytes_tmp1  += bytes_tmp2;
	    }
	} else {
		return;
	}

	portdata = soc_pci_read(unit, CMICE_LEDUP0_DATA_RAM(byte));

    bool_value = (bytes_tmp1 != bytes_input[unit][port]);
	if (bool_value) {
        bytes_input[unit][port] = bytes_tmp1; 
        /* do blink */
        portdata |= 0x04;
    } else {
        portdata &= ~0x04;
    }
    soc_pci_write(unit, CMICE_LEDUP0_DATA_RAM(byte), portdata);

    return;    
}

static int led_drv(int unit)
{
	volatile uint32 led_ctrl;
	
	soc_pci_write(unit, CMICE_LEDUP0_CTRL, 0);
	
	leddrv_load(unit, (uint8 *)ledproc_special_led, LEDDRV_FLASH_LEN);	

	bcm_linkscan_register(unit, leddrv_linkscan_cb);

	bcm_link_change(unit, PBMP_PORT_ALL(unit));

	soc_pci_write(unit, CMICE_LEDUP0_DATA_RAM(0xe2), 2);
	soc_pci_write(unit, CMICE_LEDUP0_DATA_RAM(0xe5), max_led_port*2);
	soc_pci_write(unit, CMICE_LEDUP0_DATA_RAM(0xe4), max_led_port);
    /* added by cdy, 2016/01/04, for led mode choice: 0x00: one led; 0x01: two led 
    ** default led mode is 0x01( two led )
    */
	soc_pci_write(unit, CMICE_LEDUP0_DATA_RAM(0xe6), 0x01);
	
	led_ctrl = LC_LED_ENABLE;

	soc_pci_write(unit, CMICE_LEDUP0_CTRL, led_ctrl);
	
	port_led_scan_init();
	return 0;
}

void phy_led_config(int unit)
{
	/*
	1、port16 reg 0x1c shadow 0x0b  0x2c10
	2、port16 reg 0x10  0x21

	3、portX  reg 0x1c shadow 0x02  0x0803
	4、portX  reg 0x1c shadow 0x0d  0x3415
	5、portX  reg 0x1c shadow 0x09  0x240b
	*/

	phy_ctrl_t *pc;
    uint16      tmp;
	uint16 		data;
    int         i;
	/* step 1 */
    pc = EXT_PHY_SW_STATE(unit, 18);
	data = 0x8000 | (0xb << 10) | (0x2c10 & 0x03FF);
	_WRITE_PHY_REG(unit, pc, 0x1c, data);
	
	/* step 2 */
	data = 0x21;
	_WRITE_PHY_REG(unit, pc, 0x10, data);

	for (i = 18; i < 26; i++) {
		/* step 3 */
		pc = EXT_PHY_SW_STATE(unit, i);
		data = 0x8000 | (0x2 << 10) | (0x0803 & 0x03FF);
		_WRITE_PHY_REG(unit, pc, 0x1c, data);

		/* step 4 */
		data = 0x8000 | (0xd << 10) | (0x3415 & 0x03FF);
		_WRITE_PHY_REG(unit, pc, 0x1c, data);

		/* step 5 */
		data = 0x8000 | (0x9 << 10) | (0x240b & 0x03FF);
		_WRITE_PHY_REG(unit, pc, 0x1c, data);
	}
}

void port_led_load(int unit) {

    /* No 40G card */
    if((portmode & (0x1 << 31)) == 0) {
        b2u_port_map[PORT_40G_INDEX_XE25] = -1;
        b2u_port_map[PORT_40G_INDEX_XE29] = -1;
    }
#if 0
    /* xe25 disabled */
    if(portmode & (0x1 << 31) && !(portmode & (0x1 << 25)) ) {
        b2u_port_map[PORT_40G_INDEX_XE25] = -1;
    }
    /* xe29 disabled */
    if(portmode & (0x1 << 31) && !(portmode & (0x1 << 26)) ) {
        b2u_port_map[PORT_40G_INDEX_XE29] = -1;
    }

#endif
    led_drv(0);
    phy_led_config(1);

}

static void port_led_scan_process(void)
{
	int port;
	int unit = 0;
	int max_port;
	

	max_port = sizeof(b2u_port_map)/sizeof(b2u_port_map[0]);
	while(1) {
		for (port = 1; port < max_port; port++) {
			if(b2u_port_map[port] != -1) {
					led_blink_process(unit, port);
			}
		}
		sal_usleep(1000);
	}

}

void port_led_scan_init(void)
{
	if (sal_thread_create("LED_BLINK", SAL_THREAD_STKSZ, 150, (void (*)(void*))port_led_scan_process, 0) == SAL_THREAD_ERROR)
		gprintk("%s: Thread did not start\n\r", "LED_BLINK");
}



void test0_pci_write(int unit, u32 addr, u32 data)
{
	u32 a;
	a = CMICE_LEDUP0_DATA_RAM(addr);	
	soc_pci_write(unit, a, data);
}

void test1_pci_write(int unit, u32 addr, u32 data)
{
	u32 a;
	a = CMICE_LEDUP1_DATA_RAM(addr);	
	soc_pci_write(unit, a, data);
}

u32 test0_pci_read(int unit, u32 addr)
{
	u32 a;
	a = CMICE_LEDUP1_DATA_RAM(addr);	
	return soc_pci_read(unit, a);
}

u32 test1_pci_read(int unit, u32 addr)
{
	u32 a;
	a = CMICE_LEDUP1_DATA_RAM(addr);	
	return soc_pci_read(unit, a);
}

void led0_data_ram_dump(int unit)
{
	int i, k = 0;
	int j = 0;
	u32 data;
	
	for (i = 0; i < 256; i++) {
		data = soc_pci_read(unit, CMICE_LEDUP0_DATA_RAM(i));
		if ((j % 16) == 0)
			gprintk("\r\n%x: ", k++);

		gprintk("%02x ", data);
		j++;
	}
}

void led1_data_ram_dump(int unit)
{
	int i, k = 0;
	int j = 0;
	u32 data;
	
	for (i = 0; i < 256; i++) {
		data = soc_pci_read(unit, CMICE_LEDUP1_DATA_RAM(i));
		if ((j % 16) == 0)
			gprintk("\r\n%x: ", k++);

		gprintk("%02x ", data);
		j++;
	}
}

void dump_ledproc(uint8 *program)
{
	int i;
	for (i = 0; i < LEDDRV_FLASH_LEN; i++) {
		if ((i % 8) == 0) {
			gprintk("\r\n");
		}
		gprintk("0x%02x, ", program[i]);
	}
	gprintk("\r\n");
}


void led0_test_data() 
{
    int i;
    uint32 portdata = 0;
    for(i = 0; i < 0x80; i++) {
        portdata = soc_pci_read(0, CMICE_LEDUP0_DATA_RAM(i));
        if (i % 8 == 0) {
            gprintk("\r\n");
        }


        gprintk("0x%x ", portdata);
    }

    gprintk("\r\n\r\n");
    return;

}



void led1_test_data() 
{
    int i;
    uint32 portdata = 0;
    for(i = 0; i < 0x80; i++) {
        portdata = soc_pci_read(0, CMICE_LEDUP1_DATA_RAM(i));
        if (i % 8 == 0) {
            gprintk("\r\n");
        }


        gprintk("0x%x ", portdata);
    }

    gprintk("\r\n\r\n");
    return;

}

/* huangtao: used for bink debug */
void dump_blink_info(int unit)
{
    u64 bytes_tmp1;
    int i = 0; 
    REG_MATH_DECL;       /* Required for use of the REG_* macros */
    gprintk("\r\n");
    gprintk("bytes_input:\r\n");
    while (i < BCM_PBMP_PORT_MAX) {
        gprintk("%llx ", bytes_input[unit][i]);
        if (i % 7 == 0 && i != 0) {
            gprintk("\r\n");
        }
        ++i;
    }
    
    gprintk("\r\n");
    gprintk("REAL bytes_input:\r\n");

    i = 0;
    while (i < SOC_MAX_NUM_PORTS) {
            
        REG_ADD(0, i, GRBYTr, bytes_tmp1);     /* bytes rcvd */
        REG_ADD(0, i, GTBYTr, bytes_tmp1);
        if (SOC_REG_IS_VALID(0, RRBYTr)) {
            REG_ADD(0, i, RRBYTr, bytes_tmp1); /* Runt bytes */
        }
        gprintk("%llx ", bytes_tmp1);
        if (i % 7 == 0 && i != 0) {
            gprintk("\r\n");
        }
        ++i;
    }

    i = 0;
    while (i < SOC_MAX_NUM_PORTS) {
        int byte =  LS_LED_DATA_OFFSET_B0 + b2u_port_map[i];
        uint32 portdata = soc_pci_read(0, CMICE_LEDUP0_DATA_RAM(byte));
        
        gprintk("port: %d addr:0x%x,data:0x%x \r\n", i, CMICE_LEDUP1_DATA_RAM(byte), portdata);

        ++i;
    }
    
}
