/*
 * $Id: bcm-diag.c 1.21 Broadcom SDK $
 * $Copyright: Copyright 2012 Broadcom Corporation.
 * This program is the proprietary software of Broadcom Corporation
 * and/or its licensors, and may only be used, duplicated, modified
 * or distributed pursuant to the terms and conditions of a separate,
 * written license agreement executed between you and Broadcom
 * (an "Authorized License").  Except as set forth in an Authorized
 * License, Broadcom grants no license (express or implied), right
 * to use, or waiver of any kind with respect to the Software, and
 * Broadcom expressly reserves all rights in and to the Software
 * and all intellectual property rights therein.  IF YOU HAVE
 * NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
 * IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
 * ALL USE OF THE SOFTWARE.  
 *  
 * Except as expressly set forth in the Authorized License,
 *  
 * 1.     This program, including its structure, sequence and organization,
 * constitutes the valuable trade secrets of Broadcom, and you shall use
 * all reasonable efforts to protect the confidentiality thereof,
 * and to use this information only in connection with your use of
 * Broadcom integrated circuit products.
 *  
 * 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
 * PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
 * REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
 * DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
 * ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
 * OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
 * 
 * 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
 * BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
 * INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
 * ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
 * TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

#include <gmodule.h> /* Must be included first */

#include <sal/core/sync.h>
#include <sal/core/thread.h>
#include <sal/core/dpc.h>
#include <sal/appl/sal.h>

#include <linux-bde.h>

#include <appl/diag/sysconf.h>
#include <appl/diag/system.h>

#include <bcm-core.h>

/* All shell io is done using a user/kernel proxy service. */
#include <linux-uk-proxy.h>


MODULE_AUTHOR("Broadcom Corporation");
MODULE_DESCRIPTION("BCM Diag Shell");
MODULE_LICENSE("Proprietary");

/* Debug output */
static int debug;
LKM_MOD_PARAM(debug, "i", int, 0);
MODULE_PARM_DESC(debug,
"Set debug level (default 0)");

static int boot_flags = 0;
LKM_MOD_PARAM(boot_flags, "i", int, 0);
MODULE_PARM_DESC(boot_flags, "boot flags");

/* Module Information */
#define MODULE_MAJOR 124
#define MODULE_MINOR 0
#define MODULE_NAME      "linux-bcm-diag"
#define PROXY_SERVICE	 "BCM DIAG SHELL"

/* Maximum string we can handle in printf */
#define PROXY_STRING_MAX (LUK_MAX_DATA_SIZE * 6)

/* Message buffer */
#define DBUF_DATA_SIZE 128
typedef struct _dbuf_t {
    char data[DBUF_DATA_SIZE];
} dbuf_t;
#define DBUF_DATA(dbuf) dbuf->data

/* Buffer console messages from interrupt context */
#define DBUF_CNT_MAX 32
static dbuf_t dbuf[DBUF_CNT_MAX];
static dbuf_t dbuf_flush[DBUF_CNT_MAX];
static volatile int dbuf_cnt;
static spinlock_t dbuf_lock;
static struct semaphore dbuf_sem;

/* Thread control flags */
static volatile int _bcm_shell_running;
static sal_thread_t _bcm_shell_thread;
static sal_thread_t orig_main_thread;

extern int 
tty_vprintf(const char* fmt, va_list args)
    __attribute__ ((format (printf, 1, 0)));

extern int
tty_printf(const char* fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

/* Linux kernel threads must check signals explicitely. */
static void
check_exit_signals(void)
{
    if(signal_pending(current)) {
        sal_dpc_term();
        sal_thread_exit(0);
    }
}

static void
_tty_flush(void *p1, void *p2, void *p3, void *p4, void *p5)
{
    int cnt;
    int dbuf_flush_cnt;
    unsigned long flags;
    dbuf_t *d;
    char *p;

    /* Prevent flushing from multiple threads simultaneously */
    if (down_interruptible(&dbuf_sem) != 0) {
        /* Something's wrong */
        return;
    }

    /* Copy pending data to flush buffer */
    spin_lock_irqsave(&dbuf_lock, flags);
    memcpy(dbuf_flush, dbuf, dbuf_cnt * sizeof(dbuf_t));
    dbuf_flush_cnt = dbuf_cnt;
    dbuf_cnt = 0;
    spin_unlock_irqrestore(&dbuf_lock, flags);

    /* Note that we may sleep during flush */
    for (cnt = 0; cnt < dbuf_flush_cnt; cnt++) {
        d = &dbuf_flush[cnt];
        p = DBUF_DATA(d);
        linux_uk_proxy_send(PROXY_SERVICE, p, strlen(p));
    }

    up(&dbuf_sem);
}

int 
tty_vprintf(const char* fmt, va_list args)
{
    int cnt, tmp_cnt, offset=0; 
    unsigned long flags;
    static char s[PROXY_STRING_MAX]; 

    if (sal_no_sleep()) {
        /* Schedule flush function */
        if (dbuf_cnt == 0) {
            sal_dpc(_tty_flush, 0, 0, 0, 0, 0);
        }
        /* Buffer message */
        spin_lock_irqsave(&dbuf_lock, flags);
        if (dbuf_cnt < DBUF_CNT_MAX) {
            dbuf_t *d = &dbuf[dbuf_cnt++];
            vsnprintf(DBUF_DATA(d), DBUF_DATA_SIZE-1, fmt, args);
        }
        spin_unlock_irqrestore(&dbuf_lock, flags);
        return 0;
    }

    if (dbuf_cnt) {
        /* Flush buffered messages */
        _tty_flush(0, 0, 0, 0, 0);
    }

    tmp_cnt = cnt = vsnprintf(s, PROXY_STRING_MAX - 1, fmt, args);
    if (tmp_cnt >= PROXY_STRING_MAX) {
        tmp_cnt = PROXY_STRING_MAX;
    }
    while (tmp_cnt > 0) {
        linux_uk_proxy_send(PROXY_SERVICE, &s[offset],
                   (tmp_cnt < LUK_MAX_DATA_SIZE) ? tmp_cnt : LUK_MAX_DATA_SIZE);
        tmp_cnt -= LUK_MAX_DATA_SIZE;
        offset += LUK_MAX_DATA_SIZE;
    }
    check_exit_signals();
    return cnt; 
}

/*
 * Function: tty_printf
 *
 * Purpose:
 *    Application-specific console output function.
 * Parameters:
 *    Same as standard C printf.
 * Returns:
 *    Same as standard C printf.
 */
int
tty_printf(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    return tty_vprintf(fmt, args);
}

/*
 * Function: tty_gets
 *
 * Purpose:
 *    Application-specific console input function.
 * Parameters:
 *    Same as standard C fgets.
 * Returns:
 *    Same as standard C fgets.
 */
char *
tty_gets(char* dst, int size)
{
    linux_uk_proxy_recv(PROXY_SERVICE, dst, (unsigned int *)&size); 
    check_exit_signals();
    return dst; 
}

/*
 * Function: _bcm_shell
 *
 * Purpose:
 *    Thread entry used to run an instance of the BCM diag shell
 * Parameters:
 *    None
 * Returns:
 *    Nothing
 */
static void
_bcm_shell(void* p)
{
    if (sal_core_init() < 0 || sal_appl_init() < 0) {
	gprintk("SAL Initialization failed\n");
	sal_thread_exit(0); 
    }
    _bcm_shell_thread = sal_thread_self();

    if (boot_flags) {
        sal_boot_flags_set(boot_flags);
    }

    if (debug >= 1) gprintk("BCM Diag Module Initialized. Starting proxy...\n"); 

    /* A small delay here prevents the telnet proxy 
     * from choking on the first command.
     */
    sal_usleep(100*1000);
    
    _bcm_shell_running = 1; 
    if (debug >= 1) gprintk("Starting Diag Shell...\n"); 
    diag_shell();
    if (debug >= 1) gprintk("Diag Shell is done.\n"); 
    sal_dpc_term();
    linux_bde_destroy(bde);
    _bcm_shell_running = 0; 
}

/*
 * Generic module functions
 */

/*
 * Function: _pprint
 *
 * Purpose:
 *    Print proc filesystem information.
 * Parameters:
 *    None
 * Returns:
 *    Always 0
 */
static int
_pprint(void)
{	
    pprintf("Broadcom Linux BCM Diagnostic Shell\n"); 
    pprintf("\tProxy Service: '%s'\n", PROXY_SERVICE); 
    return 0;
}

/*
 * Function: _init
 *
 * Purpose:
 *    Module initialization.
 *    Starts the BCM diag thread. 
 * Parameters:
 *    None
 * Returns:
 *    Always 0
 */
static int
_init(void)
{
    spin_lock_init(&dbuf_lock);
    sema_init(&dbuf_sem, 1);
    orig_main_thread = sal_thread_main_get();
    linux_uk_proxy_service_create(PROXY_SERVICE, 1, 0); 
    sal_thread_create("bcm-shell", 0, 0, _bcm_shell, 0);
    return 0;
}

/*
 * Function: _cleanup
 *
 * Purpose:
 *    Module cleanup function
 * Parameters:
 *    None
 * Returns:
 *    Always 0
 * Notes:
 *    The BCM diag thread will be destroyed to avoid page faults.
 */
static int
_cleanup(void)
{
    soc_cm_init_t init_data;

    /* Restore debug print vectors */
    sysconf_debug_vectors_get(&init_data);
    bcore_debug_unregister(&init_data);

    /* Restore assert handler */
    bcore_assert_set_default();

    /* Close the shell */
    if (_bcm_shell_thread) {
        sal_thread_destroy(_bcm_shell_thread);
	sal_usleep(200000);
    }
    /* This should only be relavant on a really busy system */
    if (_bcm_shell_running) {
	sal_usleep(200000);
    }

    linux_uk_proxy_service_destroy(PROXY_SERVICE);

    /* Restore main thread */
    sal_thread_main_set(orig_main_thread);

    return 0;
}	

/* Module vectors */
static gmodule_t _gmodule = {
    name: MODULE_NAME, 
    major: MODULE_MAJOR, 
    minor: MODULE_MINOR, 
    init: _init,
    cleanup: _cleanup, 
    pprint: _pprint, 
    ioctl: NULL,
    open: NULL, 
    close: NULL, 
}; 

gmodule_t*
gmodule_get(void)
{
#ifdef LKM_2_4
    EXPORT_NO_SYMBOLS;
#endif
    return &_gmodule;
}

#if 0
#ifdef LKM_2_6
EXPORT_SYMBOL(tty_vprintf);
EXPORT_SYMBOL(tty_printf);
EXPORT_SYMBOL(tty_gets);
#endif
EXPORT_SYMBOL(soc_dma_abort_dv);
EXPORT_SYMBOL(soc_dma_chan_config);
EXPORT_SYMBOL(soc_dma_desc_add);
EXPORT_SYMBOL(soc_dma_desc_end_packet);
EXPORT_SYMBOL(soc_dma_dump_dv);
EXPORT_SYMBOL(soc_dma_dump_pkt);
EXPORT_SYMBOL(soc_dma_dv_alloc);
EXPORT_SYMBOL(soc_dma_dv_free);
EXPORT_SYMBOL(soc_dma_dv_reset);
EXPORT_SYMBOL(soc_dma_ether_dump);
EXPORT_SYMBOL(soc_dma_init);
EXPORT_SYMBOL(soc_dma_start);
EXPORT_SYMBOL(soc_pci_off2name);
#if defined(BCM_CMICM_SUPPORT) || defined(BCM_IPROC_SUPPORT)
#include <soc/uc.h>
EXPORT_SYMBOL(soc_uc_firmware_version);
EXPORT_SYMBOL(soc_uc_in_reset);
EXPORT_SYMBOL(soc_uc_mem_read);
#endif
#if defined (BCM_ESW_SUPPORT) || defined (BCM_DPP_SUPPORT) || defined (BCM_DFE_SUPPORT)
#include <soc/mcm/driver.h>
#include <soc/mem.h>
#include <soc/phy/phyctrl.h>
#include <bcm_int/common/mbox.h>
#include <bcm_int/common/time-mbox.h>
EXPORT_SYMBOL(soc_mem_field_get);
EXPORT_SYMBOL(soc_mem_field_set);
EXPORT_SYMBOL(soc_mem_field_valid);
EXPORT_SYMBOL(soc_mem_iterate);
EXPORT_SYMBOL(soc_mem_read);
EXPORT_SYMBOL(soc_persist);
EXPORT_SYMBOL(soc_phy_list_get);
EXPORT_SYMBOL(soc_phyctrl_diag_ctrl);
EXPORT_SYMBOL(soc_phyctrl_offset_get);
EXPORT_SYMBOL(soc_port_cmap_get);
EXPORT_SYMBOL(soc_reg_addr);
EXPORT_SYMBOL(_bcm_mbox_debug_flag_set);
EXPORT_SYMBOL(_bcm_mbox_debug_flag_get);
EXPORT_SYMBOL(_bcm_time_bs_status_get);
EXPORT_SYMBOL(_bcm_time_bs_log_configure);
EXPORT_SYMBOL(soc_base_driver_table);
EXPORT_SYMBOL(soc_counter_get);
EXPORT_SYMBOL(soc_counter_get_rate);
EXPORT_SYMBOL(soc_counter_idx_get);
EXPORT_SYMBOL(soc_counter_set32_by_port);
EXPORT_SYMBOL(soc_counter_start);
EXPORT_SYMBOL(soc_counter_stop);
EXPORT_SYMBOL(soc_counter_sync);
EXPORT_SYMBOL(soc_reg32_get);
EXPORT_SYMBOL(soc_reg32_set);
EXPORT_SYMBOL(soc_reg64_get);
EXPORT_SYMBOL(soc_reg_addr_get);
EXPORT_SYMBOL(soc_mem_addr_get);
EXPORT_SYMBOL(soc_mem_entries);
EXPORT_SYMBOL(soc_mem_entry_dump);
EXPORT_SYMBOL(soc_mem_entry_dump_if_changed);
EXPORT_SYMBOL(soc_reg64_field_set);
EXPORT_SYMBOL(soc_reg_field_get);
EXPORT_SYMBOL(soc_reg_field_set);
EXPORT_SYMBOL(soc_reg_sprint_addr);
#if !defined(SOC_NO_DESC)
EXPORT_SYMBOL(soc_mem_desc);
EXPORT_SYMBOL(soc_reg_desc);
#endif /* !defined(SOC_NO_DESC) */
#if !defined(SOC_NO_ALIAS)
EXPORT_SYMBOL(soc_reg_alias);
#endif /* !defined(SOC_NO_ALIAS) */
#if !defined(SOC_NO_NAMES)
EXPORT_SYMBOL(soc_fieldnames);
EXPORT_SYMBOL(soc_mem_name);
EXPORT_SYMBOL(soc_mem_ufalias);
EXPORT_SYMBOL(soc_mem_ufname);
EXPORT_SYMBOL(soc_reg_name);
EXPORT_SYMBOL(soc_regaddrlist_alloc);
EXPORT_SYMBOL(soc_regaddrlist_free);
#endif /* !defined(SOC_NO_NAMES) */
#ifdef BCM_CMICM_SUPPORT
#include <soc/uc_msg.h>
EXPORT_SYMBOL(soc_cmic_uc_msg_start);
EXPORT_SYMBOL(soc_cmic_uc_msg_stop);
EXPORT_SYMBOL(soc_cmic_uc_msg_uc_start);
EXPORT_SYMBOL(soc_cmicm_reg_get);
EXPORT_SYMBOL(soc_pci_mcs_getreg);
EXPORT_SYMBOL(soc_pci_mcs_read);
EXPORT_SYMBOL(soc_pci_mcs_write);
#endif /* BCM_CMICM_SUPPORT */
#ifdef BCM_RPC_SUPPORT
#include <appl/cpudb/cpudb.h>
extern int _rlink_nexthop;
extern int _rpc_nexthop;
extern int  bcm_rlink_start(void);
extern int  bcm_rlink_stop(void);
extern int  bcm_rpc_start(void);
extern int  bcm_rpc_stop(void);
extern void bcm_rpc_dump(void);
EXPORT_SYMBOL(_rlink_nexthop);
EXPORT_SYMBOL(_rpc_nexthop);
EXPORT_SYMBOL(bcm_rlink_stop);
EXPORT_SYMBOL(bcm_rlink_start);
EXPORT_SYMBOL(bcm_rpc_dump);
EXPORT_SYMBOL(bcm_rpc_start);
EXPORT_SYMBOL(bcm_rpc_stop);
EXPORT_SYMBOL(cpudb_key_format);
EXPORT_SYMBOL(cpudb_key_parse);
#endif /* BCM_RPC_SUPPORT */
#endif /* defined (BCM_ESW_SUPPORT) || defined (BCM_DPP_SUPPORT) || defined (BCM_DFE_SUPPORT)*/
#ifdef BCM_DDR3_SUPPORT
#include <soc/shmoo_ddr40.h>
EXPORT_SYMBOL(soc_ddr40_shmoo_ctl);
EXPORT_SYMBOL(soc_ddr40_shmoo_restorecfg);
EXPORT_SYMBOL(soc_ddr40_shmoo_savecfg);
#endif /* BCM_DDR3_SUPPORT */
#endif 
