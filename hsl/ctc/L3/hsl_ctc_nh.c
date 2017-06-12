/* Copyright (C) 2004-2005 IP Infusion, Inc. All Rights Reserved. */
#if 0
#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

#include "ctc_api.h"
#include "sal.h"

/* 
   HAL includes.
*/
#include "hal_types.h"
#include "hal_msg.h"

#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_avl.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_ctc_if.h"
#include "hsl_hash.h"
#include "hsl_ctc_nh.h"
static struct hsl_ctc_nhid_desc_s {
    int initialized;
    struct {
    unsigned int alloc;
    unsigned int nhid;
    hsl_ipv4Address_t addr;
    unsigned char masklen;
    } nhids[HSL_CTC_NHID_MAXNUM+1];
 } hsl_ctc_nhid_desc = {0};

static void hsl_ctc_nhid_init(void)
{
    unsigned int i;
    if (hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
       memset(&hsl_ctc_nhid_desc, 0,  sizeof(hsl_ctc_nhid_desc));
      hsl_ctc_nhid_desc.nhids[0].alloc = HSL_CTC_NHID_ALLOCATED;
      hsl_ctc_nhid_desc.nhids[1].alloc = HSL_CTC_NHID_ALLOCATED;
      hsl_ctc_nhid_desc.nhids[2].alloc = HSL_CTC_NHID_ALLOCATED;
      hsl_ctc_nhid_desc.initialized = HSL_CTC_NHID_DESC_INITIALIZED;
      printk("%s() %d\n", __FUNCTION__, __LINE__);
    }
}
unsigned int
hsl_ctc_nhid_alloc(hsl_ipv4Address_t addr, unsigned char masklen)
{
    unsigned int i;
    if (hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    for (i = HSL_CTC_NHID_MIN; i <= HSL_CTC_NHID_MAX; i++) {
        //printk("%u, alloc=%u\n", i, hsl_ctc_nhid_desc.nhids[i].alloc);
        //printk("HSL_CTC_NHID_IS_UNALLOCATED(%u)=%u\n", i, HSL_CTC_NHID_IS_UNALLOCATED(i));
        if (HSL_CTC_NHID_IS_UNALLOCATED(i)) {
            hsl_ctc_nhid_desc.nhids[i].alloc = HSL_CTC_NHID_ALLOCATED;
            hsl_ctc_nhid_desc.nhids[i].addr = addr;
            hsl_ctc_nhid_desc.nhids[i].nhid = i;
            hsl_ctc_nhid_desc.nhids[i].masklen = masklen;
            printk ("%s() %d alloc %u\n", __FUNCTION__, __LINE__, i);
            return i;
        }
    }
    return HSL_CTC_NHID_INVALID;
}                                  

unsigned int
hsl_ctc_nhid_find_alloced(hsl_ipv4Address_t addr, unsigned char masklen)
{
    unsigned int i;
    if(hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    for (i = HSL_CTC_NHID_MIN; i<= HSL_CTC_NHID_MAX; i++) {
        if (hsl_ctc_nhid_desc.nhids[i].addr == addr
            && hsl_ctc_nhid_desc.nhids[i].masklen == masklen
            && hsl_ctc_nhid_desc.nhids[i].alloc == HSL_CTC_NHID_ALLOCATED) {
            return i;
        }
       
    }
    return HSL_CTC_NHID_INVALID;
} 


void
hsl_ctc_nhid_dealloc(hsl_ipv4Address_t addr, unsigned char masklen)
{
    unsigned int i;
    if(hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    for (i = HSL_CTC_NHID_MIN; i<= HSL_CTC_NHID_MAX; i++) {
        if (hsl_ctc_nhid_desc.nhids[i].addr == addr
            && hsl_ctc_nhid_desc.nhids[i].masklen == masklen) {
            
            hsl_ctc_nhid_desc.nhids[i].alloc = HSL_CTC_NHID_DEALLOCATED;
            hsl_ctc_nhid_desc.nhids[i].addr = 0;
            hsl_ctc_nhid_desc.nhids[i].nhid = 0;
            hsl_ctc_nhid_desc.nhids[i].masklen = 0;
            return;
        }
       
    }
    return;
} 

void
hsl_ctc_nhid_dealloc_by_id(unsigned int nhid)
{
    if(hsl_ctc_nhid_desc.initialized != HSL_CTC_NHID_DESC_INITIALIZED) {
        hsl_ctc_nhid_init();
    }
    if (hsl_ctc_nhid_desc.nhids[nhid].alloc == HSL_CTC_NHID_ALLOCATED) {    
        hsl_ctc_nhid_desc.nhids[nhid].alloc = HSL_CTC_NHID_DEALLOCATED;
    }
    return;
}

#endif

