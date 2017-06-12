
#ifndef _HSL_CTC_NH_H_
#define _HSL_CTC_NH_H_

#if 0
#define HSL_CTC_NHID_MIN 3U
#define HSL_CTC_NHID_MAX 16383U
#define HSL_CTC_NHID_MAXNUM (HSL_CTC_NHID_MAX + 1)
#define HSL_CTC_NHID_INVALID  0xFFFFFFU
#define HSL_CTC_NHID_ALLOCATED 1U
#define HSL_CTC_NHID_DEALLOCATED 0U
#define HSL_CTC_NHID_IS_UNALLOCATED(nhid) ((nhid) >= HSL_CTC_NHID_MIN\
                                     && (nhid) <= HSL_CTC_NHID_MAX\
                                     && (hsl_ctc_nhid_desc.nhids[nhid].alloc) != HSL_CTC_NHID_ALLOCATED)
  
#define HSL_CTC_NHID_DESC_INITIALIZED 0x1U
typedef unsigned int hsl_ipv4Address_t;

extern unsigned int hsl_ctc_nhid_alloc(hsl_ipv4Address_t addr, unsigned char masklen);
extern unsigned int hsl_ctc_nhid_find_alloced(hsl_ipv4Address_t addr, unsigned char masklen);
extern void hsl_ctc_nhid_dealloc(hsl_ipv4Address_t addr, unsigned char masklen);
extern void hsl_ctc_nhid_dealloc_by_id(unsigned int nhid);

#endif
#endif /*_HSL_CTC_NH_H_*/