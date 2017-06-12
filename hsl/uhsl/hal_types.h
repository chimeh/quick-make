/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_TYPES_H_
#define _HAL_TYPES_H_

typedef unsigned long long u_int64_t; /* 64 bit unsigned integer */
typedef unsigned int u_int32_t;       /* 32 bit unsigned integer */
typedef unsigned short u_int16_t;     /* 16 bit unsigned integer */
typedef unsigned char u_int8_t;       /* 8  bit unsigned integer */

typedef signed long long s_int64_t;  /* 64 bit signed integer */
typedef signed int s_int32_t;        /* 32 bit signed integer */
typedef signed short s_int16_t;      /* 16 bit signed integer */
typedef signed char s_int8_t;        /* 8  bit signed integer */

typedef unsigned long long u64;       /* 64 bit unsigned integer */
typedef unsigned int u32;             /* 32 bit unsigned integer */
typedef unsigned short u16;           /* 16 bit unsigned integer */
typedef unsigned char u8;             /* 8  bit unsigned integer */

typedef signed long long s64;         /* 64 bit signed integer */
typedef signed int s32;               /* 32 bit signed integer */
typedef signed short s16;             /* 16 bit signed integer */
typedef signed char s8;               /* 8  bit signed integer */


typedef unsigned char u_char;               /* 8  bit unsigned  char */

/*
** Boolean values
*/
typedef enum
{
    HAL_FALSE = 0,                        /* Everybody calls zero false... */
    HAL_TRUE = (!0)               /* Some want TRUE=1 or TRUE=-1 or TRUE!=0 */
} hal_bool_t;


#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN                                      6
#endif /* ETHER_ADDR_LEN */


/* MAC address length. */
#define HAL_HW_LENGTH                                       ETHER_ADDR_LEN

/* Default and Max values */
#define HAL_VLAN_NAME_LEN                                   32
#define HAL_VLAN_DEFAULT_ID                                 1
#define HAL_MAX_VLAN_ID                                     4094
#define HAL_RMAP_NAME_LEN                                   255


/* Nexthop type. */
enum hal_ipuc_nexthop_type
{
  HAL_IPUC_UNSPEC,              /* Placeholder for 'unspecified' */
  HAL_IPUC_LOCAL,               /* Nexthop is directly attached. */
  HAL_IPUC_REMOTE,              /* Nexthop is remote. */
  HAL_IPUC_SEND_TO_CP,          /* Send to Control plane. */
  HAL_IPUC_BLACKHOLE,           /* Drop. */
  HAL_IPUC_PROHIBIT             /* Administratively probihited. */
};

/* IPv4 address. */
struct hal_in4_addr
{
    u_int32_t s_addr;
};


struct hal_in6_addr
{
    union
    {
        u_int8_t  u6_addr8[16];
        u_int16_t u6_addr16[8];
        u_int32_t u6_addr32[4];
    } in6_u;
};

#ifndef pal_in6_addr
#define pal_in6_addr hal_in6_addr
#endif

#ifndef pal_in4_addr
#define pal_in4_addr hal_in4_addr
#endif

struct hal_in6_header
{
    union
    {
        struct hal_ip6_hdrctl
        {
            u_int32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                               20 bits flow-ID */
            u_int16_t ip6_un1_plen;   /* payload length */
            u_int8_t  ip6_un1_nxt;    /* next header */
            u_int8_t  ip6_un1_hlim;   /* hop limit */
        } hal_ip6_un1;
        u_int8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } hal_ip6_ctlun;

    struct hal_in6_addr ip6_src;      /* source address */
    struct hal_in6_addr ip6_dst;      /* destination address */
};

struct hal_in6_pktinfo
{
    struct hal_in6_addr ipi6_addr;
    int    ifindex;
};


#define IPV6_ADDR_ZERO(addr) (((addr).in6_u.u6_addr32[0] == 0) && ((addr).in6_u.u6_addr32[1] == 0) && \
                              ((addr).in6_u.u6_addr32[2] == 0) && ((addr).in6_u.u6_addr32[3] == 0))

struct hal_prefix
{
    u_int8_t family;
    u_int8_t prefixlen;
    u_int8_t pad1;
    u_int8_t pad2;
    union
    {
        u_int8_t prefix;
        struct hal_in4_addr prefix4;
        struct hal_in6_addr prefix6;
        struct
        {
            struct hal_in4_addr id;
            struct hal_in4_addr adv_router;
        } lp;
        u_int8_t val[9];
    } u;
};

/* Some simple macros for Ethernet addresses. */
#define HAL_ETH_BROADCAST_MAC    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

#define HAL_IS_ETH_BROADCAST(addr)                                                  \
    (((unsigned char *) (addr))[0] == ((unsigned char) 0xff))

#define HAL_IS_ETH_MULTICAST(addr)                                                  \
    (((unsigned char *) (addr))[0] & ((unsigned char) 0x1))

#define HAL_IS_ETH_ADDRESS_EQUAL(A,B)                                               \
    ((((unsigned char *) (A))[0] == ((unsigned char *) (B))[0]) &&                  \
    (((unsigned char *) (A))[1] == ((unsigned char *) (B))[1]) &&                   \
    (((unsigned char *) (A))[2] == ((unsigned char *) (B))[2]) &&                   \
    (((unsigned char *) (A))[3] == ((unsigned char *) (B))[3]) &&                   \
    (((unsigned char *) (A))[4] == ((unsigned char *) (B))[4]) &&                   \
    (((unsigned char *) (A))[5] == ((unsigned char *) (B))[5]))

#define HAL_COPY_ETH_ADDRESS(DST,SRC)                                               \
  do {                                                                              \
    ((unsigned char *) (DST))[0] = ((unsigned char *) (SRC))[0];                    \
    ((unsigned char *) (DST))[1] = ((unsigned char *) (SRC))[1];                    \
    ((unsigned char *) (DST))[2] = ((unsigned char *) (SRC))[2];                    \
    ((unsigned char *) (DST))[3] = ((unsigned char *) (SRC))[3];                    \
    ((unsigned char *) (DST))[4] = ((unsigned char *) (SRC))[4];                    \
    ((unsigned char *) (DST))[5] = ((unsigned char *) (SRC))[5];                    \
  } while (0)



#ifndef __KERNEL__
typedef _Bool bool;
#endif /* __KERNEL__ */
#endif /* _HAL_TYPES_H_ */
