#ifndef _HSL_TLV_H_
#define _HSL_TLV_H_

/*
  TLV header.
*/
struct hsl_msg_tlv_header
{
  unsigned short type;
  unsigned short length;
};
#define HSL_MSG_TLV_HEADER_SIZE        4

#define HSL_DECODE_TLV_HEADER(TH)                                       \
    do {                                                                \
      TLV_DECODE_GETW ((TH).type);                                      \
      TLV_DECODE_GETW ((TH).length);                                    \
      (TH).length -= HSL_MSG_TLV_HEADER_SIZE;                           \
    } while (0)

/* Macros for encoding and decoding.  */
#define ENCODE_PUT_EMPTY(LEN) \
        do { \
        memset ((void *) (*pnt), 0, (LEN)); \
        *pnt += (LEN); \
        *size -= (LEN); \
        } while (0)
#define ENCODE_PUTC_EMPTY() ENCODE_PUT_EMPTY(1)
#define ENCODE_PUTW_EMPTY() ENCODE_PUT_EMPTY(2)
#define ENCODE_PUTL_EMPTY() ENCODE_PUT_EMPTY(4)

#define ENCODE_SKIP_WORD(LEN)  \
        do { \
        *pnt += ((LEN) * (WORD)); \
        *size -= ((LEN) * (WORD)); \
        } while (0)
#define ENCODE_PUT(V, LEN) \
        do { \
        memcpy ((void *) (*pnt), (const void *) (V), (LEN)); \
        *pnt += (LEN); \
        *size -= (LEN); \
        } while (0)
#define ENCODE_PUTC(V) ENCODE_PUT(V,1)
#define ENCODE_PUTW(V) ENCODE_PUT(V,2)
#define ENCODE_PUTL(V) ENCODE_PUT(V,4)

#define DECODE_GET_EMPTY(LEN) \
        do {                  \
        *pnt += (LEN); \
        *size -= (LEN); \
        } while (0)
#define DECODE_GETC_EMPTY() DECODE_GET_EMPTY(1)
#define DECODE_GETW_EMPTY() DECODE_GET_EMPTY(2)
#define DECODE_GETL_EMPTY() DECODE_GET_EMPTY(4)

#define DECODE_SKIP_WORD(LEN)  \
        do { \
        *pnt += ((LEN) * (WORD)); \
        *size -= ((LEN) * (WORD)); \
        } while (0)
#define DECODE_GET(V, LEN) \
        do { \
        memcpy ((void *) (V), (const void *) (*pnt), (LEN)); \
        *pnt += (LEN); \
        *size -= (LEN); \
        } while (0)
#define DECODE_GETC(V) DECODE_GET(V,1)
#define DECODE_GETW(V) DECODE_GET(V,2)
#define DECODE_GETL(V) DECODE_GET(V,4)

#define TLV_ENCODE_PUTC(V)                                                    \
    do {                                                                      \
      *(*pnt)     = (V) & 0xFF;                                               \
      (*pnt)++;                                                               \
      (*size)--;                                                              \
    } while (0)

#define TLV_ENCODE_PUTW(V)                                                    \
    do {                                                                      \
      *(*pnt)     = ((V) >> 8) & 0xFF;                                        \
      *(*pnt + 1) = (V) & 0xFF;                                               \
      *pnt += 2;                                                              \
      *size -= 2;                                                             \
    } while (0)

#define TLV_ENCODE_PUTL(V)                                                    \
    do {                                                                      \
      *(*pnt)     = ((V) >> 24) & 0xFF;                                       \
      *(*pnt + 1) = ((V) >> 16) & 0xFF;                                       \
      *(*pnt + 2) = ((V) >> 8) & 0xFF;                                        \
      *(*pnt + 3) = (V) & 0xFF;                                               \
      *pnt += 4;                                                              \
      *size -= 4;                                                             \
    } while (0)

#define TLV_ENCODE_PUT(P,L)                                                   \
    do {                                                                      \
      memcpy ((void *)(*pnt), (void *) (P), (L));                        \
      *pnt += (L);                                                            \
      *size -= (L);                                                           \
    } while (0)

#define TLV_ENCODE_PUT_IN4_ADDR(P)	                                      \
    do {                                                                      \
      *(*pnt)     = (*((u_char *)(P)));                                       \
      *(*pnt + 1) = (*((u_char *)(P) + 1));                                   \
      *(*pnt + 2) = (*((u_char *)(P) + 2));                                   \
      *(*pnt + 3) = (*((u_char *)(P) + 3));                                   \
      *pnt += 4;                                                              \
      *size -= 4;                                                             \
    } while (0)

#define TLV_ENCODE_PUT_IN6_ADDR(P)	                                      \
    do {                                                                      \
      *(*pnt)     = (*((u_char *)(P)));                                       \
      *(*pnt + 1) = (*((u_char *)(P) + 1));                                   \
      *(*pnt + 2) = (*((u_char *)(P) + 2));                                   \
      *(*pnt + 3) = (*((u_char *)(P) + 3));                                   \
      *(*pnt + 4) = (*((u_char *)(P) + 4));                                   \
      *(*pnt + 5) = (*((u_char *)(P) + 5));                                   \
      *(*pnt + 6) = (*((u_char *)(P) + 6));                                   \
      *(*pnt + 7) = (*((u_char *)(P) + 7));                                   \
      *(*pnt + 8) = (*((u_char *)(P) + 8));                                   \
      *(*pnt + 9) = (*((u_char *)(P) + 9));                                   \
      *(*pnt + 10) = (*((u_char *)(P) + 10));                                 \
      *(*pnt + 11) = (*((u_char *)(P) + 11));                                 \
      *(*pnt + 12) = (*((u_char *)(P) + 12));                                 \
      *(*pnt + 13) = (*((u_char *)(P) + 13));                                 \
      *(*pnt + 14) = (*((u_char *)(P) + 14));                                 \
      *(*pnt + 15) = (*((u_char *)(P) + 15));                                 \
      *pnt += 16;                                                             \
      *size -= 16;                                                            \
    } while (0)

#define TLV_ENCODE_PUT_EMPTY(L)                                               \
    do {                                                                      \
      memset ((void *) (*pnt), 0, (L));                                  \
      *pnt += (L);                                                            \
      *size -= (L);                                                           \
    } while (0)

#define TLV_DECODE_GETC(V)                                                    \
    do {                                                                      \
      (V) = **pnt;                                                            \
      (*pnt)++;                                                               \
      (*size)--;                                                              \
    } while (0)

#define TLV_DECODE_GETW(V)                                                    \
    do {                                                                      \
      (V) = ((*(*pnt))    << 8)                                               \
          +  (*(*pnt + 1));                                                   \
      *pnt += 2;                                                              \
      *size -= 2;                                                             \
    } while (0)

#define TLV_DECODE_GETL(V)                                                    \
    do {                                                                      \
      (V) = ((*(*pnt))     << 24)                                             \
          + ((*(*pnt + 1)) << 16)                                             \
          + ((*(*pnt + 2)) << 8)                                              \
          +  (*(*pnt + 3));                                                   \
      *pnt += 4;                                                              \
      *size -= 4;                                                             \
    } while (0)

#define TLV_DECODE_GET(P,L)                                                   \
    do {                                                                      \
      memcpy ((void *) (P), *pnt, (L));                                  \
      *pnt += (L);                                                            \
      *size -= (L);                                                           \
    } while (0)

#define TLV_DECODE_GET_IN4_ADDR(P)                                            \
    do {                                                                      \
      (*((u_char *)(P)))     = *(*pnt);                                       \
      (*((u_char *)(P) + 1)) = *(*pnt + 1);                                   \
      (*((u_char *)(P) + 2)) = *(*pnt + 2);                                   \
      (*((u_char *)(P) + 3)) = *(*pnt + 3);                                   \
      *pnt += 4;                                                              \
      *size -= 4;                                                             \
    } while (0)

#define TLV_DECODE_GET_IN6_ADDR(P)                                            \
    do {                                                                      \
      (*((u_char *)(P)))     = *(*pnt);                                       \
      (*((u_char *)(P) + 1)) = *(*pnt + 1);                                   \
      (*((u_char *)(P) + 2)) = *(*pnt + 2);                                   \
      (*((u_char *)(P) + 3)) = *(*pnt + 3);                                   \
      (*((u_char *)(P) + 4)) = *(*pnt + 4);                                   \
      (*((u_char *)(P) + 5)) = *(*pnt + 5);                                   \
      (*((u_char *)(P) + 6)) = *(*pnt + 6);                                   \
      (*((u_char *)(P) + 7)) = *(*pnt + 7);                                   \
      (*((u_char *)(P) + 8)) = *(*pnt + 8);                                   \
      (*((u_char *)(P) + 9)) = *(*pnt + 9);                                   \
      (*((u_char *)(P) + 10)) = *(*pnt + 10);                                 \
      (*((u_char *)(P) + 11)) = *(*pnt + 11);                                 \
      (*((u_char *)(P) + 12)) = *(*pnt + 12);                                 \
      (*((u_char *)(P) + 13)) = *(*pnt + 13);                                 \
      (*((u_char *)(P) + 14)) = *(*pnt + 14);                                 \
      (*((u_char *)(P) + 15)) = *(*pnt + 15);                                 \
      *pnt += 16;                                                             \
      *size -= 16;                                                            \
    } while (0)

#define TLV_DECODE_SKIP(L)                                                    \
    do {                                                                      \
      *pnt += (L);                                                            \
      *size -= (L);                                                           \
    } while (0)

#endif /* _HSL_TLV_H */
