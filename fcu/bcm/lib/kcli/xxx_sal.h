#ifndef __XXX_SAL__
#define __XXX_SAL__

/**
 * @file kal.h
 */

#include "xxx_types.h"

#define _SAL_DEBUG
#if defined(_SAL_LINUX_KM)
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#elif defined(_SAL_LINUX_UM)
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <ctype.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <netpacket/packet.h>
#include <time.h>
#elif defined(_SAL_VXWORKS)
#include <vxWorks.h>
#include <taskLib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/times.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <timers.h>
#include <sockLib.h>
#include <inetLib.h>
#include <time.h>
#define _SDK_NOT_READLINE_
#endif

extern void sal_free(void *p);
extern void *sal_malloc(size_t size);
extern void *sal_calloc(size_t size);

#define BOOLEAN_BIT(b) ((b) ? 1 : 0)

#undef sal_memcpy
#define sal_memcpy    memcpy

#undef sal_memset
#define sal_memset  memset

#undef sal_memcmp
#define sal_memcmp   memcmp

#undef sal_memmove
#define sal_memmove  memmove
/*string*/
#undef sal_vprintf
#define sal_vprintf vprintf

#undef sal_sprintf
#define sal_sprintf sprintf

#undef sal_sscanf
#define sal_sscanf sscanf

#undef sal_strcpy
#define sal_strcpy strcpy

#undef sal_strncpy
#define sal_strncpy strncpy

#undef sal_strcat
#define sal_strcat strcat

#undef sal_strncat
#define sal_strncat strncat

#undef sal_strcmp
#define sal_strcmp strcmp

#undef sal_strncmp
#define sal_strncmp strncmp

#undef sal_strlen
#define sal_strlen strlen

#undef sal_snprintf
#define sal_snprintf snprintf

#undef sal_vsnprintf
#define sal_vsnprintf vsnprintf

#undef sal_vsprintf
#define sal_vsprintf vsprintf


#undef sal_strtos32
#undef sal_strtou32
#undef sal_atoi
#undef sal_strtol
#undef sal_strtol
#if defined(_SAL_LINUX_KM)
#define sal_strtou32(x, y, z) simple_strtoul((char*)x, (char**)y, z)
#define sal_strtos32(x, y, z) simple_strtol((char*)x, (char**)y, z)
#define sal_atoi(x) simple_strtol((char*)x, NULL, 10)
#define sal_strtol(x, y, z) simple_strtol((char*)x, (char**)y, z)

#undef sal_fprintf
#define sal_fprintf sal_fprintf
#else
#define sal_atoi atoi
#define sal_strtos32(x, y, z) strtol((char*)x, (char**)y, z)
#define sal_strtou32(x, y, z) strtoul((char*)x, (char**)y, z)
#define sal_strtol strtol
/* file operation */
#undef sal_open
#define sal_open open

#undef sal_close
#define sal_close close

#undef sal_fopen
#define sal_fopen fopen

#undef sal_fclose
#define sal_fclose fclose

#undef sal_read
#define sal_read read

#undef sal_write
#define sal_write write

#undef sal_fread
#define sal_fread fread

#undef sal_fwrite
#define sal_fwrite fwrite

#undef sal_fprintf
#define sal_fprintf fprintf
/*memory */
#undef sal_malloc
#define sal_malloc   malloc

#undef sal_realloc
#define sal_realloc realloc

#undef sal_free
#define sal_free   free

#undef sal_time
#define sal_time time

#undef sal_ctime
#define sal_ctime ctime

#endif

#undef sal_strchr
#define sal_strchr strchr

#undef sal_strstr
#define sal_strstr strstr

#undef sal_strrchr
#define sal_strrchr strrchr

#undef sal_strspn
#define sal_strspn strspn

#undef sal_strerror
#define sal_strerror strerror

#undef sal_strtok
#define sal_strtok strtok

#undef sal_strtok_r
#define sal_strtok_r strtok_r

#undef sal_tolower
#undef sal_toupper
#define sal_tolower tolower
#define sal_toupper toupper

#undef sal_isspace
#undef sal_isdigit
#undef sal_isxdigit
#undef sal_isalpha
#undef sal_isalnum
#undef sal_isupper
#undef sal_islower
#define sal_isspace isspace
#define sal_isdigit isdigit
#define sal_isxdigit isxdigit
#define sal_isalpha isalpha
#define sal_isalnum isalnum
#define sal_isupper isupper
#define sal_islower islower
#define sal_isprint isprint

#undef sal_ntohl
#undef sal_htonl
#undef sal_ntohs
#undef sal_htons

#define sal_ntohl ntohl
#define sal_htonl htonl
#define sal_ntohs ntohs
#define sal_htons htons





#define SET_BIT(flag, bit)      (flag) = (flag) | (1 << (bit))
#define CLEAR_BIT(flag, bit)    (flag) = (flag) & (~(1 << (bit)))
#define IS_BIT_SET(flag, bit)   (((flag) & (1 << (bit))) ? 1 : 0)

#define SET_BIT_RANGE(dst, src, s_bit, len) \
    { \
        uint8 i = 0; \
        for (i = 0; i < len; i++) \
        { \
            if (IS_BIT_SET(src, i)) \
            { \
                SET_BIT(dst, (s_bit + i)); \
            } \
            else \
            { \
                CLEAR_BIT(dst, (s_bit + i)); \
            } \
        } \
    }

#ifdef _SAL_VXWORKS
#define PTR_TO_INT(x)       ((uint32)(((uint32)(x)) & 0xFFFFFFFF))
#define INT_TO_PTR(x)       ((void*)(uint32)(x))

struct in6_addr
{
    union
    {
        uint8       u6_addr8[16];
        uint16      u6_addr16[8];
        uint32      u6_addr32[4];
    }
    in6_u;
#define s6_addr         in6_u.u6_addr8
#define s6_addr16       in6_u.u6_addr16
#define s6_addr32       in6_u.u6_addr32
};

#ifndef AF_INET6
#define AF_INET6    10  /* IP version 6 */
#endif

#endif

#ifdef _SAL_LINUX_KM
#ifndef AF_INET6
#define AF_INET6    10  /* IP version 6 */
#endif

#ifndef AF_INET
#define AF_INET    9  /* IP version 4 */
#endif

#endif


#endif /* !__XXX_SAL__ */

