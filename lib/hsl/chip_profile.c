
/***************************************************************
 *
 * Header Files
 *
 ***************************************************************/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <net/ip_fib.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/igmp.h>
#include <linux/mroute.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <linux/ctype.h>
#include "lkm_file.h"
#include "kconfig.h"

typedef unsigned char        uint8;        /* 8-bit quantity  */
typedef unsigned short        uint16;        /* 16-bit quantity */
typedef unsigned int        uint32;        /* 32-bit quantity */


typedef signed char        int8;        /* 8-bit quantity  */
typedef signed short        int16;        /* 16-bit quantity */
typedef signed int        int32;        /* 32-bit quantity */

/***************************************************************
 *
 *  Defines and Macros
 *
 ***************************************************************/
#define MAX_EXTERNAL_NHNUM          16384
#define ACL_REDIRECT_FWD_PTR_NUM    1024
#define WHITE_SPACE(C) ((C) == '\t' || (C) == ' ')
#define EMPTY_LINE(C)     ((C) == '\0' || (C) == '\r' || (C) == '\n')
#define NUMBER_CHAR(C) \
    ((C) == '0' || (C) == '1' || (C) == '1' || (C) == '2' || (C) == '3' || (C) == '4' \
     || (C) == '5' || (C) == '6' || (C) == '7' || (C) == '8' || (C) == '9')




/****************************************************************************
 *
 * Global and Declaration
 *
 *****************************************************************************/

/***************************************************************
 *
 *  Functions
 *
 ***************************************************************/
static void
_string_atrim(uint8* input, uint8* output)
{
    uint8* p = NULL;

    /*trim left space*/
    while (*input != '\0')
    {
        if (WHITE_SPACE(*input))
        {
            ++input;
        }
        else
        {
            break;
        }
    }

    strcpy((char*)output, (char*)input);
    /*trim right space*/
    p = output + strlen((char*)output) - 1;

    while (p >= output)
    {
        /*skip empty line*/
        if (WHITE_SPACE(*p) || ('\r' == (*p)) || ('\n' == (*p)))
        {
            --p;
        }
        else
        {
            break;
        }
    }

    *(++p) = '\0';

    return;
}

static int32
_get_interage(uint8* string, uint32* integer)
{
    uint8* ch = NULL;
    uint32 val = 0;

    ch = (uint8*)strstr((char*)string, "=");

    if (NULL == ch)
    {
        return -1;
    }
    else
    {
        ch++;
    }

    while (isspace(*ch))
    {
        ch++;
    }

    sscanf((char*)ch, "%d", &val);
    *integer = val;

    return 0;
}

static int32
_get_string(uint8* string, uint8* str)
{
    uint8* ch = NULL;

    ch = (uint8*)strstr((char*)string, "=");

    if (NULL == ch)
    {
        return -1;
    }
    else
    {
        ch++;
    }

    while (((*ch) != '\0') && isspace(*ch))
    {
        ch++;
    }

    strcpy((char*)str, (char*)ch);

    return 0;
}

static int32
_get_string_key_var(uint8* string, uint8* key, uint8* var)
{
    uint8* ch = NULL;
    uint8* var_ch = NULL;
    uint8* key_ch_tail = NULL;
    size_t key_len;
    ch = (uint8*)strstr((char*)string, "=");
    
    if (NULL == ch)
    {
        return -1;
    }
    else
    {   key_ch_tail = ch;
        var_ch = ch + 1;
    }

    while (((*var_ch) != '\0') && isspace(*var_ch))
    {
        var_ch++;
    }
    key_len = (size_t)(key_ch_tail - string);
    while ((key_ch_tail > string) && isspace(string[key_len-1]))
    {
        key_len--;
        key_ch_tail--;
    }
    strcpy((char*)var, (char*)var_ch);
    strncpy((char*)key, (char*)string, key_len);
    key[key_len] = '\0';
    return 0;
}

static int32
_do_parser_line(uint8* string, void* p_chip_info)
{
    int32 ret = 0;
    uint8 type_str[64];
    uint8 key_var[256];
    uint8 var_str[256];
    uint32 val = 0;
    
    memset(type_str, 0, sizeof(type_str));
    
    printk("%s\n", string);
    if (0 == strncmp("[Local chip_num]", (char*)string, strlen("[Local chip_num]")))
    {
        ret = _get_interage(string, &val);
        if (ret < 0 || val < 1 || val > 2)
        {
            return -1;
        }
        else
        {
            ;
        }
    }
    else if (0 == strncmp("[EXAMPLE_NAME]", (char*)string, strlen("[EXAMPLE_NAME]")))
    {
        ret = _get_string(string, type_str);
        if (ret < 0)
        {
            return -1;
        }

    } else {
        ret = _get_string_key_var(string, key_var, var_str);
        if (ret < 0)
        {
            return -1;
        }
        printk("%s = %s\n", key_var, var_str);
        kconfig_set(key_var, var_str);
    }

    return 0;
}


int
get_chip_profile(char* fname,
    void * p_init_config)
{
    int32   ret;
    char    filepath[128];
    int8    string[128];
    int8    line[128];
    lkm_file_t fp = NULL;


    /*set chip profile default */
    

    ret = 0;
    /* check whether has this file at /mnt/flash/  */
    memset(filepath, 0, sizeof(filepath));
    strcpy(filepath, (char*)fname);

    /*OPEN FILE*/
    fp = lkm_fopen((char*)filepath, "r");

    if ((NULL == fp))
    {
        ret = 0;
        goto SET_INIT_CONFIG;
    }

    /*parse profile*/
    while (lkm_fgets((char*)line, 128, fp))
    {
        /*comment line*/
        if ('#' == line[0])
        {
            continue;
        }

        /*trim left and right space*/
        memset(string, 0, sizeof(string));

        _string_atrim((uint8*)line, (uint8*)string);

        if (EMPTY_LINE(string[0]))
        {
            continue;
        }

        ret = _do_parser_line((uint8*)string, p_init_config);

        if (ret < 0)
        {
            printk("Warn: parse line: %s on %s failed", string, filepath);
        }
    }
SET_INIT_CONFIG:
    /* set init sdk param*/
    
    
    if (fp)
    {
        lkm_fclose(fp);
    }

    return ret;
}


