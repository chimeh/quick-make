/****************************************************************************
 * ctc_common_cli.c :         header
 *
 * Copyright (C) 2010 Centec Networks Inc.  All rights reserved.
 *
 * Modify History :
 * Revision       :         V1.0
 * Date           :         2010-7-28
 * Reason         :         First Create
 ****************************************************************************/

#include "sal/core/libc.h"
#include "sal/core/alloc.h"
#include "ctc_types.h"
#include "ctc_sal.h"
#ifdef SDK_IN_KERNEL
#include <linux/kernel.h>
#endif
#ifdef SDK_IN_USERMODE
#include <dirent.h>
#endif
#include "ctc_cli.h"
#include "ctc_common_cli.h"

bool source_quiet_on = FALSE;

#define WHITE_SPACE(C)        ((C) == '\t' || (C) == ' ')
#define EMPTY_LINE(C)         ((C) == '\0' || (C) == '\r' || (C) == '\n')

static int
_parser_string_atrim(char* output, const char* input)
{
    char* p = NULL;

    if (!input)
    {
        return -1;
    }

    if (!input)
    {
        return -1;
    }

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

    sal_strcpy(output, input);

    /*trim right space*/
    p = output + sal_strlen(output) - 1;

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

    return 0;
}

/* Cmd format: delay <M_SEC> */
CTC_CLI(cli_com_delay,
        cli_com_delay_cmd,
        "delay M_SEC",
        "delay time",
        "delay million seconds")
{
    uint32 delay_val = 0;

    CTC_CLI_GET_UINT32("million seconds", delay_val, argv[0]);
    msleep(delay_val * 1000);

    return CLI_SUCCESS;
}

/* Cmd format: source quiet (on|off) */
CTC_CLI(cli_com_source_quiet,
        cli_com_source_quiet_cmd,
        "source quiet (on|off)",
        "Common cmd",
        "Source quiet",
        "on",
        "off")
{
    if (0 == sal_strncmp(argv[0], "on", sal_strlen("on")))
    {
        source_quiet_on = TRUE;
    }
    else if (0 == sal_strncmp(argv[0], "off", sal_strlen("off")))
    {
        source_quiet_on = FALSE;
    }
    else
    {
        ctc_cli_out("%% Error! The 1th para is Invalid, %s\n", argv[0]);
        return CLI_ERROR;
    }

    return CLI_SUCCESS;
}

/* Cmd format: source <file_name> */
//CTC_CLI(cli_com_source_file,
//        cli_com_source_file_cmd,
//        "source INPUT_FILE",
//        "Common cmd",
//        "Input file path")
//{
//#define MAX_CLI_STRING_LEN 512
//    int32 ret = 0;
//    sal_file_t fp = NULL;
//    char* filename = NULL;
//    char string[MAX_CLI_STRING_LEN] = {0};
//    char line[MAX_CLI_STRING_LEN] = {0};
//
//    filename = argv[0];
//
//    fp = sal_fopen(filename, "r");
//    if (NULL == fp)
//    {
//        ctc_cli_out("%% Failed to open the file <%s>\n", filename);
//        return CLI_ERROR;
//    }
//
//    while (sal_fgets(string, MAX_CLI_STRING_LEN, fp))
//    {
//        /*comment line*/
//        if ('#' == string[0])
//        {
//            continue;
//        }
//
//        /*trim left and right space*/
//        sal_memset(line, 0, sizeof(line));
//        ret = _parser_string_atrim(line, string);
//        if (ret < 0)
//        {
//            ctc_cli_out("ERROR! Fail to Paser line %s", string);
//        }
//
//        if (EMPTY_LINE(line[0]))
//        {
//            continue;
//        }
//
//        sal_strcat(line, "\n");
//        if (!source_quiet_on)
//        {
//            ctc_cli_out("%s", line);
//        }
//
//        ret = ctc_vti_command(g_ctc_vti, line);
//        if (ret && source_quiet_on)
//        {
//            ctc_cli_out("%s", line);
//        }
//    }
//
//    sal_fclose(fp);
//    fp = NULL;
//
//    return CLI_SUCCESS;
//}

CTC_CLI(cli_com_show_history,
        cli_com_show_history_cmd,
        "show history",
        CTC_CLI_SHOW_STR,
        "Display the session command history")
{
    int index;
    int print_index = 1;

    for (index = g_ctc_vti->hindex + 1; index != g_ctc_vti->hindex;)
    {
        if (index == CTC_VTI_MAXHIST)
        {
            index = 0;
            continue;
        }

        if (g_ctc_vti->hist[index] != NULL)
        {
            ctc_cli_out("%d  %s%s", print_index, g_ctc_vti->hist[index], CTC_VTI_NEWLINE);
            print_index++;
        }

        index++;
    }

    return CLI_SUCCESS;
}

int32
ctc_com_cli_init(uint8 cli_tree_mode)
{
    /* register some common cli */


    return 0;
}

