/*
 * Virtual terminal [aka TeletYpe] interface routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "sal/core/libc.h"
#include "sal/core/alloc.h"
#include "xxx_types.h"
#include "xxx_sal.h"
#include "xxx_cmd.h"
#include "xxx_cli.h"
#ifdef SDK_IN_VXWORKS
#include "timers.h "
#endif

#ifdef _SAL_LINUX_UM
#include "time.h"
#endif

/* Vty events */
enum event
{
    XXX_VTI_SERV,
    XXX_VTI_READ,
    XXX_VTI_WRITE,
    XXX_VTI_TIMEOUT_RESET,
#ifdef VTYSH
    VTYSH_SERV,
    VTYSH_READ
#endif /* VTYSH */
};

/* Vector which store each vti structure. */
static vector vtivec;

/* Vty timeout value. */
static unsigned long vti_timeout_val = XXX_VTI_TIMEOUT_DEFAULT;

/* Current directory. */
char* vti_cwd = NULL;

/* Configure lock. */
static int vti_config;

xxx_vti_t* g_xxx_vti = NULL;

extern void *sal_realloc(void *ptr, size_t size);


xxx_vti_t*
xxx_vti_create(int mode);

static char g_xxx_vti_out_buf[1024] = "";
int
xxx_vti_out(xxx_vti_t* vti, const char* format, ...)
{
    va_list args;
    int len = 0;
    int size = 1024;
    char* p = NULL;

    va_start(args, format);

    /* Try to write to initial buffer.  */
#ifdef SDK_IN_VXWORKS
    len = vsprintf(g_xxx_vti_out_buf, format, args);
#else
    len = vsnprintf(g_xxx_vti_out_buf, sizeof(g_xxx_vti_out_buf), format, args);
#endif

    va_end(args);

    /* Initial buffer is not enough.  */
    if (len < 0 || len >= size)
    {
        while (1)
        {
            if (len > -1)
            {
                size = len + 1;
            }
            else
            {
                size = size * 2;
            }

            p = sal_realloc(p, size);
            if (!p)
            {
                return -1;
            }

#ifdef SDK_IN_VXWORKS
            len = vsprintf(p, format, args);
#else
            len = vsnprintf(p, size, format, args);
#endif

            if (len > -1 && len < size)
            {
                break;
            }
        }
    }

    /* When initial buffer is enough to store all output.  */
    if (!p)
    {
        p = g_xxx_vti_out_buf;
    }

    /* Pointer p must point out buffer. */
    if(vti->printf)
        vti->printf(vti,p,len);

    /* If p is not different with buf, it is allocated buffer.  */
    if (p != g_xxx_vti_out_buf)
    {
        sal_free(p);
    }

    return len;
}

/* Put out prompt and wait input from user. */
void
xxx_vti_prompt(xxx_vti_t* vti)
{
    xxx_vti_out(vti,"%s",xxx_cmd_prompt(vti->node));
}

/* Allocate new vti struct. */
xxx_vti_t*
xxx_vti_new()
{
    xxx_vti_t* new = sal_alloc(sizeof(xxx_vti_t),"kcli");

    if (!new)
    {
        return NULL;
    }
    sal_memset(new, 0, sizeof(xxx_vti_t));

    new->buf = sal_alloc(XXX_VTI_BUFSIZ, "kcli");
    if (!new->buf)
    {
        sal_free(new);
        return NULL;
    }
    sal_memset(new->buf, 0, XXX_VTI_BUFSIZ);

    new->max = XXX_VTI_BUFSIZ;

    return new;
}

/* Command execution over the vti interface. */
int
xxx_vti_command(xxx_vti_t* vti, char* buf)
{
    int ret;
    vector vline;

    /* Split readline string up into the vector */
    vline = xxx_cmd_make_strvec(buf);

    if (vline == NULL)
    {
        return CMD_SUCCESS;
    }

    ret = xxx_cmd_execute_command(vline, vti, NULL);

    if (ret != CMD_SUCCESS)
    {
        switch (ret)
        {
        case CMD_WARNING: /* do nothing*/
            /*printf ("%% System warning...\n");
            */
            break;

        case CMD_ERR_AMBIGUOUS:
            xxx_vti_out(vti, "%% Ambiguous command\n\r");
            break;

        case CMD_ERR_NO_MATCH:
            xxx_vti_out(vti, "%% Unrecognized command\n\r");
            break;

        case CMD_ERR_INCOMPLETE:
            xxx_vti_out(vti, "%% Incomplete command\n\r");
            break;

        case CMD_SYS_ERROR:
            xxx_vti_out(vti, "%% System warning...\n\r");
            break;

        default:
            break;
        }
    }

    xxx_cmd_free_strvec(vline);

    return ret;
}

char telnet_backward_char = 0x08;
char telnet_space_char = ' ';

/* Basic function to write buffer to vti. */
void
xxx_vti_write(xxx_vti_t* vti, char* buf, uint32 nbytes)
{
    vti->printf(vti,buf,nbytes);
}

/* Ensure length of input buffer.  Is buffer is short, double it. */
static void
xxx_vti_ensure(xxx_vti_t* vti, int length)
{
    if (vti->max <= length)
    {
        vti->max *= 2;
        vti->buf = sal_realloc(vti->buf, vti->max);
    }
}

/* Basic function to insert character into vti. */
static void
xxx_vti_self_insert(xxx_vti_t* vti, char c)
{
    int length;

    xxx_vti_ensure(vti, vti->length + 1);
    length = vti->length - vti->cp;
    sal_memmove(&vti->buf[vti->cp + 1], &vti->buf[vti->cp], length);
    vti->buf[vti->cp] = c;

    /*xxx_vti_write (vti, &vti->buf[vti->cp], length + 1);
    for (i = 0; i < length; i++)
      xxx_vti_write (vti, &telnet_backward_char, 1);*/

    vti->cp++;
    vti->length++;
}

/* Self insert character 'c' in overwrite mode. */
static void
xxx_vti_self_insert_overwrite(xxx_vti_t* vti, char c)
{
    xxx_vti_ensure(vti, vti->length + 1);
    vti->buf[vti->cp++] = c;

    if (vti->cp > vti->length)
    {
        vti->length++;
    }

/*
  if ((vti->node == AUTH_NODE) || (vti->node == AUTH_ENABLE_NODE))
    return;
*/
    xxx_vti_write(vti, &c, 1);
}

/* Insert a word into vti interface with overwrite mode. */
static void
xxx_vti_insert_word_overwrite(xxx_vti_t* vti, char* str)
{
    int len = sal_strlen(str);

    xxx_vti_write(vti, str, len);
    sal_strcpy(&vti->buf[vti->cp], str);
    vti->cp += len;
    vti->length = vti->cp;
}

/* Forward character. */
static void
xxx_vti_forward_char(xxx_vti_t* vti)
{
    if (vti->cp < vti->length)
    {
        xxx_vti_write(vti, &vti->buf[vti->cp], 1);
        vti->cp++;
    }
}

/* Backward character. */
static void
xxx_vti_backward_char(xxx_vti_t* vti)
{
    if (vti->cp > 0)
    {
        vti->cp--;
        xxx_vti_write(vti, &telnet_backward_char, 1);
    }
}

/* Move to the beginning of the line. */
static void
xxx_vti_beginning_of_line(xxx_vti_t* vti)
{
    while (vti->cp)
    {
        xxx_vti_backward_char(vti);
    }
}

/* Move to the end of the line. */
static void
xxx_vti_end_of_line(xxx_vti_t* vti)
{
    while (vti->cp < vti->length)
    {
        xxx_vti_forward_char(vti);
    }
}

static void xxx_vti_kill_line_from_beginning(xxx_vti_t*);
static void xxx_vti_redraw_line(xxx_vti_t*);

/* Print command line history.  This function is called from
   xxx_vti_next_line and xxx_vti_previous_line. */
static void
xxx_vti_history_print(xxx_vti_t* vti)
{
    int length;

    xxx_vti_kill_line_from_beginning(vti);

    if (vti->hist[vti->hp] != NULL)
    {
        /* Get previous line from history buffer */
        length = sal_strlen(vti->hist[vti->hp]);
        sal_memcpy(vti->buf, vti->hist[vti->hp], length);
        vti->cp = vti->length = length;

        /* Redraw current line */
        xxx_vti_redraw_line(vti);
    }
}

/* Show next command line history. */
void
xxx_vti_next_line(xxx_vti_t* vti)
{
    int try_index;
    int try_count = 0;

    if (vti->hp == vti->hindex)
    {
        xxx_vti_kill_line_from_beginning(vti);
        return;
    }

    /* Try is there history exist or not. */
    try_index = vti->hp;
    if (try_index == (XXX_VTI_MAXHIST - 1))
    {
        try_index = 0;
    }
    else
    {
        try_index++;
    }

    while ((vti->hist[try_index] == NULL) && (try_count < XXX_VTI_MAXHIST))
    {
        if (try_index == (XXX_VTI_MAXHIST - 1))
        {
            try_index = 0;
        }
        else
        {
            try_index++;
        }

        try_count++;
    }

    /* If there is not history return. */
    if (vti->hist[try_index] == NULL)
    {
        xxx_vti_kill_line_from_beginning(vti);
        return;
    }
    else
    {
        vti->hp = try_index;
    }

    xxx_vti_history_print(vti);
}

/* Show previous command line history. */
void
xxx_vti_previous_line(xxx_vti_t* vti)
{
    int try_index;
    int try_count = 0;

    try_index = vti->hp;

    if (try_index == 0)
    {
        try_index = XXX_VTI_MAXHIST - 1;
    }
    else
    {
        try_index--;
    }

    while (vti->hist[try_index] == NULL && try_count < XXX_VTI_MAXHIST)
    {
        if (try_index == 0)
        {
            try_index = XXX_VTI_MAXHIST - 1;
        }
        else
        {
            try_index--;
        }

        try_count++;
    }

    if (vti->hist[try_index] == NULL)
    {
        xxx_vti_kill_line_from_beginning(vti);
        return;
    }
    else
    {
        vti->hp = try_index;
    }

    xxx_vti_history_print(vti);
}

/* This function redraw all of the command line character. */
static void
xxx_vti_redraw_line(xxx_vti_t* vti)
{
    xxx_vti_write(vti, vti->buf, vti->length);
    vti->cp = vti->length;
}

/* Forward word. */
void
xxx_vti_forward_word(xxx_vti_t* vti)
{
    while (vti->cp != vti->length && vti->buf[vti->cp] != ' ')
    {
        xxx_vti_forward_char(vti);
    }

    while (vti->cp != vti->length && vti->buf[vti->cp] == ' ')
    {
        xxx_vti_forward_char(vti);
    }
}

/* Backward word without skipping training space. */
void
xxx_vti_backward_pure_word(xxx_vti_t* vti)
{
    while (vti->cp > 0 && vti->buf[vti->cp - 1] != ' ')
    {
        xxx_vti_backward_char(vti);
    }
}

/* Backward word. */
void
xxx_vti_backward_word(xxx_vti_t* vti)
{
    while (vti->cp > 0 && vti->buf[vti->cp - 1] == ' ')
    {
        xxx_vti_backward_char(vti);
    }

    while (vti->cp > 0 && vti->buf[vti->cp - 1] != ' ')
    {
        xxx_vti_backward_char(vti);
    }
}

/* When '^D' is typed at the beginning of the line we move to the down
   level. */
static void
xxx_vti_down_level(xxx_vti_t* vti)
{
    xxx_vti_out(vti, "%s", XXX_VTI_NEWLINE);
    xxx_vti_prompt(vti);
    vti->cp = 0;
}

/* When '^Z' is received from vti, move down to the enable mode. */
void
xxx_vti_end_config(xxx_vti_t* vti)
{
    xxx_vti_out(vti, "%s", XXX_VTI_NEWLINE);

    switch (vti->node)
    {
    case XXX_VIEW_NODE:
    case XXX_ENABLE_NODE:
        /* Nothing to do. */
        break;

    case XXX_CONFIG_NODE:
    case XXX_INTERFACE_NODE:
    case XXX_KEYCHAIN_NODE:
    case XXX_KEYCHAIN_KEY_NODE:
    case XXX_MASC_NODE:
    case XXX_VTI_NODE:
        xxx_vti_config_unlock(vti);
        vti->node = XXX_ENABLE_NODE;
        break;

    default:
        /* Unknown node, we have to ignore it. */
        break;
    }

    xxx_vti_prompt(vti);
    vti->cp = 0;
}

/* Delete a charcter at the current point. */
static void
xxx_vti_delete_char(xxx_vti_t* vti)
{
    int i;
    int size;

    if (vti->length == 0)
    {
        xxx_vti_down_level(vti);
        return;
    }

    if (vti->cp == vti->length)
    {
        return; /* completion need here? */

    }

    size = vti->length - vti->cp;

    vti->length--;
    sal_memmove(&vti->buf[vti->cp], &vti->buf[vti->cp + 1], size - 1);
    vti->buf[vti->length] = '\0';

    xxx_vti_write(vti, &vti->buf[vti->cp], size - 1);
    xxx_vti_write(vti, &telnet_space_char, 1);

    for (i = 0; i < size; i++)
    {
        xxx_vti_write(vti, &telnet_backward_char, 1);
    }
}

/* Delete a character before the point. */
static void
xxx_vti_delete_backward_char(xxx_vti_t* vti)
{
    if (vti->cp == 0)
    {
        return;
    }

    xxx_vti_backward_char(vti);
    xxx_vti_delete_char(vti);
}

/* Kill rest of line from current point. */
static void
xxx_vti_kill_line(xxx_vti_t* vti)
{
    int i;
    int size;

    size = vti->length - vti->cp;

    if (size == 0)
    {
        return;
    }

    for (i = 0; i < size; i++)
    {
        xxx_vti_write(vti, &telnet_space_char, 1);
    }

    for (i = 0; i < size; i++)
    {
        xxx_vti_write(vti, &telnet_backward_char, 1);
    }

    sal_memset(&vti->buf[vti->cp], 0, size);
    vti->length = vti->cp;
}

/* Kill line from the beginning. */
static void
xxx_vti_kill_line_from_beginning(xxx_vti_t* vti)
{
    xxx_vti_beginning_of_line(vti);
    xxx_vti_kill_line(vti);
}

/* Delete a word before the point. */
void
xxx_vti_forward_kill_word(xxx_vti_t* vti)
{
    while (vti->cp != vti->length && vti->buf[vti->cp] == ' ')
    {
        xxx_vti_delete_char(vti);
    }

    while (vti->cp != vti->length && vti->buf[vti->cp] != ' ')
    {
        xxx_vti_delete_char(vti);
    }
}

/* Delete a word before the point. */
static void
xxx_vti_backward_kill_word(xxx_vti_t* vti)
{
    while (vti->cp > 0 && vti->buf[vti->cp - 1] == ' ')
    {
        xxx_vti_delete_backward_char(vti);
    }

    while (vti->cp > 0 && vti->buf[vti->cp - 1] != ' ')
    {
        xxx_vti_delete_backward_char(vti);
    }
}

void
xxx_vti_clear_buf(xxx_vti_t* vti)
{
    sal_memset(vti->buf, 0, vti->max);
}

/* Transpose chars before or at the point. */
static void
xxx_vti_transpose_chars(xxx_vti_t* vti)
{
    char c1, c2;

    /* If length is short or point is near by the beginning of line then
       return. */
    if (vti->length < 2 || vti->cp < 1)
    {
        return;
    }

    /* In case of point is located at the end of the line. */
    if (vti->cp == vti->length)
    {
        c1 = vti->buf[vti->cp - 1];
        c2 = vti->buf[vti->cp - 2];

        xxx_vti_backward_char(vti);
        xxx_vti_backward_char(vti);
        xxx_vti_self_insert_overwrite(vti, c1);
        xxx_vti_self_insert_overwrite(vti, c2);
    }
    else
    {
        c1 = vti->buf[vti->cp];
        c2 = vti->buf[vti->cp - 1];

        xxx_vti_backward_char(vti);
        xxx_vti_self_insert_overwrite(vti, c1);
        xxx_vti_self_insert_overwrite(vti, c2);
    }
}

/* Do completion at vti interface. */
static void
xxx_vti_complete_command(xxx_vti_t* vti)
{
    int i;
    int ret;
    char** matched = NULL;
    vector vline;
    char match_list[256] = {'\0'};

    vline = xxx_cmd_make_strvec(vti->buf);
    if (vline == NULL)
    {
        return;
    }

    /* In case of 'help \t'. */
    if (sal_isspace((int)vti->buf[vti->length - 1]))
    {
        xxx_vti_vec_set(vline, '\0');
    }

    matched = xxx_cmd_complete_command(vline, vti, &ret);

    xxx_cmd_free_strvec(vline);

    /*printf( "%s", XXX_VTI_NEWLINE);
    */
    switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:

        break;

    case CMD_ERR_NO_MATCH:

        break;

    case CMD_COMPLETE_FULL_MATCH:
        xxx_vti_backward_pure_word(vti);
        xxx_vti_insert_word_overwrite(vti, matched[0]);
        xxx_vti_self_insert(vti, ' ');
        xxx_vti_out(vti, " ");
        sal_free(matched[0]);
        break;

    case CMD_COMPLETE_MATCH:
        xxx_vti_backward_pure_word(vti);
        xxx_vti_insert_word_overwrite(vti, matched[0]);
        sal_free(matched[0]);
        xxx_vti_vec_only_index_free(matched);
        return;
        break;

    case CMD_COMPLETE_LIST_MATCH:
        xxx_vti_out(vti, "\n\r");

        for (i = 0; matched[i] != NULL; i++)
        {
            if (i != 0 && ((i % 6) == 0))
            {
                /*printf( "%s", XXX_VTI_NEWLINE);
                */
                xxx_vti_out(vti, "\n\r");
            }

            /*printf( "%-10s ", matched[i]);
            */
            sal_sprintf(match_list, "%-18s ", matched[i]);
            xxx_vti_write(vti, match_list, sal_strlen(match_list));
            if (sal_strcmp(matched[i], "<cr>") != 0)
            {
                sal_free(matched[i]);
            }
        }

        /*printf( "%s", XXX_VTI_NEWLINE);
        */
        xxx_vti_out(vti, "\n\r");
        xxx_vti_prompt(vti);
        xxx_vti_redraw_line(vti);
        break;

    case CMD_ERR_NOTHING_TODO:
        /*xxx_vti_prompt (vti);
        xxx_vti_redraw_line (vti);
        */
        break;

    default:
        break;
    }

    if (matched)
    {
        xxx_vti_vec_only_index_free(matched);
    }
}

void
xxx_vti_describe_fold(xxx_vti_t* vti, int cmd_width, int desc_width, xxx_cmd_desc_t* desc)
{
    char* buf, * cmd, * p;
    int pos;

    cmd = desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd;

    if (desc_width <= 0)
    {
        xxx_vti_out(vti, "  %-*s  %s%s", cmd_width, cmd, desc->str, XXX_VTI_NEWLINE);
        return;
    }

    buf = sal_alloc(sal_strlen(desc->str) + 1, "kcli");
    if (!buf)
    {
        return;
    }
    sal_memset(buf, 0, sal_strlen(desc->str) + 1);

    for (p = desc->str; sal_strlen(p) > desc_width; p += pos + 1)
    {
        for (pos = desc_width; pos > 0; pos--)
        {
            if (*(p + pos) == ' ')
            {
                break;
            }
        }

        if (pos == 0)
        {
            break;
        }

        sal_strncpy(buf, p, pos);
        buf[pos] = '\0';
        xxx_vti_out(vti, "  %-*s  %s%s", cmd_width, cmd, buf, XXX_VTI_NEWLINE);

        cmd = "";
    }

    xxx_vti_out(vti, "  %-*s  %s%s", cmd_width, cmd, p, XXX_VTI_NEWLINE);

    sal_free(buf);
}

/* Describe matched command function. */
static void
xxx_vti_describe_command(xxx_vti_t* vti)
{
    int ret;
    vector vline;
    vector describe;
    int i, width, desc_width;
    xxx_cmd_desc_t* desc, * desc_cr = NULL;

    vline = xxx_cmd_make_strvec(vti->buf);

    /* In case of '> ?'. */
    if (vline == NULL)
    {
        vline = xxx_vti_vec_init(1);
        xxx_vti_vec_set(vline, '\0');
    }
    else if (sal_isspace((int)vti->buf[vti->length - 1]))
    {
        xxx_vti_vec_set(vline, '\0');
    }

    describe = xxx_cmd_describe_command(vline, vti, &ret);

    xxx_vti_out(vti, "%s", XXX_VTI_NEWLINE);

    /* Ambiguous error. */
    switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:
        xxx_cmd_free_strvec(vline);
        xxx_vti_out(vti, "%% Ambiguous command%s", XXX_VTI_NEWLINE);
        xxx_vti_prompt(vti);
        xxx_vti_redraw_line(vti);
        return;
        break;

    case CMD_ERR_NO_MATCH:
        xxx_cmd_free_strvec(vline);
        xxx_vti_out(vti, "%% Unrecognized command%s", XXX_VTI_NEWLINE);
        xxx_vti_prompt(vti);
        xxx_vti_redraw_line(vti);
        return;
        break;
    }

    /* Get width of command string. */
    width = 0;

    for (i = 0; i < vector_max(describe); i++)
    {
        if ((desc = vector_slot(describe, i)) != NULL)
        {
            int len;

            if (desc->cmd[0] == '\0')
            {
                continue;
            }

            len = sal_strlen(desc->cmd);
            if (desc->cmd[0] == '.')
            {
                len--;
            }

            if (width < len)
            {
                width = len;
            }
        }
    }

    /* Get width of description string. */
    desc_width = vti->width - (width + 6);

    /* Print out description. */
    for (i = 0; i < vector_max(describe); i++)
    {
        if ((desc = vector_slot(describe, i)) != NULL)
        {
            if (desc->cmd[0] == '\0')
            {
                continue;
            }

            if (sal_strcmp(desc->cmd, "<cr>") == 0)
            {
                desc_cr = desc;
                continue;
            }

            if (!desc->str)
            {
                xxx_vti_out(vti, "  %-s%s",
                            desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
                            XXX_VTI_NEWLINE);
            }
            else if (desc_width >= sal_strlen(desc->str))
            {
                xxx_vti_out(vti, "  %-*s  %s%s", width,
                            desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
                            desc->str, XXX_VTI_NEWLINE);
            }
            else
            {
                xxx_vti_describe_fold(vti, width, desc_width, desc);
            }
        }
    }

    if ((desc = desc_cr))
    {
        if (!desc->str)
        {
            xxx_vti_out(vti, "  %-s%s",
                        desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
                        XXX_VTI_NEWLINE);
        }
        else if (desc_width >= sal_strlen(desc->str))
        {
            xxx_vti_out(vti, "  %-*s  %s%s", width,
                        desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
                        desc->str, XXX_VTI_NEWLINE);
        }
        else
        {
            xxx_vti_describe_fold(vti, width, desc_width, desc);
        }
    }

    xxx_cmd_free_strvec(vline);
    xxx_vti_vec_free(describe);

    xxx_vti_prompt(vti);
    xxx_vti_redraw_line(vti);
}

/* ^C stop current input and do not add command line to the history. */
static void
xxx_vti_stop_input(xxx_vti_t* vti)
{
    vti->cp = vti->length = 0;
    xxx_vti_clear_buf(vti);
    xxx_vti_out(vti, "%s", XXX_VTI_NEWLINE);

    switch (vti->node)
    {
    case XXX_VIEW_NODE:
    case XXX_ENABLE_NODE:
        /* Nothing to do. */
        break;

    case XXX_CONFIG_NODE:
    case XXX_INTERFACE_NODE:
    case XXX_KEYCHAIN_NODE:
    case XXX_KEYCHAIN_KEY_NODE:
    case XXX_MASC_NODE:
    case XXX_VTI_NODE:
        xxx_vti_config_unlock(vti);
        vti->node = XXX_ENABLE_NODE;
        break;

    default:
        /* Unknown node, we have to ignore it. */
        break;
    }

    xxx_vti_prompt(vti);

    /* Set history pointer to the latest one. */
    vti->hp = vti->hindex;
}

void
xxx_vti_append_history_command(char* cmd)
{
#ifdef ISGCOV
    FILE* p_history_file = NULL;

    p_history_file = fopen("history", "a+");
    if ((!p_history_file) || feof((FILE*)p_history_file))
    {
        return;
    }

    sal_fprintf(p_history_file, "%s\n", cmd);

    fclose(p_history_file);
    p_history_file = NULL;
#endif
    return ;
}


/* Add current command line to the history buffer. */
static void
xxx_vti_hist_add(xxx_vti_t* vti)
{
    int index;

    if (vti->length == 0)
    {
        return;
    }

    index = vti->hindex ? vti->hindex - 1 : XXX_VTI_MAXHIST - 1;

    xxx_vti_append_history_command(vti->buf);

    /* Ignore the same string as previous one. */
    if (vti->hist[index])
    {
        if (sal_strcmp(vti->buf, vti->hist[index]) == 0)
        {
            vti->hp = vti->hindex;
            return;
        }
    }

    /* Insert history entry. */
    if (vti->hist[vti->hindex])
    {
        sal_free(vti->hist[vti->hindex]);
    }

    vti->hist[vti->hindex] = XSTRDUP(MTYPE_VTI_HIST, vti->buf);

    /* History index rotation. */
    vti->hindex++;
    if (vti->hindex == XXX_VTI_MAXHIST)
    {
        vti->hindex = 0;
    }

    vti->hp = vti->hindex;
}

/* Execute current command line. */
static int
xxx_vti_execute(xxx_vti_t* vti)
{
    int ret;

    ret = CMD_SUCCESS;

    xxx_vti_out(vti, "\n\r");
    ret = xxx_vti_command(vti, vti->buf);
    xxx_vti_hist_add(vti);
    vti->cp = vti->length = 0;
    xxx_vti_clear_buf(vti);

    xxx_vti_prompt(vti);

    return ret;
}

#define CONTROL(X)  ((X) - '@')
#define VTI_NORMAL     0
#define VTI_PRE_ESCAPE 1
#define VTI_ESCAPE     2

/* Escape character command map. */
void
xxx_vti_escape_map(unsigned char c, xxx_vti_t* vti)
{
    switch (c)
    {
    case ('A'):
        xxx_vti_previous_line(vti);
        break;

    case ('B'):
        xxx_vti_next_line(vti);
        break;

    case ('C'):
        xxx_vti_forward_char(vti);
        break;

    case ('D'):
        xxx_vti_backward_char(vti);
        break;

    default:
        break;
    }

    /* Go back to normal mode. */
    vti->escape = XXX_VTI_NORMAL;
}

static int
is_char_visible(unsigned char c)
{
    if (c >= 32 && c < 127)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/* Read data via vti netlink. */
static char g_vti_out_buf[2048] = {0};
static char g_xxx_vti_read_buf[XXX_VTI_READ_BUFSIZ] = {0};
int
xxx_vti_read_cmd(xxx_vti_t* vty, const char* szbuf, const int buf_len)
{
    int i = 0;
    int flag = 1;
    int nbytes;


    sal_memcpy(g_xxx_vti_read_buf,szbuf,buf_len < XXX_VTI_READ_BUFSIZ ? buf_len : XXX_VTI_READ_BUFSIZ);
    nbytes = buf_len;
    /*read(ioTaskStdGet(0,0), &buf[i], 1) *//*for vxworks*/
    for (i = 0; i < nbytes; i++)
    {
#ifdef SDK_IN_VXWORKS
        /*delay_a_while();
        */
#else
        /*usleep(1);
        *//*1 ms */
#endif

        if (is_char_visible(g_xxx_vti_read_buf[i]) && (vty->escape == VTI_NORMAL))
        {
            uint8   out_buf_len = 0;
            sal_memset(g_vti_out_buf,'\0',sizeof(g_vti_out_buf));
            g_vti_out_buf[0] = g_xxx_vti_read_buf[i];
            out_buf_len++;
            if (vty->cp != vty->length)
            {
                uint8 dist = 0;
                uint8 j = 0;

                /*move forward*/
                dist = vty->length - vty->cp;
                sal_memcpy(&g_vti_out_buf[1],&vty->buf[vty->cp], dist);
                out_buf_len += dist;
                /*move backward*/
                for (j=0; j< dist; j++)
                {
                    g_vti_out_buf[1 + dist + j] = telnet_backward_char;
                }
                out_buf_len += dist;
            }
            vty->printf(vty,g_vti_out_buf,out_buf_len);

            /*sal_memcpy(&g_xxx_vti->buf[g_xxx_vti->cp], &buf[i], 1); */
        }

        /* Escape character. */
        if (vty->escape == VTI_ESCAPE)
        {
            xxx_vti_escape_map (g_xxx_vti_read_buf[i], vty);
            continue;
        }

        /* Pre-escape status. */
        if (vty->escape == VTI_PRE_ESCAPE)
        {
            switch (g_xxx_vti_read_buf[i])
            {
                case '[':
                    vty->escape = VTI_ESCAPE;
                    break;
                case 'b':
                    xxx_vti_backward_word (vty);
                    vty->escape = VTI_NORMAL;
                    break;
                case 'f':
                    xxx_vti_forward_word (vty);
                    vty->escape = VTI_NORMAL;
                    break;
                case 'd':
                    xxx_vti_forward_kill_word (vty);
                    vty->escape = VTI_NORMAL;
                    break;
                case CONTROL('H'):
                case 0x7f:
                    xxx_vti_backward_kill_word (vty);
                    vty->escape = VTI_NORMAL;
                    break;
                default:
                    vty->escape = VTI_NORMAL;
                    break;
            }
            continue;

        }

        switch (g_xxx_vti_read_buf[i])
        {
            case CONTROL('A'):
                xxx_vti_beginning_of_line(vty);
                break;

            case CONTROL('B'):
                xxx_vti_backward_char(vty);
                break;

            case CONTROL('C'):
                xxx_vti_stop_input(vty);
                flag = 0;
                break;

            case CONTROL('D'):
                xxx_vti_delete_char(vty);
                break;

            case CONTROL('E'):
                xxx_vti_end_of_line(vty);
                break;

            case CONTROL('F'):
                xxx_vti_forward_char(vty);
                break;

            case CONTROL('H'):
            case 0x7f:
                xxx_vti_delete_backward_char(vty);
                break;

            case CONTROL('K'):
                xxx_vti_kill_line(vty);
                break;

            case CONTROL('N'):
                xxx_vti_next_line(vty);
                break;

            case CONTROL('P'):
                xxx_vti_previous_line(vty);
                break;

            case CONTROL('T'):
                xxx_vti_transpose_chars(vty);
                break;

            case CONTROL('U'):
                xxx_vti_kill_line_from_beginning(vty);
                break;

            case CONTROL('W'):
                xxx_vti_backward_kill_word(vty);
                break;

            case CONTROL('Z'):
                xxx_vti_end_config(vty);
                break;

            case '\n':
            case '\r':
                xxx_vti_execute(vty);
                break;

            case '\t':
                xxx_vti_complete_command(vty);
                break;

            case '?':
                xxx_vti_describe_command(vty);
                break;

            case '\033':
                if (i + 1 < nbytes && g_xxx_vti_read_buf[i + 1] == '[')
                {
                    vty->escape = VTI_ESCAPE;
                    i++;
                }
                else
                {
                    vty->escape = VTI_PRE_ESCAPE;
                }
                break;

                break;


            default:
                if (g_xxx_vti_read_buf[i] > 31 && g_xxx_vti_read_buf[i] < 127)
                {
                    xxx_vti_self_insert(vty, g_xxx_vti_read_buf[i]);
                }

                break;
        }
    }

    return 0;
}


/* Read data via vti socket. */
int
xxx_vti_read(char* buf, uint32 buf_size,uint32 mode)
{
    int nbytes = 0;

    if (XXX_VTI_SHELL_MODE_DEFAULT == mode)
    {
        //nbytes = sal_read(0, buf, buf_size);
    }
    else
    {
        /* write your code here */
    }

    return nbytes;
}

/* Create new g_xxx_vti structure. */
xxx_vti_t*
xxx_vti_create(int mode)
{
    xxx_vti_t* vti;

    /* Allocate new vti structure and set up default values. */
    vti = xxx_vti_new();
    if (!vti)
    {
        return NULL;
    }

    vti->fd = 0;
    vti->type = XXX_VTI_TERM;
    vti->address = "";

    vti->node = mode;

    vti->fail = 0;
    vti->cp = 0;
    xxx_vti_clear_buf(vti);
    vti->length = 0;
    sal_memset(vti->hist, 0, sizeof(vti->hist));
    vti->hp = 0;
    vti->hindex = 0;
    xxx_vti_vec_set_index(vtivec, 0, vti);
    vti->status = VTI_NORMAL;
    vti->v_timeout = vti_timeout_val;

    vti->lines = -1;
    vti->iac = 0;
    vti->iac_sb_in_progress = 0;
    vti->width = 0;

    xxx_vti_prompt(vti);

    return vti;
}

int
xxx_vti_config_lock(xxx_vti_t* vti)
{
    if (vti_config == 0)
    {
        vti->config = 1;
        vti_config = 1;
    }

    return vti->config;
}

int
xxx_vti_config_unlock(xxx_vti_t* vti)
{
    if (vti_config == 1 && vti->config == 1)
    {
        vti->config = 0;
        vti_config = 0;
    }

    return vti->config;
}

char*
xxx_vti_get_cwd()
{
    return vti_cwd;
}

int
xxx_vti_shell(xxx_vti_t* vti)
{
    return vti->type == XXX_VTI_SHELL ? 1 : 0;
}

int
xxx_vti_shell_serv(xxx_vti_t* vti)
{
    return vti->type == XXX_VTI_SHELL_SERV ? 1 : 0;
}

void
xxx_vti_init_vtish()
{
    vtivec = xxx_vti_vec_init(VECTOR_MIN_SIZE);
}

/* Install vti's own commands like `who' command. */
void
xxx_vti_init(int mode)
{
    /* For further configuration read, preserve current directory. */
    vtivec = xxx_vti_vec_init(VECTOR_MIN_SIZE);

    /* Initilize server thread vector. */
    /*Vxxx_vti_serv_thread = xxx_vti_vec_init (VECTOR_MIN_SIZE);*/

    if (!g_xxx_vti)
    {
        g_xxx_vti = xxx_vti_create(mode);
    }
}

