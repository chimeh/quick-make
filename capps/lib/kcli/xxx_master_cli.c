#include "sal/core/libc.h"
#include "sal/core/alloc.h"
#include "xxx_types.h"
#include "xxx_sal.h"
#ifdef SDK_IN_KERNEL
#include <linux/kernel.h>
#endif
#ifdef SDK_IN_USERMODE
#include <dirent.h>
#endif
#include "xxx_cli.h"

#include "xxx_cli.h"
#include "xxx_cmd.h"


#include "xxx_shell_server.h"



extern int32
xxx_app_cli_init(void);

extern int32
xxx_debug_tools_cli_init(void);
extern int32
xxx_sdk_deinit(void);

extern uint8 port_mapping_mode;

typedef int32 xxx_sample_cli_init_callback (uint8 cli_tree_mode);
xxx_sample_cli_init_callback* sample_cli_init_callback = NULL;

uint8 cli_end = 0;
uint8 xxx_cli_init = 0;

/* "exit" function.  */
void
xxx_cli_mode_exit(xxx_vti_t* vti)
{
    switch (vti->node)
    {
    case EXEC_MODE:
#if 0
        xxx_sdk_deinit();
        cli_end = 1;
#endif
        vti->quit(vti);
        break;

    case XXX_SDK_MODE:
    case XXX_CMODEL_MODE:
        vti->node = EXEC_MODE;
        break;

    case XXX_SDK_OAM_CHAN_MODE:
        vti->node = XXX_SDK_MODE;
        break;

    case XXX_DEBUG_MODE:
        vti->node = EXEC_MODE;
        break;

    case XXX_INTERNAL_MODE:
        vti->node = EXEC_MODE;
        break;

    case XXX_APP_MODE:
        vti->node = EXEC_MODE;
        break;

    default:
        vti->node = EXEC_MODE;
        break;
    }
}

#if defined(SDK_IN_USERMODE)
XXX_CLI(xxx_cli_common_exit_server,
        xxx_cli_common_exit_server_cmd,
        "exit server",
        "Exit current mode and down to previous mode"
        "Exit Server Progress")
{
    xxx_sdk_deinit();

    exit(0);

    return CLI_SUCCESS;
}
#endif
XXX_CLI(xxx_cli_common_help,
        xxx_cli_common_help_cmd,
        "help",
        "Description of the interactive help system")
{
    xxx_cli_out("  SDK CLI provides advanced help feature.  When you need help,\n\
	  anytime at the command line please press '?'.\n\
	  If nothing matches, the help list will be empty and you must backup\n\
	  until entering a '?' shows the available options.\n\
	  Two styles of help are provided:\n\
	  1. Full help is available when you are ready to enter a \n\
	      command argument (e.g. 'show ?') and describes each possible \n\
	      argument.\n\
	  2. Partial help is provided when an abbreviated argument is entered \n\
	      and you want to know what arguments match the input \n\
	      (e.g. 'show ve?').\n");

    return CLI_SUCCESS;
}

/* Generic "xxx_cli_common_end" command.  */
XXX_CLI(xxx_cli_common_end,
        xxx_cli_common_end_cmd,
        "end",
        "End current mode and change to EXEC mode")
{
    if (g_xxx_vti->node != EXEC_MODE)
    {
        g_xxx_vti->node = EXEC_MODE;
    }

    return CLI_SUCCESS;
}

/* Generic "xxx_cli_common_end" command.  */
XXX_CLI(xxx_cli_common_show_ver,
        xxx_cli_common_show_ver_cmd,
        "show version",
        XXX_CLI_SHOW_STR,
        "Sdk version")
{
    xxx_cli_out("    SDK %s Released at %s.\n", "a", "b");

    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_exit_config,
        xxx_cli_common_exit_config_cmd,
        "exit",
        "Exit current mode and down to previous mode")
{
    xxx_cli_mode_exit(vty);
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_quit,
        xxx_cli_common_quit_cmd,
        "quit",
        "Exit current mode and down to previous mode")
{
    xxx_cli_mode_exit(vty);
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_enter_sdk_mode,
        xxx_cli_common_enter_sdk_mode_cmd,
        "enter sdk mode",
        "Enter",
        "Ctc SDK mode",
        "Mode")
{
    g_xxx_vti->node  = XXX_SDK_MODE;
    return CLI_SUCCESS;
}
XXX_CLI(xxx_cli_common_enter_debug_mode,
        xxx_cli_common_enter_debug_mode_cmd,
        "enter debug mode",
        "Enter",
        "Ctc Debug mode",
        "Mode")
{
    g_xxx_vti->node  = XXX_DEBUG_MODE;
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_enter_internal_debug_mode,
        xxx_cli_common_enter_internal_debug_mode_cmd,
        "enter internal mode",
        "Enter",
        "Internal Debug mode",
        "Mode")
{
    g_xxx_vti->node  = XXX_INTERNAL_MODE;
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_enter_app_mode,
        xxx_cli_common_enter_app_mode_cmd,
        "enter app mode",
        "Enter",
        "App mode",
        "Mode")
{
    g_xxx_vti->node  = XXX_APP_MODE;
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_enter_cmodel_mode,
        xxx_cli_common_enter_cmodel_mode_cmd,
        "enter cmodle mode",
        "Enter",
        "Ctc Cmodel mode",
        "Mode")
{
    g_xxx_vti->node  = XXX_CMODEL_MODE;
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_fast_enter_sdk_mode,
        xxx_cli_common_fast_enter_sdk_mode_cmd,
        "sdk",
        "Enter SDK Mode")
{
    g_xxx_vti->node  = XXX_SDK_MODE;
    return CLI_SUCCESS;
}
XXX_CLI(xxx_cli_common_fast_enter_debug_mode,
        xxx_cli_common_fast_enter_debug_mode_cmd,
        "debug",
        "Enter Debug mode")
{
    g_xxx_vti->node  = XXX_DEBUG_MODE;
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_fast_enter_internal_debug_mode,
        xxx_cli_common_fast_enter_internal_debug_mode_cmd,
        "internal",
        "Enter Internal Debug mode")
{
    g_xxx_vti->node  = XXX_INTERNAL_MODE;
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_fast_enter_app_mode,
        xxx_cli_common_fast_enter_app_mode_cmd,
        "app",
        "Enter app mode")
{
    g_xxx_vti->node  = XXX_APP_MODE;
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_fast_enter_cmodel_mode,
        xxx_cli_common_fast_enter_cmodel_mode_cmd,
        "cmodel",
        "Enter cmodel mode")
{
    g_xxx_vti->node  = XXX_CMODEL_MODE;
    return CLI_SUCCESS;
}




XXX_CLI(xxx_cli_common_debug_on,
        xxx_cli_common_debug_on_cmd,
        "debug on",
        XXX_CLI_DEBUG_STR,
        "Enable debugging information")
{


    return CLI_SUCCESS;
}
XXX_CLI(xxx_cli_common_debug_off,
        xxx_cli_common_debug_off_cmd,
        "no debug on",
        XXX_CLI_NO_STR,
        XXX_CLI_DEBUG_STR,
        "Enable debugging information")
{

    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_debug_show,
        xxx_cli_common_debug_show_cmd,
        "show debug on",
        XXX_CLI_SHOW_STR,
        XXX_CLI_DEBUG_STR,
        "Enable debugging information")
{
    xxx_cli_out("Debug on:%s\n", 1 ? "TRUE" : "FALSE");
    return CLI_SUCCESS;
}



xxx_cmd_node_t exec_node =
{
    EXEC_MODE,
    "\rXXX_CLI# ",
};

xxx_cmd_node_t sdk_node =
{
    XXX_SDK_MODE,
    "\rXXX_CLI(xxx-sdk)# ",
};

xxx_cmd_node_t cmodel_node =
{
    XXX_CMODEL_MODE,
    "\rXXX_CLI(xxx-cmodel)# ",
};

xxx_cmd_node_t oam_chan_node =
{
    XXX_SDK_OAM_CHAN_MODE,
    "\rXXX_CLI(oam_chan)# ",
};

xxx_cmd_node_t debug_node =
{
    XXX_DEBUG_MODE,
    "\rXXX_CLI(xxx-debug)# ",
};

xxx_cmd_node_t internal_node =
{
    XXX_INTERNAL_MODE,
    "\rXXX_CLI(xxx-internal)# ",
};

xxx_cmd_node_t app_node =
{
    XXX_APP_MODE,
    "\rXXX_CLI(xxx-app)# ",
};

XXX_CLI(xxx_cli_common_hostname,
        xxx_cli_common_hostname_cmd,
        "hostname NAME",
        "Set system's network name",
        "System's network name")
{

    char hostname[HOST_NAME] = {0};

    sal_memcpy(hostname, argv[0], 15);
    sal_sprintf(exec_node.prompt, "\r%s# ", hostname);
    sal_sprintf(sdk_node.prompt, "\r%s(xxx-sdk)# ", hostname);
    sal_sprintf(cmodel_node.prompt, "\r%s(xxx-cmodel)# ", hostname);
    sal_sprintf(oam_chan_node.prompt, "\r%s(oam_chan)# ", hostname);
    sal_sprintf(debug_node.prompt, "\r%s(xxx-debug)# ", hostname);
    sal_sprintf(internal_node.prompt, "\r%s(xxx-internal)# ", hostname);
    return CLI_SUCCESS;
}

XXX_CLI(xxx_cli_common_error_debug,
        xxx_cli_common_error_debug_cmd,
        "debug error (on|off)",
        XXX_CLI_DEBUG_STR,
        "Error return",
        "ON",
        "OFF")
{

    return CLI_SUCCESS;
}


int32
xxx_register_sample_init_cli_callback(void* func)
{
    if(func) {
        return 0;
    }
    sample_cli_init_callback = (xxx_sample_cli_init_callback*)func;

    return 0;
}

int xxx_master_printf(struct xxx_vti_struct_s* vti, const char *szPtr, const int szPtr_len)
{
    
    return 0;
}

int xxx_master_quit(struct xxx_vti_struct_s* vti)
{
    cli_end = 1;

    return 0;
}



int xxx_master_cli(unsigned int is_xxx_shell)
{
    int  nbytes = 0;
    char*   pread_buf = NULL;

    if (xxx_cli_init == 0)
    {
        //xxx_debug_register_cb(xxx_cli_out);
        //xxx_debug_register_log_cb(xxx_cli_out);

        xxx_cmd_init(0);
        /* Install top nodes. */
        xxx_install_node(&sdk_node, NULL);

        xxx_install_node(&exec_node, NULL);

        xxx_install_node(&cmodel_node, NULL);
        xxx_install_node(&oam_chan_node, NULL);
        xxx_install_node(&debug_node, NULL);
        xxx_install_node(&internal_node, NULL);
        xxx_install_node(&app_node, NULL);

        xxx_vti_init(XXX_SDK_MODE);

        /*common CLIs*/
        /*mode CLIs*/
        install_element(EXEC_MODE, &xxx_cli_common_enter_sdk_mode_cmd);
        install_element(EXEC_MODE, &xxx_cli_common_enter_cmodel_mode_cmd);
        install_element(EXEC_MODE, &xxx_cli_common_enter_debug_mode_cmd); /*debug mode*/
        install_element(EXEC_MODE, &xxx_cli_common_enter_internal_debug_mode_cmd); /*debug mode*/
        install_element(EXEC_MODE, &xxx_cli_common_enter_app_mode_cmd);

        install_element(EXEC_MODE, &xxx_cli_common_fast_enter_sdk_mode_cmd);
        install_element(EXEC_MODE, &xxx_cli_common_fast_enter_cmodel_mode_cmd);
        install_element(EXEC_MODE, &xxx_cli_common_fast_enter_debug_mode_cmd); /*debug mode*/
        install_element(EXEC_MODE, &xxx_cli_common_fast_enter_internal_debug_mode_cmd); /*debug mode*/
        install_element(EXEC_MODE, &xxx_cli_common_fast_enter_app_mode_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_fast_enter_cmodel_mode_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_fast_enter_debug_mode_cmd); /*debug mode*/
        install_element(XXX_SDK_MODE, &xxx_cli_common_fast_enter_internal_debug_mode_cmd); /*debug mode*/
        install_element(XXX_SDK_MODE, &xxx_cli_common_fast_enter_app_mode_cmd);

        install_element(XXX_CMODEL_MODE, &xxx_cli_common_fast_enter_sdk_mode_cmd);
        install_element(XXX_CMODEL_MODE, &xxx_cli_common_fast_enter_debug_mode_cmd); /*debug mode*/
        install_element(XXX_CMODEL_MODE, &xxx_cli_common_fast_enter_internal_debug_mode_cmd); /*debug mode*/
        install_element(XXX_CMODEL_MODE, &xxx_cli_common_fast_enter_app_mode_cmd);

        install_element(XXX_INTERNAL_MODE, &xxx_cli_common_fast_enter_sdk_mode_cmd);
        install_element(XXX_INTERNAL_MODE, &xxx_cli_common_fast_enter_cmodel_mode_cmd);
        install_element(XXX_INTERNAL_MODE, &xxx_cli_common_fast_enter_debug_mode_cmd); /*debug mode*/
        install_element(XXX_INTERNAL_MODE, &xxx_cli_common_fast_enter_app_mode_cmd);

        install_element(XXX_DEBUG_MODE, &xxx_cli_common_fast_enter_sdk_mode_cmd);
        install_element(XXX_DEBUG_MODE, &xxx_cli_common_fast_enter_cmodel_mode_cmd);
        install_element(XXX_DEBUG_MODE, &xxx_cli_common_fast_enter_internal_debug_mode_cmd); /*debug mode*/
        install_element(XXX_DEBUG_MODE, &xxx_cli_common_fast_enter_app_mode_cmd);

        install_element(XXX_APP_MODE, &xxx_cli_common_fast_enter_sdk_mode_cmd);
        install_element(XXX_APP_MODE, &xxx_cli_common_fast_enter_cmodel_mode_cmd);
        install_element(XXX_APP_MODE, &xxx_cli_common_fast_enter_internal_debug_mode_cmd); /*debug mode*/
        install_element(XXX_APP_MODE, &xxx_cli_common_fast_enter_debug_mode_cmd);

        /*help CLIs*/
        install_element(XXX_SDK_MODE, &xxx_cli_common_help_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_show_ver_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_hostname_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_error_debug_cmd);


        /*quit CLIs*/
        install_element(EXEC_MODE, &xxx_cli_common_exit_config_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_exit_config_cmd);
        install_element(XXX_CMODEL_MODE, &xxx_cli_common_exit_config_cmd);
        install_element(XXX_DEBUG_MODE, &xxx_cli_common_exit_config_cmd);
        install_element(XXX_INTERNAL_MODE, &xxx_cli_common_exit_config_cmd);
        install_element(XXX_APP_MODE, &xxx_cli_common_exit_config_cmd);

        install_element(EXEC_MODE, &xxx_cli_common_quit_cmd);
        install_element(XXX_CMODEL_MODE, &xxx_cli_common_quit_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_quit_cmd);
        install_element(XXX_DEBUG_MODE, &xxx_cli_common_quit_cmd);
        install_element(XXX_INTERNAL_MODE, &xxx_cli_common_quit_cmd);
        install_element(XXX_APP_MODE, &xxx_cli_common_quit_cmd);

        install_element(XXX_SDK_MODE, &xxx_cli_common_end_cmd);
        install_element(XXX_CMODEL_MODE, &xxx_cli_common_end_cmd);
        install_element(XXX_DEBUG_MODE, &xxx_cli_common_end_cmd);
        install_element(XXX_INTERNAL_MODE, &xxx_cli_common_end_cmd);
        install_element(XXX_APP_MODE, &xxx_cli_common_end_cmd);


#if defined(SDK_IN_USERMODE)
        install_element(XXX_SDK_MODE, &xxx_cli_common_gateway_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_tftp_debug_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_boot_debug_cmd);
        install_element(XXX_SDK_MODE, &xxx_cli_common_rm_debug_cmd);
#endif



        xxx_com_cli_init(XXX_SDK_MODE);
        
        if (sample_cli_init_callback != NULL)
        {
            sample_cli_init_callback(XXX_SDK_MODE);
        }

        xxx_cli_init = 1;

        xxx_sort_node();
        g_xxx_vti->node  = XXX_SDK_MODE;
        cli_end = 0;

    }
    else
    {
        g_xxx_vti->node  = XXX_SDK_MODE;
        cli_end = 0;
    }

    if(!is_xxx_shell)
    {
        g_xxx_vti->printf = xxx_master_printf;
        g_xxx_vti->quit   = xxx_master_quit;

        pread_buf = sal_malloc(XXX_VTI_BUFSIZ);

        if(NULL == pread_buf)
        {
            printk("%s:%d pread_buf nil\n",__FUNCTION__,__LINE__);
            return -1;
        }

        /* 1. Open device & save termios config, set O_NONBLOCK */
        set_terminal_raw_mode(XXX_VTI_SHELL_MODE_DEFAULT);

        while (cli_end == 0)
        {
            /* 2. Read & call function xxx_vti_read_cmd */
            nbytes = xxx_vti_read(pread_buf,XXX_VTI_BUFSIZ,XXX_VTI_SHELL_MODE_DEFAULT);
            xxx_vti_read_cmd(g_xxx_vti,pread_buf,nbytes);
        }

        /* 3. Close device and restore */
        restore_terminal_mode(XXX_VTI_SHELL_MODE_DEFAULT);
        printk("%s:%d cli close\n",__FUNCTION__,__LINE__);
        return 0;
    }
    else
    {
        
        printk("%s:%d cli init OK \n",__FUNCTION__,__LINE__);
        return xxx_vty_socket();
    }

}



