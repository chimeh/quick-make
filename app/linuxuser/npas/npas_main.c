/*
* Copyright (C), 2001-2010, Galaxywind Co., Ltd. 
* Description: NPAS主函数
*
*/
#include <sys/ioctl.h>  /* for open(), ioctl(), xen */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>	/* for pthread_create(), xen */
#include <sys/stat.h>
#include <fcntl.h>		/* for open(), xen */
#include <sys/mman.h>
#include <errno.h>		/* for errno, xen */
#include <malloc.h>
#include <string.h>
#include "thread.h"
#include <sys/signal.h> // for signal
#include <semaphore.h>

#include "getopt.h"
#include "command.h"    /* for print_version(), vty_init(), quagga-lib\command.h */




static struct option longopts[] =
{
    { "config_file", required_argument, NULL, 'f' },
    { "help",        no_argument,       NULL, 'h' },
    { "vty_addr",    required_argument, NULL, 'A' },
    { "vty_port",    required_argument, NULL, 'P' },
    { "resume",     no_argument,        NULL, 'r' },
    { "version",     no_argument,       NULL, 'v' },
    { "daemon",      no_argument,       NULL, 'd' },
    { "mac",      required_argument,    NULL, 'm' },
    { "interface",  required_argument,  NULL, 'i' },
    { 0 }
};
static void npas_usage(char *progname, int status) {
    if (status != 0) fprintf(stderr, "Try `%s --help' for more information.\n", progname);
    else {
        printf("Usage : %s [OPTION...]\n\
    -f, --config_file  Set configuration file name\n\
    -A, --vty_addr     Set vty's bind address\n\
    -P, --vty_port     Set vty's port number\n\
    -d, --daemon       Runs in daemon mode\n\
    -m, --mac          Cp's MAC\n\
    -i, --interface    interface to communicate with CP, such as \"eth0\"\n\
    -r, --resume       Start as resume\n\
    -v, --version      Print program version\n\
    -h, --help         Display this help and exit\n\
    \n", progname);
    }
    exit(status);
}
static void npas_exception_handler(int signo, siginfo_t *siginfo, void *context)
{ }
void signal_install() {

    struct sigaction act;
    sigfillset(&act.sa_mask);

    act.sa_sigaction = npas_exception_handler;
    act.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &act, NULL) < 0) { /*段错误*/
        printf("%s %d \n\r", __FUNCTION__, __LINE__);
    }
    if (sigaction(SIGILL, &act, NULL) < 0) {  /*非法访问*/
        printf("%s %d \n\r", __FUNCTION__, __LINE__);
    }
    if (sigaction(SIGSYS, &act, NULL) < 0) {  /*非法系统调用*/
        printf("%s %d \n\r", __FUNCTION__, __LINE__);
    }
}

#define print_ffwd_version()\
{\
    npas_log_debug("version %s.%s.%s.%s, compiled by %s, %s %s \n\r", \
        FFWD_MAJOR_VERSION, FFWD_MINOR_VERSION, FFWD_BUILD_NUMBER, FFWD_SVN_REVISION, FFWD_COMPILED_BY, FFWD_DATE, FFWD_TIME);\
}
extern int npas_dbg_cmd_init();
struct thread_master * master = NULL;
int main(int argc, char **argv) {
    char *p;
    char *vty_addr = "0.0.0.0";
    int vty_port = 13333;
    char *config_file = NULL;
    char *progname = NULL;
    struct thread thread;
    int daemon_run = 0;
    char hostname[512];
    int opt;
    char log_path[32] = { 0 };



    progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

    while (1) {
        opt = getopt_long(argc, argv, "hdf:A:P:m:i:rv", longopts, 0);

        if (opt == EOF) break;

        switch (opt) {
        case 0:
            break;
        case 'f':
            config_file = optarg;
            break;
            break;
        case 'A':
            vty_addr = optarg;
            break;
        case 'm':
            break;
        case 'i':
            break;
        case 'P':
            /* Deal with atoi() returning 0 on failure */
            if (strcmp(optarg, "0") == 0) {
                vty_port = 0;
                break;
            }
            vty_port = atoi(optarg);
            vty_port = (vty_port ? vty_port : 13333);
            break;
        case 'r':
            break;
        case 'd':
            daemon_run = 1;
            break;
        case 'v':
            exit(0);
            break;
        case 'h':
            npas_usage(progname, 0);
            break;
        default:
            npas_usage(progname, 1);
            break;
        }
    }


    signal_install();
    master = thread_master_create();
    cmd_init(0);
    vty_init(master);
    npas_init(master);
    npas_dbg_cmd_init();



    sort_node();

    if (daemon_run) 
        daemon(1, 1);

    /* Create VTY socket */
    vty_serv_sock(vty_addr, vty_port, "/tmp/.npas.sock");

    /* Configuration file read*/
    if (config_file) {
        vty_read_config(config_file, NULL);
    } else {
        vty_read_str("no login", VTY_NODE);
        vty_read_str("service advanced-vty", VTY_NODE);
        //vty_read_str("no enable password", CONFIG_NODE);
        sprintf(hostname, "hostname NPAS");
        vty_read_str(hostname, CONFIG_NODE);
    }

    while (thread_fetch(master, &thread)) thread_call(&thread);

    return 0;
}



