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
#include <sys/signal.h> // for signal
#include <semaphore.h>

#include "zebra.h"
#include "thread.h"

#include "getopt.h"
#include "command.h"    /* for print_version(), vty_init(), quagga-lib\command.h */
#include "smi_server.h"
#include "smi_client.h"




struct smi_server * smi_server_init (struct thread_master *zg);

static struct option longopts[] =
{
    { "config_file", required_argument, NULL, 'f' },
    { "help",        no_argument,       NULL, 'h' },
    { "vty_addr",    required_argument, NULL, 'A' },
    { "vty_port",    required_argument, NULL, 'P' },
    { "role",        required_argument, NULL, 'r' },
    { "version",     no_argument,       NULL, 'v' },
    { "daemon",      no_argument,       NULL, 'd' },
    { "mac",      required_argument,    NULL, 'm' },
    { "interface",  required_argument,  NULL, 'i' },
    { 0 }
};
static void smi_server_usage(char *progname, int status) {
    if (status != 0) fprintf(stderr, "Try `%s --help' for more information.\n", progname);
    else {
        printf("Usage : %s [OPTION...]\n\
    -f, --config_file  Set configuration file name\n\
    -A, --vty_addr     Set vty's bind address\n\
    -P, --vty_port     Set vty's port number\n\
    -d, --daemon       Runs in daemon mode\n\
    -m, --mac          Cp's MAC\n\
    -i, --interface    interface to communicate with CP, such as \"eth0\"\n\
    -r, --role         server|client\n\
    -v, --version      Print program version\n\
    -h, --help         Display this help and exit\n\
    \n", progname);
    }
    exit(status);
}
static void smi_server_exception_handler(int signo, siginfo_t *siginfo, void *context)
{ }
void signal_install() {

    struct sigaction act;
    sigfillset(&act.sa_mask);

    act.sa_sigaction = smi_server_exception_handler;
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



struct thread_master * master = NULL;
struct smi_server *g_smis = NULL;
static struct smiclient_globals g_smic;
struct smiclient_globals *azg = &g_smic;
int smi_client_init(struct smiclient_globals *azg);

extern int proxy_cmd_init();
int main(int argc, char **argv) {
    char *p;
    char *vty_addr = "0.0.0.0";
    int vty_port = 13000;
    char *config_file = NULL;
    char *progname = NULL;
    struct thread thread;
    int daemon_run = 0;
    char hostname[512];
    int opt;
    char log_path[32] = { 0 };
    char *role = "client";
    char *vty_path = "client";



    progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);
    
    zlog_default = openzlog (progname, ZLOG_ZEBRA,
                                LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

    while (1) {
        opt = getopt_long(argc, argv, "hdf:A:P:m:i:r:v", longopts, 0);

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
            //vty_port = (vty_port ? vty_port : 13000);
            break;
        case 'r':
            role = optarg;
            break;
        case 'd':
            daemon_run = 1;
            break;
        case 'v':
            exit(0);
            break;
        case 'h':
            smi_server_usage(progname, 0);
            break;
        default:
            smi_server_usage(progname, 1);
            break;
        }
    }


    signal_install();
    master = thread_master_create();
    cmd_init(1);
    vty_init(master);
    
    if(0 == strncmp(role, "server", 2)) {
        g_smis = smi_server_init(master);
        vty_port += 1;
        vty_path = "/tmp/.smi_server_vty.sock";
    } else {
        vty_path = "/tmp/.smi_client_vty.sock";
        memset(&g_smic, 0, sizeof(g_smic));
        azg = &g_smic;
        azg->debug = 1;
        azg->smi_zg = master;
        smi_client_init(azg);
    }


    sort_node();

    if (daemon_run) 
        daemon(1, 1);

    /* Create VTY socket */
    vty_serv_sock(vty_addr, vty_port, vty_path);

    /* Configuration file read*/
    if (config_file) {
        vty_read_config(config_file, NULL);
    } else {
        vty_read_str("no login", VTY_NODE);
//      vty_read_str("no enable password", CONFIG_NODE);
        sprintf(hostname, "hostname SMI");
        vty_read_str(hostname, CONFIG_NODE);
    }

    while (thread_fetch(master, &thread)) thread_call(&thread);

    return 0;
}



