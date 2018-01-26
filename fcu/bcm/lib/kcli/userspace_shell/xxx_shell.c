/**
 @file xxx_master_cli.h

 @date 2014-12-22

 @version v2.0

 This file define the types used in APIs

*/

/****************************************************************
 *
 * Header Files
 *
 ***************************************************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include "xxx_shell.h"

/****************************************************************
*
* Defines and Macros
*
****************************************************************/
typedef struct xxx_sdk_vty_base_s xxx_sdk_vty_base_t;

typedef int (*xxx_socket)(xxx_sdk_vty_base_t *);
typedef int (*xxx_recvfrom)(xxx_sdk_vty_base_t *);
typedef int (*xxx_sendto)(xxx_sdk_vty_base_t *, char *, const int);
typedef int (*xxx_close)(xxx_sdk_vty_base_t *);
typedef int (*xxx_start_thread)(xxx_sdk_vty_base_t *);

struct xxx_sdk_vty_base_s
{
    pthread_t             task_id;
    int                 socket_fd;
    xxx_sdk_packet_t    socket_recv_buf;
    xxx_sdk_packet_t    socket_send_buf;
    xxx_socket            socket;
    xxx_sendto            sendto;
    xxx_recvfrom        recvfrom;
    xxx_close            close;
    xxx_start_thread    start_thread;
};

xxx_sdk_vty_base_t    *p_gxxx_sdk_vty = NULL;


static int xxx_sdk_start_thread(xxx_sdk_vty_base_t *pxxx_sdk_vty);


struct termios termios_old;
void
set_terminal_raw_mode(void)
{
    /*system("stty raw -echo");*/
    struct termios terminal_new;
    tcgetattr(0, &terminal_new);
    memcpy(&termios_old, &terminal_new, sizeof(struct termios));
    terminal_new.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                              | INLCR | IGNCR | ICRNL | IXON);
    /*
      OPOST (output post-processing) & ISIG (Input character signal generating enabled) need to be set
      terminal_new.c_oflag &= ~OPOST;
      terminal_new.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
      */
    terminal_new.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
    terminal_new.c_cflag &= ~(CSIZE | PARENB);
    terminal_new.c_cflag |= CS8;

    tcsetattr(0, TCSANOW, &terminal_new);
}

void
restore_terminal_mode(void)
{
    /*system("stty cooked echo");*/
    tcsetattr(0, TCSANOW, &termios_old);
    printf("\n");
}


static int xxx_socket_close(xxx_sdk_vty_base_t *pxxx_sdk_vty)
{
    if (pxxx_sdk_vty->task_id)
    {
        //pthread_cancel(pxxx_sdk_vty->task_id);
        pxxx_sdk_vty->task_id = - 1;
    }

    if ( - 1 != pxxx_sdk_vty->socket_fd)
    {
        close(pxxx_sdk_vty->socket_fd);
        pxxx_sdk_vty->socket_fd = - 1;
    }
    return 0;
}

#define ________NETLINK________
typedef struct xxx_sdk_vty_netlink_s
{
    xxx_sdk_vty_base_t            base;
    struct     sockaddr_nl         kpeer;
    int                             kpeer_len;
}xxx_sdk_vty_netlink_t;

static int xxx_netlink_create_socket(xxx_sdk_vty_base_t *pxxx_sdk_vty)
{
    int                        skfd = - 1;
    struct sockaddr_nl         local;
    xxx_sdk_vty_netlink_t    *pvty_netlink = (xxx_sdk_vty_netlink_t*)pxxx_sdk_vty;
    skfd = socket(PF_NETLINK, SOCK_RAW, XXX_SDK_NETLINK);
    if (skfd < 0)
    {
        perror("can't create socket:");
        return - 1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid      = getpid();
    local.nl_groups = 0;

    if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0)
    {
        perror("bind() error:");
        return - 1;
    }

    memset(&pxxx_sdk_vty->socket_send_buf, 0, sizeof(xxx_sdk_packet_t));
    pxxx_sdk_vty->socket_send_buf.hdr.msg_len          = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_flags      = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_type          = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_turnsize     = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_pid          = local.nl_pid;

    pxxx_sdk_vty->socket_fd = skfd;

    pvty_netlink->kpeer.nl_family      = AF_NETLINK;
    pvty_netlink->kpeer.nl_pid          = 0;
    pvty_netlink->kpeer.nl_groups      = 0;

    pvty_netlink->kpeer_len = sizeof(struct sockaddr_nl);

    return 0;
}

static int xxx_netlink_sendto(xxx_sdk_vty_base_t *pxxx_sdk_vty, char *send_buf, const int send_buf_count)
{
    int ret = - 1;
    xxx_sdk_vty_netlink_t    *pvty_netlink = (xxx_sdk_vty_netlink_t*)pxxx_sdk_vty;

    memcpy(NLMSG_DATA(&pxxx_sdk_vty->socket_send_buf), send_buf, send_buf_count);
    pxxx_sdk_vty->socket_send_buf.hdr.msg_len           = NLMSG_SPACE(send_buf_count);
    pxxx_sdk_vty->socket_send_buf.hdr.msg_turnsize      = send_buf_count;

    ret = sendto(pxxx_sdk_vty->socket_fd,
                 &pxxx_sdk_vty->socket_send_buf,
                 pxxx_sdk_vty->socket_send_buf.hdr.msg_len,
                 0, (struct sockaddr *)&pvty_netlink->kpeer,
                 pvty_netlink->kpeer_len);
    if (ret < 0)
    {
        perror("sendto kernel:");
    }

    return ret;
}

static int xxx_netlink_recvfrom(xxx_sdk_vty_base_t *pxxx_sdk_vty)
{
    int     read_size = - 1;
    //    xxx_sdk_vty_netlink_t        *pvty_netlink = (xxx_sdk_vty_netlink_t*)pxxx_sdk_vty;
    struct     sockaddr_nl         kpeer;
    socklen_t     kpeerlen = sizeof(struct sockaddr_nl);

    read_size = recvfrom(pxxx_sdk_vty->socket_fd, &pxxx_sdk_vty->socket_recv_buf,
                         sizeof(pxxx_sdk_vty->socket_recv_buf), 0,
                         (struct sockaddr*)&kpeer, &kpeerlen);

    if (read_size < 0)
    {
        perror("xxx_netlink_recvfrom error:");
    }

    return read_size;
}

static xxx_sdk_vty_base_t* xxx_sdk_alloc_netlink()
{
    xxx_sdk_vty_base_t *tmp_xxx_sdk_netlink = NULL;
    tmp_xxx_sdk_netlink = (xxx_sdk_vty_base_t *)malloc(sizeof(xxx_sdk_vty_netlink_t));
    if (!tmp_xxx_sdk_netlink)
    {
        return NULL;
    }

    memset(tmp_xxx_sdk_netlink, 0, sizeof(xxx_sdk_vty_netlink_t));

    tmp_xxx_sdk_netlink->socket = xxx_netlink_create_socket;
    tmp_xxx_sdk_netlink->sendto = xxx_netlink_sendto;
    tmp_xxx_sdk_netlink->recvfrom = xxx_netlink_recvfrom;
    tmp_xxx_sdk_netlink->close    = xxx_socket_close;
    tmp_xxx_sdk_netlink->start_thread = xxx_sdk_start_thread;

    return tmp_xxx_sdk_netlink;
}

#define ________TCP_IP________
typedef struct xxx_sdk_vty_tcp_s
{
    xxx_sdk_vty_base_t base;
}
xxx_sdk_vty_tcp_t;

static int xxx_tcp_create_socket(xxx_sdk_vty_base_t *pxxx_sdk_vty)
{
    int skfd = - 1;
    struct sockaddr_in serv_addr;
    //xxx_sdk_vty_tcp_t *pvty_tcp = (xxx_sdk_vty_tcp_t*)pxxx_sdk_vty;
    skfd = socket(AF_INET, SOCK_STREAM, 0);
    if (skfd < 0)
    {
        perror("can't create socket:");
        return - 1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port      = htons(XXX_SDK_TCP_PORT);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(skfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect error:");
        return - 1;
    }

    memset(&pxxx_sdk_vty->socket_send_buf, 0, sizeof(xxx_sdk_packet_t));
    pxxx_sdk_vty->socket_send_buf.hdr.msg_len          = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_flags      = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_type          = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_turnsize     = 0;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_pid          = getpid();

    pxxx_sdk_vty->socket_fd = skfd;

    return 0;
}

static int xxx_tcp_sendto(xxx_sdk_vty_base_t *pxxx_sdk_vty, char *send_buf, const int send_buf_count)
{
    int ret = - 1;

    memcpy(&pxxx_sdk_vty->socket_send_buf.msg, send_buf, send_buf_count);
    pxxx_sdk_vty->socket_send_buf.hdr.msg_len           = sizeof(struct xxx_msg_hdr ) + send_buf_count;
    pxxx_sdk_vty->socket_send_buf.hdr.msg_turnsize      = send_buf_count;

    ret = send(pxxx_sdk_vty->socket_fd,
               &pxxx_sdk_vty->socket_send_buf,
               pxxx_sdk_vty->socket_send_buf.hdr.msg_len, 0);
    if (!ret < 0)
    {
        perror("send pid:");
    }

    return ret;
}

static int xxx_tcp_recvfrom(xxx_sdk_vty_base_t *pxxx_sdk_vty)
{
    int     read_size = - 1;

    read_size = recv(pxxx_sdk_vty->socket_fd, &pxxx_sdk_vty->socket_recv_buf,
                     2048, 0);

    if (read_size <= 0)
    {
        perror("xxx_tcp_recvfrom error:");
    }

    return read_size;
}

static xxx_sdk_vty_base_t* xxx_sdk_alloc_tcp()
{
    xxx_sdk_vty_base_t    *tmp_xxx_sdk_tcp = NULL;
    tmp_xxx_sdk_tcp = (xxx_sdk_vty_base_t *)malloc(sizeof(xxx_sdk_vty_tcp_t));
    if (!tmp_xxx_sdk_tcp)
    {
        return NULL;
    }

    memset(tmp_xxx_sdk_tcp, 0, sizeof(xxx_sdk_vty_tcp_t));

    tmp_xxx_sdk_tcp->socket = xxx_tcp_create_socket;
    tmp_xxx_sdk_tcp->sendto = xxx_tcp_sendto;
    tmp_xxx_sdk_tcp->recvfrom = xxx_tcp_recvfrom;
    tmp_xxx_sdk_tcp->close    = xxx_socket_close;
    tmp_xxx_sdk_tcp->start_thread = xxx_sdk_start_thread;

    return tmp_xxx_sdk_tcp;
}


static void sig_handle (int signo)
{
  restore_terminal_mode();
  exit(0);
}

void set_signal()
{
    signal(SIGHUP, sig_handle);
    signal(SIGUSR1, sig_handle);
    signal(SIGINT, sig_handle);
    signal(SIGTERM, sig_handle);
}

static void* xxx_socket_recv_print_thread(void* arg)
{
    xxx_sdk_vty_base_t     *pxxx_sdk_vty = NULL;
    int  recv_size      = 0;

    pxxx_sdk_vty = (xxx_sdk_vty_base_t*)arg;
    while (1)
    {
        recv_size = pxxx_sdk_vty->recvfrom(pxxx_sdk_vty);

        if (recv_size <= 0)
        {
            restore_terminal_mode();
            pxxx_sdk_vty->close(pxxx_sdk_vty);
            exit(0);
        }

        if (XXX_SDK_CMD_QUIT == pxxx_sdk_vty->socket_recv_buf.hdr.msg_type)
        {
            restore_terminal_mode();
            pxxx_sdk_vty->close(pxxx_sdk_vty);
            exit(0);
        }
        write(STDOUT_FILENO, pxxx_sdk_vty->socket_recv_buf.msg,
              pxxx_sdk_vty->socket_recv_buf.hdr.msg_turnsize);
        fflush(stdout);

        memset(&pxxx_sdk_vty->socket_recv_buf,
               0,
               sizeof(pxxx_sdk_vty->socket_recv_buf));
    }

    return ;
}

static int xxx_sdk_start_thread(xxx_sdk_vty_base_t *pxxx_sdk_vty)
{
    return pthread_create(&pxxx_sdk_vty->task_id, NULL, xxx_socket_recv_print_thread, (void*)pxxx_sdk_vty);
}

int main(int argc, char* argv[])
{
    int nbytes  = 1;
    unsigned char     buf[1536] =  {' '};

        if (1 != argc)
        {
            p_gxxx_sdk_vty = xxx_sdk_alloc_netlink();
        }
        else
        {
            p_gxxx_sdk_vty = xxx_sdk_alloc_tcp();
        }

        if (!p_gxxx_sdk_vty)
        {
            printf("Not Support\n");
            return 0;
        }

        if (p_gxxx_sdk_vty->socket(p_gxxx_sdk_vty))
        {
            return 0;
        }

        if (p_gxxx_sdk_vty->start_thread(p_gxxx_sdk_vty))
        {
            p_gxxx_sdk_vty->close(p_gxxx_sdk_vty);
            return 0;
        }

        if (p_gxxx_sdk_vty->sendto(p_gxxx_sdk_vty, (char*)buf, nbytes) <= 0)
        {
            p_gxxx_sdk_vty->close(p_gxxx_sdk_vty);
            return 0;
        }

        set_signal();

        set_terminal_raw_mode();

        while (1)
        {
            nbytes = read(STDIN_FILENO, buf, sizeof(buf));

            if (p_gxxx_sdk_vty->sendto(p_gxxx_sdk_vty, (char*)buf, nbytes) <= 0)
            {
                break;
            }
        }

        restore_terminal_mode();

        p_gxxx_sdk_vty->close(p_gxxx_sdk_vty);
        free(p_gxxx_sdk_vty);

        return 0;
    }
