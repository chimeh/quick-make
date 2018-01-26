#ifdef SDK_IN_USERMODE
#include "xxx_shell.h"
#include "xxx_shell_server.h"
#include "xxx_cli.h"

int
xxx_vti_read_cmd(xxx_vti_t* vty, const char* szbuf, const int buf_len);
static int
xxx_vty_sendto(xxx_vti_t* vti, const char *szPtr, const int szPtr_len);
static int
xxx_vty_send_quit(xxx_vti_t* vti);

static sal_sock_t xxx_master_cli_fd = -1;

static xxx_vti_t* xxx_vty_lookup_by_pid_errno(unsigned int pid)
{
    if(g_xxx_vti->pid != pid)
    {
        g_xxx_vti->pid    = pid;
        g_xxx_vti->printf = xxx_vty_sendto;
        g_xxx_vti->quit   = xxx_vty_send_quit;
        g_xxx_vti->node   = XXX_SDK_MODE;
        xxx_vti_prompt(g_xxx_vti);
    }
    return g_xxx_vti;
}

static int xxx_vty_send_quit(xxx_vti_t* vti)
{
	xxx_sdk_packet_t	packet;
	int					ret 	= -1;

	sal_memset(&packet,0,sizeof(packet));

	if(-1 == vti->pid)
	{
		return -1;
	}

	packet.hdr.msg_len		= sizeof(struct xxx_msg_hdr);
	packet.hdr.msg_type		= XXX_SDK_CMD_QUIT;
	packet.hdr.msg_flags	= 0;
	packet.hdr.msg_turnsize	= 0;
	packet.hdr.msg_pid		= 0;

	ret = sal_send(vti->pid, &packet, 2048,0);

	sal_close(vti->pid);

	vti->pid = -1;

	return ret;
}


static int xxx_vty_sendto(xxx_vti_t* vti, const char *szPtr, const int szPtr_len)
{
	xxx_sdk_packet_t	packet;
	int					ret 	= -1;

	sal_memset(&packet,0,sizeof(packet));

	if(-1 == vti->pid)
	{
		return -1;
	}

	packet.hdr.msg_len		= sizeof(struct xxx_msg_hdr) + szPtr_len;
	packet.hdr.msg_type		= 0;
	packet.hdr.msg_flags	= 0;
	packet.hdr.msg_turnsize	= szPtr_len;
	packet.hdr.msg_pid		= 0;

	sal_memcpy(&packet.msg, szPtr,szPtr_len);
	ret = sal_send(vti->pid, &packet, 2048,0);

	return ret;
}

static void xxx_vty_recv_thread(void *arg)
{
    struct  xxx_msg_hdr *msgh 		= NULL;
	sal_sock_t			client_fd 	= (intptr)arg;
	xxx_sdk_packet_t	packet;
	int32				len;

	sal_memset(&packet,0,sizeof(packet));

	while(len = sal_recv(client_fd,&packet,sizeof(packet),0), len > 0)
	{
		msgh = &packet.hdr;
		if((msgh->msg_len >= sizeof(struct xxx_msg_hdr))
            && (len >= msgh->msg_len))
        {

            xxx_vti_read_cmd(xxx_vty_lookup_by_pid_errno(client_fd),
                                 packet.msg,
                                 msgh->msg_turnsize);
        }
		else
		{
			sal_printf("data receive from pid is:%d\n",msgh->msg_pid);
		}

		sal_memset(&packet,0,sizeof(packet));
	}

	return ;
}

int xxx_vty_socket()
{
	sal_sock_t				tmp_fd 		= -1;
	intptr				client_fd 	= -1;
	struct sal_sockaddr_in 	serv_addr;
	struct sal_sockaddr_in 	client_addr;
	sal_socklen_t			sock_len;
	int						reusraddr   = 1;
    char                    prompt[32] = "";

	tmp_fd = sal_socket(AF_INET,SOCK_STREAM,0);

	if(tmp_fd < 0)
	{
		perror("Socket create failed.");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port   = htons(XXX_SDK_TCP_PORT);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(setsockopt(tmp_fd,SOL_SOCKET,SO_REUSEADDR,(char*)&reusraddr,sizeof(reusraddr)) < 0)
	{
		perror("Setsockopt SO_REUSEADDR failed");
		sal_close(tmp_fd);
		return -1;
	}

	if(sal_bind(tmp_fd,(struct sockaddr*)&serv_addr,sizeof(serv_addr)) < 0)
	{
	    snprintf(prompt,sizeof(prompt),"TCP port(%d) bind failed",XXX_SDK_TCP_PORT);
		perror(prompt);
		sal_close(tmp_fd);
		return -1;
	}

	listen(tmp_fd, 1);

	xxx_master_cli_fd = tmp_fd;

    sal_printf("Server is up and running ...\n");

	sock_len = sizeof(client_addr);
	while(client_fd = sal_accept(xxx_master_cli_fd,(struct sockaddr*)&client_addr,&sock_len), client_fd >= 0)
	{
		sal_task_t* xxx_sdk_client_fd = NULL;

		if (0 != sal_task_create(&xxx_sdk_client_fd,
								 "xxx_sdk_server",
								 SAL_DEF_TASK_STACK_SIZE, 0, xxx_vty_recv_thread, (void*)client_fd))
		{
			sal_close(tmp_fd);
			sal_task_destroy(xxx_sdk_client_fd);
			return -1;
		}

        sal_task_destroy(xxx_sdk_client_fd);
	}

	return 0;
}

void xxx_vty_close()
{
	sal_close(xxx_master_cli_fd);
	xxx_master_cli_fd = -1;
}
#endif
