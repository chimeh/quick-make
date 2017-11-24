/*
* Copyright (C), 2001-2010, Galaxywind Co., Ltd. 
* Description: NPASÖ÷º¯Êý
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
#include <sys/signal.h> 
#include <semaphore.h>

#include "npas_tbl_link.h"

/* 
   Command channel. 
*/
struct netlsock npas_tbl_link = { -1, 0, {0}, "npas_tbl_link", (void *)0, 0, NULL, NULL};

int npas_init(void *zg) {
    npas_tbl_link.arg_zg = zg;
    npas_tbl_link_init(&npas_tbl_link);
    
    return 0;
}



