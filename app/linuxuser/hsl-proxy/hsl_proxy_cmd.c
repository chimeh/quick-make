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
#include <sys/time.h>
#include "log.h"
#include "vty.h"
#include "command.h"


/* show portmap */
DEFUN(show_portmap_hnd,
      show_portmap_cmd,
      "show portmap",
      SHOW_STR
      "show port to ifindex map\n"
      "port to ifindex\n") {

    vty_out(vty, "  xlr_drv address");
    vty_out(vty, "  help help", VTY_NEWLINE);

}
int proxy_cmd_init() {
    install_element(ENABLE_NODE, &show_portmap_cmd);
    return 0;
}


