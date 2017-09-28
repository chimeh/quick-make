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



MODULE_LICENSE ("GPL");
MODULE_AUTHOR("Jimmy");
MODULE_DESCRIPTION("HSL ");



int hsl_core_init(void);
void hsl_core_exit(void);


module_init(hsl_core_init);
module_exit(hsl_core_exit);


/* file operations that we can do */

/* Mentioning major and minor here */
static int start = 1;


module_param(start, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(start, DEVICE_NAME " start hsl core");

extern int hsl_init (void);
extern int hsl_deinit (void);

int hsl_core_init() {
    int ret = -1;
    printk(KERN_INFO "hsl core: loaded.\n");
    if (start > 0) {
        hsl_init();
        return ret;
    }

    return 0;
}

void hsl_core_exit() {
    printk(KERN_INFO "hsl core: unloaded.\n");
}







