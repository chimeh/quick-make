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















/* file operations that we can do */

/* Mentioning major and minor here */
static int start = 1;

module_param(start, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(start, " start xxx core");

extern int xxx_init (void);
extern int xxx_deinit (void);

static int __init xxx_core_init() {
    int ret = -1;
    printk(KERN_INFO "xxx core: loaded.\n");
    if (start > 0) {
        xxx_init();
        return 0;
    }

    return 0;
}

static void __exit xxx_core_exit() {
    xxx_deinit();
    printk(KERN_INFO "xxx core: unloaded.\n");
}



MODULE_VERSION("V1.0");
MODULE_AUTHOR("Jimmy");
MODULE_DESCRIPTION("HW Service Layer");
MODULE_LICENSE("GPL");

module_init(xxx_core_init);
module_exit(xxx_core_exit);
