#ifndef _BCM_L4_DEBUG_H
#define _BCM_L4_DEBUG_H

extern int hsl_debug_ipcls;
#ifndef BIT
#define BIT(n)              (1u << (n))
#endif

#define DEBUG_ERROR_IPCLS   BIT(1)
#define DEBUG_ERROR_QOS     BIT(2)
#define DEBUG_LEVEL_IPCLS   BIT(3) 
#define DEBUG_LEVEL_QOS	    BIT(4) 
#define DEBUG_ERROR_ACL	   	BIT(5)
#define DEBUG_LEVEL_ACL		BIT(6)
#define DEBUG_IPCLS_ALL    (DEBUG_ERROR_IPCLS|DEBUG_ERROR_QOS|DEBUG_LEVEL_IPCLS|DEBUG_LEVEL_QOS|DEBUG_ERROR_ACL|DEBUG_LEVEL_ACL)


#define IPCLS_IS_DEBUG_ON(flag) (hsl_debug_ipcls & (flag))

#define HSL_DEBUG_IPCLS(level, msg...) \
if(IPCLS_IS_DEBUG_ON(level)) \
{\
	printk(msg); \
}

#endif
