#include "hsl_os.h"
#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_logger.h"
#include "hsl.h"



extern int netlk_sock_init (void *);
extern int netlk_sock_deinit (void);

extern int get_chip_profile(char* fname, void * p_init_config);

static int hsl_initialized = 0;

extern int hsl_msg_process (struct socket *sock, char *buf, int buflen);
extern int hsl_op_init(void);
/*
  Initialize HSL.
*/
int
hsl_init (void) {
    int rv;
    char *msg = NULL;
    
    printk (KERN_CRIT "HSL module\n");
    if (hsl_initialized)
        return 0;
    SYSTEM_INIT_CHECK(get_chip_profile("/tmp/chip_profile.cfg", NULL), "chip_profile_parser");
    SYSTEM_INIT_CHECK(netlk_sock_init (hsl_msg_process), "netlk_sock_init");
    SYSTEM_INIT_CHECK(netlk_sock_init (hsl_op_init), "hsl_op_init");
    hsl_initialized = 1;
    HSL_FN_EXIT (0);
}


/*
   Deinitialize HSL.
*/
int
hsl_deinit (void) {
    int rv;
    char *msg = NULL;
    
    if (! hsl_initialized)
        HSL_FN_EXIT (-1);
    
    SYSTEM_INIT_CHECK(netlk_sock_deinit (), "netlk_sock_deinit");
    hsl_initialized = 0;
    
    HSL_FN_EXIT (0);
}

