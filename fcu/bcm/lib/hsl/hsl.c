/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_logger.h"
#include "hsl.h"



static int hsl_initialized = 0;


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
//    SYSTEM_INIT_CHECK(hsl_sock_init (), "os sock init");
    
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
    
//    SYSTEM_INIT_CHECK(hsl_os_deinit (), "os sock init");
    hsl_initialized = 0;
    
    HSL_FN_EXIT (0);
}

