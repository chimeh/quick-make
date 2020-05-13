#ifndef _HSL_H_
#define _HSL_H_

#define SYSTEM_INIT_CHECK(action, description) \
    if ((rv = (action)) < 0) { \
        msg = ("HSL "description".....FAILED"); \
    }else { \
        msg = ("HSL "description".....OK"); \
    } \
    printk("%s\n", msg)
    

/*
  Function prototypes for OS, TCP/IP stack and Hardware. 
*/

int hsl_init (void);
int hsl_deinit (void);
int hsl_os_init (void);
int hsl_os_deinit (void);
int hsl_hw_init (void);
int hsl_hw_deinit (void);


#endif /* _HSL_H_ */
