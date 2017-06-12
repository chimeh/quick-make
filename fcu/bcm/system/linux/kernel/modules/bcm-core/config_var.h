#ifndef __CONFIG__H__
#define __CONFIG__H__
extern long portmode;
char *custom_config_var_get(soc_cm_dev_t *dev, const char *property);
#endif