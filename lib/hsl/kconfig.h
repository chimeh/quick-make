#ifndef __KCONFIG_H__
#define __KCONFIG_H__

extern char *kconfig_get(const char *name);
extern int kconfig_get_next(char **name, char **value);
extern int kconfig_set(char *name, char *value);

#endif

