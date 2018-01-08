#ifndef __lkm_FILE_H___
#define __lkm_FILE_H___

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>


struct lkm_file;
typedef struct lkm_file* lkm_file_t;



lkm_file_t lkm_fopen(const char *file, const char *mode);

int lkm_fclose(lkm_file_t ft);

ssize_t lkm_read(lkm_file_t ft, void *buf, size_t count);

ssize_t lkm_eof(lkm_file_t ft);
ssize_t lkm_write(lkm_file_t ft, void *buf, size_t count);
char *lkm_fgets(char *buf, int size, lkm_file_t ft);
int lkm_fseek(lkm_file_t ft, long offset, int fromwhere);
long lkm_ftell(lkm_file_t ft);






#endif
