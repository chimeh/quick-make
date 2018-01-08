#include <linux/fs.h>
#include <linux/uaccess.h>
#include "lkm_file.h"

struct lkm_file {
    struct file *fp;
};

void *lkm_calloc(size_t size)
{
    void *ptr = kmalloc(size, GFP_KERNEL);
    if (ptr)
    {
        memset(ptr, 0, sizeof(size));
    }
    return ptr;
}

void lkm_free(void *p)
{
    kfree(p);
}
lkm_file_t lkm_open(const char *pathname, int flags, mode_t mode)
{
    struct lkm_file *psf = NULL;
    mm_segment_t old_fs = get_fs();

    if (NULL == pathname) {
        return NULL;
    }
    
    set_fs(KERNEL_DS);
    
    psf = lkm_calloc(sizeof(struct lkm_file));
    if (NULL == psf) {
        printk("lkm_open file %s error: out of memory\n", pathname);
        goto err_out;
    }
  
    psf->fp = filp_open(pathname, flags, mode);
    if (IS_ERR(psf->fp)) {
        //printk("lkm_open file %s error\n", pathname);
        goto err_out;
    }
    
    set_fs(old_fs);
    return psf;

err_out:
    if (NULL != psf) {
        if (psf->fp && !IS_ERR(psf->fp)) {
            filp_close(psf->fp, NULL);
        }

        lkm_free(psf);
    }

    set_fs(old_fs);
    return NULL;
}

lkm_file_t
lkm_fopen(const char *pathname, const char *mode)
{
    return lkm_open(pathname, O_RDWR, 0);
}
int
lkm_fclose(lkm_file_t ft)
{
    mm_segment_t old_fs = get_fs();

    set_fs(KERNEL_DS);
    
    if (NULL != ft) {
        if (ft->fp && !IS_ERR(ft->fp)) {
            filp_close(ft->fp, NULL);
        }
        lkm_free(ft);
    }

    set_fs(old_fs);
    return 0;
}

ssize_t
lkm_read(lkm_file_t ft, void *buf, size_t count)
{
    mm_segment_t old_fs = get_fs();
    ssize_t nbytes = -1;

    if (NULL == ft || NULL == ft->fp) {
        return -1;
    }

    set_fs(KERNEL_DS);
    nbytes = ft->fp->f_op->read(ft->fp, buf, count, &ft->fp->f_pos);
    if (nbytes < 0) {
         printk("lkm_read error\n");
    }

    set_fs(old_fs);
    return nbytes;
}

ssize_t
lkm_write(lkm_file_t ft, void *buf, size_t count)
{
    mm_segment_t old_fs = get_fs();
    ssize_t nbytes = -1;

    if (NULL == ft || NULL == ft->fp) {
        return -1;
    }

    set_fs(KERNEL_DS);
    nbytes = ft->fp->f_op->write(ft->fp, buf, count, &ft->fp->f_pos);
    if (nbytes < 0) {
         printk("lkm_write error\n");
    }

    set_fs(old_fs);
    return nbytes;
}

char *lkm_fgets(char *buf, int size, lkm_file_t ft)
{
    mm_segment_t old_fs = get_fs();
    ssize_t nbytes = -1;
    char rbuf;
    int idx = 0;

    if (NULL == ft || NULL == ft->fp) {
        return NULL;
    }

    set_fs(KERNEL_DS);

    buf[0] = '\0';
    while (idx < (size - 1)) {
        nbytes = ft->fp->f_op->read(ft->fp, &rbuf, 1, &ft->fp->f_pos);
        if (1 != nbytes) {
            if (0 == nbytes) {
                /* EOF */
                break;    
            }

            printk("lkm_fgets error\n");
            goto err_out;
        }

        buf[idx++] = rbuf;

        if ('\n' == rbuf) {
            break;
        }
    }
    

    set_fs(old_fs);
    if (0 == idx) {
        return NULL;
    }

    buf[idx] = '\0';
    return buf;

err_out:
    set_fs(old_fs);
    return NULL;
} 

int lkm_fseek(lkm_file_t ft, long offset, int fromwhere)
{
    return 0;
}