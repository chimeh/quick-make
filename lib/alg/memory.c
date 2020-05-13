#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <linux/sched.h>

void *xrealloc(void *ptr, size_t size)
{
    void *new_ptr = NULL;
    if (ptr) 
    {
        if (size != 0) 
        {
            if (!(new_ptr = kmalloc(size, GFP_KERNEL)))
            {
                return NULL;
            }
            memmove(new_ptr, ptr, size);
        }

        kfree(ptr);
    }
    else 
    {
        if (size != 0)
        {
            if (!(new_ptr = kmalloc(size, GFP_KERNEL)))
            {
                return NULL;
            }
        }
    }

    return new_ptr;
}

void *xmalloc(size_t size)
{
    return kmalloc(size, GFP_KERNEL);
}

void *xcalloc(size_t size)
{
    void *ptr = kmalloc(size, GFP_KERNEL);
    if (ptr)
    {
        memset(ptr, 0, sizeof(size));
    }
    return ptr;
}

void xfree(void *p)
{
    kfree(p);
}

char*
xstrdup(char* str)
{
    char* new_str = xmalloc(strlen(str) + 1);

    if (new_str)
    {
        memcpy(new_str, str, strlen(str) + 1);
    }

    return new_str;
}
