/*
 * Copyright (c) 2004-2007 NetFord, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by NetFord.  The name of the Company
 * may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
modification history
--------------------
2007-02-22, jmlee  created file
*/

#include <asm/io.h>
#include <stdarg.h>
#include <linux/vmalloc.h>
#include <linux/poll.h>
//#include <linux/smp_lock.h>
#include <asm/types.h>  /* Use u64 */


#define MSE_MEM_BASE_ADDR  			0xFF000000
#define MSE_MEM_SIZE			 	0x00100000


#define MSE_VERSION_LENGTH			0x20



unsigned long mse_base_addr;

void hsl_shape_init(void)
{
    mse_base_addr = (unsigned long) ioremap (MSE_MEM_BASE_ADDR , MSE_MEM_SIZE);
	printk("hsl_shape_init %p\r\n", (void *)mse_base_addr);
}

void hsl_shape_deinit(void)
{
    iounmap ((void*)mse_base_addr);
}

unsigned long sys_get_mse_base_addr(void)
{
    return mse_base_addr;
}

int hsl_shape_mem_get(char *buffer, int offset, int length)
{
    volatile unsigned char __iomem *base_addr;
    //unsigned char  data ;
	int i;    

    base_addr = (unsigned char __iomem *)sys_get_mse_base_addr() ;
    
	for(i = 0; i < length; i++)
		buffer[i] = readb(base_addr + offset + i);

	return 0;
}

void sample_write(void)
{
    volatile unsigned char __iomem *addr;
   // unsigned char  data ;
    
    addr = (unsigned char __iomem *)sys_get_mse_base_addr() ;
    
    writeb(0x6, addr + 0x6) ;
    
}

void sample_read(int enable)
{       
    volatile unsigned char __iomem *addr;
    unsigned char  data ;
    
    addr = (unsigned char __iomem *)sys_get_mse_base_addr() ;
    
    data = readb(addr + 0x7);
        
    if(enable)
        data &= ~0x1 ;
    else    
        data  |= 0x1 ;
                            
    writeb(data, addr + 0x7) ;
}

