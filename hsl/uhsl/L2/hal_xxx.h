/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_XXX_H_
#define _HAL_XXX_H_


int hal_xxx_add (unsigned int a, unsigned int b);

int hal_xxx_del(unsigned int arg1, int arg2);



struct hal_xxx_ops
{
  int (*xxx_add)(unsigned int a, unsigned int b);
  int (*xxx_del)(unsigned int arg1, int arg2);
};
#endif /* _HAL_XXX_H_ */
