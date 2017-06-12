/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_EXAMPLE_H_
#define _HAL_EXAMPLE_H_


int hal_example_add (unsigned int a, int b);

int hal_example_del(unsigned int arg1, int arg2);



struct hal_example_ops
{
  int (*example_add)(unsigned int a, int b);
  int (*example_del)(unsigned int arg1, int arg2);
};
#endif /* _HAL_EXAMPLE_H_ */
