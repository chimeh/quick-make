/* Copyright (C) 2002-2011 IP Infusion, Inc.  All Rights Reserved.  */
#include "config.h"
#include "zebra.h"

void ntohf(float* val)
{
  union {
    u_int32_t val_32;
    float     val_f;
  } conv;

  conv.val_f = *val;
  conv.val_32 = htonl (conv.val_32);
  memcpy(val, &conv.val_32, 4);
}

void htonf(float* val)
{
  union {
    u_int32_t val_32;
    float     val_f;
  } conv;

  conv.val_f = *val;
  conv.val_32 = htonl (conv.val_32);
  memcpy(val, &conv.val_32, 4);
}

