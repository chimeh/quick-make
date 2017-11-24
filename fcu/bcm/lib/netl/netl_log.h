/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _NETL_LOG_H_
#define _NETL_LOG_H_

#define netl_info(zg, ...) fprintf(stderr, __VA_ARGS__)
#define netl_warn(zg, ...) fprintf(stderr, __VA_ARGS__)
#define netl_err(zg, ...) fprintf(stderr, __VA_ARGS__)

#endif  /* _NETL_LOG_H_ */
