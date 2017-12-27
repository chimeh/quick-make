/* Copyright (C) 2001-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _ZEBOS_SMI_MACROS_H
#define _ZEBOS_SMI_MACROS_H

#define SMI_DBG_FN_DESC_MAX                    (32)
#define HAVE_SMI_DEBUG
/* #undef HAVE_SMI_DEBUG */
#undef HAVE_SMI_DEV_DEBUG


/*
 * SMI Debug Function Macros
 */
#define SMI_FN_DESC(FN_DESC)                                        \
    (# FN_DESC == "" ? __FUNCTION__ : # FN_DESC)
#ifdef HAVE_SMI_DEBUG
#define SMI_DBG_FN_DESC                dbg_fn_desc
#ifdef HAVE_ISO_MACRO_VARARGS
#define SMI_FN_ENTER(...)                                           \
    u_int8_t SMI_DBG_FN_DESC [SMI_DBG_FN_DESC_MAX];                 \
    struct timeval curr_time;                                       \
    gettimeofday(&curr_time, NULL);                                 \
    pal_strncpy (SMI_DBG_FN_DESC, SMI_FN_DESC (__VA_ARGS__),        \
                 SMI_DBG_FN_DESC_MAX - 1);                          \
    SMI_DBG_FN_DESC [SMI_DBG_FN_DESC_MAX - 1] = '\0';               \
    syslog(LOG_INFO, "[%ld us] Entering function: %s",              \
            curr_time.tv_usec, SMI_DBG_FN_DESC);                                    

#define SMI_FN_EXIT(...)                                            \
  {                                                                 \
    struct timeval curr_time;                                       \
    gettimeofday(&curr_time, NULL);                                 \
    syslog(LOG_INFO, "[%ld us] Leaving function: %s",               \
           curr_time.tv_usec, SMI_DBG_FN_DESC);                     \
    SMI_DBG_FN_DESC [0] = '\0';                                     \
    return __VA_ARGS__;                                             \
  }
#else
#define SMI_FN_ENTER(ARGS...)                                       \
    u_int8_t SMI_DBG_FN_DESC [SMI_DBG_FN_DESC_MAX];                 \
    struct timeval curr_time;                                       \
    gettimeofday(&curr_time, NULL);                                 \
    pal_strncpy (SMI_DBG_FN_DESC, SMI_FN_DESC (ARGS),               \
                 SMI_DBG_FN_DESC_MAX - 1);                          \
    SMI_DBG_FN_DESC [SMI_DBG_FN_DESC_MAX - 1] = '\0';               \
    syslog(LOG_INFO, "[%ld us] Entering function: %s",              \
            curr_time.tv_usec, SMI_DBG_FN_DESC);
#define SMI_FN_EXIT(ARGS...)                                        \
  {                                                                 \
    u_int8_t SMI_DBG_FN_DESC [SMI_DBG_FN_DESC_MAX];                 \
    struct timeval curr_time;                                       \
    gettimeofday(&curr_time, NULL);                                 \
    syslog(LOG_INFO, "[%ld us] Leaving function: %s",               \
            curr_time.tv_usec, SMI_DBG_FN_DESC);                    \
    SMI_DBG_FN_DESC [0] = '\0';                                     \
    return ARGS;                                                    \
  }
#endif /* HAVE_ISO_MACRO_VARARGS */
#else
#define SMI_DBG_FN_DESC                ""
#define SMI_FN_ENTER(FN_DESC)
#ifdef HAVE_ISO_MACRO_VARARGS
#define SMI_FN_EXIT(...)                                             \
    return __VA_ARGS__;
#else
#define SMI_FN_EXIT(ARGS...)                                         \
    return ARGS;
#endif /* HAVE_SMI_DEBUG */
#endif /* HAVE_ISO_MACRO_VARARGS */

/* SMI Validation macros */
#define SMI_VALIDATE_RANGE(min, max, val)                               \
  if(val < min || val > max)                                            \
  {                                                                     \
    printf("\n\tError: Value [%d] is out of range: <%d - %d>\n",        \
            val, min, max);                                             \
    SMI_FN_EXIT(SMI_INVALID_VAL);                                       \
  }                                                                     

#define SMI_VALIDATE_STRLEN(str, len)                                   \
  if ( !str)                                                            \
    SMI_FN_EXIT(SMI_ERROR_NULL_STRING);                                 \
  if(strlen(str) > len)                                                 \
  {                                                                     \
    printf("\n\tError: Length of the string exceeds the limit\n");      \
    SMI_FN_EXIT(SMI_INVALID_STRLEN);                                    \
  }                                                                     

#define SMI_VALIDATE_VAL(max, val)                                      \
  if(val > max)                                                         \
  {                                                                     \
    printf("\n\tError: Value [%d] is out of range: 0 - %d>\n",          \
            val, max);                                                  \
    SMI_FN_EXIT(SMI_INVALID_VAL);                                       \
  }


#endif /* _ZEBOS_SMI_MACROS_H */
