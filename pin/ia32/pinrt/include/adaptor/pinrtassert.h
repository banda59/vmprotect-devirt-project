/*
 * Copyright (C) 2025-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinrt
// <FILE-TYPE>: implementation

#if USE_PINOS_ABORT

#if defined(assert)
#undef assert
#endif

#if defined(assert_perror)
#undef assert_perror
#endif

#if defined(NDEBUG)

#define assert(expr) ((void)0)
#define assert_perror(errnum) ((void)0)

#else
#include <pinosapi.h>
#include <string.h>

#define assert(expr) OS_ASSERT(expr)
#define assert_perror(errnum)               \
    do                                      \
    {                                       \
        if (0 != (errnum))                  \
        {                                   \
            OS_ABORT_MSG(strerror(errnum)); \
        }                                   \
    }                                       \
    while (0)

#endif // NDEBUG

#else
#include <assert.h>
#endif // USE_PINOS_ABORT