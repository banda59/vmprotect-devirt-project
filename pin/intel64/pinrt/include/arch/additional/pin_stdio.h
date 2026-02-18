/*
 * Copyright (C) 2010-2025 Intel Corporation.
 * 
 * This software and the related documents are Intel copyrighted materials, and your
 * use of them is governed by the express license under which they were provided to
 * you ("License"). Unless the License provides otherwise, you may not use, modify,
 * copy, publish, distribute, disclose or transmit this software or the related
 * documents without Intel's prior written permission.
 * 
 * This software and the related documents are provided as is, with no express or
 * implied warranties, other than those that are expressly stated in the License.
 */

/**
 * This header is included from Musl's stdio.h
 */

#ifndef _PIN_STDIO_H_
#define _PIN_STDIO_H_

#include <stdarg.h>
#include <stddef.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

//
// C11 functions
//
int snprintf_s(char* __restrict, rsize_t, const char* __restrict, ...);
int vsprintf_s(char* __restrict, rsize_t, const char* __restrict, va_list);
int vsnprintf_s(char* __restrict, rsize_t, const char* __restrict, va_list);
int sprintf_s(char* __restrict, rsize_t, const char* __restrict, ...);
int sscanf_s(const char* __restrict, const char* __restrict, ...);

__END_DECLS

#endif // #ifndef _PIN_STDIO_H_
