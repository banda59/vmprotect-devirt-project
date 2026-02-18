/*
 * Copyright (C) 2015-2025 Intel Corporation.
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
 * This header is included from Musl's string.h
 */

#ifndef _PIN_STRING_H_
#define _PIN_STRING_H_

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

//
// C11 functions
//
extern char* strnstr(const char*, const char*, size_t) __purefunc;
extern size_t strnlen_s(const char*, size_t);
extern int memcpy_s(void*, rsize_t, const void*, rsize_t);
extern int strcat_s(char*, rsize_t, const char*);
extern int strncat_s(char*, rsize_t, const char*, rsize_t);
extern int strcpy_s(char*, rsize_t, const char*);
extern int strncpy_s(char*, rsize_t, const char*, rsize_t);
extern char* strtok_s(char*, rsize_t*, const char*, char**);

__END_DECLS

#endif // #ifndef _PIN_STRING_H_
