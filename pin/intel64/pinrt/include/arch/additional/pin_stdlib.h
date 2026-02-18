/*
 * Copyright (C) 2020-2025 Intel Corporation.
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
 * This header is included from Musl's stdlib.h
 */

#ifndef _PIN_STDLIB_H_
#define _PIN_STDLIB_H_

#include <stddef.h>
#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

errno_t rand_s(unsigned* randomValue);

static inline bool is_separator(char c_)
{
    if (c_ == '/')
    {
        return true;
    }
#if defined(TARGET_WINDOWS)
    if (c_ == '\\')
    {
        return true;
    }
#endif
    return false;
}

static inline bool is_drive_letter(char c_) { return (((c_ >= 'A') && (c_ <= 'Z')) || ((c_ >= 'a') && (c_ <= 'z'))); }

__END_DECLS

#endif // #ifndef _PIN_STDLIB_H_
