/*
 * Copyright (C) 2015-2023 Intel Corporation.
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
 * This header is included from Musl's wchar.h
 */

#ifndef _PIN_WCHAR_H_
#define _PIN_WCHAR_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

//
// C11 functions
//
extern size_t wcsnlen_s(const wchar_t*, size_t);

__END_DECLS

#endif // #ifndef _PIN_WCHAR_H_
