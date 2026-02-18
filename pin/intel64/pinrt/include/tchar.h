/*
 * Copyright (C) 2025-2025 Intel Corporation.
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
 * @file This header provides a minimal subset of the Microsoft <tchar.h> header.
 *       It only provides type definitions and macros for TCHAR, PTCHAR, etc. 
 *       It does not provide any of the string manipulation functions or macros. 
 *
 *       This header is provided only so that the default system <tchar.h> header
 *       is not used by mistake. It is not intended to be a complete replacement for the
 *       Microsoft header. The Microsoft header is not portable and should not be used.
 *       This header is only intended to be used in the context of the Pin runtime.
 */

#ifndef _INC_TCHAR // Use the same macro defined by Microsoft
#define _INC_TCHAR

#if !defined(TARGET_WINDOWS)
#error "This header should only be included under Windows"
#endif

#include <sys/cdefs.h>

__BEGIN_DECLS

#ifdef _UNICODE

#include <wchar.h>
#include <wctype.h>

#ifndef __TCHAR_DEFINED
typedef wchar_t _TCHAR;
typedef wchar_t _TSCHAR;
typedef wchar_t _TUCHAR;
typedef wchar_t _TXCHAR;
typedef wint_t _TINT;
#define __TCHAR_DEFINED
#endif /* __TCHAR_DEFINED */

#ifndef _TCHAR_DEFINED
typedef wchar_t TCHAR;
typedef wchar_t* PTCHAR;
typedef wchar_t TBYTE;
typedef wchar_t* PTBYTE;
#define _TCHAR_DEFINED
#endif /* _TCHAR_DEFINED */

#define _TEOF WEOF

#define __T(x) L##x

#else // MBCS

#include <string.h>
#include <ctype.h>
#include <stdio.h>

#ifndef __TCHAR_DEFINED
typedef char _TCHAR;
typedef signed char _TSCHAR;
typedef unsigned char _TUCHAR;
typedef char _TXCHAR;
typedef int _TINT;
#define __TCHAR_DEFINED
#endif /* __TCHAR_DEFINED */

#ifndef _TCHAR_DEFINED
typedef char TCHAR;
typedef char* PTCHAR;
typedef unsigned char TBYTE;
typedef unsigned char* PTBYTE;
#define _TCHAR_DEFINED
#endif /* _TCHAR_DEFINED */

#define _TEOF EOF

#define __T(x) x

#endif // _UNICODE

#define _T(x) __T(x)
#define _TEXT(x) __T(x)

__END_DECLS

#endif // _INC_TCHAR