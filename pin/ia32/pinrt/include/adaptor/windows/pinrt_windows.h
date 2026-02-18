/*
 * Copyright (C) 2017-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef _PINRT_WINDOWS_H_
#define _PINRT_WINDOWS_H_

// Some CRT headers must be included before Windows.h to prevent
// their inclusion under the WINDOWS namespace
#include <pinrtassert.h>

#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syscall.h>
#include <wchar.h>
#include <wctype.h>

// PIN defined types which may conflict with Windows types
#include <types.h>

#if defined(__cplusplus) && defined(_WINDOWS_NAMESPACE_)
namespace _WINDOWS_NAMESPACE_
{
#endif
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#if defined(TARGET_IA32E)
#ifndef _AMD64_
#define _AMD64_ 1
#endif
#endif

#define _wcsicmp wcscmp

#include <Windows.h>

// The header files of Win7 (which is the only Windows with AVX support)
// still specify CONTEXT_XSTATE to be (CONTEXT_AMD64 | 0x00000020L)
// even though   CONTEXT_XSTATE is    (CONTEXT_AMD64 | 0x00000040L)
// so override it
#undef CONTEXT_XSTATE
#if defined(_AMD64_)
#define CONTEXT_XSTATE (CONTEXT_AMD64 | 0x00000040L)
#else
#define CONTEXT_XSTATE (CONTEXT_i386 | 0x00000040L)
#endif
// Special mask is used to disable CONTEXT_XSTATE in CONTEXT.ContextFlags
#define CONTEXT_XSTATE_DISABLE (CONTEXT_CONTROL | ~CONTEXT_XSTATE)

// The extended context is composed from extended context header and
// several separate context regions
// The context region structure specifies an offset from the beginning of context header
// and size of a single block of an extended context.
// Negative offset is allowed.
typedef struct _CONTEXT_REGION
{
    INT32 Offset;
    UINT32 Size;
} CONTEXT_REGION, *PCONTEXT_REGION;

// CONTEXT_HEADER defines set of context regions that may be not adjacent.
// Only base region that describes standard CONTEXT structure is mandatory.
// CONTEXT_HEADER structure is expected only when special flags that require
// extra context regions are set in CONTEXT.ContextFlags.
// If CONTEXT_HEADER is necessary it immediately follows standard CONTEXT structure.
// Currently CONTEXT_HEADER describes standard CONTEXT structure region,
// global region that covers all other regions and XSAVE region
// to store context saved by XSAVE instruction starting from XSAVE header.
typedef struct _CONTEXT_HEADER
{
    // The total size of the extended context layout starting from the region
    // with the smallest offset. Its offset is negative.
    CONTEXT_REGION Global;

    // Regular CONTEXT structure. The offset of the region is negative.
    CONTEXT_REGION Regular;

    // XSAVE area.
    // Present if CONTEXT_XSTATE flag is set. Contains any data stored by
    // XSAVE instruction after first 512 bytes of legacy FP area.
    CONTEXT_REGION Xstate;

} CONTEXT_HEADER, *PCONTEXT_HEADER;

// The following macros provide access to context regions.

#define WIN_CONTEXT_REGION_OFFSET(Context, Region) (((PCONTEXT_HEADER)(Context + 1))->Region.Offset)

#define WIN_CONTEXT_REGION_LENGTH(Context, Region) (((PCONTEXT_HEADER)(Context + 1))->Region.Size)

#define WIN_CONTEXT_REGION(Context, Region) ((PVOID)((PCHAR)(Context + 1) + WIN_CONTEXT_REGION_OFFSET(Context, Region)))

#if defined(TARGET_IA32E)
#include "unwind_intel64.h"
#endif

#define DEVICE_TYPE DWORD

#include "ntdll.h"

// Some Windows #defines conflict with pin definitions - #undefine them now.
#ifdef REG_NONE
#undef REG_NONE
#endif
#ifdef Yield
#undef Yield
#endif

#if defined(__cplusplus) && defined(_WINDOWS_NAMESPACE_)
} // namespace WINDOWS
#endif

#endif  // _PINRT_WINDOWS_H_