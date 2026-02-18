/*
 * Copyright (C) 2023-2023 Intel Corporation.
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
 * TODO document.
 * Basically some helpful standard macros.
 */

#ifndef _PIN_SYS_CDEFS_H_
#define _PIN_SYS_CDEFS_H_

/*
 * Macro to test if we're using a GNU C compiler of a specific vintage
 * or later, for e.g. features that appeared in a particular version
 * of GNU C.  Usage:
 *
 *  #if __GNUC_PREREQ(major, minor)
 *  ...cool feature...
 *  #else
 *  ...delete feature...
 *  #endif
 */
#ifdef __GNUC__
#define __GNUC_PREREQ(x, y) ((__GNUC__ == (x) && __GNUC_MINOR__ >= (y)) || (__GNUC__ > (x)))
#else
#define __GNUC_PREREQ(x, y) 0
#endif

//#include <sys/cdefs_elf.h>

#if defined(__cplusplus)
#define __BEGIN_DECLS \
    extern "C"        \
    {
#define __END_DECLS }
#define __static_cast(x, y) static_cast< x >(y)
#else
#define __BEGIN_DECLS
#define __END_DECLS
#define __static_cast(x, y) (x) y
#endif

/*
 * The __CONCAT macro is used to concatenate parts of symbol names, e.g.
 * with "#define OLD(foo) __CONCAT(old,foo)", OLD(foo) produces oldfoo.
 * The __CONCAT macro is a bit tricky -- make sure you don't put spaces
 * in between its arguments.  __CONCAT can also concatenate double-quoted
 * strings produced by the __STRING macro, but this only works with ANSI C.
 */

#define ___STRING(x) __STRING(x)
#define ___CONCAT(x, y) __CONCAT(x, y)

#if defined(__STDC__) || defined(__cplusplus)
#define __P(protos) protos /* full-blown ANSI C */
#define __CONCAT(x, y) x##y
#define __STRING(x) #x

#define __const const /* define reserved names to standard */
#define __signed signed
#ifndef __volatile
#define __volatile volatile
#endif
#if defined(__cplusplus)
#define __inline inline /* convert to C++ keyword */
#else
#if !defined(__GNUC__) && !defined(__lint__)
#define __inline /* delete GCC keyword */
#endif           /* !__GNUC__  && !__lint__ */
#endif           /* !__cplusplus */

#else                  /* !(__STDC__ || __cplusplus) */
#define __P(protos) () /* traditional C preprocessor */

#ifdef _MSC_VER
#define __CONCAT(x, y) x##y
#define __STRING(x) #x

#else

#define __CONCAT(x, y) x /**/ y
#define __STRING(x) "x"

#endif

#endif /* !(__STDC__ || __cplusplus) */

#if __GNUC_PREREQ(2, 96)
#define __noreturn __attribute__((__noreturn__))
#define __mallocfunc __attribute__((malloc))
#define __purefunc __attribute__((pure))
#else
#define __noreturn
#define __mallocfunc
#define __purefunc
#endif

#endif /* !_PIN_SYS_CDEFS_H_ */
