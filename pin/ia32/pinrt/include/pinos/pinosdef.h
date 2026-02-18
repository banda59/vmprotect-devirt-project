/*
 * Copyright (C) 2025-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _PINOSDEF_H_
#define _PINOSDEF_H_

#ifdef __cplusplus
#define EXTERNC extern "C"
#define NORETURN__ [[noreturn]]
#else
#define EXTERNC extern
#define NORETURN__ __attribute__((__noreturn__))
#endif // __cplusplus

#define EXTERN extern
#ifdef TARGET_IA32
#ifdef __GNUC__
#define PINOSCALL __attribute__((cdecl))
#else
#define PINOSCALL __cdecl
#endif
#else
#define PINOSCALL
#endif

#ifndef PINOS_DLLVIS
#ifdef PINOS_BUILD
#if defined(TARGET_WINDOWS)
#define PINOS_DLLVIS __declspec(dllexport)
#else
#define PINOS_DLLVIS __attribute__((visibility("default")))
#endif // TARGET_WINDOWS
#else
#define PINOS_DLLVIS
#endif // PINOS_BUILD
#endif // PINOS_DLLVIS

#define PINOS_STRINGIFY(x) #x
#define PINOS_VALUE(x) x
#define PINOS_PRAGMA(compiler, pragma) _Pragma(PINOS_STRINGIFY(compiler pragma))
#if defined(__GNUC__)
#define PRAGMA_DIAG_PUSH PINOS_PRAGMA(GCC, diagnostic push)
#define PRAGMA_DIAG_POP PINOS_PRAGMA(GCC, diagnostic pop)
#define PRAGMA_DIAG_IGNORE(x) PINOS_PRAGMA(GCC, diagnostic ignored PINOS_VALUE(x))
#elif defined(__clang__)
#define PRAGMA_DIAG_PUSH PINOS_PRAGMA(clang, diagnostic push)
#define PRAGMA_DIAG_POP PINOS_PRAGMA(clang, diagnostic pop)
#define PRAGMA_DIAG_IGNORE(x) PINOS_PRAGMA(clang, diagnostic ignored PINOS_VALUE(x))
#else
#error "Unsupported compiler"
#endif

#endif // _PINOSDEF_H_