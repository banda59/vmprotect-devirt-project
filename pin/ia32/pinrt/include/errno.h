#ifndef	_ERRNO_H
#define _ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#include <bits/errno.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((const))
#endif
int *__errno_location(void);
#define errno (*__errno_location())

#ifdef _GNU_SOURCE
#if defined(TARGET_WINDOWS)
PINCRT_DLL_DATA_VIS char *program_invocation_short_name;
PINCRT_DLL_DATA_VIS char *program_invocation_name;
#else
extern char *program_invocation_short_name, *program_invocation_name;
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif

