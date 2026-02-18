/*
 * Copyright (C) 2024-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef OS_APIS_PH_
#define OS_APIS_PH_

#include <pinos.h>

/*!
 * @file
 * Contains declaration for replacement functions for certain Pin-3 OS-APIs
 * Only OS-APIs declared in this header or through pinos.h
 * should be used by Pin tool writers.
 * 
 * Any other APIs starting with OS_ that may be exposed through other headers
 * should be considered internal APIs with interface and behavior that may change
 * without notice.
 * 
 * @note Many OS-APIs return t_syscall_ret. t_syscall_ret is a native address size unsigned value.
 *       When converted to a signed value then values between -1 and -4095 are considered errors.
 *       A simple way to check if such a function returned an error is by using 
 *       the #IS_PINOS_SYSCALL_ERROR(sysret) macro.
 *       The error values themselves correspond to Linux syscall return values which is a negative errno
 *       value. PINOS uses these values for both Linux & Windows.
 *       Checking against a specific value can be done using the #SYSRET(rc).
 */

/*!
 * CPU Architecture
 */
typedef enum
{
    OS_HOST_CPU_ARCH_TYPE_INVALID = 0,
    OS_HOST_CPU_ARCH_TYPE_IA32    = 1,
    OS_HOST_CPU_ARCH_TYPE_INTEL64 = 2
} OS_HOST_CPU_ARCH_TYPE;

/*! @ingroup OS_APIS_HOST
 * Query CPU architecture.
 *
 * @param[out] arch   The architecture of this system's CPU
 *
 * @retval    0             If the operation succeeded
 * @retval    syscall error If the operation failed
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux \n
 *   @b CPU:   All \n
 */
EXTERNC t_syscall_ret OS_GetHostCPUArch(OS_HOST_CPU_ARCH_TYPE* arch);

/*! @ingroup OS_APIS_HOST
 * Get kernel release description string.
 *
 * @param[out] buf     Buffer to receive the release string
 * @param[in]  bufsize Size of buffer @b buf in bytes
 *
 * @retval    0             If the operation succeeded
 * @retval    syscall error If the operation failed
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux \n
 *   @b CPU:   All \n
 */
EXTERNC t_syscall_ret OS_GetKernelRelease(char* buf, uint32_t bufsize);

/*! @ingroup OS_APIS_HOST
 * Get a string representing a certain CPU arch.
 *
 * @param[in] arch    The architecture to get a string for it
 *
 * @retval     read-only string representing the CPU arch
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux \n
 *   @b CPU:   All \n
 */
EXTERNC const char* OS_CPUArchToString(OS_HOST_CPU_ARCH_TYPE arch); 

#endif // OS_APIS_PH_