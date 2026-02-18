/*
 * Copyright (C) 2017-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef _WIN_SYSCALLS_H_
#define _WIN_SYSCALLS_H_

#include <windows/syscall.h>

/*! @ingroup SYSCALL
 * Integral type that represents system call number.
 */
typedef uint32_t SYSCALL_NUMBER_T;

/*! @ingroup SYSCALL
 * Standard (mandatory) list of system calls to be inspected and monitored by Pin SL
 */
#define STANDARD_SL_SYSCALL_LIST                \
    SYSCALL_DEF(NtContinue)                     \
    SYSCALL_DEF(NtContinueEx)                   \
    SYSCALL_DEF(NtCallbackReturn)               \
    SYSCALL_DEF(NtGetNextThread)                \
    SYSCALL_DEF(NtGetContextThread)             \
    SYSCALL_DEF(NtSetContextThread)             \
    SYSCALL_DEF(NtTerminateThread)              \
    SYSCALL_DEF(NtTerminateProcess)             \
    SYSCALL_DEF(NtRaiseException)               \
    SYSCALL_DEF(NtAllocateVirtualMemory)        \
    SYSCALL_DEF(NtProtectVirtualMemory)         \
    SYSCALL_DEF(NtCreateSection)                \
    SYSCALL_DEF(NtMapViewOfSection)             \
    SYSCALL_DEF(NtUnmapViewOfSection)           \
    SYSCALL_DEF(NtFreeVirtualMemory)            \
    SYSCALL_DEF(NtFlushInstructionCache)        \
    SYSCALL_DEF(NtSuspendThread)                \
    SYSCALL_DEF(NtCreateProcess)                \
    SYSCALL_DEF(NtCreateProcessEx)              \
    SYSCALL_DEF(NtCreateThread)                 \
    SYSCALL_DEF(NtResumeThread)                 \
    SYSCALL_DEF(NtCreateUserProcess)            \
    SYSCALL_DEF(NtCreateThreadEx)               \
    SYSCALL_DEF(NtDelayExecution)               \
    SYSCALL_DEF(NtYieldExecution)               \
    SYSCALL_DEF(NtQueryInformationProcess)      \
    SYSCALL_DEF(NtSetInformationProcess)        \
    SYSCALL_DEF(NtQueryVirtualMemory)           \
    SYSCALL_DEF(NtAlertResumeThread)            \
    SYSCALL_DEF(NtClose)                        \
    SYSCALL_DEF(NtCreateEvent)                  \
    SYSCALL_DEF(NtCreateFile)                   \
    SYSCALL_DEF(NtCreateMutant)                 \
    SYSCALL_DEF(NtCreateNamedPipeFile)          \
    SYSCALL_DEF(NtCreateSemaphore)              \
    SYSCALL_DEF(NtDeleteFile)                   \
    SYSCALL_DEF(NtDuplicateObject)              \
    SYSCALL_DEF(NtFlushBuffersFile)             \
    SYSCALL_DEF(NtOpenFile)                     \
    SYSCALL_DEF(NtOpenKey)                      \
    SYSCALL_DEF(NtOpenProcess)                  \
    SYSCALL_DEF(NtOpenThread)                   \
    SYSCALL_DEF(NtQueryAttributesFile)          \
    SYSCALL_DEF(NtQueryInformationFile)         \
    SYSCALL_DEF(NtQueryInformationThread)       \
    SYSCALL_DEF(NtQueryObject)                  \
    SYSCALL_DEF(NtQueryPerformanceCounter)      \
    SYSCALL_DEF(NtQuerySecurityObject)          \
    SYSCALL_DEF(NtQuerySystemInformation)       \
    SYSCALL_DEF(NtQueryValueKey)                \
    SYSCALL_DEF(NtReadFile)                     \
    SYSCALL_DEF(NtReadVirtualMemory)            \
    SYSCALL_DEF(NtReleaseMutant)                \
    SYSCALL_DEF(NtReleaseSemaphore)             \
    SYSCALL_DEF(NtResetEvent)                   \
    SYSCALL_DEF(NtSetEvent)                     \
    SYSCALL_DEF(NtSetInformationFile)           \
    SYSCALL_DEF(NtWaitForMultipleObjects)       \
    SYSCALL_DEF(NtWaitForSingleObject)          \
    SYSCALL_DEF(NtWriteFile)                    \
    SYSCALL_DEF(NtWriteVirtualMemory)           \
    SYSCALL_DEF(NtSignalAndWaitForSingleObject) \
    SYSCALL_DEF(NtQueryVolumeInformationFile)   \
    SYSCALL_DEF(NtCreateMailslotFile)

/*! @ingroup SYSCALL
 * Additional (project-specific) list of Windows NT syscalls to be inspected and monitored by Pin SL
 */
#if !defined(EXTRA_SL_SYSCALL_LIST)
#define EXTRA_SL_SYSCALL_LIST
#endif

/*! @ingroup SYSCALL
 * Full (standard + extra) list of "known to Pin" system calls
 */
#define SL_SYSCALL_LIST      \
    STANDARD_SL_SYSCALL_LIST \
    EXTRA_SL_SYSCALL_LIST

/*! @ingroup SYSCALL
 * Enumeration of keys that identify "known to Pin" system calls
 */
typedef enum SYSCALL_KEY
{
#define SYSCALL_DEF(name) SYSCALL_KEY_##name = __NR_##name,
    SL_SYSCALL_LIST
#undef SYSCALL_DEF

        SYSCALL_KEY_END = __NR_Last,
    SYSCALL_KEY_UNKNOWN = SYSCALL_KEY_END
} SYSCALL_KEY;

#define SYSCALL_KEY_FIRST ((SYSCALL_KEY)0)

#define SYSCALL_NUMBER_INVALID (~(SYSCALL_KEY)0)

// This number was verified examining the WRK (Windows Research Kernel) source code
// A syscall number is at most 12 bits. Without masking we get the raw bits that
// affect the syscall behaviour (in an undocumented way) and these may change between
// system calls invocations for the same syscall. So to get the actual system call 
// number we need to use this mask.
#define KERNEL_SYSCALL_NUMBER_MASK ((uint32_t)((1 << 12) - 1))

#endif // _WIN_SYSCALLS_H_
