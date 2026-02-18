/*
 * Copyright (C) 2023-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _WIN_SYSCALL_H_
#define _WIN_SYSCALL_H_

enum E_windows_syscall_id
{
    __NR_NtContinue,
    __NR_NtContinueEx,
    __NR_NtCallbackReturn,
    __NR_NtGetNextThread,
    __NR_NtGetContextThread,
    __NR_NtSetContextThread,
    __NR_NtTerminateThread,
    __NR_NtTerminateProcess,
    __NR_NtRaiseException,
    __NR_NtAllocateVirtualMemory,
    __NR_NtProtectVirtualMemory,
    __NR_NtCreateSection,
    __NR_NtMapViewOfSection,
    __NR_NtUnmapViewOfSection,
    __NR_NtFreeVirtualMemory,
    __NR_NtFlushInstructionCache,
    __NR_NtSuspendThread,
    __NR_NtCreateProcess,
    __NR_NtCreateProcessEx,
    __NR_NtCreateThread,
    __NR_NtResumeThread,
    __NR_NtCreateUserProcess,
    __NR_NtCreateThreadEx,
    __NR_NtDelayExecution,
    __NR_NtYieldExecution,
    __NR_NtQueryInformationProcess,
    __NR_NtSetInformationProcess,
    __NR_NtQueryVirtualMemory,
    __NR_NtAlertResumeThread,
    __NR_NtClose,
    __NR_NtCreateEvent,
    __NR_NtCreateFile,
    __NR_NtCreateMutant,
    __NR_NtCreateNamedPipeFile,
    __NR_NtCreateSemaphore,
    __NR_NtDeleteFile,
    __NR_NtDuplicateObject,
    __NR_NtFlushBuffersFile,
    __NR_NtOpenFile,
    __NR_NtOpenKey,
    __NR_NtOpenProcess,
    __NR_NtOpenThread,
    __NR_NtQueryAttributesFile,
    __NR_NtQueryInformationFile,
    __NR_NtQueryInformationThread,
    __NR_NtQueryObject,
    __NR_NtQueryPerformanceCounter,
    __NR_NtQuerySecurityObject,
    __NR_NtQuerySystemInformation,
    __NR_NtQueryValueKey,
    __NR_NtReadFile,
    __NR_NtReadVirtualMemory,
    __NR_NtReleaseMutant,
    __NR_NtReleaseSemaphore,
    __NR_NtResetEvent,
    __NR_NtSetEvent,
    __NR_NtSetInformationFile,
    __NR_NtWaitForMultipleObjects,
    __NR_NtWaitForSingleObject,
    __NR_NtWriteFile,
    __NR_NtWriteVirtualMemory,
    __NR_NtSignalAndWaitForSingleObject,
    __NR_NtQueryVolumeInformationFile,
    __NR_NtCreateMailslotFile,

    __NR_Last,

    __NR_NtAdjustPrivilegesToken,
    __NR_NtCompareObjects,
    __NR_NtFlushBuffersFileEx,
    __NR_NtFlushVirtualMemory,
    __NR_NtFsControlFile,
    __NR_NtGetCurrentProcessorNumber,
    __NR_NtOpenProcessToken,
    __NR_NtOpenThreadToken,
    __NR_NtQueryDirectoryFile,
    __NR_NtQuerySystemTime,
    __NR_NtSetInformationThread,
    __NR_NtSetSystemTime,

    __NR_Invalid,

    // Next are invented syscalls
    __NR_CreateThread,
    __NR_CreateProcess,

    __NR_VirtInvalid
};

#endif // _WIN_SYSCALL_H_
