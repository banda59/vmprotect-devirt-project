/*
 * Copyright (C) 2023-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*  ntdll.h
    Declares part of the Windows NT native API implemented by ntdll.dll and 
    used by pin.
    Some of the NT types and function prototypes can be found in SDK of MSVC and
    gcc compilers. Since some of the declarations in MSVC and gcc are different, 
    and gcc declarations are not always correct, this file provides independent
    definitions.
*/
#if !defined(_NTDLL_H_)
#define _NTDLL_H_

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#if !defined(NTAPI_PREFIX)
#define NTAPI_PREFIX
#endif

#define _NTAPI_NAME_WITH_PREFIX1(prefix, name) prefix##name
#define _NTAPI_NAME_WITH_PREFIX(prefix, name) _NTAPI_NAME_WITH_PREFIX1(prefix, name)
#define _NTAPI_NAME(name) _NTAPI_NAME_WITH_PREFIX(NTAPI_PREFIX, name)

#if !defined(__GNUC__) && !defined(_MSC_VER)
#error "Unsupported compiler"
#endif

#if defined(_NTDLL_IMPLIB)
#define _NTAPI_IMPL \
    {               \
        return 0;   \
    }
#define _BOOLEAN_IMPL \
    {                 \
        return 0;     \
    }
#define _ULONG_IMPL \
    {               \
        return 0;   \
    }
#define _VOID_IMPL \
    {              \
        return;    \
    }
#define _NTAPI_DECL
#else
#define _NTAPI_IMPL
#define _BOOLEAN_IMPL
#define _ULONG_IMPL
#define _VOID_IMPL
#define _NTAPI_DECL extern __declspec(dllimport)
#endif

#define NTAPI __stdcall

#ifdef __cplusplus
#define _INLINE_FUNC inline
#else
#if defined(__GNUC__)
#define _INLINE_FUNC static inline
#elif defined(_MSC_VER)
#define _INLINE_FUNC static __inline
#endif
#endif

/*
 * Defining constants for supporting CET
 */
#ifndef IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS 20
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
#define IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT 0x00000001
#endif

    //============================================================================
    //  NTAPI types
    //============================================================================

/* 
 * Integral type representing status of NT system call
 */
    typedef LONG NTSTATUS, *PNTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define STATUS_OK ((NTSTATUS)0x0L)

/*
 * Wait completion status
 */
#ifndef STATUS_WAIT_0
#define STATUS_WAIT_0 ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_WAIT_1
#define STATUS_WAIT_1 ((NTSTATUS)0x00000001L)
#endif

#ifndef STATUS_ABANDONED_WAIT_0
#define STATUS_ABANDONED_WAIT_0 ((NTSTATUS)0x00000080L)
#endif

#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102L)
#endif

/*
 * The operation that was requested is pending completion.
 */
#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif

/*
 * An invalid HANDLE was specified.
 */
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#endif

 /*
  * {Image Relocated}
  * Image memory mapping is OK, but an image file could not be mapped
  * at the address specified in the image file and was rebased in memory.
  * Local fixups were not yet applied and must be performed on this image.
  */
#ifndef STATUS_IMAGE_NOT_AT_BASE
#define STATUS_IMAGE_NOT_AT_BASE ((NTSTATUS)0x40000003L)
#endif
/*
 * {Image Relocated}
 * Image memory mapping is OK, but an image file could not be mapped
 * at the address specified in the image file and was rebased in memory.
 * Local fixups were applied.
 */
#ifndef STATUS_IMAGE_AT_DIFFERENT_BASE
#define STATUS_IMAGE_AT_DIFFERENT_BASE ((NTSTATUS)0x40000036L)
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

/*
 * {Conflicting Address Range}
 * The specified address range conflicts with the address space.
 */
#ifndef STATUS_CONFLICTING_ADDRESSES
#define STATUS_CONFLICTING_ADDRESSES ((NTSTATUS)0xC0000018L)
#endif

/*
 * {Access Denied}
 * A process has requested access to an object but has not been granted those access rights.
 */
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

/*
 * {Wrong Type}
 * There is a mismatch between the type of object that is required
 * by the requested operation and the type of object that is
 * specified in the request.
 */
#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)
#endif

/*
 * An attempt was made to suspend a thread that has begun termination.
 */
#ifndef STATUS_THREAD_IS_TERMINATING
#define STATUS_THREAD_IS_TERMINATING ((NTSTATUS)0xC000004BL)
#endif

/*
 * A specified name string is too long for its intended use.
 */
#ifndef STATUS_NAME_TOO_LONG
#define STATUS_NAME_TOO_LONG ((NTSTATUS)0xC0000106L)
#endif

/*
 * Specified segment selector is not available
 */
#ifndef STATUS_ABIOS_SELECTOR_NOT_AVAILABLE
#define STATUS_ABIOS_SELECTOR_NOT_AVAILABLE ((NTSTATUS)0xC0000115L)
#endif

/*
 * Specified segment selector is not valid
 */
#ifndef STATUS_ABIOS_INVALID_SELECTOR
#define STATUS_ABIOS_INVALID_SELECTOR ((NTSTATUS)0xC0000116L)
#endif

/*
 * Indicates that an attempt was made to change the size of the LDT for a process that has no LDT.
 */
#ifndef STATUS_NO_LDT
#define STATUS_NO_LDT ((NTSTATUS)0xC0000117L)
#endif

/*
 * Indicates that an attempt was made to grow an LDT by setting its size,
 * or that the size was not an even number of selectors.
 */
#ifndef STATUS_INVALID_LDT_SIZE
#define STATUS_INVALID_LDT_SIZE ((NTSTATUS)0xC0000118L)
#endif

/*
 * Indicates that the starting value for the LDT information
 * was not an integral multiple of the selector size.
 */
#ifndef STATUS_INVALID_LDT_OFFSET
#define STATUS_INVALID_LDT_OFFSET ((NTSTATUS)0xC0000119L)
#endif

/*
 * The pipe operation has failed because the other end of the pipe has been closed.
 */
#ifndef STATUS_PIPE_BROKEN
#define STATUS_PIPE_BROKEN ((NTSTATUS)0xC000014BL)
#endif

/*
 * Length of provided buffer did not match expected length.
 */
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

/*
 * Invalid pointer passed to system call.
 */
#ifndef STATUS_ACCESS_VIOLATION
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005L)
#endif

/*
 * The end-of-file marker has been reached. There is no valid data in the file beyond this marker.
 */
#ifndef STATUS_END_OF_FILE
#define STATUS_END_OF_FILE ((NTSTATUS)0xC0000011L)
#endif

/*!
 * An attempt has been made to remove a file or directory that cannot be deleted.
 */
#ifndef STATUS_CANNOT_DELETE
#define STATUS_CANNOT_DELETE ((NTSTATUS)0xC0000121)
#endif

/*!
 * Debugger printed exception on control C.
 * The OutputDebugString() API raises this exception when sending a 
 * string to the debugger.
 */
#ifndef DBG_PRINTEXCEPTION_C
#define DBG_PRINTEXCEPTION_C ((NTSTATUS)0x40010006L)
#endif

 /*!
 * The object name already exists.
 */
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif

 /*!
 * No more entries are available from an enumeration operation.
 */
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

 /*!
 * Exception used to communicate a human-readable thread name to MSVC 
 * debugger. 
 * @note This exception is not defined in <ntstatus.h>. We do not know
 *       the "official" MS name for this exception.
 */
#define DBG_THREAD_NAME_EXCEPTION ((NTSTATUS)0x406D1388L)

/* 
 * Handle to the current process
 */
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

/* 
 * Handle to the current thread
 */
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

    /*!
 * Structure representing ANSI/MBCS string in NTAPI
 */
    typedef struct _STRING
    {
        USHORT Length;        // string size, in bytes, not including terminating NULL
        USHORT MaximumLength; // buffer size, in bytes, including terminating NULL
        PCHAR Buffer;         // pointer to ANSI/MBCS string
    } STRING;
    typedef STRING* PSTRING;

    typedef STRING ANSI_STRING;
    typedef PSTRING PANSI_STRING;
    typedef PSTRING PCANSI_STRING;

    /*!
 * Structure representing UNICODE string in NTAPI
 */
    typedef struct _UNICODE_STRING
    {
        USHORT Length;        // string size, in bytes, not including terminating NULL
        USHORT MaximumLength; // buffer size, in bytes, including terminating NULL
        PWSTR Buffer;         // pointer to UNICODE string
    } UNICODE_STRING;
    typedef UNICODE_STRING* PUNICODE_STRING;
    typedef const UNICODE_STRING* PCUNICODE_STRING;

    /*!
 * Structure representing OBJECT_ATTRIBUTES
 */
    typedef struct _OBJECT_ATTRIBUTES
    {
        ULONG Length;
        HANDLE RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;
        PVOID SecurityQualityOfService;
    } OBJECT_ATTRIBUTES;
    typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

/*!
 * Valid values for the Attributes field
 */
#define OBJ_INHERIT 0x00000002L
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_KERNEL_HANDLE 0x00000200L

    /*!
 * Structure that keeps process and thread IDs
 */
    typedef struct _CLIENT_ID
    {
        HANDLE UniqueProcess; // Process ID
        HANDLE UniqueThread;  // Thread ID
    } CLIENT_ID;
    typedef CLIENT_ID* PCLIENT_ID;

    /*!
 * Loader data in PEB
 */
    typedef struct _PEB_LDR_DATA
    {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
    } PEB_LDR_DATA;
    typedef PEB_LDR_DATA* PPEB_LDR_DATA;

    typedef struct _LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        // The rest are not documented fields.
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    /*!
 * CURDIR
 */
    typedef struct _CURDIR
    {
        UNICODE_STRING DosPath;
        PVOID Handle;
    } CURDIR, *PCURDIR;

#define RTL_PROCESS_PARAMETERS_FLAGS_NORMALIZED 0x1

    /*!
 * Rtl user process paremeters
 * Only first few members are defined - do not assume a maximum size for the structure
 */
    typedef struct _RTL_USER_PROCESS_PARAMETERS
    {
        ULONG MaximumLength;
        ULONG Length;
        ULONG Flags;
        ULONG DebugFlags;
        HANDLE ConsoleHandle;
        ULONG ConsoleFlags;
        HANDLE StandardInput;
        HANDLE StandardOutput;
        HANDLE StandardError;
        CURDIR CurrentDirectory;
        UNICODE_STRING DllPath;
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
        PWSTR Environment;
    } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

    /*!
 * Process Environment Block
 * Only first few members are defined - do not assume a maximum size for the structure
 */
    typedef struct _PEB
    {
        BOOLEAN Reserved_1[2];
        BOOLEAN BeingDebugged; // TRUE if the process is being debugged
        BOOLEAN Reserved_2;
        HANDLE Mutant;

        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;

        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID Reserved_3;
        PVOID ProcessHeap;
        PRTL_CRITICAL_SECTION FastPebLock;

        PVOID Reserved_4[2];
        ULONG Reserved_5;
        PVOID KernelCallbackTable;
        ULONG Reserved_6[2];
        PVOID Reserved_7;
        ULONG Reserved_8;
        PVOID Reserved_9;
        ULONG Reserved_10[2];
        PVOID Reserved_11[6];
        ULONG Reserved_12[2];
        LARGE_INTEGER Reserved_13;
        SIZE_T Reserved_14[4];

        ULONG NumberOfHeaps;
        ULONG MaximumNumberOfHeaps;
        PVOID* ProcessHeaps;

        PVOID Reserved_15[2];
        ULONG Reserved_16;

        PRTL_CRITICAL_SECTION LoaderLock;
        ULONG OSMajorVersion;
        ULONG OSMinorVersion;
        WORD OSBuildNumber;
        WORD OSCSDVersion;
        ULONG OSPlatformId;
    } PEB;
    typedef PEB* PPEB;

    /*!
 * Thread Environment Block
 * Only first few members are defined - do not assume a maximum size for the structure
 */
    typedef struct _TEB
    {
        NT_TIB NtTib; // Thread Information Block
        PVOID EnvironmentPointer;
        CLIENT_ID ClientId;
        PVOID Reserved_1;
        PVOID ThreadLocalStoragePointer;
        PPEB ProcessEnvironmentBlock; // Pointer to PEB
        ULONG LastErrorValue;         // Last Win32 error value
        ULONG CountOfOwnedCriticalSections;
        PVOID Reserved_2[2];
        ULONG Reserved_3[31];
        PVOID WOW32Reserved; // Address of the WOW syscall gate
#if defined(TARGET_IA32)
        UCHAR Padding_0[3400];
#elif defined(TARGET_IA32E)
        UCHAR Padding_0[4976];
#else
#error "BAD TARGET"
#endif
        PVOID DeallocationStack; // Base address of the allocated stack
    } TEB, *PTEB;
    typedef TEB* PTEB;

    /*!
 * Another representation of the Thread Environment Block. Defines location TLS slots in TEB.
 */
    typedef struct _TEB_TLS
    {
        BYTE Reserved1[1952];
        PVOID Reserved2[412];
        PVOID TlsSlots[64];
        BYTE Reserved3[8];
        PVOID Reserved4[26];
        PVOID ReservedForOle; // Windows 2000 only
        PVOID Reserved5[4];
        PVOID TlsExpansionSlots;
    } TEB_TLS, *PTEB_TLS;

    /* 
 * Pointer to the Process Environment Block of the current process
 */
    _INLINE_FUNC PPEB NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }

/*!
 * Offset of the WOW64 syscall gate address in 32-bit TEB : offsetof(TEB32, WOW32Reserved)
 * This constant is used in assembly files, so the value should be decimal.
 */
#define TEBOFF_WOW64_GATE 192

/*!
 * Information returned by NtQueryObject for the ObjectBasicInformation class
 */
    typedef struct _OBJECT_BASIC_INFORMATION {
        ULONG Attributes;
        ACCESS_MASK GrantedAccess;
        ULONG HandleCount;
        ULONG PointerCount;
        ULONG PagedPoolCharge;
        ULONG NonPagedPoolCharge;
        ULONG Reserved[3];
        ULONG NameInfoSize;
        ULONG TypeInfoSize;
        ULONG SecurityDescriptorSize;
        LARGE_INTEGER CreationTime;
    } OBJECT_BASIC_INFORMATION;
    typedef OBJECT_BASIC_INFORMATION* POBJECT_BASIC_INFORMATION;

/*!
 * Object Information Classes (partial definition)
 */
    typedef enum _OBJECT_INFORMATION_CLASS {
        ObjectBasicInformation = 0,
        ObjectNameInformation,
        ObjectTypeInformation
    } OBJECT_INFORMATION_CLASS;

    /*!
 * System Information Classes (partial definition)
 */
    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation = 0
    } SYSTEM_INFORMATION_CLASS;

    /*!
 * Information returned by NtQuerySystemInformation for the SystemBasicInformation class
 */
    typedef struct _SYSTEM_BASIC_INFORMATION
    {
        ULONG Reserved;
        ULONG TimerResolution;
        ULONG PageSize;
        ULONG Reserved_1[3];
        ULONG AllocationGranularity;
        ULONG_PTR MinimumUserModeAddress;
        ULONG_PTR MaximumUserModeAddress;
        ULONG_PTR ActiveProcessorsAffinityMask;
        CHAR NumberOfProcessors;
    } SYSTEM_BASIC_INFORMATION;
    typedef SYSTEM_BASIC_INFORMATION* PSYSTEM_BASIC_INFORMATION;

    /*!
 * Process Information Classes (partial definition)
 */
    typedef enum _PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0,   //PROCESS_BASIC_INFORMATION structure
        ProcessDebugPort        = 7,   //PROCESS_DEBUG_PORT structure
        ProcessWow64Information = 26,  //PROCESS_WOW64_INFORMATION structure
        ProcessMitigationPolicy = 0x34,//PROCESS_MITIGATION_POLICY enumeration
        ProcessCommandLineInformation = 0x3C
    } PROCESSINFOCLASS;

    /*!
 * When querying / setting information process with ProcessMitigationPolicy process information class,
 * ProcessInformation buffer is in/out parameter. NtQueryInformationProcess reads the Policy field
 * (enum _PROCESS_MITIGATION_POLICY), and then stores relevant data according to the enum value in
 * the union defined below.
 */
    typedef struct _ProcessMitigationData
    {
        PROCESS_MITIGATION_POLICY Policy;
        union
        {
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY ProcessDynamicCodePolicy;
        };
    } ProcessMitigationData;

// "policy" argument should have the exact name of PROCESS_MITIGATION_POLICY enumerator.
#define PROCESS_MITIGATION_DATA_SIZE(policy) \
    (offsetof(WINDOWS::ProcessMitigationData, policy) + sizeof(((WINDOWS::ProcessMitigationData*)0)->policy))

    /*!
 * Information returned by NtQueryInformationProcess for the ProcessBasicInfo class
 */
    typedef struct _PROCESS_BASIC_INFORMATION
    {
        NTSTATUS ExitStatus;
        PPEB PebBaseAddress;
        ULONG_PTR Reserved_1;
        LONG Reserved_2;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;
    typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

    /*!
 * Information returned by NtQueryInformationProcess for the ProcessWow64Information class
 */
    typedef struct _PROCESS_WOW64_INFORMATION
    {
        ULONG_PTR IsWow64Process; //non-zero value for a process running under WOW64
    } PROCESS_WOW64_INFORMATION;
    typedef PROCESS_WOW64_INFORMATION* PPROCESS_WOW64_INFORMATION;

    /*!
 * Information returned by NtQueryInformationProcess for the ProcessDebugPort class
 */
    typedef struct _PROCESS_DEBUG_PORT
    {
        DWORD_PTR DebugPort; //non-zero if process is debugged by a ring 3 debugger (always interpreted as boolean)
    } PROCESS_DEBUG_PORT;
    typedef PROCESS_DEBUG_PORT* PPROCESS_DEBUG_PORT;

    /*!
 * Thread Information Classes (partial definition)
 */
    typedef enum _THREADINFOCLASS
    {
        ThreadBasicInformation     = 0, //THREAD_BASIC_INFORMATION structure
        ThreadDescriptorTableEntry = 6  // LDT_ENTRY structure (e.g. segment descriptor)
    } THREADINFOCLASS;

    /*!
 * Information returned by NtQueryInformationThread for the ThreadBasicInfo class
 */
    typedef struct _THREAD_BASIC_INFORMATION
    {
        NTSTATUS ExitStatus;
        PTEB TebBaseAddress;
        CLIENT_ID ClientId;
        ULONG_PTR AffinityMask;
        LONG Priority;
        LONG BasePriority;
    } THREAD_BASIC_INFORMATION;
    typedef THREAD_BASIC_INFORMATION* PTHREAD_BASIC_INFORMATION;

    /*!
 * Enumerated type used to specify how child process inherit mapped section
 */
    typedef enum _SECTION_INHERIT
    {
        ViewShare = 1, // section is inherited by child processes
        ViewUnmap = 2  // section is not inherited by child processes
    } SECTION_INHERIT;

    /*!
     * Enumerated type used to specify class of memory information returned by the
     * NtQueryVirualMemory() function.
     */
    typedef enum _MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation = 0, // MEMORY_BASIC_INFORMATION structure, describes referenced memory protection region.
        MemoryWorkingSetList,
        MemorySectionName,          // Fully qualified NT name of mapped file if used to create section.
                                    // Returns UNICODE_STRING header followed by UNICODE string.
        MemoryRegionInformation     // MEMORY_REGION_INFORMATION structure
    } MEMORY_INFORMATION_CLASS;

    /*!
     * Information returned by NtQueryVirualMemory() for MemoryRegionInformation class.
     * Describes referenced memory allocation region.
     */
    typedef struct _MEMORY_REGION_INFORMATION
    {
        PVOID AllocationBase;
        ULONG AllocationProtect;
        ULONG RegionType;
        SIZE_T RegionSize;
        SIZE_T CommitSize;
        SIZE_T Reserved[2]; // Added padding to reserve space for any supported info structure
    } MEMORY_REGION_INFORMATION, * PMEMORY_REGION_INFORMATION;

    /*!
     * Information representing completion status of IO operation
     */
    typedef struct _IO_STATUS_BLOCK
    {
        union
        {
            NTSTATUS Status;
            PVOID Pointer;
        };

        ULONG_PTR Information;
    } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

    /*!
 * Information representing file basic information
 */
    typedef struct _FILE_BASIC_INFORMATION
    {
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        ULONG FileAttributes;
    } FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

    /*!
 * wait type to be performed by NtWaitForMultipleObjects
 */
    typedef enum _WAIT_TYPE
    {
        WaitAll,
        WaitAny
    } WAIT_TYPE;

    /*!
 * Event type
 */
    typedef enum _EVENT_TYPE
    {
        NotificationEvent,   //manual-reset event
        SynchronizationEvent //auto-reset event
    } EVENT_TYPE;

    /*!
 * Create process object and primary thread object
 *
 * @param[out] processHandle         Pointer to process handle that will receive the process 
 *                                   handle of the created process object
 * @param[out] threadHandle          Pointer to thread handle that will receive the process 
 *                                   handle of the created thread object
 * @param      parameter2            unknown,  (maybe - ACCESS_MASK ProcessDesiredAccess)
 * @param      parameter3            unknown,  (maybe - ACCESS_MASK ThreadDesiredAccess)
 * @param      parameter4            unknown,  (maybe - PVOID ProcessSecurityDescriptor)
 * @param      parameter5            unknown,  (maybe - PVOID ThreadSecurityDescriptor)
 * @param      parameter6            unknown,  (maybe - ULONG flags)
 * @param[in]  createSuspended       Should the thread be created suspended
 * @param      parameter8            unknown (maybe - PRTL_USER_PROCESS_PARAMETERS ProcessParameters)
 * @param      parameter9            unknown
 * @param      parameter10           unknown
 */
    typedef NTSTATUS(NTAPI* NtCreateUserProcess_T)(PHANDLE processHandle, PHANDLE threadHandle, PVOID parameter2,
                                                   PVOID parameter3, PVOID parameter4, PVOID parameter5, PVOID parameter6,
                                                   DWORD createSuspended, PVOID parameter8, PVOID parameter9, PVOID parameter10);

    /*!
 * Create thread object
 *
 * @param[out] threadHandle          Pointer to thread handle that will receive the process 
 *                                   handle of the created thread object
 * @param      parameter1            unknown
 * @param      parameter2            unknown
 * @param      processHandle         Handle of the process who owns the thread
 * @param      parameter4            unknown
 * @param      parameter5            unknown
 * @param      parameter6            unknown
 * @param[in]  createSuspended       Should the thread be created suspended
 * @param      parameter8            unknown
 * @param      parameter9            unknown
 * @param      parameter10           unknown
 */
    typedef NTSTATUS(NTAPI* NtCreateThreadEx_T)(PHANDLE threadHandle, PVOID parameter1, PVOID parameter2, HANDLE processHandle,
                                                PVOID parameter4, PVOID parameter5, DWORD createSuspended, PVOID parameter7,
                                                PVOID parameter8, PVOID parameter9, PVOID parameter10);

/*
 * Define the available options for "options" param in NtDuplicateObject
 */
#define DUPLICATE_CLOSE_SOURCE 0x00000001
#define DUPLICATE_SAME_ACCESS 0x00000002
#define DUPLICATE_SAME_ATTRIBUTES 0x00000004

    //============================================================================
    //  NTDLL.DLL exports
    //============================================================================

    /*!
 * Load specified DLL (LdrLoadDll) or get handle to already mapped DLL (LdrGetDllHandle).
 * 
 * @param[inopt] dllPath            path to DLL, in UNICODE.
 * @param[inopt] dllCharacteristics pointer to variable that conatins DLL characteristics.
 *                                  See dwFlags of LoadLibraryEx().
 * @param[inout] dllName            filename of the DLL, in UNICODE
 * @param[out] dllHandle            pointer to variable that receives handle to DLL
 */

    _NTAPI_DECL NTSTATUS NTAPI LdrGetDllHandle(PCWSTR dllPath, PULONG dllCharacteristics, PCUNICODE_STRING dllName,
                                               PVOID* dllHandle) _NTAPI_IMPL;

    /*!
 * Return version information about the currently running operating system.
 *
 * @param[inout] lpVersionInformation  Pointer to either RTL_OSVERSIONINFOW or RTL_OSVERSIONINFOEXW structure.
 *                                     The function fills the structure with OS version info.
 *                                     Caller should set corresponding size in dwOSVersionInfoSize field.
 *                                     The size defines kind of structure to fill.
 *
 * @return    STATUS_OK
 */
    _NTAPI_DECL NTSTATUS WINAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) _NTAPI_IMPL;

    /*!
 * Map specified part of section object into memory of the specified process.
 * 
 * @param[in]  sectionHandle  handle to the section object to be mapped
 * @param[in]  processHandle  handle to the process
 * @param[inout] baseAddress  pointer to variable that receives the base address
 *                            of the mapped view
 * @param[in] zeroBits        specifies alignment (number of zero bits) of the
 *                            base address
 * @param[in] commitSize      Size of initially commited memory, in bytes.
 * @param[inout_opt] sectionOffset  Offset where the view is to begin
 * @param[inout] viewSize     Size of the mapped view, in bytes
 * @param[in] inheritDisposition Specifies how child processes inherit mapped section. 
 * @param[in] allocationType  Type of allocation - combination of MEM_* flags
 * @param[in] win32Protect    Protection for pages of the view - one of the PAGE_* flags
 */
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtMapViewOfSection)(HANDLE sectionHandle, HANDLE processHandle, PVOID* baseAddress,
                                                               ULONG_PTR zeroBits, SIZE_T commitSize,
                                                               PLARGE_INTEGER sectionOffset, PSIZE_T viewSize,
                                                               SECTION_INHERIT inheritDisposition, ULONG allocationType,
                                                               ULONG win32Protect) _NTAPI_IMPL;

    /*!
 * Unmap a mapped view of a section from the address space of the specified process.
 * 
 * @param[in]  processHandle  handle to the process
 * @param[inout] baseAddress  base address of the view to be unmapped
 */
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtUnmapViewOfSection)(HANDLE processHandle, PVOID baseAddress) _NTAPI_IMPL;

    /*!
* Terminate specified thread.
* 
* @param[in] threadHandle   handle to the target thread
* @param[in] exitStatus     exit status of the thread
*/
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtTerminateThread)(HANDLE threadHandle, NTSTATUS exitStatus) _NTAPI_IMPL;

/*!
 * Create process object
 *
 * @param[out] processHandle         Pointer to process handle that will receive the process 
 *                                   handle of the created process object
 * @param[in]  desiredAccess         Access type desired by caller
 * @param[in]  objectAttributes      Pointer to object attributes struct
 * @param[in]  parentProcess         Handle to parent process
 * @param[in]  inheritObjectTable    Should inheritable handles be inherited from 
 *                                   ParentProcess
 * @param[in]  sectionHandle         Handle to an image section 
 * @param[in]  debugPort             Handle to a debug port (for debug messages)
 * @param[in]  exceptionPort         Handle to an exception port (for exception messages)
 */
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtCreateProcess)(PHANDLE processHandle, ACCESS_MASK desiredAccess,
                                                            POBJECT_ATTRIBUTES objectAttributes, HANDLE parentProcess,
                                                            BOOLEAN inheritObjectTable, HANDLE sectionHandle, HANDLE debugPort,
                                                            HANDLE exceptionPort) _NTAPI_IMPL;

/*!
 * Create process object
 *
 * @param[out] processHandle         Pointer to process handle that will receive the process 
 *                                   handle of the created process object
 * @param[in]  desiredAccess         Access type desired by caller
 * @param[in]  objectAttributes      Pointer to object attributes struct
 * @param[in]  parentProcess         Handle to parent process
 * @param[in]  flags                 Flags
 * @param[in]  sectionHandle         Handle to an image section 
 * @param[in]  debugPort             Handle to a debug port (for debug messages)
 * @param[in]  exceptionPort         Handle to an exception port (for exception messages)
 * @param[in]  jobMemberLevel        JobMemberLevel
 */
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtCreateProcessEx)(PHANDLE processHandle, ACCESS_MASK desiredAccess,
                                                              POBJECT_ATTRIBUTES objectAttributes, HANDLE parentProcess,
                                                              ULONG flags, HANDLE sectionHandle, HANDLE debugPort,
                                                              HANDLE exceptionPort, ULONG jobMemberLevel) _NTAPI_IMPL;

/*!
 * Terminate process and it's threads
 *
 * @param[in] processHandle      Process Handle
 * @param[in] exitStatus         Exit status for the process and all it's threads
 */
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtTerminateProcess)(HANDLE processHandle, NTSTATUS exitStatus) _NTAPI_IMPL;

    /*!
 * Create thread object
 *
 * @param[out] threadHandle          Pointer to thread handle that will receive the thread 
 *                                   handle of the created thread object
 * @param[in]  desiredAccess         Access type desired by caller
 * @param[in]  objectAttributes      Pointer to object attributes struct
 * @param[in]  processHandle         Handle to the process who owns the thread               
 * @param[out] clientId              Pointer to struct that will receive thread id 
 *                                   and process id                                   
 * @param[in]  threadContext         Pointer to the initial thread context
 * @param[in]  initialTeb            Pointer to the initial TEB
 * @param[in]  createSuspended       Should the thread be created suspended
 */
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtCreateThread)(PHANDLE threadHandle, ACCESS_MASK desiredAccess,
                                                           POBJECT_ATTRIBUTES objectAttributes, HANDLE processHandle,
                                                           PCLIENT_ID clientId, PCONTEXT threadContext,
                                                           /*PINITIAL_TEB*/ LPVOID initialTeb,
                                                           BOOLEAN createSuspended) _NTAPI_IMPL;
    /*!
 * Decrement suspension counter of a thread, resume execution if suspension counter
 * is 0
 *
 * @param[in]  threadHandle              Thread handle
 * @param[out]  previousSuspendCount     Optional pointer to variable that receives 
 *                                       previous suspension counter
 */
    _NTAPI_DECL NTSTATUS NTAPI _NTAPI_NAME(NtResumeThread)(HANDLE threadHandle, PULONG previousSuspendCount) _NTAPI_IMPL;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !defined(_NTDLL_H_) || defined(NTAPI_PREFIX) */
