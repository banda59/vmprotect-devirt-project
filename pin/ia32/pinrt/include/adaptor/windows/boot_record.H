/*
 * Copyright (C) 2024-2024 Intel Corporation.
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

#ifdef PIN_G_BOOT_RECORD_H
#error duplicate inclusion of boot_record
#else
#define PIN_G_BOOT_RECORD_H
/*! @file
 * This file contains boot record definition for Windows
 */

struct SYNCH_PAIR
{
    WINDOWS::HANDLE startEvent;
    WINDOWS::HANDLE continueEvent;
};

/* ============================================================================= */
// Data structures that are used in injection (copied from injector to injectee)
/* ============================================================================= */
/*! @ingroup INJECTOR
 * Structure that keeps all necessary common and per-process data
 * in order to load and start Pin root dll and Pin VM DLL in application process.
 * The structure is built by the injector process pind.exe and copied by the injector into
 * statically allocated instance of the structure in Pin root DLL loaded into the application process.
 * The location-dependent data in the structure itself as well as all referenced data
 * are updated to target loation when transferred to the application process.
 */
struct PIN_BOOT_RECORD
{
    // Pin root DLL information
    VOID* pinDllAddr;                //!< Actual load address of Pin root DLL in target process.
                                     //!< Initially contains address of BootPinDllCaller function in statically
                                     //!< initialized instance of the structure in Pin root DLL prior to injection.
                                     //!< ATTENTION!!! Should be the first member of the structure!
    const CHAR* pinDllName;          //!< Base name of Pin root DLL file
    CHAR* pinDllPath;                //!< Full path of Pin root DLL file
    UINT32 pinDllSize;               //!< Size of loaded Pin root DLL
    WINDOWS::ULONG pinDllIatProtect; //!< Memory protection attributes of IAT in Pin root DLL

    // Pin VM DLL information
    const CHAR* pinVmDllName;        //!< Name of Pin VM DLL file in format compliant with dlopen() specification.
    const CHAR* pinVmMainProcName;   //!< Name of the main procedure in Pin VM DLL

    // NTDLL.DLL information
    VOID* nt2Addr;                   //!< Actual load address of NTDLL.DLL copy in target process
    UINT32 ntSize;                   //!< Size of loaded NTDLL.DLL in virtual memory
    WINDOWS::DWORD ntTimeStamp;      //!< TimeDate stamp of this NTDLL
    WINDOWS::DWORD ntCheckSum;       //!< CheckSum of this NTDLL

    // KERNEL32.DLL information
    UINT32 k32Size;                  //!< Size of KERNEL32.DLL in memory of injector process
    WINDOWS::DWORD k32TimeStamp;     //!< TimeDate stamp of this KERNEL32
    WINDOWS::DWORD k32CheckSum;      //!< CheckSum of this KERNEL32

    // OS information
    OS_INFO_STATE osInfoState;       //!< Cross-process representation of the OS_INFO_STATE object

    ADDRINT appIP;                   //!< Original instruction pointer from starting context of the application
    ADDRINT debuggerStartAddress;    //!< Debugging support is allowed once code at this address is executed.
                                     //!< Possible values:
                                     //!<   0 - code address is not relevant; debugging support is allowed instantly;
                                     //!<   !ADDRINT(0) - code address is needed but injector failed to get it;
                                     //!<   any other value - valid code address retrieved by injector.
    SYNCH_PAIR suspendRequest;       //!< Suspend request
    const size_t* startupInfo;       //!< Pointer to process startup info in Linux format

    // See detailed explanation about layout of processInfoBlock of startup_info in lsc/support/linux/processinfo.cpp
    int argc() const noexcept { return (int)startupInfo[0]; }
    const char* * argv() const noexcept { return (const char* *)(startupInfo + 1); }
    const char* * envp() const noexcept { return argv() + argc() + 1; } // Including extra nullptr element after argv array.
};

#endif // PIN_G_BOOT_RECORD_H
