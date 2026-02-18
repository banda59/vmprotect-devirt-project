/*
 * Copyright (C) 2006-2024 Intel Corporation.
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

#ifdef PIN_G_OS_INFO_STATE_H
#error duplicate inclusion of os_info_state
#else
#define PIN_G_OS_INFO_STATE_H

#include "win_syscalls.h"

/*! @file
    Declares class representing Windows system-wide information in pin.
*/

/*
    This header is used in three projects: pind.exe, pincrt.dll and pinvm.dll.
    It may only use common definitions visible in the LEVEL_BASE namespace of all projects.
*/

#ifdef NT_VERSION
#undef NT_VERSION
#endif

/*! @ingroup SYSFUNCS
 * POD structure that represents NT kernel version (major and minor) and provides
 * the version comparison methods.
 */
union NT_VERSION
{
    struct
    {
        // there must be ascending order of members: major after minor
        UINT32 m_minor;
        UINT32 m_major;
    } m_s;
    UINT64 m_full;

    /*!
     * POD constructor. 
     */
    VOID Init(UINT32 major, UINT32 minor)
    {
        m_s.m_minor = minor;
        m_s.m_major = major;
    }

    /*!
     * Accessors. 
     */
    UINT32 Major() const { return m_s.m_major; }
    UINT32 Minor() const { return m_s.m_minor; }

    /*!
     * Comparison operators.
     */
    BOOL operator<(const NT_VERSION& right) const { return (m_full < right.m_full); }
    BOOL operator>(const NT_VERSION& right) const { return (m_full > right.m_full); }
    BOOL operator==(const NT_VERSION& right) const { return (m_full == right.m_full); }
    BOOL operator!=(const NT_VERSION& right) const { return (m_full != right.m_full); }
    BOOL operator>=(const NT_VERSION& right) const { return (m_full >= right.m_full); }
    BOOL operator<=(const NT_VERSION& right) const { return (m_full <= right.m_full); }
};

/*! @ingroup SYSFUNCS
 * @return NT_VERSION instance for the specified major and minor versions of NT kernel.
 */
inline NT_VERSION NtVersion(UINT32 major, UINT32 minor)
{
    NT_VERSION version;
    version.Init(major, minor);
    return version;
}

/*! @ingroup SYSFUNCS
 * @return NT_VERSION for XP and Server 2003.
 */
inline NT_VERSION NtVersionXP2003() { return NtVersion(5, 2); }

/*! @ingroup SYSFUNCS
 * @return NT_VERSION for Vista and Server 2008.
 */
inline NT_VERSION NtVersionVista2008() { return NtVersion(6, 0); }

/*! @ingroup SYSFUNCS
 * @return NT_VERSION for Windows 7.
 */
inline NT_VERSION NtVersionWin7() { return NtVersion(6, 1); }

/*! @ingroup SYSFUNCS
 * @return NT_VERSION for Windows 8.
 */
inline NT_VERSION NtVersionWin8() { return NtVersion(6, 2); }

/*! @ingroup SYSFUNCS
 * @return NT_VERSION for Windows 8.1.
 */
inline NT_VERSION NtVersionWin81() { return NtVersion(6, 3); }

/*! @ingroup SYSFUNCS
 * @return NT_VERSION for Windows 10.
 */
inline NT_VERSION NtVersionWin10() { return NtVersion(10, 0); }

/*! @ingroup SYSFUNCS
 * @return TRUE if the specified NT_VERSION is supported by pin.
 */
inline BOOL IsNtVersionSupported(const NT_VERSION& version)
{
    return (version >= NtVersionVista2008());
}

/*! @ingroup SYSFUNCS
 * In Windows/intel64, first four function's arguments are passed in registers. 
 * In addition, the caller must allocate placeholders for these arguments on the stack. 
 * This "shadow stack" area, which is located just after return address, can be used by callee.
 * @return size of the shadow stack area in bytes
 */
inline size_t ShadowStackSize()
{
#if defined(TARGET_IA32)
    return 0;
#elif defined(TARGET_IA32E)
    return 0x20;
#endif
}

/*! @ingroup SYSFUNCS
 * Get NT system call name associated with the specified key of the system call.
 * @param[in] key           system call key
 * @return NT system call name corresponding to the specified key.
 */
inline const CHAR* SyscallName(SYSCALL_KEY key)
{
    switch (key)
    {
#define SYSCALL_DEF(name) case SYSCALL_KEY_##name: \
                              return #name;
    SL_SYSCALL_LIST
#undef SYSCALL_DEF
    default:
// TODO Vladimir: use ASSERT according to target binary.
//        ASSERTX(FALSE);
        return 0;
    }
};

/*! @ingroup SYSFUNCS
 * Major part of build number related to final version of a Windows release.
 * The major part remains constant for any update of the release while minor part grows.
 */
typedef enum
{
    NT_BUILD_NO_WIN10_RS5  = 17763, // Major build number of Windows 10 RS5 release
    NT_BUILD_NO_WIN10_20H1 = 19041  // Major build number of Windows 10 20H1 release
} NT_BUILD_NO;

// Forward declaration.
class OS_INFO;

/*! @ingroup SYSFUNCS
 * OS info state object. 
 */
struct OS_INFO_STATE
{
    // Public constructor leaves the state uninitialized
    OS_INFO_STATE()
        : m_syscallArgsStackOffset(0), m_frequency(0.0), m_isInitialized(FALSE), m_osBuildNumber(0),
            m_kiFastSystemCallRetAddr(NULL)
    {}

    /*!
     * Retrieve the current system information and initialize the OS_INFO_STATE structure.
     * Implemented only in injector.
     *
     * @return TRUE upon success, FALSE upon failure.
     */
    BOOL Init();

    /*!
     * Return syscall numbers table.
     */
    const SYSCALL_NUMBER_T* GetSCTable() const { return m_scnTable; }

    /*!
     * Return OS version
     */
    const NT_VERSION& OsVersion() const { return m_osVersion; }

  private:
      /*!
      * Get OS Id (major + minor version and build number)
      *
      * @param[out]  version      major + minor version pair
      * @param[out]  buildNumber  Build number
      *
      * @return TRUE upon success, FALSE if OS is not supported.
      */
      static BOOL OsId(NT_VERSION& version, UINT32& buildNumber);

  private:
    // Private members of this structure are accessible only to OS_INFO
    friend class OS_INFO;
    // Array of the system call numbers indexed by SYSCALL_KEYs
    SYSCALL_NUMBER_T m_scnTable[SYSCALL_KEY_END];
    // Offset from the top of stack to the array of system call arguments passed on the stack
    size_t m_syscallArgsStackOffset;
    // Frequency of the processor
    FLT64 m_frequency;
    // Boolean specifying whether the state is initialized (TRUE) or not (FALSE)
    BOOL m_isInitialized;
    // OS build number
    UINT32 m_osBuildNumber;
    // OS version info
    NT_VERSION m_osVersion;
    VOID* m_kiFastSystemCallRetAddr;    // Need the address of KiFastSystemCallRetAddr for
                                        // emulation of sysenter.
                                        // First instruction in ring3 to be executed after sysenter is
                                        // the instruction at KiFastSystemCallRetAddr.
                                        // Note that this is a ret, and it is located just after the sysenter
                                        // instruction in ntdll.dll
};

#endif // PIN_G_OS_INFO_STATE_H
