/*
 * Copyright (C) 2025-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifdef PIN_G_INJECTOR_WINDOWS_H
#error duplicate inclusion of injector_windows
#else
#define PIN_G_INJECTOR_WINDOWS_H
/*! @file
 * This file contains injection services for Windows
 */

/*! @ingroup INJECTOR
 * Identifiers of injection type. Indicates which type of injection should be performed
 * by the injector.
 */
enum INJECTION_TYPE
{
    INJECTION_TYPE_INVALID = 0x0,         //!< Invalid injection type
    INJECTION_TYPE_EARLY   = 0x1,         //!< Injection right after kernel32.dll is loaded and
                                          //!< initialized by the primary thread.
    INJECTION_TYPE_LATE = 0x2,            //!< Injection right after the initialization
                                          //!< APC of the primary thread is executed
    INJECTION_TYPE_DEDICATED_THREAD = 0x3 //!< Injection by a dedicated thread created for this purpose
                                          //!< (currently active when pin attaches to a process)
};

/*! @ingroup INJECTOR
 * converter of known injection types
 */
class INJECTION_TYPE_CONVERTER
{
  public:
    /*!
    * Convert INJECTION_TYPE to string
    * @param[in] type 
    * @return name of injection type
    */
    static std::string ConvertToName(INJECTION_TYPE type);

    /*!
    * Convert string to INJECTION_TYPE
    * @param[in] typeName 
    * @return type of INJECTION_TYPE
    */
    static INJECTION_TYPE ConvertToType(const std::string& typeName);
};

/* ================================================================================== */
// INJECTOR_RESULT enumeration and converter
/* ================================================================================== */
/*! @ingroup INJECTOR
 * Identifiers of results returned by WIN_INJECTOR.
 */
enum INJECTOR_RESULT
{
    INJECTOR_SUCCESS              = 0x0,               //!< Success
    INJECTOR_ERR                  = 0x1,               //!< Generic error
    INJECTOR_ERR_NO_ACTIVE_SERVER = 0x2,               //!< The operation requires server, but there
                                                       //!< is no active server
    INJECTOR_ERR_PROCESS_NOT_WINDOWS_SUBSYSTEM  = 0x3, //!< The target process is not Windows subsystem image
    INJECTOR_ERR_PROCESS_TERMINATED             = 0x4, //!< Target process terminated unexpectedly
    INJECTOR_ERR_THREAD_TERMINATED              = 0x5, //!< Target thread terminated unexpectedly
    INJECTOR_ERR_FAILED_TO_CREATE_REMOTE_THREAD = 0x6, //!< Failed to create remote thread (relevant only in
                                                       //!< INJECTION_TYPE_DEDICATED_THREAD)
    INJECTOR_ERR_INVALID_PROCESS_HANDLE = 0x7,         //!< Invalid process handle
    INJECTOR_ERR_INVALID_THREAD_HANDLE  = 0x8,         //!< Invalid thread handle
};

/*! @ingroup INJECTOR
 * converter of known injector results
 */
class INJECTOR_RESULT_CONVERTER
{
  public:
    /*!
    * Convert INJECTOR_RESULT to string
    * @param[in] type 
    * @return name of injector result
    */
    static std::string ConvertToName(INJECTOR_RESULT type);

    /*!
    * Convert string to INJECTOR_RESULT
    * @param[in] typeName 
    * @return name INJECTOR_RESULT
    */
    static INJECTOR_RESULT ConvertToResult(const std::string& typeName);
};

/* ================================================================================== */
// PARENT_BIT_TYPE enumeration and converter
/* ================================================================================== */
/*! @ingroup INJECTOR
 * Identifiers of possible parent types
 */
enum PARENT_BIT_TYPE
{
    PARENT_BIT_TYPE_UNKNOWN = 0,  //!< unknown bit type
    PARENT_BIT_TYPE_32      = 32, //!< 32-bit type
    PARENT_BIT_TYPE_64      = 64  //!< 64-bit type
};

/*! @ingroup INJECTOR
 * converter of known injector results
 */
class PARENT_BIT_TYPE_CONVERTER
{
  public:
    /*!
    * Convert PARENT_BIT_TYPE to string
    * @param[in] type 
    * @return name of parent bit type result
    */
    static std::string ConvertToName(PARENT_BIT_TYPE type);

    /*!
    * Convert string to PARENT_BIT_TYPE
    * @param[in] typeName 
    * @return name PARENT_BIT_TYPE
    */
    static PARENT_BIT_TYPE ConvertToType(const std::string& typeName);
};

/* ================================================================== */
// WIN_INJECTOR abstract class
/* ================================================================== */
/*! @ingroup INJECTOR
 * Abstract interface class. 
 * Each injector implementor should inherit from this class and implement it's functions
 */
class WIN_INJECTOR
{
  public:
    /*!
    * Create WIN_INJECTOR object.
    *
    * @param[in]  processId         Injectee's process ID.
    * @param[in]  threadId          Injectee's thread ID.
    *                                It is legal to pass 0 for the thread id. In this case
    *                                the injection will take place in a newly created Pin's dedicated
    *                                thread.
    * @param[in]  injectionType     Injection type. If the user asks for INJECTION_TYPE_EARLY
    *                                and it's not applicable, the injector will try to inject
    *                                with INJECTION_TYPE_LATE.
    *                                If threadId equals 0, injectionType MUST be 
    *                                INJECTION_TYPE_DEDICATED_THREAD
    * @param[out] pInjectorRes      Injector result. Extended error information if the function fails 
    *                                (returns NULL)
    *
    * @return   WIN_INJECTOR pointer upon success, NULL upon failure
    */
    static WIN_INJECTOR* Create(UINT32 processId, UINT32 threadId, INJECTION_TYPE injectionType,
                                INJECTOR_RESULT* pInjectorRes = NULL);

    /*!
    * Get application's command line 
    *
    * @param[out]  appCommandLine application's command line
    *
    * @return  true upon success, false upon failure
    */
    virtual bool GetApplicationCommandLine(std::string* appCommandLine) = 0;

    /*!
    * Inject Pin into a newly created process:
    * - Relevant onfy for indirect injector.
    *
    * @param[in]  argc           Number of command line arguments (Pin & app) 
    * @param[in]  argv           Command line arguments (Pin & app) 
    * @param[in]  debug          Does the caller want to debug injectee? If debug is true, the function
    *                             will issue debug message and wait for debugger attach confirmation.
    *                             The message will appear only if there is an available console.
    *                            
    * @return  true upon success, false upon failure
    */
    virtual bool Inject([[maybe_unused]] INT argc, [[maybe_unused]] const CHAR** argv, [[maybe_unused]] const CHAR* const* envp,
                        [[maybe_unused]] bool debug = false)
    {
        return false;
    }

    /*!
    * Detach the injector from injectee process.
    * Resume the process if necessary.
    *                            
    * @return  true upon success, false upon failure
    */
    virtual bool Detach() { return true; }

    /*!
    * Destructor.
    */
    virtual ~WIN_INJECTOR() {};
};

#endif // PIN_G_INJECTOR_WINDOWS_H
