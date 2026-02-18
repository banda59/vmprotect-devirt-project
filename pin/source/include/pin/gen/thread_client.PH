/*
 * Copyright (C) 2010-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifdef PIN_G_THREAD_CLIENT_PH
#error duplicate inclusion of thread_client
#else
#define PIN_G_THREAD_CLIENT_PH
/*! @file
 *
 * Threading API for clients
 */
/*! @ingroup THREADS
 *  Get system identifier of the current thread.
 *
 *  @note The System thread id is not the underlying OS tid.
 *        To get the underlying OS tid please use @ref PIN_GetNativeTid().
 * 
 *  @return system ID of the current thread.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern OS_THREAD_ID PIN_GetTid();

/*! @ingroup THREADS
 *  Get native OS identifier of the current thread.
 *  @return native OS ID of the current thread.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern NATIVE_TID PIN_GetNativeTid();

/*! @ingroup THREADS
 *  Get native OS identifier from a system thread id.
 *
 *  @param[in] sysThreadId The system thread id as returned from APIs like:
 *                         @ref PIN_GetTid
 *                         @ref PIN_GetParentTid
 *
 *  @return native OS ID of for the given system thread id.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern NATIVE_TID PIN_GetNativeTidFromSysTid(OS_THREAD_ID sysThreadId);

/*! @ingroup THREADS
 *  Get native OS identifier from Pin's internal thread id.
 *
 *  @param[in] tid  The pin thread id as returned from:
 *                         @ref PIN_ThreadId
 *
 *  @return native OS ID for the given thread id.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern NATIVE_TID PIN_GetNativeTidFromThreadId(THREADID tid);

/*! @ingroup THREADS
 *  Get Pin's internal identifier of the current thread in Pin.
 *  @return ID of the current thread in Pin or INVALID_THREADID upon failure.
 *
 * @par Availability:
 * \b Mode:  JIT\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern THREADID PIN_ThreadId();

/*! @ingroup THREADS
 *  Get unique identifier of the current thread in Pin.
 *  @return Unique ID of the current thread in Pin or INVALID_PIN_THREAD_UID upon failure.
 *          
 * @note Tool writers should not try and use the returned ID to wait for a thread using @ref PIN_WaitForThreadTermination.
 *       Only the unique id obtained from a call to @ref PIN_SpawnInternalThread can be used for waiting on a thread
 *       using @ref PIN_WaitForThreadTermination.
 *       if the caller passed nullptr to pThreadUid when creating the thread, then the value returned by this call
 *       cannot be used in @ref PIN_WaitForThreadTermination.
 *       For application threads or threads created using std::thread()/pthread_create(), the value returned by 
 *       this function cannot be safely used for any purpose.
 *       This function has limited use. It is deprecated and will be removed in future versions of Pin.
 *
 * @par Availability:
 * \b Mode:  JIT\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
#if (PIN_DEPRECATED_WARNINGS != 0)
[[deprecated("The ID returned by this function cannot be safely used outside of the calling thread. \
              The caller cannot assume it's valid after thread termination.")]]
#endif
extern PIN_DEPRECATED_API PIN_THREAD_UID PIN_ThreadUid();

/*! @ingroup THREADS
 *  Get system identifier of the parent thread, if known.
 *  @return  system ID of the parent thread or INVALID_OS_THREAD_ID if the
 *           parent thread is unknown.
 *           For internal threads this function always returns INVALID_OS_THREAD_ID.
 *           On Windows the result is always INVALID_OS_THREAD_ID, since there is,
 *           in general, no well defined parent child relationship between threads.
 *
 * @par Availability:
 * \b Mode:  JIT\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern OS_THREAD_ID PIN_GetParentTid();

/*! @ingroup THREADS
 * Delay execution of the current thread for the specified time interval.
 * @param[in]  milliseconds     time interval, in milliseconds.
 * 
 * @note As of Pin 4.0 new implementations should use either std::this_thread::sleep_for()
 *       or one of the POSIX sleep functions sleep(), usleep(), nanosleep() or clock_nanosleep().
 *       This function is deprecated and will be removed in future versions of Pin.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
#if (PIN_DEPRECATED_WARNINGS != 0)
[[deprecated("New implementations should use should use std::this_thread::sleep_for() or one of the POSIX sleep functions")]]
#endif
extern PIN_DEPRECATED_API VOID
PIN_Sleep(UINT32 milliseconds);

/*! @ingroup THREADS
 * Yield the processor to another thread.
 *
 * @note As of Pin 4.0 new implementations should use either std::this_thread::yield() or sched_yield(). 
 *       This function is deprecated and will be removed in future versions of Pin.
 * 
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
#if (PIN_DEPRECATED_WARNINGS != 0)
[[deprecated("New implementations should use std::this_thread::yield() or sched_yield()")]]
#endif
extern PIN_DEPRECATED_API VOID
PIN_Yield();

/*! @ingroup THREADS
 * Create a new tool internal thread in the current process.
 *
 * It is safe to create internal threads anywhere in the tool's code, including from
 * instrumentation callbacks, analysis callbacks or from from existing internal threads.
 * 
 * In order to ensure graceful termination of internal threads on the application's exit,
 * the tool can use the following recommended method:
 *      - The tool uses the @ref PIN_AddPrepareForFiniFunction() function to register a
 *        @ref PREPARE_FOR_FINI_CALLBACK callback. When the registered function is called
 *        in an "unlocked" thread, the tool requests each other internal thread to exit
 *        and waits until the @ref PIN_WaitForThreadTermination() function returns.
 *      @note Pin doesn't wait for internal threads termination after the callbacks.
 *
 * Many of Pin's APIs, that are primarily intended for application threads, are also available in
 * internal threads. Look at the API's description ( \b Availability paragraph) or the description
 * of the corresponding group of APIs to check whether a specific API is available in internal threads.\n
 *
 * @param[in]  pThreadFunc  main (starting) function of the thread
 * @param[in]  arg          argument of the main thread function
 * @param[in]  stackSize    size of the thread's stack, in bytes. The function rounds
 *                          this value up to the page size. If this parameter is zero,
 *                          DEFAULT_THREAD_STACK_SIZE bytes will be allocated for the stack.
 * @param[out] pThreadUid   pointer to a variable that receives the unique identifier of the
 *                          new thread in Pin. This identifier can be used in the
 *                          @ref PIN_WaitForThreadTermination() function to join the thread.
 *                          If the caller specifies NULL for this parameter, the unique thread ID
 *                          is not returned and the creatred thread will not be joinable using 
 *                          @ref PIN_WaitForThreadTermination.
 *
 * @return  Pin thread ID of the new thread in Pin or INVALID_THREADID if the thread creation failed.
 *
 * @note Starting with Pin 4.0, internal threads may also be created using \a pthread_create() and \a std::thread().
 *       \a clone()/clone3() on Linux or \a CreateThread() on Windows should not be used.
 * @par
 *       Pin makes an effort to hide internal threads from the application so, usually, a tool's
 *       threads do not interfere with the application. However, the complete transparency of
 *       internal threads is not guaranteed, so tools should only use them when their instrumentation
 *       tasks cannot be done (effectively) by analysis routines within application threads.
 *       For example, a need to execute Windows services (Win32 APIs) may be a reason for creating
 *       a private thread in the tool. All Win32 APIs that do not modify the application's resources
 *       can be freely used in internal threads. In application threads, on the contrary, using
 *       Win32 APIs in analysis routines and Pin callbacks is not supported due to possible
 *       reentrancy and isolation problems.
 * @par
 *       Internal threads remain blocked inside Pin until @ref PIN_StartProgram() is called and Pin
 *       completes some initialization. On Linux, internal threads start running \a pThreadFunc
 *       before Pin executes the first application instruction. On Windows all threads, including
 *       Pin internal threads, start executing from the system runtime before they execute the
 *       \a pThreadFunc function. However, the system runtime blocks threads until the application
 *       has finished initializing its DLL's (i.e. until the application releases the internal
 *       "loader lock"). As a result, Pin internal threads on Windows do not execute \a pThreadFunc
 *       until after the application finishes executing the DLL initialization code.
 *       On Linux for all architectures and on Windows for 64 bit applications, it is possible to start
 *       a thread before @ref PIN_StartProgram by using \a pthread_create() or \a std::thread() instead of 
 *       @ref PIN_SpawnInternalThread(). See @ref PIN_InitializeInternalThread and @ref PIN_WaitForProgramStart().
 *       @note Trying to create a thread using \a pthread_create or \a std::thread  in Windows 32-bit applications
 *       running on Windows 64-bit OS (WOW64) before @ref PIN_StartProgram might result in a deadlock.
 *       
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern THREADID PIN_SpawnInternalThread(ROOT_THREAD_FUNC* pThreadFunc, VOID* arg, size_t stackSize, PIN_THREAD_UID* pThreadUid);

/*! @ingroup THREADS
 * Terminate the current thread.
 *
 * This function is intended for threads created by the tool (see @ref PIN_SpawnInternalThread())
 * and is not normally used for threads created by the application, since application threads
 * exit automatically when Pin executes a thread termination system call on their behalf.
 *
 * If this call is made on an application thread, Pin will make any callbacks registered for
 * thread exit before the thread is terminated.
 *
 * @param[in] exitCode  exit code of the thread to be returned by the
 *                      PIN_WaitForThreadTermination() function.
 * @return  the function never returns.
 *
 * @note The vm lock is obtained during the call of this API.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern VOID PIN_ExitThread(INT32 exitCode);

/*! @ingroup THREADS
 * Check to see if the current thread is created by the application or it is
 * an internal thread spawned by the tool or Pin itself (see @ref PIN_SpawnInternalThread()).
 *
 * @return  TRUE, if this function is called in a thread created by the application;
 *          FALSE, if this function is called in an internal thread spawned by the tool or Pin.
 *
 * @par Availability:
 * \b Mode:  JIT\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern BOOL PIN_IsApplicationThread();

/*! @ingroup THREADS
 * Delay the current thread until the specified thread is terminated or the time-out
 * interval elapses.
 *
 * To avoid deadlocks, the caller should not hold any lock that the target thread may try
 * to acquire. For example, this function can be safely used in the @ref PREPARE_FOR_FINI_CALLBACK
 * callback if it is registered by the @ref PIN_AddPrepareForFiniFunction(). However, it is
 * not recommended to use this function in other Pin callbacks if the target thread is
 * an application thread or an internal thread that uses Pin APIs. This is because most of Pin
 * APIs and callbacks are serialized by the same internal lock.\n
 *
 * * This function can not be used to wait for the termination of the calling thread.
 * * This function can not be used to wait for an application thread.
 * * This function can not be used to wait on threads created using \c pthread_create or \c std::thread.
 *   Use \c pthread_join and \c std::thread::join respectively.
 * * This function can not be called twice on the same unique id.
 *
 * @param[in]  threadUid        unique identifier of the thread to be waited for termination,
 *                              provided by @ref PIN_SpawnInternalThread() or @ref PIN_ThreadUid().
 * @param[in]  milliseconds     time-out interval, in milliseconds. If this parameter
 *                              is zero, the function tests the thread's state and
 *                              returns immediately. If this parameter is PIN_INFINITE_TIMEOUT,
 *                              the time-out interval never elapses.
 * @param[out] pExitCode        optional pointer to a variable that receives exit code of
 *                              the thread. If this pointer is NULL or the thread has not
 *                              terminated, the exit code is not returned.
 * @return  TRUE  - the thread has terminated,
 *          FALSE - the specified time-out interval elapsed
 *                  or threadUid is not valid or corresponds to current thread
 *                  or specified thread is not yet started when application shutdown begins.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern BOOL PIN_WaitForThreadTermination(const PIN_THREAD_UID& threadUid, UINT32 milliseconds, INT32* pExitCode);

/*! @ingroup THREADS
 * Block the calling thread until Pin finishes it's internal initialization after
 * a call to PIN_StartProgram or PIN_StartProgramProbed.
 *
 * This function is intended to be called from a thread created using pthread_create or std::thread to mimic
 * the behavior of threads created using PIN_SpawnInternalThread, that waits for program start.
 * 
 * To avoid deadlocks this function must be called from a thread different than the main tool thread.
 * It's possible to call this function from any other thread in the tool, even from an application thread.
 * However calling this function from a thread created using PIN_SpawnInternalThread or an application thread,
 * will return immediately with a return value of true.
 *
 * @return  TRUE  - the program has started and the thread can continue,
 *          FALSE - shutdown was initiated before the program started. The calling
 *                  thread should exit.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern BOOL PIN_WaitForProgramStart();

/**
 * @ingroup THREADS
 * @brief Perform initialization required for a thread created using std::thread/pthread_create
 *        to work properly with pin API. Among other things this function allocates Pin fast TLS
 *        for the thread and blocks asynchronous signals for the thread.
 * 
 * Pin 4.x allows a pintool writers to use std::thread and pthreads to create and manage threads.
 * However using the standard API circumvents initialization done by @ref PIN_SpawInternalThread.
 * To be able to properly and safely use PIN API from the new thread one should call
 * PIN_InitializeInternalThread at the begining of the thread function.
 * To properly release resources allocated by this function, the thread should exit using @ref PIN_ExitThread.
 * It is reccomended that the thread function/procedure that is used for std::thread/pthreead_create has the
 * following structure:
 * @code 
 *    {
 *     // Thread proc body
 *     PIN_InitializeInternalThread(); // PIN specific per thread initialization
 * 
 *     // Optional wait for program start
 *     // PIN_WaitForProgramStart();
 *
 *     ...// Thread logic
 * 
 *     PIN_ExitThread(exitCode); // Exit thread using PIN to release resources
 *    }
 * @endcode
 * 
 * @return VOID 
 * 
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows\n
 * \b CPU:   All\n
 */
extern VOID PIN_InitializeInternalThread();
#endif // PIN_G_THREAD_CLIENT_PH
