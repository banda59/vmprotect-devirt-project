/*
 * Copyright (C) 2015-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef PINRT_ADAPTOR_SYNC_PH_
#define PINRT_ADAPTOR_SYNC_PH_

/*!
 * @file
 * Contain Synchronization related runtime API (additional over standard runtime)
 */

//
// Mutex
//

/*!
 * @defgroup OS_APIS_MUTEX Mutex
 * @brief Implementation of mutex lock.
 */

#include "types.h"

typedef ADDRINT OS_SPINLOCK_TYPE;

typedef enum _OS_APIS_MUTEX_KIND
{
    OS_MUTEX_DEPTH_SIMPLE = 0, //!< This lock can only be acquired once, no matter if the same thread tried to acquire it twice
    OS_MUTEX_DEPTH_RECURSIVE   //!< Recursive lock that can be acquired recursively by the same thread.
} OS_MUTEX_DEPTH;

/*! @ingroup OS_APIS_MUTEX
 * This type holds a representation of a mutex.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
typedef struct _OS_APIS_MUTEX_TYPE
{
    OS_MUTEX_DEPTH kind;
    OS_SPINLOCK_TYPE spinlock;
    OS_EVENT event; ///< Futex word on Linux, futex word or Event handle on Windows depending on
                    ///< definition of MUTEX_USE_WINDOWS_EVENTS
    INT32 ready;
    UINT32 num_waiters;
    UINT32 depth;
#ifndef TARGET_WINDOWS
    UINT32 spinlock_fork_count;
#endif
} OS_MUTEX_TYPE_IMPL;

typedef PRE_ALIGNTO(CPU_MEMORY_CACHELINE_SIZE) union
{
    OS_MUTEX_TYPE_IMPL impl;
    char reserved[2 * CPU_MEMORY_CACHELINE_SIZE];
} POST_ALIGNTO(CPU_MEMORY_CACHELINE_SIZE) OS_MUTEX_TYPE;

/*! @ingroup OS_APIS_MUTEX
 * Initialize a mutex.
 * A mutex must be initialized before being used.
 * Use this function to initialize the mutex or use one of the static initializers.
 *
 * @param[in]  lock               The mutex to initialize.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
void OS_MutexInit(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Initialize a recursive mutex.
 * A mutex must be initialized before being used.
 * Use this function to initialize a recursive mutex or use one of the static initializers.
 *
 * @param[in]  lock               The mutex to initialize.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
void OS_MutexRecursiveInit(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Destroys a mutex after it is no longer in use.
 *
 * @note The behavior of a mutex after it was destroyed is undefined.
 * It is the responsibility of the user to verify that no other thread
 * is using the mutex when it comes to destroy it.
 *
 * @param[in]  lock               The mutex to destroy.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
void OS_MutexDestroy(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Aquire a mutex, blocks until the mutex becomes available (according to the mutex's semantics).
 *
 * @param[in]  lock               The mutex to acquire.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
void OS_MutexLock(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Aquire a mutex, blocks until the mutex becomes available (according to the mutex's semantics).
 * This function is similar to OS_MutexLock() except that it accept as an argument the thread ID
 * of the thread that want to acquire the lock (which is usually the current thread).
 *
 * @param[in]  lock               The mutex to acquire.
 * @param[in]  tid                The thread ID of the thread that wants to acquire the mutex.
 *                                This argument can be INVALID_NATIVE_TID if the thread ID is
 *                                not known (e.g. in a mutex of type OS_MUTEX_DEPTH_SIMPLE).
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
void OS_MutexLockTid(volatile OS_MUTEX_TYPE* lock, NATIVE_TID myTid);

/*! @ingroup OS_APIS_MUTEX
 * Tries to aquire a mutex:\n
 * - If the mutex is available, acquire it and return true.\n
 * - Otherwise, return false.
 *
 * @param[in]  lock               The mutex to acquire.
 *
 * @retval     TRUE               If the mutex was acquired.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
BOOL_T OS_MutexTryLock(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Tries to aquire a mutex:\n
 * - If the mutex is available, acquire it and return true.\n
 * - Otherwise, return false.
 * This function is similar to OS_MutexTryLock() except that it accept as an argument the thread ID
 * of the thread that want to acquire the lock (which is usually the current thread).
 *
 * @param[in]  lock               The mutex to acquire.
 * @param[in]  tid                The thread ID of the thread that wants to acquire the mutex.
 *                                This argument can be INVALID_NATIVE_TID if the thread ID is
 *                                not known (e.g. in a mutex of type OS_MUTEX_DEPTH_SIMPLE).
 *
 * @retval     TRUE               If the mutex was acquired.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
BOOL_T OS_MutexTryLockTid(volatile OS_MUTEX_TYPE* lock0, NATIVE_TID myTid);

/*! @ingroup OS_APIS_MUTEX
 * Checks whether a mutex state is locked.\n
 * Doesn't affect the mutex state and doesn't block.
 *
 * @param[in]  lock               The mutex to check.
 *
 * @retval     TRUE               If the mutex is locked.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
BOOL_T OS_MutexIsLocked(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Aquire a mutex, blocks until the mutex becomes available (according to the mutex's semantics).
 * or 'timeoutMillis' milli seconds passed.
 * When 'timeoutMillis' is zero, this function is identical to @ref OS_MutexTryLock().
 *
 * @param[in]  lock               The mutex to acquire.
 * @param[in]  timeoutMillis      The timeout to block.
 *
 * @retval     TRUE               If the mutex is locked.
 *             FALSE              If the timeout was expired and the mutex can't be acquired during that time.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
BOOL_T OS_MutexTimedLock(volatile OS_MUTEX_TYPE* lock, UINT32 timeoutMillis);

/*! @ingroup OS_APIS_MUTEX
 * Aquire a mutex, blocks until the mutex becomes available (according to the mutex's semantics).
 * or 'timeoutMillis' milli seconds passed.
 * When 'timeoutMillis' is zero, this function is identical to @ref OS_MutexTryLock().
 * This function is similar to OS_MutexTimedLock() except that it accept as an argument the thread ID
 * of the thread that want to acquire the lock (which is usually the current thread).
 *
 * @param[in]  lock               The mutex to acquire.
 * @param[in]  timeoutMillis      The timeout to block.
 * @param[in]  tid                The thread ID of the thread that wants to acquire the mutex.
 *                                This argument can be INVALID_NATIVE_TID if the thread ID is
 *                                not known (e.g. in a mutex of type OS_MUTEX_DEPTH_SIMPLE).
 *
 * @retval     TRUE               If the mutex is locked.
 *             FALSE              If the timeout was expired and the mutex can't be acquired during that time.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
BOOL_T OS_MutexTimedLockTid(volatile OS_MUTEX_TYPE* lock0, NATIVE_TID myTid, UINT32 timeoutMillis);

/*! @ingroup OS_APIS_MUTEX
 * Queries the owner of a recursive mutex.
 *
 * @param[in]  lock               The mutex to query.
 *
 * @retval     NATIVE_TID         The owner of the mutex or INVALID_NATIVE_TID is the mutex is not locked.
 *
 * @note The return value of this function is undefined for non-recursive (simple) mutex.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
NATIVE_TID OS_MutexGetOwner(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Queries the recursion of a recursive mutex. I.e. the number of times that the unlock functions needs to be
 * called before the mutex can be acquired by other thread.
 *
 * @param[in]  lock               The mutex to query.
 *
 * @retval     UINT32             The recursion level of the mutex.
 *
 * @note For non-recursive (simple) mutex, the return value of this function is 1 if the mutex is lock,
 *       or 0 if the mutex is unlocked.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
UINT32 OS_MutexGetRecursionLevel(volatile OS_MUTEX_TYPE* lock);

/*! @ingroup OS_APIS_MUTEX
 * Releases a mutex.
 *
 * @param[in]  lock               The mutex to release.
 *
 * @retval     TRUE               If the mutex was locked and as a result of this call was unlocked.
 *
 * @par Availability:
 *   - @b O/S:   Windows, Linux
 *   - @b CPU:   All
 */
BOOL_T OS_MutexUnlock(volatile OS_MUTEX_TYPE* lock);

//
// Read Write Lockx
//

/*!
 * @defgroup OS_APIS_RW_LOCK Readers writers lock
 * @brief Implementation of readers writers lock.
 */
typedef enum
{
    OS_APIS_RW_LOCK_OWNER_TYPE_NONE,
    OS_APIS_RW_LOCK_OWNER_TYPE_WRITER,
    OS_APIS_RW_LOCK_OWNER_TYPE_READER
} OS_APIS_RW_LOCK_OWNER_TYPE;

/*!
 * This is an opaque struct for readers/writers lock.
 * This struct should be used with the functions declared in this header.
 */
typedef struct
{
    OS_MUTEX_TYPE_IMPL lock;
    OS_APIS_RW_LOCK_OWNER_TYPE owner_type;
    UINT32 readers;
    OS_EVENT no_readers_event; ///< futex word on Linux, Event handle on Windows
    INT32 ready;
    UINT32 waiters_count;
#ifndef TARGET_WINDOWS
    UINT32 spinlock_fork_count;
#endif
} OS_APIS_RW_LOCK_IMPL_T;

typedef PRE_ALIGNTO(CPU_MEMORY_CACHELINE_SIZE) union
{
    OS_APIS_RW_LOCK_IMPL_T impl;
    char reserved[2 * CPU_MEMORY_CACHELINE_SIZE];
} POST_ALIGNTO(CPU_MEMORY_CACHELINE_SIZE) OS_APIS_RW_LOCK_T;

/*! @ingroup OS_APIS_RW_LOCK
 * Initializes a reader-writer lock.
 *
 * @param[in]  lock         The lock to initialize
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
void OS_RWLockInitialize(volatile OS_APIS_RW_LOCK_T* l);

/*! @ingroup OS_APIS_RW_LOCK
 * Destroy a reader-writer lock, freeing all exhausted resources associated with the lock.
 *
 * @param[in]  lock         The lock to destroy
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
void OS_RWLockDestroy(volatile OS_APIS_RW_LOCK_T* l);

/*! @ingroup OS_APIS_RW_LOCK
 * Acquires the lock for writer.
 * Blocks until the writer lock is acquired.
 *
 * @param[in]  lock         The lock to acquire
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
void OS_RWLockAcquireWrite(volatile OS_APIS_RW_LOCK_T* lock);

/*! @ingroup OS_APIS_RW_LOCK
 * Releases the lock for writer.
 *
 * @param[in]  lock         The lock to release
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
void OS_RWLockReleaseWrite(volatile OS_APIS_RW_LOCK_T* lock);

/*! @ingroup OS_APIS_RW_LOCK
 * Acquires the lock for reader.
 * Blocks until the reader lock is acquired.
 *
 * @param[in]  lock         The lock to acquire
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
void OS_RWLockAcquireRead(volatile OS_APIS_RW_LOCK_T* lock);

/*! @ingroup OS_APIS_RW_LOCK
 * Releases the lock for reader.
 *
 * @param[in]  lock         The lock to release
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
void OS_RWLockReleaseRead(volatile OS_APIS_RW_LOCK_T* lock);

/*! @ingroup OS_APIS_RW_LOCK
 * Releases the lock that was acquired.
 * The lock kind that was acquired (whether its read or write) is determined by this function.
 *
 * @param[in]  lock         The lock to release
 *
 * @return  TRUE if the lock was taken (for either read or write) and as a result of this call is unlocked, FALSE otherwise.
 *            If the reader lock was released, and a waiting writer was woken up and acquired the lock, the function will
 *            return TRUE.
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
BOOL_T OS_RWLockRelease(volatile OS_APIS_RW_LOCK_T* l);

/*! @ingroup OS_APIS_RW_LOCK
 * Tries to Acquire the lock for writer.
 * This function returns immediately if the lock can't be acquired.
 *
 * @param[in]  lock         The lock to acquire
 *
 * @return     TRUE         If the writer lock was acquired.
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
BOOL_T OS_RWLockTryAcquireWrite(volatile OS_APIS_RW_LOCK_T* l);

/*! @ingroup OS_APIS_RW_LOCK
 * Tries to Acquire the lock for reader.
 * This function returns immediately if the lock can't be acquired.
 *
 * @param[in]  lock         The lock to acquire
 *
 * @return     TRUE         If the reader lock was acquired.
 *
 * @par Availability:
 *   @b O/S:   Windows, Linux\n
 *   @b CPU:   All\n
 */
BOOL_T OS_RWLockTryAcquireRead(volatile OS_APIS_RW_LOCK_T* l);

#endif // PINRT_ADAPTOR_SYNC_PH_
