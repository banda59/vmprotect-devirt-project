/*
 * Copyright (C) 2023-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef PINRT_ADAPTOR_UTILS_PH_
#define PINRT_ADAPTOR_UTILS_PH_

/*!
 * @file
 * Contain convenient PINOS utility wrappers 
 */

#include <pinos.h>
#include <stdarg.h>
#include <syscall.h>

#include <pinrtassert.h>

#if defined(TARGET_LINUX)
#define MAX_SYSCALL_ARGS 6
#elif defined(TARGET_WINDOWS)
#define MAX_SYSCALL_ARGS 15
#else
#error "Unsupported OS"
#endif

#if DOXYGEN || defined(__cplusplus)

/** @ingroup PINRT_UTILS
 * 
 * @brief Call a native syscall bypassing isolation mechanisms using the PINOS SYS_native_syscall_unsafe 
 * generic system call.
 *
 * @param syscall_id    Native Syscall ID (Not PINOS Syscall ID !!!!!!!!! - Use __NR_xxx macros rather than SYS_xxx macros)
 * @param ...           Native system call arguments
 *
 * @return  The return value of ths PINOS syscall.
 *          Return values follow the linux convention. Values in the range [-4095,-1] Are errors.
 *
 */
template< class... Args > inline t_syscall_ret OS_Syscall_unsafe(t_syscall_id syscall_id, Args... args)
{
    static_assert(sizeof...(Args) <= MAX_SYSCALL_ARGS, "Invalid number of arguments for native syscall");
    t_syscall_arg nativeArgs[] {(t_syscall_arg)args...};
    t_syscall_arg unsafeArgs[] {t_syscall_arg(syscall_id),      // native syscall id
                                t_syscall_arg(0),               // flags
                                t_syscall_arg(sizeof...(Args)), // native arg count
                                t_syscall_arg(&nativeArgs[0])};
    return OS_Syscall(SYS_native_syscall_unsafe, SYSCALL_ARG_COUNT(unsafeArgs), unsafeArgs);
}

/** @ingroup PINRT_UTILS
 * 
 * @brief Call a native syscall while trying to to maintain isolation mechanisms using PINOS SYS_native_syscall_safe 
 * generic system call.
 *
 * @param opType        PINOS_SOP_NOP_SUCCESS - return SYSRET(SUCCESS) without doing anything
 *                      PINOS_SOP_NOP_FAILURE - return SYSRET(EPERM) without doing anything
 *                      PINOS_SOP_DO_UNSAFE   - Execute the specified system call bypassing isolation mechanisms using homemade
 *                                              SYS_native_syscall_unsafe system call (executed locally)
 *                                              Return system call return code. This is the same as calling OS_Syscall_unsafe
 *                      PINOS_SOP_ISOLATION   - Execute the specified system call trying to maintain isolation mechanisms using homemade
 *                                              SYS_native_syscall_safe system call (executed locally)
 *                                              Return system call return code.
 * @param syscall_id    Native Syscall ID (Not PINOS Syscall ID !!!!!!!!! - Use __NR_xxx macros rather than SYS_xxx macros)
 * @param ...           Native system call arguments
 *
 * @return  The return value of ths PINOS syscall.
 *          Return values follow the linux convention. Values in the range [-4095,-1] Are errors.
 *
 */
template< class... Args >
inline t_syscall_ret OS_Syscall_safe(enum PINOS_SYSCALL_OP opType, t_syscall_id syscall_id, Args... args)
{
    static_assert(sizeof...(Args) <= MAX_SYSCALL_ARGS, "Invalid number of arguments for native syscall");
    t_syscall_arg nativeArgs[] {(t_syscall_arg)args...};
    t_syscall_arg safeArgs[] {t_syscall_arg(opType),          // PINOS_SYSCALL_OP
                              t_syscall_arg(syscall_id),      // native syscall id
                              t_syscall_arg(0),               // flags
                              t_syscall_arg(sizeof...(Args)), // native arg count
                              t_syscall_arg(&nativeArgs[0])};
    return OS_Syscall(SYS_native_syscall_safe, SYSCALL_ARG_COUNT(safeArgs), safeArgs);
}

#else // #if defined(__cplusplus)

/**
 * Call a native syscall bypassing isolation mechanisms using the PINOS SYS_native_syscall_unsafe generic system call.
 *
 * @param syscall_id    Native Syscall ID (Not PINOS Syscall ID !!!!!!!!! - Use __NR_xxx macros rather than SYS_xxx macros)
 * @param arg_count     The number of native arguments (This is required for C)
 * @param ...           Native system call arguments - for this variadic function to work correctly all native arguments should
 *                      be casted to t_syscall_arg
 *
 * @return  The return value of ths PINOS syscall.
 *          Return values follow the linux convention. Values in the range [-4095,-1] Are errors.
 *
 */
static inline t_syscall_ret PINOSCALL OS_Syscall_unsafe_n(t_syscall_id syscall_id, uint32_t arg_count, ...)
{
    t_syscall_arg _args[MAX_SYSCALL_ARGS] = {0};
    va_list ap;

    assert(arg_count < MAX_SYSCALL_ARGS);

    va_start(ap, arg_count);
    for (unsigned i = 0; i < arg_count; i++)
    {
        _args[i] = va_arg(ap, t_syscall_arg);
    }
    va_end(ap);

    t_syscall_arg unsafeArgs[] = {(t_syscall_arg)(syscall_id), (t_syscall_arg)(0), (t_syscall_arg)(arg_count),
                                  (t_syscall_arg)(_args)};
    return OS_Syscall(SYS_native_syscall_unsafe, SYSCALL_ARG_COUNT(unsafeArgs), unsafeArgs);
}

/**
 * Call a native syscall while trying to to maintain isolation mechanisms using PINOS SYS_native_syscall_safe generic system call.
 *
 * @param opType        PINOS_SOP_NOP_SUCCESS - return SYSRET(SUCCESS) without doing anything
 *                      PINOS_SOP_NOP_FAILURE - return SYSRET(EPERM) without doing anything
 *                      PINOS_SOP_DO_UNSAFE   - Execute the specified system call bypassing isolation mechanisms using homemade
 *                                              SYS_native_syscall_unsafe system call (executed locally)
 *                                              Return system call return code. This is the same as calling OS_Syscall_unsafe
 *                      PINOS_SOP_ISOLATION   - Execute the specified system call trying to maintain isolation mechanisms using homemade
 *                                              SYS_native_syscall_safe system call (executed locally)
 *                                              Return system call return code.
 * @param syscall_id    Native Syscall ID (Not PINOS Syscall ID !!!!!!!!! - Use __NR_xxx macros rather than SYS_xxx macros)
 * @param arg_count     The number of native arguments (This is required for C)
 * @param ...           Native system call arguments - for this variadic function to work correctly all native arguments should
 *                      be casted to t_syscall_arg
 *
 * @return  The return value of ths PINOS syscall.
 *          Return values follow the linux convention. Values in the range [-4095,-1] Are errors.
 *
 */
static inline t_syscall_ret PINOSCALL OS_Syscall_safe_n(enum PINOS_SYSCALL_OP opType, t_syscall_id syscall_id, uint32_t arg_count,
                                                        ...)
{
    t_syscall_arg _args[MAX_SYSCALL_ARGS] = {0};
    va_list ap;

    assert(arg_count < MAX_SYSCALL_ARGS);

    va_start(ap, syscall_id);
    for (unsigned i = 0; i < arg_count; i++)
    {
        _args[i] = va_arg(ap, t_syscall_arg);
    }
    va_end(ap);

    t_syscall_arg safeArgs[] = {opType, (t_syscall_arg)(syscall_id), (t_syscall_arg)(0), (t_syscall_arg)(arg_count),
                                (t_syscall_arg)(_args)};
    return OS_Syscall(SYS_native_syscall_safe, SYSCALL_ARG_COUNT(safeArgs), safeArgs);
}

#define ___SYSCALL_NARGS_X(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, n, ...) n
#define ___SYSCALL_NARGS(...) ___SYSCALL_NARGS_X(__VA_ARGS__, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, )

/**
 * @brief Helper macro to allow calling OS_Syscall_unsafe_n without having
 *        to specify the number of argument allowing an interfae compatible
 *        with C++ OS_Syscall_unsafe 
 * 
 */
#define OS_Syscall_unsafe(syscall_id, ...) OS_Syscall_unsafe_n(syscall_id, ___SYSCALL_NARGS(__VA_ARGS__), __VA_ARGS__)
/**
 * @brief Helper macro to allow calling OS_Syscall_safe_n without having
 *        to specify the number of argument allowing an interfae compatible
 *        with C++ OS_Syscall_safe 
 * 
 */
#define OS_Syscall_safe(opType, syscall_id, ...) OS_Syscall_safe_n(opType, syscall_id, ___SYSCALL_NARGS(__VA_ARGS__), __VA_ARGS__)

#endif // #if defined(__cplusplus)

#endif // PINRT_ADAPTOR_UTILS_PH_
