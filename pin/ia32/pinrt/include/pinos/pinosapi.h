/*
 * Copyright (C) 2020-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _PINOSAPI_H_
#define _PINOSAPI_H_

#include "pinosdef.h"

#include "pinsyscall.h"

/**
 * @brief 
 * 
 * @param state 
 * @param startupInfo  Pointer to a process startup info vector (argv, envp, auxv). Data format is according to Linux ABI.
 * @return t_syscall_ret 
 */
EXTERNC PINOS_DLLVIS t_syscall_ret PINOSCALL OS_Init(void** state, void** startupInfo);

/**
 * @brief Execute a PINOS system call
 * 
 * @param syscall_id    PINOS Syscall ID (Ids can be accessed by including syscall.h of pin crt)
 * @param arg_count     The number of arguments to the syscall
 * @param args          An array of arguments containig at least arg_count arguments. If arg_count is zero
 *                      then this argument can be set to nullptr
 *
 * @return The return value of ths PINOS syscall.
 *         Return values follow the linux convention. Values in the range [-4095,-1] Are errors.
 * 
 * Note: This function will execute a generic syscall which will be routed according to configuration to
 *       to be executed locally natively, remotely or by some specific PINOS implementation. This means that
 *       syscall_id is a generig syscall id and does not correspond to a kernel syscall number.
 *
 */
EXTERNC PINOS_DLLVIS t_syscall_ret PINOSCALL OS_Syscall(t_syscall_id syscall_id, uint32_t arg_count, t_syscall_arg* args);

/**
 * @brief Same as OS_Syscall() only arguments are passed in the call itself and not through an array of arguments.
 *
 * @param syscall_id    PINOS Syscall ID (Ids can be accessed by including syscall.h of pin crt)
 * @param arg_count     The number of arguments to the syscall
 * @param ...           arg_count system call arguments
 *
 * @return  The return value of ths PINOS syscall.
 *          Return values follow the linux convention. Values in the range [-4095,-1] Are errors.
 *
 * Note: This function will execute a generic syscall which will be routed according to configuration to
 *       to be executed locally natively, remotely or by some specific PINOS implementation. This means that
 *       syscall_id is a generig syscall id and does not correspond to a kernel syscall number.
 *
 */
EXTERNC PINOS_DLLVIS t_syscall_ret PINOSCALL OS_Syscalln(t_syscall_id syscall_id, uint32_t arg_count, ...);

/**
 * @brief Execute a native OS system call
 * 
 * @param syscall_id The native OS system call to execute
 * @param args       An array of arguments to pass to the syscall.
 *                   On Linux this array must have a length of at least 6 entries (only the first 6 will be used).
 *                   On Windows this array must have a length of at least 15 entires (only the first 15 will be used).
 * 
 * Note: This function will call directly into the kernel bypassing PINOS mechanisms of syscall routing.
 *       So syscall_id is a kernel syscall number.
 * 
 * @return The native syscall return code
 * 
 */
EXTERNC PINOS_DLLVIS t_syscall_ret PINOSCALL pinos_bare_syscall(t_syscall_id syscall_id, t_syscall_arg* args);

/**
 * @brief Safely abort the program
 * 
 * This function will terminate the process immediately without raising any signals or triggering exceptions.
 * If called when a debugger is attached it will cause a breakpoint instead of aborting the program.
 * If the -pause_abort knob is set then this function will wait for a debugger to attach before aborting the program.
 *
 * @note If this function is called before PINOS is fully initialized, it will attempt to write to the pinos logger
 *       which writes to both a file and the console if present. This may fail for low integrity processes.
 *       Also in this case checking the debugOnAbort knob will not be possible.
 *
 * @param[in] file      The name of the file where the abort was called
 * @param[in] function  The name of the function where the abort was called
 * @param[in] line      The line number where the abort was called
 */
EXTERNC NORETURN__ PINOS_DLLVIS void PINOSCALL OS_Abort(const char* file, const char* function, int line);

/**
 * @brief Abort the program with a custom message
 *
 * See @ref OS_Abort() for details.
 * 
 * @param[in] file      The name of the file where the abort was called
 * @param[in] function  The name of the function where the abort was called
 * @param[in] line      The line number where the abort was called
 * @param[in] msg       The custom message to include in the abort
 */
EXTERNC NORETURN__ PINOS_DLLVIS void PINOSCALL OS_Abort_with_msg(const char* file, const char* function, int line,
                                                                 const char* msg);

#define OS_ABORT() OS_Abort(__FILE__, __PRETTY_FUNCTION__, __LINE__)
#define OS_ABORT_MSG(msg) OS_Abort_with_msg(__FILE__, __PRETTY_FUNCTION__, __LINE__, msg)
#define OS_ASSERT(expr)                                    \
    do                                                     \
    {                                                      \
        if (!(expr))                                       \
        {                                                  \
            OS_ABORT_MSG("Assertion '" #expr "' failed."); \
        }                                                  \
    }                                                      \
    while (0)

#endif // _PINOSAPI_H_
