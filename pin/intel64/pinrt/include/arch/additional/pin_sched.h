/*
 * Copyright (C) 2023-2023 Intel Corporation.
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

#ifndef _PIN_SCHED_H_
#define _PIN_SCHED_H_

/*!
 * This header is included from Musl's sched.h
 *
 * This file is intended to be included from Pin to support syscall emulation
 * of clone & clone3 on Linux.
 * The functions below (__native_clone & __native_clone3) should be used only for
 * the purpose of syscall emulation. Trying to use them for other purposes will break Pin.
 *                   !!!!!!!!!! YOU HAVE BEEN WARNED !!!!!!!!!!
 */

#include <sys/cdefs.h>
#include <stddef.h>
#include <stdint.h>

__BEGIN_DECLS

typedef uint64_t aligned_uint64_t __attribute__((__aligned__(8)));

/* 
This struct should only be used in an argument to the clone3 system
call (along with its size argument).  It may be extended with new
fields in the future. 
*/
struct clone_args
{
    /* Flags bit mask.  */
    aligned_uint64_t flags;
    /* Where to store PID file descriptor (pid_t *).  */
    aligned_uint64_t pidfd;
    /* Where to store child TID, in child's memory (pid_t *).  */
    aligned_uint64_t child_tid;
    /* Where to store child TID, in parent's memory (int *). */
    aligned_uint64_t parent_tid;
    /* Signal to deliver to parent on child termination */
    aligned_uint64_t exit_signal;
    /* The lowest address of stack.  */
    aligned_uint64_t stack;
    /* Size of stack.  */
    aligned_uint64_t stack_size;
    /* Location of new TLS.  */
    aligned_uint64_t tls;
    /* Pointer to a pid_t array (since Linux 5.5).  */
    aligned_uint64_t set_tid;
    /* Number of elements in set_tid (since Linux 5.5). */
    aligned_uint64_t set_tid_size;
    /* File descriptor for target cgroup of child (since Linux 5.7).  */
    aligned_uint64_t cgroup;
};

int __native_clone(int (*func)(void* arg), void* child_stack, int flags, void* arg, pid_t* ptid, void* tls, pid_t* ctid);
int __native_clone3(struct clone_args* cl_args, size_t size, int (*func)(void* arg), void* arg);

__END_DECLS

#endif // _PIN_SCHED_H_
