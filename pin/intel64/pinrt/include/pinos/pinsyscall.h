/*
 * Copyright (C) 2022-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _PINSCN_PH_
#define _PINSCN_PH_

#include <stdbool.h>
#include <stdint.h>
#include <pinos_errno.h>

/*
 * For (with) system build (non PIN_RT) we need the additional pin syscall ids
 * They are defined in syscall.h in the kit hierarchy as defined below
 */

typedef uintptr_t t_syscall_id;
typedef uintptr_t t_syscall_arg;
typedef intptr_t t_syscall_ret;

#define SYSOP(op) PINOS_SOP_##op
#define SYSFLAG(fl) PINOS_SCF_##fl
#define SYSRET(rc) PINOS_SYSRET_##rc

/**
 * @brief Operation type for SYS_native_syscall_safe
 * 
 */
enum PINOS_SYSCALL_OP
{
    SYSOP(ISOLATION),   //! Call syscall maintaining isolation from instrumented application
    SYSOP(NOP_SUCCESS), //! Do nothing successfully
    SYSOP(NOP_FAILURE), //! Do nothing and return an error
    SYSOP(DO_UNSAFE),   //! Same as calling SYS_native_syscall_unsafe
};

/**
 * @brief Flags for SYS_native_syscall_* syscalls
 * 
 * This flags values are reserved for future use and may be removed from the interface
 * 
 */
enum PINOS_SYSCALL_FLAGS
{
    SYSFLAG(NONE)     = 0,
    SYSFLAG(EMULATOR) = 1, //! Emulator is caller of the syscall
};

enum PINOS_SYSCALL_RESULT
{
    SYSRET(SUCCESS)         = 0,
    SYSRET(E2BIG)           = -PINOS_E2BIG,
    SYSRET(EACCES)          = -PINOS_EACCES,
    SYSRET(EADDRINUSE)      = -PINOS_EADDRINUSE,
    SYSRET(EADDRNOTAVAIL)   = -PINOS_EADDRNOTAVAIL,
    SYSRET(EAFNOSUPPORT)    = -PINOS_EAFNOSUPPORT,
    SYSRET(EAGAIN)          = -PINOS_EAGAIN,
    SYSRET(EALREADY)        = -PINOS_EALREADY,
    SYSRET(EBADF)           = -PINOS_EBADF,
    SYSRET(EBADMSG)         = -PINOS_EBADMSG,
    SYSRET(EBUSY)           = -PINOS_EBUSY,
    SYSRET(ECONNABORTED)    = -PINOS_ECONNABORTED,
    SYSRET(ECONNREFUSED)    = -PINOS_ECONNREFUSED,
    SYSRET(ECONNRESET)      = -PINOS_ECONNRESET,
    SYSRET(ECHILD)          = -PINOS_ECHILD,
    SYSRET(EDESTADDRREQ)    = -PINOS_EDESTADDRREQ,
    SYSRET(EDQUOT)          = -PINOS_EDQUOT,
    SYSRET(EEXIST)          = -PINOS_EEXIST,
    SYSRET(EFAULT)          = -PINOS_EFAULT,
    SYSRET(EFBIG)           = -PINOS_EFBIG,
    SYSRET(EHOSTDOWN)       = -PINOS_EHOSTDOWN,
    SYSRET(EHOSTUNREACH)    = -PINOS_EHOSTUNREACH,
    SYSRET(EINPROGRESS)     = -PINOS_EINPROGRESS,
    SYSRET(EINTR)           = -PINOS_EINTR,
    SYSRET(EINVAL)          = -PINOS_EINVAL,
    SYSRET(EISCONN)         = -PINOS_EISCONN,
    SYSRET(EISDIR)          = -PINOS_EISDIR,
    SYSRET(EIO)             = -PINOS_EIO,
    SYSRET(ELIBACC)         = -PINOS_ELIBACC,
    SYSRET(ELIBBAD)         = -PINOS_ELIBBAD,
    SYSRET(ELOOP)           = -PINOS_ELOOP,
    SYSRET(EMFILE)          = -PINOS_EMFILE,
    SYSRET(EMSGSIZE)        = -PINOS_EMSGSIZE,
    SYSRET(ENAMETOOLONG)    = -PINOS_ENAMETOOLONG,
    SYSRET(ENETDOWN)        = -PINOS_ENETDOWN,
    SYSRET(ENETRESET)       = -PINOS_ENETRESET,
    SYSRET(ENETUNREACH)     = -PINOS_ENETUNREACH,
    SYSRET(ENOBUFS)         = -PINOS_ENOBUFS,
    SYSRET(ENODATA)         = -PINOS_ENODATA,
    SYSRET(ENODEV)          = -PINOS_ENODEV,
    SYSRET(ENOENT)          = -PINOS_ENOENT,
    SYSRET(ENOMEM)          = -PINOS_ENOMEM,
    SYSRET(ENOPROTOOPT)     = -PINOS_ENOPROTOOPT,
    SYSRET(ENOSPC)          = -PINOS_ENOSPC,
    SYSRET(ENOSYS)          = -PINOS_ENOSYS,
    SYSRET(ENOTCONN)        = -PINOS_ENOTCONN,
    SYSRET(ENOTDIR)         = -PINOS_ENOTDIR,
    SYSRET(ENOTEMPTY)       = -PINOS_ENOTEMPTY,
    SYSRET(ENOTRECOVERABLE) = -PINOS_ENOTRECOVERABLE,
    SYSRET(ENOTSOCK)        = -PINOS_ENOTSOCK,
    SYSRET(ENOTSUP)         = -PINOS_ENOTSUP,
    SYSRET(ENOTTY)          = -PINOS_ENOTTY,
    SYSRET(EOPNOTSUPP)      = -PINOS_EOPNOTSUPP,
    SYSRET(EOVERFLOW)       = -PINOS_EOVERFLOW,
    SYSRET(EPERM)           = -PINOS_EPERM,
    SYSRET(EPFNOSUPPORT)    = -PINOS_EPFNOSUPPORT,
    SYSRET(EPROTONOSUPPORT) = -PINOS_EPROTONOSUPPORT,
    SYSRET(EPROTOTYPE)      = -PINOS_EPROTOTYPE,
    SYSRET(ERANGE)          = -PINOS_ERANGE,
    SYSRET(EREMOTE)         = -PINOS_EREMOTE,
    SYSRET(ESHUTDOWN)       = -PINOS_ESHUTDOWN,
    SYSRET(ESOCKTNOSUPPORT) = -PINOS_ESOCKTNOSUPPORT,
    SYSRET(ESRCH)           = -PINOS_ESRCH,
    SYSRET(ESPIPE)          = -PINOS_ESPIPE,
    SYSRET(ESTALE)          = -PINOS_ESTALE,
    SYSRET(ETIMEDOUT)       = -PINOS_ETIMEDOUT,
    SYSRET(ETOOMANYREFS)    = -PINOS_ETOOMANYREFS,
    SYSRET(EUSERS)          = -PINOS_EUSERS,
    SYSRET(EWOULDBLOCK)     = -PINOS_EWOULDBLOCK,
};

static inline bool __is_pinos_syscall_error(t_syscall_ret sysret) { return ((sysret < 0) && (sysret > (t_syscall_ret)(-4096))); }

#define IS_PINOS_SYSCALL_ERROR(sysret) __is_pinos_syscall_error((t_syscall_ret)(sysret))
#define PINOS_SYSCALL_RET(sysret) (IS_PINOS_SYSCALL_ERROR(sysret) ? (t_syscall_ret)-1 : (t_syscall_ret)(sysret))

#define SYSCALL_ARG_COUNT(args) (sizeof(args) / sizeof(t_syscall_arg))

#endif // _PINSCN_PH_