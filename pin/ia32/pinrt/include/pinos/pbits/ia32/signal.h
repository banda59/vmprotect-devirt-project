/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define MINSIGSTKSZ 2048
#define SIGSTKSZ 8192
#endif

// PIN_DISABLE_CRT_REG_DEF is for users (like SDE) who want to take REG_<X> definitions
// from pin reg_ia32.PH and don't want to add LEVEL_BASE:: namespace prefix.
// Otherwise it will collide with signal.h definitions (which are normally not used by users for REG_<X> definitions).
#if defined(_GNU_SOURCE) && !defined(PIN_DISABLE_CRT_REG_DEF)
enum
{
    REG_GS = 0
};
#define REG_GS REG_GS
enum
{
    REG_FS = 1
};
#define REG_FS REG_FS
enum
{
    REG_ES = 2
};
#define REG_ES REG_ES
enum
{
    REG_DS = 3
};
#define REG_DS REG_DS
enum
{
    REG_EDI = 4
};
#define REG_EDI REG_EDI
enum
{
    REG_ESI = 5
};
#define REG_ESI REG_ESI
enum
{
    REG_EBP = 6
};
#define REG_EBP REG_EBP
enum
{
    REG_ESP = 7
};
#define REG_ESP REG_ESP
enum
{
    REG_EBX = 8
};
#define REG_EBX REG_EBX
enum
{
    REG_EDX = 9
};
#define REG_EDX REG_EDX
enum
{
    REG_ECX = 10
};
#define REG_ECX REG_ECX
enum
{
    REG_EAX = 11
};
#define REG_EAX REG_EAX
enum
{
    REG_TRAPNO = 12
};
#define REG_TRAPNO REG_TRAPNO
enum
{
    REG_ERR = 13
};
#define REG_ERR REG_ERR
enum
{
    REG_EIP = 14
};
#define REG_EIP REG_EIP
enum
{
    REG_CS = 15
};
#define REG_CS REG_CS
enum
{
    REG_EFL = 16
};
#define REG_EFL REG_EFL
enum
{
    REG_UESP = 17
};
#define REG_UESP REG_UESP
enum
{
    REG_SS = 18
};
#define REG_SS REG_SS
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef int greg_t, gregset_t[19];
typedef struct _fpstate
{
    unsigned _arch_long cw, sw, tag, ipoff, cssel, dataoff, datasel;
    struct
    {
        unsigned short significand[4], exponent;
    } _st[8];
    unsigned _arch_long status;
}* fpregset_t;
struct sigcontext
{
    unsigned short gs, __gsh, fs, __fsh, es, __esh, ds, __dsh;
    unsigned _arch_long edi, esi, ebp, esp, ebx, edx, ecx, eax;
    unsigned _arch_long trapno, err, eip;
    unsigned short cs, __csh;
    unsigned _arch_long eflags, esp_at_signal;
    unsigned short ss, __ssh;
    struct _fpstate* fpstate;
    unsigned _arch_long oldmask, cr2;
};
typedef struct
{
    gregset_t gregs;
    fpregset_t fpregs;
    unsigned _arch_long oldmask, cr2;
} mcontext_t;
#else
typedef struct
{
    unsigned __space[22];
} mcontext_t;
#endif

struct sigaltstack
{
    void* ss_sp;
    int ss_flags;
    size_t ss_size;
};

typedef struct __ucontext
{
    unsigned _arch_long uc_flags;
    struct __ucontext* uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    sigset_t uc_sigmask;
    unsigned _arch_long __fpregs_mem[28];
} ucontext_t;

#define SA_NOCLDSTOP 1
#define SA_NOCLDWAIT 2
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000
#define SA_RESTORER 0x04000000

#endif

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT SIGABRT
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPOLL 29
#define SIGPWR 30
#define SIGSYS 31
#define SIGUNUSED SIGSYS

#define _NSIG 65

/* 
For pinrt we support this signal modifier to allow siagction to set/get all possible signals. 
The default behaviour of Musl's sigaction is to prevent setting or getting signals 32,33 & 34
*/
#define PIN_UNFILTER_MASK 0x00800000
#define SIG_PIN_UNFILTERED(s) ((s) | PIN_UNFILTER_MASK)
