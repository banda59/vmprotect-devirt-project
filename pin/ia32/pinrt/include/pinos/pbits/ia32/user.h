/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#undef __WORDSIZE
#define __WORDSIZE 32

typedef struct user_fpregs_struct
{
    _arch_long cwd, swd, twd, fip, fcs, foo, fos, st_space[20];
} elf_fpregset_t;

typedef struct user_fpxregs_struct
{
    unsigned short cwd, swd, twd, fop;
    _arch_long fip, fcs, foo, fos, mxcsr, reserved;
    _arch_long st_space[32], xmm_space[32], padding[56];
} elf_fpxregset_t;

struct user_regs_struct
{
    _arch_long ebx, ecx, edx, esi, edi, ebp, eax, xds, xes, xfs, xgs;
    _arch_long orig_eax, eip, xcs, eflags, esp, xss;
};

#define ELF_NGREG 17
typedef unsigned _arch_long elf_greg_t, elf_gregset_t[ELF_NGREG];

struct user
{
    struct user_regs_struct regs;
    int u_fpvalid;
    struct user_fpregs_struct i387;
    unsigned _arch_long u_tsize;
    unsigned _arch_long u_dsize;
    unsigned _arch_long u_ssize;
    unsigned _arch_long start_code;
    unsigned _arch_long start_stack;
    _arch_long signal;
    int reserved;
    struct user_regs_struct* u_ar0;
    struct user_fpregs_struct* u_fpstate;
    unsigned _arch_long magic;
    char u_comm[32];
    _arch_long u_debugreg[8];
};

#define PAGE_MASK (~(PAGESIZE - 1))
#define NBPG PAGESIZE
#define UPAGES 1
#define HOST_TEXT_START_ADDR (u.start_code)
#define HOST_STACK_END_ADDR (u.start_stack + u.u_ssize * NBPG)
