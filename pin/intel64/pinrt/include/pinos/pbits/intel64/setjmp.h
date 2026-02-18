/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

/*
setjmp stores the current execution context into jmp_buf structure
that has __jmp_buf as a member.
On Linux + Windows the begining is the same
rbx                           64 bits
rbp                           64 bits
r12 - r15                     4 x 64 bits
rsp (after return address)    64 bits
The return address            64 bits
--------Total 8 64 bit words----------
On Windows we add the following data as well
rdi                           64 bits
rsi                           64 bits
mxscr                         32 bits
padding                       16 bits
FPU control word              16 bits
--------Total 11 64 bit words---------
*/
#if defined(TARGET_WINDOWS)
typedef unsigned long long __jmp_buf[11];
#else
typedef unsigned _arch_long __jmp_buf[8];
#endif