/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _LX_SYSCALL_H_
#define _LX_SYSCALL_H_

#if defined(TARGET_IA32)
#include "ia32/syscall.h"
#elif defined(TARGET_IA32E)
#include "intel64/syscall.h"
#endif

#endif // _LX_SYSCALL_H_
