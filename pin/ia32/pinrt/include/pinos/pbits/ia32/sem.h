/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

struct semid_ds
{
    struct ipc_perm sem_perm;
    unsigned _arch_long __sem_otime_lo;
    unsigned _arch_long __sem_otime_hi;
    unsigned _arch_long __sem_ctime_lo;
    unsigned _arch_long __sem_ctime_hi;
    unsigned short sem_nsems;
    char __sem_nsems_pad[sizeof(_arch_long) - sizeof(short)];
    _arch_long __unused3;
    _arch_long __unused4;
    time_t sem_otime;
    time_t sem_ctime;
};
