/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

struct semid_ds
{
    struct ipc_perm sem_perm;
    time_t sem_otime;
    _arch_long __unused1;
    time_t sem_ctime;
    _arch_long __unused2;
    unsigned short sem_nsems;
    char __sem_nsems_pad[sizeof(_arch_long) - sizeof(short)];
    _arch_long __unused3;
    _arch_long __unused4;
};
