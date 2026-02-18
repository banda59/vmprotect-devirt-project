/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#define SHMLBA 4096

struct shmid_ds
{
    struct ipc_perm shm_perm;
    size_t shm_segsz;
    unsigned _arch_long __shm_atime_lo;
    unsigned _arch_long __shm_atime_hi;
    unsigned _arch_long __shm_dtime_lo;
    unsigned _arch_long __shm_dtime_hi;
    unsigned _arch_long __shm_ctime_lo;
    unsigned _arch_long __shm_ctime_hi;
    pid_t shm_cpid;
    pid_t shm_lpid;
    unsigned _arch_long shm_nattch;
    unsigned _arch_long __pad1;
    unsigned _arch_long __pad2;
    unsigned _arch_long __pad3;
    time_t shm_atime;
    time_t shm_dtime;
    time_t shm_ctime;
};

struct shminfo
{
    unsigned _arch_long shmmax, shmmin, shmmni, shmseg, shmall, __unused[4];
};

struct shm_info
{
    int __used_ids;
    unsigned _arch_long shm_tot, shm_rss, shm_swp;
    unsigned _arch_long __swap_attempts, __swap_successes;
};
