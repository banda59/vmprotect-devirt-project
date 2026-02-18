/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

struct msqid_ds
{
    struct ipc_perm msg_perm;
    unsigned _arch_long __msg_stime_lo;
    unsigned _arch_long __msg_stime_hi;
    unsigned _arch_long __msg_rtime_lo;
    unsigned _arch_long __msg_rtime_hi;
    unsigned _arch_long __msg_ctime_lo;
    unsigned _arch_long __msg_ctime_hi;
    unsigned _arch_long msg_cbytes;
    msgqnum_t msg_qnum;
    msglen_t msg_qbytes;
    pid_t msg_lspid;
    pid_t msg_lrpid;
    unsigned _arch_long __unused[2];
    time_t msg_stime;
    time_t msg_rtime;
    time_t msg_ctime;
};
