/*
 * Copyright (C) 2015-2024 Intel Corporation.
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

/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ***   To edit the content of this header, modify the corresponding
 ***   source file (e.g. under external/kernel-headers/original/) then
 ***   run bionic/libc/kernel/tools/update_all.py
 ***
 ***   Any manual change here will be lost the next time this script will
 ***   be run. You've been warned!
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _ASM_X86_PRCTL_H
#define _ASM_X86_PRCTL_H
#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

#define ARCH_GET_CPUID 0x1011
#define ARCH_SET_CPUID 0x1012

#define ARCH_GET_XCOMP_SUPP 0x1021
#define ARCH_GET_XCOMP_PERM 0x1022
#define ARCH_REQ_XCOMP_PERM 0x1023
#define ARCH_GET_XCOMP_GUEST_PERM 0x1024
#define ARCH_REQ_XCOMP_GUEST_PERM 0x1025

#define ARCH_XCOMP_TILECFG 17
#define ARCH_XCOMP_TILEDATA 18

#define ARCH_MAP_VDSO_X32 0x2001
#define ARCH_MAP_VDSO_32 0x2002
#define ARCH_MAP_VDSO_64 0x2003

#define ARCH_CET_STATUS 0x3001
#define ARCH_CET_DISABLE 0x3002
#define ARCH_CET_LOCK 0x3003

/* do not use 0x3001-0x3004 because of old glibc(s) when running on newer kernels */

#define ARCH_GET_UNTAG_MASK 0x4001
#define ARCH_ENABLE_TAGGED_ADDR 0x4002
#define ARCH_GET_MAX_TAG_BITS 0x4003
#define ARCH_FORCE_TAGGED_SVA 0x4004

#define ARCH_SHSTK_ENABLE 0x5001
#define ARCH_SHSTK_DISABLE 0x5002
#define ARCH_SHSTK_LOCK 0x5003
#define ARCH_SHSTK_UNLOCK 0x5004
#define ARCH_SHSTK_STATUS 0x5005

/* ARCH_SHSTK_ features bits */
#define ARCH_SHSTK_SHSTK (1ULL << 0)
#define ARCH_SHSTK_WRSS (1ULL << 1)

#endif
