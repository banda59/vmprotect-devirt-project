/*
 * Copyright (C) 2023-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#define MAP_FIXED_REMAP MAP_FIXED

// We use these flags to set windows specific allocation behaviors when calling the MMAN POSIX interface
#if defined(TARGET_WINDOWS)
#define WIN_PROT_RESERVE 0x10
#define WIN_PROT_COMMIT 0x20
#define WIN_PROT_GUARD 0x40
#define WIN_PROT_IMAGE 0x80
#else
#define WIN_PROT_RESERVE 0x00
#define WIN_PROT_COMMIT 0x00
#define WIN_PROT_GUARD 0x00
#define WIN_PROT_IMAGE 0x00
#endif

#define PROT_ALLOW_REMAP 0x100 // Protection bit causing mmap request not to fail in case the page is already mapped
// Protection bit enabling Pin to manage application memory
// This bit does not affect the actual protection of the memory range, it just
// indicates to mprotect that it should allow Pin to change the protection of
// an application memory range.
#define PROT_DIS_APP_ISOL 0x200

// Extra memory region properties passed in address returned by mmap.
// They occupy low bits of aligned address, thus do not alter address value after the bits reset.
// Relevant client should reset these bits prior to using the address for memory access.
#if defined(TARGET_WINDOWS)
#define WIN_MMAP_NOT_AT_BASE 0x1
#else
#define WIN_MMAP_NOT_AT_BASE 0x0
#endif

#define QUERY_MEM_FLAGS_PASSTHROUGH 0x1 // OS-passthrough flag for SYS_mman_query_range

// Query bits controlled by the OS
#define QUERY_MEM_MAPPED 0x1 // Represents memory being "reserved" by the OS

#define QUERY_MEM_R 0x2
#define QUERY_MEM_W 0x4
#define QUERY_MEM_X 0x8
#define QUERY_MEM_PROT_MASK (QUERY_MEM_R | QUERY_MEM_W | QUERY_MEM_X)

#define QUERY_MEM_SHARED 0x10
#define QUERY_MEM_BACKED 0x20
#define QUERY_MEM_WIN_IMAGE 0x40 // Windows only flag. Always zero on Linux

#define QUERY_MEM_ROOT_PIN_BINARY 0x100 // Indicates MMAN identifies memory as belonging to Pin binary

#define QUERY_MEM_COMMITTED 0x8000 // Windows only flag. Always one on Linux

// Query bits controlled by Pin
#define QUERY_MEM_APPLICATION 0x10000 // Indicates the memory is managed by the application, not Pin
#define QUERY_MEM_STRONG 0x20000      // Indicates the page belongs to pre-configured Pin strong-range
#define QUERY_MEM_WEAK 0x40000        // Indicates the page belongs to pre-configured Pin weak-range
#define QUERY_MEM_INUSE 0x80000       // Indicates (for Pin memory) that the memory is used (vs. reserved weak/strong range)
#define QUERY_MEM_REMAP 0x100000      // Pin-extended protection bit. Set to allow for remapping with PROT_ALLOW_REMAP

#define QUERY_MEM_FAILED_QUERY 0x80000000 // Indicates error during underlying OS query operation

#if defined(TARGET_WINDOWS)
// We select a number that is large enough so that even if the kernel has to use
// guard pages when allocating arguments for KiXXX functions, we still return
// to user space with pages marked as guard pages.
// To understand why this maybe an issue, remember that once a guard page is touched
// its guard page bit is removed, and an exception will not be delivered for consecutive
// page accesses. If this happens inside the kernel, we will not receive an exception and
// we will not know about it. If an exception happens when the stack pointer is very close
// to the stack limit (where the guard pages are), because the arguments to KiXXX functions
// are allocated on the stack, the guard pages area will be used. We need
// to ensure that the stack has enough guard pages so that even if guard pages are used
// for the arguments, we are still left with enough guard pages on the stack when we
// get back to user space.
#define PINOS_STACK_GUARD_PAGES 6 // Number of guard pages at the bottom of the stack.
#define PINOS_STACK_GUARD_SIZE (PINOS_STACK_GUARD_PAGES * PAGE_SIZE)
#endif