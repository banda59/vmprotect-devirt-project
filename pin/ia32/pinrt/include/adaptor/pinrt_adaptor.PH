/*
 * Copyright (C) 2024-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef PINRT_ADAPTOR_PH_
#define PINRT_ADAPTOR_PH_

/**
 * @file
 * This file is the main public header for pinrt_adaptor.
 * It is included directly by pin.H
 * It should contain include directive for all public pinrt_adaptor headers
 * that are installed to Pin's kit.
 * 
 * @note This file should not include any headers that are not installed
 *       to the kit.
 */

#include <pinos.h>

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <signal.h>
#include <stdbool.h>
#include "types.h"
#include "types_marker.h"

#if defined(TARGET_LINUX)
#include <linux/syscall.h>
#else
#include "windows/win_syscalls.h"
#endif

#include "pinrt_adaptor_sync.PH"

#include "pinrt_adaptor_osapi.PH"

__END_DECLS

#include "pinrt_adaptor_memory.PH"
#include "pinrt_adaptor_utils.PH"

#endif // PINRT_ADAPTOR_PH_
