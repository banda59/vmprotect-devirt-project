/*
 * Copyright (C) 2025-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _PIN_TXLL__H__
#define _PIN_TXLL__H__

// this is the maximum txll message size: a message size is uint16_t which we need to remove
// the header composed of two uint16_t.
#define TX_MAX_MSG_SIZE (0x10000-2*sizeof(uint16_t))

#endif // _PIN_TXLL__H__