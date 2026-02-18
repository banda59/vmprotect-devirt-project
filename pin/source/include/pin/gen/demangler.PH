/*
 * Copyright (C) 2024-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifdef PIN_G_DEMANGLER_PH
#error duplicate inclusion of demangler
#else
#define PIN_G_DEMANGLER_PH
/*! @file
    Allows demangling of Windows symbols
*/

#include "sym_undecorate.PH"

enum DEMANGLE_ERRCODE
{
    DEMANGLE_ERRCODE_OK,
    DEMANGLE_ERRCODE_FAIL
};

/*!
 *  Unmangled a symbol using LLVM code.
 *
 *  @param[in]      mangledName             The symbol to demangle
 *  @param[in out]  unmangledName           A pointer to a buffer to receive the unmangled name
 *  @param[in]      unmangledNameLength     The size in bytes of the unmangledName buffer
 *
 *  @return     true if the demangling succeeded, false otherwise.
 */
extern DEMANGLE_ERRCODE DemangleSymbol(const char* mangledName, char* unmangledName, size_t unmangledNameLength,
                                       UNDECORATION style);

#endif // PIN_G_DEMANGLER_PH
