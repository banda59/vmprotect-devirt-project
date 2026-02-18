/*
 * Copyright (C) 2023-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*  unwind_intel64.h
 *  Intel 64 unwind info definitions.
 *  Taken from Microsoft article http://msdn.microsoft.com/en-us/library/ssa62fwe.aspx
 *  The machine frame structure is decribed in 
 *  http://msdn.microsoft.com/en-us/library/ms794567.aspx
 */

#ifndef _UNWIND_INTEL64_H_
#define _UNWIND_INTEL64_H_

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

    typedef enum _UNWIND_OP_CODES
    {
        UWOP_PUSH_NONVOL = 0,
        UWOP_ALLOC_LARGE,
        UWOP_ALLOC_SMALL,
        UWOP_SET_FPREG,
        UWOP_SAVE_NONVOL,
        UWOP_SAVE_NONVOL_FAR,
        UWOP_SAVE_XMM,     // Deprecated, has different (unknown) meaning in Version 2
        UWOP_SAVE_XMM_FAR, // Probably deprecated
        UWOP_SAVE_XMM128,
        UWOP_SAVE_XMM128_FAR,
        UWOP_PUSH_MACHFRAME
    } UNWIND_CODE_OPS;

    typedef union _UNWIND_CODE
    {
        struct
        {
            UINT8 CodeOffset;
            UINT8 UnwindOp : 4;
            UINT8 OpInfo : 4;
        };
        UINT16 FrameOffset;
    } UNWIND_CODE, *PUNWIND_CODE;

#if !defined(UNW_FLAG_EHANDLER)
#define UNW_FLAG_EHANDLER 0x01
#define UNW_FLAG_UHANDLER 0x02
#define UNW_FLAG_CHAININFO 0x04
#endif

    typedef struct _UNWIND_INFO
    {
        UINT8 Version : 3; // Known values are 1 and 2.
        UINT8 Flags : 5;
        UINT8 SizeOfProlog;
        UINT8 CountOfCodes;
        UINT8 FrameRegister : 4;
        UINT8 FrameOffset : 4;
        UNWIND_CODE UnwindCode[1];
        /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
 *  union {
 *      OPTIONAL UINT32 ExceptionHandler;
 *      OPTIONAL UINT32 FunctionEntry;
 *  };
 *  OPTIONAL UINT32 ExceptionData[]; */
    } UNWIND_INFO, *PUNWIND_INFO;

    /* ================================================================== */
    // MACHFRAME_0 and MACHFRAME_1 structures
    /* ================================================================== */
    /*
 * Structure of the "machine frame" - data on the stack that corresponds 
 * to the UWOP_PUSH_MACHFRAME code in the unwind information. This frame 
 * is used to record the effect of a hardware interrupt or exception. 
 * There are two forms. If the UNWIND_CODE::OpInfo member equals 0, 
 * MACHFRAME_0 has been pushed on the stack. If the UNWIND_CODE::OpInfo 
 * member equals 1, then MACHFRAME_1 has instead been pushed.
 */
    typedef struct _MACHFRAME_0
    {
        UINT64 Rip;    //< instruction pointer
        UINT64 Cs;     //< CS segment register
        UINT64 Eflags; //< EFLAGS register
        UINT64 Rsp;    //< stack pointer
        UINT64 Ss;     //< SS segment register
    } MACHFRAME_0;

    typedef struct _MACHFRAME_1
    {
        UINT64 Err;    //< Error code
        UINT64 Rip;    //< instruction pointer
        UINT64 Cs;     //< CS segment register
        UINT64 Eflags; //< EFLAGS register
        UINT64 Rsp;    //< stack pointer
        UINT64 Ss;     //< SS segment register
    } MACHFRAME_1;

#define GetUnwindCodeEntry(info, index) ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) ((PVOID)&GetUnwindCodeEntry((info), ((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) ((PEXCEPTION_HANDLER)((base) + *(UINT32*)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) ((PRUNTIME_FUNCTION)((base) + *(UINT32*)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) \
    ((PVOID)((UINT32 *)GetLanguageSpecificData(info) + 1)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _UNWIND_INTEL64_H_ */
