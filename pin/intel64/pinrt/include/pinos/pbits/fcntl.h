/*
 * Copyright (C) 2023-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#define O_CREAT 0100
#define O_EXCL 0200
#define O_NOCTTY 0400
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_DSYNC 010000
#define O_SYNC 04010000
#define O_RSYNC 04010000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW 0400000
#define O_CLOEXEC 02000000

#define O_ASYNC 020000
#define O_DIRECT 040000
#define O_LARGEFILE 0100000
#define O_NOATIME 01000000
#define O_PATH 010000000
#define O_TMPFILE 020200000
#define O_NDELAY O_NONBLOCK

#define O_RSC 01000000000
#define O_RSC_LOCAL 02000000000
#define O_OPEN_IMAGE 04000000000
#define O_HONOR_CLOEXEC 010000000000

#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4

#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11

#if __LONG_MAX == 0x7fffffffL
#define F_GETLK 12
#define F_SETLK 13
#define F_SETLKW 14
#else
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#endif

#define F_SETOWN_EX 15
#define F_GETOWN_EX 16

#define F_GETOWNER_UIDS 17

/*
 * Flags to SYS_native_id
 * Q_ANY_ID     return the native id for the generic id or error
 * Q_FILE_ID    return the native file fd/handle or error if not a generic file id (or not found)
 * Q_THREAD_ID  return the native thread id or error if not a generic thread id (or not found)
 */
#define Q_ANY_ID 0
#define Q_FILE_ID 1
#define Q_THREAD_ID 2
