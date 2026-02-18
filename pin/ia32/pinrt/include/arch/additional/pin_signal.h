/*
 * Copyright (C) 2025-2025 Intel Corporation.
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

/**
 * This header is included from Musl's signal.h
 */

/*!
 * @file
 * Contain Signal related runtime API (additional over standard runtime)
 */

#ifndef _PIN_SIGNAL_H_
#define _PIN_SIGNAL_H_

#include <unistd.h>
#include <syscall.h>

/**
 * @brief Call sigprocmask bypassing filtering done by Musl's sigprocmask
 * 
 * @param[in]  how      How to treat the set argument
 * @param[in]  set      The mask to set according to how
 * @param[out] oldset   The old mask
 * @return int 
 * 
 * For detailed documentation on how sigprocmask works check man 2 sigprocmask
 * 
 * We use this function inside Pin instead of sigprocmask to allow Pin to block/unblock
 * all signals without filtering done by the CRT
 */
static inline int sigprocmask_unfiltered(int how, const sigset_t* set, sigset_t* oldset)
{
    return syscall(SYS_rt_sigprocmask, how, set, oldset, _NSIG / 8);
}

/**
 * @brief Call sigaction bypassing filtering done by Musl's sigaction
 * 
 * @param[in]  signum The signal number for which to install or query the signal handler
 * @param[in]  act    A pointer to struct sigaction
 * @param[out] oldact A pointer to struct sigaction
 * @return int 
 * 
 * For detailed documentation on how sigaction works check man 2 sigaction
 * 
 * We use this function inside Pin instead of sigaction to allow Pin to install or query
 * any signal handler without filtering done by the CRT
 * 
 */
static inline int sigaction_unfiltered(int signum, const struct sigaction* act, struct sigaction* oldact)
{
    return sigaction(SIG_PIN_UNFILTERED(signum), act, oldact);
}

/**
 * @brief Initialize the signal set to exclude all signals.
 * 
 * @param[out] set A pointer to the signal set to be initialized.
 * @return int Returns 0 on success, -1 on error (e.g., if set is NULL).
 * 
 * This function directly manipulates the sigset_t structure to clear all bits,
 * effectively making the signal set empty.
 */
int sigemptyset_unfiltered(sigset_t* set);

/**
 * @brief Initialize the signal set to include all signals.
 * 
 * @param[out] set A pointer to the signal set to be initialized.
 * @return int Returns 0 on success, -1 on error (e.g., if set is NULL).
 * 
 * This function directly manipulates the sigset_t structure to set all bits,
 * effectively including all possible signals in the set.
 */
int sigfillset_unfiltered(sigset_t* set);

/**
 * @brief Add a signal to the signal set.
 * 
 * @param[in,out] set A pointer to the signal set.
 * @param[in] signum The signal number to be added.
 * @return int Returns 0 on success, -1 on error (e.g., if set is NULL or signum is invalid).
 * 
 * This function sets the bit corresponding to the specified signal number,
 * adding the signal to the set.
 */
int sigaddset_unfiltered(sigset_t* set, int signum);

/**
 * @brief Remove a signal from the signal set.
 * 
 * @param[in,out] set A pointer to the signal set.
 * @param[in] signum The signal number to be removed.
 * @return int Returns 0 on success, -1 on error (e.g., if set is NULL or signum is invalid).
 * 
 * This function clears the bit corresponding to the specified signal number,
 * removing the signal from the set.
 */
int sigdelset_unfiltered(sigset_t* set, int signum);

/**
 * @brief Check if a signal is a member of the signal set.
 * 
 * @param[in] set A pointer to the signal set.
 * @param[in] signum The signal number to check.
 * @return int Returns 1 if the signal is a member, 0 if not, and -1 on error (e.g., if set is NULL or signum is invalid).
 * 
 * This function checks the bit corresponding to the specified signal number
 * to determine if the signal is included in the set.
 */
int sigismember_unfiltered(const sigset_t* set, int signum);

#endif // #ifndef _PIN_SIGNAL_H_
