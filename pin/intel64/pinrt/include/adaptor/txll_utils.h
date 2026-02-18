/*
 * Copyright (C) 2024-2025 Intel Corporation.
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

#ifndef __TXLL__UTILS_H__
#define __TXLL__UTILS_H__

#include <pinos.h>
#include <pbits/extrasyscalls.h>
#include <pbits/txlldef.h>
#include <stddef.h>

#ifdef __cplusplus
constexpr uint32_t TENSEC_INUSEC = 10000000;
constexpr uint32_t ONESEC_INUSEC = 1000000;
#else
#error "This file must be compiled with C++"
#endif

#define TX_NUMARG SYSCALL_ARG_COUNT(args)

/* The following are wrapper functions of Txll system calls
*/

/**
 * @brief Creates a new Tx_channel
 * 
 * @param[in] size size of Tx_channel queue, must be a multiple of 16 bytes and big enough to have
 *                 at least one message
 * @return success: pointer to the generated Tx_channel 
 *         SYSRET(ENOMEM):  not enough memory
 *         SYSRET(EINVAL):  invalid size parameter
 */
inline t_syscall_ret tx_create(size_t size) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(size)};
    return OS_Syscall(SYS_tx_channel_create, TX_NUMARG, args);
}

/**
 * @brief Closes a Tx_channel pointer
 * 
 * @param[in] chan pointer to a Tx_channel               
 * @return 
 *      success: SYSRET(SUCCESS)
 *      failure: SYSRET(EINVAL)
 */
inline t_syscall_ret tx_close(void* chan) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(chan)};
    return OS_Syscall(SYS_tx_channel_close, TX_NUMARG, args);
}

/**
 * @brief Opens a Tx_channel with a given Txid
 * 
 * @param[in] txid id of channel to open
 *                 
 * @return success: pointer to the Tx_channel
 *         failure: SYSRET(EINVAL)
 */
inline t_syscall_ret tx_open(uint64_t txid) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(&txid), t_syscall_arg(sizeof(uint64_t))};
    return OS_Syscall(SYS_tx_channel_open, TX_NUMARG, args);
}

/**
 * @brief Checks if a Tx_channel has incoming message(s) during a period of timeout microseconds.
 * 
 * @param[in] chan Pointer to a Tx_channel
 * @param[in] timeout in microseconds
 *                 
 * @return SYSRET(SUCCESS):  message exists in queue
 *         SYSRET(EPERM):    invalid queue
 *         SYSRET(ETIMEDOUT):No message in queue after timeout micro seconds
 */
inline t_syscall_ret tx_has_data(void* chan, uint32_t timeout) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(chan), t_syscall_arg(timeout)};
    return OS_Syscall(SYS_tx_has_data, TX_NUMARG, args);
}

/**
 * @brief Extracts the Txid of a channel.
 * 
 * @param[in] chan pointer to a Tx_channel
 *                 
 * @return success: the Txid of the Tx_channel
 *         failure: -1
 */
inline uint64_t tx_get_txid(void* chan) noexcept
{
    uint64_t txid        = -1;
    t_syscall_arg args[] = {t_syscall_arg(chan), t_syscall_arg(&txid), t_syscall_arg(sizeof(uint64_t))};
    t_syscall_ret ret    = OS_Syscall(SYS_tx_channel_gettxid, TX_NUMARG, args);
    if (IS_PINOS_SYSCALL_ERROR(ret))
    {
        return -1;
    }
    return txid;
}

/**
 * @brief Sending a message to a destination txid
 * 
 * @param[in] chan      sender channel
 * @param[in] dest_txid receiver (end point) txid
 * @param[in] message   pointer to a message buffer
 * @param[in] size      in bytes of above message
 *                 
 * @return  SYSRET(SUCCESS): success
 *          SYSRET(EINVAL):  invalid peer address
 *          SYSRET(ENOMEM):  internal memory mapping failure
 */
inline t_syscall_ret tx_send_to(void* chan, uint64_t dest_txid, uint8_t const* message, size_t size) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(chan), t_syscall_arg(&dest_txid), t_syscall_arg(sizeof(uint64_t)),
                            t_syscall_arg(message), t_syscall_arg(size)};
    return OS_Syscall(SYS_tx_sendto, TX_NUMARG, args);
}

/**
 * @brief Reads top message in channel and removes it from the queue.
 * 
 * @param[in]     chan     pointer to a Tx_channel
 * @param[in,out] p        pointer to a buffer, where to copy the message
 * @param[in]     size     size of above buffer
 * @param[out]    senderId sender txid
 *                 
 * @return  success: number of bytes read
 *          partial read: size of the whole message
 *          SYSRET(ENODATA): No message in queue
 *          SYSRET(EAGAIN):  Message not yet ready in queue
 */
inline t_syscall_ret tx_read_msg(void* chan, uint8_t* p, size_t size, uint64_t& senderId) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(chan), t_syscall_arg(&senderId), t_syscall_arg(sizeof(uint64_t)), t_syscall_arg(p),
                            t_syscall_arg(size)};
    return OS_Syscall(SYS_tx_recvfrom, TX_NUMARG, args);
}

/**
 * @brief Reads top message in channel but does not remove it from the queue.
 * 
 * @param[in]     chan     pointer to a Tx_channel
 * @param[in,out] p        pointer to a buffer, where to copy the message
 * @param[in]     size     size of above buffer
 * @param[out]    senderId sender txid
 *                 
 * @return  success: number of bytes read
 *          partial read: size of the whole message
 *          SYSRET(ENODATA): No message in queue
 *          SYSRET(EAGAIN):  Message not yet ready in queue
 */
inline t_syscall_ret tx_peek_msg(void* chan, uint8_t* p, size_t size, uint64_t& senderId) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(chan), t_syscall_arg(&senderId), t_syscall_arg(sizeof(uint64_t)), t_syscall_arg(p),
                            t_syscall_arg(size)};
    return OS_Syscall(SYS_tx_peekmsg, TX_NUMARG, args);
}

/**
 * @brief Waiting for a message for a timeout micro seconds amount of time. Reading and removing message if there is
 * 
 * @param[in]      chan     pointer to a Tx_channel
 * @param[in,out]  p        pointer to a buffer, where to copy the message
 * @param[in]      size     size of above buffer
 * @param[out]     senderId sender txid
 * @param[in]      timeout  in micro seconds
 *                 
 * @return  success: number of bytes read
 *          partial read: size of the whole message
 *          SYSRET(EPERM):    invalid queue
 *          SYSRET(ETIMEDOUT):No message in queue after timeout micro seconds
 *          SYSRET(EAGAIN):  Message not yet ready in queue
 */
inline t_syscall_ret tx_wait_data(void* chan, uint8_t* p, size_t size, uint64_t& senderId, uint32_t timeout) noexcept
{
    t_syscall_arg args[] = {t_syscall_arg(chan), t_syscall_arg(&senderId), t_syscall_arg(sizeof(uint64_t)),
                            t_syscall_arg(p),    t_syscall_arg(size),      t_syscall_arg(timeout)};
    return OS_Syscall(SYS_tx_channel_wait_data, TX_NUMARG, args);
}

/**
 * @brief Waiting for a message for a timeout micro seconds amount of time (default is ONESEC_INUSEC).
 *        Reading and removing message if there is.
 *        The difference from tx_wait_data is that the wait happens in this function and not in pinos syscall SYS_tx_channel_wait_data.
 * 
 * @param[in]      chan     pointer to a Tx_channel
 * @param[in,out]  p        pointer to a buffer, where to copy the message
 * @param[in]      size     size of above buffer
 * @param[out]     senderId sender txid
 * @param[in]      timeout  in micro seconds - default is ONESEC_INUSEC
 *                 
 * @return  success: number of bytes read
 *          partial read: size of the whole message
 *          SYSRET(EPERM):    invalid queue
 *          SYSRET(ETIMEDOUT):No message in queue after timeout micro seconds
 *          SYSRET(EAGAIN):  Message not yet ready in queue
 */
inline t_syscall_ret tx_rcv_msg(void* chan, uint8_t* p, size_t size, uint64_t& senderId,
                                uint32_t timeout = ONESEC_INUSEC) noexcept
{
    t_syscall_ret ret = tx_has_data(chan, timeout);

    /* either timeout or success */
    if (IS_PINOS_SYSCALL_ERROR(ret))
    {
        return ret;
    }

    do
    {
        ret = tx_read_msg(chan, p, size, senderId);
    }
    while (SYSRET(EAGAIN) == ret);

    return ret;
}

/**
 * @brief Waiting for a message for a timeout of TENSEC_INUSEC micro seconds. 
 *        See that top message in channel is ready to read but does not remove it from the queue.
 * 
 * @param[in] chan pointer to a Tx_channel
 *                 
 * @return  success: number of bytes of top message that can be read. 
 *          SYSRET(EPERM):    invalid queue
 *          SYSRET(ETIMEDOUT):No message in queue after timeout micro seconds
 */
inline t_syscall_ret tx_wait_msg(void* chan) noexcept
{
    uint32_t size = 0;
    uint64_t id;
    t_syscall_ret ret = tx_has_data(chan, TENSEC_INUSEC);

    /* either timeout or success */
    if (SYSRET(SUCCESS) != ret)
    {
        return ret;
    }

    do
    {
        ret = tx_peek_msg(chan, NULL, size, id);
    }
    while (SYSRET(EAGAIN) == ret);

    return ret;
}

#undef TX_NUMARG

#endif // __TXLL__UTILS_H__
