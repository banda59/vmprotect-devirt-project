/*
 * Copyright (C) 2024-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef PIN_G_PIN_RPC_CLIENT_PH
#define PIN_G_PIN_RPC_CLIENT_PH

/*! @file
 *
 * Client side interface to pind RPC plugins.
 * 
 * See @ref REMOTE section in Pin User Manual
 * 
 * @note APIs declared in this file are under active development and are subject 
 *       to change or removal without notice
 */

/**
 * @ingroup REMOTE
 * 
 * \def IS_RPC_EXEC_ERROR(ret)
 * @brief Check if ret is an error.
 * 
 * This macro should be used to check if PIN_DoRPC() succeeded or not.
 * 
 * @note The return status of PIN_DoRPC() does not indicate success or failure of
 *       the actual RPC (Remote Procedure Call). Just whether the RPC request was
 *       processed correctly by Pin & pind.
 * 
 */
#define IS_RPC_EXEC_ERROR(ret) IS_PINOS_SYSCALL_ERROR(ret)

/**
 * @ingroup REMOTE
 *
 * @brief RPC flags
 *
 * @note These flags cannot be combined. 
 */
enum E_pin_rpc_flags
{
    PinRpcFlagsNone, /** Normal operation. Will wait for a response with some "reasonable" internal timeout. If a timeout occurs the program will abort */
    PinRpcFlagsNoResponseRequired,   /** No response is expected from the server. Can return immediately */
    PinRpcFlagsCanBlockIndefinitely, /** Can block indefinitely waiting for a response */
};

/*! @ingroup REMOTE
 * 
 * @brief Execute an RPC (Remote Procedure Call).
 * 
 * The remote procedure is implemented by a plugin that is loaded by pind, the Pin server.
 * The plugin must be installed prior starting pin with a Pintool that uses this function.
 * For more information see @ref PLUGINSTALL "Installing and Loading pind Plugins".
 * If the plugin was not properly installed or loaded the call will fail. 
 * The return value of this function reflects the status of the remote execution.
 * The return value of the remote function is written to the last arg in rpcArgs.
 *
 * See @ref REMOTE section in Pin User Manual
 *
 *
 * @param[in]     rpcSchema     The schema describing the remote procedure.
 *                              Both the Pintool and the pind RPC plugin should use the same schema.
 *                              The schema is used both to verify the arguments before calling the RPC,
 *                              and is also used to verify the response to the RPC.
 *                              The maximum arguments for an RPC schema accepted by this function
 *                              is 15.
 * @param[in,out] rpcArgs       An array of args to pass to the remote procedure.
 *                              The args may be [in], [out] or [inout] arguments.
 *                              The length of the array must be equal to the count of the message arguments 
 *                              as described by rpcSchema + one entry for the return value of the RPC.
 *                              So the length of this array must be at least 1, even if the return argument type
 *                              is RpcVoid or RpcNil.
 *                              The return value of the remote procedure is written to the last argument in the array.
 *                              Arguments are checked against rpcSchema.
 * @param[in]     flags         Flags modifying the behavior of the RPC.
 * @return t_syscall_ret    On success SYSRET(SUCCESS) (0) is returned.
 *                          On error a negative value is returned. 
 *                          The value represents an error that is specified in pinsyscall.h.
 *                          To properly check if the return value is an error, IS_RPC_EXEC_ERROR macro should be used.

 * @note The return status of PIN_DoRPC() does not indicate success or failure of
 *       the actual RPC (Remote Procedure Call). Just whether the RPC request was
 *       processed correctly by Pin & pind.
 *       The actual success or failure of the remote procedure call should be deduced from the return
 *       value of the RPC, if such return value exists for the RPC. The actual interpretation of the 
 *       return value of the RPC is user defined.
 * 
 * @note This API is under active development and may change or be removed without notice.
 * 
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows*\n
 * \b CPU:   IA-32 and Intel(R) 64 architectures\n
 */
inline t_syscall_ret PIN_DoRPC(t_rpc_message_schema const* rpcSchema, t_rpc_arg* rpcArgs,
                               E_pin_rpc_flags flags = PinRpcFlagsNone) noexcept
{
    t_syscall_arg syscallArgs[] = {
        t_syscall_arg(rpcSchema), // syscallArgs[0] is a pointer to the message schema
        t_syscall_arg(rpcArgs),   // syscallArgs[1] is the t_rpc_arg array
        t_syscall_arg(flags),     // syscallArgs[2] is the flags
    };
    return OS_Syscall(SYS_rsc_do_rpc, SYSCALL_ARG_COUNT(syscallArgs), syscallArgs);
}

/*! @ingroup REMOTE
 *
 * @brief Calculate the size available for data given a message schema
 * 
 * An RSC/RPC message can be of a maximum size of 64KB. However the actual size
 * available for data in a message is 64KB - RSC_RPC_DATA_OFFSET - (size of argument encoding metadata).
 * This function calculates the maximum possible size that the argument encoding metadata will take and returns
 * a safe estimate to the size in bytes actually available for encoding.
 * 
 * @note The size returned is for the data of all arguments passed to the RPC.
 * 
 * @param[in] rpcSchema The message schema for which to calculate the metadata overhead 
 * @return size_t - The available size for data given a schema. 
 * 
 * @note This API is under active development and may change or be removed without notice.
 * 
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows*\n
 * \b CPU:   IA-32 and Intel(R) 64 architectures\n
 */
inline size_t PIN_CalculateSafeRPCDataSize(t_rpc_message_schema const* rpcSchema) noexcept
{
    return calculate_rpc_data_space(rpcSchema, TX_MAX_MSG_SIZE);
}

#if __cplusplus >= 201703L || DOXYGEN
// Code below supported for C++17 and above

/** @ingroup REMOTE
 * 
 * @brief Namespca grouping for C++ convenient wrappers around @ref PIN_DoRPC 
 * 
 */
namespace remote
{
/*! @ingroup REMOTE
 * @brief Wrap a buffer to be sent or filled over RPC
 * 
 * Users are encouraged to use the rpc_buffer() function to properly initialize this structure rather than doing so directly
 */
struct Rpc_buffer_wrapper
{
    uintptr_t memory;      /*!< The address of the buffer */
    size_t size;           /*!< The size of the buffer. */
    E_rpc_arg_flags flags; /*!< Flags modifying the behavior of the argument encoder or the interpretation of the result.
                                If the value is set to RpcArgFlagsDataEmpty before calling the RPC then no data will be
                                copied to the RPC message. 
                                In effect setting this flag to RpcArgFlagsDataEmpty indicates this is an out argument.*/
};
/*! @ingroup REMOTE
 * @brief Wrap a buffer to be used as an argument to an RPC
 * 
 * @param[in,out] mem   The buffer memory
 * @param[in]     size  The size of the buffer in bytes. If size is 0 then no data will be copied into the RPC request.
 * @param[in]     flags Flags modifying the behaviour of the argument encoding. If this is set to 
 *                      @ref E_rpc_arg_flags::RpcArgFlagsDataEmpty then no data will be sent to the RPC, however the RPC 
 *                      can fill the buffer on return.
 *                      This behaviour is just a performance optimization so if the buffer is intended to be filled
 *                      by the RPC and the contents are not valid until the RPC returns, then there is no point in 
 *                      copying the initial content to the RPC request. 
 * 
 * @return Rpc_buffer_wrapper structure wrapping the buffer 
 * 
 * @note This API is under active development and may change or be removed without notice.
 * 
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows*\n
 * \b CPU:   IA-32 and Intel(R) 64 architectures\n
*/
inline Rpc_buffer_wrapper rpc_buffer(void* mem, size_t size, E_rpc_arg_flags flags = RpcArgFlagsNone) noexcept
{
    return {uintptr_t(mem), size, flags};
}
/*! @ingroup REMOTE
 * @brief Wrap a buffer to be used as an argument to an RPC
 * 
 * @param[in] mem   The buffer memory
 * @param[in] size  The size of the buffer in bytes. 
 *                  If the size is 0 then no data is copied to the RPC request.
 * @return Rpc_buffer_wrapper structure wrapping the buffer 
 * 
 * @note This API is under active development and may change or be removed without notice.
 *
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows*\n
 * \b CPU:   IA-32 and Intel(R) 64 architectures\n
*/
inline Rpc_buffer_wrapper rpc_buffer(const void* mem, size_t size) noexcept
{
    ///
    return {uintptr_t(mem), size, RpcArgFlagsNone};
}

namespace details
{

template< typename T > struct Rpc_arg_type_traits
{
    static constexpr bool is_void   = false;
    static constexpr bool is_buffer = false;
};

template<> struct Rpc_arg_type_traits< void >
{
    static constexpr bool is_void   = true;
    static constexpr bool is_buffer = false;
};

template<> struct Rpc_arg_type_traits< Rpc_buffer_wrapper >
{
    static constexpr bool is_void   = false;
    static constexpr bool is_buffer = true;
};

using t_arg_data                     = decltype(t_rpc_arg::argData);
template< typename T > using t_value = pinrt::std::simple_decay_t< T >;

template< typename ArgType, typename Enable = void > struct Rpc_arg_wrapper;

template< typename T > struct Rpc_arg_wrapper< T*, bool >
{
    static_assert(true, "Pointers are supported only through Rpc_buffer_wrapper");
};
template< typename T > struct Rpc_arg_wrapper< const T*, bool >
{
    static_assert(true, "Pointers are supported only through Rpc_buffer_wrapper");
};
template< typename T > struct Rpc_arg_wrapper< volatile T*, bool >
{
    static_assert(true, "Pointers are supported only through Rpc_buffer_wrapper");
};
template< typename T > struct Rpc_arg_wrapper< const volatile T*, bool >
{
    static_assert(true, "Pointers are supported only through Rpc_buffer_wrapper");
};

template< typename BoolType >
struct Rpc_arg_wrapper< BoolType, pinrt::std::enable_if_t< pinrt::std::is_same< t_value< BoolType >, bool >::value, bool > >
    : t_rpc_arg
{
    template< typename T = BoolType > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = t_arg_data(value);
        argDataSize = 1;
        argSchema   = pinrt::rscschema::Bool_schema::v;
        flags       = RpcArgFlagsNone;
    }
};
template< typename CharType >
struct Rpc_arg_wrapper< CharType, pinrt::std::enable_if_t< pinrt::rscschema::Is_char_type< t_value< CharType > >::value, bool > >
    : t_rpc_arg
{
    template< typename T = CharType > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = t_arg_data(value);
        argDataSize = sizeof(value);
        argSchema   = pinrt::rscschema::Char_schema< t_value< CharType > >::v;
        flags       = RpcArgFlagsNone;
    }
};

template< typename IntType >
struct Rpc_arg_wrapper< IntType, pinrt::std::enable_if_t< pinrt::std::is_integral< t_value< IntType > >::value &&
                                                              (t_value< IntType >(-1) < t_value< IntType >(0)),
                                                          bool > > : t_rpc_arg
{
    template< typename T = IntType > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = t_arg_data(value);
        argDataSize = sizeof(value);
        argSchema   = pinrt::rscschema::Int_schema< t_value< IntType > >::v;
        flags       = RpcArgFlagsNone;
    }
};

template< typename UintType >
struct Rpc_arg_wrapper< UintType, pinrt::std::enable_if_t< pinrt::std::is_integral< t_value< UintType > >::value &&
                                                               (t_value< UintType >(-1) > t_value< UintType >(0)) &&
                                                               !pinrt::std::is_same< t_value< UintType >, bool >::value,
                                                           bool > > : t_rpc_arg
{
    template< typename T = UintType > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = t_arg_data(value);
        argDataSize = sizeof(value);
        argSchema   = pinrt::rscschema::Uint_schema< t_value< UintType > >::v;
        flags       = RpcArgFlagsNone;
    }
};

template< typename FloatType >
struct Rpc_arg_wrapper< FloatType, pinrt::std::enable_if_t< pinrt::std::is_floating_point< t_value< FloatType > >::value, bool > >
    : t_rpc_arg
{
    template< typename T = FloatType > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        static_assert(sizeof(value) <= sizeof(t_arg_data), "pinclient::remote supports floating point type too wide.");

        deleter     = nullptr;
        argDataSize = sizeof(value);
        argSchema   = pinrt::rscschema::Float_schema< t_value< FloatType > >::v;
        flags       = RpcArgFlagsNone;
        memcpy(&argData, &value, sizeof(value));
    }
};

template< typename BufferType >
struct Rpc_arg_wrapper< BufferType, pinrt::std::enable_if_t< Rpc_arg_type_traits< t_value< BufferType > >::is_buffer, bool > >
    : t_rpc_arg
{
    template< typename T = BufferType > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = t_arg_data(value.memory);
        argDataSize = value.size;
        argSchema   = pinrt::rscschema::Buffer_schema::v;
        flags       = value.flags;
    }
};

template< template< typename, class... > class ContainerType, typename ValueType, typename... ExtraTypes >
struct Rpc_arg_wrapper< ContainerType< ValueType, ExtraTypes... >, bool > : t_rpc_arg
{
    static_assert(std::is_standard_layout_v< ValueType >, "Container underlying type must be standard layout");
    template< typename T = ContainerType< ValueType, ExtraTypes... > > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = reinterpret_cast< t_arg_data >(value.data());
        argDataSize = value.size() * sizeof(ValueType);
        argSchema   = pinrt::rscschema::Buffer_schema::v;
        flags       = RpcArgFlagsNone;
    }
};

template< template< typename, class... > class ContainerType, typename ValueType, typename... ExtraTypes >
struct Rpc_arg_wrapper< ContainerType< ValueType, ExtraTypes... >&, bool > : t_rpc_arg
{
    static_assert(std::is_standard_layout_v< ValueType >, "Container underlying type must be standard layout");
    template< typename T = ContainerType< ValueType, ExtraTypes... > > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = reinterpret_cast< t_arg_data >(value.data());
        argDataSize = value.size() * sizeof(ValueType);
        argSchema   = pinrt::rscschema::Buffer_schema::v;
        flags       = RpcArgFlagsNone;
    }
};

template< template< typename, class... > class ContainerType, typename ValueType, typename... ExtraTypes >
struct Rpc_arg_wrapper< const ContainerType< ValueType, ExtraTypes... >&, bool > : t_rpc_arg
{
    static_assert(std::is_standard_layout_v< ValueType >, "Container underlying type must be standard layout");
    template< typename T = ContainerType< ValueType, ExtraTypes... > > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = reinterpret_cast< t_arg_data >(value.data());
        argDataSize = value.size() * sizeof(ValueType);
        argSchema   = pinrt::rscschema::Buffer_schema::v;
        flags       = RpcArgFlagsNone;
    }
};

template<> struct Rpc_arg_wrapper< std::string, bool > : t_rpc_arg
{
    template< typename T = std::string > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = reinterpret_cast< t_arg_data >(value.data());
        argDataSize = value.size() + 1;
        argSchema   = pinrt::rscschema::Buffer_schema::v;
        flags       = RpcArgFlagsNone;
    }
};
template<> struct Rpc_arg_wrapper< std::string&, bool > : t_rpc_arg
{
    template< typename T = std::string > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = reinterpret_cast< t_arg_data >(value.data());
        argDataSize = value.size() + 1;
        argSchema   = pinrt::rscschema::Buffer_schema::v;
        flags       = RpcArgFlagsNone;
    }
};
template<> struct Rpc_arg_wrapper< const std::string&, bool > : t_rpc_arg
{
    template< typename T = std::string > explicit Rpc_arg_wrapper(T&& value) noexcept
    {
        deleter     = nullptr;
        argData     = reinterpret_cast< t_arg_data >(value.data());
        argDataSize = value.size() + 1;
        argSchema   = pinrt::rscschema::Buffer_schema::v;
        flags       = RpcArgFlagsNone;
    }
};

template<> struct Rpc_arg_wrapper< void, bool > : t_rpc_arg
{
    Rpc_arg_wrapper() noexcept
    {
        deleter     = nullptr;
        argData     = 0;
        argDataSize = 0;
        argSchema   = pinrt::rscschema::Nil_schema::v;
        flags       = RpcArgFlagsDataEmpty;
    }
};

struct Out_rpc_arg
{
    template< typename T > static bool copy(const t_rpc_arg& rpcArg, T&& outArg) noexcept
    {
        if (RpcNil == ARG_SCHEMA_TYPE(rpcArg.argSchema) || RpcArgFlagsDataEmpty == rpcArg.flags)
        {
            if constexpr (pinrt::std::is_same< pinrt::std::simple_decay_t< T >, Rpc_buffer_wrapper >::value)
            {
                outArg.flags = RpcArgFlagsDataEmpty;
            }
            return true;
        }

        if constexpr (pinrt::std::is_same< pinrt::std::simple_decay_t< T >, Rpc_buffer_wrapper >::value)
        {
            if (0 == outArg.size || rpcArg.argDataSize <= outArg.size)
            {
                if (RpcBuffer == ARG_SCHEMA_TYPE(rpcArg.argSchema))
                {
                    memcpy((void*)outArg.memory, (void*)rpcArg.argData, rpcArg.argDataSize);
                }
                else
                {
                    memcpy((void*)outArg.memory, (void*)&rpcArg.argData, rpcArg.argDataSize);
                }
                return true;
            }
        }
        else
        {
            if (sizeof(outArg) == rpcArg.argDataSize)
            {
                memcpy(reinterpret_cast< void* >(&outArg), (void*)&rpcArg.argData, sizeof(outArg));
                return true;
            }
        }
        return false;
    }

    template< typename T > static bool copy(const t_rpc_arg& rpcArg, const T& outArg) noexcept
    {
        ASSERTX((RpcNil == ARG_SCHEMA_TYPE(rpcArg.argSchema) || RpcArgFlagsDataEmpty == rpcArg.flags));
        return true;
    }
};
// Recursion end condition - no more arguments to expand
template< size_t IDX, size_t N > inline bool copy_out_rpc_args_recursive(const t_rpc_arg (&)[N]) noexcept { return true; }

// Recursion main while there are arguments in the pack
template< size_t IDX, size_t N, typename ARG_TYPE, typename... Args >
inline bool copy_out_rpc_args_recursive(const t_rpc_arg (&rpcArgs)[N], ARG_TYPE&& arg, Args&&... args) noexcept
{
    bool success = Out_rpc_arg::copy(rpcArgs[IDX], std::forward< ARG_TYPE >(arg));
    return success && copy_out_rpc_args_recursive< IDX + 1 >(rpcArgs, std::forward< Args >(args)...);
}

template< size_t N, typename... Args > inline bool copy_out_rpc_args(const t_rpc_arg (&rpcArgs)[N], Args&&... args) noexcept
{
    static_assert(N >= (sizeof...(Args)), "Pack size incompatible with rpcArgs size");
    ////in the commented code we have the code we wanted to use (leaving it here as reference)
    ////however, due to a bug in GCC < 8.2 the expansion of packs with lambdas as below
    ////doesn't work and produces a compilation error.
    ////Instead we use compile time recursion to take the next argument from the pack and fill it.
    //int argIdx       = 0;
    //bool copySuccess = true;
    //([&]() { copySuccess = copySuccess && Out_rpc_arg::copy(rpcArgs[argIdx++], std::forward< Args >(args)); }(), ...);

    // Use compile time recursion to support older compilers (GCC < 8.2)
    bool copySuccess = copy_out_rpc_args_recursive< 0 >(rpcArgs, std::forward< Args >(args)...);
    return copySuccess;
}

} // namespace details

/*! @ingroup REMOTE
 * @brief Execute an RPC (Remote Procedure Call).
 *
 * This function is a convenience wrapper around PIN_DoRPC(). See PIN_DoRPC() for details.
 * 
 * @tparam SCHEMA       The schema of the RPC to use. Since this is a template argument the schema must be fully
 *                      initialized at compile time. Current implementation does not check the arguments against
 *                      the schema at compile time. This may change in the future.
 * @tparam RetType      The type of the return value of the RPC - The type must be void for this overload.
 *                      When using this overload the type is not automatically deduced and do_rpc() should be called as
 *                      `do_rpc<SCHEMA, void>(...)`.
 * @tparam Flags        Flags modifying the behavior of the RPC.
 *                      If the value is set to PinRpcFlagsNoResponseRequired then no response is expected from the server.
 *                      If the value is set to PinRpcFlagsCanBlockIndefinitely then the RPC can block indefinitely waiting
 *                      for a response.
 *                      If the value is set to PinRpcFlagsNone then the RPC will wait for a response with some "reasonable"
 *                      internal timeout.
 * @tparam Args         Type of arguments - pack automatically deduced
 * @param[in,out] args  RPC arguments 
 * @return bool         True if the RPC request was sent, the server accepted & processed it
 *                      and output arguments were successfully filled. If \a Flags is set to PinRpcFlagsNoResponseRequired then
 *                      the return value is always true if the message was sent.
 * 
 * @note This API is under active development and may change or be removed without notice.
 * 
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows*\n
 * \b CPU:   IA-32 and Intel(R) 64 architectures\n
 */
template< t_rpc_message_schema const& SCHEMA, typename RetType, E_pin_rpc_flags Flags = PinRpcFlagsNone, typename... Args >
inline pinrt::std::enable_if_t< details::Rpc_arg_type_traits< RetType >::is_void, bool > do_rpc(Args&&... args) noexcept
{
    static_assert(RPCID_INVALID != SCHEMA.rpcId);

    constexpr auto RET_IDX                 = sizeof...(Args);
    t_rpc_arg rpcArgs[1 + sizeof...(Args)] = {
        details::Rpc_arg_wrapper< Args, bool > {pinrt::std::forward< Args >(args)}...,
    };

    rpcArgs[RET_IDX] = details::Rpc_arg_wrapper< void, bool > {};

    if (IS_RPC_EXEC_ERROR(PIN_DoRPC(&SCHEMA, rpcArgs, Flags)))
    {
        return false;
    }

    if constexpr (PinRpcFlagsNoResponseRequired == Flags)
    {
        return true; // Can't modify the args if no response was requested
    }
    return details::copy_out_rpc_args(rpcArgs, std::forward< Args >(args)...);
}

/*! @ingroup REMOTE
 * @brief Execute an RPC (Remote Procedure Call).
 *
 * This function is a convenience wrapper around PIN_DoRPC(). See PIN_DoRPC() for details.
 * 
 * @tparam SCHEMA       The schema of the RPC to use. Since this is a template argument the schema must be fully
 *                      initialized at compile time. Current implementation does not check the arguments against
 *                      the schema at compile time. This may change in the future.
 * @tparam RetType      The type of the return value of the RPC - automatically deduced
 *                      If RetType is Rpc_buffer_wrapper then the size member must be 0 or
 *                      big enough to hold the return value. Please not that if size is 0
 *                      then we assume the buffer contains enough space for the return value.
 * @tparam Flags        Flags modifying the behavior of the RPC.
 *                      If the value is set to PinRpcFlagsCanBlockIndefinitely then the RPC can block indefinitely waiting
 *                      for a response.
 *                      If the value is set to PinRpcFlagsNone then the RPC will wait for a response with some "reasonable"
 *                      internal timeout.
 *                      PinRpcFlagsNoResponseRequired cannot be used with non-void return types RPCs.
 * @tparam Args         Type of arguments - pack automatically deduced
 * @param[out] retValue An argument receiving the return value of the RPC
 * @param[in,out] args  RPC arguments 
 * @return              True if the RPC request was sent, the server accepted & processed it
 *                      and output arguments and return value were successfully filled.
 * 
 * @note This API is under active development and may change or be removed without notice.
 * 
 * @par Availability:
 * \b Mode:  JIT & Probe\n
 * \b O/S:   Linux, Windows*\n
 * \b CPU:   IA-32 and Intel(R) 64 architectures\n
 */
template< t_rpc_message_schema const& SCHEMA, typename RetType, E_pin_rpc_flags Flags = PinRpcFlagsNone, typename... Args >
inline pinrt::std::enable_if_t< !details::Rpc_arg_type_traits< RetType >::is_void, bool > do_rpc(RetType& retValue,
                                                                                                 Args&&... args) noexcept
{
    static_assert(PinRpcFlagsNoResponseRequired != Flags, "Non void RPCs cannot use PinRpcFlagsNoResponseRequired");
    static_assert(RPCID_INVALID != SCHEMA.rpcId);

    constexpr auto RET_IDX                 = sizeof...(Args);
    t_rpc_arg rpcArgs[1 + sizeof...(Args)] = {
        details::Rpc_arg_wrapper< Args, bool > {pinrt::std::forward< Args >(args)}...,
    };

    rpcArgs[RET_IDX] = details::Rpc_arg_wrapper< RetType, bool > {std::forward< RetType >(retValue)};

    if (IS_RPC_EXEC_ERROR(PIN_DoRPC(&SCHEMA, rpcArgs, Flags)))
    {
        return false;
    }

    return details::copy_out_rpc_args(rpcArgs, std::forward< Args >(args)..., std::forward< RetType >(retValue));
}

} // namespace remote

#endif

#endif // PIN_G_PIN_RPC_CLIENT_PH