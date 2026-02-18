/*
 * Copyright (C) 2024-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: librscproto
// <FILE-TYPE>: public header

#ifndef _RSCPROTOMSGTYPES_H_
#define _RSCPROTOMSGTYPES_H_

/*! @file
 *
 * Types for RSC RPC protocol messages.
 * 
 * See @ref REMOTE section in Pin User Manual
 * 
 * @note APIs declared in this file are under active development and are subject 
 *       to change or removal without notice
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

/**
 * @ingroup REMOTE
 * 
 * @brief The type of RSC RPC argument
 * 
 * This is the type we wish to encode from/decode to not the type inside the RSC RPC Message.
 * For instance RpcInt might be encoded as int4, int12, varint, int4_neg, int12_neg or varint_neg
 * 
 */
typedef enum E_rpc_arg_type
{
    RpcBoolean = 0,     //!< Boolean argument type
    RpcInt,             //!< Integer (possibly negative) argument type
    RpcUInt,            //!< Unsigned integer argument type
    RpcChar,            //!< Character argument type (char, wchar_t, char16_t, char32_t)
    RpcFloat,           //!< Floating point argument type (float, double, long double)
    RpcBuffer,          //!< A memory buffer argument type
    RpcOOBRef,          //!< Currently not supported
    RpcRecord,          //!< A record argument type that may contain members of other types
                        //!< A record may contain upto 4095 members.
                        //!< Nested records are currently not supported
    RpcArray,           //!< An array argument which may contain upto 4095 entries of the same type
    RpcNil,             //!< Indicates no data argument
    RpcVoid = RpcNil,   //!< The same as RpcNil
    RpcPaddingNoEncode, /**< This type of argument is can be used to describe padding for a record argument.
                         *   The decoder will use it when constructing the record layout in memory
                         */
} E_rpc_arg_type;

/**
 * @ingroup REMOTE
 * 
 * @brief Flags affecting the encoding of RPC arguments
 * 
 */
typedef enum E_rpc_arg_flags
{
    RpcArgFlagsNone = 0,     //!< Does not modify argument encoding behavior
                             //!<
    RpcArgFlagsDataEmpty = 1 //!< Indicate that the argument has no encodable/decodable data
                             //!< If this value is set on encode then the argument will be encoded as RpcNil
                             //!< If this value is set returning from decode then the argument does not contain
                             //!< valid data.
                             //!<

} E_rpc_arg_flags;

/**
 * @ingroup REMOTE
 * 
 * @brief Type of RPC Ids
 * 
 */
typedef uint32_t t_rpc_id;
/**
 * @ingroup REMOTE
 * 
 * @brief Type of RPC argument count
 * 
 */
typedef uint8_t t_arg_count;
/**
 * @ingroup REMOTE
 * 
 * @brief Type of RPC argument schema
 * 
 */
typedef uint32_t t_rpc_arg_schema;

/**
 * @ingroup REMOTE
 * 
 * @brief A collection of RPC_arg_schema structures together describing an RPC message 
 * 
 */
typedef struct RPC_message_schema
{
    /**
     * @brief The RPC Id of the message
     * 
     */
    t_rpc_id rpcId;
    /**
     * @brief The number of arguments in the RPC request message
     * 
     */
    t_arg_count argCount;
    /**
     * @brief An array of RPC_arg_schema of length argCount
     * 
     */
    t_rpc_arg_schema* argSchemaArray;
    /**
     * @brief An RPC_arg_schema describing the RPC return value
     * 
     */
    t_rpc_arg_schema returnValueSchema;
} t_rpc_message_schema;

/**
 * @ingroup REMOTE
 * 
 * @brief TStructure to hold the actual data to encode or the actual data of a decoded argument
 * 
 */
typedef struct RPC_arg
{
    /**
     * @brief The actual data of the argument.
     * 
     * The interpretation of this field varies.
     * 
     * If argDataSize <= sizeof(uint64_t) then the actual data is stored inside the argData variable
     * If argDataSize > sizeof(uint64_t) then argData holds the value of a pointer to the memory actually
     * holding the data.
     * For RpcBuffer, argData always holds the value of a pointer to the memory holding the buffer.
     * For RpcRecord and RpcArray, argData holds the value of a pointer to an array of t_rpc_arg, 
     * an arg for each record member/array element,
     * and argDataSize holds the number of array elements / number of record members.
     * For how to encode and decode records and arrays, see a section at the bottom of the file.
     */
    uint64_t argData;
    /**
     * @brief The size of data in/pointed to by argData
     * 
     */
    size_t argDataSize;
    /**
     * @brief Deleter function pointer to be used to release argument data.
     * 
     * If this value is NULL then the free function defined in the rsc state will be used.
     */
    void (*deleter)(void*);
    /**
     * @brief A schema describing the argument
     * 
     */
    t_rpc_arg_schema argSchema;
    /**
     * @brief Encode/Decode flags for the argument.
     * 
     */
    E_rpc_arg_flags flags;
} t_rpc_arg;

#if defined(__cplusplus)
static_assert(sizeof(t_rpc_arg().argData) >= sizeof(uintptr_t),
              "argData cannot contain uintptr_t"); // make sure a pointer can fit into argData
#endif

typedef t_rpc_arg t_rpc_ret;

/**
 * @ingroup REMOTE
 * 
 * \def RPCID_INVALID
 * @brief Indicates an Invalid RPC Id
 * 
 * This RPC Id is used internally
 */
#define RPCID_INVALID (t_rpc_id)(0xFFFFFFFF)

/**
 * @ingroup REMOTE
 * 
 * \def RPCID_MIN
 * @brief The smallest RPC Id available for Pintool developers
 * 
 * RPC Ids less than RPCID_MIN are reserved for Pin
 */
#define RPCID_MIN (t_rpc_id)(2048)

/**
 * @ingroup REMOTE
 * 
 * \def RPCID_MAX
 * @brief The largest valid RPC Id available for Pintool developers
 * 
 * RPC Ids greater than RPCID_MAX are reserved for Pin
 */
#define RPCID_MAX (t_rpc_id)(RPCID_INVALID - 1025)

/**
 * @ingroup REMOTE
 * 
 * \def RPCID_RESERVED_LOW_RANGE_START
 * @brief Start of reserved the low range
 * 
 */
#define RPCID_RESERVED_LOW_RANGE_START (t_rpc_id)(0x00000000)
/**
 * @ingroup REMOTE
 * 
 * \def RPCID_RESERVED_LOW_RANGE_END
 * @brief End of reserved the low range
 * 
 */
#define RPCID_RESERVED_LOW_RANGE_END (t_rpc_id)(RPCID_MIN - 1)
/**
 * @ingroup REMOTE
 * 
 * \def RPCID_RESERVED_HIGH_RANGE_START
 * @brief Start of reserved the high range
 * 
 */
#define RPCID_RESERVED_HIGH_RANGE_START (t_rpc_id)(RPCID_MAX + 1)
/**
 * @ingroup REMOTE
 * 
 * \def RPCID_RESERVED_HIGH_RANGE_END
 * @brief End of reserved the high range
 * 
 */
#define RPCID_RESERVED_HIGH_RANGE_END (t_rpc_id)(RPCID_INVALID - 1)

/**
 * @ingroup REMOTE
 * 
 * \def RPCID_IS_VALID(rpcId)
 * @brief Check if an RPC Id is valid
 * 
 */
#define RPCID_IS_VALID(rpcId) ((rpcId) >= RPCID_MIN && (rpcId) <= RPCID_MAX)
/**
 * @ingroup REMOTE
 * 
 * \def RPCID_IS_RESERVED_LOW(rpcId)
 * @brief Check if an RPC Id is reserved in the low range
 * 
 */
#define RPCID_IS_RESERVED_LOW(rpcId) ((rpcId) >= RPCID_RESERVED_LOW_RANGE_START && (rpcId) <= RPCID_RESERVED_LOW_RANGE_END)
/**
  * @ingroup REMOTE
  * 
  * \def RPCID_IS_RESERVED_HIGH(rpcId)
  * @brief Check if an RPC Id is reserved in the high range
  * 
  */
#define RPCID_IS_RESERVED_HIGH(rpcId) ((rpcId) >= RPCID_RESERVED_HIGH_RANGE_START && (rpcId) <= RPCID_RESERVED_HIGH_RANGE_END)
/**
 * @ingroup REMOTE
 * 
 * \def RPCID_IS_RESERVED(rpcId)
 * @brief Check if an RPC Id is reserved
 * 
 */
#define RPCID_IS_RESERVED(rpcId) (RPCID_IS_RESERVED_LOW(rpcId) || RPCID_IS_RESERVED_HIGH(rpcId))

/**
 * @ingroup REMOTE
 * 
 * \def RSC_RPC_MESSAGE_SCHEMA(rpcid, argCount, ...)
 * @brief Helper macro for creating a t_rpc_message_schema
 * 
 */
#define RSC_RPC_MESSAGE_SCHEMA(rpcId, argCount, ...) \
    {                                                \
        (rpcId), (argCount), ##__VA_ARGS__           \
    }

/**
 * @ingroup REMOTE
 * 
 * \def MAKE_ARG_SCHEMA(rpcType, size)
 * @brief Helper macro for creating t_rpc_arg_schema
 * 
 */
#define MAKE_ARG_SCHEMA(rpcType, size) \
    (t_rpc_arg_schema)(((uint32_t)rpcType & 0x000000FFU) | (((uint32_t)size & 0x00001FFF) << 16))

#define BOOL_ARG_SCHEMA() MAKE_ARG_SCHEMA(RpcBoolean, 1)
#define INT_ARG_SCHEMA(type) MAKE_ARG_SCHEMA(RpcInt, sizeof(type))
#define UINT_ARG_SCHEMA(type) MAKE_ARG_SCHEMA(RpcUInt, sizeof(type))
#define CHAR_ARG_SCHEMA(type) MAKE_ARG_SCHEMA(RpcChar, sizeof(type))
#define FLOAT_ARG_SCHEMA(type) MAKE_ARG_SCHEMA(RpcFloat, sizeof(type))
#define BUFFER_ARG_SCHEMA() MAKE_ARG_SCHEMA(RpcBuffer, sizeof(uint32_t))
#define PADDING_ARG_SCHEMA(size) MAKE_ARG_SCHEMA(RpcPaddingNoEncode, size)
#define NIL_ARG_SCHEMA() MAKE_ARG_SCHEMA(RpcNil, 0)
#define ARRAY_ARG_SCHEMA() MAKE_ARG_SCHEMA(RpcArray, 0)
#define RECORD_ARG_SCHEMA(memberCount, ...) MAKE_ARG_SCHEMA(RpcRecord, memberCount), ##__VA_ARGS__

/**
 * @ingroup REMOTE
 * 
 * \def ARG_SCHEMA_TYPE(argSchema)
 * @brief Get the type of an RPC argument schema
 * 
 */
#define ARG_SCHEMA_TYPE(argSchema) ((E_rpc_arg_type)(argSchema & 0x000000FFU))
/**
 * @ingroup REMOTE
 * 
 * \def ARG_SCHEMA_SIZE(argSchema)
 * @brief Get the size of an RPC argument schema
 * 
 */
#define ARG_SCHEMA_SIZE(argSchema) ((size_t)((argSchema >> 16) & 0x00000FFFU))

#define MAKE_RPC_ARG_EX(argSchema, argData, argDataSize, flags, deleter) \
    {                                                                    \
        argData, argDataSize, deleter, argSchema, flags                  \
    }
#define MAKE_RPC_ARG(argSchema, argData, argDataSize, flags) MAKE_RPC_ARG_EX(argSchema, argData, argDataSize, flags, 0)

/**
 * @ingroup REMOTE
 * 
 * @brief Offset of RPC arguments from start of message
 * 
 */
#define RSC_RPC_DATA_OFFSET 48

#if !DOXYGEN

#if defined(__cplusplus)
extern "C"
{
#endif // __cplusplus

    /**
     * @ingroup REMOTE
     * 
     * @brief Return the maximum size the encoded metatdata for a given argument schema can occupy
     * 
     * @param[in] argSchema The argument schema for which to calculate the metadata size
     * @return size_t the maximum encoded metatdata size
     */
    inline size_t max_arg_metadata_size(const t_rpc_arg_schema* argSchema) NOEXCEPT
    {
        size_t maxSize = 1;
        switch (ARG_SCHEMA_TYPE(*argSchema))
        {
            case RpcBuffer:
                maxSize += sizeof(uint32_t);
                break;
            case RpcRecord:
            {
                ++maxSize; // Size is int12
            }
            break;
            case RpcArray:
            {
                // For array the schema does not hold enough information at this time
                // The maximum entry count is 4095. The maximum metadata size for any argument is 5
                size_t arrayLength = ARG_SCHEMA_SIZE(*argSchema) ? ARG_SCHEMA_SIZE(*argSchema) : 4095;
                maxSize += 1 + arrayLength * 5; // 1 more byte for the int12 size + metadata size for array entries
            }
            break;
            default:
                break;
        }
        return maxSize;
    }

    /**
     * @ingroup REMOTE
     * 
     * @brief Calculate the minimum size available for data given a message schema
     * 
     * An RSC/RPC message can be of a maximum size of 64KB. However the actual size
     * available for data in a message is 64KB - RSC_RPC_DATA_OFFSET - (size of argument encoding metadata).
     * This function calculates the maximum possible size that the argument encoding metadata will take and returns
     * a safe estimate to the size in bytes actually available for encoding. The actual available
     * size may be greater than the returned value.
     * 
     * @param[in] schema The message schema for which to calculate the metadata overhead 
     * @return size_t - The minimum available size for data given a schema. 
     */
    inline size_t calculate_rpc_data_space(const t_rpc_message_schema* schema, size_t maxsize) NOEXCEPT
    {
        if (!schema)
        {
            return 0;
        }

        size_t metaDataSize = max_arg_metadata_size(&schema->returnValueSchema);

        const t_rpc_arg_schema* argSchemaArray = schema->argSchemaArray;
        int argCount                           = schema->argCount;
        for (int i = 0; i < argCount; ++i)
        {
            metaDataSize += max_arg_metadata_size(&argSchemaArray[i]);
            if (RpcRecord == ARG_SCHEMA_TYPE(argSchemaArray[i]))
            {
                // We need to calculate also the size of the record members
                // increase the count of elements we go over
                argCount += ARG_SCHEMA_SIZE(argSchemaArray[i]);
            }
        }
        size_t ret = maxsize - (metaDataSize + RSC_RPC_DATA_OFFSET);
        return ret < (maxsize - RSC_RPC_DATA_OFFSET) ? ret : 0;
    }

#if defined(__cplusplus)
}
#endif // __cplusplus

#endif // !DOXYGEN

#endif // _RSCPROTOMSGTYPES_H_