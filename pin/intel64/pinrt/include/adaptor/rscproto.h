/*
 * Copyright (C) 2023-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: librscproto
// <FILE-TYPE>: public header

#ifndef _RSCPROTO_H_
#define _RSCPROTO_H_

#include "rscprotomsgtypes.h"

#define RSC_HMAC_KEY_BITS_LENGTH 256
#define RSC_HMAC_KEY_BYTES_LENGTH RSC_HMAC_KEY_BITS_LENGTH / 8

/**
 * @brief A structure holding an HMAC key
 * 
 */
typedef struct RSC_hmac_key
{
    uint64_t bits[RSC_HMAC_KEY_BYTES_LENGTH / sizeof(uint64_t)];
} t_rsc_hmac_key;

typedef t_rsc_hmac_key t_rsc_key_seed;

/**
 * @brief A structure holding an RSC message counter data
 * 
 */
typedef struct RSC_Message_counter
{
    uint32_t value;
    bool wrapAround;
} t_rsc_message_counter;

typedef uint32_t t_rsc_client_id;
typedef uint16_t t_rsc_message_flags;
typedef uint16_t t_rsc_message_size;
typedef uint32_t t_oob_message_size;

/**
 * @brief Message information read from a message or oob buffer
 * 
 */
typedef struct RSC_message_info
{
    t_rsc_client_id clientId;
    t_rsc_message_counter messageCounter;
    t_rsc_message_flags messageFlags;
    union
    {
        t_oob_message_size oobSize;
        t_rsc_message_size rscSize;
    } messageSize;

} t_rsc_message_info;

/**
 * @brief Common RSC state forward declaration
 * 
 */
typedef struct RSC_common_state t_rsc_common_state;

/**
 * @brief The RSC Server State for a client held on the Server
 * 
 */
typedef struct RSC_server_state t_rsc_server_state;

/**
 * @brief The RSC Client State held on the Client
 * 
 */
typedef struct RSC_client_state t_rsc_client_state;

/**
 * @brief Type for memory allocation function pointer
 * 
 */
typedef void* (*t_rsc_malloc_fn)(size_t);
/**
 * @brief Type for memory free function pointer
 * 
 */
typedef void (*t_rsc_free_fn)(void*);

/**
 * @brief A struct to hold the RSC state
 * 
 * It takes different forms for client and server and should be filled
 * with the corresponding functions
 * 
 * All members are initialized by either @ref initialize_server_state
 * or @ref initialize_client_state.
 * 
 */
typedef struct RSC_state
{
    t_rsc_client_id clientId;
    t_rsc_hmac_key* hmacKey;
    union
    {
        t_rsc_common_state* commonState;
        t_rsc_server_state* serverState;
        t_rsc_client_state* clientState;
    } internalState;
} t_rsc_state;

/**
 * @brief Flags to pass to the decoder
 * 
 * These flags may be combined
 *
 */
typedef enum
{
    RpcDecDefault  = 1 << 0,
    RpcDecResponse = 1 << 1, /** If this flag is specified the RPC message is treated as an RPC response
                              (The decoder expects a return value)*/
    RpcDecZeroCopy = 1 << 2, /** If this flag is set then an argument may point 
                               directly into the message or the OOB buffer. If passing this flag the user
                               must make sure that the memory of the message remains valid until the argument
                               is released by a call to release_rpc_args*/
} E_rpc_decode_flags;

/**
 * @brief Flags to pass to the encoder
 * 
 * These flags may be combined
 *
 */
typedef enum
{
    RpcEncDefault              = 1 << 0, /** Default encoding - a request*/
    RpcEncIntegrityCheckFailed = 1 << 1, /** If this flag is set then the message is an integrity check failed response */
    RpcEncReject               = 1 << 2, /** If this flag is set then the message is a request denial response */
    RpcEncResponse             = 1 << 3, /** If this flag is set then the message is an RPC response */
    RpcEncNoResponseRequired   = 1 << 4, /** If this flag is set then the message is not expected to be answered */
} E_rpc_encode_flags;

/**
 * @brief Error values
 * 
 */
typedef enum
{
    RscErrorSuccess = 0,
    RscErrorEmptyResponse,
    RscErrorBadClientId,
    RscErrorBadCounter,
    RscErrorBadMAC,
    RscErrorBadArg,
    RscErrorReject,
    RscErrorInvalid,
    RscErrorOutOfMemory,
    RscErrorUnexpectedEndOfMessage,
    RscErrorSchemaMismatch,
    RscErrorBadOOBManager,
    RscErrorOOBManagerError,
    RscErrorYes,
    RscErrorNo,
} E_rsc_error;

/**
 * @brief Identify an OOB reference id
 * 
 */
typedef struct RPC_OOB_ref_id
{
    uint8_t* refId;
    size_t refIdSize;
} t_rpc_oob_ref_id;

typedef struct RPC_OOB_data
{
    const t_rpc_oob_ref_id* oobRef;
    void* data;
} t_rpc_oob_data;

/**
 * @brief A structure holding function pointers that must be implemented to support OOB data
 * 
 */
typedef struct RPC_OOB_data_manager
{
    /**
     * @brief The context that is passed to any of the functions of the OOB manager
     * 
     */
    void* oobRefContext;
    /**
     * @brief Allocate a data buffer that can be used for OOB data transfer
     * 
     * @param[in] oobRefContext     the oobRefContext context of this structure
     * @param[in] size              the size of the buffer to allocate
     * @param[out] oobData          a structure filled with the allocated OOB data buffer information
     * 
     * @return The value stored inside the data field of the oobData structure or NULL on error
     */
    void* (*alloc_oob_data_buffer)(void* oobRefContext, size_t size, t_rpc_oob_data* oobData);
    /**
     * @brief Get a pointer to a data buffer referenced by an OOB reference
     * 
     * @param[in] oobRefContext     the oobRefContext context of this structure
     * @param[in] oobRefId          a reference to an OOB data
     * @param[out] oobData          a structure filled with the OOB data buffer information
     * 
     * @return The value stored inside the data field of the oobData structure or NULL on error
     * 
     */
    void* (*fetch_oob_data_buffer)(void* oobRefContext, const t_rpc_oob_ref_id* oobRefId, t_rpc_oob_data* oobData);
    /**
     * @brief Release data previously allocated by alloc_oob_data_buffer
     * 
     * Users should always call this function on data returned from alloc_oob_data_buffer.
     * The allocator of the buffer using alloc_oob_data_buffer should wait for a response to the RPC request using the buffer
     * before calling free_oob_data_buffer.
     * 
     */
    void (*free_oob_data_buffer)(void* oobRefContext, t_rpc_oob_data* oobData);
} t_rpc_oob_data_manager;

/**
 * @brief This structure holds an RSC Message state when encoding a message
 * 
 */
typedef struct RSC_message t_rsc_message;

/*
 * When using librscproto follow these steps (not including error handling):
 * 
 * Server:
 * Call initialize_server_state() to initialize the state for a client
 * 
 * For each message:
 * Call rsc_message_get_info() to get information about the message
 * Check it the client id is known
 * Check the validity of the message using check_rsc_request_message()
 * Update the state by calling update_rs_server_state()
 * Get the RPC ID using rsc_message_get_rpc_id()
 * Decode the message using decode_rsc_rpc_message()
 * If OOB references are supported and we have OOB ref args we should check them using: check_oob_ref_arg()
 * Execute the RPC
 * Create a new response with initialize_rsc_message()
 * Add an rpc response indicator with add_rsc_rpc_request()
 * For each argument and for the return value use add_rpc_arg()
 * Encode the message to a buffer using encode_rsc_message()
 * Send the response
 * Release the response with release_rsc_message()
 * 
 * Client:
 * Call initialize_client_state() to initialize the state of the client
 * 
 * When sending a message:
 * Create an RSC message using initialize_rsc_message()
 * Add an RPC request using add_rsc_rpc_request()
 * For each argument use add_rpc_arg()
 * Get the message counter using increment_rsc_message_counter()
 * Encode the message to a buffer using encode_rsc_message()
 * Send the request
 * Release the request with release_rsc_message()
 * Read the response message
 * Check the response using check_rsc_response_message()
 * Get the RPC ID from the response using rsc_message_get_rpc_id()
 * Decode the response using decode_rsc_rpc_message()
 * 
 */

#if defined(__cplusplus)
extern "C"
{
#endif

    /**
     * @brief Initialize the RSC Server state for a client
     * 
     * @param[in]  clientId      The Client ID for which to initialize the state
     * @param[in]  keySeed       A RSC_HMAC_KEY_BITS_LENGTH random bits.
     *                           If nullptr is passed then no MAC authentication will be used.
     *                           The server and client should be initialized with the same value.
     * @param[in]  windowSize    The size for the message counter window.
     *                           The minimum size is 64 and the maximum size is 256 (according to the RSC protocol specification)
     * @param[in]  memAlloc      A pointer to a user defined memory allocation function to be used
     *                           when allocating memory for operations related to this server state.
     *                           If NULL is passed then an internal memory allocation will be used.
     *                           If this argument is not NULL then also \a memFree must be specified.
     * @param[in]  memFree       A pointer to a user defined memory freeing function to be used
     *                           when freeing memory allocated using \a memAlloc.
     *                           If NULL is passed then an internal memory freeing function will be used.
     *                           If this argument is not NULL then also \a memAlloc must be specified.
     * @param[out] serverState   The server state to initialize - all fields are overwritten
     * @return  RscErrorSuccess:    success
     *          RscErrorInvalid:    internal error
     * 
     * This function should be called by an RSC Server to initialize the state it holds for a client
     */
    E_rsc_error initialize_server_state(t_rsc_client_id clientId, const t_rsc_key_seed* keySeed, uint32_t windowSize,
                                        t_rsc_malloc_fn memAlloc, t_rsc_free_fn memFree, t_rsc_state* serverState) NOEXCEPT;

    /**
     * @brief Release any memory allocated by initialize_server_state
     * 
     * @param[in] serverState The server state. All fields are invalid once this function returns
     */
    void release_server_state(t_rsc_state* serverState) NOEXCEPT;

    /**
     * @brief Initialize the RSC Client state for a client
     * 
     * @param[in]  clientId      The Client ID for which to initialize the state
     * @param[in]  keySeed       A RSC_HMAC_KEY_BITS_LENGTH random bits
     *                           If nullptr is passed then no MAC authentication will be used.
     *                           The server and client should be initialized with the same value.
     * @param[in]  memAlloc      A pointer to a user defined memory allocation function to be used
     *                           when allocating memory for operations related to this server state.
     *                           If NULL is passed then an internal memory allocation will be used.
     *                           If this argument is not NULL then also \a memFree must be specified.
     * @param[in]  memFree       A pointer to a user defined memory freeing function to be used
     *                           when freeing memory allocated using \a memAlloc.
     *                           If NULL is passed then an internal memory freeing function will be used.
     *                           If this argument is not NULL then also \a memAlloc must be specified.
     * @param[out] clientState  The client state to initialize - all fields are overwritten
     * @return  RscErrorSuccess:    success
     *          RscErrorInvalid:    internal error
     * 
     * This function should be called by an RSC Client to initialize it's own state
     * 
     */
    E_rsc_error initialize_client_state(t_rsc_client_id clientId, const t_rsc_key_seed* keySeed, t_rsc_malloc_fn memAlloc,
                                        t_rsc_free_fn memFree, t_rsc_state* clientState) NOEXCEPT;

    /**
     * @brief Release any memory allocated by initialize_client_state
     * 
     * @param[in] clientState The client state. All fields are invalid once this function returns
     */
    void release_client_state(t_rsc_state* clientState) NOEXCEPT;

    /**
     * @brief Get information the message's RSC integrity header
     * 
     * @param[in]   rscMessage        The RSC message
     * @param[in]   rscMessageSize    The size of the RSC message
     * @param[out]  messageInfo      Receives the message information
     * @return  RscErrorSuccess:                success
     *          RscErrorUnexpectedEndOfMessage: message buffer too small
     *          RscErrorInvalid:                internal error
     */
    E_rsc_error rsc_message_get_info(const uint8_t* rscMessage, size_t rscMessageSize, t_rsc_message_info* messageInfo) NOEXCEPT;

    /**
     * @brief Check if a response is required for a message
     * 
     * @param[in] messageInfo   The RSC message information retrieved with a call to rsc_message_get_info
     * @return  RscErrorYes:                    Response is required
     *          RscErrorNo:                     Response is not required
     *          RscErrorInvalid:                internal error (messageInfo is NULL or invalid)
     */
    E_rsc_error rsc_is_response_required(const t_rsc_message_info* messageInfo) NOEXCEPT;

    /**
     * @brief Check an RSC Message
     * 
     * @param[in,out]   rscMessage    The RSC message to check. During the check the MAC bytes are zeroed.
     * @param[in]       rscMessageSize    The size of the RSC message
     * @param[in,out]   serverState   The serverState may change as a result of the check.
     * @return  RscErrorSuccess:                success
     *          RscErrorUnexpectedEndOfMessage: message buffer too small
     *          RscErrorBadClientId:            the client id in the request is different than expected
     *          RscErrorBadCounter:             the counter in the request is either a replay or outside the counter window
     *          RscErrorBadMAC:                 MAC calculation on the request failed
     *          RscErrorInvalid:                internal error
     */
    E_rsc_error check_rsc_request_message(uint8_t* rscMessage, size_t rscMessageSize, t_rsc_state* serverState) NOEXCEPT;

    /**
     * @brief Check an RSC Response
     * 
     * @param[in,out]   rscMessage    The RSC message to check. During the check the MAC bytes are zeroed.
     * @param[in]       rscMessageSize    The size of the RSC message
     * @param[in]       messageCounter    The message counter expected in the response (the samethat was specified in the request)
     * @param[in]       clientState       The client state
     * @return  RscErrorSuccess:                success
     *          RscErrorUnexpectedEndOfMessage: message buffer too small
     *          RscErrorBadClientId:            the client id in the response is different from the one in the request
     *          RscErrorBadCounter:             the counter in the response is different from the one in the request
     *          RscErrorBadMAC:                 MAC calculation on the response failed, or the response message has indication
     *                                          for MAC failure calculated on the request
     *          RscErrorReject:                 The request was valid but has been denied
     *          RscErrorInvalid:                internal error
     */
    E_rsc_error check_rsc_response_message(uint8_t* rscMessage, size_t rscMessageSize, t_rsc_message_counter messageCounter,
                                           const t_rsc_state* clientState) NOEXCEPT;

    /**
     * @brief Increment the message counter and update the state accordingly.
     * 
     * @param[out]    messageCounter    The message counter value and wrap around flag before increment
     * @param[in,out] clientState       The client state
     * @return  RscErrorSuccess:    success
     *          RscErrorInvalid:    internal error
     */
    E_rsc_error increment_rsc_message_counter(t_rsc_message_counter* messageCounter, t_rsc_state* clientState) NOEXCEPT;

    /**
     * @brief Check the buffer of an OOB referece argument
     * 
     * @param[in] messageInfo       The RSC message information retrieved with 
     *                              a call to rsc_message_get_info
     * @param[in] oobManager        The OOB Manager used to retrieve the OOB data
     * @param[in] hmacKey           The key use to calculate the MAC
     * @param[in] oobArg            The argument with the OOB reference
     * @return E_rsc_error 
     */
    E_rsc_error check_oob_ref_arg(const t_rsc_message_info* messageInfo, t_rpc_oob_data_manager* oobManager,
                                  const t_rsc_hmac_key* hmacKey, t_rpc_arg* oobArg) NOEXCEPT;

    /**
     * @brief Get the RPC id field from the message's RPC payload
     * 
     * @param[in]  rscMessage        The RSC message
     * @param[in]  rscMessageSize    The size of the RSC message
     * @param[out] rpcId            Receives the client id
     * @return  RscErrorSuccess:                success
     *          RscErrorUnexpectedEndOfMessage: message buffer too small
     *          RscErrorInvalid:                internal error
     */
    E_rsc_error rsc_message_get_rpc_id(const uint8_t* rscMessage, size_t rscMessageSize, t_rpc_id* rpcId) NOEXCEPT;

    /**
     * @brief Given an rsc message extract the argument data from the RPC payload
     * 
     * @param[in]     state             RSC State. This value cannot be NULL.
     * @param[in]     rscMessage        The RSC message to check
     * @param[in]     rscMessageSize    The size of the RSC message
     * @param[in]     schema            The schema used to decode the message.
     *                                  If nullptr is passed then the message is decoded without a schema.
     * @param[in]     flags             Decode flags affecting the decoding
     * @param[out]    argCount          The number of arguments read.
     * @param[in,out] args              An array of decoded arguments.
     *                                  Please note that if the message is decoded as a response then the returned args array
     *                                  should have (schema->argCount + 1) args since there is an additional arg, the return value.
     *                                  If *args==nullptr then the function will allocate the args array. In this case,
     *                                  please remember to pass the correct arg count to release_rpc_args().
     * @return  RscErrorSuccess:                success
     *          RscErrorUnexpectedEndOfMessage: message buffer too small
     *          RscErrorSchemaMismatch:         mismatch between the decoded arg and the expected arg from the schema
     *          RscErrorOutOfMemory:            failed to allocate memory for the args
     *          RscErrorInvalid:                internal error
     */
    E_rsc_error decode_rsc_rpc_message(const t_rsc_state* state, const uint8_t* rscMessage, size_t rscMessageSize,
                                       const t_rpc_message_schema* schema, E_rpc_decode_flags flags, size_t* argCount,
                                       t_rpc_arg** args) NOEXCEPT;

    /**
     * @brief Release memory of arguments allocated by decode_rsc_rpc_message optionally also releasing the \a args array
     * 
     * This function should be called on the args returned/filled by @ref decode_rsc_rpc_message
     * even if a pre-allocated @ref t_rpc_arg_array was passed to @ref decode_rsc_rpc_message
     * because @ref decode_rsc_rpc_message may allocate memory for the actual data
     * wrapped by the arguments array.
     * 
     * @param[in]     state                 RSC State used when calling @ref decode_rsc_rpc_message
     * @param[in,out] args                  An array of arguments allocates by decode_rsc_rpc_message
     * @param[in]     argCount              The number of arguments in \a args
     * @param[in]     avoidReleasingArgs    If true, the args array itself is not released. This argument
     *                                      should be true if args was not allocated by @ref decode_rsc_rpc_message
     */
    void release_rpc_args_ex(const t_rsc_state* state, t_rpc_arg* args, size_t argCount, bool avoidReleasingArgs) NOEXCEPT;

    /**
     * @brief Release memory of arguments allocated by decode_rsc_rpc_message including the \a args array
     * 
     * This function should be called on the args returned/filled by @ref decode_rsc_rpc_message
     * 
     * @param[in]     state                 RSC State used when calling @ref decode_rsc_rpc_message
     * @param[in,out] args                  An array of arguments allocates by decode_rsc_rpc_message
     * @param[in]     argCount              The number of arguments in \a args
     * 
     * \sa release_rpc_args_ex
     */
    inline void release_rpc_args(const t_rsc_state* state, t_rpc_arg* args, size_t argCount) NOEXCEPT
    {
        release_rpc_args_ex(state, args, argCount, false);
    }

    /**
     * @brief Allocate a t_rsc_message object to track RSC message encoding 
     * 
     * @param[in,out]   state        The client or server state.
     * @param[out]      rscMessage   The RSC message encoder state
     * @return  RscErrorSuccess:        success
     *          RscErrorOutOfMemory:    Failed to allocate memory for the message
     *          RscErrorInvalid:        internal error
     */
    E_rsc_error initialize_rsc_message(t_rsc_state* state, t_rsc_message** rscMessage) NOEXCEPT;

    /**
     * @brief Release memory of a previously allocated RSC message
     * 
     * @param[in] rscMessage   The RSC message to release
     */
    void release_rsc_message(t_rsc_message* rscMessage) NOEXCEPT;

    /**
     * @brief Indicate the RSC message has an RPC payload
     * 
     * @param[in] rscMessage    The RSC Message encoder state
     * @param[in] rpcId         The ID of the RPC request
     * @return  RscErrorSuccess:    success
     *          RscErrorInvalid:    internal error
     */
    E_rsc_error add_rsc_rpc_request(t_rsc_message* rscMessage, t_rpc_id rpcId) NOEXCEPT;

    /**
     * @brief Add an RPC argument to the message
     * 
     * @param[in] rscMessage    The RSC Message encoder state
     * @param[in] rpcArg        A pointer to an RPC argument.
     * @return  RscErrorSuccess:        success
     *          RscErrorBadArg:         Exceed max number of args (15)
     *          RscErrorSchemaMismatch: Mismatch between the arg data and its schema
     *          RscErrorOutOfMemory:    Failed to allocate memory for storing the arg
     *          RscErrorInvalid:        internal error
     */
    E_rsc_error add_rpc_arg(t_rsc_message* rscMessage, t_rpc_arg* rpcArg) NOEXCEPT;

    /**
     * @brief Take the RSC Message encoder state and encode the message to a buffer
     * 
     * @param[in]       rscMessage            The RSC Message encoder state
     * @param[in,out]   rscMessageBuffer      A buffer into which to encode the message.
     *                                        If this value is NULL then the required buffer size is
     *                                        written to rscMessageBufferSize
     * @param[in,out]   rscMessageBufferSize  The size of rscMessageBuffer. 
     *                                        If rscMessageBuffer is NULL then the passed value is not used.
     *                                        This arg will always be updated to the size of the encoded message.
     * @param[in]       messageCounter            The message counter to write to the message
     * @param[in]       hmacKey                   The MAC calculation key
     * @param[in]       flags                 Encoding flags (default = RpcEncDefault)
     * @return  RscErrorSuccess:                success
     *          RscErrorUnexpectedEndOfMessage: message buffer too small
     *          RscErrorBadMAC:                 MAC calculation failed
     *          RscErrorInvalid:                internal error
     */
    E_rsc_error encode_rsc_message(const t_rsc_message* rscMessage, uint8_t* rscMessageBuffer, size_t* rscMessageBufferSize,
                                   t_rsc_message_counter messageCounter, const t_rsc_hmac_key* hmacKey,
                                   E_rpc_encode_flags flags
#if defined(__cplusplus)
                                   = RpcEncDefault
#endif
                                   ) NOEXCEPT;

    /**
     * @brief Return a string representing the input error code
     * 
     * @param error         The error code
     * @return const char*  The string representing the error code
     */
    const char* E_rsc_error_to_string(E_rsc_error error) NOEXCEPT;

#if defined(__cplusplus)
}
#endif

#endif // _RSCPROTO_H_

/********************************************************
 * How to use RpcRecord and RpcArray args
 ********************************************************
 *
 * Record and array arg examples can be found in the unitest (unitest_test_encode_decode_record_array.cpp).
 * 
 * Constructing Record args and schemas
 * -----------------------------------
 * Please see below an example for how to define an RpcRecord arg and how to decode a message using a record schema.
 * The example refers to a record like this:
 * 
 *      struct record
 *      {
 *          uint32_t  ui32;
 *          float     f;
 *      };
 *
 * Args and schemas for encoding:
 *  o   arg->argSchema.type = RpcRecord
 *  o   arg.argDataSize     = The number of members in the record ( in this example 2)
 *  o   arg.argData         = The address of an array of t_rpc_arg elements (in this example 2), one per each record member
 *
 * Args and schemas for decoding:
 *  o   messageSchema.argCount          = 1 , since we want to read this as a single arg
 *  o   messageSchema.argSchemaArray    = an array of 3 schemas, one for the RpcRecord and another 2 for the record members
 *  o   messageSchema.returnValueSchema = one schema for the return value (may be nil)
 *     
 *   t_rpc_arg_schema schemas[] = {
 *       RECORD_ARG_SCHEMA(2), 
 *       UINT_ARG_SCHEMA(uint32_t),
 *       FLOAT_ARG_SCHEMA(float)
 *   };
 *
 *   t_rpc_message_schema decodeMsgSchema = {rpcId, 1, schemas, NIL_ARG_SCHEMA()};
 *
 *   float fValue = 123.456f;
 *
 *   t_rpc_arg_schema schemaUint32 = UINT_ARG_SCHEMA(uint32_t);
 *   t_rpc_arg_schema schemaFloat  = FLOAT_ARG_SCHEMA(float);
 *
 *   t_rpc_arg memberArgs[] = {{&schemaUint32,  0xdeadbeef,          schemaUint32.size, 0},
 *                             {&schemaFloat,   *(uint32_t*)&fValue, schemaFloat.size,  0}};
 *
 *   t_rpc_arg recordArg;
 *   recordArg.argData     = reinterpret_cast< uint64_t >(&(memberArgs[0]));
 *   recordArg.argDataSize = 2;
 *   recordArg.argSchema   = schemas;
 *   recordArg.flags       = 0;
 * 
 * 
 * 
 * Constructing Array args and schemas
 * -----------------------------------
 * Please see below an example for how to define an RpcArray arg and how to decode a message using an array schema.
 * The example refers to an array like this:
 * 
 *      const char* arr[5] = {"one", "two", "three", "four", "five"};
 *
 * Args and schemas for encoding:
 *  o   arg->argSchema.type = RpcArray
 *  o   arg.argDataSize     = The number of elements in the array ( in this example 5)
 *  o   arg.argData         = The address of an array of t_rpc_arg elements (in this example 5), one per each element
 *
 * Args and schemas for decoding:
 *  o   messageSchema.argCount          = 1 , since we want to read this as a single arg
 *  o   messageSchema.argSchemaArray    = an array of 2 schemas, one for the RpcArray one that describes the array element
 *  o   messageSchema.returnValueSchema = one schema for the return value (may be nil)
 *
 *  t_rpc_arg_schema bufferSchema = BUFFER_ARG_SCHEMA();
 *  t_rpc_arg_schema arraySchema  = ARRAY_ARG_SCHEMA();
 *
 *  // Args for the array elements
 *  t_rpc_arg elemArgs[] = {{&bufferSchema, reinterpret_cast< uint64_t >(arr[0]), 1 + strlen(arr[0]), 0},
 *                          {&bufferSchema, reinterpret_cast< uint64_t >(arr[1]), 1 + strlen(arr[1]), 0},
 *                          {&bufferSchema, reinterpret_cast< uint64_t >(arr[2]), 1 + strlen(arr[2]), 0},
 *                          {&bufferSchema, reinterpret_cast< uint64_t >(arr[3]), 1 + strlen(arr[3]), 0},
 *                          {&bufferSchema, reinterpret_cast< uint64_t >(arr[4]), 1 + strlen(arr[4]), 0}};
 *
 *  // Arg for the array itself
 *  t_rpc_arg arrayArg;
 *  arrayArg.argData     = reinterpret_cast< uint64_t >(&(elemArgs[0]));
 *  arrayArg.argDataSize = 1;
 *  arrayArg.argSchema   = &arraySchema;
 *  arrayArg.flags       = 0;
 *
 *  // A schema array at size 2 (for all array sizes)
 *  t_rpc_arg_schema decodeSchema[] = {arraySchema, bufferSchema};
 *  t_rpc_message_schema msgSchema = {rpcId, 1, decodeSchema, NIL_ARG_SCHEMA()};
 * 
 * 
 * 
 * Limitations for RpcRecord and RpcArray
 * --------------------------
 * 
 * The library does not support nested records or arrays. i.e., a records field cannot be a record itself.
 * For example this is not supported:
 * 
 *  struct record
 *  {
 *      uint32_t ui32;
 *      float f;
 *      struct record2      // a nested record
 *      {
 *          double d;
 *          uint8_t ui8;
 *      };
 *  };
 * 
 * Also, arrays are a form of record.
 * An array of N elements is like a record with N members all of the same type.
 * Therefore the below is also not supported:
 * 
 *  struct record
 *  {
 *      uint32_t ui32;
 *      float f;
 *      char str[10];       // an array
 *  };
 * 
 */
