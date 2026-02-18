/*
 * Copyright (C) 2023-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef _IPIND_PLUGIN_H_
#define _IPIND_PLUGIN_H_

/*! @file 
 * This file contains declarations of pind plugin interfaces.
 *
 * For usage examples please refer to the @ref REMOTE section in Pin User Manual.
 *
 * @note APIs declared in this file are under active development and are subject 
 *       to change or removal without notice
*/

#ifdef __cplusplus
#include <cstdint>
#include <cstdio>
#include <cstring>
#else
#include <stdint.h>
#endif

#include <rscprotomsgtypes.h>

/*! @ingroup PLUGIN
 * 
 * @brief The plugin type.
 * 
 * For user developed plugins only RPC is supported.
 * 
 */
enum E_plugin_type
{
    /**
     * @brief Indicates a pind RPC plugin
     * 
     */
    RPC
};

/*! @ingroup PLUGIN
 *
 * @brief Holds function pointers to basic common pind plugin functionality
 *
 * This structure should not be allocated directly. It should be filled and returned as
 * part of @ref IRPCPlugin.
 * 
 * This is also the first member of @ref IRPCPlugin. So casting an @ref IRPCPlugin to IPindPlugin
 * should work, providing a C style "object oriented" way of implementing plugins.
 */
struct IPindPlugin
{
    /*!
     * When true, plugin_log_verbose() will emit logs into the plugin log file
     * This member is set (internally) to true when the plugin JSON configuration file 
     * "ExtraRPCPlugins/i/log" or "/RSCServer/RPCPlugins/i/log" is true.
     * When false or not specified at all this member will be set to true.
     * @note Plugin should not set this flag on it's own.
     */
    bool verbose_;

    /*!
     * Plugin log filename based (but not the same) on this plugin JSON configuration file field
     * "ExtraRPCPlugins/i/logfilename" or "/RSCServer/RPCPlugins/i/logfilename" (which can be relative or absolute).
     * (if doesn't exist, a default name will be given from the plugin "/name" field in 
     * the configuration file (name +.log + .<PID>)
     */
    const char* logName_;

    /*!
     * Plugin print callback. It can be used to emit plugin logs into a dedicated plugin log file.
     * The plugin file name will be the <name from plugin JSON configuration file> + .log + .<PID>
     * Plugin log file is created based on plugin JSON configuration file (.../logfilename field). 
     * @note If the path is relative it will be relative compared to the location of pin.log.
     *
     * @param[in] self      A pointer to the plugin
     * @param[in] message   A C style string to be emitted into the plugin log file  
     * @param[in] length    Length of message string
     *
     * @note    Plugin can use this directly or use these auxiliary functions (recommended): plugin_log() / plugin_log_verbose().
     * @note    This is not mandatory. Plugins can open files and emits logs into them 
     *          using their own custom implementation.
     * @note    This callback can be called only after (*init)(...) function was called.
     *          Calling it earlier will will emit an error message to the standard error but will not crash.
     */
    void (*plugin_log)(IPindPlugin* self, const char* message, size_t length);

    /*!
     * @brief Return plugin type
     *
     * @param[in] self  A pointer to the plugin
     * 
     * This method must be set and may not be NULL.
     * 
     * @return E_plugin_type The plugin type. For 3rd party plugins the only acceptable return
     *                       value is E_plugin_type::RPC.
     */
    E_plugin_type (*get_plugin_type)(IPindPlugin* self);
    /*!
     * @brief Called to initialize a plugin
     *
     * If this method is set, it will be called after the plugin
     * is loaded. This method may be NULL.
     * 
     * @param[in] self  A pointer to the plugin
     * @param[in] argc  Number of arguments (see below)
     * @param[in] argv  Array of arguments as set in the plugin JSON configuration file trough the arguments field
     *                  ("ExtraRPCPlugins/i/arguments" or "/RSCServer/RPCPlugins/i/arguments").
     * 
     * @return If this function returns false, the plugin is not initialized and pind will not use it
     */
    bool (*init)(IPindPlugin* self, int argc, const char* const argv[]);
    /*!
     * @brief Perform any cleanup of resources allocated by init() or during the lifetime of the plugin.
     *
     * If this method is set, it will be called before the plugin
     * is destroyed. This method may be NULL.
     * 
     * @param[in] self  A pointer to the plugin
     */
    void (*uninit)(IPindPlugin* self);
};

/*! @ingroup PLUGIN
 *
 * @brief Holds function pointers to pind RPC plugin functionality
 * 
 * This structure should be allocated and returned by a plugin library in response to a call
 * to @ref load_plugin.
 * 
 * This structure can be placed as the first member of a user declared structure to provide
 * plugin specific additional state.
 * 
 */
struct IRPCPlugin
{
    /**
     * @brief Common pind plugin functionality (base class)
     * 
     */
    IPindPlugin base_;

    /**
     * @brief Get the injection data of the plugin
     * 
     * The values returned from this method will be injected to Pin as environment variables.
     * This method may be NULL.
     * 
     *  @note In Pin 4.0 beta, if @ref IRPCPlugin::get_injection_data is not NULL, it will be called but the returned 
     *        data will not be injected to Pin.
     * 
     * @param[in] self  A pointer to the plugin
     * 
     * @return A string of KEY=VALUE pairs with semicolon delimiter
     */
    const char* (*get_injection_data)(IPindPlugin* self);

    /*!
     * @brief Get the schema for the given id if supported by the plugin
     *
     * This method is called to retrieve an RPC schema when pind considers
     * the plugin for processing an RPC request. 
     * This method must be set and may not be NULL.
     * 
     * @param[in] self      A pointer to the plugin
     * @param[in] rpcId     RPC request ID
     * 
     * @return RPC message schema for the specified RPC request identified by @a rpcId if and only if 
     *         the plugin supports this @a rpcId, NULL otherwise.
     */
    t_rpc_message_schema const* (*get_rpc_schema)(IPindPlugin* self, t_rpc_id rpcId);

    /**
     * @brief Execute the RPC request. Store result in the specified @a retRpcArg.
     * 
     * This method is called by pind to actually process an RPC request.
     * This method must be set and may not be NULL.
     * 
     * @param[in]  self         A pointer to the plugin
     * @param[in]  rpcId        RPC request ID
     * @param[in]  argCount     Number of RPC arguments
     * @param[in]  rpcArgs      Array of RPC arguments
     * @param[out] retRpcArg    Pointer to RPC return value arg. Will be filled with RPC execution result.
     */
    void (*do_rpc)(IPindPlugin* self, t_rpc_id rpcId, t_arg_count argCount, t_rpc_arg* rpcArgs, t_rpc_ret* retRpcArg);
};

/**
 * Auxiliary functions
 */

static inline void plugin_log_impl(IPindPlugin* pindPlugin, const char* msg, size_t length)
{
    if (NULL == pindPlugin->plugin_log)
    {
        fprintf(stderr, "plugin_log() called too early (can be called only after init())\n");
    }
    else
    {
        pindPlugin->plugin_log(pindPlugin, msg, length);
    }
}

/*!
 * Print the specified message ( \a msg) into the plugin log file.
 * See IPindPlugin::plugin_log() for more information (such as which log file is being used)
 * @param[in] pindPlugin    Pointer to IPindPlugin object
 * @param[in] msg           C Style string message (const chart*)
 * 
 */
static inline void plugin_log(IPindPlugin* pindPlugin, const char* msg) { plugin_log_impl(pindPlugin, msg, strlen(msg)); }

/*!
 * Same as plugin_log with \a length specifying the length of the message.
 */
static inline void plugin_log_n(IPindPlugin* pindPlugin, const char* msg, size_t length)
{
    plugin_log_impl(pindPlugin, msg, length);
}

static inline void plugin_log_verbose_impl(IPindPlugin* pindPlugin, const char* msg, size_t length)
{
    if (NULL == pindPlugin->plugin_log)
    {
        fprintf(stderr, "plugin_log_verbose() called too early (can be called only after init())\n");
    }
    else if (pindPlugin->verbose_)
    {
        pindPlugin->plugin_log(pindPlugin, msg, length);
    }
}

/*!
 * Same as plugin_log(), but prints conditionally depending on IPindPlugin::verbose_ flag (see documentation for more details)
 */
static inline void plugin_log_verbose(IPindPlugin* pindPlugin, const char* msg)
{
    plugin_log_verbose_impl(pindPlugin, msg, strlen(msg));
}

/*!
 * Same as plugin_log_n(), but prints conditionally depending on IPindPlugin::verbose_ flag (see documentation for more details)
 */
static inline void plugin_log_verbose_n(IPindPlugin* pindPlugin, const char* msg, size_t length)
{
    plugin_log_verbose_impl(pindPlugin, msg, length);
}

/**
 * End of Auxiliary functions
 */

#if defined(TARGET_WINDOWS)
#define PLUGIN__DLLVIS __declspec(dllexport)
#else
#define PLUGIN__DLLVIS __attribute__((visibility("default")))
#endif // TARGET_WINDOWS

#ifdef __cplusplus
#define PLUGIN_EXTERNC extern "C"
#else
#define PLUGIN_EXTERNC
#endif

//// All plugin DLLs/SOs must export these two entry points below

/*! @ingroup PLUGIN
 *
 * @brief Allocate a structure object that can be safely casted to @ref IPindPlugin.
 *        Set its pointers to the correct functions in the plugin.
 *
 * @note  Plugin may allocate any structure that contain IPindPlugin structure as its first member.
 *        This enabled every plugin to expend the set of functions pointers and state.
 *        IRPCPlugin is normally used.
 *
 * @param[in] name  A plugin library may support more than a single plugin. This argument
 *                  is use to identify the requested plugin. 
 *                  This can be achieved through the plugin JSON configuration file like this:
 *                  "ExtraRPCPlugins": [
 *                     {
 *                         "lib": "my_plugin.so",
 *                         "name": "plugin 1"
 *                     },
 *                     {
 *                         "lib": "my_plugin.so",
 *                         "name": "plugin 2"
 *                     }
 *                  ]
 * 
 * @return  pointer to @ref IPindPlugin upon successful initialization.
 *          Caller can then convert the return pointer to the actual structure created ((See comments above)).
 *          NULL upon any failure.
 *
 */
PLUGIN_EXTERNC PLUGIN__DLLVIS IPindPlugin* load_plugin(const char* name);

/*! @ingroup PLUGIN
 * 
 * @brief Release resources allocated allocated by load_plugin().
 * 
 * This function is called by pind before unloading the plugin library.
 * Resources allocated by the plugin itself either on call to @ref IPindPlugin::init,
 * or during plugin operations, should be released by @ref IPindPlugin::uninit
 * 
 * @param[in] plugin    The plugin to unload.
 * 
 */
PLUGIN_EXTERNC PLUGIN__DLLVIS void unload_plugin(IPindPlugin* plugin);

#endif // _IPIND_PLUGIN_H_
