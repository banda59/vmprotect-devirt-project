/*
 * Copyright (C) 2024-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinrt
// <FILE-TYPE>: implementation

#ifndef _RSCSCHEMA_H_
#define _RSCSCHEMA_H_

/*! @file
 *
 * C++ helper templates for creating RPC mesage and argument schemas
 * 
 * See @ref REMOTE section in Pin User Manual
 * 
 * @note APIs declared in this file are under active development and are subject 
 *       to change or removal without notice
 */

#if __cplusplus < 201703L
#error "This file may only be included when using C++17 and higher"
#endif // __cplusplus

#include <pinrtstd.hxx>

#include <rscprotomsgtypes.h>

namespace pinrt
{
/** @ingroup REMOTE
 * 
 * @brief C++ templated helpers for creating RPC argument and message schemas
*/
namespace rscschema
{
/*!
 */
template< E_rpc_arg_type ARG_TYPE, size_t ARG_SIZE > struct RPC_arg_schema_wrapper
{
    static constexpr t_rpc_arg_schema v = MAKE_ARG_SCHEMA(ARG_TYPE, ARG_SIZE);
};

template< t_rpc_id RPC_ID, t_rpc_arg_schema const& SCHEMA_RET, t_rpc_arg_schema const&... SCHEMA_ARGS >
struct RPC_message_schema_wrapper
{
    static constexpr t_rpc_arg_schema arr_[sizeof...(SCHEMA_ARGS)] = {SCHEMA_ARGS...};
    static constexpr t_rpc_message_schema schema = {RPC_ID, sizeof...(SCHEMA_ARGS), (t_rpc_arg_schema*)arr_, SCHEMA_RET};
};

template< typename T > struct Is_char_type : pinrt::std::false_type
{
};
template<> struct Is_char_type< char > : pinrt::std::true_type
{
};
template<> struct Is_char_type< wchar_t > : pinrt::std::true_type
{
};
template<> struct Is_char_type< char16_t > : pinrt::std::true_type
{
};
template<> struct Is_char_type< char32_t > : pinrt::std::true_type
{
};

/*! @brief  RPC arg description for boolean parameter
 */
using Bool_schema                   = RPC_arg_schema_wrapper< RpcBoolean, 1 >;
inline constexpr auto Bool_schema_v = Bool_schema::v;

/*! @brief  RPC arg description for integer parameter
 */
template< typename INT_TYPE, typename U = pinrt::std::enable_if_t< pinrt::std::is_integral< INT_TYPE >::value, INT_TYPE > >
using Int_schema                                                 = RPC_arg_schema_wrapper< RpcInt, sizeof(INT_TYPE) >;
template< typename INT_TYPE > inline constexpr auto Int_schema_v = Int_schema< INT_TYPE >::v;

/*! @brief  RPC arg description for unsigned integer type parameter
 */
template< typename UINT_TYPE, typename U = pinrt::std::enable_if_t< pinrt::std::is_integral< UINT_TYPE >::value, UINT_TYPE >,
          typename V = pinrt::std::enable_if_t< (UINT_TYPE(-1) > UINT_TYPE(0)), UINT_TYPE > >
using Uint_schema                                                  = RPC_arg_schema_wrapper< RpcUInt, sizeof(UINT_TYPE) >;
template< typename UINT_TYPE > inline constexpr auto Uint_schema_v = Uint_schema< UINT_TYPE >::v;

/*! @brief  RPC arg description for char type parameter
 */
template< typename CHAR_TYPE, typename U = pinrt::std::enable_if_t< Is_char_type< CHAR_TYPE >::value, CHAR_TYPE > >
using Char_schema                                                  = RPC_arg_schema_wrapper< RpcChar, sizeof(CHAR_TYPE) >;
template< typename CHAR_TYPE > inline constexpr auto Char_schema_v = Char_schema< CHAR_TYPE >::v;

/*! @brief  RPC arg description for float type parameter
 */
template< typename FLOAT_TYPE,
          typename U = pinrt::std::enable_if_t< pinrt::std::is_floating_point< FLOAT_TYPE >::value, FLOAT_TYPE > >
using Float_schema                                                   = RPC_arg_schema_wrapper< RpcFloat, sizeof(FLOAT_TYPE) >;
template< typename FLOAT_TYPE > inline constexpr auto Float_schema_v = Float_schema< FLOAT_TYPE >::v;

/*! @brief  RPC arg description for buffer parameter
 */
using Buffer_schema                   = RPC_arg_schema_wrapper< RpcBuffer, sizeof(uint32_t) >;
inline constexpr auto Buffer_schema_v = Buffer_schema::v;

/*! @brief  RPC arg description void parameter
 */
using Void_schema                   = RPC_arg_schema_wrapper< RpcNil, 0 >;
inline constexpr auto Void_schema_v = Void_schema::v;

/*! @brief  RPC arg description nil parameter
 */
using Nil_schema                   = RPC_arg_schema_wrapper< RpcNil, 0 >;
inline constexpr auto Nil_schema_v = Nil_schema::v;

} // namespace rscschema
} // namespace pinrt

#endif // _RSCSCHEMA_H_
