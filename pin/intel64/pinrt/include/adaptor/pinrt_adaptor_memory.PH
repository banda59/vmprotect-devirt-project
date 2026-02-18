/*
 * Copyright (C) 2023-2024 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef PINRT_ADAPTOR_MEMORY_PH_
#define PINRT_ADAPTOR_MEMORY_PH_

/*!
 * @file
 * Contain memory related runtime API (additional over standard runtime)
 */

#include <pinos.h>
#include <syscall.h>
#include <sys/mman.h>
#include <stdint.h>

#if defined(__cplusplus)

namespace pinrt
{

typedef uint32_t t_memattr;

constexpr inline bool is_page_readble(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_R); }

constexpr inline bool is_page_writable(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_W); }

constexpr inline bool is_page_executable(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_X); }

constexpr inline bool is_page_shared(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_SHARED); }

constexpr inline bool is_page_mapped(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_MAPPED); }

constexpr inline bool is_page_committed(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_COMMITTED); }

constexpr inline bool is_page_application(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_APPLICATION); }

constexpr inline bool is_page_backed(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_BACKED); }

constexpr inline bool is_win_image(t_memattr attr) noexcept { return 0 != (attr & QUERY_MEM_WIN_IMAGE); }

/**
 * @ingroup OS_APIS_MEMORY
 * @brief Find the same attribute range in which addr resides
 * 
 * If this function fails internally it will abort Pin
 * 
 * @param[in]  addr          An address inside a range
 * @param[out] startRange    Receives the start of the range (may be null)
 * @param[out] endRange      Receives the end of the range (may be null).
 *                           *endRange value is address of first byte after returned range,
 *                           so 0 means end of virtual address space.
 * @param[in]  refreshFromOs If true this function will request PINOS to refresh the cached data
 *                           from the underlying OS
 * 
 * @return Return the attributes for the range 
 */
t_memattr get_range_attributes(void const* addr, void** startRange, void** endRange, bool refreshFromOs = false) noexcept;

/**
 * @ingroup OS_APIS_MEMORY
 * @brief Query a memory range and return the page attributes for every page in the range.
 * 
 * @param[in] base            The base address for the range to check. It doesn't have to be page aligned.
 * @param[in] size            The size in bytes of the memory range of interest
 * @param[out] pageAttributes A uint32_t array with length equal to the number of pages overlapped by the queried range:
 *                            1 + ( (base - GetPageOfAddr(base) + size) / GetPageSize() )
 * @param[in] refreshFromOs   If true, the attributes for the memory range will be updated from the actual state of the OS.
 *                            Otherwise cached attributes are used.
 */
inline bool query_mem_range(const void* base, size_t size, t_memattr* pageAttributes, bool refreshFromOs = false) noexcept
{
    t_syscall_arg queryRangeArgs[] = {t_syscall_arg(base), t_syscall_arg(size), t_syscall_arg(pageAttributes),
                                      t_syscall_arg(refreshFromOs ? QUERY_MEM_FLAGS_PASSTHROUGH : 0)};

    auto ret = OS_Syscall(SYS_mman_query_range, SYSCALL_ARG_COUNT(queryRangeArgs), queryRangeArgs);
    if (IS_PINOS_SYSCALL_ERROR(ret))
    {
        return false;
    }
    return true;
}

} // namespace pinrt

#endif // #if defined(__cplusplus)

#endif // PINRT_ADAPTOR_MEMORY_PH_
