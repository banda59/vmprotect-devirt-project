/*
 * Copyright (C) 2024-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _EXTARSYSCALLS_H_
#define _EXTARSYSCALLS_H_

#define SYS_native_syscall_unsafe 900
#define SYS_native_syscall_safe 901
#define SYS_native_fork_with_clone 902
#define SYS_fetch_lock_generation 903
#define SYS_notify_exit_group 904
#define SYS_notify_fork 905
#define SYS_notify_execve 906
#define SYS_notify_client 907
#define SYS_notify_fork_in_child 908
#define SYS_notify_fork_in_parent 909

#define SYS_list_open_native_fds 910
#define SYS_query_realpath 911
#define SYS_native_id 912
#define SYS_is_absolute_path 913

#define SYS_unmap_and_exit_thread 920
#define SYS_alloc_thread_stack 921
#define SYS_link_native_thread 922
#define SYS_unlink_native_thread 923
#define SYS_exit_native_thread 924
#define SYS_native_thread_tid 925
#define SYS_tid_from_native_tid 926
#define SYS_generic_fd_from_native_fd 927
#define SYS_control_flt 928

#define SYS_tx_memfd_create 940
#define SYS_tx_memfd_open 941

#define SYS_tx_channel_open 950
#define SYS_tx_has_data 951
#define SYS_tx_max_payload_size 952
#define SYS_tx_peekmsg 953
#define SYS_tx_recvfrom 954
#define SYS_tx_sendto 955
#define SYS_tx_channel_close 956
#define SYS_tx_channel_create 957
#define SYS_tx_channel_gettxid 958
#define SYS_tx_channel_wait_data 959

#define SYS_futex_win_section 970

#define SYS_mman_lock 980
#define SYS_mman_query_range 982
#define SYS_mman_refresh 983
#define SYS_mman_request_isolation 984
#define SYS_mman_unlock 985
#define SYS_mman_get_range_attributes 986

#define SYS_rsc_do_rpc 990

#define SYS_INVALID_VALUE 1024

#endif // _EXTARSYSCALLS_H_