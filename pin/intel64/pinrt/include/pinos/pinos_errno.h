/*
 * Copyright (C) 2022-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinos
// <FILE-TYPE>: public header

#ifndef _PINOS_ERRNO_H_
#define _PINOS_ERRNO_H_

// We make sure not to override any system errno definitions in case
// pinos is used with the system runtime..
// To this end we make sure to push existing definitions before
// defining our PINOS_EXXX error enum and then restore them

// Push existing errno macro definitions if exist
#ifdef EPERM
#pragma push_macro("EPERM")
#undef EPERM
#define EPERM_NEED_POP
#endif
#ifdef ENOENT
#pragma push_macro("ENOENT")
#undef ENOENT
#define ENOENT_NEED_POP
#endif
#ifdef ESRCH
#pragma push_macro("ESRCH")
#undef ESRCH
#define ESRCH_NEED_POP
#endif
#ifdef EINTR
#pragma push_macro("EINTR")
#undef EINTR
#define EINTR_NEED_POP
#endif
#ifdef EIO
#pragma push_macro("EIO")
#undef EIO
#define EIO_NEED_POP
#endif
#ifdef ENXIO
#pragma push_macro("ENXIO")
#undef ENXIO
#define ENXIO_NEED_POP
#endif
#ifdef E2BIG
#pragma push_macro("E2BIG")
#undef E2BIG
#define E2BIG_NEED_POP
#endif
#ifdef ENOEXEC
#pragma push_macro("ENOEXEC")
#undef ENOEXEC
#define ENOEXEC_NEED_POP
#endif
#ifdef EBADF
#pragma push_macro("EBADF")
#undef EBADF
#define EBADF_NEED_POP
#endif
#ifdef ECHILD
#pragma push_macro("ECHILD")
#undef ECHILD
#define ECHILD_NEED_POP
#endif
#ifdef EAGAIN
#pragma push_macro("EAGAIN")
#undef EAGAIN
#define EAGAIN_NEED_POP
#endif
#ifdef ENOMEM
#pragma push_macro("ENOMEM")
#undef ENOMEM
#define ENOMEM_NEED_POP
#endif
#ifdef EACCES
#pragma push_macro("EACCES")
#undef EACCES
#define EACCES_NEED_POP
#endif
#ifdef EFAULT
#pragma push_macro("EFAULT")
#undef EFAULT
#define EFAULT_NEED_POP
#endif
#ifdef ENOTBLK
#pragma push_macro("ENOTBLK")
#undef ENOTBLK
#define ENOTBLK_NEED_POP
#endif
#ifdef EBUSY
#pragma push_macro("EBUSY")
#undef EBUSY
#define EBUSY_NEED_POP
#endif
#ifdef EEXIST
#pragma push_macro("EEXIST")
#undef EEXIST
#define EEXIST_NEED_POP
#endif
#ifdef EXDEV
#pragma push_macro("EXDEV")
#undef EXDEV
#define EXDEV_NEED_POP
#endif
#ifdef ENODEV
#pragma push_macro("ENODEV")
#undef ENODEV
#define ENODEV_NEED_POP
#endif
#ifdef ENOTDIR
#pragma push_macro("ENOTDIR")
#undef ENOTDIR
#define ENOTDIR_NEED_POP
#endif
#ifdef EISDIR
#pragma push_macro("EISDIR")
#undef EISDIR
#define EISDIR_NEED_POP
#endif
#ifdef EINVAL
#pragma push_macro("EINVAL")
#undef EINVAL
#define EINVAL_NEED_POP
#endif
#ifdef ENFILE
#pragma push_macro("ENFILE")
#undef ENFILE
#define ENFILE_NEED_POP
#endif
#ifdef EMFILE
#pragma push_macro("EMFILE")
#undef EMFILE
#define EMFILE_NEED_POP
#endif
#ifdef ENOTTY
#pragma push_macro("ENOTTY")
#undef ENOTTY
#define ENOTTY_NEED_POP
#endif
#ifdef ETXTBSY
#pragma push_macro("ETXTBSY")
#undef ETXTBSY
#define ETXTBSY_NEED_POP
#endif
#ifdef EFBIG
#pragma push_macro("EFBIG")
#undef EFBIG
#define EFBIG_NEED_POP
#endif
#ifdef ENOSPC
#pragma push_macro("ENOSPC")
#undef ENOSPC
#define ENOSPC_NEED_POP
#endif
#ifdef ESPIPE
#pragma push_macro("ESPIPE")
#undef ESPIPE
#define ESPIPE_NEED_POP
#endif
#ifdef EROFS
#pragma push_macro("EROFS")
#undef EROFS
#define EROFS_NEED_POP
#endif
#ifdef EMLINK
#pragma push_macro("EMLINK")
#undef EMLINK
#define EMLINK_NEED_POP
#endif
#ifdef EPIPE
#pragma push_macro("EPIPE")
#undef EPIPE
#define EPIPE_NEED_POP
#endif
#ifdef EDOM
#pragma push_macro("EDOM")
#undef EDOM
#define EDOM_NEED_POP
#endif
#ifdef ERANGE
#pragma push_macro("ERANGE")
#undef ERANGE
#define ERANGE_NEED_POP
#endif
#ifdef EDEADLK
#pragma push_macro("EDEADLK")
#undef EDEADLK
#define EDEADLK_NEED_POP
#endif
#ifdef ENOLCK
#pragma push_macro("ENOLCK")
#undef ENOLCK
#define ENOLCK_NEED_POP
#endif
#ifdef ENOSYS
#pragma push_macro("ENOSYS")
#undef ENOSYS
#define ENOSYS_NEED_POP
#endif
#ifdef ENOTEMPTY
#pragma push_macro("ENOTEMPTY")
#undef ENOTEMPTY
#define ENOTEMPTY_NEED_POP
#endif
#ifdef ELOOP
#pragma push_macro("ELOOP")
#undef ELOOP
#define ELOOP_NEED_POP
#endif
#ifdef EWOULDBLOCK
#pragma push_macro("EWOULDBLOCK")
#undef EWOULDBLOCK
#define EWOULDBLOCK_NEED_POP
#endif
#ifdef ENOMSG
#pragma push_macro("ENOMSG")
#undef ENOMSG
#define ENOMSG_NEED_POP
#endif
#ifdef EIDRM
#pragma push_macro("EIDRM")
#undef EIDRM
#define EIDRM_NEED_POP
#endif
#ifdef ECHRNG
#pragma push_macro("ECHRNG")
#undef ECHRNG
#define ECHRNG_NEED_POP
#endif
#ifdef EL2NSYNC
#pragma push_macro("EL2NSYNC")
#undef EL2NSYNC
#define EL2NSYNC_NEED_POP
#endif
#ifdef EL3HLT
#pragma push_macro("EL3HLT")
#undef EL3HLT
#define EL3HLT_NEED_POP
#endif
#ifdef EL3RST
#pragma push_macro("EL3RST")
#undef EL3RST
#define EL3RST_NEED_POP
#endif
#ifdef ELNRNG
#pragma push_macro("ELNRNG")
#undef ELNRNG
#define ELNRNG_NEED_POP
#endif
#ifdef EUNATCH
#pragma push_macro("EUNATCH")
#undef EUNATCH
#define EUNATCH_NEED_POP
#endif
#ifdef ENOCSI
#pragma push_macro("ENOCSI")
#undef ENOCSI
#define ENOCSI_NEED_POP
#endif
#ifdef EL2HLT
#pragma push_macro("EL2HLT")
#undef EL2HLT
#define EL2HLT_NEED_POP
#endif
#ifdef EBADE
#pragma push_macro("EBADE")
#undef EBADE
#define EBADE_NEED_POP
#endif
#ifdef ENAMETOOLONG
#pragma push_macro("ENAMETOOLONG")
#undef ENAMETOOLONG
#define ENAMETOOLONG_NEED_POP
#endif
#ifdef EBADR
#pragma push_macro("EBADR")
#undef EBADR
#define EBADR_NEED_POP
#endif
#ifdef EXFULL
#pragma push_macro("EXFULL")
#undef EXFULL
#define EXFULL_NEED_POP
#endif
#ifdef ENOANO
#pragma push_macro("ENOANO")
#undef ENOANO
#define ENOANO_NEED_POP
#endif
#ifdef EBADRQC
#pragma push_macro("EBADRQC")
#undef EBADRQC
#define EBADRQC_NEED_POP
#endif
#ifdef EBADSLT
#pragma push_macro("EBADSLT")
#undef EBADSLT
#define EBADSLT_NEED_POP
#endif
#ifdef EDEADLOCK
#pragma push_macro("EDEADLOCK")
#undef EDEADLOCK
#define EDEADLOCK_NEED_POP
#endif
#ifdef EBFONT
#pragma push_macro("EBFONT")
#undef EBFONT
#define EBFONT_NEED_POP
#endif
#ifdef ENOSTR
#pragma push_macro("ENOSTR")
#undef ENOSTR
#define ENOSTR_NEED_POP
#endif
#ifdef ENODATA
#pragma push_macro("ENODATA")
#undef ENODATA
#define ENODATA_NEED_POP
#endif
#ifdef ETIME
#pragma push_macro("ETIME")
#undef ETIME
#define ETIME_NEED_POP
#endif
#ifdef ENOSR
#pragma push_macro("ENOSR")
#undef ENOSR
#define ENOSR_NEED_POP
#endif
#ifdef ENONET
#pragma push_macro("ENONET")
#undef ENONET
#define ENONET_NEED_POP
#endif
#ifdef ENOPKG
#pragma push_macro("ENOPKG")
#undef ENOPKG
#define ENOPKG_NEED_POP
#endif
#ifdef EREMOTE
#pragma push_macro("EREMOTE")
#undef EREMOTE
#define EREMOTE_NEED_POP
#endif
#ifdef ENOLINK
#pragma push_macro("ENOLINK")
#undef ENOLINK
#define ENOLINK_NEED_POP
#endif
#ifdef EADV
#pragma push_macro("EADV")
#undef EADV
#define EADV_NEED_POP
#endif
#ifdef ESRMNT
#pragma push_macro("ESRMNT")
#undef ESRMNT
#define ESRMNT_NEED_POP
#endif
#ifdef ECOMM
#pragma push_macro("ECOMM")
#undef ECOMM
#define ECOMM_NEED_POP
#endif
#ifdef EPROTO
#pragma push_macro("EPROTO")
#undef EPROTO
#define EPROTO_NEED_POP
#endif
#ifdef EMULTIHOP
#pragma push_macro("EMULTIHOP")
#undef EMULTIHOP
#define EMULTIHOP_NEED_POP
#endif
#ifdef EDOTDOT
#pragma push_macro("EDOTDOT")
#undef EDOTDOT
#define EDOTDOT_NEED_POP
#endif
#ifdef EBADMSG
#pragma push_macro("EBADMSG")
#undef EBADMSG
#define EBADMSG_NEED_POP
#endif
#ifdef EOVERFLOW
#pragma push_macro("EOVERFLOW")
#undef EOVERFLOW
#define EOVERFLOW_NEED_POP
#endif
#ifdef ENOTUNIQ
#pragma push_macro("ENOTUNIQ")
#undef ENOTUNIQ
#define ENOTUNIQ_NEED_POP
#endif
#ifdef EBADFD
#pragma push_macro("EBADFD")
#undef EBADFD
#define EBADFD_NEED_POP
#endif
#ifdef EREMCHG
#pragma push_macro("EREMCHG")
#undef EREMCHG
#define EREMCHG_NEED_POP
#endif
#ifdef ELIBACC
#pragma push_macro("ELIBACC")
#undef ELIBACC
#define ELIBACC_NEED_POP
#endif
#ifdef ELIBBAD
#pragma push_macro("ELIBBAD")
#undef ELIBBAD
#define ELIBBAD_NEED_POP
#endif
#ifdef ELIBSCN
#pragma push_macro("ELIBSCN")
#undef ELIBSCN
#define ELIBSCN_NEED_POP
#endif
#ifdef ELIBMAX
#pragma push_macro("ELIBMAX")
#undef ELIBMAX
#define ELIBMAX_NEED_POP
#endif
#ifdef ELIBEXEC
#pragma push_macro("ELIBEXEC")
#undef ELIBEXEC
#define ELIBEXEC_NEED_POP
#endif
#ifdef EILSEQ
#pragma push_macro("EILSEQ")
#undef EILSEQ
#define EILSEQ_NEED_POP
#endif
#ifdef ERESTART
#pragma push_macro("ERESTART")
#undef ERESTART
#define ERESTART_NEED_POP
#endif
#ifdef ESTRPIPE
#pragma push_macro("ESTRPIPE")
#undef ESTRPIPE
#define ESTRPIPE_NEED_POP
#endif
#ifdef EUSERS
#pragma push_macro("EUSERS")
#undef EUSERS
#define EUSERS_NEED_POP
#endif
#ifdef ENOTSOCK
#pragma push_macro("ENOTSOCK")
#undef ENOTSOCK
#define ENOTSOCK_NEED_POP
#endif
#ifdef EDESTADDRREQ
#pragma push_macro("EDESTADDRREQ")
#undef EDESTADDRREQ
#define EDESTADDRREQ_NEED_POP
#endif
#ifdef EMSGSIZE
#pragma push_macro("EMSGSIZE")
#undef EMSGSIZE
#define EMSGSIZE_NEED_POP
#endif
#ifdef EPROTOTYPE
#pragma push_macro("EPROTOTYPE")
#undef EPROTOTYPE
#define EPROTOTYPE_NEED_POP
#endif
#ifdef ENOPROTOOPT
#pragma push_macro("ENOPROTOOPT")
#undef ENOPROTOOPT
#define ENOPROTOOPT_NEED_POP
#endif
#ifdef EPROTONOSUPPORT
#pragma push_macro("EPROTONOSUPPORT")
#undef EPROTONOSUPPORT
#define EPROTONOSUPPORT_NEED_POP
#endif
#ifdef ESOCKTNOSUPPORT
#pragma push_macro("ESOCKTNOSUPPORT")
#undef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT_NEED_POP
#endif
#ifdef EOPNOTSUPP
#pragma push_macro("EOPNOTSUPP")
#undef EOPNOTSUPP
#define EOPNOTSUPP_NEED_POP
#endif
#ifdef ENOTSUP
#pragma push_macro("ENOTSUP")
#undef ENOTSUP
#define ENOTSUP_NEED_POP
#endif
#ifdef EPFNOSUPPORT
#pragma push_macro("EPFNOSUPPORT")
#undef EPFNOSUPPORT
#define EPFNOSUPPORT_NEED_POP
#endif
#ifdef ECONNRESET
#pragma push_macro("ECONNRESET")
#undef ECONNRESET
#define ECONNRESET_NEED_POP
#endif
#ifdef ENETDOWN
#pragma push_macro("ENETDOWN")
#undef ENETDOWN
#define ENETDOWN_NEED_POP
#endif
#ifdef EAFNOSUPPORT
#pragma push_macro("EAFNOSUPPORT")
#undef EAFNOSUPPORT
#define EAFNOSUPPORT_NEED_POP
#endif
#ifdef EADDRINUSE
#pragma push_macro("EADDRINUSE")
#undef EADDRINUSE
#define EADDRINUSE_NEED_POP
#endif
#ifdef EADDRNOTAVAIL
#pragma push_macro("EADDRNOTAVAIL")
#undef EADDRNOTAVAIL
#define EADDRNOTAVAIL_NEED_POP
#endif
#ifdef ENETUNREACH
#pragma push_macro("ENETUNREACH")
#undef ENETUNREACH
#define ENETUNREACH_NEED_POP
#endif
#ifdef ENETRESET
#pragma push_macro("ENETRESET")
#undef ENETRESET
#define ENETRESET_NEED_POP
#endif
#ifdef ECONNABORTED
#pragma push_macro("ECONNABORTED")
#undef ECONNABORTED
#define ECONNABORTED_NEED_POP
#endif
#ifdef ENOBUFS
#pragma push_macro("ENOBUFS")
#undef ENOBUFS
#define ENOBUFS_NEED_POP
#endif
#ifdef EISCONN
#pragma push_macro("EISCONN")
#undef EISCONN
#define EISCONN_NEED_POP
#endif
#ifdef ENOTCONN
#pragma push_macro("ENOTCONN")
#undef ENOTCONN
#define ENOTCONN_NEED_POP
#endif
#ifdef ESHUTDOWN
#pragma push_macro("ESHUTDOWN")
#undef ESHUTDOWN
#define ESHUTDOWN_NEED_POP
#endif
#ifdef ETOOMANYREFS
#pragma push_macro("ETOOMANYREFS")
#undef ETOOMANYREFS
#define ETOOMANYREFS_NEED_POP
#endif
#ifdef ETIMEDOUT
#pragma push_macro("ETIMEDOUT")
#undef ETIMEDOUT
#define ETIMEDOUT_NEED_POP
#endif
#ifdef ECONNREFUSED
#pragma push_macro("ECONNREFUSED")
#undef ECONNREFUSED
#define ECONNREFUSED_NEED_POP
#endif
#ifdef EHOSTDOWN
#pragma push_macro("EHOSTDOWN")
#undef EHOSTDOWN
#define EHOSTDOWN_NEED_POP
#endif
#ifdef EHOSTUNREACH
#pragma push_macro("EHOSTUNREACH")
#undef EHOSTUNREACH
#define EHOSTUNREACH_NEED_POP
#endif
#ifdef EALREADY
#pragma push_macro("EALREADY")
#undef EALREADY
#define EALREADY_NEED_POP
#endif
#ifdef EINPROGRESS
#pragma push_macro("EINPROGRESS")
#undef EINPROGRESS
#define EINPROGRESS_NEED_POP
#endif
#ifdef ESTALE
#pragma push_macro("ESTALE")
#undef ESTALE
#define ESTALE_NEED_POP
#endif
#ifdef EUCLEAN
#pragma push_macro("EUCLEAN")
#undef EUCLEAN
#define EUCLEAN_NEED_POP
#endif
#ifdef ENOTNAM
#pragma push_macro("ENOTNAM")
#undef ENOTNAM
#define ENOTNAM_NEED_POP
#endif
#ifdef ENAVAIL
#pragma push_macro("ENAVAIL")
#undef ENAVAIL
#define ENAVAIL_NEED_POP
#endif
#ifdef EISNAM
#pragma push_macro("EISNAM")
#undef EISNAM
#define EISNAM_NEED_POP
#endif
#ifdef EREMOTEIO
#pragma push_macro("EREMOTEIO")
#undef EREMOTEIO
#define EREMOTEIO_NEED_POP
#endif
#ifdef EDQUOT
#pragma push_macro("EDQUOT")
#undef EDQUOT
#define EDQUOT_NEED_POP
#endif
#ifdef ENOMEDIUM
#pragma push_macro("ENOMEDIUM")
#undef ENOMEDIUM
#define ENOMEDIUM_NEED_POP
#endif
#ifdef EMEDIUMTYPE
#pragma push_macro("EMEDIUMTYPE")
#undef EMEDIUMTYPE
#define EMEDIUMTYPE_NEED_POP
#endif
#ifdef ECANCELED
#pragma push_macro("ECANCELED")
#undef ECANCELED
#define ECANCELED_NEED_POP
#endif
#ifdef ENOKEY
#pragma push_macro("ENOKEY")
#undef ENOKEY
#define ENOKEY_NEED_POP
#endif
#ifdef EKEYEXPIRED
#pragma push_macro("EKEYEXPIRED")
#undef EKEYEXPIRED
#define EKEYEXPIRED_NEED_POP
#endif
#ifdef EKEYREVOKED
#pragma push_macro("EKEYREVOKED")
#undef EKEYREVOKED
#define EKEYREVOKED_NEED_POP
#endif
#ifdef EKEYREJECTED
#pragma push_macro("EKEYREJECTED")
#undef EKEYREJECTED
#define EKEYREJECTED_NEED_POP
#endif
#ifdef EOWNERDEAD
#pragma push_macro("EOWNERDEAD")
#undef EOWNERDEAD
#define EOWNERDEAD_NEED_POP
#endif
#ifdef ENOTRECOVERABLE
#pragma push_macro("ENOTRECOVERABLE")
#undef ENOTRECOVERABLE
#define ENOTRECOVERABLE_NEED_POP
#endif
#ifdef ERFKILL
#pragma push_macro("ERFKILL")
#undef ERFKILL
#define ERFKILL_NEED_POP
#endif
#ifdef EHWPOISON
#pragma push_macro("EHWPOISON")
#undef EHWPOISON
#define EHWPOISON_NEED_POP
#endif

// Bring in our own definition of errno macros
#include "pbits/errno.h"

// Declare an enum of PINOS_EXXXX using out own definitions
enum
{
    PINOS_EPERM           = EPERM,
    PINOS_ENOENT          = ENOENT,
    PINOS_ESRCH           = ESRCH,
    PINOS_EINTR           = EINTR,
    PINOS_EIO             = EIO,
    PINOS_ENXIO           = ENXIO,
    PINOS_E2BIG           = E2BIG,
    PINOS_ENOEXEC         = ENOEXEC,
    PINOS_EBADF           = EBADF,
    PINOS_ECHILD          = ECHILD,
    PINOS_EAGAIN          = EAGAIN,
    PINOS_ENOMEM          = ENOMEM,
    PINOS_EACCES          = EACCES,
    PINOS_EFAULT          = EFAULT,
    PINOS_ENOTBLK         = ENOTBLK,
    PINOS_EBUSY           = EBUSY,
    PINOS_EEXIST          = EEXIST,
    PINOS_EXDEV           = EXDEV,
    PINOS_ENODEV          = ENODEV,
    PINOS_ENOTDIR         = ENOTDIR,
    PINOS_EISDIR          = EISDIR,
    PINOS_EINVAL          = EINVAL,
    PINOS_ENFILE          = ENFILE,
    PINOS_EMFILE          = EMFILE,
    PINOS_ENOTTY          = ENOTTY,
    PINOS_ETXTBSY         = ETXTBSY,
    PINOS_EFBIG           = EFBIG,
    PINOS_ENOSPC          = ENOSPC,
    PINOS_ESPIPE          = ESPIPE,
    PINOS_EROFS           = EROFS,
    PINOS_EMLINK          = EMLINK,
    PINOS_EPIPE           = EPIPE,
    PINOS_EDOM            = EDOM,
    PINOS_ERANGE          = ERANGE,
    PINOS_EDEADLK         = EDEADLK,
    PINOS_ENAMETOOLONG    = ENAMETOOLONG,
    PINOS_ENOLCK          = ENOLCK,
    PINOS_ENOSYS          = ENOSYS,
    PINOS_ENOTEMPTY       = ENOTEMPTY,
    PINOS_ELOOP           = ELOOP,
    PINOS_EWOULDBLOCK     = EWOULDBLOCK,
    PINOS_ENOMSG          = ENOMSG,
    PINOS_EIDRM           = EIDRM,
    PINOS_ECHRNG          = ECHRNG,
    PINOS_EL2NSYNC        = EL2NSYNC,
    PINOS_EL3HLT          = EL3HLT,
    PINOS_EL3RST          = EL3RST,
    PINOS_ELNRNG          = ELNRNG,
    PINOS_EUNATCH         = EUNATCH,
    PINOS_ENOCSI          = ENOCSI,
    PINOS_EL2HLT          = EL2HLT,
    PINOS_EBADE           = EBADE,
    PINOS_EBADR           = EBADR,
    PINOS_EXFULL          = EXFULL,
    PINOS_ENOANO          = ENOANO,
    PINOS_EBADRQC         = EBADRQC,
    PINOS_EBADSLT         = EBADSLT,
    PINOS_EDEADLOCK       = EDEADLOCK,
    PINOS_EBFONT          = EBFONT,
    PINOS_ENOSTR          = ENOSTR,
    PINOS_ENODATA         = ENODATA,
    PINOS_ETIME           = ETIME,
    PINOS_ENOSR           = ENOSR,
    PINOS_ENONET          = ENONET,
    PINOS_ENOPKG          = ENOPKG,
    PINOS_EREMOTE         = EREMOTE,
    PINOS_ENOLINK         = ENOLINK,
    PINOS_EADV            = EADV,
    PINOS_ESRMNT          = ESRMNT,
    PINOS_ECOMM           = ECOMM,
    PINOS_EPROTO          = EPROTO,
    PINOS_EMULTIHOP       = EMULTIHOP,
    PINOS_EDOTDOT         = EDOTDOT,
    PINOS_EBADMSG         = EBADMSG,
    PINOS_EOVERFLOW       = EOVERFLOW,
    PINOS_ENOTUNIQ        = ENOTUNIQ,
    PINOS_EBADFD          = EBADFD,
    PINOS_EREMCHG         = EREMCHG,
    PINOS_ELIBACC         = ELIBACC,
    PINOS_ELIBBAD         = ELIBBAD,
    PINOS_ELIBSCN         = ELIBSCN,
    PINOS_ELIBMAX         = ELIBMAX,
    PINOS_ELIBEXEC        = ELIBEXEC,
    PINOS_EILSEQ          = EILSEQ,
    PINOS_ERESTART        = ERESTART,
    PINOS_ESTRPIPE        = ESTRPIPE,
    PINOS_EUSERS          = EUSERS,
    PINOS_ENOTSOCK        = ENOTSOCK,
    PINOS_EDESTADDRREQ    = EDESTADDRREQ,
    PINOS_EMSGSIZE        = EMSGSIZE,
    PINOS_EPROTOTYPE      = EPROTOTYPE,
    PINOS_ENOPROTOOPT     = ENOPROTOOPT,
    PINOS_EPROTONOSUPPORT = EPROTONOSUPPORT,
    PINOS_ESOCKTNOSUPPORT = ESOCKTNOSUPPORT,
    PINOS_EOPNOTSUPP      = EOPNOTSUPP,
    PINOS_ENOTSUP         = ENOTSUP,
    PINOS_EPFNOSUPPORT    = EPFNOSUPPORT,
    PINOS_EAFNOSUPPORT    = EAFNOSUPPORT,
    PINOS_EADDRINUSE      = EADDRINUSE,
    PINOS_EADDRNOTAVAIL   = EADDRNOTAVAIL,
    PINOS_ENETDOWN        = ENETDOWN,
    PINOS_ENETUNREACH     = ENETUNREACH,
    PINOS_ENETRESET       = ENETRESET,
    PINOS_ECONNABORTED    = ECONNABORTED,
    PINOS_ECONNRESET      = ECONNRESET,
    PINOS_ENOBUFS         = ENOBUFS,
    PINOS_EISCONN         = EISCONN,
    PINOS_ENOTCONN        = ENOTCONN,
    PINOS_ESHUTDOWN       = ESHUTDOWN,
    PINOS_ETOOMANYREFS    = ETOOMANYREFS,
    PINOS_ETIMEDOUT       = ETIMEDOUT,
    PINOS_ECONNREFUSED    = ECONNREFUSED,
    PINOS_EHOSTDOWN       = EHOSTDOWN,
    PINOS_EHOSTUNREACH    = EHOSTUNREACH,
    PINOS_EALREADY        = EALREADY,
    PINOS_EINPROGRESS     = EINPROGRESS,
    PINOS_ESTALE          = ESTALE,
    PINOS_EUCLEAN         = EUCLEAN,
    PINOS_ENOTNAM         = ENOTNAM,
    PINOS_ENAVAIL         = ENAVAIL,
    PINOS_EISNAM          = EISNAM,
    PINOS_EREMOTEIO       = EREMOTEIO,
    PINOS_EDQUOT          = EDQUOT,
    PINOS_ENOMEDIUM       = ENOMEDIUM,
    PINOS_EMEDIUMTYPE     = EMEDIUMTYPE,
    PINOS_ECANCELED       = ECANCELED,
    PINOS_ENOKEY          = ENOKEY,
    PINOS_EKEYEXPIRED     = EKEYEXPIRED,
    PINOS_EKEYREVOKED     = EKEYREVOKED,
    PINOS_EKEYREJECTED    = EKEYREJECTED,
    PINOS_EOWNERDEAD      = EOWNERDEAD,
    PINOS_ENOTRECOVERABLE = ENOTRECOVERABLE,
    PINOS_ERFKILL         = ERFKILL,
    PINOS_EHWPOISON       = EHWPOISON,

};

// Restore previous definitions of errno macros - if any
#ifdef EPERM_NEED_POP
#pragma pop_macro("EPERM")
#undef EPERM_NEED_POP
#else
#undef EPERM
#endif
#ifdef ENOENT_NEED_POP
#pragma pop_macro("ENOENT")
#undef ENOENT_NEED_POP
#else
#undef ENOENT
#endif
#ifdef ESRCH_NEED_POP
#pragma pop_macro("ESRCH")
#undef ESRCH_NEED_POP
#else
#undef ESRCH
#endif
#ifdef EINTR_NEED_POP
#pragma pop_macro("EINTR")
#undef EINTR_NEED_POP
#else
#undef EINTR
#endif
#ifdef EIO_NEED_POP
#pragma pop_macro("EIO")
#undef EIO_NEED_POP
#else
#undef EIO
#endif
#ifdef ENXIO_NEED_POP
#pragma pop_macro("ENXIO")
#undef ENXIO_NEED_POP
#else
#undef ENXIO
#endif
#ifdef E2BIG_NEED_POP
#pragma pop_macro("E2BIG")
#undef E2BIG_NEED_POP
#else
#undef E2BIG
#endif
#ifdef ENOEXEC_NEED_POP
#pragma pop_macro("ENOEXEC")
#undef ENOEXEC_NEED_POP
#else
#undef ENOEXEC
#endif
#ifdef EBADF_NEED_POP
#pragma pop_macro("EBADF")
#undef EBADF_NEED_POP
#else
#undef EBADF
#endif
#ifdef ECHILD_NEED_POP
#pragma pop_macro("ECHILD")
#undef ECHILD_NEED_POP
#else
#undef ECHILD
#endif
#ifdef EAGAIN_NEED_POP
#pragma pop_macro("EAGAIN")
#undef EAGAIN_NEED_POP
#else
#undef EAGAIN
#endif
#ifdef ENOMEM_NEED_POP
#pragma pop_macro("ENOMEM")
#undef ENOMEM_NEED_POP
#else
#undef ENOMEM
#endif
#ifdef EACCES_NEED_POP
#pragma pop_macro("EACCES")
#undef EACCES_NEED_POP
#else
#undef EACCES
#endif
#ifdef EFAULT_NEED_POP
#pragma pop_macro("EFAULT")
#undef EFAULT_NEED_POP
#else
#undef EFAULT
#endif
#ifdef ENOTBLK_NEED_POP
#pragma pop_macro("ENOTBLK")
#undef ENOTBLK_NEED_POP
#else
#undef ENOTBLK
#endif
#ifdef EBUSY_NEED_POP
#pragma pop_macro("EBUSY")
#undef EBUSY_NEED_POP
#else
#undef EBUSY
#endif
#ifdef EEXIST_NEED_POP
#pragma pop_macro("EEXIST")
#undef EEXIST_NEED_POP
#else
#undef EEXIST
#endif
#ifdef EXDEV_NEED_POP
#pragma pop_macro("EXDEV")
#undef EXDEV_NEED_POP
#else
#undef EXDEV
#endif
#ifdef ENODEV_NEED_POP
#pragma pop_macro("ENODEV")
#undef ENODEV_NEED_POP
#else
#undef ENODEV
#endif
#ifdef ENOTDIR_NEED_POP
#pragma pop_macro("ENOTDIR")
#undef ENOTDIR_NEED_POP
#else
#undef ENOTDIR
#endif
#ifdef EISDIR_NEED_POP
#pragma pop_macro("EISDIR")
#undef EISDIR_NEED_POP
#else
#undef EISDIR
#endif
#ifdef EINVAL_NEED_POP
#pragma pop_macro("EINVAL")
#undef EINVAL_NEED_POP
#else
#undef EINVAL
#endif
#ifdef ENFILE_NEED_POP
#pragma pop_macro("ENFILE")
#undef ENFILE_NEED_POP
#else
#undef ENFILE
#endif
#ifdef EMFILE_NEED_POP
#pragma pop_macro("EMFILE")
#undef EMFILE_NEED_POP
#else
#undef EMFILE
#endif
#ifdef ENOTTY_NEED_POP
#pragma pop_macro("ENOTTY")
#undef ENOTTY_NEED_POP
#else
#undef ENOTTY
#endif
#ifdef ETXTBSY_NEED_POP
#pragma pop_macro("ETXTBSY")
#undef ETXTBSY_NEED_POP
#else
#undef ETXTBSY
#endif
#ifdef EFBIG_NEED_POP
#pragma pop_macro("EFBIG")
#undef EFBIG_NEED_POP
#else
#undef EFBIG
#endif
#ifdef ENOSPC_NEED_POP
#pragma pop_macro("ENOSPC")
#undef ENOSPC_NEED_POP
#else
#undef ENOSPC
#endif
#ifdef ESPIPE_NEED_POP
#pragma pop_macro("ESPIPE")
#undef ESPIPE_NEED_POP
#else
#undef ESPIPE
#endif
#ifdef EROFS_NEED_POP
#pragma pop_macro("EROFS")
#undef EROFS_NEED_POP
#else
#undef EROFS
#endif
#ifdef EMLINK_NEED_POP
#pragma pop_macro("EMLINK")
#undef EMLINK_NEED_POP
#else
#undef EMLINK
#endif
#ifdef EPIPE_NEED_POP
#pragma pop_macro("EPIPE")
#undef EPIPE_NEED_POP
#else
#undef EPIPE
#endif
#ifdef EDOM_NEED_POP
#pragma pop_macro("EDOM")
#undef EDOM_NEED_POP
#else
#undef EDOM
#endif
#ifdef ERANGE_NEED_POP
#pragma pop_macro("ERANGE")
#undef ERANGE_NEED_POP
#else
#undef ERANGE
#endif
#ifdef EDEADLK_NEED_POP
#pragma pop_macro("EDEADLK")
#undef EDEADLK_NEED_POP
#else
#undef EDEADLK
#endif
#ifdef ENOLCK_NEED_POP
#pragma pop_macro("ENOLCK")
#undef ENOLCK_NEED_POP
#else
#undef ENOLCK
#endif
#ifdef ENOSYS_NEED_POP
#pragma pop_macro("ENOSYS")
#undef ENOSYS_NEED_POP
#else
#undef ENOSYS
#endif
#ifdef ENOTEMPTY_NEED_POP
#pragma pop_macro("ENOTEMPTY")
#undef ENOTEMPTY_NEED_POP
#else
#undef ENOTEMPTY
#endif
#ifdef ELOOP_NEED_POP
#pragma pop_macro("ELOOP")
#undef ELOOP_NEED_POP
#else
#undef ELOOP
#endif
#ifdef EWOULDBLOCK_NEED_POP
#pragma pop_macro("EWOULDBLOCK")
#undef EWOULDBLOCK_NEED_POP
#else
#undef EWOULDBLOCK
#endif
#ifdef ENOMSG_NEED_POP
#pragma pop_macro("ENOMSG")
#undef ENOMSG_NEED_POP
#else
#undef ENOMSG
#endif
#ifdef EIDRM_NEED_POP
#pragma pop_macro("EIDRM")
#undef EIDRM_NEED_POP
#else
#undef EIDRM
#endif
#ifdef ECHRNG_NEED_POP
#pragma pop_macro("ECHRNG")
#undef ECHRNG_NEED_POP
#else
#undef ECHRNG
#endif
#ifdef EL2NSYNC_NEED_POP
#pragma pop_macro("EL2NSYNC")
#undef EL2NSYNC_NEED_POP
#else
#undef EL2NSYNC
#endif
#ifdef EL3HLT_NEED_POP
#pragma pop_macro("EL3HLT")
#undef EL3HLT_NEED_POP
#else
#undef EL3HLT
#endif
#ifdef EL3RST_NEED_POP
#pragma pop_macro("EL3RST")
#undef EL3RST_NEED_POP
#else
#undef EL3RST
#endif
#ifdef ELNRNG_NEED_POP
#pragma pop_macro("ELNRNG")
#undef ELNRNG_NEED_POP
#else
#undef ELNRNG
#endif
#ifdef EUNATCH_NEED_POP
#pragma pop_macro("EUNATCH")
#undef EUNATCH_NEED_POP
#else
#undef EUNATCH
#endif
#ifdef ENOCSI_NEED_POP
#pragma pop_macro("ENOCSI")
#undef ENOCSI_NEED_POP
#else
#undef ENOCSI
#endif
#ifdef EL2HLT_NEED_POP
#pragma pop_macro("EL2HLT")
#undef EL2HLT_NEED_POP
#else
#undef EL2HLT
#endif
#ifdef EBADE_NEED_POP
#pragma pop_macro("EBADE")
#undef EBADE_NEED_POP
#else
#undef EBADE
#endif
#ifdef ENAMETOOLONG_NEED_POP
#pragma pop_macro("ENAMETOOLONG")
#undef ENAMETOOLONG_NEED_POP
#else
#undef ENAMETOOLONG
#endif
#ifdef EBADR_NEED_POP
#pragma pop_macro("EBADR")
#undef EBADR_NEED_POP
#else
#undef EBADR
#endif
#ifdef EXFULL_NEED_POP
#pragma pop_macro("EXFULL")
#undef EXFULL_NEED_POP
#else
#undef EXFULL
#endif
#ifdef ENOANO_NEED_POP
#pragma pop_macro("ENOANO")
#undef ENOANO_NEED_POP
#else
#undef ENOANO
#endif
#ifdef EBADRQC_NEED_POP
#pragma pop_macro("EBADRQC")
#undef EBADRQC_NEED_POP
#else
#undef EBADRQC
#endif
#ifdef EBADSLT_NEED_POP
#pragma pop_macro("EBADSLT")
#undef EBADSLT_NEED_POP
#else
#undef EBADSLT
#endif
#ifdef EDEADLOCK_NEED_POP
#pragma pop_macro("EDEADLOCK")
#undef EDEADLOCK_NEED_POP
#else
#undef EDEADLOCK
#endif
#ifdef EBFONT_NEED_POP
#pragma pop_macro("EBFONT")
#undef EBFONT_NEED_POP
#else
#undef EBFONT
#endif
#ifdef ENOSTR_NEED_POP
#pragma pop_macro("ENOSTR")
#undef ENOSTR_NEED_POP
#else
#undef ENOSTR
#endif
#ifdef ENODATA_NEED_POP
#pragma pop_macro("ENODATA")
#undef ENODATA_NEED_POP
#else
#undef ENODATA
#endif
#ifdef ETIME_NEED_POP
#pragma pop_macro("ETIME")
#undef ETIME_NEED_POP
#else
#undef ETIME
#endif
#ifdef ENOSR_NEED_POP
#pragma pop_macro("ENOSR")
#undef ENOSR_NEED_POP
#else
#undef ENOSR
#endif
#ifdef ENONET_NEED_POP
#pragma pop_macro("ENONET")
#undef ENONET_NEED_POP
#else
#undef ENONET
#endif
#ifdef ENOPKG_NEED_POP
#pragma pop_macro("ENOPKG")
#undef ENOPKG_NEED_POP
#else
#undef ENOPKG
#endif
#ifdef EREMOTE_NEED_POP
#pragma pop_macro("EREMOTE")
#undef EREMOTE_NEED_POP
#else
#undef EREMOTE
#endif
#ifdef ENOLINK_NEED_POP
#pragma pop_macro("ENOLINK")
#undef ENOLINK_NEED_POP
#else
#undef ENOLINK
#endif
#ifdef EADV_NEED_POP
#pragma pop_macro("EADV")
#undef EADV_NEED_POP
#else
#undef EADV
#endif
#ifdef ESRMNT_NEED_POP
#pragma pop_macro("ESRMNT")
#undef ESRMNT_NEED_POP
#else
#undef ESRMNT
#endif
#ifdef ECOMM_NEED_POP
#pragma pop_macro("ECOMM")
#undef ECOMM_NEED_POP
#else
#undef ECOMM
#endif
#ifdef EPROTO_NEED_POP
#pragma pop_macro("EPROTO")
#undef EPROTO_NEED_POP
#else
#undef EPROTO
#endif
#ifdef EMULTIHOP_NEED_POP
#pragma pop_macro("EMULTIHOP")
#undef EMULTIHOP_NEED_POP
#else
#undef EMULTIHOP
#endif
#ifdef EDOTDOT_NEED_POP
#pragma pop_macro("EDOTDOT")
#undef EDOTDOT_NEED_POP
#else
#undef EDOTDOT
#endif
#ifdef EBADMSG_NEED_POP
#pragma pop_macro("EBADMSG")
#undef EBADMSG_NEED_POP
#else
#undef EBADMSG
#endif
#ifdef EOVERFLOW_NEED_POP
#pragma pop_macro("EOVERFLOW")
#undef EOVERFLOW_NEED_POP
#else
#undef EOVERFLOW
#endif
#ifdef ENOTUNIQ_NEED_POP
#pragma pop_macro("ENOTUNIQ")
#undef ENOTUNIQ_NEED_POP
#else
#undef ENOTUNIQ
#endif
#ifdef EBADFD_NEED_POP
#pragma pop_macro("EBADFD")
#undef EBADFD_NEED_POP
#else
#undef EBADFD
#endif
#ifdef EREMCHG_NEED_POP
#pragma pop_macro("EREMCHG")
#undef EREMCHG_NEED_POP
#else
#undef EREMCHG
#endif
#ifdef ELIBACC_NEED_POP
#pragma pop_macro("ELIBACC")
#undef ELIBACC_NEED_POP
#else
#undef ELIBACC
#endif
#ifdef ELIBBAD_NEED_POP
#pragma pop_macro("ELIBBAD")
#undef ELIBBAD_NEED_POP
#else
#undef ELIBBAD
#endif
#ifdef ELIBSCN_NEED_POP
#pragma pop_macro("ELIBSCN")
#undef ELIBSCN_NEED_POP
#else
#undef ELIBSCN
#endif
#ifdef ELIBMAX_NEED_POP
#pragma pop_macro("ELIBMAX")
#undef ELIBMAX_NEED_POP
#else
#undef ELIBMAX
#endif
#ifdef ELIBEXEC_NEED_POP
#pragma pop_macro("ELIBEXEC")
#undef ELIBEXEC_NEED_POP
#else
#undef ELIBEXEC
#endif
#ifdef EILSEQ_NEED_POP
#pragma pop_macro("EILSEQ")
#undef EILSEQ_NEED_POP
#else
#undef EILSEQ
#endif
#ifdef ERESTART_NEED_POP
#pragma pop_macro("ERESTART")
#undef ERESTART_NEED_POP
#else
#undef ERESTART
#endif
#ifdef ESTRPIPE_NEED_POP
#pragma pop_macro("ESTRPIPE")
#undef ESTRPIPE_NEED_POP
#else
#undef ESTRPIPE
#endif
#ifdef EUSERS_NEED_POP
#pragma pop_macro("EUSERS")
#undef EUSERS_NEED_POP
#else
#undef EUSERS
#endif
#ifdef ENOTSOCK_NEED_POP
#pragma pop_macro("ENOTSOCK")
#undef ENOTSOCK_NEED_POP
#else
#undef ENOTSOCK
#endif
#ifdef EDESTADDRREQ_NEED_POP
#pragma pop_macro("EDESTADDRREQ")
#undef EDESTADDRREQ_NEED_POP
#else
#undef EDESTADDRREQ
#endif
#ifdef EMSGSIZE_NEED_POP
#pragma pop_macro("EMSGSIZE")
#undef EMSGSIZE_NEED_POP
#else
#undef EMSGSIZE
#endif
#ifdef EPROTOTYPE_NEED_POP
#pragma pop_macro("EPROTOTYPE")
#undef EPROTOTYPE_NEED_POP
#else
#undef EPROTOTYPE
#endif
#ifdef ENOPROTOOPT_NEED_POP
#pragma pop_macro("ENOPROTOOPT")
#undef ENOPROTOOPT_NEED_POP
#else
#undef ENOPROTOOPT
#endif
#ifdef EPROTONOSUPPORT_NEED_POP
#pragma pop_macro("EPROTONOSUPPORT")
#undef EPROTONOSUPPORT_NEED_POP
#else
#undef EPROTONOSUPPORT
#endif
#ifdef ESOCKTNOSUPPORT_NEED_POP
#pragma pop_macro("ESOCKTNOSUPPORT")
#undef ESOCKTNOSUPPORT_NEED_POP
#else
#undef ESOCKTNOSUPPORT
#endif
#ifdef EOPNOTSUPP_NEED_POP
#pragma pop_macro("EOPNOTSUPP")
#undef EOPNOTSUPP_NEED_POP
#else
#undef EOPNOTSUPP
#endif
#ifdef ENOTSUP_NEED_POP
#pragma pop_macro("ENOTSUP")
#undef ENOTSUP_NEED_POP
#else
#undef ENOTSUP
#endif
#ifdef EPFNOSUPPORT_NEED_POP
#pragma pop_macro("EPFNOSUPPORT")
#undef EPFNOSUPPORT_NEED_POP
#else
#undef EPFNOSUPPORT
#endif
#ifdef ECONNRESET_NEED_POP
#pragma pop_macro("ECONNRESET")
#undef ECONNRESET_NEED_POP
#else
#undef ECONNRESET
#endif
#ifdef ENETDOWN_NEED_POP
#pragma pop_macro("ENETDOWN")
#undef ENETDOWN_NEED_POP
#else
#undef ENETDOWN
#endif
#ifdef EAFNOSUPPORT_NEED_POP
#pragma pop_macro("EAFNOSUPPORT")
#undef EAFNOSUPPORT_NEED_POP
#else
#undef EAFNOSUPPORT
#endif
#ifdef EADDRINUSE_NEED_POP
#pragma pop_macro("EADDRINUSE")
#undef EADDRINUSE_NEED_POP
#else
#undef EADDRINUSE
#endif
#ifdef EADDRNOTAVAIL_NEED_POP
#pragma pop_macro("EADDRNOTAVAIL")
#undef EADDRNOTAVAIL_NEED_POP
#else
#undef EADDRNOTAVAIL
#endif
#ifdef ENETUNREACH_NEED_POP
#pragma pop_macro("ENETUNREACH")
#undef ENETUNREACH_NEED_POP
#else
#undef ENETUNREACH
#endif
#ifdef ENETRESET_NEED_POP
#pragma pop_macro("ENETRESET")
#undef ENETRESET_NEED_POP
#else
#undef ENETRESET
#endif
#ifdef ECONNABORTED_NEED_POP
#pragma pop_macro("ECONNABORTED")
#undef ECONNABORTED_NEED_POP
#else
#undef ECONNABORTED
#endif
#ifdef ENOBUFS_NEED_POP
#pragma pop_macro("ENOBUFS")
#undef ENOBUFS_NEED_POP
#else
#undef ENOBUFS
#endif
#ifdef EISCONN_NEED_POP
#pragma pop_macro("EISCONN")
#undef EISCONN_NEED_POP
#else
#undef EISCONN
#endif
#ifdef ENOTCONN_NEED_POP
#pragma pop_macro("ENOTCONN")
#undef ENOTCONN_NEED_POP
#else
#undef ENOTCONN
#endif
#ifdef ESHUTDOWN_NEED_POP
#pragma pop_macro("ESHUTDOWN")
#undef ESHUTDOWN_NEED_POP
#else
#undef ESHUTDOWN
#endif
#ifdef ETOOMANYREFS_NEED_POP
#pragma pop_macro("ETOOMANYREFS")
#undef ETOOMANYREFS_NEED_POP
#else
#undef ETOOMANYREFS
#endif
#ifdef ETIMEDOUT_NEED_POP
#pragma pop_macro("ETIMEDOUT")
#undef ETIMEDOUT_NEED_POP
#else
#undef ETIMEDOUT
#endif
#ifdef ECONNREFUSED_NEED_POP
#pragma pop_macro("ECONNREFUSED")
#undef ECONNREFUSED_NEED_POP
#else
#undef ECONNREFUSED
#endif
#ifdef EHOSTDOWN_NEED_POP
#pragma pop_macro("EHOSTDOWN")
#undef EHOSTDOWN_NEED_POP
#else
#undef EHOSTDOWN
#endif
#ifdef EHOSTUNREACH_NEED_POP
#pragma pop_macro("EHOSTUNREACH")
#undef EHOSTUNREACH_NEED_POP
#else
#undef EHOSTUNREACH
#endif
#ifdef EALREADY_NEED_POP
#pragma pop_macro("EALREADY")
#undef EALREADY_NEED_POP
#else
#undef EALREADY
#endif
#ifdef EINPROGRESS_NEED_POP
#pragma pop_macro("EINPROGRESS")
#undef EINPROGRESS_NEED_POP
#else
#undef EINPROGRESS
#endif
#ifdef ESTALE_NEED_POP
#pragma pop_macro("ESTALE")
#undef ESTALE_NEED_POP
#else
#undef ESTALE
#endif
#ifdef EUCLEAN_NEED_POP
#pragma pop_macro("EUCLEAN")
#undef EUCLEAN_NEED_POP
#else
#undef EUCLEAN
#endif
#ifdef ENOTNAM_NEED_POP
#pragma pop_macro("ENOTNAM")
#undef ENOTNAM_NEED_POP
#else
#undef ENOTNAM
#endif
#ifdef ENAVAIL_NEED_POP
#pragma pop_macro("ENAVAIL")
#undef ENAVAIL_NEED_POP
#else
#undef ENAVAIL
#endif
#ifdef EISNAM_NEED_POP
#pragma pop_macro("EISNAM")
#undef EISNAM_NEED_POP
#else
#undef EISNAM
#endif
#ifdef EREMOTEIO_NEED_POP
#pragma pop_macro("EREMOTEIO")
#undef EREMOTEIO_NEED_POP
#else
#undef EREMOTEIO
#endif
#ifdef EDQUOT_NEED_POP
#pragma pop_macro("EDQUOT")
#undef EDQUOT_NEED_POP
#else
#undef EDQUOT
#endif
#ifdef ENOMEDIUM_NEED_POP
#pragma pop_macro("ENOMEDIUM")
#undef ENOMEDIUM_NEED_POP
#else
#undef ENOMEDIUM
#endif
#ifdef EMEDIUMTYPE_NEED_POP
#pragma pop_macro("EMEDIUMTYPE")
#undef EMEDIUMTYPE_NEED_POP
#else
#undef EMEDIUMTYPE
#endif
#ifdef ECANCELED_NEED_POP
#pragma pop_macro("ECANCELED")
#undef ECANCELED_NEED_POP
#else
#undef ECANCELED
#endif
#ifdef ENOKEY_NEED_POP
#pragma pop_macro("ENOKEY")
#undef ENOKEY_NEED_POP
#else
#undef ENOKEY
#endif
#ifdef EKEYEXPIRED_NEED_POP
#pragma pop_macro("EKEYEXPIRED")
#undef EKEYEXPIRED_NEED_POP
#else
#undef EKEYEXPIRED
#endif
#ifdef EKEYREVOKED_NEED_POP
#pragma pop_macro("EKEYREVOKED")
#undef EKEYREVOKED_NEED_POP
#else
#undef EKEYREVOKED
#endif
#ifdef EKEYREJECTED_NEED_POP
#pragma pop_macro("EKEYREJECTED")
#undef EKEYREJECTED_NEED_POP
#else
#undef EKEYREJECTED
#endif
#ifdef EOWNERDEAD_NEED_POP
#pragma pop_macro("EOWNERDEAD")
#undef EOWNERDEAD_NEED_POP
#else
#undef EOWNERDEAD
#endif
#ifdef ENOTRECOVERABLE_NEED_POP
#pragma pop_macro("ENOTRECOVERABLE")
#undef ENOTRECOVERABLE_NEED_POP
#else
#undef ENOTRECOVERABLE
#endif
#ifdef ERFKILL_NEED_POP
#pragma pop_macro("ERFKILL")
#undef ERFKILL_NEED_POP
#else
#undef ERFKILL
#endif
#ifdef EHWPOISON_NEED_POP
#pragma pop_macro("EHWPOISON")
#undef EHWPOISON_NEED_POP
#else
#undef EHWPOISON
#endif

#endif // _PINOS_ERRNO_H_
