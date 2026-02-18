#ifndef _SYS_AUXV_H
#define _SYS_AUXV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <elf.h>
#include <bits/hwcap.h>

unsigned _arch_long getauxval(unsigned _arch_long);

#ifdef __cplusplus
}
#endif

#endif
