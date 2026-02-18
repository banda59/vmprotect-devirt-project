#ifndef	_SYS_IO_H
#define	_SYS_IO_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#include <bits/io.h>

int iopl(int);
int ioperm(unsigned _arch_long, unsigned _arch_long, int);

#ifdef __cplusplus
}
#endif
#endif
