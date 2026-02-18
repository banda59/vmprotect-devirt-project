Headers in this directory are copied from Musl `arch/i386/bits` & `arch/x86_64/bits` and changed where required for PINOS.
In musl the headers under `arch/pinos32/bits` & `arch/pinos64/bits` include the headers from (pbits).
So for instance `arch/pinos32/bits/signal.h` looks like this:
```C
#include <pbits/ia32/signal.h>
```

Files that don't appear under `arch/pinosXX/bits` are taken from `arch/generic/bits`.

`syscall.h` contain the generic syscall definitions and it is shared by both pinos32 & pinos64 and is included from `arch/pinosXX/bits/syscall.h.in` which is preprocessed by the build system to create the final `bits/syscall.h`.

`errno.h` could have been taken from `arch/generic/bits` however we need it for direct inclusion from `pinos_errno.h` which we also use when building binaries that use PINOS with the system runtime and so can't rely on Musl header hierarchy (for instance on Linux there is a native `bits/errno.h` which would conflict with ours).

`fcntl.h` could have been taken from `arch/generic/bits` but we added some constants of our own to it.

The headers (and subfolders) here are copied to the kit under:
`<arch>/pinrt/include/pinos/pbits`

PinOS unitest notes:
NOTE_1:
In PinOS unitest (PINRT_TEST defined), we don't use system headers which collides with pbits headers (See NOTE_2 below) and don't use musl headers directly.
However there are some exceptions to this rule. Under PINRT_TEST, there are some system header we want to take from Musl (e.g atomic_arch.h in pinosatomic.hxx) 
but don't want to move into pbits since not needed in the regular flow (not unitest).
Therefore we add ${PINCRT_SRC_DIR}/arch) to the include path, so that one can include such header in a relative way (so it won't collide with native system headers).

NOTE_2: 
We don't want to include system headers in unitest files as it may collide\differ with our pinos headers. Therefore we provide our own declarations in such cases in unitest files. 