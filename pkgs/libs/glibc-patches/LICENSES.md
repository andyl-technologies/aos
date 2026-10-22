# Bounded-provider libc patch licenses

`bounded-pthread-2.39.patch` is the complete glibc 2.39 difference from base
`128392568abf34075115815f007376f50489fdcf` to signed source
`cff34ac416ff0650048fd85d50e156434f5cb9ed`, tree
`9253d845b69f5fc16ab322b38d13b08092d4664f`. Applying the canonical patch
with the index produces that exact tree. The source range contains these
signed, DCO-certified commits, in order:

- `ce6644ba7f40ac9436a9cc0bb2c30b69bf8f977a`
- `dae19eda3e0ca54dc8198ef83e8ba1a6c187441e`
- `02b2c0402b0d7d79478b09718cc6fb0f77da54f7`
- `eed10dad7a5f2ebf9968ecf993ab7d30880ed88b`
- `908402f575492f462e74a39e46384ab12aa023bb`
- `39425b83aec13492400eccc0ea96d920f236099c`
- `fe88ebc237bad3b3880a52ab7f2c29082ce6e3f2`
- `34af6e6a74edbac870ffb5fa1cbf667d0927e17f`
- `9ec3dc41fde9abcbd3ce3f1bf91f87fedd63ae3a`
- `1bf55416f45a7cf7f426f445bd84abb5149072e1`
- `cff34ac416ff0650048fd85d50e156434f5cb9ed`

The complete upstream source and exact patch remain package source evidence.
Upstream `COPYING`, `COPYING.LIB`, `LICENSES` and existing per-file notices
remain in that source. This ledger covers all 62 modified or added paths.
Internal forwarding headers and build/ABI data retain GNU C Library scope;
files with explicit notices retain those notices. The unmarked RPC source
retains the upstream repository notices; no new per-file license is invented.
Libc implementation remains outside the host protocol.

| Upstream path | Change | License or retained scope |
| --- | --- | --- |
| `dlfcn/dlerror.c` | Modified | LGPL-2.1-or-later |
| `dlfcn/libc_dlerror_result.c` | Modified | LGPL-2.1-or-later |
| `elf/Makefile` | Modified | LGPL-2.1-or-later |
| `elf/README.bounded-initial` | Added | LGPL-2.1-or-later |
| `elf/dl-bounded-initial.c` | Added | LGPL-2.1-or-later |
| `elf/dl-bounded-initial.h` | Added | LGPL-2.1-or-later |
| `elf/dl-catch.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-libc.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-minimal-malloc.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-minimal.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-misc.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-printf.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-tls.c` | Modified | LGPL-2.1-or-later |
| `elf/rtld.c` | Modified | LGPL-2.1-or-later |
| `elf/tst-bounded-initial-launch.c` | Added | LGPL-2.1-or-later |
| `elf/tst-bounded-initial-mod.c` | Added | LGPL-2.1-or-later |
| `elf/tst-bounded-initial.py` | Added | LGPL-2.1-or-later |
| `include/malloc-bounded-initial.h` | Added | LGPL-2.1-or-later |
| `include/malloc-bounded-internal.h` | Added | LGPL-2.1-or-later |
| `include/malloc-bounded-process.h` | Added | LGPL-2.1-or-later |
| `include/malloc-bounded.h` | Added | LGPL-2.1-or-later |
| `include/pthread-bounded-internal.h` | Added | GNU C Library; COPYING.LIB and retained notices |
| `include/pthread-bounded.h` | Added | LGPL-2.1-or-later |
| `malloc/Makefile` | Modified | LGPL-2.1-or-later |
| `malloc/README.bounded-application` | Added | LGPL-2.1-or-later |
| `malloc/Versions` | Modified | GNU C Library; COPYING.LIB and retained notices |
| `malloc/arena.c` | Modified | LGPL-2.1-or-later |
| `malloc/malloc-bounded-initial.h` | Added | LGPL-2.1-or-later |
| `malloc/malloc-bounded-internal.h` | Added | LGPL-2.1-or-later |
| `malloc/malloc-bounded-process.h` | Added | LGPL-2.1-or-later |
| `malloc/malloc-bounded.c` | Added | LGPL-2.1-or-later |
| `malloc/malloc-bounded.h` | Added | LGPL-2.1-or-later |
| `malloc/malloc.c` | Modified | LGPL-2.1-or-later |
| `malloc/tst-malloc-bounded-glib.c` | Added | LGPL-2.1-or-later |
| `malloc/tst-malloc-bounded.c` | Added | LGPL-2.1-or-later |
| `nptl/Makefile` | Modified | LGPL-2.1-or-later |
| `nptl/README.bounded-pthread` | Added | LGPL-2.1-or-later |
| `nptl/Versions` | Modified | GNU C Library; COPYING.LIB and retained notices |
| `nptl/allocatestack.c` | Modified | LGPL-2.1-or-later |
| `nptl/descr.h` | Modified | LGPL-2.1-or-later |
| `nptl/nptl_deallocate_tsd.c` | Modified | LGPL-2.1-or-later |
| `nptl/pthread-bounded-create.c` | Added | LGPL-2.1-or-later |
| `nptl/pthread-bounded-internal.h` | Added | LGPL-2.1-or-later |
| `nptl/pthread-bounded.c` | Added | LGPL-2.1-or-later |
| `nptl/pthread-bounded.h` | Added | LGPL-2.1-or-later |
| `nptl/pthread_create.c` | Modified | LGPL-2.1-or-later |
| `nptl/pthread_detach.c` | Modified | LGPL-2.1-or-later |
| `nptl/pthread_join_common.c` | Modified | LGPL-2.1-or-later |
| `nptl/pthread_setspecific.c` | Modified | LGPL-2.1-or-later |
| `nptl/tpp.c` | Modified | LGPL-2.1-or-later |
| `nptl/tst-pthread-bounded-mod.c` | Added | LGPL-2.1-or-later |
| `nptl/tst-pthread-bounded.c` | Added | LGPL-2.1-or-later |
| `resolv/res-close.c` | Modified | LGPL-2.1-or-later |
| `resolv/res_init.c` | Modified | LGPL-2.1-or-later |
| `resolv/resolv_context.c` | Modified | LGPL-2.1-or-later |
| `stdlib/cxa_thread_atexit_impl.c` | Modified | LGPL-2.1-or-later |
| `string/strerror_l.c` | Modified | LGPL-2.1-or-later |
| `string/strsignal.c` | Modified | LGPL-2.1-or-later |
| `sunrpc/rpc_thread.c` | Modified | Retained upstream COPYING, COPYING.LIB and LICENSES |
| `sysdeps/unix/sysv/linux/dl-sysdep.c` | Modified | LGPL-2.1-or-later |
| `sysdeps/unix/sysv/linux/tls-internal.c` | Modified | LGPL-2.1-or-later |
| `sysdeps/unix/sysv/linux/x86_64/64/libc.abilist` | Modified | GNU C Library; COPYING.LIB and retained notices |

Patch SHA-256: `fdc7fc26a7373e7ac4c2d48ac5508e077699e270300aa4851d2c683386ceaee5`.
