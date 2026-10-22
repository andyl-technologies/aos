# Bounded-thread libc patch licenses

`bounded-pthread-2.39.patch` applies the signed upstream-source commits
`ce6644ba7f40ac9436a9cc0bb2c30b69bf8f977a` and
`dae19eda3e0ca54dc8198ef83e8ba1a6c187441e` to glibc 2.39,
base `128392568abf34075115815f007376f50489fdcf`. The resulting Git tree is
`54b4ee8cfae3fd4241985304b0edc70e0150e992`. Both commits carry the
author's DCO sign-off. The complete upstream source and this exact patch are
retained as package source evidence. Upstream `COPYING`, `COPYING.LIB`,
`LICENSES` and existing per-file notices remain in that source.

The following ledger covers every changed or added upstream file. All carry
LGPL-2.1-or-later terms, either their preserved explicit file notice or the
new file's explicit SPDX identifier. It does not change the licenses of
other glibc files or transfer libc implementation into the host protocol.

| Upstream path | Change | License |
| --- | --- | --- |
| `dlfcn/dlerror.c` | Modified | LGPL-2.1-or-later |
| `dlfcn/libc_dlerror_result.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-libc.c` | Modified | LGPL-2.1-or-later |
| `elf/dl-tls.c` | Modified | LGPL-2.1-or-later |
| `include/pthread-bounded-internal.h` | Added | LGPL-2.1-or-later |
| `include/pthread-bounded.h` | Added | LGPL-2.1-or-later |
| `malloc/arena.c` | Modified | LGPL-2.1-or-later |
| `malloc/malloc.c` | Modified | LGPL-2.1-or-later |
| `nptl/Makefile` | Modified | LGPL-2.1-or-later |
| `nptl/README.bounded-pthread` | Added | LGPL-2.1-or-later |
| `nptl/Versions` | Modified | LGPL-2.1-or-later |
| `nptl/allocatestack.c` | Modified | LGPL-2.1-or-later |
| `nptl/descr.h` | Modified | LGPL-2.1-or-later |
| `nptl/nptl_deallocate_tsd.c` | Modified | LGPL-2.1-or-later |
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
| `sunrpc/rpc_thread.c` | Modified | LGPL-2.1-or-later |
| `sysdeps/unix/sysv/linux/tls-internal.c` | Modified | LGPL-2.1-or-later |
| `sysdeps/unix/sysv/linux/x86_64/64/libc.abilist` | Modified | LGPL-2.1-or-later |

Patch SHA-256: `c6874ac723b6c41d4b708a203c578db3449e323c2c9b42be14527a6bef3b3301`.
