# DMTCP source patch license inventory

Upstream revision: `f8009ce7b4ad211311ca2f72a929b975e4aa1155`
(release 4.2.0). Every modified implementation file retains its original
LGPL-3.0-or-later notice and copyright holders. No upstream source file is added
or removed.

| Change | Modified upstream files | Preserved license |
| --- | --- | --- |
| `restart-environment-bounds.patch` | `src/dmtcpplugin.cpp` | LGPL-3.0-or-later |
| `checkpoint-signal-parse.patch` | `src/dmtcpworker.cpp` | LGPL-3.0-or-later |
| `capture-context-ledger.patch` | `src/threadlist.cpp`, `src/shareddata.cpp`; declarations in `include/dmtcp.h` | LGPL-3.0-or-later implementation; public-domain interface header |
| `capture-kernel-thread-identity.patch` | `src/threadlist.cpp` | LGPL-3.0-or-later |
| `capture-descriptor-ledger.patch` | `src/threadlist.cpp`; declarations and native capture record format in `include/dmtcp.h` | LGPL-3.0-or-later implementation; public-domain interface header |
| `capture-mapping-ledger.patch` | `src/writeckpt.cpp`, `include/procselfmaps.h`; declarations in `include/dmtcp.h` | LGPL-3.0-or-later implementation; public-domain interface header |
| `capture-file-mapping-ledger.patch` | `src/plugin/ipc/file/fileconnlist.cpp`; declarations in `include/dmtcp.h` | LGPL-3.0-or-later implementation; public-domain interface header |
| `restore-saved-file-relocation.patch` | `src/plugin/ipc/file/fileconnection.cpp`; declaration in `include/dmtcp.h` | LGPL-3.0-or-later implementation; public-domain interface header |
| `restore-file-mode-preservation.patch` | `src/plugin/ipc/file/fileconnection.cpp` | Original LGPL-3.0-or-later notice and copyright holders retained |
| Hermetic loader/path substitutions in `dmtcp.nix` | `configure`, `configure.ac`, `src/util_exec.cpp`, `src/restartscript.cpp`, `src/glibcsystem.cpp`, `src/popen.cpp`, `src/plugin/ipc/ssh/ssh.cpp`, shell and Python entry-point shebangs | Each file's unchanged upstream notice; implementation files retain LGPL-3.0-or-later |

The package installs `COPYING` and `COPYING.LESSER`. Distribution of modified
DMTCP binaries must satisfy the upstream LGPL's applicable source and relinking
requirements. Source availability for a different implementation or unpatched
release does not discharge those requirements.

The binary output co-retains its matching `source` output through
`share/corresponding-source`. That output includes the complete actual source
tree after patches and hermetic substitutions, the upstream archive, exact
patches, recipe, toolchain manifest and license inventory. The native toolkit
uses shared libraries; the independently licensed host does not statically
link its implementation.

`continuation-check.c` is an independently authored MIT mechanism test and is not
installed as a toolkit implementation. The pinned public `include/dmtcp.h`
header is explicitly dedicated to the public domain, while the implementation
and dynamically loaded libraries remain LGPL-3.0-or-later.
