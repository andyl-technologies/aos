# DMTCP source patch license inventory

Upstream revision: `f8009ce7b4ad211311ca2f72a929b975e4aa1155`
(release 4.2.0). Every modified implementation file retains its original
LGPL-3.0-or-later notice and copyright holders. No upstream source file is added
or removed.

| Change | Modified upstream files | Preserved license |
| --- | --- | --- |
| `restart-environment-bounds.patch` | `src/dmtcpplugin.cpp` | LGPL-3.0-or-later |
| `checkpoint-signal-parse.patch` | `src/dmtcpworker.cpp` | LGPL-3.0-or-later |
| Hermetic loader/path substitutions in `dmtcp.nix` | `configure`, `configure.ac`, `src/util_exec.cpp`, `src/restartscript.cpp`, `src/glibcsystem.cpp`, `src/popen.cpp`, `src/plugin/ipc/ssh/ssh.cpp`, shell and Python entry-point shebangs | Each file's unchanged upstream notice; implementation files retain LGPL-3.0-or-later |

The package installs `COPYING` and `COPYING.LESSER`. Distribution of modified
DMTCP binaries must satisfy the upstream LGPL's applicable source and relinking
requirements. Source availability for a different implementation or unpatched
release does not discharge those requirements.

`continuation-check.c` is an independently authored MIT mechanism test and is not
installed as a toolkit implementation. The pinned public `include/dmtcp.h`
header is explicitly dedicated to the public domain, while the implementation
and dynamically loaded libraries remain LGPL-3.0-or-later.
