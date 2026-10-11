# DMTCP source patch license inventory

Upstream revision: `f8009ce7b4ad211311ca2f72a929b975e4aa1155`
(release 4.2.0). Every modified implementation file retains its original
LGPL-3.0-or-later notice and copyright holders. Existing notices remain intact. The selected variant adds native LGPL-compatible
implementation headers and one writer-account implementation; no file is removed.

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

The distinct `selected-writer-cohort.patch` retains the following source roles.

| Native source role | License and custody |
| --- | --- |
| `src/ckptserializer.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/dmtcprestartinternal.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/dmtcpmessagetypes.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/coordinatorapi.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/lookup_service.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/Makefile.am` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/crucible_single_worker.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/restartscript.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/dmtcp_coordinator.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/dmtcpmessagetypes.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/threadlist.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/coordinatorapi.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/writeckpt.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/crucible_capture_budget.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/dmtcp_coordinator.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/util_init.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/dmtcpworker.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/crucible_capture_budget.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/dmtcp_launch.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `jalib/jassert.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `jalib/jassert.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/plugin/ipc/file/fileconnection.cpp` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/crucible_final_frame.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/crucible_control_frame.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `jalib/crucible_log_writer.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |
| `src/crucible_restart_writer.h` | Original LGPL-3.0-or-later implementation scope and notices; selected additions remain in the native process |

| `src/dmtcpnohijackstubs.cpp` | Preserved upstream LGPL-3.0-or-later notices; nonworker utilities explicitly refuse worker account finalization without effects |

Configured TU and inert control results do not authorize capture, restored account adoption, publication, or a source-qualified installed importer. The default no-Child and early-restart refusals remain. The separate Apache host consumes versioned byte bodies and does not link these native files.

The distinct terminal-park successor appends exact selected-only changes to the same six native roles. The explicit terminal.v1 selector seals existing settled control custody before application resume; no missing selector changes the ordinary or earlier selected route. No LGPL/native body enters Apache host code. Early restored account adoption remains unsupported.

The nonworker finalized-history link successor adds an explicitly unsupported false/ENOTSUP predicate to src/dmtcpnohijackstubs.cpp; actual worker history and all original notices remain unchanged.
