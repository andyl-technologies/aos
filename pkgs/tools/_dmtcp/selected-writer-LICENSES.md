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
| Hermetic loader/path substitutions in `dmtcp-selected-writer-park.nix` | `configure`, `configure.ac`, `src/util_exec.cpp`, `src/restartscript.cpp`, `src/glibcsystem.cpp`, `src/popen.cpp`, `src/plugin/ipc/ssh/ssh.cpp`, shell and Python entry-point shebangs | Each file's unchanged upstream notice; implementation files retain LGPL-3.0-or-later |

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

The cumulative `selected-writer-terminal-park.patch` retains the following 27 source roles.

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

The distinct `selected-exec-custody.patch` preserves all original notices in
`include/protectedfds.h`, `jalib/crucible_log_writer.h`, `jalib/jassert.cpp`,
`src/crucible_single_worker.h`, `src/crucible_control_frame.h`,
`src/crucible_final_frame.h`, `src/dmtcp_launch.cpp`, `src/util_init.cpp`,
`src/execwrappers.cpp`, `src/uniquepid.h`, `src/uniquepid.cpp`, and
`src/crucible_restart_writer.h`. It adds `src/crucible_exec_state.h`,
`src/crucible_exec_custody.h`, `src/crucible_kernel_identity.h`, and
`src/crucible_descriptor_scope.h` under
LGPL-3.0-or-later; no native file is removed. All code executes within the
native toolkit processes. The separate Apache host consumes versioned data
and does not link or include these implementation files.

`exec-custody-controls.cpp` is an independently authored LGPL-3.0-or-later
component test. Its source is retained in the corresponding-source output.
It checks original debit, body, peer and descriptor preservation and source
selected kernel identity; parsed records and component checks do not authorize
source issuance, operative restored-account adoption, or node readiness.

The distinct `selected-source-custody.patch` preserves the original notices in
`src/dmtcp_coordinator.cpp` and `src/crucible_exec_state.h`. It adds
`src/crucible_source_capsule.h`, `src/crucible_source_custody.h`, and
`src/crucible_source_capsule_reader.h` under LGPL-3.0-or-later; no native file is
removed. These implementation files run solely inside the native toolkit.
The separate Apache host neither links them nor includes their headers.

`source-capsule-controls.cpp` is an independently authored LGPL-3.0-or-later
component test retained in the corresponding-source output. It checks the
bounded capsule, original export charges, complete script/final storage and
coordinator account validation. Exported or parsed preservation data does not
issue whole guest/device/clock/image source permission, operative restored-account
adoption, or node readiness. The ordinary toolkit application/checkpoint/two
fresh reconstruction checks remain mandatory and separate from these controls.


The distinct `selected-map-envelope.patch` preserves the original notices in
`src/coordinatorapi.cpp`, `src/dmtcpworker.cpp`, `src/dmtcp_coordinator.cpp`,
`src/lookup_service.cpp`, `src/lookup_service.h`, `src/dmtcpmessagetypes.cpp`,
and `src/dmtcpmessagetypes.h`. It adds `src/crucible_map_envelope.h`,
`src/crucible_map_transfer.h`, `src/crucible_map_state.h`,
`src/crucible_map_final.h`, `src/crucible_map_codec.h`,
`src/crucible_map_source_capsule.h`, `src/crucible_map_source_custody.h`,
and `src/crucible_map_source_capsule_reader.h` under LGPL-3.0-or-later;
no native file is removed. All implementation code executes inside native
checkpoint processes. The separate Apache host neither links this code nor
includes its headers.

`map-custody-controls.cpp` and `map-capsule-reader.cpp` are independently
authored LGPL-3.0-or-later component sources retained in the corresponding-source
output. They check bounded full map bodies, constructor storage and nonrenewing
charges, the distinct capsule and codec, and borrowed complete-record parsing.
These controls and preservation bytes do not issue native whole-node permission,
operative restored-account adoption, or node readiness. Normal toolkit
application/checkpoint/two fresh reconstruction checks remain mandatory and
separate from real selected gem5 capture and continuation qualification.


The distinct `selected-source-owners.patch` preserves original notices in
`src/shareddata.cpp`, `src/crucible_exec_custody.h`, `src/threadlist.cpp`, and
`src/threadwrappers.cpp`. It adds `src/crucible_original_shared_area.h`,
`src/crucible_original_thread_owner.h`, and `src/crucible_raw_kernel_call.h`
under LGPL-3.0-or-later. No native file is removed. The explicit selected
shared-birth and atomic-loop routes retain source creation/thread effects and
original finite banks; ordinary routes preserve their existing behavior.
The complete shared-area preservation extension is an explicit exec-transfer
edition 2; existing standalone producer/capsule codecs retain edition 1.

`shared-area-controls.cpp`, `thread-owner-controls.cpp`,
`source-launch-probe.cpp`, `source-launch-controls.cpp`, and
`source-launch-peer-controls.h` are independently authored LGPL-3.0-or-later
native mechanism sources co-retained in the corresponding-source output.
The library diagnostic returns scalar original exec observations, never a
native cut permit. The separate Apache host neither links nor includes these
implementation files. Kernel controls, production exec observation and parsed
preservation data do not qualify a whole native process closure, checkpoint
issuer, operative restore adopter or SourceReady. Ordinary toolkit
application/checkpoint/two fresh reconstruction checks remain mandatory.


The source-owner identity correction keeps DMTCP's virtual `Thread::tid` and
PID plugin behavior intact. Only the selected original-owner binding obtains
its TID through the noninterposed raw kernel adapter. Native kernel identity
and checkpoint-visible virtual identity remain separate.

`source-unselected-probe.cpp` and `source-unselected-controls.cpp` are
independently authored LGPL-3.0-or-later diagnostic sources co-retained with
this recipe. The selected launch control owns a separate empty mode-0600
console per native producer and checks exact original cancellation and
selected stream-EOF refusal statuses. Its ordinary inverse checks zero exits
for the application and coordinator. These controls grant no whole-process
closure, source-cut permit, checkpoint issuer, restored adoption or readiness.


`source-command-dispatch.patch` preserves the original LGPL-3.0-or-later
notice in `src/util_exec.cpp` and adds `src/dmtcp_source_command.h` under
LGPL-3.0-or-later. The recipe generates and co-retains
`src/dmtcp_source_command_paths.h` under the same license with explicit
source-built shell/copy paths. No file is removed. The nonworker launcher
uses its already-created SharedData tmpdir instead of a worker-only API stub;
ordinary worker access remains equivalent.

The executable-copy command quotes each literal operand and separates options
from paths. The launcher preserves spaces, quotes, substitutions, and hostname
punctuation as path bytes instead of interpreting them as shell syntax.

`source-command-controls.cpp` is an independently authored LGPL-3.0-or-later
component source co-retained in the corresponding-source output. It observes
the actual AOS shell ELF, encoded normal/signal/missing-shell outcomes,
concurrent commands, restored signal dispositions/masks, and retirement of a
real canceled helper. The check also retains normal and copied-executable
application/coordinator zero-exit controls. Explicit source-built C++ runtime
search prevents a bootstrap static/shared forced-unwind mismatch; existing
hardening remains enabled. These results grant no native whole-node cut,
checkpoint issuer, restored-account adoption or SourceReady authority.
