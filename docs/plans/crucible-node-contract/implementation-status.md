# RFC-0025 implementation status

Implementation work tracks the full [RFC-0025](../../rfcs/0025-crucible-node-contract/README.md).
The PR remains draft. Component tests and separately qualified native profiles
do not establish completion of the full architecture.

This summary accompanies the [phased implementation plan](phased-implementation.md)
and [qualification plan](qualification-plan.md). Detailed test logs, images,
traces and experiment history remain local. Test counts below identify their
specific stage; they are not cumulative coverage of the latest source.

## Implemented areas

| Area | Implemented behavior | Remaining qualification |
| --- | --- | --- |
| Common node contract | Backend-neutral lifecycle, capabilities, graph admission, causal scheduling, owner exclusion and implementation-bound archives | Final-source checks and complete production routing |
| Existing execution | Shared campaign and attempt APIs with legacy compatibility aliases, canonical identities and separate observed provenance | Final legacy compatibility and performance comparison |
| Public providers | Authenticated CNP/1, extension negotiation, bounded control/evidence transfers, request journals and original pending-operation custody | Complete installed-source behavioral acceptance and vendor acceptance |
| Host models | Clock, source, Block, readonly 9p and network mechanisms; retained native state and original input lineage | Ordinary mixed-world service integration and complete conformance for each selected profile |
| QEMU | Process-separated native CPU/timer/control observations, original callback custody and matching corresponding source | Current ABI/license gates and full-scenario preservation |
| gem5 | Source-built x86/AArch64 models, process-separated controller, bounded journals and backend-bound continuation | Complete Linux device parity, common-node readiness and full-world preservation |
| Quantized execution | Nondeterminism propagation, explicit capabilities and KVM clock/timer mediation | Paced hardware execution and full KVM node qualification |

The Apache host and GPL-side QEMU/plugin remain separate processes, using
versioned socket/shared-memory protocols. QEMU publication retains the matching
complete corresponding source. Backend-neutral state cannot relabel a saved
backend implementation or upgrade observation data into execution authority.

## Verified checkpoints

### Shared runtime and public integration

Earlier committed stages exercise real public providers, connected-node routing,
original pending inputs, source retirement and fresh native continuations. The
CLI preservation stage also restarts through fresh daemon processes. Those
results apply to their recorded profiles and source revisions.

Original-owner capture budgets, bounded cleanup notification and collecting
restoration phases are committed in `dfd1c93c16`, with formatting separately in
`4feaa76dc2`. Normal four-crate/all-feature/all-target checking passes for that
stage. Fresh executables pass 83 selected controls: 62 Core, eighteen daemon and
three canonical-ACK integration cases, with no failures or ignored tests.
Earlier Waker-identity failures remain failures; the correction retains and
clones the same original Waker. These component controls do not qualify complete
native Capture or fresh restoration.

Provider storage projections and prepared Blob acknowledgement checks are
committed in `19b42f9d65`, with formatting separately in `15a7be2dec`. All 89
selected provider controls pass against the complete 435-file owned dependency
set. This checkpoint has no dependency on subsequent Core changes.

### Application compilation

The production compiler build and installed compiler verification pass. The
refreshed mandatory application-target gate passes for the pre-dedup
original-report checkpoint, compiling 167 test targets across
all 48 selected application roots, including 69 integration targets. Independent
verification checks the actual compiler messages, captured source, artifact
roles and registered output. This gate compiles tests without executing them;
Crucible daemon runtime checks are separate.

### QEMU package

The ordinary QEMU package passes 589 upstream TAP checks, 44 project model/cost
fixtures and 274 static predicates. Installed verification checks its exact
binary/source pair, retained source, licenses and aggregate-only publication
policy. This does not establish success of the current ABI/license gates or
full-scenario preservation.

### gem5 packages and Linux boot

Commit `9decfccd3f` shares Linux fixtures, binds profiles to captured recipes and
filters Python bytecode from host source inputs. Independent installed
verification passes for the filtered package and corresponding source, including
ten registrations, thirty reports, 162 joins, 154 host entries and 47 recipes.
The native compiler is unchanged. Host capture is cache-free; unopened upstream
archives have not been independently scanned.

Commit `48eefd89ea` lets the Linux check package select a four-second simulated
horizon while preserving the checker's two-second default. Two fresh x86 Linux
boots reach PID1 and produce identical 20,717-byte consoles, 3,174,768,710,000
ticks and 317,480,064 callbacks. Independent installed verification checks both
raw consoles and receipts, source copies and registered outputs. The bounded
package and eleven modeled controls pass.

Both earlier two-second boot failures remain failures. The instrumented failure
reaches current tick 1,999,999,990,000 with the next event at the exclusive
2,000,000,000,000-tick horizon. The four-second result qualifies Linux/PID1 boot
only. It does not qualify common-node readiness, Capture, restoration, CPU timing
fidelity or device parity. The published birth digest agrees across runs; the
complete birth-event archive was not retained for independent recomputation.

Earlier separately qualified x86/AArch64 model profiles exercise source removal,
two fresh continuations, resource-root relocation and fresh recapture. Those
profile-specific results do not establish full Linux preservation. The new ARM
Linux boot check remains unqualified.

## Work in progress

The pre-dedup original-report/storage checkpoint passes normal five-crate,
all-feature/all-target checking and 196 selected runtime controls: two campaign,
120 provider, 71 Core and three integration cases. Its daemon cohort fails:
five startup cases report resource-policy errors before an archive-validation
case exceeds the 120-second cohort budget. A separate run confirms all five
startup failures, and the archive case also exceeds 120 seconds in isolation.
These failures remain unresolved qualification failures; this stage is
uncommitted.

The startup fixture selects a 64 KiB negotiated message window whose conservative
report projections exceed its 512 MiB policy. That policy correctly refuses.
A separately configured positive fixture and an explicit original-window
negative are being checked without reducing production accounting or raising
that policy.

The archive test repeatedly hashes actual measured files. A proposed optimization
shares completed full hashes of exact aliases within one validation pass while
retaining every descriptor/path fence and sticky refusal. The next pass hashes
again. Four new controls cover aliases, distinct inodes, full content pins and
observed drift. The change is imported but uncompiled and unrun; no performance
gain is claimed yet.

Further source work covers original allocation admission before native startup,
full Prepare/report publication, same-owner query budgets, the ordinary Clock
qualification route and mixed-world service integration. Source review of those
changes does not establish execution or native qualification. Missing original
owners, unknown storage and unavailable baseline/native prerequisites continue
to refuse.

## Known gaps and exit criteria

Completion requires the full [qualification plan](qualification-plan.md),
including:

- Complete native Capture, original source/resource removal and two independent
  fresh-world restorations with exact continuation.
- Production backend routing, mixed native execution, device parity and public
  vendor acceptance for every advertised operating mode.
- Final-source application test-target compilation, relevant ABI/license gates,
  and adverse state, timing, ownership and causality tests.
- Paced KVM qualification. Its selected CREATE still refuses before allocation,
  with only one of eleven required coverage bits implemented. Complete
  DMTCP/kernel qualification also remains outstanding.
- Resolution of twenty retained provider Clippy findings and the four-vCPU ABI
  timer-deadline divergence.
- Quiet final Linux comparisons against fresh origin/master, plus same-binary
  TCG+icount versus SIM with both set to 50 ps/instruction.

## Performance results

| Measurement | Result | Scope |
| --- | --- | --- |
| gem5 address-range predicate | 5.26x median improvement; one million allocations removed per round | Five matched lookup rounds with identical checksums |
| gem5 thread-list transitions | 2.55x median improvement; 500,000 allocations removed per round | Five matched list-mechanics rounds |
| QEMU/plugin Linux boot, six matched runs | Median 29.50669 to 29.54280 seconds (+0.12%) | Frozen controller, same guest and 50 ps/instruction; effectively flat |
| Maximum-frontier component pair | 3.37x improvement | One matched component pair |
| Immutable-domain component pair | 47.87x wall and 55.92x child CPU improvement | One matched component pair |

Component results do not add up to an overall Linux-boot speedup claim. The final
comparison must use the same guest bytes, clock policy and workload, preserve
complete deterministic witnesses, record interventions and retain all samples.
