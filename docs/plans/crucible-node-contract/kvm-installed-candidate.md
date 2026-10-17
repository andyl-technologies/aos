# Installed KVM candidate preparation

`crucible node kvm-prepare --policy <file>` reaches the actual local KVM
preparation path through `prepare_installed_kvm_candidate`. The local operator
loads this policy independently of scenario or provider requests. It is not a
remote enrollment method and adds no executable `InstalledNodeKind`.

The closed policy format is `crucible.kvm-installed-candidate`, edition 1. It
contains the native architecture, positive vCPU bound, fixed quantum in
picoseconds, positive physical host allowance in nanoseconds, and exactly three
ordered artifact roles: `qemu`, `qemu_source`, and `kernel_source`. Each role has
an absolute local file path and independently expected complete CNP content
reference. Unknown fields, including qualification overrides, are refused.
The quantum must be a whole nanosecond because the current native component
ABI represents nanoseconds; silently rounding the scenario budget is forbidden.

Preparation authenticates each regular, nonsymlink file through its pinned file
descriptor. QEMU must have an executable permission bit. Authentication streams
in 64 KiB buffers, with a 4 GiB per-file and 8 GiB aggregate limit, and rechecks
file length and mutation metadata. The candidate identity binds the original
local policy including operational paths; it is not a backend implementation
or source qualification seal. Artifact byte references retain their separate
content identities.
The candidate creates no process and does not execute a pathname after measuring
it. A future launcher must execute the original authenticated descriptor or
independently authenticate its launch handoff; the candidate's operational paths
are not launch authority.

The native preparation sequence is:

1. Reverify the retained installed artifact descriptors.
2. Match the requested architecture to the compilation and actual kernel ISA.
3. Open the real `/dev/kvm` character device and check KVM API version 12.
4. Create an actual stopped kernel VM with close-on-exec descriptors. Create no
   vCPU, RAM mapping, device, run thread, QEMU process, or input delivery.
5. Check the requested vCPU bound against the actual system limit, then query
   the genuine VM-specific controller capabilities `0xa025`, `0xa026`, and
   `0xa027`. Store the returned bitmaps as observations, not qualification.
6. Refuse quantized execution until complete native mediation exists.

Missing or inaccessible `/dev/kvm` produces `DeviceUnavailable` and is rendered
by the CLI as `EnvironmentUnavailable`. An available kernel with incomplete
mediation produces `MissingMediation`, rendered as `PreparationRefused`.
Neither condition selects TCG. Successful stopped-component preparation retains
only owned inactive kernel descriptors; its private constructor exposes no
native run or activation token. Dropping it closes those descriptors without
requiring process containment, since no autonomous resource exists.

The running kernel release is diagnostic observation only. Measuring a kernel
source artifact does not establish that the executing kernel was built from it.
Likewise, measuring a QEMU file or a source archive establishes exact bytes,
not matching native implementation or complete corresponding-source policy.
Those stronger obligations remain independently installed source qualification
and release checks. There is no candidate-to-profile promotion through supplied
booleans, component bits, ordinary clock offsets, or QMP stop responses.

## Remaining execution boundary

The existing QEMU component namespace reports original coverage bitmap `7` and
`profile-qualified:false`. The additive kernel stages provide more source
coverage but do not extend that QEMU response into a full node contract. Before
an executable KVM profile can enter a world, the native implementation must:

- Authenticate a distinct pre-vCPU preparation contract and retained input cut,
  original operation/window identity, fixed publication boundary, and finite
  physical host budget; reject unsupported machine and device combinations.
- Enforce the same capped and frozen logical domain for native architectural
  counters, paravirtual clocks, QEMU device timers, frequency reports and every
  enabled guest time surface. ARM event-stream enforcement currently refuses.
- Close every vCPU admission gate, retain complete native stop membership and
  finish or retain each outstanding userspace KVM exit disposition. A kick or
  ordinary QMP paused state is not the whole-domain acknowledgment.
- Seal device workers, interrupts, accelerated paths, DMA, staged guest inputs,
  pending timers and outputs under that same window. Disable unsupported paths
  at realization rather than silently excluding them from the inventory.
- Transfer original retained output bytes and causal custody before publishing
  at the fixed boundary; retain original command, close, outcome and ACK history
  across retries, timeout, disconnect and quarantine.
- Reserve complete world resources and mandatory process-group retirement
  custody before allocating autonomous native resources; retain the failed
  child and every pending receipt until actual reaping and backing retirement.

Only installed evidence for those actual paths may produce an executable
descriptor or let a KVM node cross the common readiness/activation barrier.
The candidate API cannot manufacture that evidence. Architectural continuation
remains weaker than exact native CPU preservation; native nondeterminism and
its world-level effect must be admitted explicitly.

The local tests distinguish bounded installation/schema regressions, actual
kernel availability refusal, and native qualification. The CLI process test for
an independently measured installed candidate is invoked explicitly with
`CRUCIBLE_KVM_CANDIDATE_POLICY`; it never counts device absence or the permanent
source-edition refusal as a hardware clock/stop qualification witness.
