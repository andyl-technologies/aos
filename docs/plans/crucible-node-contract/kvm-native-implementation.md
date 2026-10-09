# Native KVM controller implementation

This document records the executable foundation and remaining native work for
T-CN-25 and T-CN-27. The [mediation matrix](kvm-feasibility.md) supplies the
device and architectural obligations. Neither document qualifies a native
execution profile.

## Executable foundation

`crucible_qemu::kvm_profile` implements:

- `probe_native_kvm`: opens the actual `/dev/kvm` character device, checks API
  version 12, and queries actual system capabilities. It refuses unsupported
  native architectures and never substitutes TCG.
- `prepare_native_kvm`: creates a fresh stopped kernel VM, retaining both VM
  and system descriptors. It creates no vCPU, RAM mapping or device and cannot
  execute guest instructions. VM-specific capability queries require the
  actual `KVM_CAP_CHECK_EXTENSION_VM` capability. Queries reject use outside
  the creating process. This is native preparation evidence, not a runnable
  QEMU node. QEMU must create its own kernel objects in its own process; these
  descriptors are not a handoff or hot-fork surface.
- `QmpClient::query_native_kvm_acceleration`: uses standard `query-kvm` through
  the existing bounded typed QMP engine. It reports only the connected
  emulator's `present`/`enabled` booleans. It does not infer a native clock
  ceiling, native stop acknowledgment or custody from those booleans.
- `KvmControllerClock`: computes a checked rational paced clock with one
  immutable end ceiling per window. Delayed native stop does not increase the
  logical counter past that ceiling. Closed waits remain frozen. Any next
  boundary jump is explicit. This arithmetic is a shared implementation
  specification; it does not intercept native guest counter instructions.
- `KvmMediationManifest`: checks claims against an independently supplied actual
  clock-source inventory and refuses ordinary offsets/scaling, unsupported
  native counter mediation and incomplete interrupt/timer/I/O closure. The
  result is a locally consistent claim, not authenticated qualification.
- `KvmArchitecturalCapture`: keys the weaker architectural state format to
  architecture, kernel, emulator, realized configuration and capture profile;
  requires complete realized CPU/device membership; and rejects exact-state
  claims or incompatible restoration. Reference verification and native state
  collection/restoration remain separate required work.

The current machine has no `/dev/kvm`. Operational unavailability must remain
separate from native qualification. Unit tests cover arithmetic, schema and
refusal behavior. They do not count as hardware clock, stopping or architectural
continuation tests.

## Native ABI and ownership

Add a VM-specific, versioned controller-domain extension to a separate patched
host-kernel package. Do not alter the Linux guest fixture, install this kernel
on the development host, or infer support from a kernel release string. The
extension needs an authenticated measured implementation and capability query;
the out-of-tree `KVM_CAP_CRUCIBLE_CLOCK_V1` capability uses implementation-keyed
value `0xa025`. This is not an upstream Linux allocation. Its fixed 96-byte
request structure is measured together with the kernel and emulator artifacts.
Version 1 reports bitmap `7`: TSC reads, TSC writes and native RUN owners.
The additive x86 version 2 capability uses implementation-keyed value `0xa026`
and reports bitmap `31`, additionally covering the KVM pvclock projection and
software LAPIC timer component. Version 1 remains compatible and reports `7`.
These bitmaps attest implemented component source paths, not a qualified complete
node or immutable stop/publication receipt.

The VM-owned domain contains the admitted pacing ratio, frozen logical origin,
active-window generation and ceiling, kernel monotonic operational origin, and
stop-request state. It has four transactions:

1. **Configure stopped:** reject existing guest execution, incompatible nested
   virtualization, omitted clock paths, and incompatible per-vCPU realization.
   Freeze all architectural counter projections and native timers.
2. **Activate:** compare the original window identity and generation, atomically
   install one common host-origin/ceiling, and permit only that grant's vCPUs
   and admitted interrupt delivery. Duplicate activation must never reexecute.
3. **Request close:** cap the domain, request all vCPU exits and seal injection.
   A timer or kick requests closure; it is not its acknowledgment.
4. **Acknowledge native close:** wait for every native run owner and pending exit
   emulation; seal kernel timer callbacks and interrupt paths; return the
   original domain generation, CPU owner membership and pending dispositions.
   Timeout retains ownership and requires containment. No next window can run.

The controller domain must have one synchronization order shared by reads,
window transitions and timer callbacks. Do not hold a domain lock while waiting
for a vCPU or callback that needs that lock. Counter conversion uses checked
wide integer arithmetic and the same ceiling across all vCPUs. Architectural
guest counter writes retain their specified register semantics under a declared
projection policy; they must not alter the coordinator's authorization ceiling.
Store no host monotonic epoch in portable continuation.

## Linux source hooks

The source inspection for this implementation uses Linux 7.2.3, the repository's
current kernel source version. `pkgs/kernel/crucible-controller-clock-7.2.3.patch`
implements an opt-in x86 counter domain and native RUN-owner foundation. It
does not change or install the running 6.18.54 host kernel.

| Source | Required work |
| --- | --- |
| `arch/x86/kvm/vmx/vmx.c` | Install and preserve RDTSC/RDTSCP exits for controller-domain VMs; prevent the normal execution-control setup from clearing required interception. Add explicit native emulation returning a domain projection. |
| `arch/x86/kvm/svm/svm.c` | Preserve both instruction intercepts across CPUID updates and vCPU reconfiguration. Add both exit handlers, including RDTSCP auxiliary state. The current CPUID path can clear the RDTSCP intercept, so setting a bit only at realization is insufficient. |
| `arch/x86/kvm/x86.c` | Cover `kvm_read_l1_tsc`, common TSC/adjust/deadline MSR access, `kvm_guest_time_update`, wall-clock epoch and clock-pairing paths. Audit KVM/Hyper-V/Xen/VMware paravirtual views and guest frequency reports. Disable unmediated optional interfaces in the initial profile. |
| `arch/x86/kvm/lapic.c` | Cover software periodic/one-shot/TSC-deadline timer start/restart and expiry, including hardware-assisted expiry. Cancel or hold callbacks when frozen; preserve pending interrupts and original logical deadlines. Initial qualification can refuse accelerated timer modes instead of pretending they share the domain. |
| `arch/arm64/kvm/arch_timer.c` | Replace direct counter/timer projection in controller-domain VMs; cover read/write sysregs, vCPU load/put, blocking wakeups, timer IRQ updates and restoration. Native hardware counters plus offsets cannot implement a stopped ceiling. |
| `arch/arm64/kvm/sys_regs.c` | Cover physical/virtual and self-synchronizing counter views, frequency/control registers and timer registers, including permitted compatibility views. Force appropriate EL2 traps and prevent guest register writes from reopening a direct bypass. |
| `arch/arm64/kvm/vgic/` | Seal injection and pending/active GIC state under the same stopped cut, with documented restoration ordering. Refuse nested virtualization, passthrough and unsupported ITS paths initially. |
| `virt/kvm/` and architecture run loops | Enforce VM-wide generation and run admission, all-vCPU stop membership, no reentry after acknowledged closure, and complete unfinished exit disposition. Include halt/block/wakeup paths. |

The current patch compiles the actual `crucible-clock.o`, common x86 KVM,
VMX and SVM objects against the pinned configured kernel. Its hermetic check
exports sanitized UAPI headers and verifies the 96-byte layout plus 100,000
projection cases against an independent wide-integer oracle. Duplicate exit
handler initializers fail compilation. The domain enforces consecutive window
generations, immutable begin bounds, a common paced nanosecond projection,
frozen waits, bounded native RUN-owner draining and explicit frozen steps.
RDTSC/RDTSCP preserve privilege faults and RDTSCP auxiliary state. Architectural
TSC writes adjust the per-vCPU projection without changing the controller ceiling.

The additive `crucible-controller-clock-stage2-7.2.3.patch` implements KVM
pvclock, GET_CLOCK, clock pairing and a fixed zero wall-clock epoch from the
controller domain. Per-vCPU TSC writes remain architectural offsets; pvclock
therefore omits the stable cross-vCPU flag. Hyper-V activation, Xen setup,
VMware backdoor, native PMU, native PIT and pre-existing independent kernel
writers are refused or disabled. Creating irqfd, ioeventfd or coalesced MMIO
writers after configuration fails. Direct IRQ/MSI/NMI/SMI operations retain
native effect ownership and refuse admission while frozen.

LAPIC one-shot, periodic and TSC-deadline timers retain logical deadlines.
Native expiry uses checked ceiling conversion through the admitted pacing ratio
and never arms beyond the grant ceiling. Signed logical deadline addition
saturates rather than wrapping. APICv and hardware timer acceleration are disabled
for controller VMs. Freeze seals effect and callback admission, requests exits,
drains native owners using a high-resolution bounded wait, then synchronously
joins every LAPIC hrtimer callback. Begin reprojects retained deadlines without
changing pending interrupt state. The acknowledgment remains dynamic component
evidence: frozen immediate-exit reentry invalidates it, and complete pending-exit
and device disposition are not attested.

The stage-two check compiles the common KVM, controller, x86, VMX, SVM and LAPIC
objects from the patched source. It verifies the unchanged 96-byte UAPI and
executes 400,000 independent wide-integer cases for projection, inverse timer
conversion, TSC conversion and signed deadline saturation. An independent
admission-state truth table executes the same native Begin policy, including
owner retention, lost acknowledgment, stale generations, changed coordinates
and overflow. This proves source compatibility and these arithmetic/policy
properties; it does not prove native concurrency, stop latency or guest behavior.

Coverage remains partial. Zero ARM counter/timer paths currently have source
implementation. Neither architecture has qualified kernel timer/IRQ closure,
paravirtual clock closure or device/output custody. No live native guest test has
run on this machine because `/dev/kvm` is absent. The next work includes ARM EL2
counter/timer traps, automatic execution-ceiling stopping, QEMU device and worker
closure, retained output receipts and architectural capture/restoration.

Native counter trapping can reduce KVM speed substantially for polling-heavy
guests. Measure that cost once the implementation runs; ordinary direct-counter
performance is not a valid estimate for this contained profile. Retain a faster
direct path only if its complete no-outrun proof and all timer interactions are
qualified against the same clock policy.

Primary inspected sources:
[Linux 7.2.3 x86 KVM](https://github.com/gregkh/linux/blob/v7.2.3/arch/x86/kvm/x86.c),
[VMX](https://github.com/gregkh/linux/blob/v7.2.3/arch/x86/kvm/vmx/vmx.c),
[SVM](https://github.com/gregkh/linux/blob/v7.2.3/arch/x86/kvm/svm/svm.c),
[LAPIC](https://github.com/gregkh/linux/blob/v7.2.3/arch/x86/kvm/lapic.c),
[ARM timers](https://github.com/gregkh/linux/blob/v7.2.3/arch/arm64/kvm/arch_timer.c),
[ARM sysregs](https://github.com/gregkh/linux/blob/v7.2.3/arch/arm64/kvm/sys_regs.c).

## QEMU clock and effect integration

Keep the native implementation in a distinct GPL-side controller module with a
versioned process protocol. The Apache host must not inspect QEMU state or use
QEMU headers. Preserve the existing SIM accelerator checks and its instruction
clock. A native launch is a separate admitted profile and argument builder;
changing `-accel` in the existing deterministic builder is forbidden.

The QEMU controller must configure and probe the actual VM extension before
creating runnable CPU owners. It must project `QEMU_CLOCK_VIRTUAL` device reads
and timers from the same kernel/controller domain, including stopped periods
and boundary steps. Cover PIT, HPET, RTC, ACPI PM, firmware time interfaces and
device-specific clocks. An emulator nanosecond timer resolution must be declared;
it does not imply picosecond-accurate native event ordering.

The separate experimental QEMU component configures the real kernel VM before
vCPU creation through `-accel kvm,x-crucible-clock-experiment=on -S`. Its
`x-crucible-kvm-clock` command performs Begin/Freeze/Query/Step transactions.
An absent or incompatible kernel component refuses configuration; ordinary KVM
remains unchanged. When configured, the QEMU virtual-clock read uses the actual
kernel domain and aborts rather than falling back to host time if that query
fails. The component reports `profile-qualified: false` unconditionally.
The Apache host's typed QMP component namespace validates bounded requests,
original generations, immutable begin bounds, explicit stopped steps and the
closed partial-coverage response. It never converts component state into a
complete node stop/publication receipt.

This virtual-clock integration does not intercept every timer or architectural
clock. The additive kernel stage implements pvclock and software LAPIC source
mediation, while wall-clock device views and independent QEMU device workers
still need mediation and composed native qualification. The existing SIM
native-control protocol rejects KVM and is not reused for these operations.

Extend native closure beyond `pause_all_vcpus()`:

1. Stage exactly one immutable authorized input cut and retain its commitment.
2. Begin the matching kernel domain and native run owners only after world
   admission. Measure total host allowance independently of modeled time.
3. Seal callbacks/workers, asynchronous device effects and pending exit emulation
   while parking all vCPUs. Initial profiles must disable unqualified irqfd,
   ioeventfd, vhost, VFIO, passthrough and other independent writers.
4. Commit one original-window receipt and complete ordered output inventory.
   Preserve bytes, pending operations and ownership until the host acknowledges
   causal publication or explicitly authorizes contained disposition.
5. On uncertain closure, disconnect/quarantine and preserve native child/resource
   custody through the existing mandatory supervisor. QMP command acceptance or
   run state alone is insufficient evidence.

On restore, create fresh native VM/vCPU/device handles inside QEMU and restore
complete exposed registers, extended state, RAM, timers, interrupt controllers,
clock policy and custody ledgers in the qualified order. Check partial MSR
read/write counts and every state-domain result. Do not reuse SIM hot-fork or
inherit KVM descriptors. Native architectural capture continues to advertise
nondeterministic future execution and excludes physical CPU microstate.

## Remaining acceptance evidence

A runnable KVM node is still blocked on actual kernel and QEMU mediation,
admitted native child/resource launch, live state capture/restore and accessible
native hardware. Tests must execute the composed patched implementation, not a
mock that accepts controller commands. Required campaigns include all realized
counter/timer views, long frozen waits, cross-vCPU consistency, delayed stop,
halt/wakeup, pending I/O, exact output membership, disconnect containment and
fresh-handle architectural restoration. Missing `/dev/kvm` is an operational
failure, never a passing native conformance result. AArch64 requires a separate
native AArch64 machine and its measured qualification identity.
