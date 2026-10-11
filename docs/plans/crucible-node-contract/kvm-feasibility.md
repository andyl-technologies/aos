# KVM clock containment and capture feasibility

This audit supplies the architecture matrix required by
[P6](phased-implementation.md#8-p6--quantized-worlds-and-kvm), particularly
T-CN-25 and T-CN-27. It identifies implementation work and qualification gates
for the [quantized node contract](../../rfcs/0025-crucible-node-contract/04-quantized-and-physical-nodes.md).
It does not admit a KVM profile or constitute a successful hardware test.

## 1. Current implementation and local evidence

The existing `crucible-qemu` launcher admits `sim,thread=single` and explicitly
rejects KVM at both typed-profile validation and concrete pre-spawn validation.
Its canonical arguments include the SIM-specific `-icount` round-robin settings.
The existing instruction-based clock and stop protocol cannot be reused by
changing the accelerator argument. Preserve these checks while adding a separate
quantized launch path; never weaken the deterministic launch validator.

Inspection on 2026-10-08 found an x86-64 machine running Linux 6.18.54 with AMD
EPYC 9755 CPUs. CPU flags include `svm`, `rdtscp`, `constant_tsc`, `nonstop_tsc`
and `tsc_scale`. The `kvm` and `kvm_amd` modules are visible in sysfs; nested
virtualization and AVIC are enabled in their current configuration. However,
`/dev/kvm` is absent from the agent's device namespace. No KVM capability ioctl,
native guest boot, timer experiment, stop-latency measurement or capture/restore
test was possible. Module presence and CPU flags do not prove API availability.
The machine cannot supply native AArch64 KVM qualification either.

On 2026-10-10, a fresh host-side inspection found `/dev/kvm` as character
device `10:232`, while the ordinary tool sandbox still omitted it. A separate
diagnostic VM completed through standard KVM, and the private-store sandbox
probe reported API version 12. Earlier device-unavailability results describe
their original execution namespace and remain unchanged. Standard KVM access
allows host-side smoke tests; it does not establish support for the private
Crucible controller capability, clock containment, exact capture or a qualified
node profile. No modified host kernel was installed.

The audit uses the public Linux v6.18 sources and QEMU source revision
`f9587d4045c67cd0d8d8bdcd5d0bb5b6b395b63c`. These are reference implementations,
not a claim that the installed kernel or packaged patched QEMU has identical
behavior. Runtime admission must bind the actual kernel, emulator build,
architecture, realized devices and successful capability probes.

## 2. Clock policy decision

The first clock-contained profile should use a controller-owned logical clock
with an explicit, qualified within-window progression rule. It must freeze
between grants and remain within the authorized logical window during stop
overshoot. The host execution slice is a separate operational budget. Retired
instructions and host CPU cycles remain nondeterministic measurements.

A direct hardware counter with a nonzero scale continues to increase until
execution actually stops. Offset adjustment after pause can remove the elapsed
closed-window time, but cannot undo a counter value already read, a timer already
fired, or a guest action taken during stop overshoot. Consequently, ordinary
offsets plus asynchronous stop do not establish a hard window ceiling. A
controller-owned profile needs a complete trapped/emulated or equivalently
qualified capped clock path. A separately named weaker clock policy may be
admitted only when its consequences are explicitly accepted by the scenario.

A clock frozen throughout every active interval is insufficient by itself:
polling guests may never leave their wait loops. Conversely, a clock that advances
once per read changes progression with polling frequency. Define the progression
and saturation rule before implementation, and qualify timer-driven and polling
guests against that same rule. Saturation at the end of a window must trigger
closure or an explicit operational outcome, rather than pretending guest
execution has become instruction-exact.

## 3. x86-64 mediation matrix

| Source or effect | Existing mechanism | Required integration or refusal |
| --- | --- | --- |
| `RDTSC`, `RDTSCP` | KVM exposes guest TSC values, host-dependent frequency control and architecture-specific offset/scaling implementations. | Probe actual TSC control support. To establish a controller clock ceiling, add a qualified intercepted/capped read path in the kernel and emulator, or refuse that clock capability. An MSR filter does not intercept timestamp instructions. Preserve `TSC_AUX` semantics for `RDTSCP`. |
| TSC MSRs, frequency discovery | CPU/MSR configuration and supported feature enumeration. | Mediate guest writes to TSC and `TSC_ADJUST`; keep CPUID frequency leaves and other admitted frequency reports coherent with the chosen policy. Reject unsupported CPU models. |
| KVM pvclock memory and wall clock | KVM clock adjustment, kernel-populated clock pages and TSC-based guest extrapolation. | Coordinate kernel page updates, versions, scale and extrapolation with the logical clock. Changing the base timestamp alone leaves extrapolation active. Disable unsupported Hyper-V/Xen/other paravirtual clock ABIs or qualify each independently. |
| Local APIC periodic/one-shot timers and TSC deadline | In-kernel LAPIC and emulator-managed configurations; timer state and TSC-deadline support. | Audit each realized mode. Replace host-driven expiry with controller-time expiry or qualify full mediation. A userspace I/O APIC does not imply a userspace LAPIC timer. Resolve pending expiries during closure and capture. |
| PIT, HPET, ACPI PM timer, RTC | QEMU-emulated devices with model-specific clock dependencies. | Audit counter reads, comparator scheduling, periodic interrupts and RTC updates for every admitted model. A fixed RTC epoch and `clock=vm` cover only that device, not the CPU or remaining timers. Route all admitted effects through the logical clock owner. |
| PMU, `RDPMC`, other cycle/time interfaces | Model/feature controls and kernel-specific filtering. | Disable unsupported counters and discoverable interfaces for the initial profile, with explicit guest ABI consequences. Do not advertise host-cycle-derived PMU state as controller time. |
| Interrupt delivery | IRQ routing, LAPIC state, `irqfd`, posted/accelerated paths and emulator injection. | Require custody and a closed input batch before injection. Disable or separately mediate paths that can inject without coordinator authorization. Capture pending and in-service interrupt state, not only line levels. |

The ordinary KVM userspace API provides clock adjustment and TSC frequency
controls; it does not advertise an instruction-exact stop mechanism. Its MSR
filtering/exits are a different surface from timestamp instruction interception.
The v6.18 SVM implementation provides relevant architecture interception
machinery, but existence of kernel-internal machinery is not a ready userspace
controller-clock API. [KVM API](https://docs.kernel.org/virt/kvm/api.html),
[x86 KVM implementation](https://github.com/torvalds/linux/blob/v6.18/arch/x86/kvm/x86.c),
[SVM implementation](https://github.com/torvalds/linux/blob/v6.18/arch/x86/kvm/svm/svm.c)

## 4. AArch64 mediation matrix

| Source or effect | Existing mechanism | Required integration or refusal |
| --- | --- | --- |
| `CNTVCT_EL0`, `CNTPCT_EL0`, admitted alternate counter views | `KVM_CAP_COUNTER_OFFSET` and the VM-wide `KVM_ARM_SET_CNT_OFFSET` ioctl can offset physical and virtual counter views. Hardware features determine direct access and traps. | Probe capability and CPU feature realization. Offset both views coherently while all vCPUs are stopped. For a hard controller ceiling, require a qualified trap/emulation or equivalent path; a shared offset does not freeze an active hardware counter. Inventory any exposed self-synchronizing counter views too. |
| `CNTFRQ_EL0` and counter conversion | Architectural frequency reporting and selected CPU model. | Keep declared frequency and picosecond conversion coherent. Do not infer arbitrary frequency scaling from the counter-offset capability. Refuse unsupported frequency requirements. |
| Physical/virtual generic timers | KVM maintains architectural timer state with direct and emulated paths, background timers and interrupt integration. | Cover control, compare values, interrupt status and blocked-vCPU wakeups. A counter offset change is not proof that all scheduled host timers have been rescheduled consistently. Qualify every admitted timer path or add kernel mediation. |
| GIC distributor/redistributor, CPU interface, pending IRQs | VGIC device interfaces expose migration-relevant state; access and restoration order have specific constraints. | Stop all vCPUs and prevent new external injection while collecting a coherent cut. Preserve active/pending state and CPU-interface state with the qualified restoration order. Disable unmediated passthrough/ITS paths initially. |
| PMU cycle/event counters | Architecture-specific KVM PMU configuration and CPU model. | Disable or explicitly qualify exposed counters and interrupts. Refuse a profile whose time inventory omits an admitted counter source. |
| RTC, peripheral timers, firmware/paravirtual time | Board/device-specific emulator and firmware paths. | Inventory actual machine model and firmware ABI rather than assuming a universal ARM device set. Bind every source to the clock owner or refuse it. |

Linux's ARM timer implementation distinguishes direct timer state, emulated
timers and sleeping-vCPU wakeups; these need a single coherent policy. Its VGIC
interfaces constrain state capture and restoration. Neither proves that our
clock-contained profile is already available.
[ARM timer implementation](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/kvm/arch_timer.c),
[VGICv3 state interface](https://docs.kernel.org/virt/kvm/devices/arm-vgic-v3.html)

## 5. I/O, DMA and ownership matrix

| Path | Initial implementation requirement |
| --- | --- |
| Emulated MMIO/PIO and virtio | Stage immutable authorized inputs before activation. Retain output bytes and externally issued effects under the grant identity until receipt/publication acknowledgment. Include pending descriptors, completion queues and device execution in the owner boundary. |
| Asynchronous disk or network workers | A stopped vCPU is not a stopped device worker. Seal or account for every outstanding request and completion before acknowledging closure. Route modeled disks/network through admitted ports; no host socket or shared writable image bypass. |
| `ioeventfd`, `irqfd`, vhost, accelerated interrupt injection | These may bypass the provider's ordinary callbacks. Initial profiles should exclude paths without a demonstrated staging, output-custody, pause and capture mechanism. Later qualification must inspect the complete kernel/backend data path. |
| VFIO, device passthrough, physical DMA | Refuse initially. Pausing vCPUs does not stop independent DMA or irreversible physical effects. A future profile needs device-specific isolation, stop acknowledgment, ownership and capture scope. |
| RAM paging | Register all guest RAM and writer paths. Missing pages must be serviceable for kernel-originated access; enforce reservations and progress. Page removal needs proof covering pins, secondary mappings and all readers. Do not infer this proof from vCPU pause alone. |

Each profile must bind the actual device inventory. A command-line whitelist
cannot replace inspection of realized mappings and effects. Userspace-only
`userfaultfd` service is not sufficient when KVM can fault from kernel context;
fault-origin permissions and mapping features require authentic preflight.
[Linux userfaultfd interface](https://docs.kernel.org/admin-guide/mm/userfaultfd.html)

## 6. Native pause and window-close transaction

Implement the following transaction on the QEMU/GPL side and expose its
acknowledgment through a versioned process protocol. Apache host code must not
read QEMU structures or call KVM-backed QEMU callbacks directly.

1. Validate owner generation and the currently active grant; atomically prevent
   activation of another grant. Seal future input staging separately.
2. Request stop for every vCPU, retaining exclusive ownership. A signal or host
   timer expiry records a request, not completion. Wait for all acknowledged
   parked vCPU states and disposition of any unfinished exit emulation.
3. Seal modeled device/backend activity, including pending I/O and authorized
   injection. Freeze clock effects under the qualified policy and establish the
   output membership cut. The implementation must specify its lock order and
   avoid waiting for a worker while holding a lock it needs.
4. Produce a retained receipt containing the original grant, owner generation,
   all paused-vCPU acknowledgments, operational budget/overrun measurements,
   complete ordered output batch and pending-operation dispositions. Keep the
   receipt and output bytes until publication is acknowledged.
5. If closure is uncertain or times out, contain the attempt while preserving
   ownership and output custody. Do not retry native execution or authorize the
   next window. Publication still waits for coordinator causal closure, including
   slower producer frontiers and equal-boundary settlement.

QEMU's existing `pause_all_vcpus()` waits for actual stopped flags, and its KVM
execution loop accounts for reentry needed to complete I/O exit emulation.
These are useful foundations, not complete node/window closure. They do not seal
all device workers or prove a guest-time ceiling.
[QEMU pause implementation](https://github.com/qemu/qemu/blob/f9587d4045c67cd0d8d8bdcd5d0bb5b6b395b63c/system/cpus.c),
[QEMU KVM execution loop](https://github.com/qemu/qemu/blob/f9587d4045c67cd0d8d8bdcd5d0bb5b6b395b63c/accel/kvm/kvm-all.c)

## 7. Architectural capture and progression

T-CN-27 requires a new weaker capture profile; it must not reuse exact SIM
capture identity. Capture exposed CPU registers/features, extended state, RAM,
clock policy/epochs, timers, interrupt controllers, device and disk state,
pending protocol operations, input batches, retained outputs and world boundary
state. Enumerate all required registers and verify successful reads/writes;
partial MSR operations cannot count as success. Preserve architectural state
with the appropriate restoration ordering for the realized CPU and devices.

Restore into fresh VM/vCPU/device kernel objects with new runtime generations.
Do not inherit parent KVM handles through hot-fork, import stale `kvm_run`
mappings, or infer isolation from private RAM alone. Physical cache, predictor,
speculation and scheduling state are outside the weaker captured scope; future
execution remains nondeterministic. KVM smoke tests and subsequent SIM/gem5 tests
start separate realizations. Any state conversion is explicit nonexact
initialization with new lineage.

Implementation admission should retain separate refusals for unavailable KVM,
wrong native architecture, incomplete clock inventory, missing kernel mediation,
unqualified device paths, unsupported capture scope and incomplete causal input
closure. Do not advertise `controller-owned-time`, architectural capture or a
native launch profile from this audit alone.

## 8. Qualification work and remaining gate

On this machine, device availability is the first unresolved prerequisite.
When native KVM becomes accessible, collect the real API version and capability
values, then configure an actual paused VM to prove the selected controls work.
CPUID flags or `KVM_CHECK_EXTENSION` success alone are necessary evidence, not
qualification of the composed profile.

Required tests include:

- Polling each admitted counter before, during and after long closed-window
  waits; cross-vCPU consistency; clock writes and frequency reports; timer expiry
  at and around the window boundary; halt/wakeup and stop overshoot behavior.
- Multi-vCPU native stop acknowledgment under CPU/memory/I/O load; unfinished
  exit emulation; late completion races; duplicate close/publication recovery;
  failure while active; bounded retention exhaustion and cancellation.
- A slow exact producer whose late input must block the KVM node's next start,
  and a KVM producer whose unresolved output must block an exact consumer.
- Fresh-object capture/restore of exposed CPU, RAM, timer, interrupt, device,
  disk and protocol state, including pending outputs; branch isolation; refusal
  of stronger exact capture and incompatible implementation bindings.
- Observed-attempt identity and nondeterminism propagation; deterministic cache
  exclusion; clock polling and timer-based guest boot/run smoke tests. Repeated
  identical instruction trajectories are not a KVM acceptance criterion.

Native AArch64 qualification remains unavailable on this x86-64 machine even if
`/dev/kvm` becomes accessible. TCG emulation of AArch64 can test protocol/schema
logic, but cannot substitute for the native ARM counter, timer and VGIC gates.
Until these gates pass, keep the runtime profile refused and T-CN-25/T-CN-27
incomplete; this document completes only their foundation audit.
