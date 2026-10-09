# Native execution ceiling and enforced clock-profile refusal

The Linux 7.2.3 stage-four patch adds autonomous native admission closure to the
experimental x86 and ARM components. It remains separate from complete node
qualification. This machine cannot execute KVM: `/dev/kvm` is absent. ARM checks
are cross-compilation, not native AArch64 execution evidence.

## Ceiling request and ownership

Version-two and version-three domains compute one immutable native monotonic
ceiling from the original logical extent and admitted ratio. Begin validates
that the ceiling fits the signed native timer horizon before opening admission.
A domain-owned high-resolution timer freezes the projection at the original
logical end, seals admission and requests exits from every retained CPU owner.
The callback retains native callback ownership through the kicks. It never
creates a close acknowledgment.

RUN, guest reentry and direct IRQ/MSI admission independently check the original
monotonic deadline. A delayed timer interrupt therefore cannot admit another
owner at or after the ceiling. Version one keeps its previous manually closed
component semantics and uses a zero native horizon. Old immediate-exit reentry
may still disposition an unfinished exit, retains RUN ownership and invalidates
dynamic component acknowledgment; it cannot retire a new guest instruction.

Explicit Freeze synchronously joins the ceiling callback, requests stopping,
drains RUN/callback/effect ownership and joins architectural timer callbacks.
The acknowledgment cut rechecks ownership under the same gate lock. A timeout
or retained owner produces an error and retains kernel resources; neither a
kick nor a timer firing is evidence of physical stopping. Stopping latency must
be measured on native hardware and checked against the admitted host allowance.
The architecture destructors join the domain timer before freeing CPU/IRQ state.
Adding CPU owners after the first Begin is refused.

The native domain's configured ABI version is immutable. Commands through a
different version return a protocol error rather than reporting a stronger
coverage bitmap for a weaker configured domain. The 96-byte UAPI remains
unchanged; the new capability is implementation-keyed and is not an upstream
Linux allocation.

## Required clock policy

The private version-three capability `0xa027` reports x86 component bitmap `159`:
version-two counter/pvclock/software-LAPIC components plus autonomous ceiling
requests. It additionally refuses native KVM stolen-time activation, which would
otherwise expose host scheduler elapsed time. These components do not imply
complete QEMU timer/worker/output closure, architectural capture or an installed
qualified node profile.

ARM returns zero for the version-three capability and refuses its configuration
with `EOPNOTSUPP`. Ordinary EL1 CNTKCTL accesses do not use the ECV counter/timer
traps, and the pinned implementation has no enforceable interception mechanism
for the architectural event-stream control. A guest can enable a hardware-driven
WFE event stream without those counter/timer traps observing the write. The
strict required-clock profile refuses this path before guest execution instead
of treating guest cooperation as enforcement. Version two remains an explicitly
partial source component and cannot satisfy the complete required-clock profile.

Future ARM support needs a real architectural enforcement mechanism or a separately
declared weaker operating mode with suitable clock guarantees. Changing a
capability label, clearing CNTKCTL only on vCPU load, or inspecting it after an
exit would not prevent intervening hardware events and cannot qualify the strict
profile.

## Evidence and remaining integration

The stage-four check compiles the actual x86 controller, common x86 KVM, VMX,
SVM and LAPIC objects, and cross-compiles the ARM controller, run loop, timer,
sysregs, PTP, GIC refusal and VHE/nVHE switch consumers. Native portable oracles
execute 700,000 wide-integer cases, including representable native ceiling
validation. Scheduler traces delay the ceiling interrupt while attempting RUN
and interrupt admission at both sides of the original boundary; early explicit
freeze and legacy zero-horizon behavior are checked independently.

This establishes source compatibility and arithmetic/admission properties.
It does not establish physical stopping latency, kernel callback concurrency,
live architectural continuation or a complete node receipt. Qualification remains
unexecuted. The QEMU experimental namespace still configures the version-one x86
component and does not infer stronger guarantees from the new kernel capability.
The SIM native control protocol remains separate and rejects KVM.

Remaining integration includes a distinct versioned QEMU quantized controller,
input-cut retention, RTC/PIT/HPET/device clock mediation, complete worker/DMA/output
custody, native capture/restoration and original-window close/publication receipts.
Native campaigns must run the composed measured kernel/QEMU implementation and
report missing hardware separately from conformance failure or qualification.

The register access audit uses the primary
[Arm architecture register reference](https://documentation-service.arm.com/static/6166bf63e4f35d248467c9c0)
and the pinned
[Linux timer implementation](https://github.com/gregkh/linux/blob/v7.2.3/arch/arm64/kvm/arch_timer.c).
