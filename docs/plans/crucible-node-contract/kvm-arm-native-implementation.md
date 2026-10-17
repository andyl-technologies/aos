# ARM native controller component

The additive Linux 7.2.3 stage-three patch implements an experimental ARM
counter/timer component. It does not enable a runnable qualified Crucible KVM
node. Native AArch64 execution has not run on this x86 machine. Later access
to standard x86 KVM, recorded in the
[availability update](kvm-feasibility.md#1-current-implementation-and-local-evidence),
does not supply ARM execution evidence. Neither cross-compilation nor portable
policy tests replace native counter, stopping, capture or continuation campaigns.

## Realization and architectural paths

The VM-specific private capability `0xa026`, version 2, reports component bitmap
`100` on ARM: native RUN ownership, physical/virtual counter projection and the
software architectural timer component. A supported realization requires VHE,
FEAT_ECV and a nonzero architected frequency no greater than 1 GHz. Protected
KVM, nested EL2, AArch32 guests and guest PMU are refused. Hardware supporting
AArch32 EL0 is refused because an AArch64 guest can enter that state without a
hypervisor trap. Configuration precedes vCPU and device creation and clears all
physical host counter origins. The guest frequency is the real immutable
architected rate; it is not an invented per-instruction frequency.

`CNT{P,V}CT_EL0` and their self-synchronizing views trap to the normal host sysreg
emulator. The hyp counter fast path explicitly declines controlled VMs instead
of reconstructing a free-running physical value. ECV virtual timer/counter traps
and physical access traps remain installed across vCPU load. Guest counter reads
project the same capped/frozen nanosecond domain into architected ticks with
floor conversion. Timer delays use checked ceiling conversion and saturation;
unreachable deadlines stay pending without a hard-IRQ restart loop. Guest EL0
permission traps retain their architectural priority over EL2 timer trapping.

`CNT{P,V}_{TVAL,CTL,CVAL}_EL0` use software context state. Controlled VMs never
load guest timer registers into native hardware or map guest timer PPIs onto
physical timer IRQs. Blocking and WFIT wakeups reproject logical deadlines into
the admitted pacing ratio. Timer callbacks hold native callback ownership through
IRQ updates and hrtimer restart decisions. Frozen callbacks cannot enter; native
Freeze requests CPU exits, drains RUN/callback/effect ownership and synchronously
joins every background and context timer callback. Architectural deadlines and
pending state remain intact for the next Begin. PTP clock pairing returns one
atomic domain sample with the declared zero epoch. Host stolen-time activation
is refused.

The common arithmetic/admission policy is extracted into a GPL kernel header;
x86 and ARM execute the same Begin policy. The additive x86 and ARM acknowledgment
cut rechecks native ownership after callback joining, so concurrent frozen
immediate-exit reentry cannot certify a stale drain. Such reentry can disposition
an earlier exit and invalidates dynamic component acknowledgment. This is not an
immutable complete node stop receipt.

GICv2/v3 software realization is permitted. GICv5, ITS command workers, direct
GICv4 MSI/SGI injection and physical timer mappings are refused. Existing kernel
irqfd, ioeventfd and coalesced writers prevent configuration; new registration is
refused through the common stage-two guards. Complete GIC pending/active capture,
device effects, output custody and restore ordering still need implementation and
qualification.

## Source-built checks

The dedicated component check uses the actual pinned kernel source and all three
additive patches. It compiles the x86 controller/LAPIC arithmetic extraction and
cross-compiles ARM controller, RUN, sysreg, architectural timer, PTP, stolen-time
refusal and GIC refusal objects, including both VHE and nVHE hyp switch consumers.
The ARM check configuration is AArch64-only, matching the initial profile; it does
not remove compatibility features from the production kernel package.

A native source-built C oracle verifies the fixed 96-byte UAPI, executes 600,000
independent wide-integer cases for projection and architectural counter/timer
conversion, and checks retained-owner admission through an independent truth
table. This verifies arithmetic, transition policy and source compatibility.
It does not establish native concurrency, latency, hardware trap delivery,
architectural continuation or full profile qualification.

## Remaining native work

Automatic execution-ceiling stopping must seal native admission and kick every
CPU, then retain ownership until physical stopping is acknowledged. A timer firing
or a kick is only a stop request. The component cannot produce a complete receipt
from `run_owners == 0` or a QMP pause label.

The CNTKCTL_EL1 event stream is an additional clock-driven WFE input. ECV counter
and timer trap bits do not trap ordinary CNTKCTL_EL1 accesses from EL1. The source
component does not qualify that stream. A complete profile must mediate it through
an authentic architectural enforcement mechanism or refuse the profile when
that enforcement is unavailable; guest cooperation alone is insufficient.

Other remaining work includes QEMU RTC/PIT/HPET and device clocks, asynchronous
worker and DMA containment, fixed-boundary output custody, complete fresh-handle
architectural capture/restoration, and live native campaigns on both architectures.
The existing QEMU clock component uses x86 version 1 and refuses the ARM component;
the SIM native datagram protocol remains separate and rejects KVM.

Inspected primary sources include the pinned
[ARM timer implementation](https://github.com/gregkh/linux/blob/v7.2.3/arch/arm64/kvm/arch_timer.c),
[sysreg implementation](https://github.com/gregkh/linux/blob/v7.2.3/arch/arm64/kvm/sys_regs.c),
[hyp counter fast path](https://github.com/gregkh/linux/blob/v7.2.3/arch/arm64/kvm/hyp/include/hyp/switch.h),
and the Arm register access definitions in the
[Arm architecture register reference](https://documentation-service.arm.com/static/6166bf63e4f35d248467c9c0).
