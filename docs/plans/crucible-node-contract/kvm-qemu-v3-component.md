# QEMU native kernel clock edition three

The opt-in KVM accelerator property `x-crucible-clock-kernel-edition=3`
selects the kernel controller-clock capability `0xa027` before vCPU creation.
The independent command `x-crucible-kvm-clock-v3` controls only that realization.
The original property default remains edition one and the original command
refuses an edition-three realization. An unsupported edition is rejected before
opening the native device. Neither command is a SIM execution command.

Edition three requires exact kernel coverage bitmap 159: architectural counter
read/write and RUN-owner accounting, pvclock, software LAPIC mediation, and
automatic ceiling stopping. A differing bitmap refuses initialization. The
kernel's AArch64 path refuses this edition while event-stream enforcement is
unavailable; the QEMU build without native KVM support also refuses it. The
packet retains the fixed 96-byte syscall ABI, with explicit edition checking.
Native initialization still requires `-S` and a positive rational pace.

The response retains `profile-qualified:false`. A kernel RUN-owner count covers
threads inside `KVM_RUN`, including accounted completion reentry. It does not
include a userspace MMIO or PIO exit awaiting disposition after that syscall
returns. Capped TSC/pvclock and mediated LAPIC do not establish completion of
QEMU device workers, DMA, userspace interrupt injection, timers, admitted input,
or publication custody. The generic node readiness barrier cannot consume this
component response as an exact or quantized execution qualification.

The host command vocabulary likewise exposes a separate
`control_native_kvm_clock_v3_component` method. Its privately constructed checked
observation requires schema three and bitmap 159, binds the original generation
and begin/step coordinates, and refuses `profile-qualified:true`. The shared
closed response shape does not carry execution authority. The original method
continues to require schema one and bitmap seven, with unchanged wire encoding;
neither command accepts the other edition's response. Request bounds are checked
before sending to the independent QMP process boundary.

## Source and verification

The additive source change preserves the six existing files' licenses:
`accel/kvm/crucible-clock.c`, `accel/kvm/kvm-all.c`,
`include/system/kvm_int.h`, `include/system/crucible-kvm-clock.h`,
`qapi/run-state.json`, and the foreign-architecture refusal in
`accel/stubs/kvm-stub.c`. It introduces no private pointer into a public process
protocol. The existing kernel syscall carries a userspace buffer pointer under
its native fixed-width ioctl ABI; that address is not scenario state or node
wire identity.

The full default source build covers both x86_64 and AArch64 system emulators,
the normal tools, and unit/qtest targets. Isolated no-CPU unit tools use the
existing asynchronous CPU stub object; the actual system reset guard is checked
to remain the definition in `cpu-common.c`. Production guard enforcement is
unchanged.

`_fixtures/kvm-component-v3-model.py` compiles the actual production component
marshalling functions and syscall structure with an independently checked model
kernel response. It checks both capability numbers and coverage bitmaps, ABI
layout, incompatible response versions, out-of-range coordinates, malformed
booleans, and actual syscall error propagation. This is an ABI model witness.

`_fixtures/kvm-component-v3-refusal.py` exercises both commands on genuinely
paused TCG children for both architectures, checks invalid-edition refusal,
and observes a real native launch failure when `/dev/kvm` is absent. The
source-built prototype's build metadata is not an installed matching binary
and corresponding-source qualification. Device absence and successful negative
checks are not native clock, timer, physical stop, or no-outrun witnesses.

## Next native boundary

The first userspace custody gap is `kvm_cpu_exec`: the kernel can return an
MMIO/PIO exit, after which QEMU performs address-space/device work before a later
completion reentry. A complete native owner ledger must retain this original
exit, its window identity, and whether its device effect and kernel completion
have occurred. Freezing the kernel clock cannot erase that ledger or report an
all-domain stopped receipt solely because the syscall count is zero.

A future quantized controller must close vCPU admission, prevent new autonomous
work, and obtain an inventory for every retained exit and effect before it
acknowledges the original window. Unsupported accelerated/coalesced I/O,
irqfd/ioeventfd, vhost, and worker paths must be refused at realization until
their actual inventories and stopping gates are implemented. Input staging and
output transfer must retain the original operation and fixed publication cut;
ordinary QMP `stop` or this component's `freeze` does not provide that custody.
