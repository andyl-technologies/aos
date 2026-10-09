# Completion-only KVM response component

The stage-five kernel component completes one retained userspace I/O response
without another `KVM_RUN` or a guest-entry loop. It closes a specific gap in
the [userspace exit ledger](kvm-userspace-exit-ledger.md): an acknowledged
userspace handler does not prove that the kernel has consumed its response.
This component is a prerequisite for a contained KVM node; it does not qualify
that node or provide an exact native continuation format.

## Source and activation

`pkgs/kernel/crucible-controller-completion-stage5-7.2.3.patch` applies after
the four controller-clock patches to Linux 7.2.3. The common implementation
lives in `virt/kvm/crucible-completion.c`, with a bounded private journal in
`include/linux/kvm_crucible_completion.h`. Architecture hooks use the original
x86 completion callbacks and ARM MMIO completion routine. The patch preserves
existing file licenses; both new source files are GPL-2.0-only.

The private capability is `KVM_CAP_CRUCIBLE_COMPLETION_V1`, value `0xa028`.
This is an implementation-specific allocation, not an upstream Linux ABI.
Enabling it requires an installed controller clock, an inactive domain, no
native effect owners, no created vCPUs, and no previous enablement. Nonzero
flags or arguments are refused. Configuration is immutable for the VM's
lifetime. A caller must probe the actual measured implementation rather than
infer support from the kernel version.

All new behavior is conditional on this activation. The prior controller
clock versions retain their semantics when it is absent. In particular, this
component does not override the existing ARM refusal of unsupported clock
profiles or CNTKCTL eventstream enforcement.

## Private command format

`KVM_CRUCIBLE_COMPLETION` is a per-vCPU `_IOWR(KVMIO, 0xd6, ...)` ioctl.
Its version-one record has this fixed layout:

```text
u32 version                 = 1
u32 operation               = Query(1) | Step(2)
u64 operation_id
u64 expected_sequence
u64 pending_sequence
u64 consumed_sequence
u64 revision
s32 callback_result
u32 phase
u32 native_vcpu_id
u32 flags
u64 reserved[4]              = 0
```

The record is 96 bytes, with reserved fields starting at offset 64. Input
records must leave all output fields zero. Unknown versions, operations or
nonzero reserved fields are refused. No process-private pointer, callback
address or kernel emulation structure crosses this ABI.

Query uses zero operation ID and expected sequence. It reports the original
vCPU's retained component journal; it does not acknowledge whole-node stopping.
Step carries a consecutive nonzero operation ID and the exact pending sequence
reported by that journal. Both commands run under the original vCPU mutex.

The phase is `Empty`, `Pending`, `More`, `Done`, `Unknown`, or `Unsupported`.
Flags report sticky uncertain effects or opaque unsupported state. They are
never cleared by an apparently successful later operation. No field asserts
complete device, DMA, input-cut or output custody.

## Original response custody

The journal is allocated inline with its original vCPU. It retains one
original pending response, a consumed sequence, a revision, and the last accepted
Step request and result. Native sequence and revision credits are checked
before admitting effects. Counter exhaustion refuses further work.

At the terminal revision boundary, a normal run can spend the final available
birth revision while a subsequent Step lacks the two revisions reserved for
completion and a possible additional fragment. That response remains in original
custody and cannot progress through this component; containment is required.
The component does not promise successful completion at exhausted counters.

An ordinary successful native run that exposes a supported IO/MMIO response
creates a pending sequence from actual process-private completion state. Its
original exit reason, address, length, direction and IO buffer geometry are
retained. The normal entry path invalidates stale mapped exit reasons before
run admission, so a failed entry cannot mint a response from old shared bytes.
Unsupported response families retain opaque state instead of claiming coverage.

While a response or uncertain state is retained, ordinary `KVM_RUN` and other
serialized vCPU ioctls are refused. This prevents register or emulation-state
replacement from silently reconciling the original response. Step checks the
retained geometry and original native completion predicate again before effects.

An exact retry of the last accepted operation ID and expected sequence returns
the stored result before inspecting the current pending predicate or invoking
another callback. A changed sequence or stale ID is refused. The result is
stored before copying it to userspace; a destination fault therefore cannot
erase an executed original operation. This is a bounded one-result journal,
not an unlimited acknowledgment history or a portable kernel snapshot.

## Stopped completion admission

Step serializes with controller Begin and Freeze through the existing
configuration mutex. Under the controller gate it requires:

1. A configured inactive clock domain.
2. Zero actual architectural RUN owners and timer owners.
3. Zero outstanding native effect owners.
4. A supported original pending response and sufficient journal credits.

It then retains a finite mechanical effect owner, invokes exactly one original
architecture completion routine, stores the result, and releases that owner.
The new activation also rejects frozen immediate-exit reentry, so another vCPU
cannot enter the architecture run loop during stopped completion. The old
clock-only immediate-exit path remains unchanged when activation is absent.

If the callback succeeds, the original response is marked consumed. A genuine
additional MMIO fragment receives a new pending sequence and `More`; the caller
must submit another distinct Step. The ioctl does not drain an arbitrary chain
or enter a normal run loop. Any callback failure retains `Unknown` and its
original uncertain-effect history without advancing the consumed sequence.
Further effects are refused; an exact retry still retrieves the retained error.

## Architecture hooks

| Architecture | Actual completion path | Refused cases |
| --- | --- | --- |
| x86 | Original `complete_emulated_mmio`, `complete_emulated_pio`, and the three existing fast-PIO callbacks, with the original vCPU/FPU/SRCU load and release context. | Protected guest state, nested guest mode, unknown callback identity, invalid original geometry, or a callback reporting no progress without another supported pending fragment. |
| ARM64 | Original `kvm_handle_mmio_return`, next to its native private external-abort predicate in `mmio.c`; the placement follows the normal pre-vCPU-load MMIO return path. | Protected mode, nested virtualization, pending external abort, reset request, unsupported exit families, or an unexpected remaining MMIO response. |

The x86 helper omits sync-register application, new pending-exception admission,
pre-run checks and the guest run loop. The ARM helper does not enter the GIC,
PMU, native work or guest-entry loop. Completing an emulated instruction may
update architectural registers and RAM as the original routine requires; it
is a mechanical completion effect, not an effect-free query.

## Verification and limits

`linux-controller-completion-stage5-check.nix` is the public component check.
The separate `linux-controller-completion-stage5` variant deliberately applies
the five patches; the default kernel remains unchanged. It builds actual
configured x86 and cross-compiled ARM kernel objects, including the new common
module and ARM MMIO hook. It retains all four earlier source/arithmetic checks
and installs sanitized UAPI headers.

The new tests compile extracted production policy and the entire common ioctl
implementation. The latter substitutes user-copy plumbing, single-thread mutex
plumbing and the architecture callback; it also uses the actual architecture
owner-zero predicate. Tests cover ABI layout, exact retry, changed geometry,
copy failure, multiple MMIO fragments, callback failure, stale exit bytes,
active windows, live owners and finite counter exhaustion. Six separate native
mutants compile successfully and fail the assertions when they break retry,
result identity, uncertainty, owner admission, clock admission or revision
reservation. A compiler failure does not count as mutation detection.

These checks establish source compatibility and the tested journal/admission
properties. They do not execute KVM, prove concurrent kernel scheduling, measure
native stop latency or qualify guest behavior. The development machine has no
`/dev/kvm` and no ARM execution hardware; those native witnesses remain absent.
The running host kernel is unchanged.

A response routine may fault, touch RAM or take operational time. The caller
must retain syscall/process custody until a genuine result or containment/reap;
the ioctl does not promise exact wall-time stopping. Concurrent mapped response
mutation and complete emulator/device ownership still need a qualified caller
protocol.

Full RFC-0025 integration also requires QEMU to select this actual kernel
component before vCPU creation, bind its original userspace handler and kernel
response sequence, and preserve uncertain outcomes across process-protocol
retry. Complete device/DMA/asynchronous callback/output closure remains separate.
Exact snapshots additionally need an authenticated export/import format for
hidden kernel emulation state. No executable KVM node manifest, readiness proof,
deterministic execution guarantee, fork or replay guarantee follows from this
component alone.

The upstream [KVM run ABI](https://docs.kernel.org/virt/kvm/api.html#the-kvm-run-structure)
describes why userspace response completion needs separate treatment. The pinned
kernel source and these implementation-specific checks define the new component's
behavior.
