# x86 Linux functional board compatibility

The separate `gem5-linux-platform` package adds one optional-register absence
model to the source-built native emulator. The ordinary `gem5` package and its
qualified fixed-ELF closed profile remain unchanged. The platform variant is
not qualified for full-system exact capture, coordinated admission or CPU
timing fidelity.

## Optional reset-status probe

An actual Linux 7.2.3 boot aborted on a physical read at `0xfed803c0`. A bounded
native instruction trace identified the caller as
`print_s5_reset_status_mmio`, followed by `ioread32`. Linux enables this probe
for its Zen CPU feature and reads the AMD FCH reset-status register. The
default simulated CPU identifies as Hygon, while the generic PC has no FCH.
The unclaimed access therefore reached gem5's fatal `BadAddr` response.

Linux explicitly ignores an all-ones reset-status value as an error response.
The primary [Linux implementation](https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net-next/+/7609bf715c9622df912826627e31eb2c54c3f590/arch/x86/kernel/cpu/amd.c)
documents that behavior. The fixture consequently declares only this absent
optional register: one exact four-byte read returns `0xffffffff`. It fabricates
no reset reason, implements no FCH write behavior and does not change the
default response to other unclaimed addresses. Incorrect widths, addresses
and writes return native `BadAddressError`. No kernel or ISA feature is disabled.
Truthful CPU identity and a complete matching chipset model remain separate
architecture work.

## Source-built native mechanism

The passing platform output is
`/nix/store/bg0620a90hjy9zzs7ymg1jl0lhs0rr4i-gem5-linux-platform-25.1.0.1`.
Its native executable is 157,994,808 bytes with SHA-256
`bffe22ef315a2a64199ed88ed8acc843de194f31074bdd56d4fa9dcd2084f373`.
The installed source manifest appends the exact optional patch digest and
binds the platform recipe and manifest helper. Original upstream notices and
the new model's MIT notices are preserved.

Ten actual native Packet cases check the exact read, repeated read after
invalid requests, one/two/eight-byte widths, misalignment, the previous byte,
the maximum address and writes. The check also routes a valid read through the
actual native bus and verifies that repeated observations do not service a
native event. It caught a shadowed inherited address parameter during development;
the corrected model sets the inherited default and advertises the actual
four-byte register range.

## Linux driver gate scope

The x86 driver fixtures use AtomicSimpleCPU, width 16 and an explicit 10 MHz
functional clock. Their finite native budget is 20 seconds with a 1,800-second
host timeout. The smaller initial native budget stopped during real kernel
memory initialization and established no driver success. These timing settings
bound test work; they are not a performance comparison or CPU timing model.
Actual guest readiness, exact native request/publication bytes and sealed
native completion metadata remain necessary for a passing driver gate.

The current bounded network boot advances beyond the original fatal optional
register probe and discovers the modern PCI transport. It does not reach the
PID1 readiness or roundtrip markers within the budget, so it remains a failed
driver gate. The native local APIC derives its timer clock from the CPU clock
divided by sixteen; Linux rejects the resulting 625 kHz calibration at this
functional clock. That warning alone does not establish why boot has not
completed. A bounded instruction trace after an already-failed gate is used
only to diagnose the remaining execution and cannot qualify the fixture.

All source builds and native checks run on this machine with remote builders
disabled. Raw guest logs, instruction traces and images remain in temporary
storage.
