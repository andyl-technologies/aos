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

## Trace initialization cost

The single additional bounded 40-second native / 3,600-second host diagnostic
run ended without PID1 readiness after 2,596,840,268 committed instructions and
400,038,039 native callbacks. The final PC was in `trace_event_update_all`.
At the earlier 20-second cut its actual string cursor was inside
`print_fmt_xfs_extent_busy_trim`; at 40 seconds it was inside
`print_fmt_percpu_alloc_percpu`. Direct ELF reads confirm that both cursors point
to real trace format text. This is progress through different strings, not
evidence of a blocked device or a stationary instruction loop.

The unchanged linked kernel has 2,637 built-in event pointers and 1,792 eval-map
pointers. Its initial print formats total 1,486,679 bytes. Linux's
`update_event_printk` scans an event's format once for each matching system eval
map, producing 151,539,327 bytes of initial-length scan volume. NFS4 accounts
for 88,126,893 bytes (58.2%), XFS 22,248,392 (14.7%), and NFS 13,208,988 (8.7%).
This static volume is not an exact dynamic instruction count: replacements can
shorten strings, and field sanitization and other initialization also execute.
No tracing, filesystem or kernel feature was disabled to bypass this work.

`_gem5/linux-trace-cost.py` reproduces the linked-data census from the actual
ELF and System.map. Its layout JSON must contain authentic offsets obtained
from that kernel's DWARF. For this kernel, AOS GDB `ptype /o` gives
`{"call_class":16,"call_print_fmt":64,"class_system":0,"map_system":0}`.
The analyzer binds both input hashes and rejects truncated loads, missing
symbols and unbounded strings. It executes no guest code.

A separate short host profile used source-built gperftools on the same native
Atomic model and unchanged kernel/initramfs. Profiling started after native
instantiation and stopped at 1,000,000 callbacks, 6,147,390 committed
instructions and native tick 99,997,900,000 ps. It collected 378 CPU samples.
Actual installed ELF dynamic function-size ranges were used for attribution;
30 flat samples (7.9%) lacked exported native symbols and remain unresolved.
An older scratch executable had different code bytes and was not used to
symbolize the installed executable.

Memory-bus `recvAtomicBackdoor` appeared in 98 sampled stacks (25.9%),
instruction fetch in 75 (19.8%), pre-execution/decode in 69 (18.3%), and MMU
atomic translation in 30 (7.9%). These cumulative figures overlap and must not
be added. `postExecute` accounted for 20 flat samples (5.3%) and x86 TLB lookup
for 14 (3.7%). This short sample covers early boot, not the later trace-table
phase. It supports investigating faithful per-instruction bus, decode and
accounting costs; it does not establish a whole-boot speed improvement.

## Address-range predicate allocation

The measured native bus path repeatedly calls `AddrRangeMap::contains`. The
pinned implementation copies `AddrRange` into a `std::function` predicate and
copies it again for each candidate. `AddrRange` owns an interleave-mask vector;
even the ordinary cached RAM lookup allocates for the captured predicate.
The separate `addr-range-predicate-borrow.patch` passes the synchronous lambda
by its concrete type and borrows its query/candidate by const reference. The
predicate is never stored, so query lifetime remains within the call. Tree
selection, cache promotion, overlap behavior and invalidation are unchanged.

The source-built `gem5-addr-range-predicate-check` compiles the actual pinned
baseline and patched headers together with upstream native test support. Three
tests compare more than 850,000 boundary/extent/interleave/cache queries,
overlap refusal, erase/clear invalidation and the same deliberately unsupported
interleaved operations. All pass. A non-inlined hot RAM lookup performs one
million identical queries per round: the baseline allocates one million times;
the patched version allocates zero times, with identical checksum. Five rounds
give median 17.196 ms versus 3.261 ms, approximately 5.27 times faster for this
isolated lookup. This is not a measured Linux boot change.

The passing package is
`y15b0jy5b0dl278bps1xh7zbcwd2mkxp-gem5-addr-range-predicate-check-1`.
The patch is installed in the refreshed fixed-workload native profile. Both
guest ISAs pass source-namespace-deleted, twin-restoration and fresh-capture
qualification, and all 27 installed artifact bindings independently remeasure.
These preservation gates qualify the changed fixed-workload implementation;
the isolated lookup benchmark does not measure its Linux boot performance.
