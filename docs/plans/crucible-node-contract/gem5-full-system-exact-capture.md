# Full-system gem5 capture qualification

The installed fixed-ELF O3 profile remains independently qualified within its
existing scope. Full-system admission requires a separate source-owned profile;
the successful ARM Linux driver fixtures alone do not grant that authority.
This implementation work uses a separate native foundation package and does
not change the admitted checksum programs or their model.

## Serial publications

`Terminal::writeData` is the point at which a modeled UART transfers each output
byte to its terminal. Reading the host terminal dump later cannot establish the
byte's original birth. The isolated `terminal-output-publication.patch` records
the byte inside that native callback, using the event position installed before
`EventQueue::serviceOne`. Its retained FIFO preserves original output ID,
picosecond tick, global callback ordinal, ordinal within the tick, causal parent
and byte. Multiple bytes in one callback have distinct consecutive output IDs
and share the actual callback position.

Capture is configured once, before native events, on an unused terminal without
a listener, host connection, output dump or received bytes. It does not obtain
input from a host socket. The original model's transmit buffer remains part of
the process image. FIFO credit is finite (65,536 bytes/publications); exhaustion
fails before publishing the next byte. The controller must stop and publish
retained outputs promptly rather than using credit exhaustion as flow control.

Stopped observations do not service a callback. ACK releases only the original
FIFO head; duplicate positive ACKs are idempotent, and future or zero ACKs leave
custody unchanged. A new input parent cannot replace the parent beneath retained
outputs. DMTCP process-image capture owns this FIFO and its cursor. No stock
drained checkpoint is claimed to preserve this added domain.

The native mechanism witness schedules actual callbacks to the real Terminal
implementation. It checks an exclusive stop before birth, embedded NUL bytes,
multiple original outputs per callback, unchanged observations, wrong ACKs,
positive original ACKs and a later callback with a new parent. Those checks must
pass before using the hook in a full-system controller. They do not establish
Linux readiness or full-system capture completeness.

The isolated `gem5-full-system-foundation` source build has passed the actual
native callback witness. A separate process-image witness captures the retained
`A\0B` FIFO and a queued future callback, exits the source, removes its complete
image/resource/temporary namespace and reconstructs two private branches. Both
branches preserve the original birth records, wrong/duplicate ACK behavior and
future callback suffix. The source-built focused check is
`j488qzgm052bl7gpkhgwxzpzi1qqq01f-gem5-terminal-continuation-check-1`.
Its current foundation retains explicitly named source artifacts, and eight
filesystem regressions check finite file/count/byte credits before copying.

An actual ARM Linux PL011 witness uses the installed kernel/initramfs/firmware
and the existing 256 MiB, 100 MHz Atomic functional board. Its first serial byte
is `[` at native tick 1,166,530,000 ps, callback 116,654, tick ordinal 1. The
source captures that unacknowledged byte, then continues 5,000 callbacks. After
source exit and complete original namespace deletion, two restored branches
reproduce the original 395 byte publications, birth positions, ACKs and final
callback position. The suffix includes the real `Booting Linux` and PL011
boot-console messages. This is a native continuation mechanism result: no
full-system closure certificate, PID1 readiness, device parity or CPU timing
qualification is emitted. Raw images and publication records stay outside the
repository and installed profile metadata.
The matching source-built package is
`r1w0kvphv7wjgafc9m8y5r2a6ilmifm7-gem5-aarch64-terminal-continuation-check-1`;
its installed record is 1,695 bytes and includes publication/console SHA-256
commitments, the actual native cut and exact guest asset bindings.

## Shared owner and model hooks

Extract the shared private controller from the existing source-owned SE owner;
retain the SE model as its default source-owned adapter. The extraction must
preserve current framing, exclusive event ceilings, full-position mapping,
original receipt journal, source/owner identity, ACK behavior, capture socket
closure, restored route binding and process inventory. No operator-selected
Python module or arbitrary guest parameters enter this dispatch. The installed
package binds the exact controller, selected adapter, fixed guest assets,
realized configuration and native implementation. Old installed packages remain
immutable; changed controller bytes require new both-ISA qualification.

The common owner owns these effects once:

- Authentic launch identity and the framed private control connection.
- Native one-callback stepping and `m5.crucibleEventPosition` crosschecks.
- Exclusive time/full-position ceilings and immutable original operation receipts.
- Retained publication transfer and original publication ACK accounting.
- Opaque process-image capture with the controller FD closed.
- Restart binding of private resource, temporary and future image directories,
  checked Python/native environment readback before readiness, and authenticated
  historical saved-copy relocation.
- Native map/thread/FD/file inventories and diagnostic blob custody.
- Exact source/scope verification and process-group termination/reaping.

The adapter owns the following narrow model operations. Implement them as a
closed interface over source-owned adapters, rather than inheritance of the
transport implementation.

| Operation | SE adapter | Full-system adapter |
| --- | --- | --- |
| `instantiate(assets, owned_root)` | Fixed checksum ELF and O3/classic/DDR3 model | Fixed board/kernel/initramfs/firmware/device description and owned DTB |
| `configure_publications()` | Native stdout syscall publication hook | Named native Terminal FIFO and finite device publication ledgers |
| `retained_publications()` | Original write birth, bytes and process/context fields | Original UART/device birth, stream identity and bytes |
| `acknowledge_original(id)` | Native stdout FIFO head | The original named Terminal/device FIFO head |
| `stage_sealed_input(input)` | Refused by the closed no-ingress profile | Finite capability-checked device input, future native event and causal parent |
| `diagnostic_inventory()` | Partial CPU/cache/memory commitments | Partial CPU/memory/board/device commitments, explicitly incomplete where appropriate |
| `closure_scope()` | Fixed ELF, stdout/exit only and closed native process | Fixed full-system assets/model, native process and every host-backed resource |

A UART byte is not a guest `write(fd=1)` syscall. The shared publication record
therefore has a typed origin: native SE write or named Terminal/device output.
Both variants carry the original native tick, global callback ordinal, ordinal
within the tick, causal parent and retained payload. Existing SE frame versions
retain their interpretation; a changed private/public schema requires explicit
version negotiation. Host stdout-file deltas never supply native birth metadata.

At each serviced callback, the common owner checks the adapter's retained
publication ledgers before admitting another callback. Already retained outputs
are never regenerated by retries. An output ACK changes custody and must
invalidate affected observations even if the native clock remains unchanged.
An unsupported model/input/device/profile refuses preparation; it cannot fall
back to a permissive adapter.

Implement the extraction first with the SE adapter and rerun both installed
source-namespace-deleted/twin-restoration/fresh-recapture gates and provider
native tests. Then add the ARM full-system adapter against the measured serial
mechanism. A separate source-owned full-system profile writer must verify
actual assets and `config.ini`, native serial/device provenance, current complete
opaque capture receipts, source absence, two fresh capture audits and required
guest readiness/device results before declaring that specific scope admitted.
The existing fixed-ELF auditor's profile name must not be reused for a Linux
board. Partial typed diagnostics remain partial regardless of image coverage.

Diagnostic custody also needs explicit admission credit before native effects.
The current owner retains each complete typed observation in an immutable blob
and sends its SHA-256/length/section commitments in the control frame. A mixed
archive continuation with 1,024-callback Poll prefixes reached 32 retained blobs
and 261,109,404 bytes, then exhausted the finite 256 MiB budget while creating
its next receipt. The guest had already executed that prefix. This is an
operational evidence-credit failure, not evidence of a failed CPU restoration.
The owner must reserve a post-prefix blob slot and its bounded maximum byte
extent before admitting the first callback. A refused reservation leaves the
original operation and native cursor unchanged and returns an explicit no-effect
response. Poll callback credit and lifetime diagnostic credit are separate
admission parameters; changing either requires a source-owned bounded policy.
Increasing an event prefix preserves exclusive callback ceilings and stops at
an original output birth, but does not prove a general solution for workloads
with frequent publications. Original blobs remain available; clock-only caches,
silent diagnostic sampling and deleting unacknowledged evidence cannot satisfy
this custody contract.

The isolated successor controller now counts canonical private original blob
files, reserves one file and the source-owned 64 MiB maximum accepted observation
extent, and allocates that storage with `posix_fallocate` before a native
callback. The next original full observation consumes that reservation. Credit
is based on the accepted observer extent, not the size of an earlier sample.
The selected observer/profile must still qualify that finite extent; it is not
a completeness claim for arbitrary native visitors or workloads.

A refused subordinate Poll returns the distinct retained `run_refused` frame:

```json
{
  "kind": "run_refused",
  "schema": "crucible.gem5.run-refused.v1",
  "operation": "original-poll-id",
  "original": {"kind": "run", "operation": "original-poll-id"},
  "boundary": {"ordinal": "4096"},
  "processed_events": "0",
  "reason": "diagnostic_credit",
  "credit": {
    "required_files": "1", "available_files": "1019",
    "required_bytes": "67108864", "available_bytes": "33554432",
    "reserved_files": "0", "reserved_bytes": "0"
  }
}
```

The abbreviated `original` and `boundary` above stand for the complete existing
closed `Gem5Run` and `Gem5Boundary` records. Retry and recovery return the same
original refusal. Releasing that attempted Poll's administrative custody does
not acknowledge a native
publication: it uses a distinct `ack_refused` request and returns
`refusal_acknowledged`. The tombstone remains retained after that acknowledgement.
The successor uses private dialect `crucible.gem5.native/3`; its ready frame
requires an explicit source-owned `diagnostic_credit_policy` containing schema,
maximum object bytes, lifetime bytes, file count and refusal schema. Missing
policy or an old dialect refuses before callbacks. Installed `/2` packages retain
their original bytes and interpretation. Provider decoding, signed continuation
import and common-operation
failure handling must support this distinct outcome before a successor profile
is registered. An original common grant with prior completed prefixes reports
its preserved progress; this subordinate refusal cannot become a successful
horizon or a claim that the whole grant had no effects.

Actual stock O3 observer tests refused exhausted file credit at callback zero
and refused a later subordinate Poll at callback 4,096 after four genuine
1,024-callback prefixes. Both witnesses preserve the original exclusive limit,
native cursor, request identity and every complete blob, including its SHA-256.
The smaller hostile credit policies are source-constructed test variants.
Nine focused filesystem/credit tests also pass, including an allocation-error
case that preserves genuine logical credit and ordinary I/O uncertainty instead
of fabricating a credit shortage. These mechanism checks do not
register the modified controller as an installed exact profile.

## Installed profile and owned assets

Each full-system profile must bind the exact native executable and complete
source/patch closure, controller/model, capture library, DMTCP launcher/restart
tools, image auditor and native host ABI. The fixed machine description and the
actual realized `config.ini` bind every connection and default, including CPU,
clock, memory mode and geometry, interrupt controllers, UARTs, firmware loaders
and VirtIO transports. Atomic functional execution can have exact continuation
without claiming modern CPU timing fidelity.

The AArch64 profile additionally owns the installed ELF kernel, initramfs,
bootloader and exact generated DTB. The x86 profile owns its ELF kernel,
initramfs, actual boot-parameter bytes, MP/firmware table contents and explicit
optional-register platform variant. Matching kernel corresponding-source outputs
remain co-retained where required. Restored owners receive private copies of
every mutable resource and private loader-asset custody, with no path dependence
on a deleted original tree.

All realized devices must have their host interaction classified. Host listeners,
TAP/network sockets, external disks, uncontrolled wall-clock input and live
controller FDs are excluded from the image. An empty packet/disk workload is not
proof of closure for devices capable of reaching those resources. Finite fixture
network/disk/9p state held inside the native process is distinct from production
distributed disk or network node state; production integration needs the node
protocol's original request, input prefix and completion ownership.

## Exact qualification witnesses

A full-system installed profile requires independently audited complete opaque
capture at actual stopped native boundaries, source exit, original resource-tree
deletion, two concurrent fresh restorations and a fresh independently audited
capture in each branch. Historical images remain immutable. Native map, thread,
FD and file-mapping ledgers must agree with raw captured bodies and kernel census;
typed diagnostics remain explicitly partial.

Witness cuts include a pending unacknowledged serial publication, a pending
VirtIO DMA request and a staged future completion, with the original queue
incarnation and frozen physical spans. Both restored branches must reproduce
the original native output/completion suffix, superdense birth positions,
guest-visible bytes and continuation state. One branch's ACK or input must not
mutate the other branch. Every native/helper process group must be terminated,
reaped and absent from the live kernel census.

Readiness is a separate guest assertion: the installed PID1 and application
must reach their actual ready marker and perform the required network/block/9p
roundtrips. A firmware banner, event-budget exhaustion, native compilation or a
partial diagnostic inventory cannot replace these assertions. Production
catalog activation remains refused until the actual source-owned bundle has
passed both capture and the relevant readiness/device gates.
