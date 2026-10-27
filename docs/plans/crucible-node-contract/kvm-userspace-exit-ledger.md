# KVM userspace exit custody component

The native KVM clock component counts owners inside `KVM_RUN`. A returned run
can leave an original port-I/O or MMIO response in userspace, even after QEMU's
device callback returns. KVM consumes that response during a subsequent run.
Stopped run threads therefore do not establish a complete architectural cut.
The kernel API also states that the hidden pending operation is absent from
userspace-visible architectural state. See the
[KVM run-structure documentation](https://docs.kernel.org/virt/kvm/api.html#the-kvm-run-structure).

The independent userspace exit ledger records these actual transitions without
changing the original clock edition-one or edition-three command semantics. It
provides partial native inventory. It grants no execution, deterministic timing,
whole-device capture, input, output or physical-stop qualification.

## Native allocation and lifecycle

`x-crucible-userspace-exit-ledger=on` is an immutable accelerator property. It
requires an already configured native controller clock, `-S`, and a positive
maximum CPU roster no larger than 4096. QEMU reserves the complete per-CPU ledger
before creating or running vCPUs. Allocation failure refuses initialization.
Normal KVM configurations keep the component disabled.

Each record retains the original QEMU CPU index and kernel vCPU ID, last response
sequence, last consumed response sequence, exit reason and phase. Both indices
are assigned once before architecture pre-create hooks or native FD allocation.
Replacement, duplicate native IDs, create-and-park and rebinding are refused.
Bulk register replacement also refuses pending or uncertain original responses.
The records are process-local
and contain no portable reconstruction authority. The actual kernel response
data remains in the original `kvm_run` mapping and native kernel state.

| Actual transition | Retained phase | Meaning |
| --- | --- | --- |
| Before the original `KVM_RUN` | Running | The original CPU is entering the kernel. |
| Successful IO/MMIO exit before dispatch | Handling | The synchronous callback has not returned. |
| Original callback returns | Pending | Kernel response consumption is still owed. |
| Failed or interrupted re-entry | Unknown | Consumption has not been attested, including `EINTR`. |
| Successful subsequent run | Ready or a new exit phase | The original response was consumed; a new MMIO piece can remain pending. |
| Other completion exit families | Unsupported | Original response and opaque handler history remain recorded. |

Unsupported completion families include hypercalls, OSI/PAPR, Xen, EPR, TDX and
userspace MSR exits. Their opaque-effect history survives later kernel response
consumption. Coalesced I/O, ioeventfd/irqfd, pre/post-run architecture hooks,
autonomous workers, DMA and device output are outside the ledger's coverage.

The component deliberately retains uncertainty after interrupted re-entry.
Upstream KVM normally completes pending operations before checking signals, but
the experimental clock gate can reject entry earlier. An interrupted run alone
does not authenticate completion through that gate.
Later successful consumption does not erase the uncertain-effect history.

All three possible bookkeeping transitions are reserved before `KVM_RUN`: entry,
return, and an optional synchronous dispatch return. Reservations belong to the
original CPU run. Another CPU cannot consume their counter credit. Exhaustion
refuses a new run before kernel entry; previously reserved returns remain
recordable. Sequence numbers never wrap, and refused native transitions retain
the original records and faulted component state.

## Independent observation and caller

`x-crucible-kvm-userspace-exits` is read-only. The source requires paused or
prelaunch runstate and actual stop acknowledgements for every created CPU. Query
does not enter KVM, dispatch a device callback, consume a response, drain output,
clear history or replay an exit. Its bounded edition-one response contains the
original records in increasing CPU-index order. `device-closure`, `input-custody`,
`output-custody` and `profile-qualified` are always false.

The permissive QMP client exposes a separate checked observation type. It rejects
unknown schemas, changed wire fields, unbounded or duplicate CPU records,
inconsistent phases or response sequences, and any complete-domain claim. Its
local custody predicate retains pending callbacks, uncertain responses, opaque
effects and component faults. A clear local ledger supplies no native execution
or complete stopping authority.

## Required next native controls

1. Add a separate kernel completion-only admission path that authenticates the
   original response obligation while keeping guest execution closed. Reordering
   the clock gate or relying on `immediate_exit` without an original response
   acknowledgement is insufficient. Multi-part MMIO and unsupported exits must
   retain their complete original instruction/response chain.
2. Bind each original exit and callback effect to its admitted window and input
   cut. Capture actual response bytes and future publication birth evidence before
   acknowledging custody. Close cannot manufacture these from counts.
3. Enroll and gate every asynchronous device/worker owner, kernel IRQ path,
   coalesced ring and DMA writer. Native pause acknowledgements and pending
   inventories must originate from those owners. A device callback returning does
   not fence work it scheduled elsewhere.
4. Authenticate the complete captured kernel/device state and corresponding-source
   profile under an installed native capability. Pending hidden kernel responses
   cannot be reconstructed from register ioctls or the ledger alone.

## Local evidence and qualification

The source check compiles actual extracted production configuration, lifecycle
and reservation functions with the explicit AOS compiler. It exercises original
response preservation, interrupted re-entry, segmented MMIO, independent CPU
records, opaque history, zero-allocation preparation refusal and original finite
credit reservations. Compiled negative mutations must fail those assertions.
These are component model checks with a single-threaded lock substitute.

The full default QEMU source build includes x86_64 and AArch64 system targets.
Actual stopped TCG children exercise each real native inventory refusal handler;
the ledger-enabled KVM launch separately reports absent `/dev/kvm`. Original
edition-one and edition-three clock refusal checks remain required. None of
these checks qualifies native KVM execution on this machine.
