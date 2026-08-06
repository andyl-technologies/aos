# Patch 0048 — `crucible-fault-safe-boundary`

## Purpose

Provides the exact-icount, all-relevant-execution-context quiescence and commit
protocol used by destructive and lifecycle fault commands. It extends the
existing safe fingerprint/preemption boundaries; it does not create a second
scheduler.

## Capability and dependencies

- Provides `qemu.fault-safe-boundary.v1`.
- Depends on 0047, existing sim observer, forced vCPU exit, RR cursor,
  preemption injection, and time-advance commit barrier patches.
- Required by 0049–0059.

## Boundary phases

Supported phases are:

| Phase | Meaning |
| --- | --- |
| `node_boundary` | Between scheduler quanta with all vCPUs stopped and device main-loop callbacks drained through the authorized coordinate. |
| `before_instruction` | Immediately before the selected architecture instruction, after interrupt decision and before architectural side effects. |
| `after_instruction` | Immediately after selected instruction commits and before the next interrupt/instruction. |
| `before_memory_access` | After effective address/size/type resolution and before data read/write/MMIO/DMA side effect. |
| `after_memory_access` | After access result/side effect and before guest consumer commits it. |
| `interrupt_phase` | Exact raise, route, acknowledge, or deliver hook. |
| `device_phase` | Exact accelerator/device submit, execute, complete, reset, or memory hook. |

Commands contain target icount and authorization ceiling. The plugin may arm only
when current icount is not past target. QEMU forces the selected execution path
to exit no later than target and refuses to apply before the exact target/phase.
If the hook cannot occur by the ceiling, it returns `not_applicable` or
`past_boundary` according to whether the opportunity was absent or missed.

## Quiescence

`node_boundary` requires:

- all vCPUs outside TCG execution and ordered at the fixed RR cursor;
- BQL held where the existing safe-boundary contract requires it;
- device callbacks and bottom halves with deadlines at or before the coordinate
  drained in canonical order;
- no in-progress shared-memory command/result publication;
- dirty tracking and VMState-visible state stable for the mutation window.

Instruction/access/interrupt hooks quiesce only the relevant vCPU execution
context but serialize against node-boundary mutation and VMState. Other vCPUs
cannot pass the global aggregate icount ordering point under single-threaded RR
TCG.

## Command state machine

```text
received -> validated -> armed -> reached -> applying -> applied -> acknowledged
                     \-> canceled
                     \-> not_applicable/past_boundary/rejected
```

Every transition is one-way and sequence-checked. Once `applying`, cancellation
is forbidden. Applying twice is impossible even across wakeups, callbacks, or
save/restore. A bounded 4,096-sequence replay window admits host publication
reordering without permitting duplicate or old sequence reuse. Same-boundary
commands order by phase, numeric registered command kind, binding hash,
opportunity hash, then command sequence.

After publishing a boundary-dispatched result, QEMU releases the fault
transport lock and invokes the optional GPL-side completion callback before it
allows guest execution to resume. The callback may consume the result and
submit an authorized follow-up command. Dispatch then drains that newly due
command at the unchanged boundary. This is the live conformance path for a
two-command prepare/commit transaction; it is not a host callback or a shared
memory function pointer. The ordinary Crucible host performs the same exchange
through the versioned command/result rings while the scheduler ceiling remains
pinned to the current boundary.

## Result evidence

The result includes armed/reached/applied icounts, phase, vCPU/RR cursor,
quiescence generation, command-set digest, before/after node fingerprint, and
handler evidence digest. `applied` is published only after dirty tracking and
handler state are committed.

## VMState

Patch 0059 serializes armed/reached states, command bytes, order keys, boundary
generation, and partially published result state. Snapshot is forbidden while a
handler is in `applying`; QEMU first completes or rolls back before acknowledging
the save barrier.

## Live microtests

1. Apply no-op probe commands at every phase and verify exact instruction/access/
   interrupt boundaries on x86-64 and AArch64.
2. Race eventfd wakeups, QMP activity, device completions, RR switches, and host
   scheduling perturbation; result ordering and fingerprints remain identical.
3. Arm commands for past, absent, exact, and ceiling-exceeded opportunities and
   verify distinct statuses.
4. Queue many same-boundary commands in permuted host order and verify canonical
   application order.
5. Consume a preparation result through the GPL-side completion callback,
   submit its authorized commit, and prove both results carry the same icount
   and byte-for-byte identical handler evidence.
6. Save before armed, after armed, and after applied states; patch 0059's later
   aggregate test must resume identically.
7. Revert this patch and prove exact-boundary probe gate fails.
8. Prove non-sim QEMU matches the unpatched corpus.

## Licensing checklist

This determinism-critical patch touches shared TCG/scheduler paths only behind
the sim-fault predicate. Upstream file licenses/notices remain. New files update
the license inventory. The DCO-signed commit includes focused microtests and
corresponding-source metadata.

- **[QFP-BOUND-1]** No mutation may acknowledge success before the safe boundary
  and dirty/fingerprint commit complete.
- **[QFP-BOUND-2]** Host scheduling or command publication order MUST NOT affect
  same-boundary application order.
