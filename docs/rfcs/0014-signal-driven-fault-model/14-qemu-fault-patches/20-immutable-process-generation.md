# Patch 0066 — `crucible-immutable-process-generation`

## Purpose

Provision the exact host-supervised QEMU process generation at launch, before
the plugin admits fault commands. Terminal authorization and VMState restore
therefore compare against an immutable process identity instead of allowing a
request to choose the identity it claims to authorize.

## Launch contract

The host passes the required plugin argument `process_generation=<u64>`. The
value is nonzero and monotonically increases for each replacement of the same
logical node. The plugin resolves
`qemu_plugin_crucible_lifecycle_set_process_generation`, calls it exactly once
during installation, and fails installation if the export is absent or rejects
the value.

The QEMU export accepts exactly one nonzero value in `-accel sim` precise mode,
before a terminal transition is staged. It rejects zero, unsupported execution
modes, calls after terminal staging, and every second call, including an
identical retry. No QMP request, guest action, fault payload, or restored state
may initialize or change the value.

## Consumers

| Consumer | Required comparison |
| --- | --- |
| Terminal lifecycle completion | `process-generation` must equal the launch-provisioned value before exit is authorized. |
| Fault VMState | The saved generation must equal the launch-provisioned value before staged state commits on restore. |
| Host transaction journal | The prepared replacement, completion request, reaped child, and committed manifest all name one generation. |
| Evidence | Terminal evidence and process-exit evidence retain the same generation for replay verification. |

The first process for a node uses generation 1. A replacement uses the exact
next generation durably prepared by the host transaction; it never reuses a
generation from a contained or reaped child. Exhaustion fails closed instead of
wrapping.

## Live gates

1. Reject missing, malformed, and zero plugin arguments before runtime
   activation.
2. Reject an unpatched QEMU that lacks the setter and a setter that returns an
   error.
3. Prove the setter accepts one nonzero value before fault admission and rejects
   all second calls and calls after terminal staging.
4. Complete a terminal transition with the exact generation; reject the prior,
   next, and zero generations without scheduling exit or resuming the guest.
5. Crash after each host replacement transaction phase and prove recovery
   either contains the prepared child or commits only its exact generation.
6. Save and restore before and after terminal staging; reject any mismatch
   between launch, VMState, command, evidence, and durable host records.

## Licensing checklist

The setter and lifecycle state are QEMU/GPL-side changes. The Apache host passes
only a scalar launch argument and communicates terminal requests through the
versioned QAPI process boundary; it does not link QEMU code or headers. The
signed patch, branch bundle, corresponding source, and boundary gates ship as
one retained suite.
