# Containing process lifetime and local Cleanup

This is an informative implementation design for the initial QEMU-SIM work.
It specifies no enabled wire edition or qualified execution profile. Current
Setup, receiver declarations and activation refusals remain unchanged. Read it
with the [implementation sequence](phased-implementation.md) and the normative
[resource obligations](../../rfcs/0021-crucible-paged-ram/05-runtime-policy-and-supervision.md).

## Physical ownership

A complete process reservation can retain initial Main stack, initial TLS,
loader allocations and ordinary allocator liability until the actual creator
collects the process. This approach needs a genuine prepaid containing owner;
an observed cgroup limit, loaded-image map or serialized reservation extent
cannot construct that owner.

Such a profile would use process collection as the final return boundary for
these process-private resources. It would not need a local return receipt for
every loader allocation. This is a distinct explicitly selected contract from
the proposed finite-arena loader profile; it does not relax that profile or
authorize an allocator fallback.

The complete reservation has to cover simultaneous liabilities, including
creation before `exec`, kernel accounting, initial stack/TLS, loader demand,
private growth and retained histories. Shared physical allocations are counted
once, while independently reachable private growth remains reserved. Resources
that can outlive process exit have their own retained owners: external backing,
shared mappings, descriptors, supervisor tasks and issuer history. Collection
does not establish their closure.

Exhaustion, failed `exec`, process termination, timeout and incomplete handover
are operational failures. Independent supervision and collection capacity must
remain available through those failures. Killing or collecting the process
does not produce successful Work, callback completion or local Cleanup.

## Prequeued, once-only handover

The current preinit receiver performs one
`recvmsg(MSG_DONTWAIT | MSG_CMSG_CLOEXEC)`. It does not wait for the creator to
observe a successful spawn. Moving only the sender after child birth would
introduce a startup race.

A coordinated process-lifetime contract can preserve prequeued delivery:

1. The genuine issuer consumes one Source borrower assignment into its canonical
   birth-attempt owner before creation. That owner retains the already charged
   reservation, exact receiving endpoint, nonwrapping account/process
   generations, selected artifact contract and complete attempt journal.
2. The issuer queues Setup once on that endpoint. The assignment remains
   consumed after a failed or partial send; queued aliases and external owners
   stay retained. No send or acknowledgement returns the reservation.
3. Only that attempt invokes creation, once, under the actual containing
   resource obligation. It owns every possible birth liability while the
   creation result is pending. Any intermediate helper births also need real
   funding and collection owners.
4. The receiver authenticates the parent, endpoint, sealed carrier and issued
   family, then adopts one canonical local borrower in prepaid fixed storage.
   It saves actual custody before independent posts. Existing fixed-control and
   prefix uses are subextents of the same charge, not additional reservations.
5. The creator captures the actual returned `Child` immediately, before any
   fallible post or transport, and binds it reciprocally to that same attempt.
   The receiver may already have started; the prebirth assignment owns this
   interval. An uncertain result preserves the original debt.
6. Final settlement requires genuine matching collection and separate closure
   of every external owner. A failed post, lost acknowledgement, elapsed
   deadline or empty cgroup never replenishes the assignment.

Retrying an uncertain birth, reusing or leaking the designated endpoint,
releasing debt while creation is pending, or ignoring wrapper-created children
would violate this contract. A planned PID is not a birth-attempt owner.

The authenticated Setup transport can be the consumer edge of this real
transfer. Its fields identify the actual producer operation; decoding them is
not that operation. A separate resource-phase protocol or transfer descriptor
is not inherently necessary. A coordinated revision of the existing Setup and
sealed-plan contract could carry the handover, using its family, assignment,
account, process, artifact and endpoint coordinates. The full byte layout,
editions, state machine and independent vectors still need definition before
any schema is enabled. Current Setup6 cannot silently acquire these stronger
semantics, and deployment accepts no mixed editions or fallback reader.

## Independent local Cleanup entry

The concrete synchronous Cleanup continuation remains `deferred_driver_run` on
its original initiating thread, with its Main/BQL, coroutine and callback
invocation contracts. An auxiliary stack or replacement worker cannot satisfy
those identities.

The existing entry body uses fixed records, finite parent loops, try-gates and
one clock observation. It allocates no storage, creates no worker, joins no
thread and drains no RCU queue. That structure does not establish a hard
completion bound under scheduling, faults and kernel delays. The selected
service still needs its actual timing contract.

A process-lifetime borrower can own the physical execution resources used by
this body. It cannot supply the independently prepaid delegated entry right,
actual clock result, compiled work inventory, original scopes or factual
return receipts. In particular, copying delegated maxima into an inventory
would manufacture required work rather than identify the selected service.

The smallest existing continuation is the preconstruct-refusal path. It has
the actual stopped constructor/Main/control invocation, born Native terminal
and Tail, and real construction-factory-unentered history. Its continuation
and last-use perform two physical passes over those exact identities before
the driver returns its children. Null nominated outputs cannot select this
path. Partial-construction disposal is a subsequent extension requiring its
complete transitive Core/Module consumer contracts.

An accepting entry producer therefore needs all of the following:

- A pre-Work reservation bound to the real adopted containing borrower,
  canonical Cleanup request, delegated outer right and exact incarnations.
- Actual fixed-control subextent membership in the expanded paid owner layout.
- A compiled inventory covering entry, Native/Tail birth, both physical passes
  and every return/post path. Required units, duration and stack come from the
  exact selected service and call graph.
- Factual retained-custody authentication usable after Work ends, without
  querying expired Work permission. Authentication occurs outside the gate,
  followed by recapture of the same child/profile incarnation under the gate.
- Retention of every partial result, initiating refusal and independent post.
  No retry or presumed absence of birth repairs an unknown outcome.

## Existing owners and remaining implementation

The host already retains original resident/metadata leases in
`AuthenticatedNativeSlotPurpose`, disjoint Source/Target reservations in
`InstalledProcessFamily`, and generation-specific loans in its incarnation
journal. `AuthenticatedSourceHostPurpose` owns the actual Source child keeper;
successful waits on that owned child record collection. Launch retirement now
joins that journal with its other physical-return conditions.

Before queuing Setup, that purpose irreversibly assigns the actual child-side
socket to one non-cloneable `AuthenticatedSourceBirth`. Its borrowed descriptor
keeps that endpoint alive through the creation attempt and actual Child
retention. The journal refuses another assignment even when creation was never
attempted, and an uncertain attempted birth retains the existing payer. This
host prerequisite adds no native grant or enabled wire contract; socket identity
alone does not authenticate native process adoption.

The creator runs in the authenticated service's guardian. Its child inherits
that membership, then attaches itself to the Source cgroup in `pre_exec` before
loading QEMU. This establishes an authenticated ancestor and pre-exec
attachment. It does not establish creation directly in the Source subdivision
or prove the complete simultaneous guardian/fork and Source/exec accounting.

The remaining implementation is the complete resource-domain classification,
the revised contract joining that host birth assignment to authenticated local
adoption, and the real compiled Cleanup-entry producer. Existing physical-return
APIs still require their own actual
terminal, last-use, unmap and settlement receipts. This design supplies none
of the missing writer, paging, fork/rearm, performance or release qualification.
