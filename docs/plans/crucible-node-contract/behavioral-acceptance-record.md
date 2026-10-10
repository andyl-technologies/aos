# Retained behavioral acceptance and Node admission

The acceptance record retains a complete original RFC-0025 qualification claim,
its exact tested unit, the independently required classes, omitted requirement
IDs and the historical decision. Failed, unsupported, not-executed and
not-applicable rows remain distinct. Decoding an `AcceptanceRecord` produces
audit data and cannot construct `AcceptedQualification` or native authority.

`InstalledAcceptancePolicy::scope_for_node` selects the current binding, unit
and required classes from actual installed configuration and guarantees. It
borrows original bytes and the retained record from finite host ownership.
`BehavioralAdmissionEvidence` checks that scope against the common Node claim
and calls `accept_claim` on the original bytes at every admission before
calling the underlying admission policy. It delegates other claim kinds,
content, schema, owner, implementation and capability checks unchanged. A stale
historical acceptance therefore cannot bypass current oracle or evidence
verification, nor replace native owner/readiness qualification.

The requirement catalog is compared against every normative ID in the complete
compiled RFC corpus. Twelve literal SHA-256 pins fix those original source
files independently of the provider and generated ID list. The existing claim
edition, protocol-only report, source qualification authority, applicability
rules, class prerequisites and native admission tables remain unchanged.

Original claims have a 4 MiB default parsing ceiling. Audit records have an
independent 8 MiB default ceiling. Canonical parsing retains its existing array
and nesting caps. Direct report encoding counts bytes through a nonretaining
writer before allocating canonical JSON. Evaluation checks the exact borrowed
prospective report with a 4096-control-byte refusal diagnostic before cloning
current scope or invoking evidence callbacks. Each control byte may occupy six
JSON bytes; this preflight includes the complete format and decision fields.
Actual diagnostics are capped at 4096 raw bytes. The evaluation borrows raw original bytes instead of duplicating
them; its owner must retain those immutable bytes for that borrow's lifetime.
Trusted evidence callbacks retain the existing per-object, closure-byte and
object-count ceilings and must enforce them before fetching allocations.

The tests are ledger/admission models with a synthetic installed authority.
They demonstrate rejection and delegation semantics, not native class
qualification. Existing realized source reports still refuse acceptance where
mandatory original review or executable requirement coverage is absent. This
mechanism supplies the acceptance/admission seam; it does not complete that
provider's behavioral evidence population or qualify a device/ISA/backend.
