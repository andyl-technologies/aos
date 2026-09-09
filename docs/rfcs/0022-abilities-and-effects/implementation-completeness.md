# Implementation scope and completion evidence

This checklist distinguishes the complete RFC from its first vertical slice.
The [implementation phases](09-implementation-and-validation.md) order delivery;
finishing nginx alone does not finish the broader consumption, platform,
operations, or testing design. A release may deliver a declared subset, but
must reject unsupported required contracts and describe that subset accurately.

## Responsibility and acceptance map

Names below identify responsibilities, not mandatory filenames or crate splits.
Use the shared libraries described in the implementation plan and keep native
effects out of portable model/validation/inspection code.

| Feature | Responsible surface | Completion evidence |
| --- | --- | --- |
| Closed versioned contracts and identity | Shared model and validation libraries | Canonical valid/invalid fixtures; native and web decoders agree; unknown semantics and bounded-input violations reject |
| Nix schemas and helpers | AOS module library plus restricted evaluation adapter | Request/output/method fixtures agree with Rust; evaluated outputs are forced and checked; no effect or secret access during evaluation |
| Recursive implementation | Provider modules plus shared graph validator | Separately authored providers compose to admitted leaves without package-name special cases; cycles, missing ports, phase errors, and scope escapes reject |
| Controller ownership and aggregation | Composition and transition planner | Two contributors cause one shared transition; two instances stay distinct; collisions and double controllers reject |
| Static matching and late resolution | Shared validator/resolver with source and registry adapters | Equal canonical inputs yield equal choices and plans; ambiguity, invalid pins, conditional TLS, backtracking limits, and oscillation have deterministic outcomes |
| Publication and legacy compatibility | Package builders, APR publication, APM readers | Exact signed ability artifacts and gates survive round trips; supported old clients reject before activation through every entry path |
| Authority and provider admission | Policy adapter plus existing runtime providers | Mediation checks caller and provider grants; stale assignments, missing enforcement, and foreign resources fail before dependent effects |
| Planned providers and stage handoff | Runtime orchestration and boot adapters | A planned manager becomes ready before consumer acquisition; missing root prerequisites and cyclic bootstrap fail; receiving stage safely resumes ownership |
| Complete resource lifecycle | Provider transition constructors | Create, update, restart, no-op, drift, contribution removal, disable, replacement, and retained-target activation follow the lifecycle table |
| Conditional execution | Shared graph validator and executor | Every branch validates before execution; selected branch is durable; skipped results cannot satisfy required dependencies |
| Durable execution | Runtime, journal, and trusted method adapters | Every intent/effect/outcome boundary has qualified crash recovery; indeterminate effects reconcile; cancellation and deadlines cannot erase ownership |
| Generations and GC | Existing profile/config/image backends plus runtime records | Partial commits remain accurately visible; active consumers and recovery artifacts survive GC; persistent deletion requires separate authority |
| Systemd and containers | Scoped manager and launch adapters | Host and qualified system-container nginx behave as promised; user/initrd/container scopes cannot escape to host control; foreground support is explicit |
| Credentials, storage, and networking | Selected resource/enforcement providers | Exact workload views and lifetimes are enforced; renewal/revocation and stop requirements are tested; ingress and policy precede readiness |
| Build and library consumption | Derivation metadata and artifact audits | Build/host/target uses remain distinct; actual ELF/plugin dependencies agree with declared consumption; exact closure retention is preserved |
| Aggregate roles and Kubernetes | Role/package interfaces and Kubernetes adapter | k3s consumes its payloads without extra service starts; Cilium contribution is scoped; unauthorized objects reject and submitted revisions are observed |
| Images and initrd | Existing image/boot builders and stage interfaces | Userland and bootable artifacts carry the right contract; unavailable launch facilities remain obligations; early consumers cannot depend on late facilities |
| Rollout and rollback | Strategy providers plus ordinary runtime contracts | At least one qualified strategy handles partial completion, health failure, draining, and retention; rollback revalidates current grants and data compatibility |
| Documentation and operator tools | Shared inspection library, CLI, docs, Hub, editor | Same checked graph yields consistent identities/explanations; signed release docs differ from deployment/observation views; prose changes cause no reload |
| Debugging and visualization | Inspection queries and execution records | Expand/collapse, projection selection, dependency/removal traces, timeline, and redacted bundles work against successful and failed fixtures |
| VM/fleet and release qualification | Existing test harnesses and qualification catalog | Production path is exercised with independent probes; fresh evidence binds exact subjects and required coverage; cached regression output is not release admission |
| Optional Crucible instrumentation | AOS guest adapter and existing generic interfaces | Ordinary runtime needs no Crucible; enabled assertions/choices use the same execution; advanced campaign gates track PR #194 explicitly |

The test chapters define the evidence needed for these rows. A schema fixture
does not substitute for an enforcement test; an opaque legacy adapter does not
establish typed guarantees; one supported provider does not establish semantic
equivalence for other runtimes.

## Required end-to-end reference fixture

Maintain one versioned fixture across authoring, source/registry planning,
inspection, runtime, and VM tests. Its symbolic labels below stand for exact
typed identities and authenticated artifacts, not new wire syntax.

The fixture contains environment `web`, nginx instance `edge`, two application
instances `app-a` and `app-b`, and separate managed-configuration, execution,
credential-delivery, and systemd providers. Both applications receive only
their own virtual-host slots. Nginx receives separately authorized lower
implementation bindings. The systemd manager and storage are grounded in the
environment inventory; a second fixture starts a manager through a valid
planned bootstrap path. TLS is initially disabled and later enabled with an
explicit opaque credential version.

Retain the following checkpoints as shared semantic fixtures. Runtime evidence
is produced by executing the real providers, not by treating fixture JSON as
proof that the effects occurred.

1. **Declaration and binding:** source and authenticated registry paths produce
   the same normalized contribution map, provider selections, logical resource
   IDs, and desired configuration. No TLS credential request is active yet.
   A failed grant or ambiguous provider produces no live mutation.
2. **First activation:** one nginx controller composes candidate preparation,
   required unit/resource preparation, validation, publication, start, and
   independent behavior observation. Validation sees the candidate under the
   intended identity and filesystem view. Both applications' routes work.
3. **Single-contributor update:** changing `app-a` changes its provenance and
   the aggregate configuration revision while preserving `app-b`'s slot and
   resource identity. The declared configuration-only path publishes and
   reloads once. Repeating equal desired state with matching observations
   performs no reload.
4. **TLS and runtime inputs:** enabling TLS introduces and authorizes its
   credential requirement. Missing delivery fails admission. Candidate
   validation and actual service execution receive the same declared version
   through their proper views; secret bytes appear in neither plan nor debug
   bundle. An endpoint allocated at runtime uses a typed materialization
   operation rather than a future value in pure Nix.
5. **Failure before publication:** invalid candidate configuration fails
   validation; the old live target remains selected and functional. Candidate
   cleanup does not release resources still used by the old service.
6. **Failure after publication:** reload or readiness failure retains the new
   committed configuration and records old/unknown actual consumer state.
   An explicit rollback creates a new plan under current policy. It succeeds
   only if required credentials, artifacts, and state compatibility remain.
7. **Interrupted publication:** kill the executor after the external commit
   but before its success record. Restart recovery inspects the authoritative
   selected revision, settles that operation, and never blindly republishes
   or double-starts it. Repeat with qualified guest power loss to test the
   claimed durability boundary separately from process-crash recovery.
8. **Removal and replacement:** removing `app-a` recomputes the aggregate;
   removing `app-b` does not disable an operator-enabled nginx instance.
   Explicit disable stops it and releases eligible ephemeral resources while
   retaining persistent state. Provider replacement either uses a qualified
   adoption contract or rejects the unsupported transfer before effects.
9. **Scope and retention:** a second nginx instance cannot reuse the first
   instance's exclusive destinations. A stale manager assignment or revoked
   grant blocks further dependent effects. GC during partial activation
   retains candidate, old-consumer, and recovery artifacts until their recorded
   users detach.

Expected observations identify behavior as well as manager acknowledgements.
For example, a route-specific response distinguishes the newly requested
configuration from the old one; a successful `reload` acknowledgement alone
does not prove that distinction. The fixture must avoid manufacturing success
through a test-only service-control path.

## Dependency and migration boundaries

The core contract libraries, restricted authoring, source/registry validation,
inspection, and host systemd vertical slice can develop against existing AOS
facilities. They do not depend on all proposed sandbox or campaign features
being available. Each runtime adapter must name its actual provider protocol
and guarantees; an existing backend is usable only for semantics it enforces.

Integration with the pending sandbox work in PR #232 is qualified when its
resource/view/lease interfaces are available. Do not duplicate those brokers
to claim this RFC complete, or infer their guarantees from a draft. The same
rule applies to advanced Crucible campaigns from PR #194. Baseline guest
instrumentation and ordinary VM/fleet testing have separate acceptance gates.

During migration, preserve one activation owner per resource and the current
high-level install/desired-state intent. A package switches to structured
activation only when its required features, retained-generation behavior,
recovery, and actual runtime provider path are qualified together. Keep legacy
packages explicitly legacy; publication cannot claim a completed migration by
merely generating manifests for their existing opaque scripts.

## Details an implementor may choose

Rust type names, private module boundaries, helper spelling, CLI layout, and
the concrete journal storage implementation may be chosen within these
contracts. Freeze and publish their exact schema/API representations with
cross-consumer fixtures before declaring version 1 stable. That engineering
work must not change authority, matching, identity, lifecycle, publication,
recovery, or required failure behavior without a design revision.

An adapter may support fewer operations or guarantees initially and reject the
rest. It may not silently reinterpret unsupported requests. A new interface,
equivalence mapping, privileged primitive, or provider-specific migration must
document its additional semantics and qualify them before advertisement.
These are explicit extension gates rather than missing permission to invent
behavior in the generic engine.
