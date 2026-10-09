# 12. Security considerations

## 12.1. Trust boundaries

Dispatch has four relevant boundaries: consumer to session, session to
execution provider, trusted verifier to search backend, and proposal to the
consumer's resource authority. Correct assignment verification addresses only
the third boundary's result integrity. It does not eliminate the need for
authentication, resource authorization, process confinement, or current-state
admission.

Assignment inputs and native candidates MUST be treated as untrusted data.
Peer-provided validity, feasibility, optimality, and verification fields MUST
NOT replace independent checks. The trusted runner MUST bind evaluation to the
exact immutable problem and supported semantic version.

A private `VerifiedPlan` constructor MAY enforce this relationship within a
library. Serialization MUST NOT recreate that authority automatically. An
imported candidate MUST be re-evaluated before it acquires a locally verified
type. Verification MAY execute in an isolated worker to preserve the caller's
resource policy.

A remote consumer MAY explicitly trust an authenticated Dispatch verifier.
That policy MUST identify the verifier and its supported semantics; the result
MUST distinguish trusted remote verification from local verification. Without
that policy, remote evaluation is advisory and the consumer MUST verify the
candidate independently. Transport authentication alone does not certify the
correctness of the remote verifier.

## 12.2. Resource abuse and denial of service

Parsing and optimization can consume disproportionate resources even for
well-formed inputs. Implementations MUST enforce byte, object-count, nesting,
queue, cache, worker, result, and diagnostic bounds before their corresponding
expansion. Compressed or sparse input MUST NOT bypass expanded-model budgets.
Arithmetic overflow MUST be rejected; it MUST NOT wrap into a smaller demand
or more favorable objective.

Hard containment MUST use an execution mechanism independent of cooperation
from the native engine. The watchdog MUST remain able to terminate a stuck
worker and its descendants. The supervisor requires bounded resources of its
own and SHOULD retain headroom outside the worker's leaf limit.

A worker count is not a CPU entitlement. Multiple sessions and workers MUST
remain beneath the authenticated owner's aggregate allowance when aggregate
enforcement is claimed. A shared service MUST bound session creation and
pending requests as well as solver processes. A cgroup cannot authenticate a
caller or bound an application's network submission queue by itself.

The provider MUST report the scope of memory containment. An enclosing OOM
event can affect an application even if its individual workers have leaf
limits. Embedded execution MUST NOT advertise containment that it cannot
provide. Namespaces MAY reduce access to host resources; they MUST NOT be
described as CPU or memory fairness mechanisms.

## 12.3. Process and transport confinement

Backend executables, service identities, permitted resource profiles, and
transport endpoints MUST come from trusted configuration. Model data MUST NOT
select executable commands, privileged identities, cgroup paths, or arbitrary
filesystem paths. Backends SHOULD run with the minimum filesystem and network
access necessary to solve the submitted problem.

Local protocol endpoints MUST be private to the authorized session or protected
by peer authentication and filesystem permissions appropriate to the owner.
An untrusted peer MUST NOT be able to inject a candidate into another session.
Endpoints and prepared handles MUST bind to a worker or session generation so
that restart cannot confuse old and new requests.

Remote transports MUST authenticate peers and protect confidentiality and
integrity. Authorization MUST cover profile selection, session operations,
result access, cancellation, and artifact retrieval. Remote credentials MUST
NOT be included in problem or result artifacts. Service implementations SHOULD
avoid privileged launch authority in components that parse assignment models.

A backend process can contain native-code defects or compromised dependencies.
Independent verification checks output semantics but does not prevent data
exfiltration or host access by that process. Execution confinement and trusted
build provenance therefore remain necessary parts of the deployment policy.

## 12.4. Model confidentiality

Problems can expose topology, capacity, tenant priorities, storage residency,
and operational plans. Model data, prepared inputs, diagnostics, and artifacts
MUST remain scoped to their authorized owner. Cross-owner cache reuse requires
an explicit data-sharing contract and MUST NOT reveal the existence or content
of another owner's problems.

Logging SHOULD redact opaque identifiers and omit full models by default.
Retention MUST be bounded and disclosed. Cleanup MUST release runtime-owned
files, sockets, and handles, but MUST NOT claim secure erasure of RAM, swap, or
filesystem storage unless the execution provider explicitly supplies it.

## 12.5. Stale and concurrent proposals

A verified assignment can become unsafe when its observations are stale.
Dispatch MUST return the observation basis and model identity. The consumer
MUST check the relevant version or authority token and obtain required
reservations before applying the proposal. A digest is an identity check, not
a freshness test or authorization token.

Two individually feasible proposals may overcommit shared resources if applied
concurrently. Consumers MUST use disjoint entitlements or coordinate through a
common authority. A placement proposal MUST NOT authorize destructive storage
retirement, ownership transfer, or workload migration without the consumer's
normal safety protocol.

Cancellation of a solve does not revoke a previously applied allocation.
Likewise, releasing a session does not release resources managed by the
consumer. These lifecycles MUST remain distinguishable.

# 13. IANA considerations

This specification requests no IANA assignments. It defines no global service
port, URI scheme, media type registration, or Internet protocol registry.
Dispatch model, message, and capability identifiers belong to a published
Dispatch schema registry whose evolution follows Section 7.

# 14. References

## 14.1. Normative references

- **[BCP14]** Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997,
  <https://www.rfc-editor.org/rfc/rfc2119>; Leiba, B., "Ambiguity of Uppercase vs
  Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017,
  <https://www.rfc-editor.org/rfc/rfc8174>.
- **[CBOR]** Bormann, C. and P. Hoffman, "Concise Binary Object Representation
  (CBOR)", RFC 8949, December 2020,
  <https://www.rfc-editor.org/rfc/rfc8949>.
- **[SHA2]** National Institute of Standards and Technology, "Secure Hash
  Standard (SHS)", FIPS PUB 180-4, August 2015,
  <https://doi.org/10.6028/NIST.FIPS.180-4>.
- **[PROTOBUF]** Protocol Buffers, "Language Guide (proto3)",
  <https://protobuf.dev/programming-guides/proto3/>.
- **[CGROUP]** Linux kernel documentation, "Control Group v2",
  <https://docs.kernel.org/admin-guide/cgroup-v2.html>.
- **[SYSTEMD-RC]** systemd, "systemd.resource-control",
  <https://github.com/systemd/systemd/blob/main/man/systemd.resource-control.xml>.
- **[SYSTEMD-SERVICE]** systemd, "systemd.service",
  <https://github.com/systemd/systemd/blob/main/man/systemd.service.xml>.
- **[SYSTEMD-DELEGATION]** systemd, "Control Group APIs and Delegation",
  <https://systemd.io/CGROUP_DELEGATION/>.

The Linux and systemd references are normative only for providers advertising
the corresponding mechanisms. Deployments MUST identify the versions whose
behavior they qualify; a moving documentation URL does not authorize silent
changes in a session's negotiated guarantees.

## 14.2. Informative references

- **[REBALANCER]** Meta, "Rebalancer",
  <https://github.com/facebook/rebalancer>.
- **[REBALANCER-HISTORY]** Meta Engineering, "Open-Sourcing Rebalancer: A
  Generic, High-Performance Library for Solving Assignment Problems",
  September 21, 2026,
  <https://engineering.fb.com/2026/09/21/open-source/rebalancer-generic-high-performance-library-assignment-problems/>.
- **[REBALANCER-PAPER]** Kumar et al., "Rebalancer: A Generic High Performance
  Library for Solving Assignment Problems", OSDI 2024,
  <https://www.usenix.org/system/files/osdi24-kumar.pdf>.
- **[HIGHS]** HiGHS project, <https://highs.dev/>.
- **[CP-SAT]** Google OR-Tools, "CP-SAT Solver",
  <https://developers.google.com/optimization/cp/cp_solver>.
- **[FLOW]** Google OR-Tools, "Minimum Cost Flows",
  <https://developers.google.com/optimization/flow/mincostflow>.
- **[SCIP]** SCIP Optimization Suite, <https://www.scipopt.org/>.
- **[TIMEFOLD]** Timefold Solver,
  <https://github.com/TimefoldAI/timefold-solver>.
- **[CRUSH]** Ceph documentation, "CRUSH Maps",
  <https://docs.ceph.com/en/latest/rados/operations/crush-map/>.
- **[PROTOBUF-CANONICAL]** Protocol Buffers, "Proto Serialization Is Not
  Canonical", <https://protobuf.dev/programming-guides/serialization-not-canonical/>.
