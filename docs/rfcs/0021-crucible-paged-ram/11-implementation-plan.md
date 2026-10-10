# 11 - Capability qualification and coordinated release

## 11.1 Contract acceptance and capability activation

This chapter defines release obligations, independently of package layout or
implementation order. The [companion implementation documents](../../plans/crucible-paged-ram/README.md)
contain the source inventory, QEMU work packages, dependency graph, proposed
profile roadmap, and evidence allocation. Accepting this specification does not
enable paging or advertise any execution, capture, or branch capability.

A shared logical codec or store is a foundation. A specified implementation
profile is a contract. A qualified capability requires evidence for the actual
implementation, build, resolved configuration, mappings, fault origins, and
requested operating mode. These three states are distinct. QEMU-SIM is the
initial implementation target; the gem5 and KVM profiles in
[chapter 14](14-implementation-profiles.md) remain unavailable until qualified.

- **[PLAN-1]** Implementation MUST maintain a conformance matrix mapping
  every normative requirement to owning components, positive evidence,
  negative/adversarial evidence, and the backend/release capability it gates.
  An unimplemented or unqualified requirement MUST block the corresponding
  advertised capability.
- **[PLAN-2]** Before enabling a public schema, maintainers MUST specify its
  complete canonical byte layout, numeric tags, bounds, state machine,
  atomic ordering where shared memory is used, and independent C/Rust
  vectors. Semantic record sketches in this RFC MUST NOT be treated as an
  implicit permission to ship native-layout or unspecified wire contracts.

The matrix allocates common byte identity, authentication, generation/lease
custody, finite resources, and private-branch isolation to each profile.
Deterministic trace equality remains mandatory for QEMU-SIM and each qualified
deterministic gem5 configuration. KVM's declared nondeterministic profile uses
its coherent capture, clock/timer, writer, kernel-fault, and quantum-containment
criteria; it cannot satisfy a deterministic request by relabeling those tests.
A proof for one implementation does not qualify another.

## 11.2 Peak reservations and progress

- **[PLAN-3]** General precise paging with a strict peak below the worst-case
  inter-boundary footprint MUST remain disabled until the implementation
  proves either a fault-safe resource suspension/reclaim boundary reachable
  during a blocked access, or safe concurrent removal with complete CPU,
  DMA, raw-pointer, and read-lifetime protection. Neither approach MAY inject
  a guest-visible event or modeled time step. Initial paused-only operation
  MUST reserve its sound interval peak and refuse unsupported smaller admission
  or live peak reductions. Unexpected resource loss after valid admission MUST
  fail operationally before exhausting the independent progress reserve.

Each profile proves its concrete wait-for and physical-access lifetimes. QEMU
BQL/runstate, gem5 event-queue suspension, and KVM vCPU stopping are different
mechanisms, none independently sufficient to prove removal safety. Without a
proved smaller interval bound, reserve full guest RAM plus independent progress
resources. A runtime residency target is not an admission guarantee. Paging
qualification does not enable general low-peak operation, concurrent eviction,
exact capture, or branch creation automatically.

## 11.3 Release compatibility, artifacts, and performance

- **[PLAN-4]** The release MUST update the compatibility registry atomically
  with all affected protocol, fingerprint, trace, checkpoint, and policy
  definitions. Capability advertisement MUST match enabled and qualified
  implementations. Noncurrent peers and artifacts MUST fail before execution.
- **[PLAN-5]** Release qualification MUST pass the repository ABI and license
  gates, preserve QEMU file licenses, co-retain complete corresponding source,
  and use hermetically built AOS dependencies. New kernel/filesystem requirements
  MUST be checked on the actual deployment host, not inferred from headers.

Development can proceed in reviewable phases. Deployment makes one coordinated
cutover; it provides no compatibility reader, digest converter, fallback profile,
or mixed-peer execution. Equal RAM roots are insufficient to authorize a
checkpoint restore into another implementation. The enclosing capture binding
and PROFILE-7 govern full-machine compatibility.

All enabled profiles retain chapter 10's performance requirements within their
declared execution contract. In particular, introducing future profiles does
not change the QEMU baseline, fixed sample plans, resource caps, deadlines, or
zero regression margin for either host CPU time or elapsed time. Missing or
failed evidence blocks the corresponding claim. Source review, smaller frames,
lower allocation peaks, and unchanged modeled time do not establish parity.

Release documentation identifies supported combinations, prerequisites,
resource-floor calculations, runtime controls, typed failures, retained cleanup
ownership, and recovery. Remote demand paging, live migration, and cross-profile
continuation conversion require separate contracts and qualification.
