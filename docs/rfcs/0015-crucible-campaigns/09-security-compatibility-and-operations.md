# 09 — Security, compatibility, provenance, and operations

Campaigns retain complete machine state, accept structured guest input, execute
large adaptive workloads, and may eventually move artifacts between hosts. This
file defines the fail-closed trust and operational boundaries.

## 09.1 Trust domains

```text
scenario/policy author        trusted to define admitted experiment
campaign operator             authorized to allocate/steer/retain/export
guest application             untrusted protocol producer
QEMU/plugin process           separate GPL process, protocol peer
campaign daemon               trusted campaign and execution coordinator
object store                  untrusted for integrity, trusted per deployment for availability
future worker host            authenticated executor, untrusted for unverified result bytes
```

Content authentication protects integrity against store corruption but not
confidentiality or authorization. A malicious executor can withhold work or
return bad bytes; replay/content checks reject inconsistent canonical objects.

- **[CSEC-1]** Every object crossing a process, store, or host boundary MUST be
  length-bounded, schema-validated, and content-authenticated before use.

## 09.2 Guest protocol safety

Guest choice and measurement messages are untrusted. Admission ceilings cover
counts, identifier bytes, alternatives, landmarks, constraints, outstanding
requests, message sizes, and per-run totals. Decoders validate before
allocation, use checked arithmetic, reject aliasing offsets, and do not reflect
unbounded guest strings into logs.

- **[CSEC-2]** A guest cannot request an undeclared environment mutation or
  supply its own effect application. It may only request selection from an
  admitted guest choice domain.
- **[CSEC-3]** Guest choice deadlock is bounded by modeled timeout and lifecycle
  policy. The host MUST publish whether timeout occurred before or after a
  selection was committed.

## 09.3 Resource admission

Before running, the daemon validates campaign ceilings for:

- total and per-class selectables;
- candidate and observation cardinality;
- maximum expansion depth and active path length;
- proposal, attempt, and finding counts per budget grant;
- event-log, coverage, metric, and projection bytes;
- hot templates, live worlds, vCPUs, RAM, dirty-page budget, descriptors, and
  disk overlays;
- exact closure and store quotas;
- generator computation per poll;
- projection rebuild and report bounds.

- **[CSEC-4]** Campaign policy MUST NOT contain an algorithm or parameter set
  whose single poll, decode, or validation step is unbounded by admitted input
  size.
- **[CSEC-5]** Resource exhaustion pauses or rejects work with explicit status;
  it MUST NOT silently change selected values, stop conditions, or model faults.

## 09.4 QEMU fork isolation

The fork coordinator is a high-risk QEMU capability. Security and correctness
requirements include:

- a closed supported-device and backend manifest;
- one authorized host controller and generation;
- exact quiescence acknowledgements;
- complete inherited-descriptor disposition;
- new branch-private writable disks, rings, sockets, logs, and temporary files;
- child process sandbox/cgroup policy reapplied before resume;
- parent template unable to receive child commands;
- child unable to command or corrupt siblings;
- rollback of all children on partial world-fork failure.

- **[CSEC-6]** The fork child MUST execute no guest instruction between process
  creation and successful resource-rebind/sandbox acknowledgement.
- **[CSEC-7]** Fork capability MUST be disabled under tracing, plugins, devices,
  external backends, or host kernels not present in the validated capability
  manifest.

## 09.5 License/process boundary

QEMU fork coordination, QEMU device quiescence, QEMU VMState extraction, and any
code including QEMU headers are GPL-side. The Apache host sends public protocol
commands and stores opaque/versioned artifacts. Shared memory contains checked
offsets and wire values, never QEMU or Rust-native objects.

Every new or removed QEMU file updates `pkgs/emulation/qemu-patches/LICENSES.md`.
The published Crucible suite co-retains matching complete QEMU source, and the
full closure passes the existing license-boundary gate.

- **[CSEC-8]** Campaign implementation MUST NOT move guest assertions,
  objectives, guidance, or policy evaluation into the QEMU process. Those remain
  Apache host responsibilities.

## 09.6 Provenance and compatibility matrix

Campaign lineage records:

```text
scenario schema and ID
campaign policy schema and generator versions
Crucible engine version
QEMU build and patch-series digest
QEMU machine type and device capability manifest
control, shared-memory, guest-choice, and measurement protocol versions
exact-closure schema and object-codec versions
host architecture and required deterministic execution capabilities
immutable guest image/config artifact identities
```

Compatibility is explicit per artifact type:

- semantic campaign facts may remain readable under a newer compatible decoder;
- a configuration remains meaningful only with its scenario/schedule schema;
- exact closure restore requires the declared QEMU/machine/device contract;
- hot templates never survive daemon or host-process restart;
- incompatible exact state can fall back to thin replay only when the scenario
  and execution semantics remain compatible;
- otherwise a new lineage is required.

- **[CSEC-9]** No decoder may infer compatibility from version ordering alone.
  Admitted version pairs and migrations are explicit and tested.
- **[CSEC-10]** Offline migration rewrites create new authenticated objects that
  record source object IDs, migration tool identity, and output schema. Runtime
  silent lowering is prohibited.

## 09.7 Policy and scenario changes

| Change | Reuse |
| --- | --- |
| Worker count, memory limit, cache policy | Same snapshot semantics; operational only |
| Additional budget grant | Same lineage; accounting fact |
| Guidance weights or candidate policy | Same lineage; new policy revision for future proposals |
| Retention policy | Same lineage; new policy/pin projection |
| Measurement objective over already retained samples | Same lineage; re-evaluate observations |
| Legal choice domain, signal program, topology, workload, property semantics | New scenario and lineage |
| Guest/QEMU binary or patch series | New provenance lineage |

The initial implementation does not attempt prefix-equivalence reuse across
scenario changes. Users should encode anticipated future variation as declared
choice domains in the original scenario.

## 09.8 Authorization

Daemon roles include:

```text
viewer        inspect non-sensitive metadata and reports
operator      start/pause/resume and grant bounded resources
steerer       activate policy revisions and issue manual proposals
debugger      fetch retained exact state and create debug sessions
exporter      replicate or export sensitive closures
administrator configure stores, quotas, and trusted worker identities
```

Mutating commands carry authenticated principal, command ID, expected snapshot,
and authorization evidence. Principal identity is audit metadata and does not
enter modeled configuration identity.

- **[CSEC-11]** Export and debugger capabilities MUST be separate from ordinary
  campaign operation because exact closures may contain secrets.

## 09.9 Store confidentiality and integrity

Deployments use TLS, bucket/filesystem ACLs, encryption at rest, and credential
rotation appropriate to retained guest state. Content hash paths expose object
equality and should not be published in untrusted namespaces.

Authenticated encryption may wrap canonical plaintext objects. Replicas verify
the canonical object digest after decryption. Key IDs and nonces are envelope
metadata rather than plaintext identity.

## 09.10 Crash and partition behavior

| Failure | Required behavior |
| --- | --- |
| Worker process dies | Lease expires; attempt repeats |
| Daemon dies | Campaign ref remains valid; rebuild projections and queues |
| Store write interrupted | Unreachable staging/incomplete multipart object; old ref remains |
| Ref CAS lost | Re-read, merge/rebase, retry |
| Observation duplicated | Idempotent content/credit admission |
| Observation conflicts | Retain conflict and stop affected planning path |
| Hot child rebind fails | Kill child; no graph edge; retry another tier |
| Host maintenance | Persist/pin exact closures, release hot processes, restore later/elsewhere |
| Future network partition | Leases expire; duplicate work deduplicates; no corrupt merge |

- **[CSEC-12]** No operational failure may be converted into a modeled result
  unless the scenario explicitly models that failure through a recorded
  selection and execution evidence.

## 09.11 Audit and export

Campaign exports include:

- source campaign/snapshot/policy/lineage IDs;
- object-kind and byte counts;
- sensitive closure classes;
- missing optional acceleration objects;
- exact compatibility requirements;
- findings and replay verification status;
- exporter principal and operational timestamp in a detached audit envelope.

The detached audit envelope may differ between transfers without changing the
exported canonical objects.
