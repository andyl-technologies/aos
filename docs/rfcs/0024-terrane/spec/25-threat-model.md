# 25 — Threat model

This file owns the adversaries the specification defends against, the
assets it protects, the attack surfaces the design exposes, the mitigation
each surface receives with pointers to the requirements that provide it,
and the residual risks that remain. It is the file to read when asking
"what happens if X is compromised".

## Model

Terrane's security posture rests on four facts about its design, and every
mitigation below is an instance of one of them:

1. **Content is self-verifying.** Every chunk, manifest, tree node, and
   commit is identified by the hash of its bytes and verified against that
   hash before it is admitted or served. A compromised tier cannot forge
   content; it can only withhold it.
2. **Authority is per root, carried in offline-verifiable tokens, and
   enforced once.** There is no ambient authority in a sandbox, no bucket
   credential in a client, and no authorization service to fail open.
3. **Mutable state is one conditional write.** Refs are the only mutable
   thing, they change by compare-and-swap with epoch fencing, and every
   change is a signed commit. There is nothing else for an attacker to
   corrupt in place.
4. **Sharing is scoped by domain.** Deduplication, caching, page cache, and
   existence answers are confined to a disclosure domain, so a co-tenant
   learns nothing from the store's optimizations.

## Adversaries

| Adversary | Capabilities assumed | Goal |
| --- | --- | --- |
| **Untrusted job** | Holds a valid workload token scoped to its own branch; runs arbitrary code; can send any bytes to any surface it can reach | Read or alter a baseline; poison content other jobs will trust; exhaust storage; learn what other tenants have built |
| **Compromised sandbox** | Full control of a consumer of a realized surface; no token; can issue any filesystem call against the mount | Escape the view; read another domain's bytes; tamper with shared backing objects; crash the host tier |
| **Malicious or buggy client** | Speaks the wire protocol with a valid token; may send malformed packs, wrong hashes, decompression bombs, or race ref updates | Corrupt the store; deny service; escalate through parser bugs |
| **Compromised cache tier** | Controls a host or intermediate tier's storage and process, including its object directory and index | Serve wrong bytes; withhold content; harvest tokens or presigned URLs passing through |
| **Curious co-tenant** | Legitimate principal in one tenant domain; can time requests and observe `has` answers | Learn whether another tenant holds particular content |
| **Network attacker** | Can observe, replay, and inject traffic between tiers and to buckets; cannot break TLS | Steal capabilities; replay commits; downgrade |
| **Compromised issuer key** | Holds an issuer's private key | Mint tokens for any principal |

Out of scope: a compromised bucket provider (mitigated only by encryption
at rest, which this version leaves as a slot), a compromised host kernel,
and physical access to host storage.

## Assets

- Content bytes and their existence, per disclosure domain.
- The integrity of every ref: that it points only where an authorized,
  signed commit put it.
- Provenance records and their signatures.
- Capability tokens, issuer keys, and presigned read URLs.
- Availability of the authority store and of host tiers.
- Storage capacity and bandwidth, which an attacker can consume.

## Attack surfaces and mitigations

Each surface names the requirements that mitigate it. A requirement cited
here is normative in its own file; this file adds only the mapping.

### Upload validation

A client controls every byte it uploads. A malformed upload must be unable
to corrupt shared state or exhaust a store.

- Wrong content under a hash: every chunk MUST be re-hashed on receipt and
  rejected on mismatch ([`05-chunking.md`](05-chunking.md) CDC validation,
  [`12-pack-format.md`](12-pack-format.md) pack admission). A dedup hit
  never bypasses this because the hit itself is decided by hash.
- Chunk boundaries that break history independence or dedup: boundaries
  MUST be re-derived by the store on every new chunk
  ([`05-chunking.md`](05-chunking.md)).
- Decompression bombs: a per-chunk uncompressed-size cap and a compression
  ratio cap MUST be enforced before allocating output
  ([`05-chunking.md`](05-chunking.md)).
- Pathological manifests: chunk count per object MUST be bounded relative
  to declared size ([`04-content-model.md`](04-content-model.md)).
- Pathological trees: node size, key length, entry count, and nesting depth
  MUST be bounded by the encoding profile
  ([`06-tree-format.md`](06-tree-format.md)), and decoder limits apply
  before allocation (`reference/terrane-v1.cddl` profile rules).
- Storage exhaustion ahead of a commit: bytes written under a token MUST
  be bounded by the root's quota property and unreferenced bytes are
  reclaimed after the grace window (AUTH-24,
  [`17-garbage-collection.md`](17-garbage-collection.md)).
- Index poisoning: an index entry is only written for content the store
  itself verified; a client MUST NOT be able to write an index record
  directly ([`12-pack-format.md`](12-pack-format.md),
  [`13-bucket-layout.md`](13-bucket-layout.md)).

### Ref updates

- Racing or replaying a ref update: refs change only by compare-and-swap
  on the previous value with an epoch, so a replayed or stale update fails
  ([`09-refs-and-commits.md`](09-refs-and-commits.md)).
- Pointing a ref at a commit the principal could not have made: the
  authority MUST verify the commit's signature and embedded token against
  the ref and epoch before accepting (PROV-4).
- A superseded writer continuing to commit: epoch fencing and the `epoch`
  caveat (AUTH-18, AUTH-42).
- Forcing a ref to arbitrary history: requires `admin` (AUTH-21 verbs)
  and is recorded in the reflog (PROV-21).

### Existence oracles and timing

- `has` and negotiation answers across domains: DOM-10, DOM-16.
- Filter distribution: DOM-11.
- Trust-filtered entries revealing existence: PROV-15 presents them as
  absent.
- Timing side channels from shared packs or page cache: DOM-9, DOM-17;
  see §Residual risks.

### Capabilities in transit and at rest

- Token theft on the wire: all protocol traffic MUST use TLS 1.3
  ([`18-protocol.md`](18-protocol.md)); tokens are short-lived (AUTH-41)
  and attenuated to the narrowest context (AUTH-14, AUTH-36).
- Presigned URL leakage: scoped to one pack key and byte range, lifetime
  bounded, never logged in full, never cached (AUTH-33, AUTH-34). A leaked
  URL exposes at most one pack's authorized range for minutes.
- Tokens reaching a sandbox: forbidden by construction (AUTH-35).
- Issuer key compromise: key retirement invalidates every token whose
  chain begins with it (AUTH-13, AUTH-44). Until retirement, the attacker
  can mint any token; this is the highest-impact single compromise and is
  addressed operationally by hardware-backed issuer keys and short token
  lifetimes.

### Realized surfaces and host privilege

- A sandbox escaping its view: the FUSE surface serves only entries of the
  authorized view; passthrough backing files are opened by the host, not
  the consumer; EROFS images are generated from the view only
  ([`27-surface-fuse.md`](27-surface-fuse.md),
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md)).
- A sandbox tampering with shared backing objects: sealed objects are
  immutable, owned by a publisher identity no consumer shares, and
  verified by fs-verity or an equivalent measured immutability primitive
  before passthrough ([`14-host-tier.md`](14-host-tier.md)). Read-only
  mode bits are defense in depth, not the mechanism.
- A sandbox crashing the host tier: per-exposure FUSE workers with memory,
  descriptor, and request limits; one worker's failure faults only its
  exposure ([`27-surface-fuse.md`](27-surface-fuse.md)).
- Privileged mount operations: the process that performs mount syscalls
  is separate from the process that holds network credentials and from the
  process that serves FUSE requests ([`26-surfaces.md`](26-surfaces.md)
  process separation).
- Cross-domain sharing through kernel objects: DOM-12, DOM-14.

### Compromised cache tier

- Serving wrong bytes: every consumer verifies content against its hash
  before use; a host tier verifies before sealing; a sealed object is
  bound to a measured digest ([`14-host-tier.md`](14-host-tier.md)). A
  compromised tier can withhold, not forge.
- Withholding: tier lists route around an unhealthy tier
  ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)); the
  authority is always reachable as the last tier.
- Harvesting presigned URLs: a tier that mints presigned reads holds
  bucket credentials by design; a tier that merely forwards requests does
  not, and MUST NOT be given them ([`11-store-trait.md`](11-store-trait.md)
  `guard` placement). Compromise of a minting tier is compromise of its
  bucket credential and is out of scope beyond credential rotation.
- Poisoning derived attributes: attribute provenance (PROV-9) lets a
  reader require that classifications and hashes were produced by a
  trusted job.

### Garbage collection races

- Deleting content a concurrent commit is about to reference: the grace
  window MUST exceed the maximum commit duration, commit order is packs
  then indexes then ref, and a client MUST abort a commit that outlives
  the window ([`17-garbage-collection.md`](17-garbage-collection.md)).
- Two collectors running at once: a singleton lease with an epoch
  ([`17-garbage-collection.md`](17-garbage-collection.md)).
- Sweeping in one region content that another region's ref still needs:
  mark across every replica before sweeping any
  ([`17-garbage-collection.md`](17-garbage-collection.md),
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md)).

### Denial of service

- Ref CAS storms: per-principal and per-ref rate limits at `guard`
  ([`18-protocol.md`](18-protocol.md)).
- Negotiation amplification: `has` batches are size-bounded and
  filters are served, not computed, per request
  ([`21-bandwidth.md`](21-bandwidth.md)).
- Host cache pollution by an untrusted job: admission is per domain and
  per root quota; eviction is size-aware and pinned content is protected
  ([`14-host-tier.md`](14-host-tier.md)).

## Residual risks

These are known and accepted in this version. Each is either addressed
operationally or scheduled in
[`40-risks-and-open-questions.md`](40-risks-and-open-questions.md).

- **[THREAT-1]** Timing side channels that reveal cross-domain existence
  through shared pack bytes (DOM-9) or shared host page cache. An
  implementation claiming the Security level MUST document which channels
  it closes (DOM-17). Tenants with a strict requirement use `private`
  domains, which share nothing.
- **[THREAT-2]** A compromised bucket provider can read every unencrypted
  byte. Encryption at rest is a property slot (DOM-21) with no registered
  scheme in this version.
- **[THREAT-3]** A compromised host kernel or a process holding
  `CAP_SYS_ADMIN` on a host defeats every host-side isolation. Process
  separation limits which process needs that capability; it does not
  remove the need.
- **[THREAT-4]** A compromised issuer key is total until retired. Token
  lifetimes bound the damage window after retirement; nothing bounds it
  before detection.
- **[THREAT-5]** Provenance records assert what a token claimed; they do
  not prove that the workload ran the code it claims. The `attested`
  selector profile (PROV-12) relies on an external attestation the
  specification does not define.
- **[THREAT-6]** Availability of a home region for a ref is required for
  commits to that ref. A partition makes writes wait; it does not cause
  incorrect writes ([`20-consistency.md`](20-consistency.md)).

## Explicitly not mitigated

- Confidentiality of content sizes and access patterns from the bucket
  provider or a network observer of TLS traffic.
- Correctness of content a trusted principal chooses to commit. Trust
  selectors decide whom to believe; they do not audit what was believed.
- Malicious behavior by a principal holding `admin` on a root, beyond
  leaving a signed record of it.

## Interactions

Every file cited above. In addition
[`36-testing-and-conformance.md`](36-testing-and-conformance.md) MUST
include adversarial gates for upload validation, ref CAS fencing,
cross-domain `has`, and surface confinement, named by the requirements
this file maps to.

## Informative: a worked compromise

An untrusted pull-request job is fully compromised by malicious code in a
dependency. It holds a token attenuated to `commit refs/heads/pr/1234`,
`before(<deadline>)`, `epoch(refs/heads/pr/1234, 1)`.

It can write any bytes into packs, but only verified content is indexed,
and unreferenced bytes are reclaimed. It can commit any tree to its own
branch, but no other principal reads that branch without choosing to, and
a baseline consumer's `signed-baseline` selector hides its entries even
after a fold unless a trusted principal re-introduces them. It cannot
touch `refs/heads/main`, cannot read another tenant's domain, learns
nothing from `has` about content outside its domain, cannot obtain a
bucket credential, and cannot outlive its deadline. The blast radius is
one branch and its quota, and the branch carries a signed record of
everything the job did.
