# T-STORE-3 shared-directory audit

This audit inspects the implementation at
`330e82243d9441a63e9fbbb7672b9e4fd6883041`. It does not accept T-STORE-3.
The complete `shared-dir-read-only` and `dom-host-isolation` owning gates
require current-source execution and independent review. Their results must
then be reconciled with all six assigned requirements below.

## Requirement coverage

| Requirement | Inspected implementation | Required evidence and limits |
| --- | --- | --- |
| STORE-14 | [Shared views][shared] open existing non-private host content through the concrete verified reader. `put` returns `ReadOnly` before consulting the directory. Reads allocate temporary response data without admitting content or creating viewing-instance reservations. | The original seven read-only selectors must preserve directory bytes and names, reject corrupt content without repair, verify complete chunks before ranged responses, retain canonical manifest metadata, and exercise residence fallback. The separate actual setgid-mode guest must pass. A portable residence callback alone establishes no native seal or physical custody. |
| DOM-12 | [Host layouts][layout] bind one physical root to a configured domain. [Routes][routes] reject overlapping paths and roots observed as the same device/inode. Native publication supplies domain-bound immutable backing. | The original isolation selectors must retain one existing inode for authorized consumers of the same domain and refuse aliases and symlink crossings. Genuine native publication/reassembly evidence remains necessary for sealed backing and page-cache sharing; a routing table alone does not establish those properties. |
| DOM-13 | [Routes][routes] select one configured shared directory using the guard-issued effective root domain. Unknown domains have no fallback, including to `public`; unreachable identities are filtered before membership lookup. | The original isolation selectors must prove that another directory and unreachable hashes are never probed. The enclosing repository must obtain and close current authorization around each disclosure. Retaining a routing table or an old domain decision grants no later read authority. |
| DOM-14 | Shared routes preserve one selected domain per operation; [publication][publication] binds each sealed object to its configured domain. | These backend checks alone do not prove mixed-domain shared-realization admission. Production FUSE/worker integration must establish that every consumer can access every domain represented by any shared backing directory. EROFS and VM surfaces remain separate worklines. No global DOM-14 conformance follows from the two backend gates. |
| DOM-15 | [Shared views][shared] reject private domains before opening their roots. [Consumer maintenance][consumers] schedules private retirement independently of FIFO pressure. [Physical retirement][retirement] retains original jobs, descriptors and funding through publisher acknowledgment and actual accounting. | The three original private-release guests must prove independent-consumer protection, refusal after lease release, actual private unlink, retained backing and quota, and a measured charge decrease after backing closes. Cold inline and manifest recovery must preserve the original public inode. These finite scenarios do not by themselves prove crash recovery or final release of arbitrary retained kernel mappings. |
| HOST-27 | Each shared view and published body remains bound to one configured domain. Sealed tiers reject unsupported zero-wipe configuration under D-128. | Isolation must preserve distinct physical domain custody. Configuration refusal must precede resource mutation; a wipe-policy mismatch cannot silently select another domain or deduplicate across domains. The supported sealed-tier policy is `none`; this grants no conformance for future wipe strategies. |

## Qualification checkpoint

At the inspected source, canonical evaluation of both owning gates succeeds.
Their missing dependency graph includes six original KVM guests: read-only,
isolation, portable shared modes, private release, cold private release and
cold manifest release. The two test images are being built in an AOS guest
with a fresh native-builder probe. Their audited missing dependency closure
has no overlap with the separately running publisher prerequisites.

Compilation, retained executable hashes, finite selector results and complete
gate results are distinct evidence. Neither successful image construction nor
earlier component qualifications accept this task. Original guest identities,
filesystem and quota controls, selectors and deadlines must remain intact.

Acceptance also requires resolving the DOM-14 realization boundary and the
DOM-15 physical-lifetime limits above. The assigned requirement IDs are
obligations, not a conformance claim established by a green gate name.

[shared]: ../../../../../crates/terrane/sdk/terrane-sdk/src/store/shared_dir/mod.rs
[routes]: ../../../../../crates/terrane/sdk/terrane-sdk/src/store/shared_dir/domains.rs
[layout]: ../../../../../crates/terrane/sdk/terrane-sdk/src/host/cache/layout.rs
[publication]: ../../../../../crates/terrane/linux/terrane-linux/src/publisher_io/native.rs
[consumers]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/consumer/sweep.rs
[retirement]: ../../../../../crates/terrane/linux/terrane-linux/src/host_cache/owner/publication/retirement.rs
