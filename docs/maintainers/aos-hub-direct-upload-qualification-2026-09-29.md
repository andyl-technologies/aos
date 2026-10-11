# Direct upload qualification: 2026-09-29

This ledger records the direct upload increments in the hybrid Hub PR.
It supplements the [hybrid qualification ledger](aos-hub-hybrid-qualification-2026-09-28.md).
Connected client, Native, broker and provider acceptance remains pending.

## External staging and byte execution

The external storage executor supports retained private multipart creation,
bounded part registration, positive closure, streaming full-object and per-part
verification, concurrent range copies, guarded destination completion and abort.
Unknown mutation outcomes remain fenced across restart; historical receipts
recover exact acknowledgements without creating a new effect. Multipart manifests
use bounded pages. Bulk bytes remain in the storage-side Worker, outside Native
and the compact Durable Object journal.

Frozen producer receipt `/tmp/hub-external-direct-stage/qualified-final.json`
(`cc8010c73cb9c414c78c67f82da11f9b9b25582222d9f0f5bd5f3be41c9fca23`)
binds 19 source paths and 5,496 inputs: 39 pure tests, 13 persistent stage groups,
16 existing consumer groups and six separate byte-forwarding wrapper groups.
The controlled private S3 fixture installs parts after registration; these gates
do not qualify a real client signed UploadPart URL or public provider policy.
The forwarding wrapper has its own artifact and scope. Independent final review
`527ad2ec2d2efba48c2068e94afb6e4625559111e3707979c0b77fa5e52337c6`
verifies source, prerequisite and evidence hashes.

Current-context receipt `/tmp/hub-external-stage-current-context-v2/qualification.json`
(`3fd69f7de0987a327e48253dbe054726f0a41eb864788419d92e4da3f58dba9a`)
records another 39 passing Worker tests and actual default-feature Worker Wasm
compilation. Seventeen producer postimages match exactly; two contextual Worker
parents preserve the committed ingress and narinfo changes. The capture includes
2,884 unchanged files and explicitly retains the current lock, S3 resolver and
runtime build-root fixes. Two preceding invocations selected the wrong package
and ran zero tests; they remain compiler-only evidence, not test qualification.

The executor remains disabled without its independent namespace, issuer,
credential and capability configuration. Real provider checksum and multipart
closure behavior, completed-stage privacy, all alternate writers and old grants,
Native business reservations, connected clients and hosted timing remain
activation prerequisites. The current immutable read retry is limited to its
original logical eligibility; separate recovery work must preserve mutation and
publication deadlines. No hosted throughput or combined fleet result is claimed.

## Recovery of an already pending immutable read

The subsequent recovery increment adds an explicit authenticated admission mode.
It can resume only the exact retained verification of a positively closed stage,
with the original actor, source, manifest, configuration and dispatch nonce.
Fresh request authentication, snapshot and read-lease deadlines still apply,
including after awaited journal operations. Recovery preserves the original
mutation and publication deadlines; it cannot create, close, promote or abort an
upload, allocate another identity, or turn a HEAD into a completion receipt.

Producer receipt `/tmp/hub-external-stage-read-recovery/qualified-final.json`
(`76c99058fc69bd5a6771d84f74f96480f63ab9630094354043409b5202a010d0`)
binds ten source paths and 5,497 unchanged inputs. It records 45 pure tests,
default Worker Wasm compilation and six persistent recovery groups, including
restart, lost terminal acknowledgements, post-expiry immutable verification,
conflicting identities and expiry during a delayed journal acknowledgement.
Independent final review
`9c1712704aa51bcec455794b88f9c04f10b07d4b97aa375a033b684886af277f`
verifies that source and evidence.

Current-context receipt `/tmp/hub-external-stage-current-context-v3/qualification.json`
(`b5130d6357262397be54aebaf09c52c525830c83a1385ef0ccd504571e6d4b30`)
records 45 passing Worker tests and actual default Worker Wasm compilation.
All ten producer postimages match and all 2,888 captured inputs remain unchanged.
An earlier invocation was interrupted before source-copy completion was
confirmed and remains unqualified. The six persistent groups remain separate
producer evidence; no current combined client, real provider, fleet or hosted
acceptance is claimed. Recovery across configuration rotation or migration is
outside this increment.

## Immutable account identity and live authorization

Account UUIDs now pin API tokens, retained browser session contexts, JWT provenance
and reviewed topology operations. Permission checks revalidate the same live actor
around awaited IAM reads. A replacement account cannot inherit a retained
request merely by reusing its numeric SQL ID. Existing tokens without an owner
pin must be reissued; validation never backfills that pin from a numeric ID.
Migration 004 and the matching snapshot census are additive prerequisites.
Their presence does not activate the unfinished direct upload service.

Cold browser session reconstruction still needs a separate persisted account
UUID captured when the session was minted. The existing database session row
contains a numeric user ID; reconstruction must not adopt a replacement user's
UUID from that slot. That correction and its real mint/restart tests remain
activation prerequisites. The earlier session tests qualify retained contexts,
without establishing that missing cold-session pin.

Producer receipt `/tmp/hub-native-principal-auth/qualification-v5.json`
(`c1da1f8433fdc4d56607ccd61591955be337365cc3e1608cfab92ececf57cb98`)
records 47 named passing tests and Native, ordinary Worker Wasm and CLI
publication test compilation, with 2,472 unchanged crate inputs. Tests cover
revocation, expiry, recycled IDs, genuine browser session provenance, account
changes during IAM reads and exact reviewed-plan ownership. Independent final
review `88ec3dd261be62a0bcc2e00201b9521ed5c30420b28a62f1e259eca65eb6d250`
binds the source, named results and retained earlier compiler failures.

Current-context receipt `/tmp/hub-principal-auth-current-context/qualification.json`
(`0689ea40fa9d89125f81ea1b434840053840b72a7b74ab5927edff7f23d34059`)
records another 47 passing tests and all three compilation checks. All 2,900
captured inputs remain unchanged; 44 producer postimages match exactly and one
Worker parent preserves the newer staging and recovery exports. The four-file
mechanical prefix is committed separately, with token and import-name
equivalence checks; the final functional bytes remain the qualified candidate.

The broader core run finished with 1,151 passing tests and 28 failures. Failures
include snapshot schema and census integration, the fresh-schema expectation,
complete descriptor-to-router coverage, and timing or database-lock checks.
The full log is retained at
`/tmp/hub-principal-auth-current-context/core-full-v1.log`; this increment does
not establish full-suite acceptance. Actual PostgreSQL/MariaDB identity,
current combined runtime and hosted gates remain pending. Canonical restored
token-ID validation and pre-publication identity discovery have their own later
increments; this receipt does not qualify them or globally transactional
revocation across arbitrary concurrent changes.

## Canonical credentials and pre-upload identity discovery

The shared live API-token loader now rejects noncanonical credential IDs before
SQL. A correctly signed subject or a matching stored secret cannot authorize a
corrupt token ID. Genuine browser session provenance keeps its separate path.

WhoAmI adds deployment identity, an immutable actor commitment and a closed
transfer policy. These fields use protected configuration and a final live
actor read after awaited response data. Hybrid mode requires a configured
identity and advertises `direct_required` independently of provider readiness.
An unconfigured standalone Hub returns `legacy` with empty identity fields.
Standalone direct activation and the actual direct service remain pending.

Separate producer receipts
`/tmp/hub-canonical-token-identity/qualification-v1.json`
(`20b68f1e43e369055b86c0dbbfe88a967069134911443afc620db92037cc3d46`)
and `/tmp/hub-identity-continuity/qualification-v3.json`
(`53075bddac0c6fbe053166977336b200053787b07ff805912a8a5e2a2cc7e68c`)
record ten credential tests and four discovery tests respectively. Independent
review `a05f3f48800d240582a836dfdebdfb49fce9007c04adff55a4302ab04a39c23d`
verifies both sources, their captured inputs and a surgical current apply.

Current-context receipt
`/tmp/hub-principal-followups-current-context/qualification.json`
(`5fc74d6994e4540b2564849af511badf736dfa87290d927a324edda0063bbc6f`)
records another 14 named passing tests plus Native test, ordinary Worker Wasm
and CLI publication test compilation. All 2,901 inputs remain unchanged.
Seven owned outputs match their producer postimages; the Worker parent retains
the newer staging, recovery and authentication exports. This evidence does not
resolve the recorded full-core failures or qualify runtime, provider, browser,
fleet, standalone direct configuration or hosted behavior.

## Browser direct upload and standalone compatibility

The cache-file uploader prepares bounded file slices and signed provider parts
with four concurrent requests. It checks the retained grant and actual clock
immediately before Fetch, omits application credentials from provider requests,
and retains bounded resume metadata in IndexedDB without bearer URLs or tokens.
Checkpoint merging and cancellation share one read/write transaction. Provider
ETags must be exposed by CORS; ambiguous outcomes preserve the original part.

Authenticated WhoAmI policy selects discovery. A successful older standalone
response or explicit `legacy` policy preserves the existing upload path without
requiring direct capabilities or configured deployment IDs. Required direct
mode needs the same bearer, actor, target and capability proof. Unknown policy,
discovery errors and refreshed direct-required credentials refuse legacy file
dispatch. The marked legacy client checks the exact current bearer before its
controls, body and single refresh attempt; unrelated console flows are unchanged.

Producer receipt
`/tmp/hub-direct-upload-console/frozen-v3/qualification.json`
(`54d29ade959e3da7dfe23cb364b297719d5d2d22f1599ce7fc32211a7db278be`)
records 20 pure tests and an actual development Wasm library build, with all
2,466 inputs unchanged. Independent final review
`bbeb26cc90eb04cbb899787fbfe3335ec157b9fb330c677238114def6bb4a808`
verifies source, tests, artifact and exact patch application. Earlier dated
signature, expiry and credential-custody corrections remain preserved.

Current-context receipt `/tmp/hub-console-current-context/qualification.json`
(`cdaf63979c40680d58974c2560042d587679d499a6f912a3c48c8d3995eaaabe`)
records another 20 pure passing tests and ordinary Wasm compilation, with all
2,906 inputs unchanged and all 11 owned postimages exact. Capability-manifest
presentation is a separate semantic-equivalent formatting commit. Functional
coverage removes six obsolete browser exceptions; explicit Abort retains its
CLI exception. This evidence does not qualify an optimized console, actual
browser Fetch/IndexedDB/CORS, current broker, real provider, fleet or hosted
performance. No direct uploads are enabled by this increment alone.

## Snapshot generation compatibility after principal identity changes

Snapshot records accept exactly the compiled migration generations 3 and 4.
The paired authenticated headers select the matching trusted schema before any
row callback. Archives cannot supply SQL or select an unknown generation. The
historical migration digests and generation-3 archive bytes remain unchanged;
genuine encrypted fixtures exercise historical replay and truncation refusal.
Current schema checks cover 272 tables, 2,652 columns and 652 CHECK expressions.
New nullable principal UUID cells are classified without backfilling old rows.

Producer receipt `/tmp/hub-schema4-current-correction/qualification-v1.json`
(`dd02b1d2c1306114806a9d71c59737678b932e0d55efcbca4c3431f946871970`)
records 178 distinct tests: 156 snapshot cases, one fresh-schema case and 21
Native scratch cases. Independent functional review
`0b77d9b054289796028c0781a1c141d454155d9b03cdf77676948c8f1d1eed87`
and split review
`36d62d43bc07ec1c4703cceba4e1c0c7f8e1edacd6c51aae081368753afc2c4e`
verify the exact source and separate mechanical prefix, committed as
`5be6e6cf54`.

The first combined context passes 170 named tests, then fails Native compilation
because the browser now calls WhoAmI and its old Web capability exception is
stale. Failure receipt
`/tmp/hub-schema4-root-context/combined-failure-v1.json`
(`dbe08795e236fc1e8baa0a04859dd937784d6918d4fc50754b0e7d1914003947`)
preserves that result. Removing only the obsolete exception produces the
corrected combined context.

Current receipt `/tmp/hub-schema4-root-context-v2/qualification.json`
(`33e7d1ef3dab8e03b3f565e9f083450be5d14def9a6e21d06c9c53e4ebdd4f29`)
records all 178 named tests and ordinary Worker Wasm compilation passing, with
2,909 unchanged captured inputs and 17 exact owned postimages. Source input
digest is `a489b16f9eaaf5cd576917a77b0c37a173e35aa15ff56ce2f6971ef61113a359`.
This resolves the focused schema/archive integration failures. It does not
establish a new full-core pass, whole-Hub restore activation, current provider
or fleet acceptance. Direct service routing and later schema continuations
remain separate work.

## Fresh external metadata observations and retained journal decoding

The Worker can hold the addressed object's read slot through a provider HEAD
and its durable acknowledgement. A new observation requires the current compact
pointer to an actual positive publication receipt. Active or unknown writes
block it; missing legacy pointers are refused without HEAD-based adoption.
Exact historical replay performs no provider request and remains explicitly
historical. Application, snapshot and read-lease deadlines are checked after
acknowledgement and reply signing.

Heap ownership of the stage session preserves its JSON representation. The
original inline representation produced a Wasm RuntimeError during retained
state decoding; the precise trap cause is unproved. A serialization witness and
read-only restart checks preserve the original unknown operation without
rewriting its journal or issuing a provider effect.

Producer receipt `/tmp/hub-external-observation-box/qualification-v3.json`
(`3f0433c96a1bce76e38b8bffbb72712457464fe892610b6be9f7a6c5c3dd2aed`)
records 56 distinct pure tests, ordinary development Worker Wasm compilation,
ten persistent observation fault groups and two original pending-journal
restart checks. The separately run codec case overlaps those 56 tests.
Independent review
`832f17d167689c112c52e6a8a06529be91c648c908cb5edabe250fd8d8323b2c`
binds the exact source, artifacts and retained failures. Initial fixture field
ordering mistakes, the original stalled runtime and diagnostic runs remain
preserved. These runtime results use the earlier authentication context and a
controlled provider.

Current receipt `/tmp/hub-observation-current-context/qualification.json`
(`f03454288a154b7675847e700714fe98970dcb4162f223968b9af9ed815ceb96`)
records another 56 named pure tests and ordinary default Worker Wasm compilation
passing, with all 2,918 captured inputs unchanged and all 20 owned postimages
exact. Existing file preimages match without changes to current authentication.
Source input digest is
`7dd82e12e876c6b255e032bb437008b08578fe1007cc4e37453f7793c54076f1`.
The helper declaration wrap accompanies its required visibility change; other
existing hunks contain functional changes.

This qualifies metadata observations and retained decoding. Mutable GET,
Native after-await authorization, current persistent provider behavior,
complete writer closure, optimized packages, fleet and hosted activation remain
separate gates. An observation does not authorize a later independent body read.

## Explicit standalone Legacy capabilities

An unconfigured standalone Legacy Hub may advertise empty deployment and actor
identities together with an empty provider profile list. A partially populated
identity still fails validation. DirectRequired discovery, direct actor checks
and placement authorization continue to require the complete authenticated pin.
The generated ProtoJSON roundtrip preserves the explicit empty Legacy identity.

Producer receipt `/tmp/hub-direct-legacy-capabilities/qualification.json`
(`01e8108bc5475eb1a6b8f8878d57131269e8b14ae495ee8bddd952a84af411b7`)
records 19 portable tests passing on unchanged captured inputs. The initial
17-pass/two-failure run is retained; corrections add the two empty-string serde
defaults required by generated ProtoJSON and fix a malformed-identity fixture.
Independent source review
`c48e206d99167d263d4d71a376a0b654986a6866998e92c11142a96fd84014cc`
binds both final source paths.

Current receipt `/tmp/hub-legacy-caps-current-context/qualification.json`
(`56e21394c0e85a4401674bf62770b61329c05bc38345b48a78d7ad97a93ab904`)
records 19 named portable tests and ordinary default Worker Wasm compilation
passing. Both owned postimages match exactly and all 2,918 captured inputs
remain unchanged. Source input digest is
`770eea0410fe4645d2f9c2599b857562f2f92926b99fc43bf4a7066b9bd807dc`.
This is compatibility validation; connected Native, client, browser, provider,
fleet and hosted qualification remain separate gates.

## Bodyless OCI allocation and original bearer ownership

Direct OCI allocation retains the original deployment, account UUID and client
operation together with the exact registry, repository, digest and size. Lost
responses replay that allocation without creating another logical upload or
quota hold. Genuine OCI bearer grants carry their original account pin; current
token provenance and registry push permission are checked around awaited work.
Repository writes require the originally authorized active registry identity.
Allocation performs no provider request and receives an empty request body.

The unreleased migration 004 corrects the upload foreign key and adds the
retained allocation table. The matching current census is 273 tables, 2,668
columns and 656 CHECK constraints. Historical generation 3 DDL, digests and
genuine archive fixtures remain unchanged. Databases initialized with an older
004 draft require manual reset and reinitialization; this is not a migration
over that draft. The hosted staging database remains at generation 1.

Producer receipt `/tmp/hub-direct-oci-allocation/qualification-v9.json`
(`7b76c0094fb4c9857fc5cbb879f1325f0331de07c390bc3279546c40517dc37c`)
binds 201 distinct focused passes: allocation database 7, real outer handlers 9,
OCI JWT 5, snapshot 158, fresh schema 1 and Native scratch 21. Core results use
the unchanged V8 inputs; V9 reruns the remaining Native gates after correcting
three current census assertions. Earlier compiler, fixture and census failures
remain retained. Independent final review
`f7190ec1f100c2f4b986042045de6a9735c18ac795f58295d21453b34730dcf0`
binds the actual source and evidence without claiming a combined producer run.

Current receipt `/tmp/hub-oci-current-context/qualification.json`
(`0bd7cce346e3ff7f4f7be00887547d934cfb7724be4f5e457d95161793ff6c99`)
records all 201 exact named cases passing together with Native test compilation
and ordinary default Worker Wasm compilation. All 2,925 captured inputs remain
unchanged; all 25 allocator and census postimages match exactly. Source input
digest is `a400d22f8d7b4b54dad5d9e474b149074520ec7b7197ba0f0b767c2850920760`.

Seven-method direct service routing, Worker readiness markers, signed provider
delegation, storage-local manifest projection, connected clients, fleet and
hosted activation remain separate gates. This increment does not enable them.

## Parallel direct clients and publication barriers

The CLI, selected Hub cache, APR publication and OCI callers use the shared
direct upload engine. File and part concurrency are bounded separately; the
default engine permits eight files, four parts per file and 32 aggregate
provider requests. Small metadata uses one-part objects and bounded waves of
64 intents. Private payload and metadata staging precede publication barriers;
a failed prerequisite or refused commit leaves the other destinations' public
pointers unchanged. Generic non-Hub stores retain their existing transport.

Source custody uses retained descriptors, bounded hash catalogues and 64 KiB
stream chunks. FIFOs are refused before Hub or provider requests. NAR spools
have separate disk bounds. Checkpoints retain original operation, identity and
receipt facts without tokens or signed upload URLs. Provider grants are checked
again after waiting for concurrency capacity. Required direct mode refuses
legacy upload fallback. The Unix source/journal machinery is qualified on
Linux; portable selector propagation and refusal policy do not establish a
Windows build or runtime result.

Producer V5 receipt `/tmp/hub-direct-upload-client-final-v5/qualification.json`
(`68e658c0bc11bcbbbb75b9528327a7d2722a6c43df600699db27e0f61cebee8b`)
binds 73 exact client paths. Its 88 distinct passes combine 73 unchanged
earlier net/remote/OCI cases with 15 current cache/APR cases; its four-package
check passes. Independent review
`0e4dbee3f7f211520a6f87281922af73e9a7ef218ba08a79f774660e57122aee`
binds source and evidence. Root adapter review
`408f57be6a9a720998641794fb588dc4047b398eb3a99f5c6cee693401ad8cfc`
covers the cache, publication, NAR and CLI wiring. The mechanical prefix is
committed separately; split receipt `5c0e1a01f554d6809513faeb4cdcf64ced65b97c535f789053a0946b9e2af1ee`
reproduces all final postimages exactly.

The first current integration attempt stops before compilation because the
locked dependency graph needs updating. Immutable failure receipt
`e7dfed2e76b9627e5249c8054f4435a79998f70202dc023701d63b2b44e42ab4`
retains that failure and all 2,968 unchanged inputs. The correction adds only
15 dependency edges to four client package entries, with no package, version,
source or checksum changes; the newer console dependencies remain intact.
Offline full resolution and subsequent locked metadata both pass. Producer
lock receipt `cabab5178df23b460e1c022c72063e559dd1dc0d13811ef390b0da540e384a1c`
and root review `52d2edcbad8c8a72cc0fc4e66940cffaf74aac9385a8666f297bc909c78646bf`
bind the scoped correction.

Current receipt `/tmp/hub-client-current-context-v2/qualification.json`
(`3dea2cb365f978ed812df89f04f4b66f861cca3f3e68fc464721e73f43beea6c`)
records all 88 exact named tests passing together on the current Hub/proto,
Legacy, authentication, browser, OCI and schema-004 context. All four client
packages compile and the three Linux debug binaries `aos`, `apr` and `apm`
build. All 2,968 captured inputs remain unchanged; all 73 client postimages
and the reviewed lock postimage match exactly. Source input digest is
`e10eef7834fa4ac7dde9dd158106782312c2f52f9dd048cc00caf8dd3464abd6`.
Strict synthetic ownership tests run in the authorized host user namespace.
Three actual version probes return exit zero; smoke receipt
`f66021c5039b7c2ec05d1b1d7b73e92dc3fe628dbab3be73fd4dea8337850ffc`
binds startup and dynamic library loading to the linked artifact receipt.

These are local HTTP, filesystem, scheduling and barrier checks. They do not
qualify actual signed provider transfers, Native or Worker activation, OCI
projection, browser Fetch/CORS, current packaged artifacts, foreground
cancellation, throughput or cross-cloud byte budgets. The synthetic 12,535
metadata case demonstrates batching and overlap; its control count is not an
observed Native request or SQL count. The running release staging publication
remains unchanged. Connected storage execution, fleet and hosted acceptance
remain separate gates.

## Storage-local semantic metadata transport

Native can send a bounded signed metadata observation plan to the paired
Worker without receiving a lease-renewal credential. The plan retains the
original SQL-derived object stamp, binding writer revision, exact selector,
independently selected protected profile fingerprint and application deadline.
The Worker selects its actual configured issuer and read lease, and keeps the
durable read slot across provider HEAD and terminal acknowledgment. Ambiguous
effects retain their fence; historical replay does not dispatch provider work.

The separate Native HTTP pool disables redirects and transport retries.
Concurrency waiting precedes signing and sending. Response bounds, MAC,
correlation and the original deadline are checked before returning evidence.
The business caller still must check current actor, ACL, binding, placement,
publication and receipt facts after awaiting this transport.

Producer receipt `/tmp/hub-semantic-external-observation-v2/qualified-final-v2.json`
(`facab83010f94f57e1ea8e57dd9be4a045086018de90c332d5f25e806c03029b`)
records 23 focused core, Worker and Native HTTP tests, default developer Worker
Wasm compilation and assembly, and nine persistent controlled issuer/guard
groups. Those groups use the actual Rust issuer and SQLite guard with a
controlled signed HEAD provider, covering held reads, lost acknowledgments,
restart and expiry after awaits. Independent final review
`dd1e11e40856b410cfcb1559c564758aa1eca56c82743e92177df68a1f0f0014`
binds that source and evidence.

Current receipt `/tmp/hub-semantic-current-context/qualification.json`
(`2b8b9a224cf7a79150ef46c390463091787f1c38d0096e1b0d0baa1649ac455d`) records the same 23 exact focused cases passing on current
direct-client, Legacy, authentication, browser, OCI and schema-004 source,
with Native test-context and default Worker Wasm compilation. All 2,976
captured inputs remain unchanged and all 18 owned postimages match exactly.
Source input digest is
`af52262c4539111152045a3adec16ae6bfb27dfd59164c74fe8db477040b9481`.
Root preimage review
`0fa925a831d24d889edc3bec6a542e6897008f91a21ef1404e6399efc0c405b2`
binds the surgical current-context integration.

This increment qualifies semantic HEAD transport. It does not qualify a live
Native service factory, mutable body GET, destination reservation, all writers,
optimized Worker artifact, actual provider policy, capacity, throughput,
foreground cancellation, fleet or hosted activation. Existing token-bearing
observation encoding remains unchanged. The original semantic profile
fingerprint is distinct from the planned full direct-upload protected pin.

## Original browser-session identity after cold reload

Fresh session mint atomically pins the original canonical user UUID. Cold and
cached cookie resolution compares that retained pin with the live account,
session hash and lifetime bounds. An old cookie without a pin requires fresh
authentication; resolving it never assigns or repairs a UUID. Browser claims,
email presentation and post-email identity checks retain the same provenance.

Producer V2 receipt `/tmp/hub-cold-session-owner-pin-v2/qualification-v2.json`
(`b24b026d95fa080c026b100e5c2e238d2ece9fb170daa82ee48c411f31026880`)
records 20 focused tests, Native test-context and default Worker Wasm checks,
and 2,970 unchanged inputs. Independent evidence review
`029de336c1d6ac9d5e23367b3cbfb4c467e5fd6b8d586891b81654af0f9c335e`
binds that result. The earlier malformed-UUID email-resolution source blocker
is preserved; V2 validates the canonical UUID before returning an email.

The first current run stopped on zero matching session tests despite Cargo
exit zero. Retained failure
`58a8a6356ad4dfd2076a7f77d8637ae2c7f0a6c674a1289a1792808cc3562f10`
binds the old compiled test list, absent new dependency and unchanged source.
The copied owned sources had older modification times than the warm artifact.
Refreshing only those 14 isolated source modification times forced normal
Cargo recompilation; no source bytes, selector or test expectation changed.
The zero-test result is not counted as a pass.

Current receipt `/tmp/hub-cold-session-current-context/qualification.json`
(`0c242a1a90f8c08747ad5142739d017269260ab47988ea8c317c0cda7036d8d3`) records all 20 exact tests passing after that rebuild,
with Native test-context and default Worker Wasm compilation. All 2,978
captured inputs remain unchanged and all 14 owned postimages match exactly.
Source input digest is
`7fcf5d4aaf1f165fd866f9ff769db6bbf5846b21f0ba9193c514b7bc5811e42d`.
The preparation's only unowned amendment is the committed semantic transport
ledger; code parents match their qualified preimages. The current initializer
and compiled/source audit assert 273 tables, 2,669 columns and 657 CHECKs.
Unreleased migration004 digest is
`8744c486ed5f20950bb74665cfe4e3288f1345e0d94e4224069ef1bba5e969c2`.

The file database fixture drops and reopens genuine Database handles in one
process. It does not establish an OS or VM restart, PostgreSQL/MySQL runtime,
hosted login, snapshot import or whole-Hub deployment result. Historical
snapshot contracts remain unchanged; the session pin is authentication state
excluded from snapshot records. Older initialized migration004 requires an
explicit reset or migration, and hosted staging remains generation1. This
supersedes the earlier retained-context limitation for the tested cold paths.

## Client restart while server verification is pending

Clients accept `CompletingStaging` as pending verification so independent staging
waves can continue. Their publication barrier still requires `Committed` for
every original owner. A reopened private SQLite journal retains the original
Complete request and skips Begin and provider body transfers for that completed
local request. Polls preserve its operation, resource version, manifest, actor,
and placement identity. One original finish deadline bounds discovery, journal
page reads, control requests, and polling waits.

Current source receipt
`/tmp/hub-direct-upload-client-pending-current/qualification.json`
(`9f888a784e99795de08b80ac6217f2fcdfb328de8026e2723f4e16fce6a89fcf`)
records six focused tests and successful checks of `aos`, `aos-package`,
`aos-cache`, and `aos-oci`. All 5,628 captured tracked inputs remain unchanged;
six approved client postimages match exactly. The subsequent deployment RFC
clarification changes two documentation files and no compiled source. The
actual SQLite reopen and HTTP fixture sends the identical Complete twice,
receiving pending then committed, with no Begin or provider body. Deadline
helpers are separately checked with held futures and an already elapsed cutoff.

This is client protocol and local restart evidence. It does not qualify actual
Worker queue consumption, Native commit, real R2/S3 behavior, throughput,
cross-cloud byte budgets, full fleet execution, or hosted acceptance. Mechanical
formatting follows in a separate commit.

## Retained runtime checkpoint

Commit `5027166b2b` connects bounded signed Native metadata controls, real target
admission and atomic accounting to the broker and physical guard. Native receives
no bulk bytes. Immutable Complete and Abort intents, original baselines and
independent guard receipts survive replay; unknown effects retain their fences.
Production execution requires independently accepted current provider and
profile dependencies and fails closed when they are absent.

The source-built focused gates below passed. Counts describe separate scopes;
overlapping runs are not added into a combined suite result.

| Scope | Passed gates |
| --- | --- |
| Core lifecycle and snapshots | 58 direct tests; 176 snapshot, catalogue, historical archive and retained receipt tests |
| Native and SQL authority | 6 target tests, including 64 real admissions with one invocation-scoped profile discovery; 3 OCI tests with SQLite and live PostgreSQL accounting/replay; 2 separate live PostgreSQL IAM and membership revocation tests; 1 signed ingress fixture |
| Routing and public contract | 1 complete 428-method route check; 21 retained classifier tests; 2 minimum-size protobuf tests; 3 CLI coverage tests |
| Clients | 115 focused tests: cache 8, console 23, net 52, OCI 12 and remote 20; console Wasm compilation |
| CLI reporting | 3 library tests and binary compilation; original counters are reported after commit and on error |
| Broker and Worker | 9 signed HTTP orchestration tests; 3 journal, 2 provider pool and 1 SQL migration translation tests; default Worker and broker Wasm compilation |
| Physical guard | 3 Rust tests and the packaged persistent Worker runner: 7 action requests across 3 process lifetimes and 2 SIGKILL restarts, with an explicit test provider; guard Wasm compilation |
| Installer and acceptance | 8 independent signature and protected discovery tests; 36 Cloudflare configuration, rendering and secret custody tests; Hub CLI compilation |

The actual 64-object broker fixture uses four HTTP phases. Freeze, Baseline,
Promote and Commit request sizes are 75,309 / 176,494 / 211,956 / 107,495 bytes;
reply sizes are 221,682 / 75,250 / 177,994 / 202,195 bytes. All fit the unchanged
256 KiB bound. Lost Commit replies and a new runtime recover disk-retained
originals without changing the first Complete or CAS. These are encoding and
replay results, without a throughput claim. Subsequent metadata concurrency work
is outside this checkpoint.

The separately committed relative snapshot custody fix passes 28 tests in the
actual build sandbox. Client fixtures under foreign-root ancestry prove refusal
before effects; their positive cases under a trusted root still require VM
execution. Earlier failed gates and unknown originals remain retained.

## Small ordinary provider SDK probe

A fresh 32 KiB ordinary provider probe passed direct signed UploadPart, CORS and
rejection of bytes with an incorrect MD5. Ordinary Create and Complete, HEAD,
full SHA-256 verification through GET, and native SDK range copy with a
known-length stream passed. Positive Abort and rejection of late parts also
passed. Cleanup of the successful probe was positively acknowledged; older
unknown originals remain retained.

This small probe does not qualify large objects, queue execution, clock bounds,
staging privacy, capacity, throughput or the full fleet. Installer and local
runtime gates do not supply that independent provider qualification. Current
integrated fleet and hosted Native acceptance remain pending; no hosted
performance result is claimed.

## Published follow-up source checkpoints

These source-built gates cover separate runs and scopes; their counts are not
combined into a new full-suite result.

- [TLS fixtures and snapshot census, `b80ce0d7`](https://github.com/andyl-technologies/aos/commit/b80ce0d7c7bed293e35c17d5cefe308765525f65):
  the original sandbox run passed 4,831 of 4,835 tests. Its four failed cases
  subsequently passed in a separate corrected sandbox run. Twenty-one Native
  scratch tests also passed. The original failures remain recorded.
- [Acceptance and installer checkpoint, `88a6b8bf17`](https://github.com/andyl-technologies/aos/commit/88a6b8bf170bac83845825d9e49cad9ac6bd7025):
  12 shared qualification tests and 37 installer tests passed, and the Hub CLI
  binary compiled. The isolated source set comprised 11 installer/shared files
  and two Worker integration files. Its default Worker Wasm build passed in
  1 minute 32 seconds. These gates qualify the tested contracts and compilation.
- [Authority bootstrap, `4fb8a9fe81`](https://github.com/andyl-technologies/aos/commit/4fb8a9fe81bf486c2dda8d6a9387b5dbf1eb9a64):
  five tests actually executed and passed, covering real root Plan/Apply,
  private canonical export, read-only SQLite attachment, stale-pin refusal,
  authenticated TLS hydration and credential/authority races with revocation.
  The live PostgreSQL case derived and hydrated through a role restricted to
  the documented table reads. The standalone binary compiled and its top-level,
  Export and Hydrate help commands passed. The
  [operator guide](../users/aos-hub/authority-bootstrap.md) describes the
  interface; installed package availability remains a fleet gate.
- [Metadata inventory measurement, `352cbb71d3`](https://github.com/andyl-technologies/aos/commit/352cbb71d3f8aad38c9652855e639068fad59f05):
  the opt-in Native router/local filesystem fixture actually wrote and
  SHA-verified 12,535 metadata objects, using 196 Append calls. Seal and Commit
  reply bodies were 4,202,537 and 4,403,116 bytes; each remained below 8 MiB.
  Metadata bodies totalled 1,066,900 bytes. Inventory control request and reply
  body aggregates were 2,598,606 and 8,665,015 bytes respectively. The actual
  test completed in 51.460 seconds. These are local inventory measurements.

These checkpoints establish no current VM qualification, 2 GiB provider
transfer, deployment queue execution, throughput, clock bound, staging privacy
or hosted Native acceptance.

## Further reviewed source and focused gates

The source through [`9b6b14872c`](https://github.com/andyl-technologies/aos/commit/9b6b14872ced776165f145efa84f17c831e57576)
includes the following reviewed increments. The counts describe separate focused
runs, with overlapping scopes; they are not a new combined suite result.

| Source scope | Reviewed gate and limits |
| --- | --- |
| [Immutable front cache and Native shielding, `6569f0e54b`](https://github.com/andyl-technologies/aos/commit/6569f0e54b595fc954ea2ae984d506c4dbdc441e) | Five actual HTTP tests and an isolated default Worker Wasm build passed. Cache reuse is restricted to immutable public policy; object-byte cache hits still require fresh Native grants. Local per-isolate bounds do not establish hosted Cache API behavior or global throughput. |
| [Canonical documentation projection, `5b6ccb9419`](https://github.com/andyl-technologies/aos/commit/5b6ccb9419e766f068ce4476ae5a6f874baa5879) | Fourteen core, one Native and three integration tests passed for typed storage-local projections and their public rendering. |
| [Independent acceptance review, `e1700d6cae`](https://github.com/andyl-technologies/aos/commit/e1700d6cae46477313b1cd0770ca4689cf2e82ac) | Thirteen tests passed, including the actual prepare/sign CLI, exact reviewed candidate rechecks, independent Ed25519 verification, raw-report substitution refusals and protected key custody. Selected-file commitments and authenticated driver captures still require independent human review of the actual evidence chain. |
| [Native custody and guarded Worker controls, `7818742a13`](https://github.com/andyl-technologies/aos/commit/7818742a1300e9dd56fe2a3b8c210ad5d1b1144e) | Native bootstrap nine, SQL fence two, frozen-access nine and accounting one tests passed. Guard gates passed five core, two persisted Worker SQLite and one per-key tests. Worker gates passed four provider-pool tests and six controlled HTTPS driver tests. The packaged fixture observed private-namespace 404 refusal and retained guard state across two SIGKILL restarts. These controlled observations do not qualify a deployed provider namespace or its complete writer set. |
| [External provider observations, `cad69adcd2`](https://github.com/andyl-technologies/aos/commit/cad69adcd267d63199b247911208bc8f8f7774da) | Five actual TLS cases passed for the source-built provider conformance tool. The tool retains observations; it does not issue a provider contract or accepted runtime artifact. |

A separate full hermetic baseline of 24 selected application packages from
committed `cad69adcd2` passed 4,892 tests across 102 binaries, with zero failures
and nine tests skipped. Its terminal build, install, fixup and source scrub
succeeded. The Native release package with PostgreSQL support built from that
same source, and all six actual installed tools passed
`--help`, including authority bootstrap, independent review and provider
conformance. This baseline excludes future custody coalescing and mirror changes;
it does not qualify a provider deployment or the integrated fleet. Earlier
failed runs remain recorded above.

Two additional closed contract corrections are committed:

- [`76df675426`](https://github.com/andyl-technologies/aos/commit/76df675426e1dcb9da9ba1fff45b614932fe2711)
  records the emulator's unsupported global queue invocation bound explicitly.
  Hosted queue invocation caps remain required, independently selected policies.
  Object and provider limits apply per participating isolate; no aggregate
  global concurrency limit is inferred from them.
- [`bd485532ab`](https://github.com/andyl-technologies/aos/commit/bd485532ab51de7b171fb54d9428c123ad13c244)
  binds narinfo qualification to the actual 256 KiB production parser ceiling;
  seven shared boundary tests passed. Full accepted runtime and bulk-object
  measurement gates remain in force. The separate 12,535-object publication
  workload is unchanged.

The current source audit still finds no hybrid upstream mirror job or
pull-through implementation: full-mirror scheduling is skipped in hybrid, and
the existing mirror writer requires a local filesystem. Deployment R2 placement
copy, OCI composition and staging cleanup, cache GC and OCI GC have connected
remote adapters and controller paths. Their presence does not qualify their
deployed execution. Unsupported external-provider copy, OCI composition and
conditional deletion remain explicit per-binding capability restrictions under
[RFC0023's workflow contract](../rfcs/0023-hub-hybrid-topology/04-workflows.md).
Whole-Hub PostgreSQL/Worker capture and restore remain the later portability
phase; the current snapshot CLI exposes SQLite capture and verification.

Current integrated VM/fleet execution, actual 2 GiB provider transfer,
complete queue and mixed-load measurements,
clock bounds, staging privacy and writer closure, hosted Native acceptance,
runtime parity, latency and byte-direction budgets remain qualification gates.
Earlier failed runs and unknown originals remain recorded above. No production
readiness or hosted performance result follows from these focused source tests.

## Storage-local Git tree and pack checkpoints

[Selected tree projection, `edf0446f72`](https://github.com/andyl-technologies/aos/commit/edf0446f72ad05b907792e7186e44b0baadaf3d9)
adds bounded name/kind/OID pages with continuations bound to the verified tree,
selection and source snapshot. Ten focused tests passed: four shared predicate
and pagination tests, five Worker/wire/Native-validator integration tests, and
one Native capability test. The isolated default Worker Wasm check passed.
Controlled R2/S3 stream fixtures exercised the actual registry indexer with a
raw source-tree fetch trap, provider length bounds and source/hash/cursor drift
refusal. The frozen 14-file manifest is SHA-256
`6ac35b117940e00077f7e84a32435c9fd9c3a326d847794d1207b3b7173f2798`.
Earlier compiler failures and the zero-test capability invocation remain retained
and are not counted as passing tests.

[Pack/index verification and projection, `157359b957`](https://github.com/andyl-technologies/aos/commit/157359b957c4303161b0f55d6a86b9221a231eee)
consumes pack chunks without retaining encoded pack bodies. Complete SHA-256
pack/index, CRC, offset and delta validation precedes selected decoded content.
The existing 8 MiB pack, 4 MiB index, 12 MiB decoded graph and 4 MiB object limits
remain enforced; selection returns at most eight objects and 128 KiB of content.
The isolated registry suite passed 90 tests, including 16 pack cases with actual
AOS Git OFS/REF fixtures, stream splits, substitution refusals and resource/range
bounds. The pure Wasm check and one pure execution-deadline test passed. The Worker
adapter source check passed with an explicit Reader dependency and a gate-only
module declaration; its initial private-Reader compile failure remains retained.
The frozen 11-file evidence manifest is SHA-256
`09a1ff991decef84fed51910726556a50d8fe575f2247b36572d3c9c9f80abe0`.

These controlled fixtures and source checks do not establish completed mirror
runtime integration, deployed upstream/provider behavior, publication, fleet
qualification or throughput. Pack transport, source-incarnation checks, authority
and capacity integration remain pending. The Worker source check does not qualify
actual awaited reads or cancellation. Earlier failures and pending deployment
gates remain in force.
