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

Account UUIDs now pin API tokens, genuine cookie sessions, JWT provenance and
reviewed topology operations. Permission checks revalidate the same live actor
around awaited IAM reads. A replacement account cannot inherit a retained
request merely by reusing its numeric SQL ID. Existing tokens without an owner
pin must be reissued; validation never backfills that pin from a numeric ID.
Migration 004 and the matching snapshot census are additive prerequisites.
Their presence does not activate the unfinished direct upload service.

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
