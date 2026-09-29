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
