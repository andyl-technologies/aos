# External object coordination prerequisite

The external journal module is an interface and state contract. It has no
production route, Durable Object storage adapter, namespace approval issuer or
provider executor. External conditional DELETE remains disabled, including
when a structurally valid reviewed deletion is constructed. Existing R2
schemas and receipts are unchanged. Its fixture tests do not qualify any
provider or establish actual Durable Object durability.

## Authority before activation

An authenticated Native/operator control source must persist a permanent
authority ID for each physical bucket and the exact provider addresses proven
to reach it. The map constructor validates structure and conflicting entries;
it does not establish provider ownership or alias equivalence. Ordinary signed
work requests cannot invent authority IDs or approve aliases. Missing or
unproven mappings must reject execution.

Logical binding aliases with identical approved coordinates converge directly.
Different endpoint/bucket aliases converge only after independent approval as
the same physical namespace. Matching ETags, credentials, DNS answers or
provider bucket labels do not establish that equivalence. Production needs
complete namespace admission policy to prevent two authorities reaching the
same physical bucket. DNS/endpoint ownership changes require renewed evidence;
an approved mutable hostname alone cannot prove ongoing storage identity.

Initial activation also requires a never-reused namespace or proof that all
previous direct writers and admitted provider effects have drained and settled.
Waiting out an HTTP timeout or signed-work lifetime does not establish that
proof. A new guard cannot reconstruct unknown effects dispatched before its
journal existed. Native-only and Worker-only direct S3 writers cannot coexist
in a guarded namespace unless they participate in the same authority boundary.

Guard addressing is a domain-separated hash of permanent authority ID and
full physical key. Binding and placement prefixes are joined into the key;
splitting that same key into different logical prefixes cannot create another
guard. Binding revisions, credential generations, request IDs and lease tokens
do not affect its address. The authority map and DO namespace must survive
SQL resets and credential changes while storage can be reused. Historical
address mappings cannot be reassigned or dropped based on receipt age.

The initial interface accepts canonical HTTPS origins without base paths and
canonical bucket/key spelling. It rejects noncanonical or unapproved values.
An adapter must perform existing URL safety checks and construct the same exact
physical key as S3 URL signing. Unsupported endpoint forms must fail closed.

## Durable adapter obligations

The production DO adapter must check its addressed scope, acquire the object's
gate, and hold it over journal and provider awaits. Its journal pins the scope,
stores one pending intent and stores terminal receipts by stable operation ID.
Persist pending before dispatch. Persist the exact terminal acknowledgement
before removing only its matching pending record. Propagate storage errors.
Keep bodies, retained secrets and signed provider URLs request-local.

The effect closure receives authenticated request-local credentials and exact
provider payloads. Typed journal metadata contains only scope, operation ID,
effect kind and nonsecret payload fingerprints. Compute PUT SHA-256/size from
the exact dispatched bytes, and multipart fingerprints from the validated
upload ID and exact ordered completion parts. Do not trust separately supplied
caller digest declarations. A reviewed DELETE uses retained SQL action ID and
its existing stable claim fingerprint, never a transient lease token.

Only a conclusively settled provider rejection may become a `Rejected` receipt.
An adapter must qualify its provider's actual negative acknowledgement contract;
generic HTTP status, intermediaries and transport errors are insufficient.
Rejected results cannot establish deletion or reclaimed bytes. An unknown
effect, incompatible response or lost receipt remains fenced across restart.
Neither observation of absence nor capability probe success resolves it.

## Required routing changes

All these paths must enter the same external authority/key boundary before
external destructive GC can be enabled:

| Current path | Required boundary |
| --- | --- |
| `surface::execute_external_storage_work` `PutMetadata`/`PutProbe` | Journal PUT; retain stable effect ID and exact body fingerprint |
| External `CompleteMultipart` | Journal visible completion; persist provider completion acknowledgement before later observation |
| External `DeleteProbe` | Journal removal of the service-owned reserved key |
| External HEAD, inventory evidence and presence-sensitive reads | Guard observations against unresolved effects; return actual provider identity |
| Retained `hybrid_frozen_cleanup` HEAD | Resolve the same historical authority/key; never publish its retained credential |
| Future external copy, composition, staging publish/delete | Journal every destination-visible mutation under the same authority/key |
| Credential probe paths | Inventory all provider effects; multipart create/part/abort may remain outside when they cannot make an object visible |

Multipart create and part transfers can remain direct because they do not
publish the destination. Completion must be guarded. Post-completion HEAD is
separate evidence and must not substitute for the recorded acknowledgement.
Copy involving two keys needs a specified acquisition order or independent
version-bound source observation to avoid deadlock and source replacement.
Out-of-band writers require a provider-native exact version condition or an
explicit exclusive-writer namespace contract; a DO cannot fence them.

## Remaining destructive work

Add claim-aware Native deleter admission alongside the existing claim-aware
fetcher. Recheck the live SQL action, credential hold, frozen address, retained
generation and observed capability before signing the short-lived cleanup
grant, then correlate and revalidate the terminal result before SQL commit.
Add the closed destructive result schema and durable provider receipt adapter.

Keep DELETE disabled until every visible writer and observation above is
covered and real provider qualification passes wrong-condition survival,
matching deletion, absence, duplicate/renewed action replay, replacement races,
lost response and storage-failure cases. Qualification must prove exact binding
semantics; it cannot repair an earlier unknown effect. Versioned buckets need
explicit version-aware deletion and accounting before physical reclamation
can be claimed; plain DELETE may only create a delete marker.

No receipt retirement or timed fence removal is included. Any future retirement
protocol must establish durable replay/admission floors and provider settlement
across all admitted operation sources before deleting terminal evidence.
