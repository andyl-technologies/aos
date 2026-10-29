# External authority qualification bootstrap

`aos-hub-authority-bootstrap` is a separate operator tool installed by the
source-built `aos-hub` package. It exports current reviewed SQL metadata and
publishes exact current provider credential versions to the paired Worker. It
does not serve Native traffic, upload objects, produce a provider contract, sign
runtime acceptance, or establish provider readiness.

Run Export after the root operator has applied the actual physical authority,
alias, binding association, exclusivity attestation and admitted generation
through `StorageAuthorityService` Plan/Apply. Read, write and presign credentials
must be current, validated and included in that reviewed attestation. The
selected binding must use private access.

## Permanent binding lifetimes

A binding stable ID is reserved permanently when its creation commits. Deleting
an unreferenced binding preserves that reservation. Create a distinct stable ID
for a replacement; equal numeric IDs, owner, resource version or timestamps do
not establish the former lifetime. Exact successful plan retries retain their
original receipt and do not create another binding.

Deletion plans capture the reservation UUID internally. Upgrade and activation
validate retained deletion history in bounded pages without rewriting its
original confirmation bytes. A live identity with a positive prior deletion is
unsafe. A legacy claimed deletion without the original UUID is also ambiguous,
including a lost reply or blocked attempt. These cases require explicit operator
reconciliation or reset; changing a timestamp or silently discarding history
cannot authorize work. Legacy unclaimed deletion plans require a new plan.

The read-only helper checks these invariants independently of the schema marker.
Historical archives may remain verifiable, but import must validate and retain
permanent reservations before exposing authority. Reservation presence itself
never grants a provider lease or qualifies restored work.

## Validate queued credentials without Native provider material

The configured Native Hybrid router registers only an unvalidated immutable
reference and the SHA-256 digest of its exact provider value. It does not resolve
provider material during `PlanSetBindingCredential` or rotation. The reviewed
binding version, stable identity, owner and head generation fence Apply; a
missing local resolver never selects this policy. Native-only and Workers-only
registration retain their existing provider-byte verification. Metadata
registration grants no work or lease admission: staging and the actual queued
controller validation remain mandatory.

Install the paired Worker and storage control key before validating external
credentials. Create each immutable credential revision through the normal
authenticated binding control API. Apply its reviewed
`PlanValidateBindingCredential` plan; keep the returned operation identity. On
the operator or Worker machine, stage only that actual queued original:

```sh
aos-hub-authority-bootstrap --database-url-file ./operator/sql.url stage-credential \
  --operation-id '<queued-operation-id>' \
  --deployment-id '<paired-deployment-id>' \
  --worker-url 'https://paired-worker.test' \
  --storage-work-key-file ./operator/storage-work.key \
  --secret-version-manifest ./operator/provider-versions.json \
  --output ./operator/credential-stage
```

This command attaches read-only to live SQL, verifies the original binding,
credential head, immutable reference, fingerprint, write-state CAS and probe
token, and resolves material on the invoking operator machine. It authenticates
the Worker acknowledgement and rechecks the originals after the exchange. The
private receipt contains metadata and a commitment to the staged control; it
contains no provider material and cannot mark SQL credentials valid.

The existing Native controller sends a fresh metadata-only challenge. Worker
uses its exact retained material to execute the real purpose-specific provider
probe and authenticates the result against the complete original task and nonce.
Native atomically fences the running claim, binding, credential head and original
write state before persisting validation. Write capability selection also keeps
the original fence across controller restart. A missing stage or failed exchange
leaves the credential unvalidated. If the controller already failed an unstaged
task, stage that original and use authenticated `RetryOperation` with its current
resource version; the helper does not retry or settle the task itself.

## Export current decisions

Prepare an existing private directory and owner-private input files. The SQL URL
file contains one database URL. The issuer configuration is the same explicit
configuration used by `aos-hub-authority initialize` and `serve`; its permanent
installation and executor must exactly match the reviewed authority. The public
verifier file contains the independently supplied lowercase hexadecimal Ed25519
public key. Export does not read the issuer's signing seed or publisher/renewal
keys.

The admitted qualification prefix must be within the actual reviewed binding and
attestation prefixes and contain a `.aos-direct-qualification` path component.
It identifies the separately configured qualification domain; its stage prefix
is exactly that prefix followed by `/.aos-direct-upload`.

```sh
aos-hub-authority-bootstrap --database-url-file ./operator/sql.url export \
  --authority-id '<permanent-authority-uuid>' \
  --association-id '<reviewed-association-id>' \
  --deployment-id '<paired-deployment-id>' \
  --issuer-configuration ./operator/issuer.json \
  --issuer-public-key-file ./operator/issuer-public-key.hex \
  --admitted-prefix 'binding-prefix/.aos-direct-qualification/probe' \
  --output ./operator/export
```

The new directory contains:

| File | Content |
| --- | --- |
| `publication.json` | Canonical current root-reviewed `StorageAuthorityPublication`, including aliases and complete attestation membership. |
| `bootstrap.json` | Closed version-one metadata: exact binding snapshot, public `DirectExternalProfileSelector`, issuer installation/public verifier/timing policy, independently derived read/write cohorts, and isolated stage prefix. |

The binding snapshot contains immutable secret-version references and
fingerprints, never provider material. Selector credential identities are stable
hashes of the actual binding, purpose, generation, reference and fingerprint.
The export contains no provider contract booleans, private-stage qualification,
accepted profile or runtime readiness claim. Use its actual aliases, publication
and cohorts when configuring the independent issuer and Worker consumers. Add
provider closure/private-stage evidence only from actual separately measured
qualification.

Output publication uses a new private directory and files with `0700`/`0600`
permissions. Traversal rejects symlinks, foreign custody and writable ancestors;
the final parent must be private. All documents are bounded to one MiB. The tool
publishes the final directory only after every file is durable and never
overwrites a prior export. A failed attempt may retain a private `.partial`
directory for inspection.

## Hydrate on the operator or Worker machine

After independent issuer initialization and Worker installation, run Hydrate
where the actual provider material is available. It requires live SQL both
before and after the authenticated Worker exchange; an old exported snapshot
alone cannot prove current authority. To keep provider material off Native, run
this separate executable on an operator or Worker machine with narrow protected
SQL connectivity. The Native service does not need a provider credential
manifest.

```sh
aos-hub-authority-bootstrap --database-url-file ./operator/sql.url hydrate \
  --bootstrap ./operator/export/bootstrap.json \
  --worker-url 'https://paired-worker.test' \
  --storage-work-key-file ./operator/storage-work.key \
  --secret-version-manifest ./operator/provider-versions.json \
  --output ./operator/hydration
```

The manifest is the existing owner-private map from exact immutable secret
references to private material files. Hydrate resolves and fingerprint-checks
those exact versions, then calls the existing protected binding publication
interface over the configured HTTPS origin. It verifies the exact acknowledged
revision and rechecks the entire original publication, binding and credential
set against live SQL. Changed pins refuse before publication; changes during
publication trigger exact remote revocation and refuse success. Remote failures
remain failures; they do not establish provider settlement.

`hydration/hydration.json` records the local acknowledgement, its exact snapshot
revision and bootstrap/publication commitments. It contains no material and
always reports `provider_readiness_evaluated: false`. It is an operator receipt,
not a permission, acceptance artifact or provider qualification. Continue with
the existing `aos-hub authority-control-sync`, actual issuer lease renewal,
fresh protected profile inspection, measured SDK/provider/runtime evidence and
independent acceptance review. Each of those steps retains its own trust checks.

## Native restart and retained cleanup

Cold Native placement reads adopt the Worker-held snapshot through a fresh signed
metadata challenge and reply. This compares full current SQL binding coordinates,
credential purposes, generations, references and fingerprints before and after
the exchange. An existing live acknowledgement retains its exact snapshot hash;
expiry can renew only under the same current validated pins. Native does not load
the provider manifest or trust an old hydration receipt. Changes during adoption
trigger exact remote revocation and refuse the local plan.

Each Native client coalesces concurrent adoption within the same binding. It
reuses only independently authenticated acknowledgements for at most ten seconds,
checks full current SQL pins on every reuse, and refreshes when the snapshot has
at most sixty seconds remaining. Reuse never extends expiry or grants execution
permission. The process-local renewal map holds at most 1,024 cohorts, evicts only
idle entries, and refuses a new cohort if all entries are busy. Different bindings
renew independently; cold clients and evicted entries require a fresh challenge.
Explicit revocation invalidates the local proof under the same binding gate.
A failed refresh refuses the read rather than falling back to stale custody.
Queued callers share a one-second failure backoff; no automatic renewal retries
extend the request or the acknowledgement.

Initial material custody is bounded to twenty-four hours. Fresh adoption for an
active, currently validated binding renews separate bounded custody; active
bindings do not require daily manual hydration. Missing or expired material after
a long idle period requires explicit operator staging and actual validation.
Explicitly revoked material cannot be recovered under its old identity.

Frozen external cleanup HEADs likewise send only an exact current claim,
historical held delete reference and fresh nonce. Worker selects that retained
generation rather than the current head and refuses unresolved physical work.
Native rechecks the live claim, hold and snapshot after the authenticated reply.
SQL receipt commit additionally requires the live lease and current cleanup
authorization. A known physical result with stale SQL authority does not cause an
SDK mutation replay or settle pending or unknown physical work.

If an exact historical cleanup credential expired from Worker custody, an
operator may recover it only under its still-active SQL action and hold:

```sh
aos-hub-authority-bootstrap --database-url-file ./operator/sql.url stage-cleanup-credential \
  --action-id '<claimed-placement-action-id>' \
  --claim-token-file ./operator/cleanup-claim.token \
  --deployment-id '<paired-deployment-id>' \
  --worker-url 'https://paired-worker.test' \
  --storage-work-key-file ./operator/storage-work.key \
  --secret-version-manifest ./operator/provider-versions.json \
  --output ./operator/cleanup-credential-stage
```

Recovery neither extends the SQL claim lease nor grants deletion permission. The
current external frozen executor supports HEAD; metadata custody does not add a
new delete capability or qualify provider behavior.

## Existing SQL and least privilege

The helper attaches to an existing exact production schema. It creates no
database, runs no migration and changes no SQL rows. SQLite opens read-only and
does not change journal mode. PostgreSQL requires the package's `postgres`
feature, connection permission, schema usage and `SELECT` on these tables:

```sql
GRANT USAGE ON SCHEMA public TO operator_reader;
GRANT SELECT ON schema_version, hub_schema_identity,
  physical_storage_authorities, physical_storage_aliases,
  binding_storage_authority_revisions, storage_authority_attestations,
  storage_authority_admission_heads, storage_authority_admission_revisions,
  bindings, binding_credential_heads, binding_credential_revisions,
  binding_write_revisions, topology_operations, binding_write_state,
  binding_identity_reservations, topology_plans
  TO operator_reader;
```

Limit the login and network audience independently. The subsequent Native
`authority-control-sync` step writes its exact SQL acknowledgement and uses its
existing operator authority. It does not require widening the helper's reader
role.

Historical cleanup recovery additionally reads the exact existing claim and its
authorization dependencies. Grant these only to the separate cleanup reader:

```sql
GRANT SELECT ON oci_gc_placement_actions, oci_gc_candidates,
  oci_gc_placement_snapshots, oci_gc_candidate_repositories, oci_gc_runs,
  oci_gc_registry_locks, oci_registry_state, surface_placements,
  surface_placement_observations, oci_gc_credential_holds, oci_tags,
  oci_release_roots, oci_release_evidence, oci_leases, oci_upload_sessions,
  oci_publication_sessions, oci_publication_objects TO cleanup_reader;
```

That reader also needs the binding and schema tables above. No helper command
requires SQL mutation privileges, schema ownership or migration permission.
