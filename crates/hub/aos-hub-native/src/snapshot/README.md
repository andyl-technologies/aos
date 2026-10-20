# Inert database capture

`aos-hub snapshot capture-sqlite`, `capture-postgres` and `verify-capture`
expose audited SQL readers and encrypted database records on Linux. PostgreSQL
capture requires the `postgres` build feature. They capture
and verify current database rows and exact private originals, replaying retained
SQL constraints independently in a disposable private in-memory database. They do not
produce a complete portable Hub, import SQL, restore objects, or authorize
serving, pending jobs, guard namespace adoption or provider mutations.

## Existing explicit custody

Provision these inputs separately before running either operation:

- A dedicated raw 32-byte Ed25519 exporter seed, required only for capture.
- Independent raw 32-byte AES keys for metadata and private stream wrapping.
- A closed version-one external signer trust file, at most 64KiB.
- Optionally, at most 32 existing raw nonarchive keys to reject known key
  equality. Omission proves no separation from unknown source/runtime keys.

Credential files must be regular, root/effective-user-owned, have one hard
link and no group/other permissions. All path components are opened without
following links; ancestors must be owned by root/the effective user and not
writable by other users, with root-owned sticky traversal such as `/tmp`
permitted. The final credential parent must not be group/other writable.
The runtime loader's `$CREDENTIALS_DIRECTORY` group-read exception is not
accepted for archive credentials. Keys are not hex/base64/PEM text, stdin,
environment values, generated output or automatically selected runtime keys.

```json
{"version":1,"signers":[{"id":"offline-export","ed25519_public_key_hex":"<64 lowercase hex digits>"}]}
```

Trust is externally provisioned; the archive cannot nominate its own signer.
Capture proves that the supplied seed matches an external pin before source
or output admission. Verification authenticates the closed root before it
loads wrapping keys. Existing source ciphertext is preserved unchanged;
this process never initializes or loads the original Hub sealing key.

## Local workflow

The existing SQLite source must be in an owner-private directory. It is
anchored to an absolute literal path before SQLx opens it so a filename that
starts with `file:` cannot select another SQLite URI. Read-only opening
creates no source, performs no migration or journal-mode change, validates
current lineage/schema and holds one consistent transaction through audit
and enumeration. SQLite may coordinate ordinary reads with WAL shared memory.

```text
aos-hub snapshot capture-sqlite \
  --source-sqlite /private/hub/hub.db --output /private/archives/capture-1 \
  --signer-id offline-export --signing-seed-file /private/keys/export.seed \
  --signer-trust-file /private/keys/trust.json \
  --metadata-wrapping-id metadata-wrap --metadata-wrapping-key-file /private/keys/metadata.key \
  --private-wrapping-id private-wrap --private-wrapping-key-file /private/keys/private.key

aos-hub snapshot verify-capture --archive /private/archives/capture-1 \
  --signer-trust-file /private/keys/trust.json \
  --metadata-wrapping-id metadata-wrap --metadata-wrapping-key-file /private/keys/metadata.key \
  --private-wrapping-id private-wrap --private-wrapping-key-file /private/keys/private.key
```

Runtime `--root`, database URL/file, and nonlocal `--target` options are
rejected before credential loading or state initialization, including their
environment-backed values. No serving/indexing/storage configuration is
accepted by this command family. Clear runtime environment settings before
using offline commands. Help output hides the runtime database URL's
environment value; it never prints its embedded credential.

Capture requires an existing trusted output parent and a nonexistent final
name. It creates a random private 0700 sibling directory and only these
0600 files: `metadata.aosh`, `private.aosh`, `archive.json`. It closes and
syncs both completed encrypted streams, writes/syncs the signed root last,
then reads back and verifies actual paired records, EOFs and retained SQL
constraints in memory. Rollback and connection close precede publication. It syncs the
staging directory, checks that its retained descriptor and temporary name
still select the same inode before and after this sync, and publishes via
no-replace rename. The parent is synced after publication.

Before rename, failure/cancellation removes only known files through the
retained staging descriptor; cleanup never recursively traverses a path.
After successful rename the published directory is never removed. A parent
sync failure returns `snapshot directory published; durability was not
confirmed`, which means the final name exists but crash durability is
unconfirmed. Inspect that name before retrying; capture cannot overwrite it.
A stdout/report write failure can also occur after a completed publication.
Abrupt termination or a crash can leave an unpublished private staging
directory containing partial ciphertext. There is no automatic startup scan
or recursive cleanup; inspect private unpublished remnants separately.

Descriptor checks protect against other-user path substitution. The SQLite
opener and rename remain pathname operations; these checks do not defeat a
malicious same-owner replacement/ABA race. Source and archive custody must
remain trusted for the operation. No immutable/proc-fd SQLite mode is claimed.

## Bounds, cancellation and result scope

`--timeout-seconds` defaults to 3600 and admits 1–86400 seconds.
`--max-stream-plaintext-bytes` defaults to 1GiB and admits 1 byte–64GiB per
stream; codec-derived frame/ciphertext bounds are applied independently to
both streams. Source audit has a 300-second / one-million-progress-callback
ceiling; existing source paging/cell/row and typed-record hard limits remain.
Private scratch replay has separate explicit limits, admitted before I/O:

| Option | Default | Supported range |
| --- | --- | --- |
| `--max-scratch-database-bytes` | 64MiB | 4096 bytes–256MiB |
| `--max-scratch-retained-rows` | 1,000,000 | 1–10,000,000 |
| `--max-scratch-value-bytes` | 256MiB | 1 byte–1GiB |
| `--scratch-timeout-seconds` | 300 | 1–3600 seconds |
| `--max-scratch-progress-callbacks` | 100,000 | 1–1,000,000 |

Replay time is capped by the remaining operation deadline. The page limit
bounds the primary SQLite database, not all process heap. Stream, original
value, row, page and work limits are independent; a large stream allowance
does not guarantee replay will fit its database/value limits. Limit failure
refuses publication or a successful verification report.

SIGINT/SIGTERM and deadline cancellation are cooperative between reads,
writes, pages and SQLite progress observations. On observed cancellation,
verification signals the actual scratch worker and awaits rollback/close.
A blocked kernel I/O syscall can delay cancellation; there is no hard
wall-clock cancellation guarantee. Dropping an awaiting workflow signals
both input and SQL cancellation, but eventual worker cleanup may outlive it.
No plaintext scratch file is created, and no perfect memory erasure is claimed.

The sanitized v2 JSON report says `retained_sqlite_constraints` with signed
root profile `framing_only`. It proves paired grammar, exact private-cell
reconstruction/reclassification, current classifier/schema identity, all
admitted table markers/counts, authenticated framing END/EOF/root summaries and
independent retained SQL PK/UNIQUE/CHECK/FK/integrity/count checks under the
trusted compiled schema. `checked_retained_tables` is the independent replay
count; `synthetic_lineage_rows` reports two derived compiled-schema markers,
not exported historical originals. Omitted transient auth rows stay empty.
Source audit remains an authenticated exporter declaration. No private rows,
credentials, key bytes or input/output paths are printed. The signed root
profile is unchanged; this local result never upgrades its archive claims.

Application/object closure, original sealing-key custody, external credential
custody, live external journal continuity and activation/old-writer fencing
remain explicit pending recovery contracts. This report cannot be used as a
whole-Hub completeness receipt or an activation grant. The independently
qualified v1 records-only implementation and receipt remain historical proof.

## Inert PostgreSQL capture

A build with the `postgres` feature also exposes `capture-postgres`. Its source
connection comes only from `--source-database-url-file`: an existing private
UTF-8 file, at most 16KiB, containing an explicit PostgreSQL URL with user,
host and database. Archive custody rules also apply to that file. The URL is
never written into the archive or report. There is no environment or runtime
connection fallback and no source initializer or migration.

```text
aos-hub snapshot capture-postgres \
  --source-database-url-file /private/source/postgres.url \
  --output /private/archives/postgres-capture-1 \
  --signer-id offline-export --signing-seed-file /private/keys/export.seed \
  --signer-trust-file /private/keys/trust.json \
  --metadata-wrapping-id metadata-wrap --metadata-wrapping-key-file /private/keys/metadata.key \
  --private-wrapping-id private-wrap --private-wrapping-key-file /private/keys/private.key
```

This first PostgreSQL source supports only the exact current generation-eight
schema, UTF-8 server/client text encoding and admitted PostgreSQL 18 catalogue
semantics. Other encodings are refused before length-first values can expand
through conversion. The tested source engine
is the AOS-built PostgreSQL 18.6. Other major versions and altered/unknown
catalogue objects fail closed. Admission compares normalized logical types,
defaults, constraints and indexes; database names, roles, OIDs and physical
constraint/index names are excluded. Default collation implementation details
are not portability identities. The compiled semantic catalogue commitment is
regenerated from production migrations in the actual PostgreSQL source test.

One dedicated `REPEATABLE READ READ ONLY` transaction spans catalogue admission,
compiled CHECK/FK data checks, all table counts and row enumeration. The reader
holds `ACCESS SHARE` on selected tables: ordinary writes and VACUUM can proceed,
but heap rewrite/drop cannot invalidate the source. Internal `ctid` locators
order only this held snapshot; they are never exported or used as logical IDs.
This physical-locator dependence is PostgreSQL-specific and establishes no
cross-engine row-order or ciphertext equality. Declared IDs and exact original
cell values remain unchanged. Sequence definitions are admitted, but PostgreSQL's
non-MVCC sequence allocation state is not exported. Target allocation floors
and deleted identity reuse require the later explicit import contract; this
capture cannot grant that authority from existing row maxima.

Catalogue admission bounds facts to 16,384, each detail to 128KiB and total
detail bytes to 16MiB before client allocation. Pages admit at most 256 rows,
1MiB per cell and 8MiB value payload; cell lengths are read before values.
The complete source transaction has a 300-second ceiling, individual SQL
statements at most 30 seconds, and lock waits at most five seconds, clipped by
remaining operation time. Exceeding a bound refuses a completed capture.

The encrypted record profile is `database_capture/v2`; immutable SQLite
`database_capture/v1` and historical generation-three through eight verification
remain unchanged. Version two explicitly identifies PostgreSQL/read-only
repeatable-read admission and its semantic catalogue commitment. It declares
compiled constraint/count checks, **not** a SQLite-style physical integrity
check. `verify-capture` independently reconstructs these paired encrypted
records and replays retained constraints in private SQLite scratch memory.
Reports add `source_engine: "postgresql"`; their signed root is still
`framing_only`, and all pending recovery requirements remain present.

### Private data and credential coverage

This is a deliberate inert SQL capture, not a normal complete portable Hub
artifact. The existing classifier retains encrypted private originals including
Hub password/token/invitation hashes, invitation/IdP ciphertexts, private plans,
retained operation/session receipts and SQL sealed signing-key cells such as
`draft_signing_key`. Both streams are encrypted; the metadata stream names and
commits private dependencies instead of exposing their original contents.
Authentication ceremony/session tables classified as transient are omitted.
Unknown settings and unclassified structured originals refuse capture.

Provider material and runtime sealing/issuer/guard/exporter private keys live
outside the source SQL catalogue and are not collected. SQL secret-version
references are original source references, never target credentials or renewed
validation. Existing sealed bytes are preserved without loading their sealing
key. A future complete portability artifact must explicitly separate these key
and authorization dependencies, close the referenced object inventory, perform
storage-local transfer and reconcile current remote journals before any inert
import or fenced activation. This command performs none of those later steps.

## Authenticated object requirements

`derive-object-requirements` projects a verified generation-eight SQLite or
PostgreSQL capture into a separate encrypted requirements artifact.
`verify-object-requirements` requires that artifact and the exact original
capture. Both commands independently replay the retained SQL constraints and
binding lifetime/Direct completion provenance checks. Historical generation-three
through eight capture verification stays unchanged; requirements derivation
admits only the exact generation-eight schema and column coverage contract.

```text
aos-hub snapshot derive-object-requirements \
  --archive /private/archives/capture-1 --output /private/archives/requirements-1 \
  --signer-id offline-export --signing-seed-file /private/keys/export.seed \
  --signer-trust-file /private/keys/trust.json \
  --metadata-wrapping-id metadata-wrap --metadata-wrapping-key-file /private/keys/metadata.key \
  --private-wrapping-id private-wrap --private-wrapping-key-file /private/keys/private.key

aos-hub snapshot verify-object-requirements \
  --archive /private/archives/capture-1 --requirements /private/archives/requirements-1 \
  --signer-trust-file /private/keys/trust.json \
  --metadata-wrapping-id metadata-wrap --metadata-wrapping-key-file /private/keys/metadata.key \
  --private-wrapping-id private-wrap --private-wrapping-key-file /private/keys/private.key
```

The literal coverage contract accounts for every column in all 279 current
tables. Selected rows retain ordered scalar references, SQL IDs, paths, hashes,
sizes, states, versions and authority coordinates in the private stream. Fixed
families distinguish catalogue copies, cache/store roots, OCI, registry and image
roots, authority dependencies, retained mutations, operations and opaque
application dependencies. These are source references to investigate, not a
resolved physical object inventory. Secret-classified cells are excluded.
Private structured originals contribute domain-, table-, column- and type-bound
SHA-256 digests; their plaintext is not duplicated into requirements. Those
digests explicitly require later typed application/graph resolution. Original
provider secret-version references remain source references; they do not admit
target credentials, validation or provider work.

The inner format is `aos.hub.object-requirements/v1`. Both encrypted streams bind
the SHA-256 of the exact source `archive.json` bytes, source schema/classifier and
literal coverage commitments. The private stream carries source ordinals,
families and canonical projected cells. Verification regenerates every expected
record during private replay and compares canonical bytes; it refuses another
capture, changed references, incomplete/trailing records or changed coverage.
Framing signatures use the explicit archive signer, never a runtime qualification
or provider evidence signer. The signed outer root remains `framing_only`.

Projection retains one row at a time, with a one-MiB encoded-record bound applied
before cloning selected values. `--max-projected-rows` defaults to one million
and admits 1–10,000,000; total retained source rows are capped at ten million.
Existing stream, scratch database/value/work and operation limits also apply.
Provisional rows enter only private encrypted staging. Full replay and a second
independent exact-source readback must finish before the existing no-replace
publication protocol runs. Cancellation and post-publication durability outcomes
follow the capture rules above. Reports contain counts and the scope
`retained_sql_and_incomplete_object_requirements`, without source values or paths.

The artifact explicitly leaves signed graph closure, physical content and
incarnations, external journal continuity, credential/key custody, old-writer
fencing and target import/activation pending. Neither command contacts storage,
loads provider material or source sealing keys, copies object bodies, imports
SQL or activates a target. A complete portability workflow still needs Worker
HubDb logical capture, typed signed store/Git/cache/OCI/image graph closure,
guarded storage-local transfer, inert target rebinding and explicit fencing and
readback. No whole-Hub completeness receipt is produced by this slice.
