# Offline SQLite database capture

`aos-hub snapshot capture-sqlite` and `verify-capture` expose the audited
SQLite reader and encrypted database record protocol on Linux. They capture
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
267 table markers/counts, authenticated framing END/EOF/root summaries and
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
