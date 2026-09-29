# Offline SQLite database capture

`aos-hub snapshot capture-sqlite` and `verify-capture` expose the audited
SQLite reader and encrypted database record protocol on Linux. They capture
and verify current database rows and exact private originals. They do not
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
then reads back and verifies actual paired records and EOFs. It syncs the
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
SIGINT/SIGTERM and deadline cancellation are cooperative between reads,
writes, pages and record callbacks. A blocked kernel I/O syscall can delay
cancellation; there is no hard wall-clock cancellation guarantee. Dropping
an awaiting workflow requests cancellation for its owned blocking verifier.

The sanitized JSON report says `records_and_reconstruction` with signed
root profile `framing_only`. It proves paired grammar, exact private-cell
reconstruction/reclassification, current classifier/schema identity, all
267 table markers/counts and authenticated framing END/EOF/root summaries.
Source integrity/CHECK/FK/count results are authenticated exporter
declarations, not independently repeated by `verify-capture`. No private
rows, credentials, key bytes or input/output paths are printed.

Uniqueness/global SQL replay constraints, application/object closure,
original sealing-key custody, external credential custody, live external
journal continuity and activation/old-writer fencing remain explicit
pending recovery contracts. This report cannot be used as a whole-Hub
completeness receipt or an activation grant.
