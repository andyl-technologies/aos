# Schema registry

Every durable record, process-protocol message, CLI output contract, and
Crucible-owned QEMU migration section that Crucible versions independently has
exactly one row in
[`schema-registry.tsv`](../../../../crates/crucible/crucible-test-support/data/schema-registry.tsv).
The file is owned by `crucible-test-support` and exposed as
`crucible_test_support::schema_registry` (`SCHEMA_REGISTRY`,
`schema_registry_entries`, `find_schema`). Adding or changing a format means
updating its row.

## Format

The file is tab separated. Empty lines and lines starting with `#` are
comments (section headings group related rows); every other line has exactly
five fields:

```text
# schema-name	version	owner	object-kind	compatibility-gates
crucible.content-envelope	1	crucible-store::content_envelope	envelope	gate:content-address,gate:campaign-store-equivalence
```

| Column | Meaning |
| --- | --- |
| `schema-name` | Stable dotted schema identity. It names a logical format; the on-wire magic may use a shorter or older spelling (for example `crucible.execution.schedule` is encoded with `crucible.schedule.v4\0`). |
| `version` | The current positive version. Decoders admit only this version. |
| `owner` | The `crate::module` that defines the encoding, or `qemu-patch::...` for formats defined by the patched QEMU. |
| `object-kind` | A classification such as `envelope`, `campaign-fact`, `component-message`, `process-protocol-message`, `device-state`, `cli-output`, `physical-record`, or `deployment-config`. |
| `compatibility-gates` | Comma-separated canonical gate names (from `crucible_test_support::campaign_gates`) that must pass when the format changes. |

## How it is checked

- The `schema_registry` module parses every row and its tests reject
  malformed rows, non-positive versions, empty owners or kinds, and duplicate
  names. The gate traceability test additionally requires a module-path owner
  and requires every listed gate to exist in the campaign gate catalog.
- Owning crates compare their compiled schema constants against their rows in
  their own tests. For example `crucible-campaign` checks its campaign record
  versions, `crucible-qemu-host` checks its QMP checkpoint, fingerprint
  projection, and hot-fork payload versions, `crucible-daemon` checks its
  run-lock record, and `crucible-qemu-protocol` checks its process-protocol
  versions.
- Source-coverage tests compare registered rows with version constants found in
  selected engine sources, test scripts, release contracts, and the QEMU patch.

## Scope

A row exists for each independently versioned contract:

- campaign content records, component requests and responses, and retained
  execution records;
- content-store envelope, refs, graph configuration, physical objects,
  inventory, quota, keys, packs, and transfer records;
- daemon component frames, operational journals, assignment-ledger records,
  exact checkpoint records, and replay evidence;
- CLI input schemas, deployment configuration, bundle exports, and
  machine-readable reports;
- control frames, guest selectable and doorbell messages, shared-memory regions
  and fault payloads, and the debug gateway;
- campaign execution payloads, exact continuation and device snapshots, QMP
  commands, and hot-fork responses;
- the reproduction artifact shared by the CLI and test support;
- QEMU-side block, fault VMState, RAM checkpoint and restore, and hot-fork
  protocol versions, and every Crucible-owned QEMU migration section.

Strings that look like versions but do not create an independent format are
deliberately not rows:

- hash-domain strings, digest separators, and semantic-ID prefixes (for
  example `crucible.campaign.finding-signature.v1`), whose containing record
  owns compatibility;
- nested canonical fields and enum variants, which share their container's
  version (the hot-fork template resource stage is an exception because it
  carries and validates its own version);
- QEMU per-device fingerprint-projection entries, which are authenticated by the
  registered projection manifest;
- `crucible.test.*` and inline test fixture strings;
- standard 9P, virtio, QMP, and QEMU migration versions owned by their upstream
  protocols (the registry owns only Crucible-added migration sections);
- text projections generated from decoded binary records, and execution-model
  subcodecs nested inside registered scenario, reproduction, schedule, or
  checkpoint payloads.
