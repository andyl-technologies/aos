# Schema inventory audit

The [registry](schema-registry.tsv) assigns one owner and current version to
independently encoded campaign formats and the Crucible/QEMU process boundary.
This inventory compares declarations and encode/decode paths in `crates/` with
the Crucible QEMU patch. A registry row names a logical format;
its on-wire magic may use a shorter or older spelling. For example,
`crucible.execution.schedule` is encoded with `crucible.schedule.v3\0`, and
`crucible.qemu.vm-snapshot` uses `crucible.qemu-vm-snapshot.v4\0`.

| Source family | Formats assigned in the registry |
| --- | --- |
| `crucible-campaign` object, choice, exploration, observation, finding, archive, authority, planner, execution, and service modules | Content records and independently versioned component requests and responses. The request-attempts page pair is version 2. |
| `crucible-cas` content envelope, content-store, and `cas::campaign_codec` modules | Envelope, mutable refs, graph configuration, physical objects, inventory, quota, key, pack, transfer, corpus, coverage, findings, manifest, and frontier records. The pre-RFC campaign CAS records are still current and have their own rows. |
| `crucible-daemon` campaign, planner, executor, checkpoint, and loopback modules | Component frames, operational journals, campaign state identity, exact checkpoint records, and replay evidence. The campaign loopback frame is version 21. |
| `crucible-cli` campaign and verify-serve modules | Input schemas, durable deployment configuration, bundle exports, and versioned machine-readable reports. The general campaign-object report uses the `crucible.cli.campaign-object.v1` tag; its choice-object variant uses the `v2` tag. |
| `crucible-protocol`, `crucible-shmem`, `crucible-api` | Control frames, selectable and guest doorbell messages, shared-memory region and fault payloads, and the debug gateway. |
| `crucible`, `crucible-device`, `crucible-qemu` | Campaign execution payloads, exact continuation and device snapshots, QMP commands, and hot-fork responses. |
| `pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch` | QEMU-side block, fault VMState, RAM checkpoint/restore, and hot-fork protocol versions; matching host-side shared-memory and QMP records are listed above. |

The following version-looking strings are excluded as independent registry
rows. They do not create an additional wire or durable schema:

- `CampaignHash::derive` domains, `ContentHash` domains, digest separators,
  and semantic-ID prefixes identify what is hashed. They are not decoded as
  separate records. Their containing record or message owns compatibility.
  Examples are `crucible.campaign.finding-signature.v1` in
  `crucible-campaign::finding` and
  `crucible.qemu.device-projection-schema.v3` in
  `crucible-qemu::qmp::fingerprint_projection`.
- Nested canonical fields and enum variants share the containing format's
  version. Examples include SMC generation fields inside campaign facts and
  the QEMU hot-fork barrier's resource and worker subrecords.
- `crucible.test.*` and inline test fixture strings are local test inputs,
  never published format tags.
- Standard 9P, virtio, QMP, and QEMU migration versions are owned by their
  upstream protocols. The registry owns only Crucible additions to those
  transports.
- `crucible-cas::cas::campaign_codec` also emits
  `crucible.campaign-replay-input.v1` as replay-hash input; it is never stored
  as a standalone record. Its provenance and lineage material likewise feeds
  content identities. The latter uses `crucible.campaign.lineage.v1` as a
  hash-domain prefix, while the registry's `crucible.campaign.lineage` row
  names the separately encoded RFC-0020 object.
- The pre-campaign execution-model subcodecs for world, plan, properties,
  predicate, action, seed, and scheduler state are nested in the registered
  scenario, reproduction, schedule, or checkpoint payloads. Their source tags
  live in `crucible::model::toml`; they do not create a new RFC-0020 contract.

This inventory does not prove exhaustive source closure: a full review of all
serialization and output paths is still needed before T-CAM-0.3 can close.
The source declarations remain authoritative. When a version changes, update
its row and compatibility gate together with the codec and golden vectors.
