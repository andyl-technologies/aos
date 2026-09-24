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
| `crucible-cli` campaign, store-repair, and verify-serve modules | Input schemas, durable deployment configuration, bundle exports, and versioned machine-readable reports. The store-repair placement report uses `crucible.cli.store-repair.v1`. The general campaign-object report uses the `crucible.cli.campaign-object.v1` tag; its choice-object variant uses the `v2` tag. |
| `crucible-protocol`, `crucible-shmem`, `crucible-api` | Control frames, selectable and guest doorbell messages, shared-memory region and fault payloads, and the debug gateway. |
| `crucible`, `crucible-device`, `crucible-qemu` | Campaign execution payloads, exact continuation and device snapshots, QMP commands, and hot-fork responses. |
| `pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch` | QEMU-side block, fault VMState, RAM checkpoint/restore, and hot-fork protocol versions; matching host-side shared-memory and QMP records are listed above. |

The untagged-writer review found these independently versioned contracts:

| Format | Source evidence | Registry entry |
| --- | --- | --- |
| Durable production lifecycle state | `crucible-api::vm_lifecycle::quantum_loop::lifecycle::persistence` writes `run-state.json` with `PRODUCTION_RUN_STATE_VERSION = 2`; `recovery` checks that version before decoding. | `crucible.production-run-state` |
| Production network adapter continuation | `crucible-api::vm_lifecycle::network_faults` serializes opaque JSON `adapter_state` with `NETWORK_ADAPTER_CHECKPOINT_VERSION = 9` and validates that version on restore. | `crucible.production-network-adapter-checkpoint` |
| Pending network output | `crucible::backend::io::network_checkpoint` independently encodes and decodes canonical CBOR for each routed frame, with `BACKEND_NETWORK_OUTPUT_VERSION = 1`. | `crucible.execution.backend-network-output` |
| Scheduler event-log segment | `crucible::scheduler::event_codec` writes a binary segment with `EVENT_LOG_SEGMENT_BINARY_VERSION = 2`; the exact checkpoint store retains and authenticates segment bytes for resume. | `crucible.execution.event-log-segment` |
| Scenario selectable component and fault-signal plan | `crucible::model::scenario_selectables` uses an independent binary magic and version 1; `crucible::model::fault_signal::wire` decodes separately versioned JSON plan bytes at version 2. | `crucible.execution.scenario-selectable-component`, `crucible.execution.fault-signal-plan` |
| Signal evaluator artifacts | `crucible::model::fault_signal::{sampler,spatial,trace}` independently encode and decode the inverse-CDF table, spatial artifact, trace manifest, and trace chunk. Each codec is version 1. | `crucible.execution.signal-*` rows |
| Fault adapter continuation | `crucible::model::fault_signal::adapter_runtime` independently encodes and decodes opaque JSON checkpoint bytes, with `ADAPTER_CHECKPOINT_VERSION = 2`. | `crucible.execution.fault-adapter-checkpoint` |
| QEMU fuzz corpus index and descriptor | `crucible-cli::cli::run_save::qemu_live::fuzz::corpus` separately reads and writes `live-fuzz-corpus.json` and immutable descriptor objects, each with `CORPUS_SCHEMA = 1`. | `crucible.cli.live-fuzz-corpus-index`, `crucible.cli.live-fuzz-corpus-descriptor` |
| Guest campaign runtime configuration | `modules/services/crucible-campaign.nix` emits `/etc/crucible/campaign-runtime.env` with `aos.crucible.campaign-runtime.v1`; the phase 1 and phase 9 license gates consume this file and its configuration identity. | `aos.crucible.campaign-runtime` |
| Control-plane RPC | `crucible-api::rpc_abi` encodes the `crucible.rpc/<message-name>` wire vocabulary at `RPC_PROTOCOL_MAJOR = 6`; the client wire model uses that encoder. | `crucible.api.rpc` |
| Crucible-owned QEMU migration sections | The QEMU patch declares 20 production `VMStateDescription` sections or subsections with distinct `.name` and `.version_id` values. QEMU's migration loader matches these versions inside the opaque VMState artifact. | `crucible.qemu.vmstate.*` rows |

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
  upstream protocols. The registry owns Crucible-added QEMU migration
  sections; fields within each section share its version.
- The lifecycle manifest and journal are fields of `run-state.json`, and the
  campaign runtime identity is a hash of the emitted configuration. Neither
  is a separately decoded format.
- `crucible.scheduler.event-log.segment-text.v2` is a text projection generated
  from a decoded binary event-log segment; it is not independently stored or
  decoded for resume.
- Failure-triage replay-evidence payload version 2 belongs to the registered
  `crucible.campaign.finding-triage-replay-evidence` object version 2.
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

The current `crucible.cli.*.vN` source-tag review found the store-repair report
missing from the registry; its row is now present. The other unmatched CLI tags
are `crucible.cli.test.*` fixtures and the registered choice-object alias noted
above. This inventory does not prove exhaustive source closure. Generic
`write_all`, serde, QMP, and Nix-generated guest output paths have not all been
matched to registry rows or classified as nested fields. Three newer
simulation-only QEMU VMState subsections also await review after their QEMU
patch is integrated. T-CAM-0.3 remains open.
The source declarations remain authoritative. When a version changes, update
its row and compatibility gate together with the codec and golden vectors.
