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
| `crucible-harness` | The canonical reproduction artifact shared with the CLI; its other version tags name hash domains or fixture evidence. |
| `pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch` | QEMU-side block, fault VMState, RAM checkpoint/restore, and hot-fork protocol versions; matching host-side shared-memory and QMP records are listed above. |

The untagged-writer review found these independently versioned contracts:

| Format | Source evidence | Registry entry |
| --- | --- | --- |
| Durable production lifecycle state | `crucible-api::vm_lifecycle::quantum_loop::lifecycle::persistence` writes `run-state.json` with `PRODUCTION_RUN_STATE_VERSION = 2`; `recovery` checks that version before decoding. | `crucible.production-run-state` |
| Production run ownership lock | `crucible-api::vm_lifecycle` writes and rereads `active-run.lock` across process lifetimes. Its record requires version 1, and the reader rejects unversioned or unsupported records. | `crucible.production-run-lock` |
| Production network adapter continuation | `crucible-api::vm_lifecycle::network_faults` serializes opaque JSON `adapter_state` with `NETWORK_ADAPTER_CHECKPOINT_VERSION = 9` and validates that version on restore. | `crucible.production-network-adapter-checkpoint` |
| Pending network output | `crucible::backend::io::network_checkpoint` independently encodes and decodes canonical CBOR for each routed frame, with `BACKEND_NETWORK_OUTPUT_VERSION = 1`. | `crucible.execution.backend-network-output` |
| Scheduler event-log segment | `crucible::scheduler::event_codec` writes a binary segment with `EVENT_LOG_SEGMENT_BINARY_VERSION = 2`; the exact checkpoint store retains and authenticates segment bytes for resume. | `crucible.execution.event-log-segment` |
| Scheduler-owned nested continuations | `crucible::device_subnode::checkpoint` encodes and checks `crucible.device-scheduling-subnode.v1`; `crucible::scheduler::runtime_state::network_checkpoint` independently encodes and checks `crucible.scheduler-network.v1`. Both are decoded from the registered single-scheduler continuation. | `crucible.execution.device-scheduling-subnode`, `crucible.execution.scheduler-network` |
| Event-graph continuation | `crucible::trigger::event_graph` encodes and checks `crucible.event-graph-state.v1`; production checkpoint restore reads it as a separate object. | `crucible.execution.event-graph-state` |
| Scenario selectable component and fault-signal plan | `crucible::model::scenario_selectables` uses an independent binary magic and version 1; `crucible::model::fault_signal::wire` decodes separately versioned JSON plan bytes at version 2. | `crucible.execution.scenario-selectable-component`, `crucible.execution.fault-signal-plan` |
| Signal evaluator artifacts | `crucible::model::fault_signal::{sampler,spatial,trace}` independently encode and decode the inverse-CDF table, spatial artifact, trace manifest, and trace chunk. Each codec is version 1. | `crucible.execution.signal-*` rows |
| Fault adapter continuation | `crucible::model::fault_signal::adapter_runtime` independently encodes and decodes opaque JSON checkpoint bytes, with `ADAPTER_CHECKPOINT_VERSION = 2`. | `crucible.execution.fault-adapter-checkpoint` |
| Fault runtime and resolved trace | `crucible::model::fault_signal::runtime` validates semantic checkpoint version 4 on CBOR restore and independently checks the version-1 magic of the standalone resolved-effect trace. | `crucible.execution.fault-runtime-checkpoint`, `crucible.execution.resolved-effect-trace` |
| Native failure-triage replay evidence | `crucible::model::failure::replay_evidence` checks its version-2 binary magic; the daemon independently checks payload schema 2 inside the campaign triage record before decoding. | `crucible.execution.failure-triage-replay-evidence` |
| QEMU fuzz corpus index and descriptor | `crucible-cli::cli::run_save::qemu_live::fuzz::corpus` separately reads and writes `live-fuzz-corpus.json` and immutable descriptor objects, each with `CORPUS_SCHEMA = 1`. | `crucible.cli.live-fuzz-corpus-index`, `crucible.cli.live-fuzz-corpus-descriptor` |
| Guest campaign runtime configuration | `modules/services/crucible-campaign.nix` emits `/etc/crucible/campaign-runtime.env` with `aos.crucible.campaign-runtime.v1`; the phase 1 and phase 9 license gates consume this file and its configuration identity. | `aos.crucible.campaign-runtime` |
| Control-plane RPC | `crucible-api::rpc_abi` encodes the `crucible.rpc/<message-name>` wire vocabulary at `RPC_PROTOCOL_MAJOR = 6`; the client wire model uses that encoder. | `crucible.api.rpc` |
| Crucible-owned QEMU migration sections | The QEMU patch declares 23 production `VMStateDescription` sections or subsections with distinct `.name` and `.version_id` values. The integrated device-continuation change adds `serial/crucible-timing`, `virtio-blk/crucible-backend-wce`, and `virtio/crucible-start-on-kick`, each at version 1. QEMU's migration loader matches these versions inside the opaque VMState artifact. | `crucible.qemu.vmstate.*` rows |
| Hot-fork template resource stage | The patched QEMU template reporter emits `CrucibleHotForkTemplateResourceStageState.schema-version = 13`; `crucible-qemu::qmp::hot_fork::template::parse` independently checks that nested version while decoding the version-29 template response. | `crucible.qemu.hot-fork.template-resource-stage` |
| Guest debug transcript | `crucible-cli::cli::triage_debug::debug_terminal` writes a standalone `CRGT` version-1 recording when `--record-transcript` is selected. Its record bodies use the separately registered guest-introspection frame codec. | `crucible.cli.guest-transcript` |
| CLI reproduction and live-QEMU replay artifacts | `crucible-cli::cli::artifact` encodes and strictly decodes the outer version-4 reproduction artifact; its `live_qemu` component separately encodes and decodes a version-4 replay contract. | `crucible.reproduction-artifact`, `crucible.live-qemu-replay-contract` |
| CLI savepoint and lifecycle bundle | `planning::invocations::savepoint` parses exported version-6 handles; `artifact_capture` encodes and decodes `CLAB` version-1 lifecycle object bundles. | `crucible.savepoint-handle`, `crucible.lifecycle-artifact-bundle` |
| Authored search inputs | `planning::invocations` checks the versioned scenario-family, schedule-named-truths, and retained-evidence TOML schemas after independent parses. | `crucible.scenario-family`, `crucible.search-schedule-named-truths`, `crucible.search-retained-evidence` |
| Authored campaign schedule | `crucible-cli::cli::campaign::schedule` strictly parses version-2 TOML and rejects the prior retired-count coordinate; preemptions use exact `at_tick`. | `crucible.cli.campaign-schedule-authoring` |
| Portable finding bundle | `campaign::finding_bundle` writes and parses its version-2 manifest; its separately stored version-4 findings ledger is read by the campaign triage path, which now checks both schema and ledger kind. | `crucible.campaign.finding-bundle`, `crucible.failure-triage.findings-ledger` |
| Failure-cluster reports | `crucible::model::failure::reporting` emits a version-1 `cluster-report` JSON object for each report and a separate version-1 `cluster-report-set` JSON object for the collection; `crucible-cli::cli::triage_debug::ledger_format` writes the rendered report to `triage-report.json` or `triage-report.jsonl`. | `crucible.failure-triage.cluster-report`, `crucible.failure-triage.cluster-report-set` |
| DAG-store checkpoint material | `crucible::model::store_artifacts` writes scenario definition, checkpoint node, schedule delta, and CoW delta reference bytes with separate `crucible.dag-store.*.vN` headers. The temporal graph persists these bytes by content hash. | Four `crucible.dag-store.*` rows |
| External formal trace | `crucible::trigger::evidence` writes a standalone `format=crucible.external-formal-trace.v1` export. | `crucible.external-formal-trace` |
| Signal evaluator checkpoint | `crucible::model::fault_signal::evaluator` encodes and strictly decodes `CREVAL01` version 1 inside the fault-runtime checkpoint. Its own version check makes it an independent format. | `crucible.execution.signal-evaluator-checkpoint` |
| Native host and cross-host evidence | `_e2e-determinism-native-runner.sh` strictly checks three input attestation/sign-off schemas and writes four distinct native profile, gate, host, and cross-host evidence schemas. | Seven `crucible.e2e.*` rows |
| Phase 9 acceptance evidence | `_phase9-campaign-release-acceptance.sh` strictly checks manual evidence and sign-off input schemas and writes a release-acceptance record; `_campaign-manual-evidence-spec.nix` emits a versioned evidence specification. | Four `aos.crucible.campaign-*` evidence rows |
| Operator contract inputs | The four RFC operator/dogfood TOML contracts and three test-side release, E2E, and gate-matrix TOML contracts each have a schema tag checked by a dedicated gate. They are retained review inputs, not disposable test fixtures. | Seven `aos.crucible.*-contract` or inventory rows |

The following version-looking strings are excluded as independent registry
rows. They do not create an additional wire or durable schema:

- `CampaignHash::derive` domains, `ContentHash` domains, digest separators,
  and semantic-ID prefixes identify what is hashed. They are not decoded as
  separate records. Their containing record or message owns compatibility.
  Examples are `crucible.campaign.finding-signature.v1` in
  `crucible-campaign::finding` and
  `crucible.qemu.device-projection-schema.v3` in
  `crucible-qemu::qmp::fingerprint_projection`.
- `crucible.scheduler.event-log.entry.v2` and
  `crucible.session.fork-handle.v1` identify hash material, not separately
  decoded records. `crucible.model.world-fault-topology.v1` is a hash domain
  for JSON carried by the versioned world record. Device snapshot codecs in
  `crucible-device` already have their own registry rows.
- Nested canonical fields and enum variants share the containing format's
  version. Examples include SMC generation fields inside campaign facts and
  the QEMU hot-fork barrier's worker subrecords. The template resource-stage
  record is an exception because it carries and validates its own version.
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

The `crucible-api/src` production `write_all` and `serde_json::{to_*,from_*}`
paths were reviewed as a bounded source family, excluding test fixtures:

| Source paths | Classification |
| --- | --- |
| `vm_lifecycle.rs` run-lock encode/write/decode | Independent durable ownership record, now registered as `crucible.production-run-lock`. |
| `vm_lifecycle/quantum_loop/lifecycle/persistence{,/recovery}.rs` JSON measurement, write, and decode | One `run-state.json` record, registered as `crucible.production-run-state`; the counting writer and staged write do not create additional formats. |
| `vm_lifecycle/network_faults.rs` adapter-state encode/decode | Nested opaque checkpoint body independently decoded at version 9, registered as `crucible.production-network-adapter-checkpoint`. |
| `vm_lifecycle/network_faults{,/boundary,/evidence}.rs` remaining JSON encodes | Digest and evidence material only: observation lists, campaign records, control events, mapping outputs, and queue state feed hashes or the containing adapter checkpoint. They are not separately decoded records. |
| `vm_lifecycle/checkpoint_store/{storage,sparse}.rs` and `storage/{file_io,copy}.rs` writes | Authenticated copies or sparse reconstruction of existing checkpoint artifacts and content-addressed bytes. Their formats are owned by the corresponding checkpoint and QEMU VM-state registry rows; copying does not introduce a new decoder. |
| `debug_gateway.rs` frame write and `debug_relay.rs` stream write | The former writes `crucible.debug-gateway.frame` encoded by `crucible-protocol`; the latter forwards opaque debugger stream bytes without a Crucible schema. |

This review is limited to those `crucible-api/src` production calls and the
`modules/services/crucible-campaign.nix` outputs. That Nix module emits the
registered `aos.crucible.campaign-runtime` file and the registered
`crucible.campaign-local-policy` TOML file parsed by
`crucible-daemon::campaign_policy`; its systemd unit is service-manager
configuration rather than a Crucible wire format.

The production QMP request and response family was reviewed from the closed
`crucible-qemu::qmp::command::QmpCommand` vocabulary through its typed response
parsers and the patched QEMU QAPI declarations. The patch declares 26
Crucible-named commands. The source check requires each command to remain in
one of these groups:

| QMP path | Classification |
| --- | --- |
| Sixteen hot-fork commands, five checkpoint commands, and the fingerprint-projection query | Their explicit payload versions are registered under `crucible.qemu.hot-fork.*`, `crucible.qemu.checkpoint-qmp`, and `crucible.qemu.fingerprint-projection-manifest`. Nested hot-fork barrier and block-source-proof records retain their existing independent rows. The template resource-stage response now has its own version-13 row. |
| `crucible-complete-terminal-lifecycle`, `query-crucible-selectable-reply-boundary`, `crucible-complete-selectable-reply`, `x-crucible-adopt-launch-fdsets` | Patched QAPI commands with no independent `schema-version` field. Their arguments and replies are defined by the pinned QEMU QAPI release. The selectable-reply pair has no host `QmpCommand` caller; the terminal and fdset commands use the closed host vocabulary. |
| QMP greeting, event/error envelope, capability negotiation, status/jobs, snapshot save/delete, stop/continue, descriptor transfer, and quit | Standard QEMU QMP contracts. `crucible-qemu::shutdown` also writes the standard `quit` request directly. These have no additional Crucible payload version. |

The QEMU patch's internal plugin child plan/status, child QMP and console
reinitializers, and selectable-reply status are separately registered under
their `qemu-patch::*` owners where they cross a versioned process boundary.

The production `crucible-daemon/src` `write_all`, CBOR, and TOML decode paths
were reviewed as one bounded source family. `planner_process` writes the
registered `crucible.planner.process-frame`. `campaign_gc` manifests and
journal, `exact_pin_retention`, `hot_checkpoint_retention`,
`campaign_debug_inventory`, `campaign_transfer`, and `campaign_bootstrap`
write their corresponding registered records. `crucible_measurement::evidence`
encodes the registered measurement replay evidence. `campaign_policy` reads
the registered local-policy TOML. `anchored_fs` and transfer journal I/O are
generic persistence helpers for those records; `campaign_finding_handoff`
writes authenticated guest-asset bytes without a new wrapper schema.

The Nix-generated Crucible guest-input review covered
`modules/services/crucible-campaign.nix`, the packaged-executor TOML emitted
by the phase 4/5 Crucible tests, and the `_envoy-network-guest.nix` root-image
builder. The module's two versioned outputs and the packaged-executor TOML
have existing registry rows. The Envoy builder copies an init script, traffic
script, nginx configuration, and standard account files into an ext4 image;
it does not define a separate Crucible serialization contract. The phase 6
hot-fork-readiness JSON files are QMP test requests and responses, covered by
the QMP family above, while the other phase gate `$out/result` files are test
status artifacts rather than guest inputs.

The remaining Nix-generated Crucible guest builders in `tests/crucible`
compile standard ELF or Linux initramfs images, copy executables and scripts
into root images, or emit phase-gate evidence. Their raw network probe strings
such as `crucible-network-probe-v1` are test fixture payloads, not standalone
decoded records. The hand-coded guest doorbell frame in
`phase5-cli-fuzz-guest.nix` uses the registered white-box doorbell protocol.
`_nginx-curl-http-200-guest.nix` adds service configuration and init scripts,
not a Crucible schema. `crucible.qemu.trace-fingerprint.v7` is emitted by the
GPL trace plugin for phase 0/2 test evidence; the Nix gates consume its JSONL
output, but it is not a production guest input or persisted campaign format.

The current `crucible.cli.*.vN` source-tag review found the store-repair report
missing from the registry; its row is now present. The other unmatched CLI tags
are `crucible.cli.test.*` fixtures and the registered choice-object alias noted
above. The CLI guest transcript was found through its generic byte writer,
not its source tag. The `crucible.signal-mutation-provenance.v1` JSON written by
`crucible-cli::cli::artifact_capture` is a named component inside the
registered reproduction artifact, not a separately decoded record.

The remaining production `crucible-cas/src` `write_all` paths were classified
against the existing content-store and campaign-CAS rows: pack and index,
encrypted/compressed objects, quota, inventory, refs, write-back journal,
frontier/claim records, and campaign-head entries retain their own registered
formats. Generic store copying and staged writes preserve their caller's
format. The searched production CAS source has no direct serde JSON or TOML
codec. In `crucible-cli/src`, the report renderers serialize the registered
`crucible.cli.*` output schemas; the packed-repack journal and QEMU fuzz
index/descriptor have their existing rows. The fuzz coverage JSON is stored
and loaded only by the version-1 descriptor's `coverage_events` reference,
so it inherits that descriptor contract. The schedule-prefix-proof text is
hash input, not an independently decoded record.

The production `crucible-qemu/src` generic writers and `crucible-harness/src`
serialization paths were reviewed as a bounded source family:

| Source paths | Classification |
| --- | --- |
| `crucible-qemu::checkpoint::{host_io_codec,node_codec}`, `realization::snapshot_codec`, `production_fault_runtime::checkpoint_codec`, and `supervision::accelerator_io_servicer` | Independently decoded host continuations and snapshot envelopes with existing QEMU registry rows. Nested device, ring, network-output, scheduler, and fault-runtime blobs use their separately registered codecs. The bounded CBOR helper only writes the caller's format. |
| `crucible-qemu::qmp`, `fault_action_sink::node_payload::encoding`, `mapped_quantum`, and `supervision::device_host_work` | QMP uses its standard envelope and registered Crucible command payloads; node-fault JSON carries the registered `crucible.shmem.node-fault-policy-json` magic inside a registered node-fault payload. The remaining encoders write registered shared-memory control or data messages. |
| `crucible-qemu::launch::entropy`, `qmp::vmstate_control`, `shutdown`, `console_observation`, `linux_cgroup`, and `spawn::materialization` | The fw_cfg entropy file is a fixed raw seed; the debug activation token and QMP quit are fixed control bytes. Console bytes and checkpoint materialization are opaque pass-through data. Cgroup writes use the kernel interface. None has an independent Crucible decoder or version. |
| `crucible-harness::reproduction` | Its canonical tab-separated reproduction artifact is version 4 and shares the existing `crucible.reproduction-artifact` row with the CLI codec. The fresh-lineage baseline event is independently stored and strictly parsed by `crucible-cas`, where its version-1 row already exists. Campaign provenance material and fresh-lineage identity material only feed hashes. |
| `crucible-harness::{e2e,adversarial,replay_oracle,fingerprint}` | The `crucible.e2e.*`, `crucible.adversarial.*`, replay-oracle sampling, and fingerprint-definition tags delimit mock evidence or hash algorithms; no separate durable or wire decoder consumes them. |

The remaining CLI stream-writer review traced `replay::emit_canonical_trace`,
`triage_debug::ledger_format`, `campaign::authoring::write_new_record`,
`campaign::fixture::write_fixture_file`, and
`campaign::finding_bundle::branch::write_private_file`. The first renders
JSON/JSONL/table views of canonical log entries without a separate schema
version. The triage writer persists the newly registered cluster-report JSON
formats and the existing findings-ledger format. The generic campaign writers
persist their callers' registered scenario, schedule, lineage, policy,
import-manifest, branch-report, and component-authority records; the daemon
already checks the authority file's version-one `CRUCCA01` magic and length.

The production `crucible-guest/src` emitter and `crucible-session/src` paths
were also checked. `crucible-guest::selectable` and its group wrapper use the
registered selectable register/request/reply and guest-choice codecs;
`guest_introspection_agent` uses the registered introspection doorbell and
frame codecs. Its pipe, PTY, and SSH `write_all` calls forward unframed child
input inside the already versioned introspection exchange. CLI stdout renders
selected values or random bytes for guest scripts, without an independently
decoded Crucible record. `crucible-session` has no file, serde, or wire writer;
its `crucible.session.fork-handle.v1` string only domains a handle hash, as
classified above.

The `reviewed_durable_source_tags_have_matching_registry_versions` test scans
the named source files above for versioned format tags and checks their
registry versions. It also checks the evaluator's binary magic and version.
The `crucible.reproduction.event-log-artifact.v2` string in the DAG-store
source is explicitly classified as a content-hash domain, not a separately
decoded record. The scan covers reviewed sources rather than every source file
in the repository: other core model, CLI, and Nix-generated paths still need
source-to-registry classification. T-CAM-0.3 remains open.
The source declarations remain authoritative. When a version changes, update
its row and compatibility gate together with the codec and golden vectors.
