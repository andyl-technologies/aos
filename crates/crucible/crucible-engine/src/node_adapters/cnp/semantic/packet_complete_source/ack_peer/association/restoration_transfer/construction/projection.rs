//! Projects the closed Source transfer DTO grammar without constructing DTOs.
//!
//! Numeric strings use the largest u64 width; each fixed digest uses its actual
//! 32-byte base64 width. Real immutable strings/Values are borrowed. No Bytes or
//! decimal-integer Serialize implementation runs during these counters.

use super::*;
use crucible_node_format::{ContentRef, HashRef, Id, SchemaRef};
use serde::Serialize;

pub(super) const NUMBER: &str = "18446744073709551615";
pub(super) const DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize)]
pub(super) struct HashFields<'a> {
    pub(super) algorithm: &'a str,
    pub(super) domain: &'a str,
    pub(super) digest: &'a str,
}

impl<'a> From<&'a HashRef> for HashFields<'a> {
    fn from(value: &'a HashRef) -> Self {
        Self {
            algorithm: &value.algorithm,
            domain: &value.domain,
            digest: &value.digest,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Reference<'a> {
    hash: HashFields<'a>,
    length: &'static str,
    media_type: &'a str,
}

impl<'a> From<&'a ContentRef> for Reference<'a> {
    fn from(value: &'a ContentRef) -> Self {
        Self {
            hash: (&value.hash).into(),
            length: NUMBER,
            media_type: &value.media_type,
        }
    }
}

impl Reference<'static> {
    pub(super) fn future(media: &'static str) -> Self {
        Self {
            hash: HashFields {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: HEX,
            },
            length: NUMBER,
            media_type: media,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Schema<'a> {
    id: &'a str,
    version: u16,
    definition: Reference<'a>,
    extensions: &'a crucible_node_format::Extensions,
}
impl<'a> From<&'a SchemaRef> for Schema<'a> {
    fn from(value: &'a SchemaRef) -> Self {
        Self {
            id: value.id.as_str(),
            version: value.version,
            definition: (&value.definition).into(),
            extensions: &value.extensions,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Position {
    time_ps: &'static str,
    microstep: &'static str,
    phase: u16,
}
impl Position {
    pub(super) fn ceiling() -> Self {
        Self {
            time_ps: NUMBER,
            microstep: NUMBER,
            phase: 3,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Restoration<'a> {
    pub(super) schema: &'static str,
    pub(super) archive_index: Reference<'a>,
    pub(super) capture_manifest: Reference<'a>,
    pub(super) owner_state: Reference<'a>,
    pub(super) journal: Reference<'a>,
    pub(super) source_runtime: Reference<'a>,
    pub(super) backend_implementation: Reference<'a>,
    pub(super) backend_schema: Schema<'a>,
    pub(super) archived_cut: Position,
    pub(super) archived_ordinal: &'static str,
    pub(super) target_world: HashFields<'a>,
    pub(super) target_owner: &'a Id,
    pub(super) target_owner_binding: HashFields<'a>,
    pub(super) target_activation: &'a Id,
    pub(super) target_generation: &'static str,
    pub(super) target_owner_generation: &'static str,
    pub(super) mapping: Reference<'a>,
    pub(super) nonce: &'static str,
}

#[derive(Serialize)]
pub(super) struct Allocation {
    maximum_known_requested_bytes: &'static str,
    maximum_input_bytes: &'static str,
    maximum_nodes: &'static str,
    maximum_depth: &'static str,
    maximum_owned_backing_bytes: &'static str,
    maximum_tree_entries: &'static str,
    maximum_metadata_rows: &'static str,
    maximum_literal_backing_bytes: &'static str,
    maximum_content_transfers: &'static str,
    maximum_content_objects: &'static str,
    maximum_content_groups: &'static str,
    maximum_content_bytes: &'static str,
    maximum_content_metadata_bytes: &'static str,
    maximum_model_bytes: &'static str,
}

impl Allocation {
    pub(super) fn ceiling() -> Self {
        Self {
            maximum_known_requested_bytes: NUMBER,
            maximum_input_bytes: NUMBER,
            maximum_nodes: NUMBER,
            maximum_depth: NUMBER,
            maximum_owned_backing_bytes: NUMBER,
            maximum_tree_entries: NUMBER,
            maximum_metadata_rows: NUMBER,
            maximum_literal_backing_bytes: NUMBER,
            maximum_content_transfers: NUMBER,
            maximum_content_objects: NUMBER,
            maximum_content_groups: NUMBER,
            maximum_content_bytes: NUMBER,
            maximum_content_metadata_bytes: NUMBER,
            maximum_model_bytes: NUMBER,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Prepare<'a> {
    pub(super) schema: &'static str,
    pub(super) restoration: Restoration<'a>,
    pub(super) host_protocol: Reference<'a>,
    pub(super) native_protocol: Reference<'a>,
    pub(super) native_control: Reference<'a>,
    pub(super) native_anchor: Reference<'a>,
    pub(super) transaction_id: &'a Id,
    pub(super) generation: &'static str,
    pub(super) allocation: Allocation,
}

#[derive(Serialize)]
pub(super) struct Commit<'a, 'p> {
    pub(super) schema: &'static str,
    pub(super) prepare: &'p Prepare<'a>,
    pub(super) capture_terminal: ActualEnvelope<'a>,
    pub(super) prepare_request_id: &'a Id,
    pub(super) prepare_request_sequence: &'static str,
    pub(super) prepare_request_digest: &'static str,
    pub(super) prepare_response_sequence: &'static str,
    pub(super) prepare_response_digest: &'static str,
    pub(super) transfer_token: &'static str,
}

#[derive(Serialize)]
pub(super) struct ActualEnvelope<'a> {
    protocol: &'a str,
    message: crucible_node_transport::envelope::MessageKind,
    session_id: Option<&'a Id>,
    incarnation_id: Option<&'a Id>,
    node_id: Option<&'a Id>,
    execution_owner_id: Option<&'a Id>,
    capture_owner_id: Option<&'a Id>,
    request_id: Option<&'a Id>,
    operation_id: Option<&'a Id>,
    sequence: &'static str,
    method: crucible_node_transport::envelope::Method,
    body: &'a serde_json::Map<String, serde_json::Value>,
    extensions: &'a crucible_node_format::Extensions,
}
impl<'a> From<&'a Envelope> for ActualEnvelope<'a> {
    fn from(v: &'a Envelope) -> Self {
        Self {
            protocol: &v.protocol,
            message: v.message,
            session_id: v.session_id.0.as_ref(),
            incarnation_id: v.incarnation_id.0.as_ref(),
            node_id: v.node_id.0.as_ref(),
            execution_owner_id: v.execution_owner_id.0.as_ref(),
            capture_owner_id: v.capture_owner_id.0.as_ref(),
            request_id: v.request_id.0.as_ref(),
            operation_id: v.operation_id.0.as_ref(),
            sequence: NUMBER,
            method: v.method,
            body: &v.body,
            extensions: &v.extensions,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Empty {}

#[derive(Serialize)]
pub(super) struct BaselineArguments<'a> {
    transaction_id: &'a Id,
    capture_manifest: Reference<'a>,
    expected_world_binding_hash: HashFields<'a>,
    expected_owner_binding_hash: HashFields<'a>,
    destination_owner_ids: [&'a Id; 1],
}

#[derive(Serialize)]
pub(super) struct Baseline<'a> {
    kind: &'static str,
    binding_hash: HashFields<'a>,
    owner_generation: &'static str,
    activation_id: Option<&'a Id>,
    world_generation: &'static str,
    arguments: BaselineArguments<'a>,
    extensions: Empty,
}
impl<'a> Baseline<'a> {
    pub(super) fn for_restoration(id: &'a Id, v: &'a Restoration<'a>) -> Self {
        Self {
            kind: "prepare_restore",
            binding_hash: HashFields {
                algorithm: v.target_owner_binding.algorithm,
                domain: v.target_owner_binding.domain,
                digest: v.target_owner_binding.digest,
            },
            owner_generation: NUMBER,
            activation_id: Some(v.target_activation),
            world_generation: NUMBER,
            arguments: BaselineArguments {
                transaction_id: id,
                capture_manifest: Reference {
                    hash: HashFields {
                        algorithm: v.capture_manifest.hash.algorithm,
                        domain: v.capture_manifest.hash.domain,
                        digest: v.capture_manifest.hash.digest,
                    },
                    length: NUMBER,
                    media_type: v.capture_manifest.media_type,
                },
                expected_world_binding_hash: HashFields {
                    algorithm: v.target_world.algorithm,
                    domain: v.target_world.domain,
                    digest: v.target_world.digest,
                },
                expected_owner_binding_hash: HashFields {
                    algorithm: v.target_owner_binding.algorithm,
                    domain: v.target_owner_binding.domain,
                    digest: v.target_owner_binding.digest,
                },
                destination_owner_ids: [v.target_owner],
            },
            extensions: Empty {},
        }
    }
}

#[derive(Serialize)]
pub(super) struct AssignedEnvelope<'a, B, E> {
    protocol: &'static str,
    message: &'static str,
    session_id: Option<&'a Id>,
    incarnation_id: Option<&'a Id>,
    node_id: Option<&'a Id>,
    execution_owner_id: Option<&'a Id>,
    capture_owner_id: Option<&'a Id>,
    request_id: Option<&'a Id>,
    operation_id: Option<&'a Id>,
    sequence: &'static str,
    method: &'static str,
    body: B,
    extensions: E,
}
impl<'a, B, E> AssignedEnvelope<'a, B, E> {
    pub(super) fn new(controller: &'a CnpController, id: &'a Id, body: B, extensions: E) -> Self {
        Self {
            protocol: "CNP/1",
            message: "request",
            session_id: Some(controller.authority().session_id()),
            incarnation_id: Some(controller.authority().incarnation_id()),
            node_id: Some(&controller.route().node),
            execution_owner_id: Some(&controller.route().execution_owner),
            capture_owner_id: None,
            request_id: Some(id),
            operation_id: None,
            sequence: NUMBER,
            method: "begin",
            body,
            extensions,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Binding<'a> {
    pub(super) schema: &'static str,
    pub(super) assigned_query: &'static str,
    pub(super) completed_query_response: &'static str,
    pub(super) allocation: Reference<'a>,
}

#[derive(Serialize)]
pub(super) struct PrepareExtensions<'a, 'p> {
    #[serde(rename = "source-owned.packet-complete-restore-prepare/12")]
    pub(super) prepare: &'p Prepare<'a>,
    #[serde(rename = "source-owned.packet-fresh-restore-allocation-prepare-binding/13")]
    pub(super) binding: Binding<'a>,
    #[serde(rename = "source-owned.packet-complete-restore-prepare-proof/12")]
    pub(super) proof: Proof,
}

#[derive(Serialize)]
pub(super) struct CommitExtensions<'a, 'p, 'c> {
    #[serde(rename = "source-owned.packet-complete-restore-commit/12")]
    pub(super) commit: &'c Commit<'a, 'p>,
    #[serde(rename = "source-owned.packet-complete-restore-commit-proof/12")]
    pub(super) proof: Proof,
}

#[derive(Serialize)]
pub(super) struct Proof {
    pub(super) schema: &'static str,
    pub(super) algorithm: &'static str,
    pub(super) context_digest: &'static str,
    pub(super) mac: &'static str,
}
impl Proof {
    pub(super) fn new(schema: &'static str) -> Self {
        Self {
            schema,
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM,
            context_digest: DIGEST,
            mac: DIGEST,
        }
    }
}

#[derive(Serialize)]
pub(super) struct PrepareContext {
    schema: &'static str,
    algorithm: &'static str,
    source_birth: &'static str,
    kernel_binding: &'static str,
    policy_binding: &'static str,
    host_registration: &'static str,
    native_registration: &'static str,
    hello_request: &'static str,
    hello_response: &'static str,
    assigned_prepare: &'static str,
    prepare_request: &'static str,
    input_roster: &'static str,
}

impl PrepareContext {
    pub(super) fn ceiling() -> Self {
        Self {
            schema: "source-owned.packet-complete-restore-prepare-context/12",
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM,
            source_birth: DIGEST,
            kernel_binding: DIGEST,
            policy_binding: DIGEST,
            host_registration: DIGEST,
            native_registration: DIGEST,
            hello_request: DIGEST,
            hello_response: DIGEST,
            assigned_prepare: DIGEST,
            prepare_request: DIGEST,
            input_roster: DIGEST,
        }
    }
}

#[derive(Serialize)]
pub(super) struct RestorationContext {
    schema: &'static str,
    algorithm: &'static str,
    source_birth: &'static str,
    kernel_binding: &'static str,
    policy_binding: &'static str,
    host_registration: &'static str,
    native_registration: &'static str,
    hello_request: &'static str,
    hello_response: &'static str,
    assigned_restore: &'static str,
    archive_binding: &'static str,
    target_binding: &'static str,
    mapping_binding: &'static str,
    request_binding: &'static str,
}

impl RestorationContext {
    pub(super) fn ceiling() -> Self {
        Self {
            schema: "source-owned.packet-complete-restore-context/11",
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM,
            source_birth: DIGEST,
            kernel_binding: DIGEST,
            policy_binding: DIGEST,
            host_registration: DIGEST,
            native_registration: DIGEST,
            hello_request: DIGEST,
            hello_response: DIGEST,
            assigned_restore: DIGEST,
            archive_binding: DIGEST,
            target_binding: DIGEST,
            mapping_binding: DIGEST,
            request_binding: DIGEST,
        }
    }
}

#[derive(Serialize)]
pub(super) struct CommitContext {
    schema: &'static str,
    algorithm: &'static str,
    restoration: RestorationContext,
    commit_request: &'static str,
    prepare_request: &'static str,
    prepare_response: &'static str,
    transfer_token: &'static str,
    input_roster: &'static str,
}
impl CommitContext {
    pub(super) fn ceiling() -> Self {
        Self {
            schema: "source-owned.packet-complete-restore-commit-context/12",
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM,
            restoration: RestorationContext::ceiling(),
            commit_request: DIGEST,
            prepare_request: DIGEST,
            prepare_response: DIGEST,
            transfer_token: DIGEST,
            input_roster: DIGEST,
        }
    }
}

#[derive(Serialize)]
pub(super) struct PrepareReceipt {
    schema: &'static str,
    algorithm: &'static str,
    prepare_digest: &'static str,
    context_digest: &'static str,
    input_roster: &'static str,
    transfer_token: &'static str,
    generation: &'static str,
    native_sequence: &'static str,
    assigned_response: &'static str,
    mac: &'static str,
}
impl PrepareReceipt {
    pub(super) fn ceiling() -> Self {
        Self {
            schema: PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION,
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM,
            prepare_digest: DIGEST,
            context_digest: DIGEST,
            input_roster: DIGEST,
            transfer_token: DIGEST,
            generation: NUMBER,
            native_sequence: NUMBER,
            assigned_response: DIGEST,
            mac: DIGEST,
        }
    }
}

#[derive(Serialize)]
pub(super) struct CommitReceipt<'a> {
    schema: &'static str,
    algorithm: &'static str,
    commit_digest: &'static str,
    context_digest: &'static str,
    installed_mapping: Reference<'a>,
    transfer_token: &'static str,
    native_sequence: &'static str,
    assigned_response: &'static str,
    mac: &'static str,
}
impl CommitReceipt<'static> {
    pub(super) fn ceiling() -> Self {
        Self {
            schema: PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION,
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM,
            commit_digest: DIGEST,
            context_digest: DIGEST,
            installed_mapping: Reference::future("application/json"),
            transfer_token: DIGEST,
            native_sequence: NUMBER,
            assigned_response: DIGEST,
            mac: DIGEST,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Held<'a, 'p> {
    schema: &'static str,
    native_pid: &'static str,
    target_world: &'p HashFields<'a>,
    target_owner: &'a Id,
    target_owner_binding: &'p HashFields<'a>,
    target_activation: &'a Id,
    target_generation: &'static str,
    captured_owner_state: &'p Reference<'a>,
    captured_control: Reference<'a>,
    captured_journal: &'p Reference<'a>,
    mapping: &'p Reference<'a>,
    restore_commit: Reference<'static>,
    context_digest: &'static str,
    local_cursor: Position,
    inventory_hash: HashFields<'static>,
    physical_gate_held: bool,
}

impl<'a, 'p> Held<'a, 'p> {
    pub(super) fn ceiling(restoration: &'p Restoration<'a>, control: Reference<'a>) -> Self {
        Self {
            schema: "source-owned.packet-restored-commit-held/12",
            native_pid: NUMBER,
            target_world: &restoration.target_world,
            target_owner: restoration.target_owner,
            target_owner_binding: &restoration.target_owner_binding,
            target_activation: restoration.target_activation,
            target_generation: NUMBER,
            captured_owner_state: &restoration.owner_state,
            captured_control: control,
            captured_journal: &restoration.journal,
            mapping: &restoration.mapping,
            restore_commit: Reference::future("application/json"),
            context_digest: DIGEST,
            local_cursor: Position::ceiling(),
            inventory_hash: HashFields {
                algorithm: "blake3-256",
                domain: MAXIMUM_HASH_DOMAIN,
                digest: HEX,
            },
            physical_gate_held: true,
        }
    }
}

const MAXIMUM_HASH_DOMAIN: &str = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

#[derive(Serialize)]
pub(super) struct ArchiveBinding<'a, 'p> {
    schema: &'static str,
    archive_index: &'p Reference<'a>,
    capture_manifest: &'p Reference<'a>,
    owner_state: &'p Reference<'a>,
    journal: &'p Reference<'a>,
    source_runtime: &'p Reference<'a>,
    backend_implementation: &'p Reference<'a>,
    backend_schema: &'p Schema<'a>,
    archived_cut: &'p Position,
    archived_ordinal: &'static str,
}

#[derive(Serialize)]
pub(super) struct TargetBinding<'a, 'p> {
    schema: &'static str,
    world: &'p HashFields<'a>,
    owner: &'a Id,
    owner_binding: &'p HashFields<'a>,
    activation: &'a Id,
    generation: &'static str,
    owner_generation: &'static str,
    nonce: &'static str,
}

impl<'a> Restoration<'a> {
    pub(super) fn archive_binding(&self) -> ArchiveBinding<'a, '_> {
        ArchiveBinding {
            schema: "source-owned.packet-complete-restore-archive-binding/11",
            archive_index: &self.archive_index,
            capture_manifest: &self.capture_manifest,
            owner_state: &self.owner_state,
            journal: &self.journal,
            source_runtime: &self.source_runtime,
            backend_implementation: &self.backend_implementation,
            backend_schema: &self.backend_schema,
            archived_cut: &self.archived_cut,
            archived_ordinal: self.archived_ordinal,
        }
    }

    pub(super) fn target_binding(&self) -> TargetBinding<'a, '_> {
        TargetBinding {
            schema: "source-owned.packet-complete-restore-target-binding/11",
            world: &self.target_world,
            owner: self.target_owner,
            owner_binding: &self.target_owner_binding,
            activation: self.target_activation,
            generation: self.target_generation,
            owner_generation: self.target_owner_generation,
            nonce: self.nonce,
        }
    }
}

impl Prepare<'_> {
    pub(super) fn input_roster(&self) -> impl Serialize + '_ {
        (
            "source-owned.packet-complete-restore-input-roster/12",
            &self.host_protocol,
            &self.native_protocol,
            &self.native_control,
            &self.native_anchor,
            &self.restoration.owner_state,
            &self.restoration.journal,
            &self.restoration.mapping,
            self.restoration.nonce,
            self.transaction_id,
            self.generation,
            &self.allocation,
        )
    }
}

#[derive(Serialize)]
pub(super) struct AssignedIdentity<'r, 'a, B, E> {
    protocol: &'static str,
    session_id: Option<&'a Id>,
    incarnation_id: Option<&'a Id>,
    node_id: Option<&'a Id>,
    execution_owner_id: Option<&'a Id>,
    capture_owner_id: Option<&'a Id>,
    request_id: Option<&'a Id>,
    operation_id: Option<&'a Id>,
    method: &'static str,
    body: &'r B,
    extensions: &'r E,
    request_origin: &'static str,
}

impl<'a, B, E> AssignedEnvelope<'a, B, E> {
    pub(super) fn identity(&self) -> AssignedIdentity<'_, 'a, B, E> {
        AssignedIdentity {
            protocol: self.protocol,
            session_id: self.session_id,
            incarnation_id: self.incarnation_id,
            node_id: self.node_id,
            execution_owner_id: self.execution_owner_id,
            capture_owner_id: self.capture_owner_id,
            request_id: self.request_id,
            operation_id: self.operation_id,
            method: self.method,
            body: &self.body,
            extensions: &self.extensions,
            request_origin: "controller",
        }
    }
}
