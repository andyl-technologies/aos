//! Pins the complete fixed codec payload graph and its derived partial controls.
//!
//! Exhaustive field patterns bind each edge to the real field type. There is
//! deliberately no Vec implementation: literal Value maps and Bytes have their
//! own funded populations, while baseline request vectors are priced separately.
//! An added typed collection requires a new allocation proof before compiling.

use super::*;
use crate::envelope::{Envelope, MessageKind, Method, Nullable};
use crate::reference_packet::input::{PacketInputContext, PacketInputCut};
use crate::reference_packet::service::complete_restore::{
    PacketCompleteRestoreRequest,
    activation::{
        PacketRestorationActivationAllocationRow, PacketRestorationActivationArtifact,
        PacketRestorationActivationOriginals, PacketRestorationActivationPhase,
        PacketRestorationActivationProof, PacketRestorationActivationRequest,
        PacketRestorationActivationScope, PacketRestorationActivationTarget,
        upload::{
            PacketRestorationActivationUploadArtifact, PacketRestorationActivationUploadRequest,
            PacketRestorationActivationUploadRole,
        },
    },
    import18::{
        PacketNativeImport17CommitReceipt, PacketNativeImport17Limits,
        PacketNativeImport17PrepareReceipt, PacketNativeImport17Proof, PacketNativeImport18Binding,
        PacketNativeImport18NativeFamily, PacketNativeImport18SemanticSpendFamily,
        PacketNativeImport18SourceFamily,
    },
    restoration_observe::{
        PacketRestorationObservationArtifact, PacketRestorationObservationProof,
        PacketRestorationObservationRequest,
    },
    transfer::{
        PacketCompleteRestoreCommitRequest, PacketCompleteRestoreInputAllocation,
        PacketCompleteRestorePrepareRequest,
    },
};
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::reference_packet::service::restored_input_reactive17::{
    PacketRestoredInputReactive17Artifact, PacketRestoredInputReactive17Command,
    PacketRestoredInputReactive17PostCheckpointData, PacketRestoredInputReactive17Request,
};
use crucible_node_format::{Bytes, ContentRef, HashRef, Id, Phase, Position, SchemaRef, U64};
use serde_json::{Map, Value};

/// Names fixed payload partials, diagnostics and nested tagged-buffer levels.
pub(super) trait CodecField: Sized {
    const TAG_LEVELS: usize = 0;
    const NAME_BYTES: usize = 0;

    fn controls() -> usize;
}

const fn field_tags<S, T: CodecField>(_: fn(&S) -> &T) -> usize {
    T::TAG_LEVELS
}

const fn field_names<S, T: CodecField>(_: fn(&S) -> &T) -> usize {
    T::NAME_BYTES
}

fn field_controls<S, T: CodecField>(_: fn(&S) -> &T) -> usize {
    size_of::<Option<T>>() + size_of::<Result<Option<T>, serde_json::Error>>() + T::controls()
}

// Both ordinary derives and the map-only record wrapper fit this deliberately
// additive roster. The wrapper's private Fields has the same inline layout;
// both complete root/result views are charged alongside every field partial.
macro_rules! record {
    ($name:ident { $($field:ident),+ $(,)? }) => {
        impl CodecField for $name {
            const TAG_LEVELS: usize = {
                let mut result = 0;
                $(result = maximum(result, field_tags(|value: &Self| &value.$field));)+
                result
            };

            const NAME_BYTES: usize = {
                let mut result = stringify!($name).len();
                $(result += stringify!($field).len() + 4 + field_names(|value: &Self| &value.$field);)+
                result
            };

            fn controls() -> usize {
                2 * size_of::<Self>() + 2 * size_of::<Result<Self, serde_json::Error>>()
                    + serde_partials::field_selector_data()
                    $(+ field_controls(|value: &Self| &value.$field))+
            }
        }

        const _: fn(&$name) = |value| {
            let $name { $($field: _,)+ } = value;
        };
    };
}

// These existing partial companions name the actual primitive visitors,
// including Id construction errors and the pinned Bytes/base64 decoder.
macro_rules! primitive {
    ($($type:ty),+ $(,)?) => {$(
        impl CodecField for $type {
            const NAME_BYTES: usize =
                <Self as serde_partials::DecoderPartial>::DIAGNOSTIC_NAMES_BYTES;

            fn controls() -> usize {
                <Self as serde_partials::DecoderPartial>::partial_counter_data()
            }
        }
    )+};
}

primitive!(u16, U64, String, Id, Bytes, MessageKind, Method, Phase);

macro_rules! unit {
    ($type:ident { $($variant:ident),+ $(,)? }) => {
        impl CodecField for $type {
            const NAME_BYTES: usize = stringify!($type).len()
                $(+ stringify!($variant).len() + 4)+;

            fn controls() -> usize {
                size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
                    + size_of::<String>() + size_of::<Result<String, serde_json::Error>>()
            }
        }

        const _: fn(&$type) = |value| match value { $($type::$variant => {}),+ };
    };
}

unit!(PacketNativeImport18NativeFamily {
    Snapshot17,
    Snapshot18
});
unit!(PacketNativeImport18SemanticSpendFamily {
    Legacy17,
    Complete18
});
unit!(PacketNativeImport18SourceFamily {
    Captured17,
    Captured18,
    Imported18
});
unit!(PacketRestorationActivationPhase { Arm, WorldActivate });
unit!(PacketRestorationActivationUploadRole {
    Coordinator,
    Manifest
});

impl<T: CodecField, const N: usize> CodecField for [T; N] {
    const TAG_LEVELS: usize = T::TAG_LEVELS;
    const NAME_BYTES: usize = N * T::NAME_BYTES;

    fn controls() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + N * (size_of::<Option<T>>() + T::controls())
    }
}

impl<T: CodecField> CodecField for Nullable<T> {
    const TAG_LEVELS: usize = T::TAG_LEVELS;
    const NAME_BYTES: usize = T::NAME_BYTES;

    fn controls() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + size_of::<Value>()
            + size_of::<Result<Value, serde_json::Error>>()
            + T::controls()
    }
}

// Every map in this selected graph is a baseline field with the defining
// literal-JSON decoder. It cannot invoke RawValue's ordinary Value decoder.
// Its arbitrary descendants belong to the independent strict-JSON forest row.
impl CodecField for Map<String, Value> {
    fn controls() -> usize {
        size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
    }
}

impl CodecField for std::collections::BTreeMap<String, Value> {
    fn controls() -> usize {
        size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
    }
}

record!(PacketRestoredInputReactive17PostCheckpointData {
    schema,
    current_record,
    current_model,
});

record!(PacketInputCut {
    schema_version,
    session_id,
    incarnation_id,
    node_id,
    execution_owner_id,
    owner_generation,
    activation_id,
    world_generation,
    world_binding_hash,
    stage_operation_id,
    batch_id,
    batch_sequence,
    input_epoch,
    batch_hash,
    delivery_inventory,
    cutoff,
});

record!(ContentRef {
    hash,
    length,
    media_type,
});

record!(HashRef {
    algorithm,
    domain,
    digest,
});

record!(SchemaRef {
    id,
    version,
    definition,
    extensions,
});

record!(Position {
    time_ps,
    phase,
    microstep,
});

record!(PacketCompleteRestoreCommitRequest {
    schema,
    prepare,
    capture_terminal,
    prepare_request_id,
    prepare_request_sequence,
    prepare_request_digest,
    prepare_response_sequence,
    prepare_response_digest,
    transfer_token,
});

record!(Envelope {
    protocol,
    message,
    session_id,
    incarnation_id,
    node_id,
    execution_owner_id,
    capture_owner_id,
    request_id,
    operation_id,
    sequence,
    method,
    body,
    extensions,
});

record!(PacketCompleteRestorePrepareRequest {
    schema,
    restoration,
    host_protocol,
    native_protocol,
    native_control,
    native_anchor,
    transaction_id,
    generation,
    allocation,
});

record!(PacketCompleteRestoreInputAllocation {
    maximum_known_requested_bytes,
    maximum_input_bytes,
    maximum_nodes,
    maximum_depth,
    maximum_owned_backing_bytes,
    maximum_tree_entries,
    maximum_metadata_rows,
    maximum_literal_backing_bytes,
    maximum_content_transfers,
    maximum_content_objects,
    maximum_content_groups,
    maximum_content_bytes,
    maximum_content_metadata_bytes,
    maximum_model_bytes,
});

record!(PacketCompleteRestoreRequest {
    schema,
    archive_index,
    capture_manifest,
    owner_state,
    journal,
    source_runtime,
    backend_implementation,
    backend_schema,
    archived_cut,
    archived_ordinal,
    target_world,
    target_owner,
    target_owner_binding,
    target_activation,
    target_generation,
    target_owner_generation,
    mapping,
    nonce,
});

record!(PacketNativeImport17CommitReceipt {
    schema,
    algorithm,
    import_binding_digest,
    context_digest,
    commit_digest,
    installed_mapping,
    transfer_token,
    native_sequence,
    assigned_response,
    mac,
});

record!(PacketNativeImport17PrepareReceipt {
    schema,
    algorithm,
    import_binding_digest,
    context_digest,
    prepare_digest,
    input_roster,
    transfer_token,
    generation,
    native_sequence,
    assigned_response,
    mac,
});

record!(PacketNativeImport17Proof {
    schema,
    algorithm,
    context_digest,
    mac,
});

record!(PacketNativeImport18Binding {
    schema,
    prepare_digest,
    native_family,
    native_before,
    controller17,
    source_family,
    source17,
    node25,
    geometry_identity,
    role_extents,
    limits,
    normalization,
    normalization_maximum,
    semantic_spend_family,
    semantic_spend,
    semantic_spend_maximum,
});

record!(PacketNativeImport17Limits {
    role_maximums,
    immutable_objects,
    immutable_bytes,
    immutable_depth,
    maximum_nodes,
    maximum_requested_bytes,
    maximum_target_requested_bytes,
    maximum_before_bytes,
});

record!(PacketRestorationObservationArtifact { request, proof });

record!(PacketRestorationObservationProof {
    schema,
    algorithm,
    context_digest,
    mac,
});

record!(PacketRestorationObservationRequest {
    schema,
    scope,
    world_original,
    world_terminal,
    maximum_items,
    native_allocation,
});

record!(PacketRestorationActivationAllocationRow {
    retained_requested_bytes,
    maximum_simultaneous_transient_bytes,
    declared_counter_scratch_bytes,
});

record!(PacketRestorationActivationScope {
    source_birth,
    source_runtime,
    scope_proof,
    target,
    restoration,
});

record!(PacketRestorationActivationOriginals {
    captured_owner_state,
    captured_control,
    captured_journal,
    mapping,
    commit_request,
    commit_response,
    context_digest,
});

record!(PacketRestorationActivationTarget {
    native_pid,
    session,
    incarnation,
    node,
    owner,
    owner_generation,
    binding_hash,
    world,
    activation,
    generation,
    prepared_token,
    gate,
    admission,
    transaction,
});

record!(PacketRestorationActivationUploadArtifact { request, proof });

record!(PacketRestorationActivationProof {
    schema,
    algorithm,
    context_digest,
    mac,
});

record!(PacketRestorationActivationUploadRequest {
    schema,
    scope,
    role,
    coordinator,
    manifest,
    maximum_frame_bytes,
    chunk_bytes,
    maximum_requests,
    native_allocation,
});

record!(PacketRestorationActivationArtifact { request, proof });

record!(PacketRestorationActivationRequest {
    schema,
    phase,
    scope,
    native_allocation,
});

record!(PacketRestoredInputReactive17Artifact { request, proof });

record!(PacketRestoredInputReactive17Request {
    schema,
    command,
    scope,
    first_observation,
    current_record,
    current_model,
    history_prefix,
    history_next_sequence,
    native_allocation,
});

record!(PacketNativeStartupAllocationRow {
    retained_requested_bytes,
    maximum_simultaneous_transient_bytes,
    declared_counter_scratch_bytes,
});

impl CodecField for PacketInputContext {
    const TAG_LEVELS: usize = 1 + PacketInputCut::TAG_LEVELS;
    const NAME_BYTES: usize = PacketInputCut::NAME_BYTES
        + ContentRef::NAME_BYTES
        + "action,stage,commit,cut,input_request_id,staging_receipt".len();

    fn controls() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + PacketInputCut::controls()
            + Id::controls()
            + ContentRef::controls()
    }
}

const _: fn(&PacketInputContext) = |value| match value {
    PacketInputContext::Stage { cut } => {
        let _: &PacketInputCut = cut;
    }
    PacketInputContext::Commit {
        cut,
        input_request_id,
        staging_receipt,
    } => {
        let _: &PacketInputCut = cut;
        let _: &Id = input_request_id;
        let _: &ContentRef = staging_receipt;
    }
};

impl CodecField for PacketRestoredInputReactive17Command {
    const TAG_LEVELS: usize = 1 + PacketInputContext::TAG_LEVELS;
    const NAME_BYTES: usize = PacketInputContext::NAME_BYTES
        + "action,input,context,run,settle,poll,retire,observe,blob_begin,blob_chunk,blob_finish"
            .len();

    fn controls() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + PacketInputContext::controls()
    }
}

const _: fn(&PacketRestoredInputReactive17Command) = |value| match value {
    PacketRestoredInputReactive17Command::Input { context } => {
        let _: &PacketInputContext = context;
    }
    PacketRestoredInputReactive17Command::Run
    | PacketRestoredInputReactive17Command::Settle
    | PacketRestoredInputReactive17Command::Poll
    | PacketRestoredInputReactive17Command::Retire
    | PacketRestoredInputReactive17Command::Observe
    | PacketRestoredInputReactive17Command::BlobBegin
    | PacketRestoredInputReactive17Command::BlobChunk
    | PacketRestoredInputReactive17Command::BlobFinish => {}
};

// These scalar baseline enums are also closed: an added allocating payload
// cannot bypass the fixed codec graph by inheriting a primitive companion.
const _: fn(&MessageKind) = |v| match v {
    MessageKind::Request | MessageKind::Response | MessageKind::Event => {}
};
const _: fn(&Phase) = |v| match v {
    Phase::BoundaryControl | Phase::Publication | Phase::Delivery | Phase::Reaction => {}
};
const _: fn(&Method) = |v| match v {
    Method::Hello
    | Method::Discover
    | Method::Realize
    | Method::Admit
    | Method::NativeImport18Bootstrap
    | Method::Activate
    | Method::Input
    | Method::Observe
    | Method::Begin
    | Method::Poll
    | Method::Cancel
    | Method::QuantumClose
    | Method::WorldActivate
    | Method::Abort
    | Method::Retire
    | Method::BlobBegin
    | Method::BlobChunk
    | Method::BlobFinish
    | Method::Release
    | Method::OperationUpdate
    | Method::ObservationReady
    | Method::ProviderFault => {}
};

macro_rules! roots {
    ($callback:ident) => {
        $callback!(
            PacketRestoredInputReactive17Artifact,
            PacketRestoredInputReactive17PostCheckpointData,
            PacketRestorationActivationArtifact,
            PacketRestorationActivationUploadArtifact,
            PacketRestorationObservationArtifact,
            PacketNativeImport18Binding,
            PacketNativeImport17Proof,
            PacketNativeImport17PrepareReceipt,
            PacketNativeImport17CommitReceipt,
            PacketCompleteRestorePrepareRequest,
            PacketCompleteRestoreCommitRequest,
            PacketInputContext,
        )
    };
}

macro_rules! root_tags {
    ($($type:ty),+ $(,)?) => {{
        let mut result = 0;
        $(result = maximum(result, <$type as CodecField>::TAG_LEVELS);)+
        result
    }};
}

macro_rules! root_names {
    ($($type:ty),+ $(,)?) => { 0 $(+ <$type as CodecField>::NAME_BYTES)+ };
}

pub(super) const TAG_LEVELS: usize = roots!(root_tags);
pub(super) const NAME_BYTES: usize = roots!(root_names);

pub(super) fn control_bytes() -> usize {
    macro_rules! controls {
        ($($type:ty),+ $(,)?) => { 0 $(+ <$type as CodecField>::controls())+ };
    }
    roots!(controls)
}
