//! Binds a new settled Capture request to the genuine administrative ticket.
//!
//! The Source issuer must first join the real OriginalLineageOwnerCaptureTicket,
//! current World/Window claim, SourceRead member fence and independently admitted
//! whole construction row. These DTOs and MAC helpers are DATA operations only.
//! The native consumer still needs its actual private boot/connection/current
//! model association, recounted row and spent original slot before any effect.
//! Old original-purpose class15 and its profile/guards are unchanged.

use crate::bodies::{BeginArguments, BeginKind, CaptureArguments, RequestBody};
use crate::reference_packet::service::complete_restore::activation::{
    PacketRestorationActivationProof, PacketRestorationActivationScope,
};
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind, Method},
};
use crucible_node_contract::{Bytes, ContentRef, Id, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

/// Names the separately negotiated closed Source proof extension.
pub const RESTORED_SETTLED_CAPTURE_FEATURE: &str =
    "source-owned.packet-restored-settled-capture/17";

/// Names the exact independent context and key domain family.
pub const RESTORED_SETTLED_CAPTURE_REQUEST: &str =
    "source-owned.packet-restored-settled-capture-request/17";

/// Bounds this small proof artifact independently of complete state/model banks.
pub const MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES: usize = 16_384;
const PROOF_SCHEMA: &str = "source-owned.packet-restored-settled-capture-proof/17";
const CONTEXT_SCHEMA: &str = "source-owned.packet-restored-settled-capture-context/17";
const KEY_DOMAIN: &str = "source-owned.packet-restored-settled-capture-key/17";

/// Carries complete immutable and current Capture correspondence as DATA.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureRequest {
    /// Selects this exact family, never an old invocation Capture request.
    pub schema: String,
    /// Keeps the actual target World plus immutable signed restoration originals.
    pub scope: PacketRestorationActivationScope,
    /// Copies exact baseline Capture arguments from the actual admitted ticket.
    pub capture: CaptureArguments,
    /// Names the actual capture owner from the same administrative ticket.
    pub capture_owner: Id,
    /// Names the actual administrative Capture operation, including before uploads.
    pub capture_operation: Id,
    /// Names the actual current Runtime7 object bound by that same ticket.
    pub runtime_object: ContentRef,
    /// Names the genuine ordered coordinator prefix/safe-point checkpoint.
    ///
    /// Its complete canonical body is retained in the preupload history-prefix
    /// envelope. A matching timestamp, coordinate, count or this fullref cannot
    /// issue the separate live Core/Window administrative Capture claim.
    pub coordinator_checkpoint: ContentRef,
    /// Names the actual signed parent archive whose full reachable DAG is retained.
    pub parent_archive: ContentRef,
    /// Names the immutable first restored Observe proof without calling it current.
    pub first_observation: ContentRef,
    /// Names the latest grant-free current restored12 proof before this Capture.
    pub current_record: ContentRef,
    /// Names its full underlying Producer2 or Reactive model proof.
    pub current_model: ContentRef,
    /// Names the closed complete Source/SDK history prefix before this Capture original.
    pub history_prefix: ContentRef,
    /// Retains the actual SDK next sequence at the cut before Capture uploads.
    ///
    /// Those later upload originals remain in the new Capture attempt; they do
    /// not recursively belong to the artifact whose bytes they transport.
    pub history_next_sequence: U64,
    /// Names the exact installed complete class17 schema definition.
    pub native_schema: ContentRef,
    /// Bounds the independently recounted native phase demand admitted by Source.
    ///
    /// Each actual axis must fit this bound and the genuine remaining native
    /// lifetime reserve. Native debits its actual retained phase demand, not
    /// this advertised bound; this DATA never renews previously spent credit.
    pub native_allocation: PacketNativeStartupAllocationRow,
}

impl PacketRestoredSettledCaptureRequest {
    /// Validates closed correspondence syntax without issuing a Capture permit.
    ///
    /// # Errors
    /// Refuses old family, malformed full references, short axes or invalid Capture data.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != RESTORED_SETTLED_CAPTURE_REQUEST {
            return Err(invalid());
        }
        validate_scope_data(&self.scope)?;
        self.capture_owner.validate()?;
        self.capture_operation.validate()?;
        if self.history_next_sequence.get() == 0 {
            return Err(invalid());
        }
        self.capture.validate()?;
        crate::connection::serialized_credit(
            self,
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
        )?;
        self.native_allocation.requested_peak_data()?;
        self.runtime_object.validate()?;
        self.parent_archive.validate()?;
        self.coordinator_checkpoint.validate()?;
        if self.coordinator_checkpoint.media_type
            != "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17"
            || self.runtime_object.media_type
                != "application/vnd.crucible.runtime-original-lineage+json;version=7"
            || self.parent_archive.media_type
                != "application/vnd.crucible.native-signed-index-body.v3+json"
        {
            return Err(invalid());
        }
        for reference in [
            &self.first_observation,
            &self.current_record,
            &self.current_model,
            &self.history_prefix,
            &self.native_schema,
        ] {
            reference.validate()?;
            if reference.media_type != "application/json" {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// Binds the whole unsigned extension to its actual assigned request digest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureContext {
    /// Selects the distinct complete assigned Capture context.
    pub schema: String,
    /// Retains the full actual independently derived request, including its row.
    pub request: PacketRestoredSettledCaptureRequest,
    /// Retains the 32-byte digest of the complete actually assigned Envelope.
    pub assigned_request: Bytes,
}

impl PacketRestoredSettledCaptureContext {
    /// Checks fixed context syntax without proving currentness or ticket ownership.
    ///
    /// # Errors
    /// Refuses a wrong domain, invalid request or noncomplete assigned digest.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != CONTEXT_SCHEMA || self.assigned_request.as_slice().len() != 32 {
            return Err(invalid());
        }
        self.request.validate_data()
    }
}

/// Retains the unsigned request and its complete domain-separated Source MAC.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureArtifact {
    /// Retains the full signed request; syntax alone is not a native grant.
    pub request: PacketRestoredSettledCaptureRequest,
    /// Retains closed proof bytes, never a Source/Window/private native Scope.
    pub proof: PacketRestorationActivationProof,
}

impl PacketRestoredSettledCaptureArtifact {
    /// Checks complete artifact syntax and its independent encoded ceiling.
    ///
    /// # Errors
    /// Refuses malformed request data, another proof family, short digests or
    /// an oversized artifact. MAC/currentness verification remains mandatory.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        if self.proof.schema != PROOF_SCHEMA
            || self.proof.algorithm != "blake3-256-mac"
            || self.proof.context_digest.as_slice().len() != 32
            || self.proof.mac.as_slice().len() != 32
        {
            return Err(invalid());
        }
        crate::connection::serialized_credit(
            self,
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
        )?;
        Ok(())
    }
}

/// Returns the exact context discriminator for actual caller construction.
pub const fn restored_settled_capture_context_schema_data() -> &'static str {
    CONTEXT_SCHEMA
}

/// Commits every assigned field and unsigned extension, omitting only its proof.
///
/// # Errors
/// Refuses another method/kind/owner, changed Capture arguments, other extensions,
/// missing assigned identity, malformed unsigned request or excessive frame bytes.
pub fn restored_settled_capture_assigned_request_digest_data(
    original: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.message != MessageKind::Request
        || original.method != Method::Begin
        || original.sequence.get() == 0
        || original.request_id.0.is_none()
        || original.operation_id.0.is_none()
        || original.node_id.0.is_none()
        || original.execution_owner_id.0.is_some()
        || original.capture_owner_id.0.is_none()
        || original.extensions.len() != 1
        || !original
            .extensions
            .contains_key(RESTORED_SETTLED_CAPTURE_FEATURE)
    {
        return Err(invalid());
    }
    let extension = original
        .extensions
        .get(RESTORED_SETTLED_CAPTURE_FEATURE)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if extension
        .keys()
        .any(|key| key != "request" && key != "proof")
    {
        return Err(invalid());
    }
    let request: PacketRestoredSettledCaptureRequest =
        serde_json::from_value(extension.get("request").ok_or_else(invalid)?.clone())
            .map_err(crucible_node_contract::ContractError::from)?;
    request.validate_data()?;
    let RequestBody::Begin(begin) = crate::bodies::decode_request(Method::Begin, &original.body)?
    else {
        return Err(invalid());
    };
    if begin.kind != BeginKind::Capture || !begin.extensions.is_empty() {
        return Err(invalid());
    }
    let BeginArguments::Capture(arguments) = begin.decoded_arguments()? else {
        return Err(invalid());
    };
    if arguments != request.capture
        || original.operation_id.0.as_ref() != Some(&request.capture_operation)
        || original.capture_owner_id.0.as_ref() != Some(&request.capture_owner)
        || original.session_id.0.as_ref() != Some(&request.scope.target.session)
        || original.incarnation_id.0.as_ref() != Some(&request.scope.target.incarnation)
        || original.node_id.0.as_ref() != Some(&request.scope.target.node)
        || begin.binding_hash != request.scope.target.binding_hash
        || begin.owner_generation != request.scope.target.owner_generation
        || begin.activation_id.0.as_ref() != Some(&request.scope.target.activation)
        || begin.world_generation != request.scope.target.generation
    {
        return Err(invalid());
    }
    crate::connection::serialized_credit(original, maximum_frame_bytes)?;
    let mut value =
        serde_json::to_value(original).map_err(crucible_node_contract::ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|extensions| extensions.get_mut(RESTORED_SETTLED_CAPTURE_FEATURE))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove("proof");
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > maximum_frame_bytes {
        return Err(invalid());
    }
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Computes data only after the genuine Source issuer authenticates its claim.
///
/// # Errors
/// Refuses invalid context syntax, oversized canonical body or encoding failure.
pub fn restored_settled_capture_proof_data(
    key: &[u8; 32],
    context: &PacketRestoredSettledCaptureContext,
) -> Result<PacketRestorationActivationProof, ProviderError> {
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    Ok(PacketRestorationActivationProof {
        schema: PROOF_SCHEMA.to_owned(),
        algorithm: "blake3-256-mac".to_owned(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &bytes).as_bytes().to_vec()),
    })
}

/// Verifies MAC correspondence without creating the native spent Capture scope.
///
/// # Errors
/// Refuses wrong key/context/domain, malformed proof digests or changed assigned data.
pub fn verify_restored_settled_capture_proof_data(
    key: &[u8; 32],
    context: &PacketRestoredSettledCaptureContext,
    proof: &PacketRestorationActivationProof,
) -> Result<(), ProviderError> {
    if proof.schema != PROOF_SCHEMA
        || proof.algorithm != "blake3-256-mac"
        || proof.context_digest.as_slice().len() != 32
        || proof.mac.as_slice().len() != 32
    {
        return Err(invalid());
    }
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    if blake3::hash(&bytes) != *proof.context_digest.as_slice()
        || blake3::keyed_hash(&derived, &bytes) != *proof.mac.as_slice()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Hashes the exact validated MAC context without granting Capture rights.
///
/// # Errors
/// Refuses invalid context syntax, excessive canonical bytes or encoding failure.
pub fn restored_settled_capture_context_digest_data(
    context: &PacketRestoredSettledCaptureContext,
) -> Result<[u8; 32], ProviderError> {
    Ok(*blake3::hash(&context_bytes(context)?).as_bytes())
}

const CONTRACT_BYTES: &[u8] = include_bytes!("restored_settled_capture_contract17.json");

/// Borrows the complete compiled Capture17 DATA contract definition.
pub const fn restored_settled_capture_contract_data() -> &'static [u8] {
    CONTRACT_BYTES
}

/// Returns the full separately negotiated Capture17 schema reference.
///
/// # Errors
/// Reports static identifier or full content-reference construction failure.
pub fn restored_settled_capture_schema_data()
-> Result<crucible_node_contract::SchemaRef, ProviderError> {
    Ok(crucible_node_contract::SchemaRef {
        id: Id::new(RESTORED_SETTLED_CAPTURE_FEATURE)?,
        version: 17,
        definition: canonical::content_ref(CONTRACT_BYTES, "application/json")?,
        extensions: Default::default(),
    })
}

/// Compares every schema/reference field against the actual compiled definition.
///
/// This allocation-free DATA comparison never issues a Source or native permit.
///
/// # Errors
/// Refuses another family/version, extensions or changed full definition fields.
pub fn authenticate_restored_settled_capture_schema_data(
    schema: &crucible_node_contract::SchemaRef,
) -> Result<(), ProviderError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&(CONTRACT_BYTES.len() as u64).to_be_bytes());
    hasher.update(CONTRACT_BYTES);
    let digest = hasher.finalize().to_hex();
    if schema.id.as_str() != RESTORED_SETTLED_CAPTURE_FEATURE
        || schema.version != 17
        || !schema.extensions.is_empty()
        || schema.definition.media_type != "application/json"
        || schema.definition.length.get() != CONTRACT_BYTES.len() as u64
        || schema.definition.hash.algorithm != "blake3-256"
        || schema.definition.hash.domain != "cnp.blob.v1"
        || schema.definition.hash.digest != digest.as_str()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Counts fixed schema factory/comparison/hash/conversion headers.
pub fn restored_settled_capture_schema_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<crucible_node_contract::SchemaRef>()
        + size_of::<Result<crucible_node_contract::SchemaRef, ProviderError>>()
        + size_of::<Result<ContentRef, crucible_node_contract::ContractError>>()
        + size_of::<Result<Id, crucible_node_contract::ContractError>>()
        + size_of::<&crucible_node_contract::SchemaRef>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
        + size_of::<Result<(), ProviderError>>()
}

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledCaptureRequest {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            scope,
            capture,
            capture_owner,
            capture_operation,
            runtime_object,
            coordinator_checkpoint,
            parent_archive,
            first_observation,
            current_record,
            current_model,
            history_prefix,
            history_next_sequence,
            native_schema,
            native_allocation,
        } = self;
        observer.observe(schema)?;
        observer.observe(scope)?;
        let CaptureArguments {
            capture_id,
            participant_ids,
            cut_id,
            cut,
            event_ordinal,
            ordering_profile,
            preservation_contract,
        } = capture;
        observer.observe(capture_id)?;
        observer.observe(participant_ids)?;
        observer.observe(cut_id)?;
        observer.observe(cut)?;
        observer.observe(event_ordinal)?;
        observer.observe(ordering_profile)?;
        observer.observe(preservation_contract)?;
        observer.observe(capture_owner)?;
        observer.observe(capture_operation)?;
        observer.observe(runtime_object)?;
        observer.observe(coordinator_checkpoint)?;
        observer.observe(parent_archive)?;
        observer.observe(first_observation)?;
        observer.observe(current_record)?;
        observer.observe(current_model)?;
        observer.observe(history_prefix)?;
        observer.observe(history_next_sequence)?;
        observer.observe(native_schema)?;
        let PacketNativeStartupAllocationRow {
            retained_requested_bytes,
            maximum_simultaneous_transient_bytes,
            declared_counter_scratch_bytes,
        } = native_allocation;
        observer.observe(retained_requested_bytes)?;
        observer.observe(maximum_simultaneous_transient_bytes)?;
        observer.observe(declared_counter_scratch_bytes)
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledCaptureContext {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            request,
            assigned_request,
        } = self;
        observer.observe(schema)?;
        observer.observe(request)?;
        observer.observe(assigned_request)
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledCaptureArtifact {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { request, proof } = self;
        observer.observe(request)?;
        observer.observe(proof)
    }
}

/// Counts fixed headers for this contract's DATA validation and MAC projection.
///
/// Dynamic request, Value and canonical banks require their independent defining
/// construction projection; this getter never treats its fixed sum as that row.
pub fn restored_settled_capture_contract_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<PacketRestoredSettledCaptureRequest>()
        + size_of::<PacketRestoredSettledCaptureContext>()
        + size_of::<PacketRestoredSettledCaptureArtifact>()
        + size_of::<Result<PacketRestoredSettledCaptureRequest, serde_json::Error>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
        + size_of::<Result<PacketRestorationActivationProof, ProviderError>>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + size_of::<crate::bodies::BeginRequest>()
        + size_of::<RequestBody>()
        + size_of::<BeginArguments>()
        + size_of::<CaptureArguments>()
        + size_of::<Result<RequestBody, ProviderError>>()
        + size_of::<Result<BeginArguments, crucible_node_contract::ContractError>>()
        + size_of::<serde_json::Value>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<Option<&'static serde_json::Value>>()
        + size_of::<Option<&'static serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Result<&'static serde_json::Value, ProviderError>>()
        + size_of::<Result<&'static serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<Option<&'static mut serde_json::Value>>()
        + size_of::<Option<&'static mut serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Result<&'static mut serde_json::Map<String, serde_json::Value>, ProviderError>>(
        )
        + size_of::<serde_json::map::Keys<'static>>()
        + size_of::<[&'static ContentRef; 5]>()
        + size_of::<std::array::IntoIter<&'static ContentRef, 5>>()
        + size_of::<[&'static ContentRef; 7]>()
        + size_of::<std::array::IntoIter<&'static ContentRef, 7>>()
        + size_of::<[&'static ContentRef; 9]>()
        + size_of::<std::array::IntoIter<&'static ContentRef, 9>>()
        + size_of::<[&'static Id; 9]>()
        + size_of::<std::array::IntoIter<&'static Id, 9>>()
        + field_view_bytes(|value: &'static PacketRestoredSettledCaptureRequest| {
            let PacketRestoredSettledCaptureRequest {
                schema,
                scope,
                capture,
                capture_owner,
                capture_operation,
                runtime_object,
                coordinator_checkpoint,
                parent_archive,
                first_observation,
                current_record,
                current_model,
                history_prefix,
                history_next_sequence,
                native_schema,
                native_allocation,
            } = value;
            (
                schema,
                scope,
                capture,
                capture_owner,
                capture_operation,
                runtime_object,
                coordinator_checkpoint,
                parent_archive,
                first_observation,
                current_record,
                current_model,
                history_prefix,
                history_next_sequence,
                native_schema,
                native_allocation,
            )
        })
        + field_view_bytes(|value: &'static PacketRestorationActivationScope| {
            let PacketRestorationActivationScope {
                source_birth,
                source_runtime,
                scope_proof,
                target,
                restoration,
            } = value;
            (
                source_birth,
                source_runtime,
                scope_proof,
                target,
                restoration,
            )
        })
        + field_view_bytes(|value: &'static CaptureArguments| {
            let CaptureArguments {
                capture_id,
                participant_ids,
                cut_id,
                cut,
                event_ordinal,
                ordering_profile,
                preservation_contract,
            } = value;
            (
                capture_id,
                participant_ids,
                cut_id,
                cut,
                event_ordinal,
                ordering_profile,
                preservation_contract,
            )
        })
}

// Naming the inferred borrowed tuple prices its defining view without creating
// an owner, extending a lifetime, or lending any runtime authorization.
const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}

fn context_bytes(context: &PacketRestoredSettledCaptureContext) -> Result<Vec<u8>, ProviderError> {
    context.validate_data()?;
    crate::connection::serialized_credit(context, MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES)?;
    let value =
        serde_json::to_value(context).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

fn validate_scope_data(scope: &PacketRestorationActivationScope) -> Result<(), ProviderError> {
    if scope.restoration.context_digest.as_slice().len() != 32
        || scope.restoration.commit_request == scope.restoration.commit_response
        || scope.target.native_pid.get() == 0
        || scope.target.native_pid.get() > i32::MAX as u64
        || scope.target.owner_generation.get() == 0
        || scope.target.generation.get() == 0
    {
        return Err(invalid());
    }
    let target = &scope.target;
    for id in [
        &target.session,
        &target.incarnation,
        &target.node,
        &target.owner,
        &target.activation,
        &target.prepared_token,
        &target.gate,
        &target.admission,
        &target.transaction,
    ] {
        id.validate()?;
    }
    target.binding_hash.validate()?;
    target.world.validate()?;
    let originals = &scope.restoration;
    for reference in [
        &scope.source_birth,
        &scope.source_runtime,
        &scope.scope_proof,
        &originals.captured_owner_state,
        &originals.captured_control,
        &originals.captured_journal,
        &originals.mapping,
        &originals.commit_request,
        &originals.commit_response,
    ] {
        reference.validate()?;
    }
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored settled Capture17 correspondence differs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::BeginRequest;
    use crate::envelope::Nullable;
    use crucible_node_contract::{Extensions, Phase, Position};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn reference(bytes: &[u8]) -> Result<ContentRef, ProviderError> {
        Ok(canonical::content_ref(bytes, "application/json")?)
    }

    pub(super) fn fixture() -> Result<(PacketRestoredSettledCaptureRequest, Envelope), ProviderError>
    {
        // This is inert DATA from the existing grammar fixture. It creates no
        // Source ticket, controller, socket, model, native owner or Window claim.
        let scope = super::super::complete_restore::activation::tests::request()?.scope;
        let request = PacketRestoredSettledCaptureRequest {
            schema: RESTORED_SETTLED_CAPTURE_REQUEST.into(),
            capture: CaptureArguments {
                capture_id: Id::new("settled-capture")?,
                participant_ids: vec![scope.target.node.clone()],
                cut_id: Id::new("current-cut")?,
                cut: Position::new(U64::new(12), U64::new(0), Phase::BoundaryControl),
                event_ordinal: U64::new(2),
                ordering_profile: "superdense-v1".into(),
                preservation_contract: Id::new("complete-preservation")?,
            },
            capture_owner: Id::new("capture-owner-distinct-from-execution")?,
            capture_operation: Id::new("capture-operation")?,
            runtime_object: canonical::content_ref(
                b"current-runtime-object",
                "application/vnd.crucible.runtime-original-lineage+json;version=7",
            )?,
            coordinator_checkpoint: canonical::content_ref(
                b"ordered-current-coordinator-checkpoint",
                "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17",
            )?,
            parent_archive: canonical::content_ref(
                b"signed-parent-archive",
                "application/vnd.crucible.native-signed-index-body.v3+json",
            )?,
            first_observation: reference(b"immutable-first-observe")?,
            current_record: reference(b"current-restored12")?,
            current_model: reference(b"current-producer2")?,
            history_prefix: reference(b"pre-upload-history-prefix")?,
            history_next_sequence: U64::new(30),
            native_schema: reference(b"whole-native17-definition")?,
            native_allocation: PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(100),
                maximum_simultaneous_transient_bytes: U64::new(200),
                declared_counter_scratch_bytes: U64::new(300),
            },
            scope,
        };
        let target = &request.scope.target;
        let arguments = serde_json::to_value(&request.capture)
            .map_err(crucible_node_contract::ContractError::from)?;
        let body = BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: target.binding_hash.clone(),
            owner_generation: target.owner_generation,
            activation_id: Nullable(Some(target.activation.clone())),
            world_generation: target.generation,
            arguments: arguments.as_object().ok_or_else(invalid)?.clone(),
            extensions: Extensions::new(),
        };
        let body =
            serde_json::to_value(body).map_err(crucible_node_contract::ContractError::from)?;
        let mut extensions = Extensions::new();
        extensions.insert(
            RESTORED_SETTLED_CAPTURE_FEATURE.into(),
            serde_json::json!({"request": &request}),
        );
        let envelope = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(target.session.clone())),
            incarnation_id: Nullable(Some(target.incarnation.clone())),
            node_id: Nullable(Some(target.node.clone())),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(Some(request.capture_owner.clone())),
            operation_id: Nullable(Some(Id::new("capture-operation")?)),
            request_id: Nullable(Some(Id::new("actual-assigned-capture")?)),
            sequence: U64::new(42),
            method: Method::Begin,
            body: body.as_object().ok_or_else(invalid)?.clone(),
            extensions,
        };
        Ok((request, envelope))
    }

    #[test]
    fn settled_capture_preserves_runtime_and_index_reference_media() -> TestResult {
        let (request, _) = fixture()?;
        request.validate_data()?;

        let mut changed = request.clone();
        changed.runtime_object.media_type = "application/json".into();
        assert!(changed.validate_data().is_err());
        changed = request.clone();
        changed.parent_archive.media_type = "application/json".into();
        assert!(changed.validate_data().is_err());

        // Other proof objects remain ordinary JSON. The two signed input
        // families do not widen the accepted media of any current proof.
        changed = request;
        changed.current_record.media_type =
            "application/vnd.crucible.native-signed-index-body.v3+json".into();
        assert!(changed.validate_data().is_err());
        Ok(())
    }

    #[test]
    fn settled_capture_digest_binds_actual_capture_routing_and_omits_only_nested_proof()
    -> TestResult {
        let (request, original) = fixture()?;
        let expected = restored_settled_capture_assigned_request_digest_data(&original, 65_536)?;
        let mut proof_filled = original.clone();
        proof_filled
            .extensions
            .get_mut(RESTORED_SETTLED_CAPTURE_FEATURE)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(invalid)?
            .insert(
                "proof".into(),
                serde_json::json!({"untrusted": "digest-projection-only"}),
            );
        assert_eq!(
            expected,
            restored_settled_capture_assigned_request_digest_data(&proof_filled, 65_536)?
        );

        let mut changed = original.clone();
        changed.execution_owner_id = Nullable(Some(request.scope.target.owner.clone()));
        assert!(restored_settled_capture_assigned_request_digest_data(&changed, 65_536).is_err());
        changed = original.clone();
        changed.capture_owner_id = Nullable(Some(Id::new("foreign-capture-owner")?));
        assert!(restored_settled_capture_assigned_request_digest_data(&changed, 65_536).is_err());
        changed = original.clone();
        changed.session_id = Nullable(Some(Id::new("foreign-session")?));
        assert!(restored_settled_capture_assigned_request_digest_data(&changed, 65_536).is_err());
        changed = original.clone();
        changed.sequence = U64::new(43);
        assert_ne!(
            expected,
            restored_settled_capture_assigned_request_digest_data(&changed, 65_536)?
        );
        Ok(())
    }

    #[test]
    fn settled_capture_mac_refuses_changed_current_checkpoint_prefix_cut_and_old_domain()
    -> TestResult {
        let (request, original) = fixture()?;
        let context = PacketRestoredSettledCaptureContext {
            schema: CONTEXT_SCHEMA.into(),
            request,
            assigned_request: Bytes::new(
                restored_settled_capture_assigned_request_digest_data(&original, 65_536)?.to_vec(),
            ),
        };
        let key = [19; 32];
        let proof = restored_settled_capture_proof_data(&key, &context)?;
        verify_restored_settled_capture_proof_data(&key, &context, &proof)?;
        let mut changed = context.clone();
        changed.request.current_record = changed.request.first_observation.clone();
        assert!(verify_restored_settled_capture_proof_data(&key, &changed, &proof).is_err());
        changed = context.clone();
        changed.request.history_next_sequence = U64::new(31);
        assert!(verify_restored_settled_capture_proof_data(&key, &changed, &proof).is_err());
        let mut old_domain = proof;
        old_domain.schema = "source-owned.packet-restoration-activation-proof/1".into();
        assert!(verify_restored_settled_capture_proof_data(&key, &context, &old_domain).is_err());
        Ok(())
    }

    #[test]
    fn settled_capture_schema_refuses_changed_full_definition_and_metadata_keeps_spare_banks()
    -> TestResult {
        let schema = restored_settled_capture_schema_data()?;
        authenticate_restored_settled_capture_schema_data(&schema)?;
        let mut changed = schema.clone();
        changed.definition.length = U64::new(changed.definition.length.get() + 1);
        assert!(authenticate_restored_settled_capture_schema_data(&changed).is_err());
        let (mut request, _) = fixture()?;
        let mut participants = Vec::with_capacity(7);
        participants.extend(request.capture.participant_ids.iter().cloned());
        request.capture.participant_ids = participants;
        let mut records = crate::retained_metadata::records::MetadataRecordBank::reserve(1024)?;
        let mut aliases = crate::retained_metadata::aliases::MetadataAliasBank::reserve(8)?;
        let mut observer = crate::retained_metadata::MetadataObserver::recording_with_aliases(
            &mut records,
            &mut aliases,
        );
        observer.observe(&request)?;
        let facts = observer.finish();
        assert!(
            facts.vector_capacity_bytes
                >= request.capture.participant_ids.capacity() * std::mem::size_of::<Id>()
        );
        assert!(!records.rows().is_empty());
        Ok(())
    }
    #[test]
    fn coordinator_checkpoint_keeps_its_own_media_and_mac_correspondence() -> TestResult {
        let (request, _) = fixture()?;
        request.validate_data()?;
        let context = PacketRestoredSettledCaptureContext {
            schema: CONTEXT_SCHEMA.to_owned(),
            request: request.clone(),
            assigned_request: Bytes::new(vec![7; 32]),
        };
        let key = [11; 32];
        let proof = restored_settled_capture_proof_data(&key, &context)?;
        verify_restored_settled_capture_proof_data(&key, &context, &proof)?;

        let mut changed = context.clone();
        changed.request.coordinator_checkpoint = canonical::content_ref(
            b"different-ordered-prefix",
            "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17",
        )?;
        assert!(verify_restored_settled_capture_proof_data(&key, &changed, &proof).is_err());
        changed.request.coordinator_checkpoint =
            reference(b"ordered-current-coordinator-checkpoint")?;
        assert!(changed.validate_data().is_err());
        Ok(())
    }
}

/// Defines two separately signed Capture-owned uploads, never generic Blob permission.
pub mod upload;
pub use upload::{
    PacketRestoredSettledCaptureUploadArtifact, PacketRestoredSettledCaptureUploadContext,
    PacketRestoredSettledCaptureUploadContinuation, PacketRestoredSettledCaptureUploadRequest,
    restored_settled_capture_upload_counter_scratch_data,
};

/// future owned String and Bytes backing are independently retained per proof.
pub const fn restored_settled_capture_proof_layout_data()
-> (&'static str, &'static str, usize, usize) {
    (PROOF_SCHEMA, "blake3-256-mac", 32, 32)
}
