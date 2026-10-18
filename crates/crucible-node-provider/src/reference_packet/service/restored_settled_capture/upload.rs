//! Binds two auxiliary transfers to the same genuine settled Capture claim.
//!
//! Source retains its real Capture ticket and pending SDK owner before the
//! first history upload. Native separately authenticates current boot/Control
//! and spends original receive credit from its preChild selected17 reservation.
//! These request/MAC helpers issue no upload lease or Capture authority.

use super::*;
use crate::bodies::BlobBeginRequest;
use crucible_node_contract::{ContractError, SchemaRef};

/// Names the separately negotiated two-object upload feature.
pub const RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE: &str =
    "source-owned.packet-restored-settled-capture-upload/17";
const REQUEST_SCHEMA: &str = "source-owned.packet-restored-settled-capture-upload-request/17";
const CONTEXT_SCHEMA: &str = "source-owned.packet-restored-settled-capture-upload-context/17";
const PROOF_SCHEMA: &str = "source-owned.packet-restored-settled-capture-upload-proof/17";
const KEY_DOMAIN: &str = "source-owned.packet-restored-settled-capture-upload-key/17";

/// Selects one closed original upload ordinal without creating its spent slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketRestoredSettledCaptureUploadOrdinal {
    /// Uploads the pre-auxiliary Source/SDK history-prefix artifact.
    HistoryPrefix,
    /// Uploads the same actual administrative ticket's current Runtime7 object.
    RuntimeObject,
}

/// Binds exact content and native construction axes to the whole Capture scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureUploadRequest {
    /// Selects this distinct upload request family.
    pub schema: String,
    /// Retains the same complete Source-admitted Capture request.
    pub capture: PacketRestoredSettledCaptureRequest,
    /// Selects exactly history prefix first, then current Runtime object.
    pub ordinal: PacketRestoredSettledCaptureUploadOrdinal,
    /// Binds the actual baseline Blob transfer identity.
    pub transfer_id: Id,
    /// Names exactly the object selected by the ordinal, including full hash/length.
    pub content: ContentRef,
    /// Accounts independent new raw/typed/terminal/bytes/correspondence owners.
    pub native_allocation: PacketNativeStartupAllocationRow,
}

impl PacketRestoredSettledCaptureUploadRequest {
    /// Checks closed content and extent correspondence without issuing a lease.
    ///
    /// # Errors
    /// Refuses another grammar, changed ordinal content, invalid scope/ID or row.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != REQUEST_SCHEMA {
            return Err(invalid());
        }
        self.capture.validate_data()?;
        self.transfer_id.validate()?;
        self.content.validate()?;
        self.native_allocation.requested_peak_data()?;
        let expected = match self.ordinal {
            PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => {
                &self.capture.history_prefix
            }
            PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => {
                &self.capture.runtime_object
            }
        };
        if &self.content != expected {
            return Err(invalid());
        }
        crate::connection::serialized_credit(
            self,
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
        )?;
        Ok(())
    }
}

/// Binds one actual assigned BlobBegin to its complete signed upload request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureUploadContext {
    /// Selects the distinct actual assigned-original context.
    pub schema: String,
    /// Retains the whole exact independently derived upload request.
    pub request: PacketRestoredSettledCaptureUploadRequest,
    /// Hashes the actual assigned Envelope with only nested proof removed.
    pub assigned_request: Bytes,
}

impl PacketRestoredSettledCaptureUploadContext {
    /// Checks complete bounded context syntax, without authenticating native state.
    ///
    /// # Errors
    /// Refuses wrong family, malformed request or a short assigned digest.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != CONTEXT_SCHEMA || self.assigned_request.as_slice().len() != 32 {
            return Err(invalid());
        }
        self.request.validate_data()?;
        crate::connection::serialized_credit(
            self,
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
        )?;
        Ok(())
    }
}

/// Retains the exact signed upload request, never a portable native scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureUploadArtifact {
    /// Retains its complete same-Capture request and independently consumed row.
    pub request: PacketRestoredSettledCaptureUploadRequest,
    /// Retains a distinct upload-domain Source MAC.
    pub proof: PacketRestorationActivationProof,
}

/// Binds a later actual Chunk/Finish to the retained verified BlobBegin attempt.
///
/// This continuation carries no new permission. Native requires the same live
/// spent slot, initial MAC context, transfer, original history and next offset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureUploadContinuation {
    /// Selects the closed continuation family.
    pub schema: String,
    /// Names the actual initially verified upload context digest.
    pub context_digest: Bytes,
    /// Retains the exact actual Capture operation from the administrative ticket.
    pub capture_operation: Id,
    /// Retains the same actual transfer identity.
    pub transfer_id: Id,
}

impl PacketRestoredSettledCaptureUploadArtifact {
    /// Checks complete request/proof syntax without issuing native permission.
    ///
    /// # Errors
    /// Refuses another proof domain, invalid request, short digests or encoded growth.
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

impl PacketRestoredSettledCaptureUploadContinuation {
    /// Checks bounded continuation DATA without finding or renewing a spent slot.
    ///
    /// # Errors
    /// Refuses another schema, short context digest or invalid operation/transfer IDs.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != "source-owned.packet-restored-settled-capture-upload-continuation/17"
            || self.context_digest.as_slice().len() != 32
        {
            return Err(invalid());
        }
        self.capture_operation.validate()?;
        self.transfer_id.validate()?;
        crate::connection::serialized_credit(
            self,
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
        )?;
        Ok(())
    }
}

/// Returns the exact independent request/context/continuation discriminators.
pub const fn restored_settled_capture_upload_schema_ids_data()
-> (&'static str, &'static str, &'static str) {
    (
        REQUEST_SCHEMA,
        CONTEXT_SCHEMA,
        "source-owned.packet-restored-settled-capture-upload-continuation/17",
    )
}

/// Hashes the complete actual BlobBegin and unsigned upload extension.
///
/// # Errors
/// Refuses wrong Capture routing, missing assignment, body/request mismatch,
/// unrelated extensions or oversized raw/canonical frame.
pub fn restored_settled_capture_upload_assigned_request_digest_data(
    original: &Envelope,
    maximum_frame: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.message != MessageKind::Request
        || original.method != Method::BlobBegin
        || original.sequence.get() == 0
        || original.request_id.0.is_none()
        || original.operation_id.0.is_some()
        || original.execution_owner_id.0.is_some()
        || original.extensions.len() != 1
    {
        return Err(invalid());
    }
    let extension = original
        .extensions
        .get(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if extension
        .keys()
        .any(|key| key != "request" && key != "proof")
    {
        return Err(invalid());
    }
    let request: PacketRestoredSettledCaptureUploadRequest =
        serde_json::from_value(extension.get("request").ok_or_else(invalid)?.clone())
            .map_err(ContractError::from)?;
    request.validate_data()?;
    if original.sequence < request.capture.history_next_sequence
        || request.ordinal == PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix
            && original.sequence != request.capture.history_next_sequence
    {
        return Err(invalid());
    }
    let target = &request.capture.scope.target;
    if original.session_id.0.as_ref() != Some(&target.session)
        || original.incarnation_id.0.as_ref() != Some(&target.incarnation)
        || original.node_id.0.as_ref() != Some(&target.node)
        || original.capture_owner_id.0.as_ref() != Some(&request.capture.capture_owner)
    {
        return Err(invalid());
    }
    let body: BlobBeginRequest =
        serde_json::from_value(serde_json::Value::Object(original.body.clone()))
            .map_err(ContractError::from)?;
    body.validate()?;
    if !body.extensions.is_empty()
        || body.transfer_id != request.transfer_id
        || body.content != request.content
    {
        return Err(invalid());
    }
    crate::connection::serialized_credit(original, maximum_frame)?;
    let mut value = serde_json::to_value(original).map_err(ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|fields| fields.get_mut(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove("proof");
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > maximum_frame {
        return Err(invalid());
    }
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn context_bytes(
    context: &PacketRestoredSettledCaptureUploadContext,
) -> Result<Vec<u8>, ProviderError> {
    context.validate_data()?;
    let bytes =
        canonical::canonical_json(&serde_json::to_value(context).map_err(ContractError::from)?)?;
    if bytes.len() > MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Hashes the actual upload context for SDK proof correspondence DATA.
///
/// # Errors
/// Refuses malformed context syntax, excessive bytes or canonical failure.
pub fn restored_settled_capture_upload_context_digest_data(
    context: &PacketRestoredSettledCaptureUploadContext,
) -> Result<[u8; 32], ProviderError> {
    Ok(*blake3::hash(&context_bytes(context)?).as_bytes())
}

/// Computes domain-separated upload proof after the genuine Source claim is held.
///
/// # Errors
/// Refuses malformed or oversized context data or canonical encoding failure.
pub fn restored_settled_capture_upload_proof_data(
    key: &[u8; 32],
    context: &PacketRestoredSettledCaptureUploadContext,
) -> Result<PacketRestorationActivationProof, ProviderError> {
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    Ok(PacketRestorationActivationProof {
        schema: PROOF_SCHEMA.into(),
        algorithm: "blake3-256-mac".into(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &bytes).as_bytes().to_vec()),
    })
}

/// Verifies proof DATA before the actual native attempt can authenticate its lease.
///
/// # Errors
/// Refuses changed key/context, wrong domain or short digest/MAC fields.
pub fn verify_restored_settled_capture_upload_proof_data(
    key: &[u8; 32],
    context: &PacketRestoredSettledCaptureUploadContext,
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

/// Compares a later assigned Chunk/Finish to the actual retained verified Begin.
///
/// This pure correspondence check never locates a native owner or authenticates
/// the Begin MAC. The genuine consumer separately requires its same spent slot,
/// append-only original ledger, exact next offset and independently funded row.
///
/// # Errors
/// Refuses changed Capture context, transfer, routing, extension or method body.
pub fn authenticate_restored_settled_capture_upload_continuation_data(
    original: &Envelope,
    context: &PacketRestoredSettledCaptureUploadContext,
    continuation: &PacketRestoredSettledCaptureUploadContinuation,
) -> Result<(), ProviderError> {
    original.validate()?;
    context.validate_data()?;
    continuation.validate_data()?;
    let request = &context.request;
    let target = &request.capture.scope.target;
    if original.message != MessageKind::Request
        || original.request_id.0.is_none()
        || original.sequence.get() == 0
        || original.operation_id.0.is_some()
        || original.execution_owner_id.0.is_some()
        || original.extensions.len() != 1
        || original.capture_owner_id.0.as_ref() != Some(&request.capture.capture_owner)
        || original.session_id.0.as_ref() != Some(&target.session)
        || original.incarnation_id.0.as_ref() != Some(&target.incarnation)
        || original.node_id.0.as_ref() != Some(&target.node)
        || continuation.capture_operation != request.capture.capture_operation
        || continuation.transfer_id != request.transfer_id
        || continuation.context_digest.as_slice()
            != restored_settled_capture_upload_context_digest_data(context)?
    {
        return Err(invalid());
    }
    let actual: PacketRestoredSettledCaptureUploadContinuation = serde_json::from_value(
        original
            .extensions
            .get(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE)
            .ok_or_else(invalid)?
            .clone(),
    )
    .map_err(ContractError::from)?;
    if actual != *continuation {
        return Err(invalid());
    }
    match crate::bodies::decode_request(original.method, &original.body)? {
        RequestBody::BlobChunk(body) => {
            body.validate()?;
            if body.transfer_id != request.transfer_id || !body.extensions.is_empty() {
                return Err(invalid());
            }
        }
        RequestBody::BlobFinish(body) => {
            body.validate()?;
            if body.transfer_id != request.transfer_id || !body.extensions.is_empty() {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledCaptureUploadRequest {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            capture,
            ordinal,
            transfer_id,
            content,
            native_allocation,
        } = self;
        observer.observe(schema)?;
        observer.observe(capture)?;
        observer.observe(&match ordinal {
            PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => 0usize,
            PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => 1,
        })?;
        observer.observe(transfer_id)?;
        observer.observe(content)?;
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

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledCaptureUploadContext {
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

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledCaptureUploadArtifact {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { request, proof } = self;
        observer.observe(request)?;
        observer.observe(proof)
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketRestoredSettledCaptureUploadContinuation {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            context_digest,
            capture_operation,
            transfer_id,
        } = self;
        observer.observe(schema)?;
        observer.observe(context_digest)?;
        observer.observe(capture_operation)?;
        observer.observe(transfer_id)
    }
}

/// Counts fixed upload DTO/result/hash/partial parser and borrowed headers.
///
/// Dynamic raw/DOM/typed/canonical/native bank demand remains separately derived
/// and admitted before this helper's callers. This fixed sum supplies no credit.
pub fn restored_settled_capture_upload_counter_scratch_data() -> usize {
    use std::mem::size_of;
    super::restored_settled_capture_contract_counter_scratch_data()
        + size_of::<PacketRestoredSettledCaptureUploadRequest>()
        + size_of::<PacketRestoredSettledCaptureUploadContext>()
        + size_of::<PacketRestoredSettledCaptureUploadArtifact>()
        + size_of::<PacketRestoredSettledCaptureUploadContinuation>()
        + size_of::<PacketRestoredSettledCaptureUploadOrdinal>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadRequest, serde_json::Error>>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadContinuation, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationProof, ProviderError>>()
        + size_of::<BlobBeginRequest>()
        + size_of::<Result<BlobBeginRequest, serde_json::Error>>()
        + size_of::<Result<crate::bodies::RequestBody, ProviderError>>()
        + size_of::<serde_json::Value>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, ContractError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<[u8; 32]>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Option<&'static serde_json::Value>>()
        + size_of::<Option<&'static serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Result<&'static serde_json::Value, ProviderError>>()
        + size_of::<Result<&'static serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<Option<&'static mut serde_json::Value>>()
        + size_of::<Option<&'static mut serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Result<&'static mut serde_json::Map<String, serde_json::Value>, ProviderError>>(
        )
        + size_of::<serde_json::map::Keys<'static>>()
        + super::field_view_bytes(
            |value: &'static PacketRestoredSettledCaptureUploadRequest| {
                let PacketRestoredSettledCaptureUploadRequest {
                    schema,
                    capture,
                    ordinal,
                    transfer_id,
                    content,
                    native_allocation,
                } = value;
                (
                    schema,
                    capture,
                    ordinal,
                    transfer_id,
                    content,
                    native_allocation,
                )
            },
        )
        + super::field_view_bytes(
            |value: &'static PacketRestoredSettledCaptureUploadContext| {
                let PacketRestoredSettledCaptureUploadContext {
                    schema,
                    request,
                    assigned_request,
                } = value;
                (schema, request, assigned_request)
            },
        )
        + super::field_view_bytes(
            |value: &'static PacketRestoredSettledCaptureUploadContinuation| {
                let PacketRestoredSettledCaptureUploadContinuation {
                    schema,
                    context_digest,
                    capture_operation,
                    transfer_id,
                } = value;
                (schema, context_digest, capture_operation, transfer_id)
            },
        )
}

const CONTRACT_BYTES: &[u8] = include_bytes!("upload_contract17.json");

/// Borrows the complete compiled two-object CaptureUpload17 DATA definition.
pub const fn restored_settled_capture_upload_contract_data() -> &'static [u8] {
    CONTRACT_BYTES
}

/// Returns the exact separately negotiated Capture-owned upload schema.
///
/// # Errors
/// Reports static identifier or complete content-reference construction failure.
pub fn restored_settled_capture_upload_schema_data() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE)?,
        version: 17,
        definition: canonical::content_ref(CONTRACT_BYTES, "application/json")?,
        extensions: Default::default(),
    })
}

/// Checks the full immutable definition allocation-free without issuing permission.
///
/// # Errors
/// Refuses another feature/version, extensions or changed full definition fields.
pub fn authenticate_restored_settled_capture_upload_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&(CONTRACT_BYTES.len() as u64).to_be_bytes());
    hasher.update(CONTRACT_BYTES);
    let digest = hasher.finalize().to_hex();
    if schema.id.as_str() != RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE
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

/// Counts fixed upload schema constructor/hash/comparison headers.
pub fn restored_settled_capture_upload_schema_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<SchemaRef>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<Result<ContentRef, ContractError>>()
        + size_of::<Result<Id, ContractError>>()
        + size_of::<&SchemaRef>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn fixture() -> Result<(PacketRestoredSettledCaptureUploadRequest, Envelope), ProviderError> {
        let (capture, mut original) = super::super::tests::fixture()?;
        let request = PacketRestoredSettledCaptureUploadRequest {
            schema: REQUEST_SCHEMA.into(),
            content: capture.history_prefix.clone(),
            capture,
            ordinal: PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix,
            transfer_id: Id::new("actual-prefix-transfer")?,
            native_allocation: PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(100),
                maximum_simultaneous_transient_bytes: U64::new(200),
                declared_counter_scratch_bytes: U64::new(300),
            },
        };
        original.operation_id = Nullable(None);
        original.method = Method::BlobBegin;
        original.sequence = request.capture.history_next_sequence;
        let body = serde_json::to_value(BlobBeginRequest {
            transfer_id: request.transfer_id.clone(),
            content: request.content.clone(),
            extensions: Default::default(),
        })
        .map_err(ContractError::from)?;
        original.body = body.as_object().ok_or_else(invalid)?.clone();
        original.extensions.clear();
        original.extensions.insert(
            RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(),
            serde_json::json!({"request":&request}),
        );
        Ok((request, original))
    }

    #[test]
    fn capture_owned_upload_binds_actual_prefix_cut_content_and_distinct_mac_domain() -> TestResult
    {
        let (request, original) = fixture()?;
        let assigned =
            restored_settled_capture_upload_assigned_request_digest_data(&original, 65_536)?;
        let context = PacketRestoredSettledCaptureUploadContext {
            schema: CONTEXT_SCHEMA.into(),
            request,
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        let proof = restored_settled_capture_upload_proof_data(&[31; 32], &context)?;
        verify_restored_settled_capture_upload_proof_data(&[31; 32], &context, &proof)?;
        PacketRestoredSettledCaptureUploadArtifact {
            request: context.request.clone(),
            proof: proof.clone(),
        }
        .validate_data()?;

        let mut old_domain = proof;
        old_domain.schema = "source-owned.packet-restored-settled-capture-proof/17".into();
        assert!(
            verify_restored_settled_capture_upload_proof_data(&[31; 32], &context, &old_domain)
                .is_err()
        );
        let mut changed = original.clone();
        changed.sequence = U64::new(changed.sequence.get() + 1);
        assert!(
            restored_settled_capture_upload_assigned_request_digest_data(&changed, 65_536).is_err()
        );
        let mut changed = context.request.clone();
        changed.ordinal = PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject;
        assert!(changed.validate_data().is_err());
        let mut changed = original;
        changed
            .body
            .insert("transfer_id".into(), serde_json::json!("foreign-transfer"));
        assert!(
            restored_settled_capture_upload_assigned_request_digest_data(&changed, 65_536).is_err()
        );
        let schema = restored_settled_capture_upload_schema_data()?;
        authenticate_restored_settled_capture_upload_schema_data(&schema)?;
        let mut changed = schema;
        changed.definition.length = U64::new(changed.definition.length.get() + 1);
        assert!(authenticate_restored_settled_capture_upload_schema_data(&changed).is_err());
        Ok(())
    }

    #[test]
    fn upload_continuation_requires_same_retained_context_operation_and_transfer() -> TestResult {
        let (request, mut original) = fixture()?;
        let context = PacketRestoredSettledCaptureUploadContext {
            schema: CONTEXT_SCHEMA.into(),
            assigned_request: Bytes::new(
                restored_settled_capture_upload_assigned_request_digest_data(&original, 65_536)?
                    .to_vec(),
            ),
            request,
        };
        let continuation = PacketRestoredSettledCaptureUploadContinuation {
            schema: restored_settled_capture_upload_schema_ids_data().2.into(),
            context_digest: Bytes::new(
                restored_settled_capture_upload_context_digest_data(&context)?.to_vec(),
            ),
            capture_operation: context.request.capture.capture_operation.clone(),
            transfer_id: context.request.transfer_id.clone(),
        };
        original.method = Method::BlobFinish;
        original.sequence = U64::new(original.sequence.get() + 1);
        let body = serde_json::to_value(crate::bodies::BlobFinishRequest {
            transfer_id: context.request.transfer_id.clone(),
            extensions: Default::default(),
        })
        .map_err(ContractError::from)?;
        original.body = body.as_object().ok_or_else(invalid)?.clone();
        original.extensions.insert(
            RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(),
            serde_json::to_value(&continuation).map_err(ContractError::from)?,
        );
        authenticate_restored_settled_capture_upload_continuation_data(
            &original,
            &context,
            &continuation,
        )?;
        let mut changed = continuation.clone();
        changed.capture_operation = Id::new("other-operation")?;
        assert!(
            authenticate_restored_settled_capture_upload_continuation_data(
                &original, &context, &changed
            )
            .is_err()
        );
        let mut changed = original;
        changed
            .body
            .insert("transfer_id".into(), serde_json::json!("other-transfer"));
        assert!(
            authenticate_restored_settled_capture_upload_continuation_data(
                &changed,
                &context,
                &continuation
            )
            .is_err()
        );
        Ok(())
    }
}

/// Returns exact distinct Upload17 proof fields as borrowed sizing DATA.
///
/// Source/SDK request clones and canonical/MAC work are independent terms.
/// These constants create neither a signed proof nor a native upload lease.
pub const fn restored_settled_capture_upload_proof_layout_data()
-> (&'static str, &'static str, usize, usize) {
    (PROOF_SCHEMA, "blake3-256-mac", 32, 32)
}
