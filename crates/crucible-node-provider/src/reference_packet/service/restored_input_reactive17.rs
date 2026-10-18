//! Defines Source-signed ordinary Input and Reactive actions after restoration.
//!
//! The separate edition-17 artifact commits the actual assigned Envelope and
//! latest authenticated Source/SDK checkpoint. The edition-4 input cut remains
//! nested correlation DATA. Neither DTO decoding nor a valid MAC constructs a
//! native action scope, Runtime dispatch, Window claim, or resource reservation.
//!
//! ```text
//! extensions = {"source-owned.packet-restored-input-reactive/17":
//!   {"request":{schema,command,scope,first_observation,current_record,
//!     current_model,history_prefix,history_next_sequence,native_allocation},
//!    "proof":{schema,algorithm,context_digest,mac}}}
//! ```

use crate::reference_packet::input::PacketInputContext;
use crate::reference_packet::service::complete_restore::activation::{
    PacketRestorationActivationProof, PacketRestorationActivationScope,
};
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};
use crate::{ProviderError, bodies::*, envelope::*};
use crucible_node_contract::{Bytes, ContentRef, InputBatch, SchemaRef, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

mod wire;
pub(crate) use wire::{verify_selected_wire_data, verify_selected_wire_header_data};

/// Names the separately negotiated Input/Reactive action contract.
pub const RESTORED_INPUT_REACTIVE17_FEATURE: &str =
    "source-owned.packet-restored-input-reactive/17";
/// Bounds the signed correspondence independently of full state and model banks.
pub const MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES: usize = 16_384;
const REQUEST_SCHEMA: &str = "source-owned.packet-restored-input-reactive-request/17";
const CONTEXT_SCHEMA: &str = "source-owned.packet-restored-input-reactive-context/17";
const PROOF_SCHEMA: &str = "source-owned.packet-restored-input-reactive-proof/17";
const KEY_DOMAIN: &str = "source-owned.packet-restored-input-reactive-key/17";

/// Distinguishes staging, custody commitment, and actual Reactive execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PacketRestoredInputReactive17Command {
    /// Carries the unchanged edition-4 cut as correlation data within this MAC.
    Input {
        /// Retains the exact stage or commit context, including its receipt.
        context: PacketInputContext,
    },
    /// Runs the exact independently admitted ordinary execution interval.
    Run,
    /// Settles the exact independently admitted same-time boundary interval.
    Settle,
    /// Polls the actual retained execution operation without creating a grant.
    Poll,
    /// Retires the actual consumed operation and its retained originals.
    Retire,
    /// Observes the current native model without advancing simulated execution.
    Observe,
    /// Begins the actual separately admitted input or authorization upload.
    BlobBegin,
    /// Transfers one actual bounded upload chunk.
    BlobChunk,
    /// Completes the same actual upload.
    BlobFinish,
}

impl PacketRestoredInputReactive17Command {
    /// Returns the exact baseline method for this closed command.
    pub const fn method_data(&self) -> Method {
        match self {
            Self::Input { .. } => Method::Input,
            Self::Run | Self::Settle => Method::Begin,
            Self::Poll => Method::Poll,
            Self::Retire => Method::Retire,
            Self::Observe => Method::Observe,
            Self::BlobBegin => Method::BlobBegin,
            Self::BlobChunk => Method::BlobChunk,
            Self::BlobFinish => Method::BlobFinish,
        }
    }

    /// Borrows the unchanged cut only for an actual Input command.
    pub fn input_context_data(&self) -> Option<&PacketInputContext> {
        match self {
            Self::Input { context } => Some(context),
            _ => None,
        }
    }
}

/// Reports the actual post-action native proof in the new17 response extension.
///
/// The unchanged baseline result retains its custody receipt. These references
/// additionally identify the actual restored wrapper and its complete Reactive
/// model, produced after that same original Stage or Commit. They confer no
/// consumption, scheduling, Source claim or native execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredInputReactive17PostCheckpointData {
    /// Selects the distinct closed response proof grammar.
    pub schema: String,
    /// Names the complete actual post-action restored native record.
    pub current_record: ContentRef,
    /// Names its actual complete underlying Reactive model.
    pub current_model: ContentRef,
}

impl PacketRestoredInputReactive17PostCheckpointData {
    /// Constructs bounded response correspondence from defining native outputs.
    ///
    /// # Errors
    /// Refuses invalid, empty, non-JSON or indistinguishable full references.
    pub fn from_native_outputs_data(
        current_record: ContentRef,
        current_model: ContentRef,
    ) -> Result<Self, ProviderError> {
        let result = Self {
            schema: "source-owned.packet-restored-input-reactive-post-checkpoint/17".into(),
            current_record,
            current_model,
        };
        result.validate_data()?;
        Ok(result)
    }

    /// Validates the closed post-checkpoint geometry without validating proof.
    ///
    /// # Errors
    /// Refuses another schema, invalid/empty/non-JSON references or alias roles.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != "source-owned.packet-restored-input-reactive-post-checkpoint/17"
            || self.current_record == self.current_model
        {
            return Err(invalid());
        }
        for reference in [&self.current_record, &self.current_model] {
            reference.validate()?;
            if reference.length.get() == 0
                || reference.length.get() > 65_536
                || reference.media_type != "application/json"
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(crate) fn observe_owned_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.schema)?;
        observer.observe(&self.current_record)?;
        observer.observe(&self.current_model)
    }
}

/// Borrows actual independently owned new17 Source protocol fields for census.
///
/// This closed DATA view invokes no Serialize callback, native action or grant.
pub enum PacketRestoredInputReactive17RetainedData<'a> {
    /// Borrows an actual retained unsigned request.
    Request(&'a PacketRestoredInputReactive17Request),
    /// Borrows an actual retained complete signing context.
    Context(&'a PacketRestoredInputReactive17Context),
    /// Borrows an actual retained complete signed artifact.
    Artifact(&'a PacketRestoredInputReactive17Artifact),
    /// Borrows the actual typed response checkpoint extension.
    PostCheckpoint(&'a PacketRestoredInputReactive17PostCheckpointData),
}

impl PacketRestoredInputReactive17RetainedData<'_> {
    /// Observes each actual owned field without creating authoritative state.
    ///
    /// # Errors
    /// Refuses finite metadata-counter overflow or unsupported owner geometry.
    pub fn original_retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        match self {
            Self::Request(value) => value.observe_metadata(&mut observer)?,
            Self::Context(value) => value.observe_metadata(&mut observer)?,
            Self::Artifact(value) => value.observe_metadata(&mut observer)?,
            Self::PostCheckpoint(value) => value.observe_owned_metadata_data(&mut observer)?,
        }
        Ok(observer.finish())
    }

    /// Names this closed borrowed wrapper and its direct observer/result views.
    pub const fn counter_scratch_data() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<MetadataObserver<'static>>()
            + std::mem::size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + std::mem::size_of::<
                Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>,
            >()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}

/// Binds one actual action to immutable restoration and current native history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredInputReactive17Request {
    /// Selects this closed request family.
    pub schema: String,
    /// Selects one baseline method and its exact staged-input correlation data.
    pub command: PacketRestoredInputReactive17Command,
    /// Binds the actual complete restored target and immutable Commit originals.
    pub scope: PacketRestorationActivationScope,
    /// Names the genuinely published first Observe, as immutable ancestry only.
    pub first_observation: ContentRef,
    /// Names the latest authenticated current restored proof before this action.
    pub current_record: ContentRef,
    /// Names the full underlying current Reactive or Producer model proof.
    pub current_model: ContentRef,
    /// Names the complete retained history prefix immediately before assignment.
    pub history_prefix: ContentRef,
    /// Binds the actual SDK sequence assigned to this action after that prefix.
    pub history_next_sequence: U64,
    /// Names the independently recounted and admitted native action axes.
    pub native_allocation: PacketNativeStartupAllocationRow,
}

impl PacketRestoredInputReactive17Request {
    /// Validates closed syntax while leaving all owning authority checks separate.
    ///
    /// # Errors
    /// Refuses another family, malformed correspondence, invalid cut or row overflow.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != REQUEST_SCHEMA || self.history_next_sequence.get() == 0 {
            return Err(invalid());
        }
        super::complete_restore::activation::validate_scope_data(&self.scope)?;
        self.native_allocation.requested_peak_data()?;
        for reference in [
            &self.first_observation,
            &self.current_record,
            &self.current_model,
            &self.history_prefix,
        ] {
            reference.validate()?;
            if reference.media_type != "application/json" {
                return Err(invalid());
            }
        }
        if let Some(context) = self.command.input_context_data() {
            context.cut().validate()?;
            if let PacketInputContext::Commit {
                staging_receipt, ..
            } = context
            {
                staging_receipt.validate()?;
            }
        }
        crate::connection::serialized_credit(
            self,
            MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES,
        )?;
        Ok(())
    }

    /// Checks actual routing and baseline body without constructing a permission.
    ///
    /// # Errors
    /// Refuses another method, owner, assigned sequence, body, input batch or cut.
    pub fn authenticate_assigned_data(&self, original: &Envelope) -> Result<(), ProviderError> {
        self.validate_data()?;
        original.validate()?;
        let target = &self.scope.target;
        if original.message != MessageKind::Request
            || original.method != self.command.method_data()
            || original.sequence != self.history_next_sequence
            || original.request_id.0.is_none()
            || original.session_id.0.as_ref() != Some(&target.session)
            || original.incarnation_id.0.as_ref() != Some(&target.incarnation)
            || original.node_id.0.as_ref() != Some(&target.node)
            || original.execution_owner_id.0.as_ref() != Some(&target.owner)
            || original.capture_owner_id.0.is_some()
            || matches!(
                self.command,
                PacketRestoredInputReactive17Command::Run
                    | PacketRestoredInputReactive17Command::Settle
                    | PacketRestoredInputReactive17Command::Poll
            ) != original.operation_id.0.is_some()
        {
            return Err(invalid());
        }
        let body = decode_request(original.method, &original.body)?;
        match (&self.command, body) {
            (PacketRestoredInputReactive17Command::Input { context }, RequestBody::Input(body)) => {
                authenticate_input_data(context, original, &body, &self.scope)?;
            }
            (PacketRestoredInputReactive17Command::Run, RequestBody::Begin(body))
                if body.kind == BeginKind::ExactRun =>
            {
                self.authenticate_begin_data(&body)?
            }
            (PacketRestoredInputReactive17Command::Settle, RequestBody::Begin(body))
                if body.kind == BeginKind::BoundarySettle =>
            {
                self.authenticate_begin_data(&body)?
            }
            (PacketRestoredInputReactive17Command::Poll, RequestBody::Poll(body))
                if body.after_observation_sequence.get() == 0 && body.extensions.is_empty() => {}
            (PacketRestoredInputReactive17Command::Retire, RequestBody::Retire(body))
                if body.disposition == RetirementDisposition::Consumed
                    && body.extensions.is_empty() => {}
            (PacketRestoredInputReactive17Command::Observe, RequestBody::Observe(body))
                if body.binding_hash == target.binding_hash
                    && body.owner_generation == target.owner_generation
                    && body.after_observation_sequence.get() == 0
                    && body.maximum_items.get() == 1
                    && body.extensions.is_empty() => {}
            (PacketRestoredInputReactive17Command::BlobBegin, RequestBody::BlobBegin(body))
                if body.extensions.is_empty() => {}
            (PacketRestoredInputReactive17Command::BlobChunk, RequestBody::BlobChunk(body))
                if body.extensions.is_empty() => {}
            (PacketRestoredInputReactive17Command::BlobFinish, RequestBody::BlobFinish(body))
                if body.extensions.is_empty() => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }

    fn authenticate_begin_data(&self, body: &BeginRequest) -> Result<(), ProviderError> {
        let target = &self.scope.target;
        if body.binding_hash != target.binding_hash
            || body.owner_generation != target.owner_generation
            || body.activation_id.0.as_ref() != Some(&target.activation)
            || body.world_generation != target.generation
            || !body.extensions.is_empty()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Retains the exact request and complete assigned-envelope digest for signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredInputReactive17Context {
    /// Selects the distinct action MAC context.
    pub schema: String,
    /// Retains the complete unsigned action correspondence.
    pub request: PacketRestoredInputReactive17Request,
    /// Hashes the whole assigned Envelope, omitting only its nested proof.
    pub assigned_request: Bytes,
}

/// Retains the closed Source proof without constructing a live native claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredInputReactive17Artifact {
    /// Retains the full signed request and action row.
    pub request: PacketRestoredInputReactive17Request,
    /// Retains its domain-separated Source MAC.
    pub proof: PacketRestorationActivationProof,
}

impl PacketRestoredInputReactive17Artifact {
    /// Checks closed artifact syntax without authenticating its Source key.
    ///
    /// # Errors
    /// Refuses invalid correspondence, a foreign proof family or oversized data.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.request.validate_data()?;
        validate_proof_data(&self.proof)?;
        crate::connection::serialized_credit(
            self,
            MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES,
        )?;
        Ok(())
    }
}

/// Returns the exact context discriminator without granting a signer loan.
pub const fn restored_input_reactive17_context_schema_data() -> &'static str {
    CONTEXT_SCHEMA
}
/// Returns the exact request discriminator without granting an action claim.
pub const fn restored_input_reactive17_request_schema_data() -> &'static str {
    REQUEST_SCHEMA
}

/// Commits the actual complete assigned Envelope, omitting only its nested proof.
///
/// # Errors
/// Refuses foreign or multiple extensions, unknown artifact fields, malformed
/// unsigned correspondence, changed assigned routing or excessive frame bytes.
pub fn restored_input_reactive17_assigned_request_digest_data(
    original: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    if original.extensions.len() != 1 {
        return Err(invalid());
    }
    let extension = original
        .extensions
        .get(RESTORED_INPUT_REACTIVE17_FEATURE)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if !extension.contains_key("request")
        || extension
            .keys()
            .any(|key| key != "request" && key != "proof")
    {
        return Err(invalid());
    }
    let request: PacketRestoredInputReactive17Request =
        serde::Deserialize::deserialize(extension.get("request").ok_or_else(invalid)?)
            .map_err(crucible_node_contract::ContractError::from)?;
    request.authenticate_assigned_data(original)?;
    crate::connection::serialized_credit(original, maximum_frame_bytes)?;
    let mut value =
        serde_json::to_value(original).map_err(crucible_node_contract::ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|extensions| extensions.get_mut(RESTORED_INPUT_REACTIVE17_FEATURE))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove("proof");
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > maximum_frame_bytes {
        return Err(invalid());
    }
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Computes proof DATA only after an actual Source issuer authenticates its claim.
///
/// # Errors
/// Refuses malformed or oversized context and canonical encoding failure.
pub fn restored_input_reactive17_proof_data(
    key: &[u8; 32],
    context: &PacketRestoredInputReactive17Context,
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

/// Verifies domain-separated assigned-request correspondence as DATA only.
///
/// # Errors
/// Refuses another key, changed request/assigned digest or a foreign proof family.
pub fn verify_restored_input_reactive17_proof_data(
    key: &[u8; 32],
    context: &PacketRestoredInputReactive17Context,
    proof: &PacketRestorationActivationProof,
) -> Result<(), ProviderError> {
    validate_proof_data(proof)?;
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    if blake3::hash(&bytes) != *proof.context_digest.as_slice()
        || blake3::keyed_hash(&derived, &bytes) != *proof.mac.as_slice()
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_proof_data(proof: &PacketRestorationActivationProof) -> Result<(), ProviderError> {
    if proof.schema != PROOF_SCHEMA
        || proof.algorithm != "blake3-256-mac"
        || proof.context_digest.as_slice().len() != 32
        || proof.mac.as_slice().len() != 32
    {
        return Err(invalid());
    }
    Ok(())
}

fn context_bytes(context: &PacketRestoredInputReactive17Context) -> Result<Vec<u8>, ProviderError> {
    if context.schema != CONTEXT_SCHEMA || context.assigned_request.as_slice().len() != 32 {
        return Err(invalid());
    }
    context.request.validate_data()?;
    crate::connection::serialized_credit(
        context,
        MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES,
    )?;
    let value =
        serde_json::to_value(context).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

fn authenticate_input_data(
    context: &PacketInputContext,
    original: &Envelope,
    body: &InputRequest,
    scope: &PacketRestorationActivationScope,
) -> Result<(), ProviderError> {
    let cut = context.cut();
    let target = &scope.target;
    cut.validate()?;
    body.validate()?;
    if cut.session_id != target.session
        || cut.incarnation_id != target.incarnation
        || cut.node_id != target.node
        || cut.execution_owner_id != target.owner
        || cut.owner_generation != target.owner_generation
        || cut.activation_id != target.activation
        || cut.world_generation != target.generation
        || cut.world_binding_hash != target.world
        || body.binding_hash != target.binding_hash
        || body.owner_generation != cut.owner_generation
        || body.batch_id != cut.batch_id
        || body.batch_sequence != cut.batch_sequence
        || body.input_epoch != cut.input_epoch
        || body.batch_hash != cut.batch_hash
        || !body.extensions.is_empty()
        || body.events.len() > 4
        || body.events.iter().any(|event| {
            !event.extensions.is_empty()
                || event.destination.node_id != cut.node_id
                || event.payload.length.get() > 32
        })
    {
        return Err(invalid());
    }
    if let PacketInputContext::Commit {
        input_request_id,
        staging_receipt,
        ..
    } = context
    {
        staging_receipt.validate()?;
        if original.request_id.0.as_ref() == Some(input_request_id) {
            return Err(invalid());
        }
    }
    let batch = InputBatch {
        schema_version: 1,
        execution_owner_id: target.owner.clone(),
        input_epoch: body.input_epoch.clone(),
        batch_id: body.batch_id.clone(),
        batch_sequence: body.batch_sequence,
        events: body.events.clone(),
        extensions: Default::default(),
    };
    if batch.identity()? != cut.batch_hash {
        return Err(invalid());
    }
    Ok(())
}

impl ObserveMetadata for PacketRestoredInputReactive17Command {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        if let Some(context) = self.input_context_data() {
            observer.observe(context.cut())?;
            if let PacketInputContext::Commit {
                input_request_id,
                staging_receipt,
                ..
            } = context
            {
                observer.observe(input_request_id)?;
                observer.observe(staging_receipt)?;
            }
        }
        Ok(())
    }
}

impl ObserveMetadata for PacketRestoredInputReactive17Request {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            command,
            scope,
            first_observation,
            current_record,
            current_model,
            history_prefix,
            history_next_sequence,
            native_allocation,
        } = self;
        observer.observe(schema)?;
        observer.observe(command)?;
        observer.observe(scope)?;
        observer.observe(first_observation)?;
        observer.observe(current_record)?;
        observer.observe(current_model)?;
        observer.observe(history_prefix)?;
        observer.observe(history_next_sequence)?;
        observer.observe(&native_allocation.retained_requested_bytes)?;
        observer.observe(&native_allocation.maximum_simultaneous_transient_bytes)?;
        observer.observe(&native_allocation.declared_counter_scratch_bytes)
    }
}

impl ObserveMetadata for PacketRestoredInputReactive17Context {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
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

impl ObserveMetadata for PacketRestoredInputReactive17Artifact {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { request, proof } = self;
        observer.observe(request)?;
        observer.observe(proof)
    }
}

const CONTRACT_BYTES: &[u8] = include_bytes!("restored_input_reactive17_contract.json");

/// Borrows the complete defining Input/Reactive17 contract bytes.
pub const fn restored_input_reactive17_contract_data() -> &'static [u8] {
    CONTRACT_BYTES
}

/// Constructs the exact separately negotiated Input/Reactive17 schema reference.
///
/// # Errors
/// Reports static identifier or complete content-reference construction failure.
pub fn restored_input_reactive17_schema_data() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: crucible_node_contract::Id::new(RESTORED_INPUT_REACTIVE17_FEATURE)?,
        version: 17,
        definition: canonical::content_ref(CONTRACT_BYTES, "application/json")?,
        extensions: Default::default(),
    })
}

/// Compares every schema field against the complete compiled definition.
///
/// # Errors
/// Refuses another feature/edition, extensions or changed full definition.
pub fn authenticate_restored_input_reactive17_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&(CONTRACT_BYTES.len() as u64).to_be_bytes());
    hash.update(CONTRACT_BYTES);
    let digest = hash.finalize().to_hex();
    if schema.id.as_str() != RESTORED_INPUT_REACTIVE17_FEATURE
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

/// Checks explicit negotiation of this exact installed definition as DATA.
///
/// This does not prove a received native17 reserve or issue an action scope.
///
/// # Errors
/// Refuses absent/duplicate features or any changed schema/reference field.
pub fn authenticate_restored_input_reactive17_selection_data(
    selection: &crate::reference_packet::control::PacketControlSelection,
    authority: &crate::handshake::ConnectionAuthority,
) -> Result<(), ProviderError> {
    if authority
        .selected_features()
        .iter()
        .filter(|feature| feature.as_str() == RESTORED_INPUT_REACTIVE17_FEATURE)
        .count()
        != 1
        || !authority
            .envelope_extensions()
            .contains(RESTORED_INPUT_REACTIVE17_FEATURE)
    {
        return Err(invalid());
    }
    fn formats(formats: &[SchemaRef]) -> Result<(), ProviderError> {
        let mut schemas = formats
            .iter()
            .filter(|schema| schema.id.as_str() == RESTORED_INPUT_REACTIVE17_FEATURE);
        authenticate_restored_input_reactive17_schema_data(schemas.next().ok_or_else(invalid)?)?;
        if schemas.next().is_some() {
            return Err(invalid());
        }
        Ok(())
    }

    formats(&selection.provider.implementation.formats)?;
    if selection.realization.bindings.is_empty()
        || selection
            .provider
            .extensions_supported
            .iter()
            .filter(|feature| feature.as_str() == RESTORED_INPUT_REACTIVE17_FEATURE)
            .count()
            != 1
    {
        return Err(invalid());
    }
    for binding in &selection.realization.bindings {
        formats(&binding.compatibility.implementation.formats)?;
    }
    authority.ensure_live()
}

/// Counts fixed DTO, borrowed, codec, hash and result headers for this contract.
///
/// Dynamic typed, DOM, canonical and request/terminal owners require their own
/// independently admitted defining storage terms; this sum grants no credit.
pub fn restored_input_reactive17_contract_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<PacketRestoredInputReactive17Request>()
        + size_of::<PacketRestoredInputReactive17Context>()
        + size_of::<PacketRestoredInputReactive17Artifact>()
        + size_of::<PacketRestoredInputReactive17Command>()
        + size_of::<PacketRestoredInputReactive17PostCheckpointData>()
        + size_of::<Result<PacketRestoredInputReactive17PostCheckpointData, serde_json::Error>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<&crate::handshake::ConnectionAuthority>()
        + size_of::<&crate::reference_packet::control::PacketControlSelection>()
        + size_of::<&crate::connection::ReceivedBody>()
        + size_of::<&[SchemaRef]>()
        + size_of::<std::slice::Iter<'static, SchemaRef>>()
        + size_of::<Option<&SchemaRef>>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::NodeBinding>>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::Id>>()
        + size_of::<&crucible_node_contract::NodeBinding>()
        + size_of::<Result<&SchemaRef, ProviderError>>()
        + size_of::<[&str; 10]>()
        + size_of::<PacketRestorationActivationProof>()
        + size_of::<Result<PacketRestoredInputReactive17Request, serde_json::Error>>()
        + size_of::<Result<PacketRestoredInputReactive17Artifact, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationProof, ProviderError>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<Result<RequestBody, ProviderError>>()
        + size_of::<RequestBody>()
        + size_of::<InputBatch>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
        + size_of::<Option<&PacketInputContext>>()
        + size_of::<&PacketRestorationActivationScope>()
        + size_of::<&PacketRestoredInputReactive17Request>()
        + size_of::<&PacketRestoredInputReactive17Artifact>()
        + size_of::<&PacketRestoredInputReactive17Context>()
        + size_of::<Option<&serde_json::Value>>()
        + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Option<&mut serde_json::Value>>()
        + size_of::<Option<&mut serde_json::Map<String, serde_json::Value>>>()
        + size_of::<serde_json::map::Keys<'static>>()
        + size_of::<[&ContentRef; 4]>()
        + size_of::<std::array::IntoIter<&'static ContentRef, 4>>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::SchemaRef>>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::Event>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<MetadataObserver<'static>>()
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored Input/Reactive17 signed correspondence differs")
}

// crucible-lint: allow panic-shortcut -- closed proof DATA correspondence is the observation.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crucible_node_contract::{Extensions, Id, Phase, Position};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // This fixture has no Controller, Runtime, Source, Window or native scope.
    pub(crate) fn fixture()
    -> Result<(PacketRestoredInputReactive17Request, Envelope), ProviderError> {
        let scope = super::super::complete_restore::activation::tests::request()?.scope;
        let target = &scope.target;
        let epoch = Id::new("signed17-original-epoch")?;
        let batch = InputBatch {
            schema_version: 1,
            execution_owner_id: target.owner.clone(),
            input_epoch: epoch.clone(),
            batch_id: Id::new("signed17-original-batch")?,
            batch_sequence: U64::new(1),
            events: Vec::new(),
            extensions: Extensions::new(),
        };
        let cut = crate::reference_packet::input::PacketInputCut {
            schema_version: 4,
            session_id: target.session.clone(),
            incarnation_id: target.incarnation.clone(),
            node_id: target.node.clone(),
            execution_owner_id: target.owner.clone(),
            owner_generation: target.owner_generation,
            activation_id: target.activation.clone(),
            world_generation: target.generation,
            world_binding_hash: target.world.clone(),
            stage_operation_id: Id::new("signed17-original-stage")?,
            batch_id: batch.batch_id.clone(),
            batch_sequence: batch.batch_sequence,
            input_epoch: epoch.clone(),
            batch_hash: batch.identity()?,
            delivery_inventory: canonical::content_ref(
                b"[]",
                "application/vnd.crucible.input-inventory+json",
            )?,
            cutoff: Position::new(U64::new(7), U64::new(2), Phase::Reaction),
        };
        let request = PacketRestoredInputReactive17Request {
            schema: REQUEST_SCHEMA.into(),
            command: PacketRestoredInputReactive17Command::Input {
                context: PacketInputContext::Stage { cut },
            },
            first_observation: canonical::content_ref(
                b"immutable-first-observe",
                "application/json",
            )?,
            current_record: canonical::content_ref(
                b"actual-current-restored12",
                "application/json",
            )?,
            current_model: canonical::content_ref(b"actual-current-reactive4", "application/json")?,
            history_prefix: canonical::content_ref(b"actual-complete-prefix", "application/json")?,
            history_next_sequence: U64::new(73),
            native_allocation: PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(17),
                maximum_simultaneous_transient_bytes: U64::new(19),
                declared_counter_scratch_bytes: U64::new(23),
            },
            scope,
        };
        let target = &request.scope.target;
        let batch_hash = batch.identity()?;
        let body = InputRequest {
            binding_hash: target.binding_hash.clone(),
            owner_generation: target.owner_generation,
            batch_id: batch.batch_id,
            batch_sequence: batch.batch_sequence,
            input_epoch: epoch,
            batch_hash,
            events: batch.events,
            extensions: Extensions::new(),
        };
        let mut original = crate::envelope::tests::request();
        original.method = Method::Input;
        original.sequence = request.history_next_sequence;
        original.session_id = Nullable(Some(target.session.clone()));
        original.incarnation_id = Nullable(Some(target.incarnation.clone()));
        original.node_id = Nullable(Some(target.node.clone()));
        original.execution_owner_id = Nullable(Some(target.owner.clone()));
        original.capture_owner_id = Nullable(None);
        original.operation_id = Nullable(None);
        original.body = serde_json::to_value(body)
            .map_err(crucible_node_contract::ContractError::from)?
            .as_object()
            .ok_or_else(invalid)?
            .clone();
        original.extensions = Extensions::from_iter([(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            serde_json::json!({"request":&request}),
        )]);
        Ok((request, original))
    }

    pub(crate) fn sealed_fixture(key: &[u8; 32]) -> Result<Envelope, ProviderError> {
        let (request, mut original) = fixture()?;
        let context = PacketRestoredInputReactive17Context {
            schema: CONTEXT_SCHEMA.into(),
            request: request.clone(),
            assigned_request: Bytes::new(
                restored_input_reactive17_assigned_request_digest_data(&original, 65_536)?.to_vec(),
            ),
        };
        let artifact = PacketRestoredInputReactive17Artifact {
            request,
            proof: restored_input_reactive17_proof_data(key, &context)?,
        };
        original.extensions.insert(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            serde_json::to_value(artifact).map_err(crucible_node_contract::ContractError::from)?,
        );
        Ok(original)
    }

    #[test]
    fn input17_commits_whole_assignment_and_only_omits_its_own_nested_proof() -> TestResult {
        let (_, original) = fixture()?;
        let digest = restored_input_reactive17_assigned_request_digest_data(&original, 65_536)?;
        let mut sealed = original.clone();
        sealed
            .extensions
            .get_mut(RESTORED_INPUT_REACTIVE17_FEATURE)
            .unwrap()["proof"] = serde_json::json!({"untrusted":"digest-projection-only"});
        assert_eq!(
            digest,
            restored_input_reactive17_assigned_request_digest_data(&sealed, 65_536)?
        );

        let mut changed = original.clone();
        changed.request_id = Nullable(Some(Id::new("another-original")?));
        assert_ne!(
            digest,
            restored_input_reactive17_assigned_request_digest_data(&changed, 65_536)?
        );
        changed = original.clone();
        changed.sequence = U64::new(74);
        assert!(restored_input_reactive17_assigned_request_digest_data(&changed, 65_536).is_err());
        changed = original.clone();
        changed
            .extensions
            .get_mut(RESTORED_INPUT_REACTIVE17_FEATURE)
            .unwrap()["unrecognized"] = serde_json::json!(true);
        assert!(restored_input_reactive17_assigned_request_digest_data(&changed, 65_536).is_err());
        changed = original;
        changed.extensions.insert(
            crate::reference_packet::input::PACKET_INPUT_FEATURE.into(),
            serde_json::json!({}),
        );
        assert!(restored_input_reactive17_assigned_request_digest_data(&changed, 65_536).is_err());
        Ok(())
    }

    #[test]
    fn input17_mac_binds_current_frontier_cut_phase_row_and_source_domain() -> TestResult {
        let (request, original) = fixture()?;
        let context = PacketRestoredInputReactive17Context {
            schema: CONTEXT_SCHEMA.into(),
            request,
            assigned_request: Bytes::new(
                restored_input_reactive17_assigned_request_digest_data(&original, 65_536)?.to_vec(),
            ),
        };
        let key = [31; 32];
        let proof = restored_input_reactive17_proof_data(&key, &context)?;
        verify_restored_input_reactive17_proof_data(&key, &context, &proof)?;
        assert!(verify_restored_input_reactive17_proof_data(&[32; 32], &context, &proof).is_err());
        for mutation in 0..5 {
            let mut changed = context.clone();
            match mutation {
                0 => changed.request.current_record = changed.request.first_observation.clone(),
                1 => changed.request.history_next_sequence = U64::new(74),
                2 => changed.request.command = PacketRestoredInputReactive17Command::Poll,
                3 => {
                    changed
                        .request
                        .native_allocation
                        .declared_counter_scratch_bytes = U64::new(24)
                }
                _ => changed.assigned_request = Bytes::new(vec![1; 32]),
            }
            assert!(verify_restored_input_reactive17_proof_data(&key, &changed, &proof).is_err());
        }
        let mut old = proof;
        old.schema = "source-owned.packet-restoration-activation-proof/1".into();
        assert!(verify_restored_input_reactive17_proof_data(&key, &context, &old).is_err());
        Ok(())
    }

    #[test]
    fn input17_cut_stays_exact_and_old_input4_sibling_parser_remains_closed() -> TestResult {
        let original = sealed_fixture(&[31; 32])?;
        assert!(PacketInputContext::decode(&original.extensions).is_err());
        let artifact: PacketRestoredInputReactive17Artifact = serde::Deserialize::deserialize(
            original
                .extensions
                .get(RESTORED_INPUT_REACTIVE17_FEATURE)
                .unwrap(),
        )?;
        let context = artifact.request.command.input_context_data().unwrap();
        assert_eq!(context.cut().cutoff.microstep, U64::new(2));
        assert_eq!(context.cut().cutoff.phase, Phase::Reaction);
        let old = Extensions::from_iter([(
            crate::reference_packet::input::PACKET_INPUT_FEATURE.into(),
            serde_json::to_value(context)?,
        )]);
        assert_eq!(PacketInputContext::decode(&old)?, *context);
        let mut changed = original;
        changed.extensions = old;
        assert!(restored_input_reactive17_assigned_request_digest_data(&changed, 65_536).is_err());
        Ok(())
    }

    #[test]
    fn input17_post_checkpoint_keeps_distinct_complete_proof_roles_and_closed_fields() -> TestResult
    {
        let restored = canonical::content_ref(b"actual restored proof", "application/json")?;
        let model = canonical::content_ref(b"actual Reactive model", "application/json")?;
        let checkpoint = PacketRestoredInputReactive17PostCheckpointData::from_native_outputs_data(
            restored.clone(),
            model.clone(),
        )?;
        checkpoint.validate_data()?;
        let mut changed = checkpoint.clone();
        changed.current_model = restored;
        assert!(changed.validate_data().is_err());
        changed = checkpoint.clone();
        changed.current_record.length = U64::new(65_537);
        assert!(changed.validate_data().is_err());
        changed = checkpoint.clone();
        changed.schema = "source-owned.packet-restoration-observe/1".into();
        assert!(changed.validate_data().is_err());
        let mut encoded = serde_json::to_value(&checkpoint)?;
        encoded["unrecognized"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<PacketRestoredInputReactive17PostCheckpointData>(encoded)
                .is_err()
        );
        let facts = PacketRestoredInputReactive17RetainedData::PostCheckpoint(&checkpoint)
            .original_retained_metadata_data()?;
        assert!(facts.string_capacity_bytes >= checkpoint.schema.len() + model.media_type.len());
        Ok(())
    }

    #[test]
    fn input17_schema_uses_whole_compiled_definition() -> TestResult {
        let schema = restored_input_reactive17_schema_data()?;
        authenticate_restored_input_reactive17_schema_data(&schema)?;
        let mut changed = schema.clone();
        changed.definition.media_type = "application/octet-stream".into();
        assert!(authenticate_restored_input_reactive17_schema_data(&changed).is_err());
        changed = schema;
        changed.definition.length = U64::new(changed.definition.length.get() + 1);
        assert!(authenticate_restored_input_reactive17_schema_data(&changed).is_err());
        Ok(())
    }
}
