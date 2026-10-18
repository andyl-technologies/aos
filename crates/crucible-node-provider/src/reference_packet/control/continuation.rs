//! Captures complete original model and native control state without transport authority.
//!
//! This is one component of Native5 preservation. The enclosing source must
//! independently capture the same endpoint, outstanding Capture reservation,
//! protocol suffix and host custody. These bytes never install a continuation.
//!
//! ```text
//! {schema: "source-owned.packet-native-control-state/5", captured_process,
//!  administrative_cut, local_cursor, model, control: {all original fields}}
//! ```
//!
//! Explicitly selected allocation capture uses edition 6 and includes the
//! original `complete_capture_allocation_selection` in `control`. Edition 5
//! forbids that key, including null; neither edition grants restoration rights.
//!
//! ```text
//! {schema: "source-owned.packet-native-control-state/6", ...,
//!  control: {..., complete_capture_allocation_selection: "original_observe12"}}
//! ```

use super::super::continuation_models::PacketOriginalModelSnapshot;
use super::*;

const SCHEMA: &str = "source-owned.packet-native-control-state/5";
const CAPTURE_ALLOCATION_SCHEMA: &str = "source-owned.packet-native-control-state/6";
const MAXIMUM_BYTES: usize = 8 * 1024 * 1024;

/// Retains complete bytes produced directly from the same native control allocation.
///
/// It excludes endpoint sockets, blob receiver and correlation state. Those
/// mandatory owners require the same Capture ticket and independent closure;
/// this component grants no capture, readiness or fresh-adoption authority.
pub struct PacketOriginalControlSnapshot {
    reference: ContentRef,
    bytes: Vec<u8>,
    administrative_cut: Position,
    local_cursor: Position,
}

impl PacketOriginalControlSnapshot {
    /// Borrows the complete canonical control/model object identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows every original canonical state byte.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn retained_encoded_capacity_data(&self) -> usize {
        self.bytes.capacity()
    }

    /// Returns the complete administrative cut independently of the local cursor.
    pub fn administrative_cut(&self) -> Position {
        self.administrative_cut
    }

    /// Returns the actual original model cursor without advancing it.
    pub fn local_cursor(&self) -> Position {
        self.local_cursor
    }
}

#[derive(Serialize)]
struct ControlView<'a> {
    selection: &'a PacketControlSelection,
    originals: Vec<OriginalView<'a>>,
    begins: &'a BTreeMap<Id, BeginRequest>,
    begin_requests: &'a BTreeMap<Id, Id>,
    content: Vec<(&'a ContentRef, &'a [u8])>,
    content_bytes: usize,
    realized: bool,
    admitted: bool,
    staged: &'a Option<(ActivateRequest, ContentRef)>,
    active: &'a Option<WorldActivateRequest>,
    fenced: bool,
    native_effect_attempted: bool,
    immediate: bool,
    current_operation: &'a Option<Id>,
    terminals: &'a BTreeMap<Id, Map<String, Value>>,
    common_coordinator: &'a Option<super::super::coordinator::PacketCoordinatorInstallation>,
    world_coordinator: &'a Option<super::super::coordinator::PacketWorldCoordinatorInstallation>,
    connected_coordinator:
        &'a Option<super::super::coordinator::PacketConnectedCoordinatorInstallation>,
    complete_coordinator:
        &'a Option<super::super::coordinator::PacketNative5CoordinatorInstallation>,
    complete_storage: &'a Option<super::native5::PacketNative5StorageSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_capture_profile: &'a Option<super::super::service::PacketNative5CaptureProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_confirmation_selection:
        &'a Option<super::super::service::PacketNative5ConfirmationSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_ack_emitter_selection:
        &'a Option<super::super::service::PacketNative5AckEmitterSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_protocol_metadata_limits:
        &'a Option<super::super::service::PacketNative5ProtocolMetadataLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_protocol_metadata_birth_facts:
        &'a Option<super::super::service::PacketNative5ProtocolMetadataBirthFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_restore_selection:
        &'a Option<super::super::service::complete_restore::PacketNative5CompleteRestoreSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_restore_input_emitter_selection: &'a Option<
        super::super::service::complete_restore::PacketNative5RestoreInputEmitterSelection,
    >,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_capture_allocation_selection: &'a Option<
        super::super::service::capture_allocation::PacketNative5CaptureAllocationSelection,
    >,
}

#[derive(Serialize)]
struct OriginalView<'a> {
    request: &'a Id,
    identity: &'a HashRef,
    response_body: &'a Map<String, Value>,
    evidence: &'a [(ContentRef, Vec<u8>)],
}

#[derive(Serialize)]
struct SnapshotView<'a> {
    schema: &'static str,
    captured_process: U64,
    administrative_cut: Position,
    local_cursor: Position,
    model: &'a Value,
    control: ControlView<'a>,
}

impl PacketControl {
    /// Captures complete control/model bytes at the actual stopped local cursor.
    ///
    /// The global administrative cut is retained separately. No cursor, gate,
    /// journal, credit or pending phase changes. The source's actual ticket and
    /// endpoint fence remain independent prerequisites for a whole capture.
    ///
    /// # Errors
    /// Refuses invalid finite limits, a cut preceding the actual cursor, missing
    /// model ownership, oversized complete state or changed full source bytes.
    pub fn capture_control_state(
        &self,
        administrative_cut: Position,
        maximum_bytes: usize,
    ) -> Result<PacketOriginalControlSnapshot, ProviderError> {
        if self.complete_capture_allocation_selection.is_some() {
            return Err(ProviderError::Correlation(
                "native selected Control6 publisher unavailable",
            ));
        }
        administrative_cut.validate()?;
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "packet whole control snapshot ceiling",
            ));
        }
        if self.complete_capture_allocation_selection.is_some() {
            self.authenticate_complete_capture_allocation_selection(
                self.complete_capture_allocation_selection,
            )?;
        }
        let local_cursor = self.program.inventory()?.reached;
        if administrative_cut < local_cursor {
            return Err(ProviderError::Correlation(
                "packet administrative cut precedes local cursor",
            ));
        }
        let model: PacketOriginalModelSnapshot = match &self.program {
            NativeProgram::OutputOnly(program) => {
                program.capture_state(local_cursor, maximum_bytes)?
            }
            NativeProgram::Connected(program) => {
                program.capture_state(local_cursor, maximum_bytes)?
            }
            NativeProgram::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        };
        model.reference().verify(model.bytes())?;
        let model_value = canonical::parse_json(model.bytes(), maximum_bytes)?;
        let mut originals = Vec::new();
        originals
            .try_reserve_exact(self.originals.len())
            .map_err(|_| {
                ProviderError::ResourceExhausted("packet original control snapshot slots")
            })?;
        for (request, (identity, reply)) in &self.originals {
            originals.push(OriginalView {
                request,
                identity,
                response_body: &reply.body,
                evidence: &reply.evidence,
            });
        }
        let mut content = Vec::new();
        content
            .try_reserve_exact(self.content.len())
            .map_err(|_| ProviderError::ResourceExhausted("packet content snapshot slots"))?;
        for (reference, bytes) in &self.content {
            reference.verify(bytes)?;
            content.push((reference, bytes.as_slice()));
        }
        let view = SnapshotView {
            schema: if self.complete_capture_allocation_selection.is_some() {
                CAPTURE_ALLOCATION_SCHEMA
            } else {
                SCHEMA
            },
            captured_process: U64::new(u64::from(std::process::id())),
            administrative_cut,
            local_cursor,
            model: &model_value,
            control: ControlView {
                selection: &self.selection,
                originals,
                begins: &self.begins,
                begin_requests: &self.begin_requests,
                content,
                content_bytes: self.content_bytes,
                realized: self.realized,
                admitted: self.admitted,
                staged: &self.staged,
                active: &self.active,
                fenced: self.fenced,
                native_effect_attempted: self.native_effect_attempted,
                immediate: self.immediate,
                current_operation: &self.current_operation,
                terminals: &self.terminals,
                common_coordinator: &self.common_coordinator,
                world_coordinator: &self.world_coordinator,
                connected_coordinator: &self.connected_coordinator,
                complete_coordinator: &self.complete_coordinator,
                complete_storage: &self.complete_storage,
                complete_capture_profile: &self.complete_capture_profile,
                complete_confirmation_selection: &self.complete_confirmation_selection,
                complete_ack_emitter_selection: &self.complete_ack_emitter_selection,
                complete_protocol_metadata_limits: &self.complete_protocol_metadata_limits,
                complete_protocol_metadata_birth_facts: &self
                    .complete_protocol_metadata_birth_facts,
                complete_restore_selection: &self.complete_restore_selection,
                complete_restore_input_emitter_selection: &self
                    .complete_restore_input_emitter_selection,
                complete_capture_allocation_selection: &self.complete_capture_allocation_selection,
            },
        };
        crate::connection::serialized_credit(&view, maximum_bytes)?;
        let value = serde_json::to_value(view).map_err(ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        canonical::parse_json(&bytes, maximum_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        Ok(PacketOriginalControlSnapshot {
            reference,
            bytes,
            administrative_cut,
            local_cursor,
        })
    }
}

/// Holds decoded control/model data without original ownership or adoption permission.
///
/// The installed source must independently authenticate its complete original
/// capture, endpoint/client journals and fresh target before reconstructing an
/// actor. This wrapper cannot satisfy any native capture or restoration trait.
pub struct PacketDecodedControlSnapshot {
    record: ControlRecord,
    model: super::super::continuation_models::PacketDecodedModelSnapshot,
}

impl PacketDecodedControlSnapshot {
    pub(super) fn into_original_model_parts(
        self,
    ) -> (
        ControlRecord,
        super::super::continuation_models::PacketDecodedModelSnapshot,
    ) {
        (self.record, self.model)
    }

    /// Returns the retained administrative cut without changing model time.
    pub fn administrative_cut(&self) -> Position {
        self.record.administrative_cut
    }

    /// Returns the distinct retained original local model cursor.
    pub fn local_cursor(&self) -> Position {
        self.record.local_cursor
    }

    /// Returns the explicit historical allocation family without granting live currency.
    pub fn capture_allocation_selection(
        &self,
    ) -> Option<super::super::service::capture_allocation::PacketNative5CaptureAllocationSelection>
    {
        self.record.control.complete_capture_allocation_selection
    }

    /// Borrows bounded decoded model data without transferring native authority.
    pub fn model(&self) -> &super::super::continuation_models::PacketDecodedModelSnapshot {
        &self.model
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlRecord {
    schema: String,
    captured_process: U64,
    administrative_cut: Position,
    local_cursor: Position,
    model: Value,
    control: ControlState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains the control state shared with its enclosing historical record.
pub(super) struct ControlState {
    selection: PacketControlSelection,
    originals: Vec<OriginalRecord>,
    begins: BTreeMap<Id, BeginRequest>,
    begin_requests: BTreeMap<Id, Id>,
    content: Vec<(ContentRef, Vec<u8>)>,
    content_bytes: usize,
    realized: bool,
    admitted: bool,
    staged: Option<(ActivateRequest, ContentRef)>,
    active: Option<WorldActivateRequest>,
    fenced: bool,
    native_effect_attempted: bool,
    immediate: bool,
    current_operation: Option<Id>,
    terminals: BTreeMap<Id, Map<String, Value>>,
    common_coordinator: Option<super::super::coordinator::PacketCoordinatorInstallation>,
    world_coordinator: Option<super::super::coordinator::PacketWorldCoordinatorInstallation>,
    connected_coordinator:
        Option<super::super::coordinator::PacketConnectedCoordinatorInstallation>,
    complete_coordinator: Option<super::super::coordinator::PacketNative5CoordinatorInstallation>,
    complete_storage: Option<super::native5::PacketNative5StorageSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_capture_profile: Option<super::super::service::PacketNative5CaptureProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_confirmation_selection:
        Option<super::super::service::PacketNative5ConfirmationSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_ack_emitter_selection: Option<super::super::service::PacketNative5AckEmitterSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_protocol_metadata_limits:
        Option<super::super::service::PacketNative5ProtocolMetadataLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_protocol_metadata_birth_facts:
        Option<super::super::service::PacketNative5ProtocolMetadataBirthFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_restore_selection:
        Option<super::super::service::complete_restore::PacketNative5CompleteRestoreSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_restore_input_emitter_selection:
        Option<super::super::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    complete_capture_allocation_selection:
        Option<super::super::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains an original control response and all of its evidence children.
pub(super) struct OriginalRecord {
    request: Id,
    identity: HashRef,
    response_body: Map<String, Value>,
    evidence: Vec<(ContentRef, Vec<u8>)>,
}

/// Decodes complete bounded control/model data independently of restoration authority.
///
/// # Errors
/// Refuses wrong full typed references, duplicate or unknown fields, noncanonical
/// bytes, oversized complete state, invalid local/global cuts or mismatched model
/// process/configuration/cursor. Original native and transport authenticity remains
/// a separate mandatory source-owned conjunction.
pub fn decode_packet_control_snapshot(
    bytes: &[u8],
    reference: &ContentRef,
    maximum_bytes: usize,
) -> Result<PacketDecodedControlSnapshot, ProviderError> {
    if maximum_bytes == 0 || maximum_bytes > MAXIMUM_BYTES || bytes.len() > maximum_bytes {
        return Err(ProviderError::ResourceExhausted(
            "packet control snapshot bytes",
        ));
    }
    reference.verify(bytes)?;
    if canonical::content_ref(bytes, "application/json")? != *reference {
        return Err(ProviderError::Correlation(
            "packet control snapshot content role",
        ));
    }
    let value = canonical::parse_json(bytes, maximum_bytes)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(ProviderError::Correlation(
            "packet control snapshot canonical bytes",
        ));
    }
    // Check key presence before Option deserialization can erase explicit null.
    authenticate_control_edition_data(&value)?;
    let record: ControlRecord = serde_json::from_value(value).map_err(ContractError::from)?;
    if record.captured_process.get() == 0 || record.local_cursor > record.administrative_cut {
        return Err(ProviderError::Correlation(
            "packet complete control snapshot scope",
        ));
    }
    record.local_cursor.validate()?;
    record.administrative_cut.validate()?;
    let model_bytes = canonical::canonical_json(&record.model)?;
    let model_ref = canonical::content_ref(&model_bytes, "application/json")?;
    let model = super::super::continuation_models::decode_packet_model_snapshot(
        &model_bytes,
        &model_ref,
        maximum_bytes,
    )?;
    if record.model.get("captured_process")
        != Some(&Value::String(record.captured_process.to_string()))
        || record.model.get("cut")
            != Some(&serde_json::to_value(record.local_cursor).map_err(ContractError::from)?)
        || record.model.get("configuration")
            != Some(
                &serde_json::to_value(&record.control.selection.realize.configuration)
                    .map_err(ContractError::from)?,
            )
    {
        return Err(ProviderError::Correlation(
            "packet original control/model association",
        ));
    }
    record.control.validate()?;
    let complete = serde_json::to_value(&record).map_err(ContractError::from)?;
    if canonical::canonical_json(&complete)? != bytes {
        return Err(ProviderError::Correlation(
            "packet complete control roundtrip changed",
        ));
    }
    Ok(PacketDecodedControlSnapshot { record, model })
}

// This closed edition discriminator borrows the already parsed input. It does
// not build a definition, normalize bytes or infer a selected family from null.
fn authenticate_control_edition_data(value: &Value) -> Result<(), ProviderError> {
    let schema = value.get("schema").and_then(Value::as_str);
    let control =
        value
            .get("control")
            .and_then(Value::as_object)
            .ok_or(ProviderError::Correlation(
                "packet complete Control object absent",
            ))?;
    let selection = control.get("complete_capture_allocation_selection");
    match (schema, selection) {
        (Some(SCHEMA), None) => Ok(()),
        (Some(CAPTURE_ALLOCATION_SCHEMA), Some(Value::String(selected)))
            if selected == "original_observe12" =>
        {
            Ok(())
        }
        _ => Err(ProviderError::Correlation(
            "packet complete Control edition/selection differs",
        )),
    }
}

impl ControlState {
    fn validate(&self) -> Result<(), ProviderError> {
        self.selection.provider.validate()?;
        self.selection.realization.validate()?;
        self.selection.realize.validate()?;
        self.selection.world.validate()?;
        if self.originals.len() > ORIGINALS
            || self.content.len() > OBJECTS
            || self.content_bytes > CONTENT_BYTES
            || self.begins.len() > ORIGINALS
            || self.begin_requests.len() > ORIGINALS
            || self.terminals.len() > ORIGINALS
            || self
                .originals
                .windows(2)
                .any(|pair| pair[0].request >= pair[1].request)
            || self.content.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(ProviderError::ResourceExhausted(
                "packet captured control inventory",
            ));
        }
        let mut content_bytes = 0usize;
        for (reference, bytes) in &self.content {
            reference.verify(bytes)?;
            content_bytes =
                content_bytes
                    .checked_add(bytes.len())
                    .ok_or(ProviderError::ResourceExhausted(
                        "packet captured content bytes",
                    ))?;
        }
        if content_bytes != self.content_bytes {
            return Err(ProviderError::Correlation(
                "packet captured content credit changed",
            ));
        }
        for original in &self.originals {
            original.request.validate()?;
            original.identity.validate()?;
            crate::bodies::decode_response_shape(&original.response_body)?;
            for (reference, bytes) in &original.evidence {
                reference.verify(bytes)?;
            }
        }
        for (operation, begin) in &self.begins {
            operation.validate()?;
            begin.validate()?;
        }
        for (operation, request) in &self.begin_requests {
            operation.validate()?;
            request.validate()?;
        }
        for (operation, body) in &self.terminals {
            operation.validate()?;
            crate::connection::serialized_credit(body, FRAME)?;
        }
        if let Some((request, receipt)) = &self.staged {
            request.validate()?;
            receipt.validate()?;
        }
        if let Some(request) = &self.active {
            request.validate()?;
        }
        match (&self.complete_coordinator, &self.complete_storage) {
            (Some(_), Some(selected)) => selected.validate()?,
            (None, None) => {}
            _ => {
                return Err(ProviderError::Correlation(
                    "native5 captured storage/coordinator mixture",
                ));
            }
        }
        if let Some(profile) = &self.complete_capture_profile {
            if self.complete_coordinator.is_none() || self.complete_storage.is_none() {
                return Err(ProviderError::Correlation(
                    "native5 captured profile lacks original birth storage",
                ));
            }
            profile.validate()?;
        }
        let owned_protocol = matches!(
            self.complete_capture_profile,
            Some(super::super::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
        );
        if owned_protocol != self.complete_protocol_metadata_limits.is_some() {
            return Err(ProviderError::Correlation(
                "native5 captured protocol metadata profile differs",
            ));
        }
        if let Some(metadata) = self.complete_protocol_metadata_limits {
            metadata.validate_data()?;
            self.complete_protocol_metadata_birth_facts
                .ok_or(ProviderError::Correlation(
                    "native5 captured metadata birth facts absent",
                ))?
                .validate_data(&metadata)?;
            if self.complete_storage.is_none()
                || self.complete_coordinator.is_none()
                || self.complete_ack_emitter_selection.is_none()
            {
                return Err(ProviderError::Correlation(
                    "native5 captured protocol metadata lacks original birth",
                ));
            }
        }
        if self.complete_protocol_metadata_limits.is_none()
            && self.complete_protocol_metadata_birth_facts.is_some()
        {
            return Err(ProviderError::Correlation(
                "native5 captured metadata facts lack selection",
            ));
        }
        if self.complete_capture_allocation_selection.is_some() {
            use super::super::service::capture_allocation::{
                PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE, capture_allocation_record_schema,
                capture_allocation_schema,
            };
            if !owned_protocol
                || self.complete_protocol_metadata_limits.is_none()
                || self.complete_protocol_metadata_birth_facts.is_none()
                || self.complete_ack_emitter_selection.is_none()
                || self.complete_coordinator.is_none()
                || self.complete_storage.is_none()
                || !self
                    .selection
                    .provider
                    .extensions_supported
                    .iter()
                    .any(|feature| feature.as_str() == PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
            {
                return Err(ProviderError::Correlation(
                    "captured native allocation family lacks original tuple",
                ));
            }
            for schema in [
                capture_allocation_schema()?,
                capture_allocation_record_schema()?,
            ] {
                if !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&schema)
                    || !self.selection.realization.bindings.iter().all(|binding| {
                        binding
                            .compatibility
                            .implementation
                            .formats
                            .contains(&schema)
                    })
                {
                    return Err(ProviderError::Correlation(
                        "captured native allocation definition differs",
                    ));
                }
            }
        }
        if self.complete_restore_input_emitter_selection.is_some() {
            let schema =
                super::super::service::complete_restore::canonical_restore_inputs_schema()?;
            if self.complete_restore_selection != Some(super::super::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || !matches!(self.complete_capture_profile, Some(super::super::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. }))
                || !self.selection.provider.implementation.formats.contains(&schema)
            {
                return Err(ProviderError::Correlation("captured native restore input writer tuple differs"));
            }
        }
        if self.complete_restore_selection == Some(
            super::super::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            for schema in crate::reference_packet::Native5Policy::complete_restore_transfer_schemas()? {
                if !self.selection.provider.implementation.formats.contains(&schema) {
                    return Err(ProviderError::Correlation("captured native restore transfer schema differs"));
                }
            }
        }
        if self.complete_restore_selection.is_some() {
            if self.complete_protocol_metadata_limits.is_none()
                || self.complete_protocol_metadata_birth_facts.is_none()
                || self.complete_ack_emitter_selection.is_none()
            {
                return Err(ProviderError::Correlation(
                    "captured complete restore birth absent",
                ));
            }
            if self.complete_coordinator.is_none() {
                return Err(ProviderError::Correlation(
                    "captured complete restore coordinator absent",
                ));
            }
            for schema in [
                super::super::service::complete_restore::complete_restore_request_schema()?,
                super::super::service::complete_restore::complete_restore_proof_schema()?,
                super::super::service::complete_restore::complete_restore_receipt_schema()?,
            ] {
                if !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&schema)
                {
                    return Err(ProviderError::Correlation(
                        "captured complete restore schema differs",
                    ));
                }
            }
        }
        if self.complete_ack_emitter_selection.is_some() {
            let schema = super::super::service::ack_emitter::native_canonical_blob_ack_schema()?;
            if self.complete_confirmation_selection
                != Some(
                    super::super::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5,
                )
                || self.complete_storage.is_none()
                || self.complete_capture_profile.is_none()
                || !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&schema)
            {
                return Err(ProviderError::Correlation(
                    "native5 captured ACK emitter lacks original tuple",
                ));
            }
        }
        if self.complete_confirmation_selection.is_some() {
            let schema = super::super::service::confirmation::native_after_confirmation_schema()?;
            if self.complete_coordinator.is_none()
                || self.complete_storage.is_none()
                || self.complete_capture_profile.is_none()
                || !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&schema)
            {
                return Err(ProviderError::Correlation(
                    "native5 captured confirmation lacks original birth tuple",
                ));
            }
        }
        if let Some(installed) = &self.complete_coordinator {
            if self.common_coordinator.is_some()
                || self.world_coordinator.is_some()
                || self.connected_coordinator.is_some()
            {
                return Err(ProviderError::Correlation(
                    "native5 captured coordinator mixture",
                ));
            }
            installed.validate(&self.selection)?;
        }
        if let Some(operation) = &self.current_operation {
            operation.validate()?;
        }
        Ok(())
    }
}

mod capture_transition;
pub use capture_transition::PacketOriginalCaptureTransitionData;

/// Reports actual compiled layouts used by complete Control/model validation.
///
/// A Source combines these data with nonallocating counts of its exact input,
/// pinned map-node geometry and the named simultaneous phases. None of these
/// values authenticates an archive, changes a budget or grants live authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketControlSnapshotValidationLayouts {
    /// Retains the actual compiled Control decoder's encoded-input ceiling.
    pub maximum_control_bytes: usize,
    /// Retains the actual compiled model decoder's encoded-input ceiling.
    pub maximum_model_bytes: usize,
    /// Bounds an actual private typed value/array slot across these decoders.
    pub maximum_typed_slot_bytes: usize,
    /// Reports the largest alignment of those actual typed slots.
    pub maximum_typed_slot_alignment: usize,
    /// Bounds actual key-plus-value layouts across concrete decoder BTree maps.
    pub maximum_tree_key_value_bytes: usize,
    /// Reports the largest actual alignment of those map keys/values.
    pub maximum_tree_entry_alignment: usize,
    /// Reports the independently retained complete typed Control record header.
    pub control_record_bytes: usize,
    /// Reports the independently retained decoded model record header.
    pub model_record_bytes: usize,
    /// Reports a full temporary typed producer-state header.
    pub producer_state_bytes: usize,
    /// Reports a full temporary typed reactive-state header.
    pub reactive_state_bytes: usize,
    /// Bounds the simultaneous full-control-size DOM projections described below.
    pub maximum_simultaneous_control_dom_views: usize,
    /// Counts complete typed state projections; exactly one model kind is chosen.
    pub maximum_simultaneous_typed_model_views: usize,
    /// Bounds separate full-control-size canonical/model serialization banks.
    ///
    /// The Source charges actual serializer capacity growth for each bank, not
    /// merely its logical encoded length. Raw input buffers are separate terms.
    pub maximum_simultaneous_control_encoded_banks: usize,
    /// Bounds the separately parsed unchanged-cut anchor input.
    pub maximum_anchor_bytes: usize,
    /// Bounds separately decoded original Capture request input.
    pub maximum_capture_request_bytes: usize,
}

/// Returns compiled private layouts and the complete validation phase roster.
///
/// Four conservative whole-control DOM views cover retained embedded model,
/// separately retained decoded model state, the transition comparison and one
/// sequential definition/inventory hash projection. One typed model projection
/// and two canonical/model byte banks coexist conservatively. Anchor and actual
/// Capture request scratch remain separate, as do caller-owned raw bodies and
/// cold protocol holders. Every count still comes from the actual selected body.
#[must_use]
pub fn packet_control_snapshot_validation_layouts() -> PacketControlSnapshotValidationLayouts {
    use super::super::connected::{PacketConnectedGrant, PacketConnectedNativeRecord};
    use std::mem::{align_of, size_of};
    let model = super::super::continuation_models::original_model_validation_layouts();
    let slots = [
        size_of::<ControlRecord>(),
        size_of::<ControlState>(),
        size_of::<OriginalRecord>(),
        size_of::<PacketControlSelection>(),
        size_of::<Envelope>(),
        size_of::<CaptureArguments>(),
        size_of::<PacketNativeRecord>(),
        size_of::<PacketConnectedNativeRecord>(),
        model[0],
    ];
    let alignments = [
        align_of::<ControlRecord>(),
        align_of::<ControlState>(),
        align_of::<OriginalRecord>(),
        align_of::<PacketControlSelection>(),
        align_of::<Envelope>(),
        align_of::<CaptureArguments>(),
        align_of::<PacketNativeRecord>(),
        align_of::<PacketConnectedNativeRecord>(),
        model[1],
    ];
    let entries = [
        (
            size_of::<Id>() + size_of::<PacketGrant>(),
            align_of::<Id>().max(align_of::<PacketGrant>()),
        ),
        (
            size_of::<Id>() + size_of::<PacketConnectedGrant>(),
            align_of::<Id>().max(align_of::<PacketConnectedGrant>()),
        ),
        (
            size_of::<Id>() + size_of::<Vec<Id>>(),
            align_of::<Id>().max(align_of::<Vec<Id>>()),
        ),
        (
            size_of::<Id>() + size_of::<BeginRequest>(),
            align_of::<Id>().max(align_of::<BeginRequest>()),
        ),
        (2 * size_of::<Id>(), align_of::<Id>()),
        (
            size_of::<Id>() + size_of::<Map<String, Value>>(),
            align_of::<Id>().max(align_of::<Map<String, Value>>()),
        ),
        (
            size_of::<ContentRef>() + size_of::<Vec<u8>>(),
            align_of::<ContentRef>().max(align_of::<Vec<u8>>()),
        ),
        (
            size_of::<String>() + size_of::<Value>(),
            align_of::<String>().max(align_of::<Value>()),
        ),
    ];
    PacketControlSnapshotValidationLayouts {
        maximum_control_bytes: MAXIMUM_BYTES,
        maximum_model_bytes: super::super::continuation_models::PACKET_MODEL_SNAPSHOT_BYTES,
        maximum_typed_slot_bytes: slots.into_iter().max().unwrap_or(0),
        maximum_typed_slot_alignment: alignments.into_iter().max().unwrap_or(1),
        maximum_tree_key_value_bytes: entries.iter().map(|entry| entry.0).max().unwrap_or(0),
        maximum_tree_entry_alignment: entries.iter().map(|entry| entry.1).max().unwrap_or(1),
        control_record_bytes: size_of::<ControlRecord>(),
        model_record_bytes: model[2],
        producer_state_bytes: model[3],
        reactive_state_bytes: model[4],
        maximum_simultaneous_control_dom_views: 4,
        maximum_simultaneous_typed_model_views: 1,
        maximum_simultaneous_control_encoded_banks: 2,
        maximum_anchor_bytes: 8192,
        maximum_capture_request_bytes: 65536,
    }
}

#[path = "continuation_startup.rs"]
mod startup;

mod settled;

mod settled_reader;
pub(crate) use settled_reader::{
    PacketSettledControlRecord17Data, settled_control_record17_counter_scratch_data,
};

mod pending_settled17;

#[path = "continuation/decoded_metadata.rs"]
mod decoded_metadata;

#[path = "continuation/capture_future_input.rs"]
mod capture_future_input;
pub use capture_future_input::{
    PacketDecodedCaptureFutureControlData, decode_packet_control_snapshot_for_capture_future_data,
};
