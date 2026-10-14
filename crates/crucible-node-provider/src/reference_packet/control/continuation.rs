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

use super::super::continuation_models::PacketOriginalModelSnapshot;
use super::*;

const SCHEMA: &str = "source-owned.packet-native-control-state/5";
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
        administrative_cut.validate()?;
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "packet whole control snapshot ceiling",
            ));
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
            schema: SCHEMA,
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
    /// Returns the retained administrative cut without changing model time.
    pub fn administrative_cut(&self) -> Position {
        self.record.administrative_cut
    }

    /// Returns the distinct retained original local model cursor.
    pub fn local_cursor(&self) -> Position {
        self.record.local_cursor
    }

    /// Borrows bounded decoded model data without transferring native authority.
    pub fn model(&self) -> &super::super::continuation_models::PacketDecodedModelSnapshot {
        &self.model
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRecord {
    schema: String,
    captured_process: U64,
    administrative_cut: Position,
    local_cursor: Position,
    model: Value,
    control: ControlState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlState {
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalRecord {
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
    let record: ControlRecord = serde_json::from_value(value).map_err(ContractError::from)?;
    if record.schema != SCHEMA
        || record.captured_process.get() == 0
        || record.local_cursor > record.administrative_cut
    {
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
