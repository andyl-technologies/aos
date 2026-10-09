//! Borrows original selected source windows from the owning controller cache.
//!
//! The view cannot be deserialized or created from a relation DTO. It proves
//! controller custody and exact agreement of selected records, not installed
//! source qualification. The enclosing adopter must independently authenticate
//! both measured processes, original enrollment, admission and runtime scope.

use super::ReferenceController;
use crate::{
    ProviderError,
    bodies::*,
    client::ClientOriginal,
    envelope::{Method, RequestOrigin},
    reference_lineage::{LineageStage, NativeLineageReceipt},
};
use crucible_node_contract::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

#[path = "lineage_ack.rs"]
mod acknowledgement;
#[path = "lineage_records.rs"]
mod records;
#[path = "lineage_rows.rs"]
mod rows;
#[path = "lineage_validation.rs"]
mod validation;
pub use acknowledgement::OriginalLineageAcknowledgement;
pub use rows::{OriginalLineageEvidence, OriginalLineageObject};

#[path = "lineage_ready.rs"]
mod realization;
pub use realization::OriginalLineageRealization;

/// Selects exact original controls already retained by their owning controller.
///
/// These IDs are lookup selectors and grant no execution or source authority.
pub struct LineageWindowRequests<'a> {
    /// Selects the actual original realization which established the closed gate.
    pub realization: &'a Id,
    /// Selects the actual original accepted input custody acknowledgement.
    pub input: &'a Id,
    /// Selects the actual original completed quantized window permission.
    pub begin: &'a Id,
}

/// Borrows exact original source and native closure custody without effect authority.
///
/// Its controller borrow prevents concurrent ACK or replacement through that
/// controller. Producer-local IDs, original permissions and typed proof roles
/// remain unchanged. Source qualification requires a separate installed policy.
pub struct OriginalLineageWindow<'a> {
    controller: &'a ReferenceController,
    originals: [&'a ClientOriginal; 3],
    origin: records::Origin,
    relation: records::Relation,
    measurement: records::Measurement,
    measurement_ref: ContentRef,
    stop: StopReceipt,
    observation: ObservationBatch,
    input: InputBatch,
    stage: LineageStage,
    native: NativeLineageReceipt,
}

impl OriginalLineageWindow<'_> {
    /// Returns original Realize, Input and Begin controls with their cached replies.
    pub fn originals(&self) -> &[&ClientOriginal; 3] {
        &self.originals
    }

    /// Returns the original stable kernel PID reported in actual closed-gate custody.
    ///
    /// The installed adopter independently checks the original direct child and
    /// start counter. This getter does not claim that it remains currently live.
    pub fn native_pid(&self) -> U64 {
        self.origin.child_pid
    }

    /// Returns the unchanged original kernel start counter retained at realization.
    pub fn native_start_ticks(&self) -> U64 {
        self.origin.original_kernel_start_ticks
    }

    /// Returns the selected child artifact bound by the original gate and profile.
    pub fn native_executable(&self) -> &ContentRef {
        &self.origin.native_executable
    }

    /// Returns the exact accepted original public input batch, including event order.
    pub fn input_batch(&self) -> &InputBatch {
        &self.input
    }

    /// Returns the selected native stage and every original payload byte range.
    pub fn native_stage(&self) -> &LineageStage {
        &self.stage
    }

    /// Returns the unchanged native closed receipt and preceding checksum state.
    pub fn native_receipt(&self) -> &NativeLineageReceipt {
        &self.native
    }

    /// Returns the original stop scope and observation closure.
    pub fn stop(&self) -> &StopReceipt {
        &self.stop
    }

    /// Returns actual publication events with their original IDs and native FIFO.
    pub fn observation(&self) -> &ObservationBatch {
        &self.observation
    }

    /// Returns the exact selected physical measurement reference from original Begin.
    pub fn measurement_reference(&self) -> &ContentRef {
        &self.measurement_ref
    }

    /// Returns the exact original native consumption relation reference.
    pub fn consumption_relation_reference(&self) -> &ContentRef {
        &self.measurement.consumption_relation
    }

    /// Returns the original preceding public publication acknowledgement, if present.
    ///
    /// This cumulative state relation is separate from same-time event parents.
    pub fn preceding_public_acknowledgement(&self) -> Option<&ContentRef> {
        self.measurement
            .previous_publication
            .as_ref()
            .map(|previous| &previous.publication_consumption)
    }

    /// Returns the original canonical accepted batch body reference.
    pub fn input_batch_reference(&self) -> &ContentRef {
        &self.relation.input_batch
    }

    /// Returns original raw initialization and length-prefixed native Ready bytes.
    ///
    /// # Errors
    /// Refuses missing or altered original typed content custody.
    pub fn native_initialization(&self) -> Result<(&[u8], &[u8]), ProviderError> {
        Ok((
            self.controller.content(&self.relation.initialize_request)?,
            self.controller
                .content(&self.relation.initialize_response_wire)?,
        ))
    }

    /// Returns original raw Close command and exact length-prefixed native reply.
    ///
    /// # Errors
    /// Refuses missing or altered original typed content custody.
    pub fn native_close(&self) -> Result<(&[u8], &[u8]), ProviderError> {
        Ok((
            self.controller.content(&self.relation.close_request)?,
            self.controller
                .content(&self.relation.close_response_wire)?,
        ))
    }
}

impl ReferenceController {
    /// Borrows a selected window from exact retained original source controls.
    ///
    /// This does no native I/O, ACK or source enrollment. It does not accept a
    /// caller-supplied receipt, body or expected hash as replacement custody.
    ///
    /// # Errors
    /// Refuses legacy profiles, missing or uncertain original controls, changed
    /// source scope, incomplete evidence, malformed selected codecs, altered
    /// ordered input, native stage/closure disagreement or absent ancestry.
    pub fn original_lineage_window(
        &self,
        requests: LineageWindowRequests<'_>,
    ) -> Result<OriginalLineageWindow<'_>, ProviderError> {
        if !self.profile.is_lineage() {
            return Err(ProviderError::Correlation(
                "original selected lineage source custody differs",
            ));
        }
        let (realize_original, realized) = completed(self, requests.realization, Method::Realize)?;
        let Some(MethodResult::Realize(realized)) = realized.result else {
            return Err(ProviderError::Correlation(
                "original selected lineage source custody differs",
            ));
        };
        let gate: ControlReceipt = validated(self, &realized.closed_gate_receipt)?;
        let gate_record: ClosedGateRecord = validated(self, &gate.record_ref)?;
        validation::control(
            self,
            &gate,
            requests.realization,
            ControlReceiptKind::ClosedGate,
        )?;
        if gate_record.owner_ids != [self.bootstrap.owner_id.clone()]
            || gate_record.gate_id != self.bootstrap.gate_id
            || gate_record.prepared_token != self.bootstrap.prepared_token
        {
            return Err(ProviderError::Correlation(
                "original selected lineage source custody differs",
            ));
        }
        let origin: records::Origin =
            record(self, &gate_record.physical_status_ref, "application/json")?;
        let (input_original, accepted) = completed(self, requests.input, Method::Input)?;
        let Some(MethodResult::Input(accepted)) = accepted.result else {
            return Err(ProviderError::Correlation(
                "original selected lineage source custody differs",
            ));
        };
        let (begin_original, completed_begin) = completed(self, requests.begin, Method::Begin)?;
        let Some(MethodResult::QuantumBegin(result)) = completed_begin.result else {
            return Err(ProviderError::Correlation(
                "original selected lineage source custody differs",
            ));
        };
        let RequestBody::Begin(begin) =
            decode_request(Method::Begin, &begin_original.request.body)?
        else {
            return Err(ProviderError::Correlation(
                "original selected lineage source custody differs",
            ));
        };
        let BeginArguments::QuantumBegin(grant) = begin.decoded_arguments()? else {
            return Err(ProviderError::Correlation(
                "original selected lineage source custody differs",
            ));
        };
        let measurement: records::Measurement =
            record(self, &result.physical_measurement_ref, "application/json")?;
        let relation: records::Relation = record(
            self,
            &measurement.consumption_relation,
            "application/vnd.crucible.reference-consumption-relation+json",
        )?;
        let input: InputBatch = validated(self, &relation.input_batch)?;
        let stage: LineageStage = record(
            self,
            &relation.native_stage,
            "application/vnd.crucible.reference-lineage-stage+json",
        )?;
        let native: NativeLineageReceipt = record(
            self,
            &relation.native_receipt,
            "application/vnd.crucible.reference-lineage-native-receipt+json",
        )?;
        let stop: StopReceipt = validated(self, &result.stop_receipt)?;
        let observation: ObservationBatch = validated(self, &result.observation_batch)?;
        let view = OriginalLineageWindow {
            controller: self,
            originals: [realize_original, input_original, begin_original],
            origin,
            relation,
            measurement,
            measurement_ref: result.physical_measurement_ref.clone(),
            stop,
            observation,
            input,
            stage,
            native,
        };
        validation::window(&view, &grant, &result, &accepted, &begin)?;
        Ok(view)
    }
}

fn completed<'a>(
    controller: &'a ReferenceController,
    id: &Id,
    method: Method,
) -> Result<(&'a ClientOriginal, ResponseBody), ProviderError> {
    let original = controller
        .custody
        .original(RequestOrigin::Controller, id)
        .ok_or_else(invalid)?;
    if original.request.method != method
        || original.request.session_id.0.as_ref()
            != Some(&controller.bootstrap.authority.session_id)
        || original.request.incarnation_id.0.as_ref()
            != Some(&controller.bootstrap.authority.incarnation_id)
    {
        return Err(ProviderError::Correlation(
            "original selected lineage source custody differs",
        ));
    }
    let owned = matches!(method, Method::Input | Method::Begin | Method::QuantumClose);
    if owned
        && (original.request.execution_owner_id.0.as_ref() != Some(&controller.bootstrap.owner_id)
            || original.request.node_id.0.as_ref() != Some(&controller.bootstrap.node_id))
    {
        return Err(invalid());
    }
    let response = original.response.as_ref().ok_or_else(invalid)?;
    if response.method != method
        || response.request_id != original.request.request_id
        || response.operation_id != original.request.operation_id
        || response.session_id != original.request.session_id
        || response.incarnation_id != original.request.incarnation_id
    {
        return Err(invalid());
    }
    let decoded = decode_response(
        &decode_request(method, &original.request.body)?,
        &response.body,
    )?;
    if !matches!(decoded.shape, ResponseShape::Completed { .. }) {
        return Err(ProviderError::Correlation(
            "original selected lineage source custody differs",
        ));
    }
    Ok((original, decoded))
}

fn record<T: DeserializeOwned>(
    controller: &ReferenceController,
    reference: &ContentRef,
    media: &str,
) -> Result<T, ProviderError> {
    if reference.media_type != media || reference.length.get() > 65_536 {
        return Err(ProviderError::Correlation(
            "original selected lineage source custody differs",
        ));
    }
    let value = canonical::parse_json(controller.content(reference)?, 65_536)?;
    serde_json::from_value(value).map_err(|_| invalid())
}

fn validated<T: DeserializeOwned + Validate>(
    controller: &ReferenceController,
    reference: &ContentRef,
) -> Result<T, ProviderError> {
    let value: T = record(controller, reference, "application/json")?;
    value.validate()?;
    Ok(value)
}

fn wire(controller: &ReferenceController, reference: &ContentRef) -> Result<Value, ProviderError> {
    if reference.media_type != "application/vnd.crucible.reference-native-wire"
        || reference.length.get() > 65_540
    {
        return Err(ProviderError::Correlation(
            "original selected lineage source custody differs",
        ));
    }
    let bytes = controller.content(reference)?;
    let length = bytes
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(invalid)?;
    if usize::try_from(length).ok() != bytes.len().checked_sub(4) {
        return Err(ProviderError::Correlation(
            "original selected lineage source custody differs",
        ));
    }
    Ok(canonical::parse_json(&bytes[4..], 65_536)?)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original selected lineage source custody differs")
}
