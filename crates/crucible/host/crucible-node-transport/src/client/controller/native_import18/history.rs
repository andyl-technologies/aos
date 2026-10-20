//! Borrows actual SDK18 Prepare partials as DATA for an enclosing Source history.
//!
//! No view decodes state, verifies a Source MAC, recreates a live deadline or
//! issues restoration/Window permission. The enclosing versioned Source codec
//! separately validates completion and exact original Controller history.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::retained_metadata::{
    historical_response_body_counter_scratch_data, historical_response_body_data,
    ordinary_bytes_formatter_counter_scratch_data,
};
use serde::{
    Serializer,
    ser::{Error, SerializeStruct},
};
use std::mem::size_of;

/// Borrows one genuine capsule's actual protocol, once and partial history.
///
/// This view is not Clone or Deserialize and has no public constructor. Live
/// actor, literal-slot and deadline tokens are never serialized as capabilities.
/// Actual terminal wire bytes remain in the enclosing Controller frame bank.
pub struct OriginalNativeImport18AssignmentHistoryView<'a> {
    owner: &'a OriginalNativeImport18Assignment,
}

impl OriginalNativeImport18Assignment {
    /// Borrows real complete or incomplete SDK fields without copying them.
    ///
    /// # Errors
    /// Refuses a capsule from another process or creator thread.
    pub fn borrowed_history_data(
        &self,
    ) -> Result<OriginalNativeImport18AssignmentHistoryView<'_>, ProviderError> {
        self.controller.ensure_current()?;
        Ok(OriginalNativeImport18AssignmentHistoryView { owner: self })
    }

    /// Names fixed actual metadata/formatter/compact view controls before lookup.
    pub fn history_counter_scratch_data() -> usize {
        CnpController::original_native_import18_assignment_counter_scratch_data()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
            + input_upload::history_counter_scratch_data()
            + historical_response_body_counter_scratch_data()
            + ordinary_bytes_formatter_counter_scratch_data()
            + size_of::<OriginalNativeImport18AssignmentHistoryView<'static>>()
            + size_of::<Result<OriginalNativeImport18AssignmentHistoryView<'static>, ProviderError>>(
            )
            + size_of::<PhaseHistory<'static, PacketCompleteRestorePrepareRequest>>()
            + size_of::<PhaseFieldLoans<'static, PacketCompleteRestorePrepareRequest>>()
            + size_of::<(
                &PacketNativeImport18Binding,
                &SchemaRef,
                &Vec<u8>,
                &AssignedPhase<PacketCompleteRestorePrepareRequest>,
                &input_upload::InputUploadBank,
            )>()
            + size_of::<&Self>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<Result<(usize, usize), ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<(&Envelope, &Envelope)>()
            + size_of::<Result<(&Envelope, &Envelope), ProviderError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}

impl<'a> OriginalNativeImport18AssignmentHistoryView<'a> {
    /// Borrows the genuine completed bounded-input Prepare pair as DATA.
    ///
    /// This private completion does not imply model adoption or Commit readiness.
    ///
    /// # Errors
    /// Refuses foreign creator or absent/incomplete Prepare.
    pub fn completed_prepare_pair_data(
        &self,
    ) -> Result<(&'a Envelope, &'a Envelope), ProviderError> {
        self.owner.controller.ensure_current()?;
        let pair = completed_pair(&self.owner.prepare)?;
        self.owner.controller.ensure_current()?;
        Ok(pair)
    }

    /// Checks actual complete seven-bank originals and ACKs as historical DATA.
    ///
    /// # Errors
    /// Refuses foreign creator or any absent, failed or partial upload progress.
    pub fn completed_input_uploads_data(&self) -> Result<(), ProviderError> {
        self.owner.controller.ensure_current()?;
        let result = self
            .owner
            .uploads
            .authenticate_completed_history_data(&self.owner.prepare, &self.owner.binding);
        self.owner.controller.ensure_current()?;
        result
    }

    /// Counts actual retained capsule children, including failed/spare banks.
    ///
    /// The containing capsule's inline header is separately owned by its Source.
    /// Operational quote rows outside this capsule remain separate owners.
    ///
    /// # Errors
    /// Refuses foreign creator or actual metadata bookkeeping exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.owner.retained_metadata_data()
    }

    /// Quotes the largest actual ordinary Bytes formatter before serialization.
    ///
    /// Actual compact chunks use the defining fixed scratch supplier; output
    /// DOM/canonical/encoder storage is the enclosing caller's independent row.
    /// No serializer, parser or allocation runs in this observation.
    ///
    /// The caller first admits owner.retained_metadata_counter_scratch_data's
    /// actual result before this complete field observation.
    ///
    /// # Errors
    /// Refuses foreign creator, actual metadata exhaustion or encoded overflow.
    pub fn serialization_prewalk_data(&self) -> Result<(usize, usize), ProviderError> {
        let mut observer = MetadataObserver::new();
        self.owner.observe_actual_history_data(&mut observer)?;
        let bytes = observer
            .ordinary_bytes_formatter_data()
            .maximum_temporary_requested_bytes_data()?;
        self.owner.controller.ensure_current()?;
        Ok((
            bytes.max(20),
            OriginalNativeImport18Assignment::history_counter_scratch_data(),
        ))
    }
}

impl Serialize for OriginalNativeImport18AssignmentHistoryView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.owner
            .controller
            .ensure_current()
            .map_err(S::Error::custom)?;
        let OriginalNativeImport18Assignment {
            controller: _,
            binding,
            expected_backend_schema,
            normalization,
            prepare,
            uploads,
        } = self.owner;
        let mut value = serializer.serialize_struct("NativeImport18AssignmentHistoryData", 5)?;
        value.serialize_field("binding", binding)?;
        value.serialize_field("expected_backend_schema", expected_backend_schema)?;
        value.serialize_field("normalization", &BorrowedCompactBytes::new(normalization))?;
        value.serialize_field("prepare", &PhaseHistory(prepare))?;
        value.serialize_field("uploads", &uploads.history_data())?;
        self.owner
            .controller
            .ensure_current()
            .map_err(S::Error::custom)?;
        value.end()
    }
}

type PhaseFieldLoans<'a, T> = (
    &'a Stage,
    &'a Option<Id>,
    &'a Option<BeginRequest>,
    &'a T,
    &'a Option<Value>,
    &'a Option<Value>,
    &'a Option<Value>,
    &'a Option<PacketNativeImport17Proof>,
    &'a Option<Value>,
    &'a Option<Envelope>,
    &'a Vec<u8>,
    &'a Option<crate::transport::RetainedFrame>,
    &'a Option<Envelope>,
    &'a Option<crate::connection::ReceivedFrame>,
    &'a Option<ResponseBody>,
    &'a Option<PacketNativeImport17PrepareReceipt>,
);

struct PhaseHistory<'a, T>(&'a AssignedPhase<T>);

impl<T: Serialize> Serialize for PhaseHistory<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let AssignedPhase {
            stage,
            request_id,
            baseline,
            request,
            body,
            payload,
            binding_value,
            proof,
            proof_value,
            original,
            bytes,
            literal_slot: _,
            cut: _,
            json_profile: _,
            raw,
            response,
            received,
            decoded,
            prepare_receipt,
        } = self.0;
        let stage = match stage {
            Stage::Preparing => "preparing",
            Stage::Unsigned => "unsigned",
            Stage::Sealing => "sealing",
            Stage::Sealed => "sealed",
            Stage::Publishing => "publishing",
            Stage::RawReceived => "raw_received",
            Stage::Decoding => "decoding",
            Stage::Complete => "complete",
        };
        let typed = decoded
            .as_ref()
            .map(historical_response_body_data)
            .transpose()
            .map_err(S::Error::custom)?;
        let mut value =
            serializer.serialize_struct("NativeImport18AssignedPhaseHistoryData", 16)?;
        value.serialize_field("stage", stage)?;
        value.serialize_field("request_id", request_id)?;
        value.serialize_field("baseline", baseline)?;
        value.serialize_field("request", request)?;
        value.serialize_field("body", body)?;
        value.serialize_field("payload", payload)?;
        value.serialize_field("binding_value", binding_value)?;
        value.serialize_field("proof", proof)?;
        value.serialize_field("proof_value", proof_value)?;
        value.serialize_field("original", original)?;
        value.serialize_field("bytes", &BorrowedCompactBytes::new(bytes))?;
        value.serialize_field(
            "raw",
            &raw.as_ref()
                .map(|frame| (&frame.value, BorrowedCompactBytes::new(&frame.bytes))),
        )?;
        value.serialize_field("response", response)?;
        value.serialize_field(
            "received",
            &received
                .as_ref()
                .map(crate::connection::ReceivedFrame::borrowed_settled17_data),
        )?;
        value.serialize_field("decoded", &typed)?;
        value.serialize_field("prepare_receipt", prepare_receipt)?;
        value.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_sealing_history_keeps_actual_banks_and_no_completed_pair() {
        let baseline = BeginRequest {
            kind: crate::bodies::BeginKind::PrepareRestore,
            binding_hash: canonical::hash("cnp.owner-binding.v1", b"history-data").unwrap(),
            owner_generation: U64::new(1),
            activation_id: Nullable(None),
            world_generation: U64::new(1),
            arguments: Default::default(),
            extensions: Default::default(),
        };
        let mut phase =
            AssignedPhase::new(Id::new("history/prepare").unwrap(), baseline, String::new());
        phase.stage = Stage::Sealing;
        phase.bytes.extend_from_slice(b"retained assigned bytes");
        phase.proof_value = Some(serde_json::json!({"partial":"proof"}));
        let before = phase.bytes.clone();

        let data = serde_json::to_value(PhaseHistory(&phase)).unwrap();

        assert_eq!(data["stage"], "sealing");
        assert_eq!(data["proof_value"]["partial"], "proof");
        assert_eq!(data["bytes"][0], "source-private.compact-bytes/7");
        assert_eq!(data["bytes"][1], before.len());
        assert!(data["response"].is_null());
        assert!(completed_pair(&phase).is_err());
        assert_eq!(phase.bytes, before);
    }
}

#[path = "history/partials.rs"]
pub(super) mod partials;
