//! Counts the closed next Capture request without constructing that original.
//!
//! Session, owner, binding, activation and participants come from the actual
//! stopped Control. Future request/operation/capture/cut identifiers use the
//! explicit CNP Id grammar bound. This produces requested-layout data only;
//! the real incoming request must still satisfy SDK/schema/Control checks.

use super::*;
use crate::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE as PRESERVATION;
use crate::reference_packet::serialization_storage::NativeSerializationStorageData;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;
use std::mem::size_of;

// Contract source: crucible/crucible-node-format/src/values.rs Id::new. This is the
// closed ASCII grammar extent, never a configured storage allowance or an
// observed String capacity. The actual request retains its own identifiers.
const MAXIMUM_CAPTURE_IDENTIFIER_BYTES: usize = 128;
const MAXIMUM_DECIMAL_U64_BYTES: usize = 20;

pub(crate) struct NativeProjectedCaptureRequestData {
    pub(crate) body: NativeSerializationStorageData,
    pub(crate) envelope: NativeSerializationStorageData,
    pub(crate) arguments: NativeSerializationStorageData,
    pub(crate) begin_requested_bytes: usize,
    pub(crate) arguments_requested_bytes: usize,
    pub(crate) participant_count: usize,
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("native next Capture closed request projection")
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, term| {
        total.checked_add(*term).ok_or_else(credit)
    })
}

fn hash(
    projection: &mut OriginalSerializationStorageProjection,
    domain: &str,
) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        projection.add_field(key)?;
    }
    projection.add_string("blake3-256")?;
    projection.add_string(domain)?;
    projection.add_unescaped_ascii_extent(2 * blake3::OUT_LEN)
}

fn position(projection: &mut OriginalSerializationStorageProjection) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["time_ps", "microstep", "phase"] {
        projection.add_field(key)?;
    }
    projection.add_unescaped_ascii_extent(MAXIMUM_DECIMAL_U64_BYTES)?;
    projection.add_unescaped_ascii_extent(MAXIMUM_DECIMAL_U64_BYTES)?;
    // Typed Phase is one u16 leaf, but the retained incoming Envelope keeps
    // valid raw Number spellings such as 1.0 and -0. The pinned generic f64
    // serializer bound dominates that same scalar's canonical output and
    // formatter temporary; it creates no future Position or Envelope.
    projection.add_value(&0.0f64)
}

fn arguments(
    projection: &mut OriginalSerializationStorageProjection,
    participants: &[Id],
) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in [
        "capture_id",
        "participant_ids",
        "cut_id",
        "cut",
        "event_ordinal",
        "ordering_profile",
        "preservation_contract",
    ] {
        projection.add_field(key)?;
    }
    projection.add_unescaped_ascii_extent(MAXIMUM_CAPTURE_IDENTIFIER_BYTES)?;
    projection.add_value(&participants)?;
    projection.add_unescaped_ascii_extent(MAXIMUM_CAPTURE_IDENTIFIER_BYTES)?;
    position(projection)?;
    projection.add_unescaped_ascii_extent(MAXIMUM_DECIMAL_U64_BYTES)?;
    projection.add_string("superdense-v1")?;
    projection.add_string(PRESERVATION)
}

fn body(
    projection: &mut OriginalSerializationStorageProjection,
    participants: &[Id],
    activation_id: &Id,
    world_generation: U64,
    owner_generation: U64,
) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in [
        "kind",
        "binding_hash",
        "owner_generation",
        "activation_id",
        "world_generation",
        "arguments",
        "extensions",
    ] {
        projection.add_field(key)?;
    }
    projection.add_value(&BeginKind::Capture)?;
    hash(projection, "cnp.owner-binding.v1")?;
    projection.add_value(&owner_generation)?;
    projection.add_value(activation_id)?;
    projection.add_value(&world_generation)?;
    arguments(projection, participants)?;
    // The selected borrowed header filter requires empty Begin extensions
    // before typed decoding; an arbitrary extension DOM cannot enter this shape.
    projection.add_object()
}

impl PacketControl {
    pub(super) fn project_original_capture_body(
        &self,
        projection: &mut OriginalSerializationStorageProjection,
    ) -> Result<(), ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation(
                "native Capture projected binding roster",
            ));
        };
        let [owner] = self.selection.realization.owner_bindings.as_slice() else {
            return Err(ProviderError::Correlation(
                "native Capture projected owner roster",
            ));
        };
        let activation = self.active.as_ref().ok_or(ProviderError::Correlation(
            "native Capture projected activation absent",
        ))?;
        body(
            projection,
            &owner.owner.participant_ids,
            &activation.activation_id,
            activation.world_generation,
            binding.authority.owner_generation,
        )
    }

    pub(crate) fn quote_original_next_capture_request(
        &self,
        observed: &Envelope,
        maximum_frame_bytes: usize,
        maximum_requested_bytes: usize,
    ) -> Result<NativeProjectedCaptureRequestData, ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || self.current_operation.is_some()
            || self.complete_capture_allocation_selection.is_none()
        {
            return Err(ProviderError::Correlation(
                "native next Capture current Control differs",
            ));
        }
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation(
                "native next Capture binding roster",
            ));
        };
        let [owner] = self.selection.realization.owner_bindings.as_slice() else {
            return Err(ProviderError::Correlation(
                "native next Capture owner roster",
            ));
        };
        let activation = self.active.as_ref().ok_or(ProviderError::Correlation(
            "native next Capture active world absent",
        ))?;
        if observed.message != crate::envelope::MessageKind::Request
            || observed.method != Method::Observe
            || observed.protocol != "CNP/1"
            || observed.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || observed.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
        {
            return Err(ProviderError::Correlation(
                "native next Capture original Observe differs",
            ));
        }
        let mut body_projection =
            OriginalSerializationStorageProjection::new(maximum_requested_bytes)?;
        body(
            &mut body_projection,
            &owner.owner.participant_ids,
            &activation.activation_id,
            activation.world_generation,
            binding.authority.owner_generation,
        )?;
        let body_data = body_projection.finish(maximum_requested_bytes)?;

        let mut envelope = OriginalSerializationStorageProjection::new(maximum_requested_bytes)?;
        envelope.add_object()?;
        for key in [
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ] {
            envelope.add_field(key)?;
        }
        envelope.add_value(&observed.protocol)?;
        envelope.add_value(&crate::envelope::MessageKind::Request)?;
        envelope.add_value(&observed.session_id)?;
        envelope.add_value(&observed.incarnation_id)?;
        envelope.add_value(&binding.compatibility.node_id)?;
        envelope.add_value(&())?;
        envelope.add_value(&binding.compatibility.capture_owner.id)?;
        envelope.add_unescaped_ascii_extent(MAXIMUM_CAPTURE_IDENTIFIER_BYTES)?;
        envelope.add_unescaped_ascii_extent(MAXIMUM_CAPTURE_IDENTIFIER_BYTES)?;
        envelope.add_unescaped_ascii_extent(MAXIMUM_DECIMAL_U64_BYTES)?;
        envelope.add_value(&Method::Begin)?;
        body(
            &mut envelope,
            &owner.owner.participant_ids,
            &activation.activation_id,
            activation.world_generation,
            binding.authority.owner_generation,
        )?;
        envelope.add_object()?;
        let envelope = envelope.finish(maximum_requested_bytes)?;
        if envelope.maximum_encoded_bytes > maximum_frame_bytes {
            return Err(ProviderError::ResourceExhausted(
                "native next Capture projected Envelope exceeds actual negotiated frame",
            ));
        }
        let mut arguments_projection =
            OriginalSerializationStorageProjection::new(maximum_requested_bytes)?;
        arguments(&mut arguments_projection, &owner.owner.participant_ids)?;
        let arguments_encoding = arguments_projection.finish(maximum_requested_bytes)?;
        let participant_slots = owner
            .owner
            .participant_ids
            .len()
            .checked_mul(size_of::<Id>())
            .ok_or_else(credit)?;
        let participant_strings = owner
            .owner
            .participant_ids
            .iter()
            .try_fold(0usize, |total, id| {
                total.checked_add(id.as_str().len()).ok_or_else(credit)
            })?;
        let arguments_requested_bytes = sum(&[
            size_of::<CaptureArguments>(),
            participant_slots,
            participant_strings,
            MAXIMUM_CAPTURE_IDENTIFIER_BYTES,
            MAXIMUM_CAPTURE_IDENTIFIER_BYTES,
            "superdense-v1".len(),
            PRESERVATION.len(),
        ])?;
        let begin_requested_bytes = sum(&[
            size_of::<BeginRequest>(),
            body_data.dom_and_canonical_scratch_bytes,
        ])?;
        if sum(&[
            body_data.requested_total()?,
            envelope.requested_total()?,
            arguments_encoding.requested_total()?,
            arguments_requested_bytes,
            begin_requested_bytes,
        ])? > maximum_requested_bytes
        {
            return Err(credit());
        }
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native next Capture origin changed",
            ));
        }
        Ok(NativeProjectedCaptureRequestData {
            body: body_data,
            envelope,
            arguments: arguments_encoding,
            begin_requested_bytes,
            arguments_requested_bytes,
            participant_count: owner.owner.participant_ids.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};

    // The typed request is inert test data. It supplies no binding, Source or
    // Capture authority; actual canonical and allocated Value backing validate
    // the independent prospective projection rather than another projection.
    #[test]
    fn capture_body_projection_covers_real_maximum_ids_numeric_phase_and_dom()
    -> Result<(), ProviderError> {
        let identifier = Id::new("X".repeat(MAXIMUM_CAPTURE_IDENTIFIER_BYTES))?;
        let participants = vec![Id::new("native/0")?, Id::new("native/1")?];
        let activation = Id::new("actual-test-data-activation")?;
        let generation = U64::new(u64::MAX);
        let arguments = CaptureArguments {
            capture_id: identifier.clone(),
            participant_ids: participants.clone(),
            cut_id: identifier,
            cut: Position::new(generation, generation, Phase::Reaction),
            event_ordinal: generation,
            ordering_profile: "superdense-v1".into(),
            preservation_contract: Id::new(PRESERVATION)?,
        };
        let arguments = serde_json::to_value(arguments).map_err(ContractError::from)?;
        let request = BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: canonical::json_hash("cnp.owner-binding.v1", &())?,
            owner_generation: generation,
            activation_id: Nullable(Some(activation.clone())),
            world_generation: generation,
            arguments: arguments.as_object().ok_or_else(credit)?.clone(),
            extensions: Extensions::new(),
        };
        let actual = serde_json::to_value(&request).map_err(ContractError::from)?;
        let canonical = canonical::canonical_json(&actual)?;
        let mut observer = MetadataObserver::new();
        observer.observe(&actual)?;
        let actual_backing = requested_metadata_backing_storage_data(&observer.finish())?;
        let mut projection = OriginalSerializationStorageProjection::new(16 * 1024 * 1024)?;
        body(
            &mut projection,
            &participants,
            &activation,
            generation,
            generation,
        )?;
        let projected = projection.finish(16 * 1024 * 1024)?;

        assert_eq!(actual["arguments"]["cut"]["phase"].as_u64(), Some(3));
        assert!(canonical.len() <= projected.maximum_encoded_bytes);
        assert!(actual_backing <= projected.dom_and_canonical_scratch_bytes);

        for spelling in ["1.0", "1e0", "-0"] {
            let mut raw = actual.clone();
            raw["arguments"]["cut"]["phase"] =
                serde_json::from_str(spelling).map_err(ContractError::from)?;
            let _: CaptureArguments =
                serde_json::from_value(raw["arguments"].clone()).map_err(ContractError::from)?;
            let stored =
                crate::reference_packet::serialization_storage::actual_serialization_storage_data(
                    &raw,
                    Default::default(),
                    16 * 1024 * 1024,
                )?;
            assert!(stored.maximum_encoded_bytes <= projected.maximum_encoded_bytes);
            assert!(
                stored.serializer_temporary_requested_bytes
                    <= projected.serializer_temporary_requested_bytes
            );
            assert!(stored.serialized_value_nodes <= projected.serialized_value_nodes);
            assert!(stored.serialized_capacity_records <= projected.serialized_capacity_records);
        }

        let actual_envelope = Envelope {
            protocol: "CNP/1".into(),
            message: crate::envelope::MessageKind::Request,
            session_id: Nullable(Some(Id::new("session")?)),
            incarnation_id: Nullable(Some(Id::new("incarnation")?)),
            node_id: Nullable(Some(Id::new("node")?)),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(Some(Id::new("owner")?)),
            request_id: Nullable(Some(Id::new("request")?)),
            operation_id: Nullable(Some(Id::new("operation")?)),
            sequence: generation,
            method: Method::Begin,
            body: actual.as_object().ok_or_else(credit)?.clone(),
            extensions: Extensions::new(),
        };
        let mut observer = MetadataObserver::new();
        observer.observe(&actual_envelope)?;
        let actual_metadata = observer.finish();
        assert_eq!(actual_metadata.capacity_records, 48 + participants.len());
        assert_eq!(actual_metadata.observed_nodes, 82 + 2 * participants.len());
        Ok(())
    }

    #[test]
    fn future_capture_projection_refuses_short_credit_without_mutating_participants()
    -> Result<(), ProviderError> {
        let mut participants = Vec::with_capacity(17);
        participants.push(Id::new("native/0")?);
        let activation = Id::new("active-test-data")?;
        let before = (participants.len(), participants.capacity());
        let project = |maximum| -> Result<NativeSerializationStorageData, ProviderError> {
            let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
            body(
                &mut projection,
                &participants,
                &activation,
                U64::new(1),
                U64::new(1),
            )?;
            projection.finish(maximum)
        };
        let quoted = project(16 * 1024 * 1024)?;
        let exact = quoted.requested_total()?;
        project(exact)?;
        assert!(project(exact - 1).is_err());
        assert_eq!((participants.len(), participants.capacity()), before);
        Ok(())
    }
}
