//! Projects selected Observe receipt/result fields before their owning copies.
//!
//! Every scope value is borrowed from the actual stopped Control and original.
//! Future native/report/wrapper references contribute only their closed field
//! extents. This produces no receipt, ContentRef, reply or allocation authority.

use super::*;
use crate::reference_packet::serialization_storage::NativeSerializationStorageData;
use crate::reference_packet::service::capture_allocation::{
    PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA, PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD,
};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};

type Projection = OriginalSerializationStorageProjection;

pub(crate) struct NativeObservePublicationProjectionData {
    pub(crate) native_receipt: NativeSerializationStorageData,
    pub(crate) wrapper_record: NativeSerializationStorageData,
    pub(crate) terminal: NativeSerializationStorageData,
    pub(crate) typed_receipt_requested_bytes: usize,
    pub(crate) binding_identity_requested_bytes: usize,
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native Observe publication projection")
}

fn hash(projection: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        projection.add_field(key)?;
    }
    projection.add_string("blake3-256")?;
    projection.add_string(domain)?;
    projection.add_unescaped_ascii_extent(2 * blake3::OUT_LEN)
}

fn reference(projection: &mut Projection, media_type: &str) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["hash", "length", "media_type"] {
        projection.add_field(key)?;
    }
    hash(projection, "cnp.blob.v1")?;
    projection.add_unescaped_ascii_extent(20)?;
    projection.add_string(media_type)
}

impl PacketControl {
    fn project_original_observe_receipt(
        &self,
        projection: &mut Projection,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation("Observe receipt binding roster"));
        };
        let storage = self
            .complete_storage
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "Observe receipt born storage absent",
            ))?;
        projection.add_object()?;
        for key in [
            "schema",
            "native_pid",
            "original",
            "binding_hash",
            "session",
            "incarnation",
            "node",
            "owner",
            "owner_generation",
            "input_epoch",
            "world",
            "native_record",
            "storage_selection",
        ] {
            projection.add_field(key)?;
        }
        projection.add_string("source-owned.packet-receipt/5")?;
        projection.add_value(&U64::new(u64::from(self.capture_creator)))?;
        projection.add_value(original)?;
        hash(projection, "cnp.owner-binding.v1")?;
        projection.add_value(&binding.authority.session_id)?;
        projection.add_value(&binding.authority.incarnation_id)?;
        projection.add_value(&binding.compatibility.node_id)?;
        projection.add_value(&binding.compatibility.capture_owner.id)?;
        projection.add_value(&binding.authority.owner_generation)?;
        projection.add_value(&binding.authority.input_epoch)?;
        projection.add_value(&self.selection.world)?;
        reference(projection, "application/json")?;
        projection.add_value(storage)?;
        if let Some(profile) = &self.complete_capture_profile
            && !profile.is_original_arrays()
        {
            projection.add_field("capture_profile")?;
            projection.add_value(profile)?;
        }
        macro_rules! optional {
            ($field:ident, $key:literal) => {
                if let Some(value) = &self.$field {
                    projection.add_field($key)?;
                    projection.add_value(value)?;
                }
            };
        }
        optional!(complete_confirmation_selection, "confirmation_selection");
        optional!(complete_ack_emitter_selection, "ack_emitter_selection");
        optional!(complete_restore_selection, "complete_restore_selection");
        optional!(
            complete_protocol_metadata_limits,
            "protocol_metadata_limits"
        );
        optional!(
            complete_protocol_metadata_birth_facts,
            "protocol_metadata_birth_facts"
        );
        optional!(
            complete_restore_input_emitter_selection,
            "restore_input_emitter_selection"
        );
        Ok(())
    }

    pub(super) fn project_original_observe_result(
        &self,
        projection: &mut Projection,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation("Observe result binding roster"));
        };
        let [owner] = self.selection.realization.owners.as_slice() else {
            return Err(ProviderError::Correlation("Observe result owner roster"));
        };
        let active = self.active.as_ref().ok_or(ProviderError::Correlation(
            "Observe result active world absent",
        ))?;
        let request_id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("Observe result original absent"))?;
        projection.add_object()?;
        for key in [
            "observations",
            "next_sequence",
            "complete",
            "inventory_hash",
        ] {
            projection.add_field(key)?;
        }
        projection.add_array_extent(1)?;
        projection.add_object()?;
        for key in [
            "schema_version",
            "execution_owner_id",
            "owner_binding_hash",
            "world_binding_hash",
            "activation_id",
            "world_generation",
            "owner_generation",
            "operation_id",
            "grant_id",
            "first_sequence",
            "last_sequence",
            "events",
            "visibility",
            "measurement_ref",
            "extensions",
        ] {
            projection.add_field(key)?;
        }
        projection.add_value(&1u16)?;
        projection.add_value(&owner.id)?;
        hash(projection, "cnp.owner-binding.v1")?;
        projection.add_value(&self.selection.world)?;
        projection.add_value(&active.activation_id)?;
        projection.add_value(&active.world_generation)?;
        projection.add_value(&binding.authority.owner_generation)?;
        projection.add_value(request_id)?;
        projection.add_value(&())?;
        projection.add_value(&U64::new(0))?;
        projection.add_value(&U64::new(0))?;
        projection.add_array_extent(0)?;
        projection.add_value(&Visibility::Staged)?;
        reference(projection, "application/json")?;
        projection.add_object()?;
        projection.add_value(&U64::new(1))?;
        projection.add_value(&true)?;
        hash(
            projection,
            if self.program.is_connected() {
                "source-owned.packet-connected-inventory/4"
            } else {
                "source-owned.packet-inventory.v1"
            },
        )
    }

    pub(crate) fn quote_original_observe_publication_shapes(
        &self,
        original: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        maximum: usize,
    ) -> Result<NativeObservePublicationProjectionData, ProviderError> {
        currency.authenticate_before_observe(self)?;
        if original.method != Method::Observe
            || self.complete_capture_allocation_selection.is_none()
        {
            return Err(ProviderError::Correlation(
                "Observe publication projection original differs",
            ));
        }
        let mut receipt = Projection::new(maximum)?;
        self.project_original_observe_receipt(&mut receipt, original)?;
        let native_receipt = receipt.finish(maximum)?;
        let mut wrapper = Projection::new(maximum)?;
        wrapper.add_object()?;
        for key in ["schema", "native", "allocation"] {
            wrapper.add_field(key)?;
        }
        wrapper.add_string(PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD)?;
        self.project_original_observe_receipt(&mut wrapper, original)?;
        reference(&mut wrapper, PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?;
        let wrapper_record = wrapper.finish(maximum)?;

        let mut terminal = Projection::new(maximum)?;
        terminal.add_object()?;
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
            terminal.add_field(key)?;
        }
        terminal.add_value(&original.protocol)?;
        terminal.add_value(&crate::envelope::MessageKind::Response)?;
        terminal.add_value(&original.session_id)?;
        terminal.add_value(&original.incarnation_id)?;
        terminal.add_value(&original.node_id)?;
        terminal.add_value(&original.execution_owner_id)?;
        terminal.add_value(&original.capture_owner_id)?;
        terminal.add_value(&original.request_id)?;
        terminal.add_value(&original.operation_id)?;
        terminal.add_unescaped_ascii_extent(20)?;
        terminal.add_value(&original.method)?;
        terminal.add_object()?;
        for key in ["status", "operation_state", "result", "extensions"] {
            terminal.add_field(key)?;
        }
        terminal.add_string("completed")?;
        terminal.add_value(&OperationState::Completed)?;
        self.project_original_observe_result(&mut terminal, original)?;
        terminal.add_object()?;
        terminal.add_object()?;
        let terminal = terminal.finish(maximum)?;

        let active = self.active.as_ref().ok_or(ProviderError::Correlation(
            "Observe receipt activation absent",
        ))?;
        // These are actual selected owners. A receipt's independent decoded
        // clones contain only a subset, so retaining their full capacities is
        // conservative; no snapshot length or configured byte cap stands in.
        let mut metadata = MetadataObserver::new();
        metadata.observe(&self.selection)?;
        metadata.observe(original)?;
        metadata.observe(&self.complete_storage)?;
        metadata.observe(&self.complete_capture_profile)?;
        let typed_receipt_requested_bytes =
            requested_metadata_backing_storage_data(&metadata.finish())?
                .checked_add(std::mem::size_of::<ProducedOriginalObserveReceipt>())
                .and_then(|bytes| bytes.checked_add(active.activation_id.as_str().len()))
                .and_then(|bytes| bytes.checked_add("source-owned.packet-receipt/5".len()))
                .and_then(|bytes| {
                    bytes.checked_add(
                        "blake3-256".len() + "cnp.owner-binding.v1".len() + 2 * blake3::OUT_LEN,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        "blake3-256".len()
                            + "cnp.blob.v1".len()
                            + 2 * blake3::OUT_LEN
                            + "application/json".len(),
                    )
                })
                .ok_or_else(exhausted)?;
        // All three production identity calls serialize this same immutable
        // OwnerBinding (request comparison, receipt and ObservationBatch).
        // Count its actual typed children before any canonical hash allocation.
        let [owner_binding] = self.selection.realization.owner_bindings.as_slice() else {
            return Err(ProviderError::Correlation("Observe identity owner roster"));
        };
        let mut identity_fields = MetadataObserver::new();
        identity_fields.observe(owner_binding)?;
        let identity =
            crate::reference_packet::serialization_storage::actual_serialization_storage_data(
                owner_binding,
                identity_fields.finish(),
                maximum,
            )?;
        let binding_identity_requested_bytes = identity
            .requested_total()?
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    3 * ("blake3-256".len() + "cnp.owner-binding.v1".len() + 2 * blake3::OUT_LEN),
                )
            })
            .ok_or_else(exhausted)?;
        let total = [
            binding_identity_requested_bytes,
            native_receipt.requested_total()?,
            wrapper_record.requested_total()?,
            terminal.requested_total()?,
            typed_receipt_requested_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, next| {
            sum.checked_add(next).ok_or_else(exhausted)
        })?;
        if total > maximum {
            return Err(exhausted());
        }
        currency.authenticate_before_observe(self)?;
        Ok(NativeObservePublicationProjectionData {
            native_receipt,
            wrapper_record,
            terminal,
            typed_receipt_requested_bytes,
            binding_identity_requested_bytes,
        })
    }
}
