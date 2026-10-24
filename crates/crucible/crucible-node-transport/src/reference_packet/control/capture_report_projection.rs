//! Counts the selected report's fixed grammar before allocating its owners.
//!
//! The original Observe and stopped Control supply actual scope strings and
//! generations. Not-yet-computed byte sums use decimal-string extents in the
//! private counter; no placeholder Report, Envelope or ContentRef is created.
//! These are prospective layout bounds, never observed capacities or rights.

use super::*;
use crate::reference_packet::serialization_storage::NativeSerializationStorageData;
use crate::reference_packet::service::capture_allocation::{
    NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN, PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT,
    PacketNativeCaptureAllocationReport,
};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;
use std::mem::size_of;

pub(crate) struct NativeCaptureReportProjectionData {
    pub(crate) encoding: NativeSerializationStorageData,
    pub(crate) typed_report_layout_bytes: usize,
    pub(crate) owned_string_requested_bytes: usize,
    pub(crate) owned_string_rows: usize,
}

pub(crate) struct NativeCaptureReportObservationContext<'a> {
    pub(crate) original: &'a Envelope,
    pub(crate) observed: &'a ObserveRequest,
    pub(crate) currency: &'a restore_fresh::PacketLiveCaptureControlCurrency,
    pub(crate) metadata: &'a super::super::service::PacketNative5ProtocolMetadataBirthFacts,
    pub(crate) endpoint_records_before: usize,
    pub(crate) provider_next_sequence_before: u64,
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("native Observe report closed projection")
}

fn add(total: &mut usize, next: usize) -> Result<(), ProviderError> {
    *total = total.checked_add(next).ok_or_else(credit)?;
    Ok(())
}

fn owned_string(
    projection: &mut OriginalSerializationStorageProjection,
    requested: &mut usize,
    rows: &mut usize,
    value: &str,
) -> Result<(), ProviderError> {
    projection.add_string(value)?;
    add(requested, value.len())?;
    add(rows, 1)
}

fn owned_hash(
    projection: &mut OriginalSerializationStorageProjection,
    requested: &mut usize,
    rows: &mut usize,
    value: &HashRef,
) -> Result<(), ProviderError> {
    projection.add_value(value)?;
    for value in [&value.algorithm, &value.domain, &value.digest] {
        add(requested, value.len())?;
        add(rows, 1)?;
    }
    Ok(())
}

fn future_observe_hash(
    projection: &mut OriginalSerializationStorageProjection,
    requested: &mut usize,
    rows: &mut usize,
) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        projection.add_field(key)?;
    }
    owned_string(projection, requested, rows, "blake3-256")?;
    owned_string(
        projection,
        requested,
        rows,
        NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN,
    )?;
    projection.add_string_extent(2 * blake3::OUT_LEN)?;
    add(requested, 2 * blake3::OUT_LEN)?;
    add(rows, 1)
}

fn future_counts(
    projection: &mut OriginalSerializationStorageProjection,
    keys: &[&str],
) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in keys {
        projection.add_field(key)?;
        // Every report count is a U64 decimal String. This is a serialized
        // extent only; it does not assign the not-yet-produced numeric result.
        projection.add_string_extent(20)?;
    }
    Ok(())
}

impl PacketControl {
    pub(crate) fn quote_original_capture_report_shape(
        &self,
        context: NativeCaptureReportObservationContext<'_>,
        maximum: usize,
    ) -> Result<NativeCaptureReportProjectionData, ProviderError> {
        let NativeCaptureReportObservationContext {
            original,
            observed,
            currency,
            metadata,
            endpoint_records_before,
            provider_next_sequence_before,
        } = context;
        currency.authenticate_before_observe(self)?;
        if original.method != Method::Observe
            || original.message != crate::envelope::MessageKind::Request
            || self.complete_protocol_metadata_birth_facts.as_ref() != Some(metadata)
            || self.complete_capture_allocation_selection.is_none()
        {
            return Err(ProviderError::Correlation(
                "native Observe report original scope differs",
            ));
        }
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation("native report binding roster"));
        };
        let active = self.active.as_ref().ok_or(ProviderError::Correlation(
            "native report active world absent",
        ))?;
        let request = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native report original ID absent",
            ))?;
        let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
        let mut strings = 0usize;
        let mut string_rows = 0usize;
        projection.add_object()?;
        for key in [
            "schema",
            "scope",
            "before",
            "after",
            "metadata_banks",
            "retained_requested_bytes",
            "shared_edges",
            "unique_roots",
            "growth",
            "transients",
        ] {
            projection.add_field(key)?;
        }
        owned_string(
            &mut projection,
            &mut strings,
            &mut string_rows,
            PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT,
        )?;
        projection.add_object()?;
        for key in [
            "native_pid",
            "observe_request",
            "observe_sequence",
            "observe_hash",
            "session",
            "incarnation",
            "node",
            "owner",
            "binding_hash",
            "world",
            "activation",
            "world_generation",
            "owner_generation",
            "model_cursor",
            "control_originals_before",
            "endpoint_records_before",
            "provider_next_sequence_before",
        ] {
            projection.add_field(key)?;
        }
        projection.add_value(&U64::new(u64::from(self.capture_creator)))?;
        owned_string(
            &mut projection,
            &mut strings,
            &mut string_rows,
            request.as_str(),
        )?;
        projection.add_value(&original.sequence)?;
        future_observe_hash(&mut projection, &mut strings, &mut string_rows)?;
        for identifier in [
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
            &binding.compatibility.node_id,
            &binding.compatibility.capture_owner.id,
        ] {
            owned_string(
                &mut projection,
                &mut strings,
                &mut string_rows,
                identifier.as_str(),
            )?;
        }
        // The real Observe dispatcher must validate this against its actual
        // binding before the transformer may build or publish a report.
        owned_hash(
            &mut projection,
            &mut strings,
            &mut string_rows,
            &observed.binding_hash,
        )?;
        owned_hash(
            &mut projection,
            &mut strings,
            &mut string_rows,
            &self.selection.world,
        )?;
        owned_string(
            &mut projection,
            &mut strings,
            &mut string_rows,
            active.activation_id.as_str(),
        )?;
        projection.add_value(&active.world_generation)?;
        projection.add_value(&binding.authority.owner_generation)?;
        projection.add_value(&currency.cursor())?;
        projection.add_value(&U64::new(
            u64::try_from(currency.originals_before()).map_err(|_| credit())?,
        ))?;
        projection.add_value(&U64::new(
            u64::try_from(endpoint_records_before).map_err(|_| credit())?,
        ))?;
        projection.add_value(&U64::new(provider_next_sequence_before))?;
        for _ in 0..2 {
            future_counts(
                &mut projection,
                &[
                    "encoded_capacity",
                    "literal_and_descriptor_bytes",
                    "current_encoded_bytes",
                ],
            )?;
        }
        projection.add_value(metadata)?;
        for _ in 0..3 {
            projection.add_string_extent(20)?;
        }
        future_counts(
            &mut projection,
            &[
                "observe_publication_bytes",
                "capture_request_bytes",
                "capture_publication_bytes",
                "after_confirmation_bytes",
            ],
        )?;
        future_counts(
            &mut projection,
            &[
                "observe_encoding_bytes",
                "model_control_encoding_bytes",
                "native_before_encoding_bytes",
                "native_after_encoding_bytes",
                "quote_scratch_bytes",
            ],
        )?;
        let encoding = projection.finish(maximum)?;
        let encoding_requested = encoding.requested_total()?;
        if size_of::<PacketNativeCaptureAllocationReport>()
            .checked_add(strings)
            .and_then(|bytes| bytes.checked_add(encoding_requested))
            .is_none_or(|bytes| bytes > maximum)
        {
            return Err(credit());
        }
        currency.authenticate_before_observe(self)?;
        Ok(NativeCaptureReportProjectionData {
            encoding,
            typed_report_layout_bytes: size_of::<PacketNativeCaptureAllocationReport>(),
            owned_string_requested_bytes: strings,
            owned_string_rows: string_rows,
        })
    }
}
