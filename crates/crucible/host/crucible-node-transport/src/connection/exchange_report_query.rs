//! Restricts the selected startup report query before typed request decoding.
//!
//! Raw framing/JSON/Envelope parsing keeps the negotiated limit. Only the true
//! current native startup owner selects this read; its static source scopes and
//! closed Observe/query grammar are checked before allocating a RequestBody.
//! Generic receive remains unchanged and no mode is installed on Connection.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::service::ack_emitter::OriginalNativeReportStartupAllocation;
use crate::reference_packet::service::{
    PacketNative5SourceLaunch,
    fresh_restore_allocation::{
        PACKET_FRESH_RESTORE_ALLOCATION_QUERY, PacketNativeFreshRestoreAllocationQuery,
    },
    report_startup::PacketNativeReportStartupPurpose as Purpose,
};

pub(crate) struct OriginalReportQueryReceiveStorageData {
    pub(crate) maximum_frame_body_bytes: usize,
    pub(crate) raw_and_envelope_requested_bytes: usize,
    pub(crate) typed_query_requested_bytes: usize,
    pub(crate) correlation_requested_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
    /// Names a subextent of the original bank, not a new allocation.
    pub(crate) original_literal_required_bytes: usize,
    /// Names a subextent of the original descriptor bank.
    pub(crate) original_descriptor_required_bytes: usize,
}

impl OriginalReportQueryReceiveStorageData {
    pub(crate) fn requested_bytes(&self) -> Result<usize, ProviderError> {
        sum(&[
            self.raw_and_envelope_requested_bytes,
            self.typed_query_requested_bytes,
            self.correlation_requested_bytes,
            self.declared_counter_scratch_bytes,
        ])
    }
}

/// Counts a closed next-Observe read without issuing a read/allocation grant.
pub(crate) fn original_report_query_receive_storage_data(
    launch: &PacketNative5SourceLaunch,
    purpose: Purpose,
) -> Result<OriginalReportQueryReceiveStorageData, ProviderError> {
    native_query_receive_storage_from_limits(launch.limits, purpose)
}

fn native_query_receive_storage_from_limits(
    limits: crate::handshake::Limits,
    purpose: Purpose,
) -> Result<OriginalReportQueryReceiveStorageData, ProviderError> {
    let mut data = query_receive_storage_from_limits(limits, purpose)?;
    if matches!(purpose, Purpose::OriginalObserve12) {
        // This is the actual restricted native receive, not a feature-selected
        // generic read. Raw framing, parser, Error and partial owner terms stay.
        data.raw_and_envelope_requested_bytes = sum(&[
            acknowledgements::native_original_open_ack_storage(data.maximum_frame_body_bytes)?,
            mul(2, size_of::<Envelope>())?,
            size_of::<ConnectionIncident>(),
        ])?;
    }
    data.requested_bytes()?;
    Ok(data)
}

fn query_receive_storage_from_limits(
    limits: crate::handshake::Limits,
    purpose: Purpose,
) -> Result<OriginalReportQueryReceiveStorageData, ProviderError> {
    crucible_node_format::Validate::validate(&limits)?;
    let bytes = allowance(limits.frame_bytes.get())?;
    let typed_query = match purpose {
        Purpose::OriginalObserve12 => 0,
        Purpose::FreshCompletedAdmit13 => sum(&[
            size_of::<PacketNativeFreshRestoreAllocationQuery>(),
            growth(PACKET_FRESH_RESTORE_ALLOCATION_QUERY.len())?,
            mul(3, growth(32)?)?,
        ])?,
    };
    let result = OriginalReportQueryReceiveStorageData {
        maximum_frame_body_bytes: bytes,
        // This reuses the real full-R raw/parser/four-DOM/canonical/error
        // primitive, not the smaller successful ACK or original-clone bound.
        // Its ResponseBody header is conservative extra; RequestBody below is
        // independently charged for the actual restricted Observe decode.
        raw_and_envelope_requested_bytes: sum(&[
            acknowledgements::open_ack_storage(bytes)?,
            mul(2, size_of::<Envelope>())?,
            size_of::<ConnectionIncident>(),
        ])?,
        typed_query_requested_bytes: sum(&[
            size_of::<RequestBody>(),
            size_of::<crate::bodies::ObserveRequest>(),
            growth("blake3-256".len())?,
            growth("cnp.owner-binding.v1".len())?,
            growth(64)?,
            typed_query,
            // Query serde/DTO construction visits its three bounded Bytes
            // formatters before callbacks; malformed strings are rejected by
            // the scalar guard before that independent typed construction.
            match purpose {
                Purpose::OriginalObserve12 => 0,
                Purpose::FreshCompletedAdmit13 => mul(3, growth(43)?)?,
            },
        ])?,
        correlation_requested_bytes: sum(&[
            super::super::super::restore_input_quote::tree_storage(
                1,
                1,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
            128,
        ])?,
        declared_counter_scratch_bytes: original_report_query_receive_counter_scratch_data(),
        original_literal_required_bytes: add(bytes, 4)?,
        original_descriptor_required_bytes:
            crate::transport::original_frames::original_frame_slot_layout(),
    };
    result.requested_bytes()?;
    Ok(result)
}

impl<S: ProviderStream> Connection<S> {
    /// Quotes the same returned Observe layout from this actual connection.
    ///
    /// This is arithmetic DATA only. Actual original startup/currentness and
    /// the restricted receive predicate remain separate required guards.
    ///
    /// # Errors
    /// Refuses invalid negotiated limits or checked layout overflow.
    pub(crate) fn original_observe_returned_query_storage_data(
        &self,
    ) -> Result<usize, ProviderError> {
        let receive = native_query_receive_storage_from_limits(
            self.authority.limits(),
            Purpose::OriginalObserve12,
        )?;
        OriginalPacketPrefixStorageData::native_observe_returned_query_storage_data(&receive)
    }
}

/// Names declared local headers only, excluding compiler/recursive/allocator work.
pub(crate) const fn original_report_query_receive_counter_scratch_data() -> usize {
    size_of::<OriginalReportQueryReceiveStorageData>()
        + size_of::<Result<OriginalReportQueryReceiveStorageData, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<&OriginalReportQueryReceiveStorageData>()
        + size_of::<Envelope>()
        + size_of::<ReceivedFrame>()
        + size_of::<Purpose>()
        + size_of::<&OriginalNativeReportStartupAllocation>()
        + acknowledgements::native_original_open_ack_counter_scratch_data()
        + size_of::<OriginalReportQueryReceiveStorageData>()
        + size_of::<Result<OriginalReportQueryReceiveStorageData, ProviderError>>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<[usize; 3]>()
        + size_of::<bool>()
}

/// Checks static installed source data; this predicate is not a startup issuer.
pub(crate) fn authenticate_original_report_query_header_data(
    selection: &PacketControlSelection,
    purpose: Purpose,
    query: &Envelope,
) -> Result<(), ProviderError> {
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(query_error());
    };
    if query.protocol != "CNP/1"
        || query.message != MessageKind::Request
        || query.method != Method::Observe
        || query.sequence.get() == 0
        || query.request_id.0.is_none()
        || query.session_id.0.as_ref() != Some(&binding.authority.session_id)
        || query.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
        || query.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || query.execution_owner_id.0.as_ref() != Some(&binding.compatibility.execution_owner.id)
        || query.capture_owner_id.0.is_some()
        || query.operation_id.0.is_some()
        || query.body.len() != 5
        || query
            .body
            .get("extensions")
            .and_then(Value::as_object)
            .is_none_or(|v| !v.is_empty())
        || decimal(query.body.get("owner_generation"))? != binding.authority.owner_generation.get()
        || decimal(query.body.get("after_observation_sequence"))? != 0
    {
        return Err(query_error());
    }
    let maximum = decimal(query.body.get("maximum_items"))?;
    if maximum == 0
        || maximum
            > match purpose {
                Purpose::OriginalObserve12 => 64,
                Purpose::FreshCompletedAdmit13 => 1,
            }
    {
        return Err(query_error());
    }
    let hash = query
        .body
        .get("binding_hash")
        .and_then(Value::as_object)
        .ok_or_else(query_error)?;
    if hash.len() != 3
        || hash.get("algorithm").and_then(Value::as_str) != Some("blake3-256")
        || hash.get("domain").and_then(Value::as_str) != Some("cnp.owner-binding.v1")
        || hash.get("digest").and_then(Value::as_str).is_none_or(|v| {
            v.len() != 64
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    {
        return Err(query_error());
    }
    match purpose {
        Purpose::OriginalObserve12 if query.extensions.is_empty() => Ok(()),
        Purpose::FreshCompletedAdmit13 if query.extensions.len() == 1 => {
            let value = query
                .extensions
                .get(PACKET_FRESH_RESTORE_ALLOCATION_QUERY)
                .and_then(Value::as_object)
                .ok_or_else(query_error)?;
            if value.len() != 4
                || value.get("schema").and_then(Value::as_str)
                    != Some(PACKET_FRESH_RESTORE_ALLOCATION_QUERY)
            {
                return Err(query_error());
            }
            for key in [
                "nonce",
                "completed_admit_request",
                "completed_admit_response",
            ] {
                let value = value
                    .get(key)
                    .and_then(Value::as_str)
                    .ok_or_else(query_error)?;
                if value.len() != 43
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(query_error());
                }
            }
            Ok(())
        }
        _ => Err(query_error()),
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn receive_original_native_report_query(
        &mut self,
        startup: &OriginalNativeReportStartupAllocation,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        startup.authenticate_current(self)?;
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(query_error());
        }
        // No prior unresolved registration is allowed into this one read's
        // incident/correlation budget. Actual report/currency state is native.
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let result = self.receive_original_native_report_query_inner(startup);
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_native_report_query_inner(
        &mut self,
        startup: &OriginalNativeReportStartupAllocation,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        startup.authenticate_query_header_data(self, &envelope)?;
        let body = self.validate_body(&envelope, true)?;
        self.retain_original_request_id(&envelope, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        startup.authenticate_current(self)?;
        Ok(Some(ReceivedFrame { envelope, body }))
    }
}

fn decimal(value: Option<&Value>) -> Result<u64, ProviderError> {
    let value = value.and_then(Value::as_str).ok_or_else(query_error)?;
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) || value.len() > 20 {
        return Err(query_error());
    }
    value.bytes().try_fold(0u64, |n, b| {
        if !b.is_ascii_digit() {
            return Err(query_error());
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))
            .ok_or_else(query_error)
    })
}

fn query_error() -> ProviderError {
    ProviderError::Correlation("native startup query header or scalar grammar")
}

#[cfg(test)]
#[path = "exchange_report_query_tests.rs"]
mod tests;
