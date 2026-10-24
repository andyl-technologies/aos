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

use crucible_source_birth_data::profile::reference_packet::service::native_startup::report_query as shared;
pub(crate) use shared::OriginalReportQueryReceiveStorageData;

#[path = "exchange_report_query/layout.rs"]
mod layout;

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
        data.raw_and_envelope_requested_bytes = shared::native_raw_and_envelope_storage_data(
            data.maximum_frame_body_bytes,
            &layout::FIXED,
            &acknowledgements::ACK_FIXED_LAYOUT,
        )?;
    }
    data.requested_bytes()?;
    Ok(data)
}

fn query_receive_storage_from_limits(
    limits: crate::handshake::Limits,
    purpose: Purpose,
) -> Result<OriginalReportQueryReceiveStorageData, ProviderError> {
    let components = shared::query_receive_components_from_limits(
        limits,
        purpose,
        &layout::FIXED,
        &acknowledgements::ACK_FIXED_LAYOUT,
    )?;
    let result = OriginalReportQueryReceiveStorageData {
        maximum_frame_body_bytes: components.maximum_frame_body_bytes,
        raw_and_envelope_requested_bytes: components.raw_and_envelope_requested_bytes,
        typed_query_requested_bytes: components.typed_query_requested_bytes,
        correlation_requested_bytes: components.correlation_requested_bytes,
        declared_counter_scratch_bytes: original_report_query_receive_counter_scratch_data(),
        original_literal_required_bytes: shared::original_literal_required_bytes(
            components.maximum_frame_body_bytes,
        )?,
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
        // Lower by-value inputs coexist with the retained upper function's
        // Limits and Purpose inputs; neither old header donates this window.
        + size_of::<crate::handshake::Limits>()
        + size_of::<Purpose>()
        // The lower initializer/return and upper receiver/`?` input remain
        // independent of the completed row already counted above.
        + size_of::<shared::ReportQueryReceiveComponents>()
        + size_of::<Result<shared::ReportQueryReceiveComponents, ProviderError>>()
        + size_of::<shared::ReportQueryReceiveComponents>()
        + size_of::<Result<shared::ReportQueryReceiveComponents, ProviderError>>()
        // The formed upper const loans and lower borrowed inputs overlap.
        // Generic and native calls are sequential and share this fixed row.
        + size_of::<&shared::ReportQueryFixedLayoutData>()
        + size_of::<&crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::AckFixedLayoutData>()
        + size_of::<&shared::ReportQueryFixedLayoutData>()
        + size_of::<&crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::AckFixedLayoutData>()
        // The added native-refinement and literal forwarders run sequentially:
        // scalar input/return and returned Result/upper `?` input are named.
        + size_of::<usize>()
        + size_of::<usize>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
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

#[cfg(test)]
#[path = "exchange_report_query/layout_tests.rs"]
mod layout_tests;
