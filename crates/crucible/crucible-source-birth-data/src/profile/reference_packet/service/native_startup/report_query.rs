//! Shares the actual report-query receive arithmetic without native authority.
//!
//! The upper native consumer supplies genuine compiled layout facts. This module
//! keeps the generic full-frame receive and selected native refinement distinct;
//! framing, authentication, correlation mutation and I/O remain upper-owned.

use super::super::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_QUERY;
use super::super::report_startup::PacketNativeReportStartupPurpose as Purpose;
use super::report_ack;
use crate::ProviderError;

/// Carries genuine fixed layouts from the actual upper query constructors.
///
/// These scalar facts are not native owners, population caps or admission rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportQueryFixedLayoutData {
    /// Reports the actual compiled Fresh query DTO header.
    pub fresh_query_bytes: usize,
    /// Reports the actual compiled Envelope header.
    pub envelope_bytes: usize,
    /// Reports the actual compiled connection-incident header.
    pub connection_incident_bytes: usize,
    /// Reports the actual compiled typed request-body header.
    pub request_body_bytes: usize,
    /// Reports the actual compiled typed Observe request header.
    pub observe_request_bytes: usize,
    /// Reports the actual Id plus Envelope correlation-entry width.
    pub correlation_key_value_bytes: usize,
    /// Reports the actual maximum Id/Envelope entry alignment.
    pub correlation_entry_alignment: usize,
}

/// Reports the same closed next-query receive components as arithmetic DATA.
///
/// No field grants a read, allocation, currentness claim or native authority.
pub struct OriginalReportQueryReceiveStorageData {
    /// Names the unchanged negotiated whole-frame byte ceiling.
    pub maximum_frame_body_bytes: usize,
    /// Counts the full raw/parser/Envelope and terminating-error population.
    pub raw_and_envelope_requested_bytes: usize,
    /// Counts the independent typed Observe and selected query construction.
    pub typed_query_requested_bytes: usize,
    /// Counts the original request correlation tree and ID population.
    pub correlation_requested_bytes: usize,
    /// Carries the separate defining declared local-header count.
    pub declared_counter_scratch_bytes: usize,
    /// Names a subextent of the original bank, not a new allocation.
    pub original_literal_required_bytes: usize,
    /// Names a subextent of the original descriptor bank.
    pub original_descriptor_required_bytes: usize,
}

impl OriginalReportQueryReceiveStorageData {
    /// Sums the independent raw, typed, correlation and declared-counter terms.
    ///
    /// # Errors
    /// Refuses checked requested-storage overflow.
    pub fn requested_bytes(&self) -> Result<usize, ProviderError> {
        sum(&[
            self.raw_and_envelope_requested_bytes,
            self.typed_query_requested_bytes,
            self.correlation_requested_bytes,
            self.declared_counter_scratch_bytes,
        ])
    }
}

/// Retains the four components computed before the actual final layout queries.
///
/// A consumer still queries its defining counter, checked original literal and
/// descriptor extent in that order. This partial record is not a complete row.
pub struct ReportQueryReceiveComponents {
    /// Names the negotiated whole-frame ceiling.
    pub maximum_frame_body_bytes: usize,
    /// Counts the full raw and Envelope owners.
    pub raw_and_envelope_requested_bytes: usize,
    /// Counts the independent typed query owners.
    pub typed_query_requested_bytes: usize,
    /// Counts the original correlation owners.
    pub correlation_requested_bytes: usize,
}

/// Computes the original generic receive prefix in its original error order.
///
/// # Errors
/// Refuses invalid limits, unrepresentable allowances or checked layout overflow.
pub fn query_receive_components_from_limits(
    limits: crate::profile::handshake::Limits,
    purpose: Purpose,
    fixed: &ReportQueryFixedLayoutData,
    ack: &report_ack::AckFixedLayoutData,
) -> Result<ReportQueryReceiveComponents, ProviderError> {
    crucible_node_format::Validate::validate(&limits)?;
    let bytes = allowance(limits.frame_bytes.get())?;
    let typed_query = match purpose {
        Purpose::OriginalObserve12 => 0,
        Purpose::FreshCompletedAdmit13 => sum(&[
            fixed.fresh_query_bytes,
            growth(PACKET_FRESH_RESTORE_ALLOCATION_QUERY.len())?,
            mul(3, growth(32)?)?,
        ])?,
    };
    let result = ReportQueryReceiveComponents {
        maximum_frame_body_bytes: bytes,
        // This reuses the real full-R raw/parser/four-DOM/canonical/error
        // primitive, not the smaller successful ACK or original-clone bound.
        // Its ResponseBody header is conservative extra; RequestBody below is
        // independently charged for the actual restricted Observe decode.
        raw_and_envelope_requested_bytes: sum(&[
            report_ack::open_ack_storage(bytes, ack)?,
            mul(2, fixed.envelope_bytes)?,
            fixed.connection_incident_bytes,
        ])?,
        typed_query_requested_bytes: sum(&[
            fixed.request_body_bytes,
            fixed.observe_request_bytes,
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
            crate::profile::requested_storage::tree_storage_data(
                1,
                1,
                fixed.correlation_key_value_bytes,
                fixed.correlation_entry_alignment,
            )?,
            128,
        ])?,
    };
    Ok(result)
}

/// Computes only the selected native raw/Envelope refinement.
///
/// This does not select the receive path or authenticate a native startup owner.
/// The actual upper native producer performs that selection independently.
///
/// # Errors
/// Preserves the actual original-open ACK and checked prefix-storage refusals.
pub fn native_raw_and_envelope_storage_data(
    bytes: usize,
    fixed: &ReportQueryFixedLayoutData,
    ack: &report_ack::AckFixedLayoutData,
) -> Result<usize, ProviderError> {
    sum(&[
        report_ack::native_original_open_ack_storage(bytes, ack)?,
        mul(2, fixed.envelope_bytes)?,
        fixed.connection_incident_bytes,
    ])
}

/// Adds the checked original JSON-literal extent at the caller's original field.
///
/// # Errors
/// Refuses overflow using the unchanged packet-prefix storage error.
pub fn original_literal_required_bytes(bytes: usize) -> Result<usize, ProviderError> {
    add(bytes, 4)
}

fn allowance(value: u64) -> Result<usize, ProviderError> {
    usize::try_from(value)
        .map_err(|_| ProviderError::ResourceExhausted("unrepresentable connection allowance"))
}

fn growth(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(bytes, 4)?, 256)
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |sum, value| add(sum, *value))
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original packet prefix requested storage")
}
