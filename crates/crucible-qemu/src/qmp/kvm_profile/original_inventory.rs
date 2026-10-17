//! Bounded observation of retained original native RUN identities.
//!
//! Native scheduling determines journal order. Callers learn original row and
//! invocation identities from this namespace rather than guessing CPU order.
//! Separate pages are observations, not one immutable snapshot: an authenticated
//! ACK may change a row's knowledge between page queries.

use serde::{Deserialize, Serialize};

use super::{
    QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpTimeoutStream, exchange_component,
};

const MAXIMUM_RETURNS: u32 = 65_536;
const MAXIMUM_PAGE: u32 = 128;
const MAXIMUM_VCPUS: u32 = 4096;

/// Selects an observational page from the actual retained native ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmOriginalReturnsRequest {
    /// Selects the exact current original source-owned window generation.
    pub generation: u64,
    /// Selects the first retained lifetime row, including an empty final page.
    pub first_record: u32,
    /// Bounds returned entries to a positive count of at most 128.
    pub maximum_records: u32,
}

/// Identifies one original source-owned return without ACK or dispatch permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmOriginalReturnIdentity {
    /// Identifies the original preallocated lifetime row.
    pub record_index: u32,
    /// Identifies that row's original window, possibly older than this page.
    pub generation: u64,
    /// Identifies the actual reserved kernel invocation; it is not a CPU ordinal.
    pub expected_invocation: u64,
    /// Identifies the original immutable QEMU CPU roster slot.
    pub vcpu_index: u32,
    /// Identifies the actual original kernel CPU; BSP zero is valid.
    pub native_vcpu_id: u64,
    /// Reports whether the original native RUN syscall was actually issued.
    pub issued: bool,
    /// Reports whether the original kernel return is retained by its owner.
    pub receipt_known: bool,
    /// Reports an exact previous ACK proving this attempt had no new birth.
    pub no_birth_known: bool,
    /// Reports the retained original ACK outcome, without executing another ACK.
    pub ack_known: bool,
}

/// Reports one finite source-owned page at the original stopped CPU cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmOriginalReturnsObservation {
    /// Selects this observational response edition, exactly one.
    pub schema_version: u32,
    /// Identifies the current exact source-owned window generation.
    pub generation: u64,
    /// Retains the requested first lifetime row.
    pub first_record: u32,
    /// Identifies the first row after the returned contiguous page.
    pub next_record: u32,
    /// Counts the complete finite source-owned lifetime ledger.
    pub retained_returns: u32,
    /// Lists actual retained native identities in contiguous row order.
    pub entries: Vec<QmpKvmOriginalReturnIdentity>,
    /// Remains false because this observation cannot qualify a runnable node.
    pub profile_qualified: bool,
}

/// Retains one request-correlated bounded original-return observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpKvmOriginalReturnsState {
    observed: QmpKvmOriginalReturnsObservation,
}

impl QmpKvmOriginalReturnsState {
    /// Borrows the partial page without providing native operation authority.
    pub fn observed(&self) -> &QmpKvmOriginalReturnsObservation {
        &self.observed
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Queries the actual stopped original native return identities.
    ///
    /// This command performs no ioctl, ACK, RUN, reconciliation or device
    /// dispatch. The caller independently authenticates installed artifacts
    /// and the retained peer. It must not combine pages into a capture proof.
    ///
    /// # Errors
    /// Refuses invalid page credit before I/O, actual native refusal, transport
    /// failure, changed generation/indices, unbounded or inconsistent identities,
    /// unknown response fields, or any profile qualification claim.
    pub fn query_native_kvm_original_returns(
        &mut self,
        request: &QmpKvmOriginalReturnsRequest,
    ) -> Result<QmpKvmOriginalReturnsState, QmpError> {
        validate_original_returns_request(request)?;
        exchange_component(self, QmpCommand::KvmOriginalReturns { request }, |value| {
            parse_original_returns(request, value)
        })
    }
}

fn malformed_inventory(reason: &'static str) -> QmpError {
    QmpError::MalformedTypedResponse {
        command: QmpCommandKind::KvmOriginalReturns,
        response: reason.to_owned(),
    }
}

fn validate_original_returns_request(
    request: &QmpKvmOriginalReturnsRequest,
) -> Result<(), QmpError> {
    if request.maximum_records == 0
        || request.maximum_records > MAXIMUM_PAGE
        || request.first_record > MAXIMUM_RETURNS
    {
        return Err(malformed_inventory("invalid original native return page"));
    }
    Ok(())
}

fn parse_original_returns(
    request: &QmpKvmOriginalReturnsRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmOriginalReturnsState, QmpError> {
    let malformed = || malformed_inventory("inconsistent or qualified native return page");
    let entries = value
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(malformed)?;
    if entries.len() > request.maximum_records as usize {
        return Err(malformed());
    }
    let observed: QmpKvmOriginalReturnsObservation =
        serde_json::from_value(value.clone()).map_err(|_| malformed())?;
    if observed.schema_version != 1
        || observed.generation != request.generation
        || observed.first_record != request.first_record
        || observed.retained_returns > MAXIMUM_RETURNS
        || observed.first_record > observed.retained_returns
        || observed.profile_qualified
    {
        return Err(malformed());
    }
    let expected_count = request
        .maximum_records
        .min(observed.retained_returns - observed.first_record);
    let expected_next = observed
        .first_record
        .checked_add(expected_count)
        .ok_or_else(malformed)?;
    if observed.next_record != expected_next || observed.entries.len() != expected_count as usize {
        return Err(malformed());
    }
    for (offset, entry) in observed.entries.iter().enumerate() {
        let offset = u32::try_from(offset).map_err(|_| malformed())?;
        if entry.record_index != observed.first_record + offset
            || entry.generation == 0
            || entry.generation > observed.generation
            || entry.expected_invocation == 0
            || entry.vcpu_index >= MAXIMUM_VCPUS
            || (entry.receipt_known && !entry.issued)
            || (entry.no_birth_known && (!entry.issued || entry.receipt_known || !entry.ack_known))
            || (entry.ack_known && !entry.receipt_known && !entry.no_birth_known)
        {
            return Err(malformed());
        }
    }
    Ok(QmpKvmOriginalReturnsState { observed })
}

#[cfg(test)]
#[path = "original_inventory_tests.rs"]
mod tests;
