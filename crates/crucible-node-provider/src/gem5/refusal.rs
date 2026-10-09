//! Closed native/3 diagnostic reservation refusals for an original subordinate Poll.
//!
//! Parsing authenticates no native peer or execution authority. The owning driver
//! must first select the installed dialect and validate actual original native
//! scope. Zero callbacks in this response never erase earlier grant progress.
//!
//! ```text
//! {"kind":"run_refused","schema":"crucible.gem5.run-refused.v1",
//!  "operation":"original/prefix","original":{...},"boundary":{...},
//!  "processed_events":"0","reason":"diagnostic_credit","credit":{...}}
//! ```

use super::{GEM5_NATIVE_FRAME_BYTES, Gem5Boundary, Gem5Run};
use crate::ProviderError;
use crucible_node_contract::{Id, U64, canonical};
use serde::{Deserialize, Serialize};

/// Identifies the independently negotiated reservation/refusal dialect.
pub const GEM5_RESERVATION_PROTOCOL: &str = "crucible.gem5.native/3";

/// Retains the mandatory installed native diagnostic reservation policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5DiagnosticCreditPolicy {
    /// Selects the closed diagnostic-credit schema.
    pub schema: String,
    /// Bounds one actual immutable diagnostic body.
    pub maximum_object_bytes: U64,
    /// Bounds the complete actual retained diagnostic byte inventory.
    pub maximum_total_bytes: U64,
    /// Bounds the complete retained immutable diagnostic file inventory.
    pub maximum_files: U64,
    /// Selects the mandatory typed subordinate refusal schema.
    pub refusal_schema: String,
}

/// Retains a refused original reservation without authorizing another attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5RefusalCredit {
    /// Retains the original requested file reservation.
    pub required_files: U64,
    /// Retains actual remaining file credit before any callbacks.
    pub available_files: U64,
    /// Retains the original requested worst-case byte reservation.
    pub required_bytes: U64,
    /// Retains actual available logical byte credit before native callbacks.
    pub available_bytes: U64,
    /// Must be zero because the attempted reservation was not acquired.
    pub reserved_files: U64,
    /// Must be zero because the attempted reservation was not acquired.
    pub reserved_bytes: U64,
}

/// Retains the unchanged parked cut of one failed subordinate native Poll.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5RunRefusal {
    /// Must be `run_refused`, distinct from successful prefix completion.
    pub kind: String,
    /// Must select the explicitly negotiated refusal schema.
    pub schema: String,
    /// Names the original native prefix and cannot be reused for new effects.
    pub operation: Id,
    /// Retains the complete original immutable prefix permission.
    pub original: Gem5Run,
    /// Retains the actual unchanged native and logical boundary.
    pub boundary: Gem5Boundary,
    /// Must be zero for this subordinate Poll alone.
    pub processed_events: U64,
    /// Must identify diagnostic reservation exhaustion.
    pub reason: String,
    /// Retains the complete original attempted reservation and credit census.
    pub credit: Gem5RefusalCredit,
}

/// Preserves original refusal bytes after bounded pure structural validation.
///
/// This is historical data, not a seal establishing native no-effect knowledge.
/// Successful native peer validation and original journal reconciliation remain
/// mandatory before interpreting the parsed receipt in a running operation.
pub struct ParsedGem5RunRefusal {
    original_bytes: Vec<u8>,
    receipt: Gem5RunRefusal,
}

impl ParsedGem5RunRefusal {
    /// Borrows every original wire byte for immutable evidence and retry checks.
    pub fn bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    /// Borrows the structurally checked unchanged-cut refusal as inert data.
    pub fn receipt(&self) -> &Gem5RunRefusal {
        &self.receipt
    }
}

/// Parses a complete refusal under the explicitly selected original native/3 policy.
///
/// The expected boundary is the original stopped prefix cut. It may already
/// contain progress from earlier prefixes of the same common operation. Parsing
/// never declares that whole operation effect-free or releases output custody.
///
/// # Errors
/// Refuses old dialects, noncanonical or oversized frames, unsupported schemas,
/// missing fields, changed original permissions or boundaries, nonzero callback
/// progress, inconsistent budgets or a reservation that was not actually short.
pub fn parse_run_refusal(
    bytes: &[u8],
    dialect: &str,
    policy: &Gem5DiagnosticCreditPolicy,
    original: &Gem5Run,
    before: &Gem5Boundary,
) -> Result<ParsedGem5RunRefusal, ProviderError> {
    parse_run_refusal_for_model(
        bytes,
        dialect,
        super::model::Gem5ModelDialect::ReservedSe,
        policy,
        original,
        before,
    )
}

/// Parses refusal under an explicitly selected source-installed model dialect.
///
/// # Errors
/// Refuses legacy or foreign dialects before interpreting any attempted prefix.
/// Successful parsing remains inert data and grants no execution authority.
pub fn parse_run_refusal_for_model(
    bytes: &[u8],
    dialect: &str,
    selected: super::model::Gem5ModelDialect,
    policy: &Gem5DiagnosticCreditPolicy,
    original: &Gem5Run,
    before: &Gem5Boundary,
) -> Result<ParsedGem5RunRefusal, ProviderError> {
    let expected = match selected {
        super::model::Gem5ModelDialect::ReservedSe => GEM5_RESERVATION_PROTOCOL,
        super::model::Gem5ModelDialect::ArmLinux => "crucible.gem5.arm-linux-native/1",
        super::model::Gem5ModelDialect::LegacySe => {
            return Err(ProviderError::Frame(
                "legacy model has no reservation dialect",
            ));
        }
    };
    if dialect != expected
        || policy.schema != "crucible.gem5.diagnostic-credit-policy.v1"
        || policy.refusal_schema != "crucible.gem5.run-refused.v1"
        || policy.maximum_object_bytes.get() == 0
        || policy.maximum_total_bytes < policy.maximum_object_bytes
        || policy.maximum_files.get() == 0
    {
        return Err(ProviderError::Frame(
            "unsupported native reservation policy",
        ));
    }
    let value = canonical::parse_json(bytes, GEM5_NATIVE_FRAME_BYTES)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(ProviderError::Frame("noncanonical original run refusal"));
    }
    let receipt: Gem5RunRefusal = serde_json::from_value(value)
        .map_err(|_| ProviderError::Frame("invalid closed native run refusal"))?;
    if receipt.kind != "run_refused"
        || receipt.schema != policy.refusal_schema
        || receipt.reason != "diagnostic_credit"
        || receipt.operation != original.operation
        || receipt.original != *original
        || receipt.boundary != *before
        || receipt.processed_events.get() != 0
    {
        return Err(ProviderError::Correlation(
            "refused native prefix scope changed",
        ));
    }
    let credit = &receipt.credit;
    if credit.required_files.get() != 1
        || credit.required_bytes != policy.maximum_object_bytes
        || credit.available_files > policy.maximum_files
        || credit.available_bytes > policy.maximum_total_bytes
        || credit.reserved_files.get() != 0
        || credit.reserved_bytes.get() != 0
        || (credit.available_files >= credit.required_files
            && credit.available_bytes >= credit.required_bytes)
    {
        return Err(ProviderError::Frame(
            "inconsistent refused reservation credit",
        ));
    }
    Ok(ParsedGem5RunRefusal {
        original_bytes: bytes.to_vec(),
        receipt,
    })
}

/// Retains administrative custody acknowledgement for one original refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5RefusalAcknowledgement {
    /// Must be `refusal_acknowledged`, distinct from publication acknowledgement.
    pub kind: String,
    /// Names the original refused prefix whose immutable tombstone stays retained.
    pub operation: Id,
}

/// Checks an administrative refusal ACK without settling successful output custody.
///
/// # Errors
/// Refuses missing or extra fields, noncanonical bytes, successful-output ACKs or
/// another original prefix identity. Native peer validation remains mandatory.
pub fn validate_refusal_acknowledgement(
    bytes: &[u8],
    refusal: &ParsedGem5RunRefusal,
) -> Result<Gem5RefusalAcknowledgement, ProviderError> {
    let value = canonical::parse_json(bytes, GEM5_NATIVE_FRAME_BYTES)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(ProviderError::Frame("noncanonical refusal ACK"));
    }
    let ack: Gem5RefusalAcknowledgement = serde_json::from_value(value)
        .map_err(|_| ProviderError::Frame("invalid closed refusal ACK"))?;
    if ack.kind != "refusal_acknowledged" || ack.operation != refusal.receipt.operation {
        return Err(ProviderError::Correlation(
            "refusal ACK changed original custody",
        ));
    }
    Ok(ack)
}

#[cfg(test)]
#[path = "refusal_tests.rs"]
mod tests;
