//! Checks original checksum windows through independent byte-limb arithmetic.
//!
//! These records carry observations, not native authority. The installation
//! verifier authenticates their original measured process, request and receipt
//! custody before using this oracle result in a behavioral claim. A successful
//! result establishes only the declared checksum/window properties; it grants
//! neither repeatability nor state preservation.

use crucible_node_contract::{Bytes, ContentRef, Id, Phase, U64, canonical};
use crucible_node_provider::reference_device::{DeviceGrant, DeviceOutput, DeviceReceipt};
use serde::{Deserialize, Serialize};

use super::QualificationError;

/// Retains one original native request, input and transferred output evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceWindowObservation {
    /// Contains the immutable grant extracted from the original admitted request.
    pub original_grant: DeviceGrant,
    /// Contains exactly the original authenticated immutable input bytes.
    pub input: Bytes,
    /// Commits to the original complete transferred native stop receipt.
    pub receipt: ContentRef,
    /// Contains original receipt bytes, without reconstruction or normalization.
    pub receipt_bytes: Bytes,
    /// Commits to the original native publication payload.
    pub payload: ContentRef,
    /// Contains the exact original payload bytes released at the boundary.
    pub payload_bytes: Bytes,
}

/// Selects independently measured source scope and predeclared harness bounds.
pub struct ReferenceOracleContract {
    /// Names the actual originally enrolled native execution owner.
    pub owner: Id,
    /// Names the actual originally enrolled native process incarnation.
    pub incarnation: Id,
    /// Fences older actual owner realizations.
    pub generation: U64,
    /// Selects the positive fixed logical window duration in picoseconds.
    pub quantum_ps: U64,
    /// Selects the positive installed physical activation budget in nanoseconds.
    pub host_budget_ns: U64,
    /// Selects the first original window index from the immutable fixture.
    pub first_quantum: U64,
    /// Selects the first original physical sampling boundary.
    pub first_time_ps: U64,
    /// Selects the actual predeclared cumulative native checksum state.
    pub initial_checksum: U64,
    /// Bounds the complete fixture population before traversing observations.
    pub maximum_windows: usize,
    /// Bounds immutable original input bytes per window, at most4096.
    pub maximum_input_bytes: usize,
    /// Retains the complete independently declared original control population.
    pub expected_windows: Vec<ReferenceExpectedWindow>,
}

/// Binds a fixture's immutable original request and input before native execution.
pub struct ReferenceExpectedWindow {
    /// Identifies the predeclared original window request.
    pub window: Id,
    /// Identifies its predeclared immutable input batch.
    pub batch: Id,
    /// Commits to the exact predeclared input octets and their media type.
    pub input: ContentRef,
}

/// Reports independent oracle facts without minting qualification authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceOracleResult {
    /// Identifies this bounded independent checksum/window interpretation.
    pub schema: String,
    /// Counts the complete checked original window population.
    pub windows: U64,
    /// Counts all original consumed bytes without changing input order.
    pub bytes_processed: U64,
    /// Reports the independently computed cumulative checksum.
    pub checksum: U64,
    /// Retains every original receipt reference in original window order.
    pub receipts: Vec<ContentRef>,
    /// Retains every original payload reference in original window order.
    pub payloads: Vec<ContentRef>,
}

/// Checks all original windows against independent input and clock oracles.
///
/// # Errors
/// Refuses incomplete or over-budget populations, changed original scope or
/// content, reordered windows, arithmetic overflow, failed physical park/budget,
/// incorrect publication coordinates, byte counts or native checksum payloads.
pub fn verify_reference_windows(
    contract: &ReferenceOracleContract,
    windows: &[ReferenceWindowObservation],
) -> Result<ReferenceOracleResult, QualificationError> {
    if contract.generation.get() == 0
        || contract.quantum_ps.get() == 0
        || contract.host_budget_ns.get() == 0
        || contract.maximum_windows == 0
        || contract.maximum_windows > 1024
        || contract.maximum_input_bytes > 4096
        || windows.is_empty()
        || windows.len() > contract.maximum_windows
        || windows.len() != contract.expected_windows.len()
    {
        return Err(QualificationError::Refused(
            "invalid checksum oracle scope or population",
        ));
    }
    let mut checksum = ByteLimbChecksum::new(contract.initial_checksum.get());
    let mut quantum = contract.first_quantum.get();
    let mut time = contract.first_time_ps.get();
    let mut total_bytes = 0u64;
    let mut receipts = Vec::new();
    let mut payloads = Vec::new();
    receipts
        .try_reserve_exact(windows.len())
        .map_err(|_| QualificationError::Refused("oracle receipt allocation"))?;
    payloads
        .try_reserve_exact(windows.len())
        .map_err(|_| QualificationError::Refused("oracle payload allocation"))?;

    for (index, window) in windows.iter().enumerate() {
        let grant = &window.original_grant;
        let expected_window = &contract.expected_windows[index];
        let publication_time =
            time.checked_add(contract.quantum_ps.get())
                .ok_or(QualificationError::Refused(
                    "oracle physical coordinate overflow",
                ))?;
        if grant.owner_id != contract.owner
            || grant.incarnation_id != contract.incarnation
            || grant.generation != contract.generation
            || grant.quantum.get() != quantum
            || grant.host_budget_ns != contract.host_budget_ns
            || grant.window_id != expected_window.window
            || grant.input_batch_id != expected_window.batch
            || grant.start.time_ps.get() != time
            || grant.start.microstep.get() != 0
            || grant.start.phase != Phase::BoundaryControl
            || grant.publication.time_ps.get() != publication_time
            || grant.publication.microstep.get() != 0
            || grant.publication.phase != Phase::Publication
            || window.input.as_slice().len() > contract.maximum_input_bytes
            || window.receipt_bytes.as_slice().len() > 65_536
            || window.payload_bytes.as_slice().len() > 4096
        {
            return Err(QualificationError::Refused(
                "changed original checksum window scope",
            ));
        }
        expected_window.input.verify(window.input.as_slice())?;
        window.receipt.verify(window.receipt_bytes.as_slice())?;
        window.payload.verify(window.payload_bytes.as_slice())?;
        let receipt: DeviceReceipt = decode_original(window.receipt_bytes.as_slice(), 65_536)?;
        let payload: DeviceOutput = decode_original(window.payload_bytes.as_slice(), 4096)?;
        let length = u64::try_from(window.input.as_slice().len())
            .map_err(|_| QualificationError::Refused("oracle input length overflow"))?;
        for byte in window.input.as_slice() {
            checksum.push(*byte);
        }
        let expected = DeviceOutput {
            bytes_processed: U64::new(length),
            checksum: U64::new(checksum.value()),
        };
        if receipt.grant != *grant
            || !receipt.application_parked
            || receipt.measured_host_ns.get() > contract.host_budget_ns.get()
            || receipt.output != expected
            || payload != expected
        {
            return Err(QualificationError::Refused(
                "independent native checksum or budget oracle failed",
            ));
        }
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or(QualificationError::Refused(
                "oracle cumulative byte overflow",
            ))?;
        receipts.push(window.receipt.clone());
        payloads.push(window.payload.clone());
        time = publication_time;
        if index + 1 < windows.len() {
            quantum = quantum.checked_add(1).ok_or(QualificationError::Refused(
                "oracle quantum counter overflow",
            ))?;
        }
    }
    Ok(ReferenceOracleResult {
        schema: "crucible.reference-checksum-oracle.v1".into(),
        windows: U64::new(
            u64::try_from(windows.len())
                .map_err(|_| QualificationError::Refused("oracle population overflow"))?,
        ),
        bytes_processed: U64::new(total_bytes),
        checksum: U64::new(checksum.value()),
        receipts,
        payloads,
    })
}

fn decode_original<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, QualificationError> {
    let value = canonical::parse_json(bytes, maximum)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(QualificationError::Refused(
            "noncanonical original native evidence",
        ));
    }
    serde_json::from_value(value).map_err(|error| {
        QualificationError::Contract(crucible_node_contract::ContractError::Json(error))
    })
}

// The native device uses u64 wrapping multiplication. This oracle implements
// the specified polynomial in base256 with explicit carry, truncating only the
// declared modulo2^64 checksum. Coordinate/budget arithmetic never wraps.
struct ByteLimbChecksum([u8; 8]);

impl ByteLimbChecksum {
    fn new(value: u64) -> Self {
        Self(value.to_le_bytes())
    }

    fn push(&mut self, byte: u8) {
        let old = self.0;
        let mut carry = u16::from(byte);
        for (index, limb) in self.0.iter_mut().enumerate() {
            let shifted = if index == 0 {
                0
            } else {
                u16::from(old[index - 1])
            };
            let sum = u16::from(old[index]) + shifted + carry;
            *limb = (sum & 255) as u8;
            carry = sum >> 8;
        }
    }

    fn value(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

#[cfg(test)]
mod tests;
