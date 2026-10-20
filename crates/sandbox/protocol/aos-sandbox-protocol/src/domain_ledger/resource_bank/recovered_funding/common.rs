//! Owns the sole version-two recovered funding header/vector/checksum codec.
//!
//! Declared Delete17/Execution18 use five vectors; Stop21 uses four. Cleanup22
//! uses four vectors and its fixed financial association. Closed
//! purpose determines width. No legacy magic, variable vector list or supplied
//! type tag can reinterpret another purpose's declaration or seed semantics.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct FundingCommonDataV2 {
    pub(super) purpose: u8,
    pub(super) enrollment: EnrollmentIdentity,
    pub(super) recipient: [u8; 16],
    pub(super) baseline: ResourceVector,
    pub(super) charged_before: ResourceVector,
    pub(super) charged_after: ResourceVector,
    pub(super) complete: ResourceVector,
    pub(super) controller_next: u64,
    pub(super) controller_end: u64,
}

fn width_v2(purpose: u8, declared: bool) -> Result<usize, ResourceBankDataError> {
    match (purpose, declared) {
        (17 | 18, true) => Ok(RECOVERED_OPERATION_FUNDING_BYTES_V1),
        (21, false) => Ok(RECOVERED_LIFECYCLE_STOP_SEED_BYTES_V2),
        (22, false) => Ok(RECOVERED_HOST_STOP_CLEANUP_SEED_BYTES_V1),
        _ => Err(ResourceBankDataError::CorruptLedger),
    }
}

pub(super) fn require_canonical_v2(row: FundingCommonDataV2, declared: Option<ResourceVector>)
    -> Result<(), ResourceBankDataError> {
    width_v2(row.purpose, declared.is_some())?;
    let mut enrollment = [0; 96];
    codec::encode_enrollment(row.enrollment, &mut enrollment);
    codec::decode_enrollment(&enrollment)?;
    if row.recipient == [0; 16] || row.complete == ResourceVector::ZERO
        || row.controller_next == 0 || row.controller_next == u64::MAX || row.controller_end == 0
        || row.charged_before.checked_add(row.complete)? != row.charged_after
    { return Err(ResourceBankDataError::CorruptLedger); }
    row.baseline.checked_sub(row.charged_before)?;
    row.baseline.checked_sub(row.charged_after)?;
    if let Some(declared) = declared { declared.checked_sub(row.complete)?; }
    Ok(())
}

pub(super) fn encode_into_v2(row: FundingCommonDataV2, declared: Option<ResourceVector>, bytes: &mut [u8])
    -> Result<(), ResourceBankDataError> {
    encode_with_association_v2(row, declared, &[], bytes)
}

// The finite purpose controls the extension width. Ordinary rows cannot carry
// a cleanup association, and cleanup cannot masquerade as declared capacity.
pub(super) fn encode_with_association_v2(row: FundingCommonDataV2,
    declared: Option<ResourceVector>, association: &[u8], bytes: &mut [u8],
) -> Result<(), ResourceBankDataError> {
    let length = width_v2(row.purpose, declared.is_some())?;
    let expected = if row.purpose == 22 { HOST_STOP_CLEANUP_ASSOCIATION_BYTES_V1 } else { 0 };
    if bytes.len() != length || association.len() != expected {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    // The actual fixed output arrays are zero-initialized by both callers.
    bytes.fill(0);
    let purpose = row.purpose;
    let next = row.controller_next;
    let end = row.controller_end;
    codec::encode_enrollment(row.enrollment, &mut bytes[16..112]);
    bytes[112..128].copy_from_slice(&row.recipient);
    for (index, value) in [row.baseline, row.charged_before, row.charged_after, row.complete].into_iter().enumerate() {
        codec::encode_vector(value, &mut bytes[128 + index * 176..304 + index * 176]);
    }
    if let Some(declared) = declared { codec::encode_vector(declared, &mut bytes[832..1008]); }
    if row.purpose == 22 { bytes[832..1008].copy_from_slice(association); }
    require_canonical_v2(row, declared)?;
    bytes[..8].copy_from_slice(b"AOSRFS02");
    bytes[8] = purpose;
    let cut = length - 48;
    bytes[cut..cut + 8].copy_from_slice(&next.to_be_bytes());
    bytes[cut + 8..cut + 16].copy_from_slice(&end.to_be_bytes());
    let checksum = Sha256::digest(&bytes[..length - 32]);
    bytes[length - 32..].copy_from_slice(&checksum);
    Ok(())
}

pub(super) fn decode_v2(bytes: &[u8]) -> Result<(FundingCommonDataV2, Option<ResourceVector>), ResourceBankDataError> {
    if bytes.len() < 16 || &bytes[..8] != b"AOSRFS02" || bytes[9..16].iter().any(|byte| *byte != 0) {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    let declared = matches!(bytes[8], 17 | 18);
    let length = width_v2(bytes[8], declared)?;
    if bytes.len() != length || Sha256::digest(&bytes[..length - 32]).as_slice() != &bytes[length - 32..] {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    let cut = length - 48;
    let row = FundingCommonDataV2 {
        purpose: bytes[8], enrollment: codec::decode_enrollment(&bytes[16..112])?,
        recipient: bytes[112..128].try_into().map_err(|_| ResourceBankDataError::CorruptLedger)?,
        baseline: codec::decode_vector(&bytes[128..304])?,
        charged_before: codec::decode_vector(&bytes[304..480])?,
        charged_after: codec::decode_vector(&bytes[480..656])?,
        complete: codec::decode_vector(&bytes[656..832])?,
        controller_next: u64::from_be_bytes(bytes[cut..cut + 8].try_into().map_err(|_| ResourceBankDataError::CorruptLedger)?),
        controller_end: u64::from_be_bytes(bytes[cut + 8..cut + 16].try_into().map_err(|_| ResourceBankDataError::CorruptLedger)?),
    };
    let declared = if declared { Some(codec::decode_vector(&bytes[832..1008])?) } else { None };
    // The fixed scalar carrier is copied only for the validation call.
    require_canonical_v2(FundingCommonDataV2 { ..row }, declared)?;
    Ok((row, declared))
}

// One key recipe serves all three purpose-specific shapes. The callers have
// already checked their closed purpose; these bytes supply no native owner.
pub(super) fn key_v2(enrollment: EnrollmentIdentity, recipient: [u8; 16], purpose: u8) -> [u8; 17] {
    let mut encoded = [0; 96];
    codec::encode_enrollment(enrollment, &mut encoded);
    let hash = Sha256::new().chain_update(b"aos.controller.recovered-funding.key.v1\0")
        .chain_update(encoded).chain_update(recipient).chain_update([purpose]).finalize();
    let mut key = [0; 17];
    key[0] = PREFIX;
    key[1..].copy_from_slice(&hash[..16]);
    key
}
