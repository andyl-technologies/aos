//! Compares original Q04 clock, stream and acknowledgement context DATA.
//!
//! These predicates share the historical comparisons used by the Controller
//! and Broker. Success supplies no native original, current cut or continuation.

use aos_sandbox_model::{ObjectDigest, RawPairedClockSample};

use super::{
    ProtectedHistoryDataErrorV1, Q04CutIdentityV1, Q04EffectSubgateV1,
    Q04PhaseRecordV1, Q04PreholdPublicationDataV1, Q04RootDecisionV1,
    Q04TransactionOwnerV1, fixed,
};

/// Bounds refreshed Source replies in the closed original Q04 programme.
///
/// The initial Source reply is additional. This is wire-programme geometry,
/// independent of the separate Source native transaction frame counts.
pub const Q04_ORIGINAL_SOURCE_REFRESH_COUNT_V1: usize = 11;

/// Selects the existing closed Q04 query on the original Root endpoint.
pub const Q04_ORIGINAL_QUERY_MAGIC_V1: &[u8; 8] = b"AOSSGQ04";

/// Compares a cut with original clock and authenticated-stream context DATA.
///
/// All inputs are comparison DATA. A successful comparison creates no native
/// origin, currentness, prehold, stream or Cache mutation continuation.
#[must_use]
pub fn matches_original_q04_cut_context_data_v1(
    identity: &Q04CutIdentityV1,
    original: RawPairedClockSample,
    nonce: [u8; 16],
    metadata: &[u8; 32],
    response: &Q04PreholdPublicationDataV1,
) -> bool {
    let cut = identity.bytes();
    let reply = response.bytes();

    identity.nonce() == nonce
        && cut[112..128] == original.host_boot_id()
        && cut[128..136] == original.boottime_nanoseconds().to_be_bytes()
        && cut[112..128] == metadata[..16]
        && cut[144..160] == metadata[16..32]
        && cut[168..200] == reply[128..160]
        && cut[296..328] == reply[288..320]
        && cut[328..392] == reply[320..384]
        && cut[392..424] == reply[64..96]
        && cut[520..584] == reply[160..224]
        && cut[616..648] == reply[256..288]
}

/// Compares one Root phase with its complete original acknowledgement context.
///
/// Historical comparison does not supply the stream, clock or phase authority.
/// The caller independently retains the actual original that produced the DATA.
///
/// # Errors
///
/// Preserves a malformed native transaction recipe or historical predecessor.
pub fn matches_original_q04_root_phase_data_v1(
    phase: &Q04PhaseRecordV1,
    expected_phase: u8,
    identity: &Q04CutIdentityV1,
    decision: &Q04RootDecisionV1,
    gate: &Q04EffectSubgateV1,
    acknowledgement: ObjectDigest,
    prior: Option<&Q04PhaseRecordV1>,
) -> Result<bool, ProtectedHistoryDataErrorV1> {
    if phase.phase() != expected_phase
        || phase.bytes()[96..128] != *decision.digest().as_bytes()
        || phase.bytes()[128..160] != *gate.digest().as_bytes()
        || phase.acknowledgement() != acknowledgement
        || phase.native_transaction_id() != Q04TransactionOwnerV1::Root.transaction_id(
            identity, phase.phase(), ObjectDigest::from_bytes(fixed(phase.bytes(), 64)),
        )?
    {
        return Ok(false);
    }

    if let Some(prior) = prior {
        phase.require_successor(prior)?;
    }

    Ok(true)
}
