//! Canonical historical Controller anchor for one authenticated Capture60.
//!
//! The source, exact successful response and complete original Storage Session
//! snapshot remain immutable after the real native owner commits them under
//! C18. This codec checks every signed historical link but conveys DATA only:
//! a cold consumer must compare these exact bytes to the actual protected
//! ControllerStorageCaptureAdmission row keyed by execution.
//!
//! ```text
//! AOSCCA02 | response-length:u32be | history-length:u32be | source[944]
//!          | exact-response | exact-stored-Storage-Session | checksum[32]
//! ```

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1,
    BrokerSessionDurableEndpointV1, BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES};
use sha2::{Digest as _, Sha256};
use crate::authenticated_session::all_methods::{AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1};
use crate::authenticated_session::historical_method::historical_terminal_outcome;
use crate::authenticated_session::stored_history::{StoredBrokerSessionHistoryV1,
    VALUE_FIXED_BYTES_V3, canonical_protocol_key_v1};
use crate::storage_capture_grant::{StorageCaptureGrantSourceV1,
    StorageCaptureGrantSourceV2,
    decode_storage_capture_attempt_response_ongoing_v2};

const MAGIC: &[u8; 8] = b"AOSCCA02";
const PREFIX: usize = 16 + crate::storage_capture_grant::STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2;
const FIXED: usize = PREFIX + 32;
const DOMAIN: &[u8] = b"aos.sandbox.controller.capture-admission-anchor.v1\0";

/// Bounds complete Source944 plus the original authenticated Session framing.
pub const MAXIMUM_CAPTURE_ADMISSION_ANCHOR_BYTES_V2: usize = FIXED
    + crate::storage_capture_grant::MAXIMUM_RESPONSE_BODY_BYTES
    + VALUE_FIXED_BYTES_V3 + BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
    + crate::authenticated_session::historical_checkpoint::MAXIMUM_BYTES;

/// Rejects an incomplete, foreign or contradictory original admission anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid original Controller Capture admission anchor")]
pub struct ControllerCaptureAdmissionAnchorErrorV1;

type Result<T> = std::result::Result<T, ControllerCaptureAdmissionAnchorErrorV1>;

/// Retains exact historical signed-source DATA without native authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerCaptureAdmissionAnchorDataV1 {
    bytes: Vec<u8>,
    source: StorageCaptureGrantSourceV2,
    response_begin: usize,
    response_end: usize,
    attempt: crate::storage_capture_grant::ValidatedStorageCaptureAttemptV1,
}

impl ControllerCaptureAdmissionAnchorDataV1 {
    /// Borrows exact response/history widths before any model allocation.
    ///
    /// # Errors
    /// Refuses obsolete versions, malformed framing or inconsistent lengths.
    /// This verifies no signature, protected row or native custody.
    pub fn payload_widths_v4(bytes: &[u8]) -> Result<(usize, usize)> { framing_widths(bytes) }

    /// Bounds the complete full-source anchor before allocation.
    #[must_use]
    pub fn encoded_len_ongoing_v4(response_bytes: usize, history_bytes: usize) -> Option<usize> {
        if response_bytes == 0 || response_bytes > crate::storage_capture_grant::MAXIMUM_RESPONSE_BODY_BYTES
            || history_bytes == 0
        { return None; }
        let bytes = FIXED.checked_add(response_bytes)?.checked_add(history_bytes)?;
        (bytes <= MAXIMUM_CAPTURE_ADMISSION_ANCHOR_BYTES_V2).then_some(bytes)
    }

    /// Encodes complete ongoing-source and signed historical Session DATA.
    ///
    /// # Errors
    /// Rejects malformed or foreign signed request/source/response associations.
    pub fn new_ongoing_v4(source: &StorageCaptureGrantSourceV2, response: &[u8], history: &[u8]) -> Result<Self> {
        let length = Self::encoded_len_ongoing_v4(response.len(), history.len())
            .ok_or(ControllerCaptureAdmissionAnchorErrorV1)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| ControllerCaptureAdmissionAnchorErrorV1)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&u32::try_from(response.len()).map_err(|_| ControllerCaptureAdmissionAnchorErrorV1)?.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(history.len()).map_err(|_| ControllerCaptureAdmissionAnchorErrorV1)?.to_be_bytes());
        bytes.extend_from_slice(source.canonical_bytes_v2());
        bytes.extend_from_slice(response);
        bytes.extend_from_slice(history);
        let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes).finalize();
        bytes.extend_from_slice(&digest);
        Self::decode_owned(bytes)
    }

    /// Decodes the complete exact original Capture60 and its signed Session.
    ///
    /// # Errors
    /// Rejects malformed, unauthentic, foreign, truncated or noncanonical DATA.
    /// Protected Controller provenance remains an independent native obligation.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (source, response_begin, response_end, attempt) = validate(bytes)?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| ControllerCaptureAdmissionAnchorErrorV1)?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned, source, response_begin, response_end, attempt })
    }

    fn decode_owned(bytes: Vec<u8>) -> Result<Self> {
        let (source, response_begin, response_end, attempt) = validate(&bytes)?;
        Ok(Self { bytes, source, response_begin, response_end, attempt })
    }

    /// Borrows exact encoded bytes for protected-row equality.
    #[must_use]
    pub fn canonical_bytes_v1(&self) -> &[u8] { &self.bytes }

    /// Borrows the complete signed original source as historical DATA.
    #[must_use]
    pub const fn source_v1(&self) -> &StorageCaptureGrantSourceV1 { self.source.original_source_v1() }

    /// Borrows the full versioned source when this is an ongoing anchor.
    #[must_use]
    pub const fn ongoing_source_v2(&self) -> Option<&StorageCaptureGrantSourceV2> { Some(&self.source) }

    /// Returns the persisted original native effect horizon as comparison DATA.
    #[must_use]
    pub const fn effective_deadline_boottime_nanoseconds_v3(&self) -> u64 {
        match self.attempt.effective_deadline_boottime_nanoseconds() {
            Some(deadline) => deadline,
            None => 0,
        }
    }

    /// Returns the exact historical signed60 attempt as comparison DATA.
    #[must_use]
    pub const fn attempt_v3(&self) -> crate::storage_capture_grant::ValidatedStorageCaptureAttemptV1 {
        self.attempt
    }

    /// Borrows the actual exact authenticated60 success body.
    #[must_use]
    pub fn response_bytes_v1(&self) -> &[u8] { &self.bytes[self.response_begin..self.response_end] }

    /// Borrows the complete original protected Storage history value.
    #[must_use]
    pub fn storage_history_bytes_v1(&self) -> &[u8] {
        &self.bytes[self.response_end..self.bytes.len() - 32]
    }
}

fn validate(bytes: &[u8]) -> Result<(StorageCaptureGrantSourceV2, usize, usize,
    crate::storage_capture_grant::ValidatedStorageCaptureAttemptV1)>
{
    let invalid = || ControllerCaptureAdmissionAnchorErrorV1;
    let (response_length, _) = framing_widths(bytes)?;
    let digest_at = bytes.len().checked_sub(32).ok_or_else(invalid)?;
    let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..digest_at]).finalize();
    if bytes[digest_at..] != digest[..] { return Err(invalid()); }
    let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&bytes[16..PREFIX]).map_err(|_| invalid())?;
    let response_begin = PREFIX;
    let response_end = response_begin.checked_add(response_length).ok_or_else(invalid)?;
    let response = &bytes[response_begin..response_end];
    let attempt = decode_storage_capture_attempt_response_ongoing_v2(response, &source, false)
        .map_err(|_| invalid())?;
    attempt.effective_deadline_boottime_nanoseconds().ok_or_else(invalid)?;
    let stored = StoredBrokerSessionHistoryV1::decode(
        &canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage), &bytes[response_end..digest_at])
        .map_err(|_| invalid())?;
    if stored.protocol != BrokerSessionProtocolV1::Storage
        || stored.endpoint != BrokerSessionDurableEndpointV1::Client
    { return Err(invalid()); }
    let checkpoint = stored.checkpoint.as_ref().ok_or_else(invalid)?;
    let transcript = checkpoint.verify().map_err(|_| invalid())?;
    let history = stored.history_model().map_err(|_| invalid())?;
    let last = history.records().len().checked_sub(1).ok_or_else(invalid)?;
    let outcome = historical_terminal_outcome(history.records(), last, checkpoint, &transcript)
        .map_err(|_| invalid())?;
    if outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
        || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.request().storage_execution_capture_source_ongoing_v2() != Some(&source)
        || outcome.request().request_id() != source.original_source_v1().original_reserve_request_id()
        || outcome.request().deadline_boottime_nanoseconds() != source.original_source_v1().original_deadline_boottime_nanoseconds()
        || !matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { exact_body, .. }
            if exact_body.as_slice() == response)
    { return Err(invalid()); }
    Ok((source, response_begin, response_end, attempt))
}

fn framing_widths(bytes: &[u8]) -> Result<(usize, usize)> {
    let invalid = || ControllerCaptureAdmissionAnchorErrorV1;
    if bytes.len() < FIXED || bytes.len() > MAXIMUM_CAPTURE_ADMISSION_ANCHOR_BYTES_V2 {
        return Err(invalid());
    }
    if bytes.get(..8) != Some(MAGIC) { return Err(invalid()); }
    let response_length = usize::try_from(u32::from_be_bytes(take(bytes, 8)?)).map_err(|_| invalid())?;
    let history_length = usize::try_from(u32::from_be_bytes(take(bytes, 12)?)).map_err(|_| invalid())?;
    let expected = ControllerCaptureAdmissionAnchorDataV1::encoded_len_ongoing_v4(response_length, history_length);
    if expected != Some(bytes.len()) { return Err(invalid()); }
    Ok((response_length, history_length))
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(ControllerCaptureAdmissionAnchorErrorV1)?;
    bytes.get(offset..end).ok_or(ControllerCaptureAdmissionAnchorErrorV1)?
        .try_into().map_err(|_| ControllerCaptureAdmissionAnchorErrorV1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obsolete_anchor_marker_is_refused_before_model_decoding() {
        let mut bytes = vec![0; FIXED + 2];
        bytes[..8].copy_from_slice(b"AOSCCA01");
        bytes[8..12].copy_from_slice(&1_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&1_u32.to_be_bytes());

        assert!(ControllerCaptureAdmissionAnchorDataV1::payload_widths_v4(&bytes).is_err());
        assert!(ControllerCaptureAdmissionAnchorDataV1::decode(&bytes).is_err());
    }
}
