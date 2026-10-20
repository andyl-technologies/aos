//! Separates short physical acquisition from the original ongoing lifetime.
//!
//! This explicit begin version binds the complete signed SourceV2. The shared
//! native proof/terminal/ACK schemas keep their exact existing encoders and
//! carry this distinct begin digest; only explicit ongoing comparators accept
//! the full source. Parsed lifetime DATA never replaces an actual native owner.
//!
//! ```text
//! AOSEOHS3 | v3:u16be | zero[2] | nonce[32] | ongoing-D:u64be
//! | acquisition-cutoff:u64be | AOSSCG02[944] | attempt[16]
//! | durable-attempt-digest[32] | nonce-readback-deadline:u64be
//! ```

use super::*;
use crate::storage_capture_grant::StorageCaptureGrantSourceV2;

/// Exact complete explicit ongoing begin width.
pub const CAPTURE_BEGIN_BYTES_V3: usize = 1060;
const BEGIN_DOMAIN_V3: &[u8] = b"aos.sandbox.storage.capture-held-begin.v3\0";

/// Binds both immutable bounds to the exact signed full source and native attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureHeldBeginDataV3 {
    /// Fresh challenge for the actual same held channel.
    pub nonce: [u8; 32],
    /// Original ongoing bound intersected with the persisted native attempt.
    pub cutoff_boottime_nanoseconds: u64,
    /// Original actual59/source acquisition bound, distinct from ongoing use.
    pub acquisition_cutoff_boottime_nanoseconds: u64,
    /// Fresh nonce/readback bound intersected with both immutable horizons.
    pub acquisition_deadline_boottime_nanoseconds: u64,
    /// Complete Controller-signed acquisition and original-lifetime source.
    pub source: StorageCaptureGrantSourceV2,
    /// Exact already-committed native attempt identity.
    pub attempt: [u8; 16],
    /// Exact durable native attempt commitment.
    pub durable_attempt_digest: ObjectDigest,
}

impl CaptureHeldBeginDataV3 {
    /// Joins an explicit ongoing response without renewing either horizon.
    ///
    /// # Errors
    /// Rejects absence, foreign/full source, response substitution, missing
    /// native deadline, a larger ongoing bound, or invalid acquisition fields.
    pub fn new(nonce: [u8; 32], cutoff: u64, acquisition_cutoff: u64,
        nonce_deadline: u64, source: StorageCaptureGrantSourceV2,
        attempt: ValidatedStorageCaptureAttemptV1) -> Result<Self> {
        if attempt.status() != StorageCaptureAttemptStatusV1::EffectPossible
            || attempt.locator() != source.locator_v2()
            || cutoff > attempt.effective_deadline_boottime_nanoseconds().ok_or_else(invalid)?
        { return Err(invalid()); }
        let value = Self { nonce, cutoff_boottime_nanoseconds: cutoff,
            acquisition_cutoff_boottime_nanoseconds: acquisition_cutoff,
            acquisition_deadline_boottime_nanoseconds: nonce_deadline, source,
            attempt: attempt.attempt().ok_or_else(invalid)?,
            durable_attempt_digest: attempt.durable_attempt_digest().ok_or_else(invalid)? };
        value.encode()?;
        Ok(value)
    }

    /// Encodes both fixed original horizons and the full signed source.
    ///
    /// # Errors
    /// Rejects invalid coordinates or any bound larger than its original source.
    pub fn encode(self) -> Result<[u8; CAPTURE_BEGIN_BYTES_V3]> {
        encode_begin_frame_v3(self.nonce,
            self.cutoff_boottime_nanoseconds, self.acquisition_cutoff_boottime_nanoseconds,
            self.acquisition_deadline_boottime_nanoseconds,
            self.source.effective_execution_deadline_v2(),
            self.source.original_source_v1().original_deadline_boottime_nanoseconds(),
            self.source.canonical_bytes_v2(), self.attempt, self.durable_attempt_digest)
    }

    /// Decodes the versioned begin without granting physical or ongoing use.
    ///
    /// # Errors
    /// Rejects another version, malformed source, identities or either horizon.
    /// The actual server must still compare the retained native attempt deadline.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let frame = decode_begin_frame_v3(bytes)?;
        let value = Self { nonce: frame.nonce, cutoff_boottime_nanoseconds: frame.cutoff,
            acquisition_cutoff_boottime_nanoseconds: frame.acquisition_cutoff,
            acquisition_deadline_boottime_nanoseconds: frame.nonce_deadline,
            source: StorageCaptureGrantSourceV2::from_canonical_bytes_v2(frame.source)?,
            attempt: frame.attempt, durable_attempt_digest: frame.durable };
        value.encode()?;
        Ok(value)
    }

    /// Commits every original acquisition and ongoing coordinate under version3.
    ///
    /// # Errors
    /// Rejects any canonical encoding refusal.
    pub fn digest(self) -> Result<[u8; 32]> { Ok(digest(BEGIN_DOMAIN_V3, &self.encode()?)) }
}

impl CaptureHeldProofDataV2 {
    /// Compares the exact ongoing begin while reusing the sole physical row checker.
    ///
    /// # Errors
    /// Rejects another complete source/begin or any old physical coordinate refusal.
    pub fn verify_begin_ongoing_v3(self, begin: CaptureHeldBeginDataV3) -> Result<()> {
        self.verify_begin_coordinates_v3(begin.digest()?, begin.nonce, begin.source.original_source_v1())
    }
}

impl CaptureHeldTerminalDataV2 {
    /// Constructs a terminal for the exact ongoing begin and physical proof.
    ///
    /// # Errors
    /// Rejects a different source/proof or the existing mode/digest constraints.
    pub fn new_ongoing_v3(begin: CaptureHeldBeginDataV3, proof: CaptureHeldProofDataV2,
        mode: CaptureTerminalModeDataV2, settlement: ObjectDigest) -> Result<Self> {
        proof.verify_begin_ongoing_v3(begin)?;
        Self::new_bound_v3(begin.nonce, begin.digest()?, proof, mode, settlement)
    }

    /// Compares this same terminal against the whole ongoing hold.
    ///
    /// # Errors
    /// Rejects substituted original source, nonce, digests or head.
    pub fn verify_proof_ongoing_v3(self, begin: CaptureHeldBeginDataV3,
        proof: CaptureHeldProofDataV2) -> Result<()> {
        if self != Self::new_ongoing_v3(begin, proof, self.mode, self.settlement_digest)? {
            return Err(invalid());
        }
        Ok(())
    }
}

impl CaptureHeldAckDataV2 {
    /// Compares the full durable result against the complete ongoing source.
    ///
    /// # Errors
    /// Rejects another source/lifetime/attempt, physical owner, catalog or Host
    /// settlement. Authenticity and native completion remain with the real owner.
    pub fn verify_complete_hold_ongoing_v3(self, begin: CaptureHeldBeginDataV3,
        proof: CaptureHeldProofDataV2, terminal: CaptureHeldTerminalDataV2) -> Result<()> {
        terminal.verify_proof_ongoing_v3(begin, proof)?;
        self.verify_terminal(terminal)?;
        self.complete.ok_or_else(invalid)?.verify_original_ongoing_v2(
            &begin.source, begin.attempt, begin.durable_attempt_digest)?;
        self.verify_complete_coordinates_v3(proof, terminal)
    }
}
