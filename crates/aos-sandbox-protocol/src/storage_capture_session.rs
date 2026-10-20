//! Closed physical Capture branch on the existing held-output socket.
//!
//! These packets are comparison DATA. A proof is accepted only from the live
//! fixed Storage endpoint while its genuine resident worker, detached mount,
//! exclusive stream files and output writer remain held. Method60's durable
//! attempt response is a selector, never physical readiness.
//!
//! ```text
//! begin = AOSEOHS3 | v3:u16 | zero[2] | nonce[32] | ongoing-cutoff:u64
//!       | acquisition-cutoff:u64 | AOSSCG02[944] | attempt[16]
//!       | durable-attempt-digest[32] | nonce-readback-deadline:u64
//! proof = AOSEOHP2 | v2:u16 | zero[2] | begin-digest[32]
//!       | ExistingOutputResponseV1[236] | physical-row-digest[32]
//!       | dataset-binding[32] | catalog-generation:u64 | catalog-digest[32]
//!       | detached-mount-id:u64 | stdout(dev:u64,ino:u64)
//!       | stderr(dev:u64,ino:u64) | worker-request-digest[32]
//! terminal = AOSEOHT2 | v2:u16 | zero[2] | mode:u8 | zero[7]
//!          | nonce[32] | begin-digest[32] | proof-digest[32]
//!          | held-head:u64 | actual-Host-settlement-digest[32]
//! ack = AOSEOHA2 | v2:u16 | zero[2] | mode:u8 | zero[7] | nonce[32]
//!     | terminal-digest[32] | proof-digest[32] | held-head:u64
//!     | final-head:u64 | complete-physical-result-digest[32]
//!     | AOSCRS02[676] (all zero for Abort)
//! ```
//!
//! Begin intentionally carries no guessed journal head. Storage obtains the
//! actual current head while joining the exact resident attempt and retaining
//! its writer. Only a completed terminal ack commits both pipe EOFs, synced
//! readback, durable result and native posts; firstObserve is not that terminal.

pub mod ongoing;
pub mod stop_cleanup;
mod stop_cleanup_receipt;

use aos_sandbox_core::ObjectDigest;
use crate::storage_capture_result::{CaptureCompleteRecordDataV2,
    CAPTURE_COMPLETE_RECORD_BYTES_V2};
use sha2::{Digest as _, Sha256};
use crate::storage_capture_grant::{
    StorageCaptureGrantSourceV1, StorageCaptureAttemptStatusV1,
    ValidatedStorageCaptureAttemptV1,
};
use crate::storage_existing_output::{ExistingOutputResponseV1, RESPONSE_BYTES};

/// Exact physical Capture proof packet size.
pub const CAPTURE_PROOF_BYTES_V2: usize = 456;
/// Exact physical Capture terminal packet size.
pub const CAPTURE_TERMINAL_BYTES_V2: usize = 156;
/// Exact physical Capture acknowledgement size, including the whole result.
pub const CAPTURE_ACK_BYTES_V2: usize = 164 + CAPTURE_COMPLETE_RECORD_BYTES_V2;
/// Fixed negative-only Abort/Ack delivery budget after the positive cutoff.
///
/// This interval permits no pipe use, new spawn, Complete terminal or renewal.
/// The genuine resident owner must prepay its one terminal and owed Ack.
pub const CAPTURE_NEGATIVE_TERMINAL_NANOSECONDS_V2: u64 = 10_000_000_000;


const PROOF: &[u8; 8] = b"AOSEOHP2";
const TERMINAL: &[u8; 8] = b"AOSEOHT2";
const ACK: &[u8; 8] = b"AOSEOHA2";
const PROOF_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-held-proof.v2\0";
const TERMINAL_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-held-terminal.v2\0";

/// Rejects malformed, substituted or incomplete Capture session coordinates.
#[derive(Debug, thiserror::Error)]
pub enum CaptureSessionProtocolErrorV2 {
    /// A fixed field, version, reserved byte or complete binding differs.
    #[error("physical Capture session coordinates are invalid")]
    Binding,
    /// The single canonical signed-source DATA parser refused its bytes.
    #[error(transparent)]
    Source(#[from] crate::ProtocolValidationError),
    /// The single canonical output-row DATA parser refused its bytes.
    #[error(transparent)]
    Output(#[from] crate::storage_existing_output::ExistingOutputProtocolErrorV1),
    /// The sole canonical complete-result codec refused its bytes.
    #[error(transparent)]
    Complete(#[from] crate::storage_capture_result::CaptureCompleteRecordErrorV2),
}

type Result<T> = std::result::Result<T, CaptureSessionProtocolErrorV2>;

/// Fixes the native FIFO identity reported for one transferred write endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturePipeIdentityDataV2 {
    /// Native pipe filesystem device.
    pub device: u64,
    /// Native pipe inode.
    pub inode: u64,
}

/// Carries Storage's actual held physical preparation comparison coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureHeldProofDataV2 {
    /// Digest of the exact begin packet.
    pub begin_digest: [u8; 32],
    /// Same current protected output row and actual held journal head.
    pub row: ExistingOutputResponseV1,
    /// Exact durable physical binding row digest in that held writer.
    pub physical_row_digest: ObjectDigest,
    /// Verified dedicated dataset binding.
    pub dataset_binding: ObjectDigest,
    /// Current protected physical catalog generation.
    pub catalog_generation: u64,
    /// Current protected physical catalog head digest.
    pub catalog_digest: ObjectDigest,
    /// Actual unpublished detached mount identity held by the worker.
    pub mount_id: u64,
    /// Actual stdout FIFO identity; its only transferred right is write-only.
    pub stdout: CapturePipeIdentityDataV2,
    /// Actual stderr FIFO identity; its only transferred right is write-only.
    pub stderr: CapturePipeIdentityDataV2,
    /// Digest of the complete authenticated worker request for this preparation.
    pub worker_request_digest: ObjectDigest,
}

/// Distinguishes a completed physical terminal from a negative abort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureTerminalModeDataV2 {
    /// Requests completion after Guest exit; Storage still independently owes EOF.
    Complete,
    /// Abandons admission and requests actual worker cancellation.
    Abort,
}

impl CaptureTerminalModeDataV2 {
    const fn byte(self) -> u8 { match self { Self::Complete => 1, Self::Abort => 2 } }
    fn from_byte(byte: u8) -> Result<Self> {
        match byte { 1 => Ok(Self::Complete), 2 => Ok(Self::Abort), _ => Err(invalid()) }
    }
}

/// Binds the caller's terminal to the exact live physical hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureHeldTerminalDataV2 {
    /// Actual Host disposition of this Capture continuation.
    pub mode: CaptureTerminalModeDataV2,
    /// Original connection nonce.
    pub nonce: [u8; 32],
    /// Complete original begin digest.
    pub begin_digest: [u8; 32],
    /// Complete physical proof digest.
    pub proof_digest: [u8; 32],
    /// Storage's actual initial held output head.
    pub held_head: u64,
    /// Nonzero actual Host settlement for Complete, zero for Abort.
    pub settlement_digest: ObjectDigest,
}

/// Reports a completed result or negative abort on the same physical session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureHeldAckDataV2 {
    /// Accepted terminal mode; Abort does not assert EOF or physical completion.
    pub mode: CaptureTerminalModeDataV2,
    /// Original connection nonce.
    pub nonce: [u8; 32],
    /// Digest of the exact terminal packet.
    pub terminal_digest: [u8; 32],
    /// Digest of the exact physical proof packet.
    pub proof_digest: [u8; 32],
    /// Initial output head retained across this hold.
    pub held_head: u64,
    /// Actual final output head after the complete result, or held head on Abort.
    pub final_head: u64,
    /// Durable physical result digest only for Complete; zero for Abort.
    pub result_digest: ObjectDigest,
    /// Whole canonical durable result for Complete; absent for Abort.
    pub complete: Option<CaptureCompleteRecordDataV2>,
}

fn invalid() -> CaptureSessionProtocolErrorV2 { CaptureSessionProtocolErrorV2::Binding }

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes.get(offset..offset + N).ok_or_else(invalid)?
        .try_into().map_err(|_| invalid())
}

fn header<const N: usize>(magic: &[u8; 8]) -> [u8; N] {
    header_version_v3(magic, 2)
}

fn header_version_v3<const N: usize>(magic: &[u8; 8], version: u16) -> [u8; N] {
    let mut bytes = [0; N];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&version.to_be_bytes());
    bytes
}

fn require_header(bytes: &[u8], magic: &[u8; 8], length: usize) -> Result<()> {
    require_header_version_v3(bytes, magic, length, 2)
}

fn require_header_version_v3(bytes: &[u8], magic: &[u8; 8], length: usize, version: u16) -> Result<()> {
    if bytes.len() != length || bytes.get(..8) != Some(magic)
        || bytes.get(8..10) != Some(version.to_be_bytes().as_slice())
        || bytes.get(10..12) != Some([0, 0].as_slice())
    { return Err(invalid()); }
    Ok(())
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(domain).chain_update(bytes).finalize().into()
}

struct BeginFrameFieldsV3<'bytes> {
    nonce: [u8; 32], cutoff: u64, acquisition_cutoff: u64, nonce_deadline: u64,
    source: &'bytes [u8], attempt: [u8; 16], durable: ObjectDigest,
}

#[allow(clippy::too_many_arguments)]
fn encode_begin_frame_v3<const N: usize>(nonce: [u8; 32],
    cutoff: u64, acquisition_cutoff: u64, nonce_deadline: u64,
    source_cutoff: u64, source_acquisition_cutoff: u64, source: &[u8],
    attempt: [u8; 16], durable: ObjectDigest) -> Result<[u8; N]> {
    if N != ongoing::CAPTURE_BEGIN_BYTES_V3 || source.len() != crate::storage_capture_grant::STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2
        || nonce == [0; 32] || attempt == [0; 16] || durable.as_bytes() == &[0; 32]
        || cutoff == 0 || cutoff > source_cutoff || nonce_deadline == 0
        || acquisition_cutoff == 0 || acquisition_cutoff > source_acquisition_cutoff
        || nonce_deadline > cutoff || nonce_deadline > acquisition_cutoff
    { return Err(invalid()); }
    let mut bytes = header_version_v3::<N>(b"AOSEOHS3", 3);
    bytes[12..44].copy_from_slice(&nonce);
    bytes[44..52].copy_from_slice(&cutoff.to_be_bytes());
    bytes[52..60].copy_from_slice(&acquisition_cutoff.to_be_bytes());
    let source_end = 60 + crate::storage_capture_grant::STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2;
    bytes[60..source_end].copy_from_slice(source);
    bytes[source_end..source_end + 16].copy_from_slice(&attempt);
    bytes[source_end + 16..source_end + 48].copy_from_slice(durable.as_bytes());
    bytes[source_end + 48..source_end + 56].copy_from_slice(&nonce_deadline.to_be_bytes());
    Ok(bytes)
}

fn decode_begin_frame_v3(bytes: &[u8]) -> Result<BeginFrameFieldsV3<'_>> {
    require_header_version_v3(bytes, b"AOSEOHS3", ongoing::CAPTURE_BEGIN_BYTES_V3, 3)?;
    let source_end = 60 + crate::storage_capture_grant::STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2;
    let cutoff = u64::from_be_bytes(take(bytes, 44)?);
    Ok(BeginFrameFieldsV3 {
        nonce: take(bytes, 12)?, cutoff,
        acquisition_cutoff: u64::from_be_bytes(take(bytes, 52)?),
        nonce_deadline: u64::from_be_bytes(take(bytes, source_end + 48)?),
        source: &bytes[60..source_end], attempt: take(bytes, source_end)?,
        durable: ObjectDigest::from_bytes(take(bytes, source_end + 16)?),
    })
}

impl CaptureHeldProofDataV2 {
    fn verify_begin_coordinates_v3(self, begin_digest: [u8; 32], nonce: [u8; 32],
        source: &StorageCaptureGrantSourceV1) -> Result<()> {
        let (admitted, stdout, stderr) = source.output_limits();
        if self.begin_digest != begin_digest || self.row.nonce != nonce
            || self.row.request_digest != self.begin_digest
            || self.row.execution != *source.settlement().execution().as_bytes()
            || self.row.create != *source.settlement().create_operation().as_bytes()
            || self.row.assignment_digest != *source.assignment().digest().as_bytes()
            || self.row.claim_digest != *source.output_claim_digest().as_bytes()
            || self.row.record_digest != *source.output_record_digest().as_bytes()
            || self.row.admitted_bytes != admitted || self.row.maximum_stdout_bytes != stdout
            || self.row.maximum_stderr_bytes != stderr
        { return Err(invalid()); }
        self.encode()?;
        Ok(())
    }

    /// Encodes the complete physical hold DATA and exact two FIFO identities.
    ///
    /// # Errors
    /// Refuses sentinel physical coordinates, zero head or the same FIFO twice.
    pub fn encode(self) -> Result<[u8; CAPTURE_PROOF_BYTES_V2]> {
        if self.begin_digest == [0; 32] || self.row.journal_sequence == 0
            || self.physical_row_digest.as_bytes() == &[0; 32]
            || self.dataset_binding.as_bytes() == &[0; 32] || self.catalog_generation == 0
            || self.catalog_digest.as_bytes() == &[0; 32] || self.mount_id == 0
            || self.stdout.device == 0 || self.stdout.inode == 0
            || self.stderr.device == 0 || self.stderr.inode == 0 || self.stdout == self.stderr
            || self.worker_request_digest.as_bytes() == &[0; 32]
        { return Err(invalid()); }
        let mut bytes = header(PROOF);
        bytes[12..44].copy_from_slice(&self.begin_digest);
        bytes[44..44 + RESPONSE_BYTES].copy_from_slice(&self.row.encode()?);
        bytes[280..312].copy_from_slice(self.physical_row_digest.as_bytes());
        bytes[312..344].copy_from_slice(self.dataset_binding.as_bytes());
        bytes[344..352].copy_from_slice(&self.catalog_generation.to_be_bytes());
        bytes[352..384].copy_from_slice(self.catalog_digest.as_bytes());
        bytes[384..392].copy_from_slice(&self.mount_id.to_be_bytes());
        for (offset, value) in [(392, self.stdout.device), (400, self.stdout.inode),
            (408, self.stderr.device), (416, self.stderr.inode)]
        { bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes()); }
        bytes[424..456].copy_from_slice(self.worker_request_digest.as_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one physical proof while preserving its DATA-only nature.
    ///
    /// # Errors
    /// Refuses malformed row, length/header, physical identities or fixed fields.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require_header(bytes, PROOF, CAPTURE_PROOF_BYTES_V2)?;
        let value = Self {
            begin_digest: take(bytes, 12)?,
            row: ExistingOutputResponseV1::decode(&bytes[44..280])?,
            physical_row_digest: ObjectDigest::from_bytes(take(bytes, 280)?),
            dataset_binding: ObjectDigest::from_bytes(take(bytes, 312)?),
            catalog_generation: u64::from_be_bytes(take(bytes, 344)?),
            catalog_digest: ObjectDigest::from_bytes(take(bytes, 352)?),
            mount_id: u64::from_be_bytes(take(bytes, 384)?),
            stdout: CapturePipeIdentityDataV2 { device: u64::from_be_bytes(take(bytes, 392)?),
                inode: u64::from_be_bytes(take(bytes, 400)?) },
            stderr: CapturePipeIdentityDataV2 { device: u64::from_be_bytes(take(bytes, 408)?),
                inode: u64::from_be_bytes(take(bytes, 416)?) },
            worker_request_digest: ObjectDigest::from_bytes(take(bytes, 424)?),
        };
        value.encode()?;
        Ok(value)
    }

    /// Hashes every exact physical proof byte.
    ///
    /// # Errors
    /// Refuses malformed proof DATA.
    pub fn digest(self) -> Result<[u8; 32]> { Ok(digest(PROOF_DOMAIN, &self.encode()?)) }
}

impl CaptureHeldTerminalDataV2 {
    fn new_bound_v3(nonce: [u8; 32], begin_digest: [u8; 32], proof: CaptureHeldProofDataV2,
        mode: CaptureTerminalModeDataV2, settlement_digest: ObjectDigest) -> Result<Self> {
        let value = Self { mode, nonce, begin_digest,
            proof_digest: proof.digest()?, held_head: proof.row.journal_sequence, settlement_digest };
        value.encode()?;
        Ok(value)
    }

    /// Encodes a fixed, nonrenewing terminal.
    ///
    /// # Errors
    /// Refuses zero identities/head or a mode/digest mismatch.
    pub fn encode(self) -> Result<[u8; CAPTURE_TERMINAL_BYTES_V2]> {
        if self.nonce == [0; 32] || self.begin_digest == [0; 32] || self.proof_digest == [0; 32]
            || self.held_head == 0
            || (self.mode == CaptureTerminalModeDataV2::Complete) != (self.settlement_digest.as_bytes() != &[0; 32])
        { return Err(invalid()); }
        let mut bytes = header(TERMINAL);
        bytes[12] = self.mode.byte(); bytes[20..52].copy_from_slice(&self.nonce);
        bytes[52..84].copy_from_slice(&self.begin_digest);
        bytes[84..116].copy_from_slice(&self.proof_digest);
        bytes[116..124].copy_from_slice(&self.held_head.to_be_bytes());
        bytes[124..156].copy_from_slice(self.settlement_digest.as_bytes());
        Ok(bytes)
    }

    /// Decodes a canonical terminal without claiming EOF or worker completion.
    ///
    /// # Errors
    /// Refuses malformed fields/header or reserved bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require_header(bytes, TERMINAL, CAPTURE_TERMINAL_BYTES_V2)?;
        if bytes[13..20] != [0; 7] { return Err(invalid()); }
        let value = Self { mode: CaptureTerminalModeDataV2::from_byte(bytes[12])?, nonce: take(bytes, 20)?,
            begin_digest: take(bytes, 52)?, proof_digest: take(bytes, 84)?,
            held_head: u64::from_be_bytes(take(bytes, 116)?),
            settlement_digest: ObjectDigest::from_bytes(take(bytes, 124)?), };
        value.encode()?; Ok(value)
    }

    /// Hashes every exact terminal byte.
    ///
    /// # Errors
    /// Refuses malformed terminal DATA.
    pub fn digest(self) -> Result<[u8; 32]> { Ok(digest(TERMINAL_DOMAIN, &self.encode()?)) }
}

impl CaptureHeldAckDataV2 {
    /// Encodes an exact completed result or explicit negative abort.
    ///
    /// # Errors
    /// Complete requires an advanced durable head and nonzero result; Abort
    /// requires the unchanged held head and no success-shaped result digest.
    pub fn encode(self) -> Result<[u8; CAPTURE_ACK_BYTES_V2]> {
        if self.nonce == [0; 32] || self.terminal_digest == [0; 32] || self.proof_digest == [0; 32]
            || self.held_head == 0
            || match self.mode {
                CaptureTerminalModeDataV2::Complete => self.final_head <= self.held_head
                    || self.complete.is_none()
                    || self.result_digest != self.complete.ok_or_else(invalid)?.digest()?,
                CaptureTerminalModeDataV2::Abort => self.final_head != self.held_head
                    || self.result_digest.as_bytes() != &[0; 32] || self.complete.is_some(),
            }
        { return Err(invalid()); }
        let mut bytes = header(ACK);
        bytes[12] = self.mode.byte(); bytes[20..52].copy_from_slice(&self.nonce);
        bytes[52..84].copy_from_slice(&self.terminal_digest);
        bytes[84..116].copy_from_slice(&self.proof_digest);
        bytes[116..124].copy_from_slice(&self.held_head.to_be_bytes());
        bytes[124..132].copy_from_slice(&self.final_head.to_be_bytes());
        bytes[132..164].copy_from_slice(self.result_digest.as_bytes());
        if let Some(complete) = self.complete {
            bytes[164..].copy_from_slice(&complete.encode()?);
        }
        Ok(bytes)
    }

    /// Decodes one canonical terminal acknowledgement.
    ///
    /// # Errors
    /// Refuses malformed header, reserved bytes or terminal/result coordinates.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require_header(bytes, ACK, CAPTURE_ACK_BYTES_V2)?;
        if bytes[13..20] != [0; 7] { return Err(invalid()); }
        let value = Self { mode: CaptureTerminalModeDataV2::from_byte(bytes[12])?, nonce: take(bytes, 20)?,
            terminal_digest: take(bytes, 52)?, proof_digest: take(bytes, 84)?,
            held_head: u64::from_be_bytes(take(bytes, 116)?), final_head: u64::from_be_bytes(take(bytes, 124)?),
            result_digest: ObjectDigest::from_bytes(take(bytes, 132)?),
            complete: match CaptureTerminalModeDataV2::from_byte(bytes[12])? {
                CaptureTerminalModeDataV2::Complete => Some(CaptureCompleteRecordDataV2::decode(&bytes[164..])?),
                CaptureTerminalModeDataV2::Abort => {
                    if bytes[164..].iter().any(|byte| *byte != 0) { return Err(invalid()); }
                    None
                }
            },
        };
        value.encode()?; Ok(value)
    }

    fn verify_complete_coordinates_v3(self, proof: CaptureHeldProofDataV2,
        terminal: CaptureHeldTerminalDataV2) -> Result<()> {
        let complete = self.complete.ok_or_else(invalid)?;
        if self.mode != CaptureTerminalModeDataV2::Complete
            || complete.physical_row_digest != proof.physical_row_digest
            || complete.dataset_binding != proof.dataset_binding
            || complete.mount_id != proof.mount_id
            || complete.worker_request_digest != proof.worker_request_digest
            || complete.catalog_generation < proof.catalog_generation
            || complete.catalog_generation == proof.catalog_generation
                && complete.catalog_digest != proof.catalog_digest
            || complete.host_settlement_digest != terminal.settlement_digest
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares the exact terminal and physical hold without adding authority.
    ///
    /// # Errors
    /// Refuses a foreign mode, nonce, terminal/proof digest or original held head.
    pub fn verify_terminal(self, terminal: CaptureHeldTerminalDataV2) -> Result<()> {
        self.encode()?;
        if self.mode != terminal.mode || self.nonce != terminal.nonce
            || self.terminal_digest != terminal.digest()? || self.proof_digest != terminal.proof_digest
            || self.held_head != terminal.held_head
        { return Err(invalid()); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_ack_requires_the_whole_record_and_abort_cannot_hide_one() {
        let complete = crate::storage_capture_result::tests::complete();
        let ack = CaptureHeldAckDataV2 {
            mode: CaptureTerminalModeDataV2::Complete,
            nonce: [1; 32], terminal_digest: [2; 32], proof_digest: [3; 32],
            held_head: 4, final_head: 8, result_digest: complete.digest().unwrap(),
            complete: Some(complete),
        };
        let encoded = ack.encode().unwrap();
        assert_eq!(encoded.len(), 840);
        assert_eq!(CaptureHeldAckDataV2::decode(&encoded).unwrap(), ack);
        let mut missing = ack;
        missing.complete = None;
        assert!(missing.encode().is_err());
        let mut abort = ack;
        abort.mode = CaptureTerminalModeDataV2::Abort;
        abort.final_head = abort.held_head;
        abort.result_digest = ObjectDigest::from_bytes([0; 32]);
        assert!(abort.encode().is_err());
        abort.complete = None;
        let mut encoded = abort.encode().unwrap();
        assert_eq!(CaptureHeldAckDataV2::decode(&encoded).unwrap(), abort);
        encoded[164..].copy_from_slice(&complete.encode().unwrap());
        assert!(CaptureHeldAckDataV2::decode(&encoded).is_err());
    }
}
