//! Canonical complete physical Capture result DATA.
//!
//! A record contains both exact stream descriptors and the original signed
//! source, durable attempt, native worker, physical binding and final catalog
//! coordinates. Its checksum is not a MAC, native provenance or a completion
//! permit. Only Storage's private same-worker commit/readback path can adopt it.
//! Historical pre-writer AOSPOV01 observations retain their separate grammar.
//!
//! ```text
//! AOSCRS02 | version:u16be=2 | zero[2] | source/attempt/physical coordinates
//!         | stdout(max:u64be,bytes:u64be,truncated:u8,zero[7],SHA256[32])
//!         | stderr(max:u64be,bytes:u64be,truncated:u8,zero[7],SHA256[32])
//!         | stdout-EOF:u8=1 | stderr-EOF:u8=1 | synced-readback:u8=1
//!         | zero[5] | domain-separated-record-digest[32]
//! ```

use aos_sandbox_model::{CapturedStreamV1, ExecutionCapturedOutputV1,
    ExecutionCapturedStreamKindV1, MediaType, ObjectDescriptor, ObjectDigest,
    PortableMediaType, ResourceDimension, ResourceVector};
use sha2::{Digest as _, Sha256};
use crate::storage_capture_grant::{StorageCaptureGrantSourceV1,
    StorageCaptureAttemptStatusV1, ValidatedStorageCaptureAttemptV1};

/// Exact canonical complete-result width, including its checksum.
pub const CAPTURE_COMPLETE_RECORD_BYTES_V2: usize = 676;

const MAGIC: &[u8; 8] = b"AOSCRS02";
const DOMAIN: &[u8] = b"aos.sandbox.storage.capture-complete-record.v2\0";

/// Rejects a malformed or substituted complete-result DATA record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("complete physical Capture result coordinates are invalid")]
pub struct CaptureCompleteRecordErrorV2;

type Result<T> = std::result::Result<T, CaptureCompleteRecordErrorV2>;

/// Contains one final independently synced and read-back stream prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureCompleteStreamDataV2 {
    /// Original admitted per-stream ceiling.
    pub maximum_bytes: u64,
    /// Exact stored prefix length.
    pub captured_bytes: u64,
    /// Whether bytes beyond the ceiling were discarded.
    pub truncated: bool,
    /// SHA-256 of the exact stored prefix, including the empty stream.
    pub content_digest: ObjectDigest,
}

impl CaptureCompleteStreamDataV2 {
    fn require_valid(self) -> Result<()> {
        if self.captured_bytes > self.maximum_bytes
            || self.truncated && self.captured_bytes != self.maximum_bytes
            || self.content_digest.as_bytes() == &[0; 32]
            || self.captured_bytes == 0
                && self.content_digest.as_bytes() != Sha256::digest([]).as_slice()
        {
            return Err(CaptureCompleteRecordErrorV2);
        }
        Ok(())
    }

    fn captured_stream(self, stream: ExecutionCapturedStreamKindV1) -> Result<CapturedStreamV1> {
        self.require_valid()?;
        let media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| CaptureCompleteRecordErrorV2)?;
        CapturedStreamV1::new(stream,
            ObjectDescriptor::new(media, self.content_digest, self.captured_bytes),
            self.captured_bytes, self.truncated).map_err(|_| CaptureCompleteRecordErrorV2)
    }
}

/// Fixes complete stream and native coordinates without conferring authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureCompleteRecordDataV2 {
    /// Complete Controller-signed source commitment.
    pub source_digest: ObjectDigest,
    /// Original protected physical attempt identity.
    pub attempt: [u8; 16],
    /// Exact committed physical attempt record digest.
    pub durable_attempt_digest: ObjectDigest,
    /// Execution whose two streams completed.
    pub execution: [u8; 16],
    /// Original accepted CreateExecution operation.
    pub create_operation: [u8; 16],
    /// Authenticated logical output record digest.
    pub output_record_digest: ObjectDigest,
    /// Original Host output claim digest.
    pub claim_digest: ObjectDigest,
    /// Exact canonical assignment commitment.
    pub assignment_digest: ObjectDigest,
    /// Verified dedicated dataset binding.
    pub dataset_binding: ObjectDigest,
    /// Actual detached capture mount identity.
    pub mount_id: u64,
    /// Fresh final protected catalog generation.
    pub catalog_generation: u64,
    /// Fresh final protected catalog head digest.
    pub catalog_digest: ObjectDigest,
    /// Exact durable physical dataset binding row.
    pub physical_row_digest: ObjectDigest,
    /// Actual initial ZFS observation commitment.
    pub before_observation_digest: ObjectDigest,
    /// Actual mounted ZFS observation commitment.
    pub mounted_observation_digest: ObjectDigest,
    /// Actual post-write ZFS observation commitment.
    pub after_observation_digest: ObjectDigest,
    /// Complete authenticated worker request commitment.
    pub worker_request_digest: ObjectDigest,
    /// Existing native detached writer result commitment.
    pub worker_result_digest: ObjectDigest,
    /// Actual terminal Host settlement commitment.
    pub host_settlement_digest: ObjectDigest,
    /// Actual stdout readback, with its original limit.
    pub stdout: CaptureCompleteStreamDataV2,
    /// Actual stderr readback, with its original limit.
    pub stderr: CaptureCompleteStreamDataV2,
}

impl CaptureCompleteRecordDataV2 {
    /// Compares a complete result to the entire explicitly versioned source.
    ///
    /// # Errors
    /// Rejects a changed source/lifetime commitment, attempt, output or limits.
    /// The comparison alone cannot authenticate native completion.
    pub fn verify_original_ongoing_v2(self,
        source: &crate::storage_capture_grant::StorageCaptureGrantSourceV2,
        attempt: [u8; 16], durable_attempt_digest: ObjectDigest) -> Result<()>
    {
        self.verify_original_fields_v2(source.original_source_v1(), source.source_digest_v2(),
            attempt, durable_attempt_digest)
    }

    /// Checks versioned response coordinates and the full ongoing source.
    ///
    /// # Errors
    /// Rejects another locator, absent effect fence or any full-record mismatch.
    pub fn verify_source_ongoing_v2(self,
        source: &crate::storage_capture_grant::StorageCaptureGrantSourceV2,
        attempt: ValidatedStorageCaptureAttemptV1) -> Result<()>
    {
        if attempt.status() != StorageCaptureAttemptStatusV1::EffectPossible
            || attempt.locator() != source.locator_v2()
        { return Err(CaptureCompleteRecordErrorV2); }
        self.verify_original_ongoing_v2(source,
            attempt.attempt().ok_or(CaptureCompleteRecordErrorV2)?,
            attempt.durable_attempt_digest().ok_or(CaptureCompleteRecordErrorV2)?)
    }

    fn verify_original_fields_v2(self, source: &StorageCaptureGrantSourceV1,
        source_digest: ObjectDigest, attempt: [u8; 16], durable_attempt_digest: ObjectDigest)
        -> Result<()>
    {
        self.require_valid()?;
        let (_, stdout, stderr) = source.output_limits();
        if attempt != self.attempt || durable_attempt_digest != self.durable_attempt_digest
            || self.source_digest != source_digest
            || self.execution != *source.settlement().execution().as_bytes()
            || self.create_operation != *source.settlement().create_operation().as_bytes()
            || self.output_record_digest != source.output_record_digest()
            || self.claim_digest != source.output_claim_digest()
            || self.assignment_digest != source.assignment().digest()
            || self.stdout.maximum_bytes != stdout || self.stderr.maximum_bytes != stderr
        {
            return Err(CaptureCompleteRecordErrorV2);
        }
        Ok(())
    }

    fn require_valid(self) -> Result<()> {
        self.stdout.require_valid()?;
        self.stderr.require_valid()?;
        if self.attempt == [0; 16] || self.execution == [0; 16]
            || self.create_operation == [0; 16] || self.mount_id == 0
            || self.catalog_generation == 0
            || self.stdout.maximum_bytes.checked_add(self.stderr.maximum_bytes).is_none()
            || self.source_digest.as_bytes() == &[0; 32]
            || self.durable_attempt_digest.as_bytes() == &[0; 32]
            || self.output_record_digest.as_bytes() == &[0; 32]
            || self.claim_digest.as_bytes() == &[0; 32]
            || self.assignment_digest.as_bytes() == &[0; 32]
            || self.dataset_binding.as_bytes() == &[0; 32]
            || self.catalog_digest.as_bytes() == &[0; 32]
            || self.physical_row_digest.as_bytes() == &[0; 32]
            || self.before_observation_digest.as_bytes() == &[0; 32]
            || self.mounted_observation_digest.as_bytes() == &[0; 32]
            || self.after_observation_digest.as_bytes() == &[0; 32]
            || self.worker_request_digest.as_bytes() == &[0; 32]
            || self.worker_result_digest.as_bytes() == &[0; 32]
            || self.host_settlement_digest.as_bytes() == &[0; 32]
        {
            return Err(CaptureCompleteRecordErrorV2);
        }
        Ok(())
    }

    /// Encodes every complete coordinate and both final stream prefixes.
    ///
    /// # Errors
    /// Rejects sentinel identities, impossible truncation/lengths, invalid empty
    /// content digests or overflowing aggregate limits.
    pub fn encode(self) -> Result<[u8; CAPTURE_COMPLETE_RECORD_BYTES_V2]> {
        self.require_valid()?;
        let mut bytes = [0; CAPTURE_COMPLETE_RECORD_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes[12..44].copy_from_slice(self.source_digest.as_bytes());
        bytes[44..60].copy_from_slice(&self.attempt);
        bytes[60..92].copy_from_slice(self.durable_attempt_digest.as_bytes());
        bytes[92..108].copy_from_slice(&self.execution);
        bytes[108..124].copy_from_slice(&self.create_operation);
        bytes[124..156].copy_from_slice(self.output_record_digest.as_bytes());
        bytes[156..188].copy_from_slice(self.claim_digest.as_bytes());
        bytes[188..220].copy_from_slice(self.assignment_digest.as_bytes());
        bytes[220..252].copy_from_slice(self.dataset_binding.as_bytes());
        bytes[252..260].copy_from_slice(&self.mount_id.to_be_bytes());
        bytes[260..268].copy_from_slice(&self.catalog_generation.to_be_bytes());
        bytes[268..300].copy_from_slice(self.catalog_digest.as_bytes());
        bytes[300..332].copy_from_slice(self.physical_row_digest.as_bytes());
        bytes[332..364].copy_from_slice(self.before_observation_digest.as_bytes());
        bytes[364..396].copy_from_slice(self.mounted_observation_digest.as_bytes());
        bytes[396..428].copy_from_slice(self.after_observation_digest.as_bytes());
        bytes[428..460].copy_from_slice(self.worker_request_digest.as_bytes());
        bytes[460..492].copy_from_slice(self.worker_result_digest.as_bytes());
        bytes[492..524].copy_from_slice(self.host_settlement_digest.as_bytes());
        bytes[524..532].copy_from_slice(&self.stdout.maximum_bytes.to_be_bytes());
        bytes[532..540].copy_from_slice(&self.stdout.captured_bytes.to_be_bytes());
        bytes[540] = u8::from(self.stdout.truncated);
        bytes[548..580].copy_from_slice(self.stdout.content_digest.as_bytes());
        bytes[580..588].copy_from_slice(&self.stderr.maximum_bytes.to_be_bytes());
        bytes[588..596].copy_from_slice(&self.stderr.captured_bytes.to_be_bytes());
        bytes[596] = u8::from(self.stderr.truncated);
        bytes[604..636].copy_from_slice(self.stderr.content_digest.as_bytes());
        bytes[636..639].copy_from_slice(&[1, 1, 1]);
        let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..644]).finalize();
        bytes[644..].copy_from_slice(&digest);
        Ok(bytes)
    }

    /// Decodes an exact complete record using the same validation as encoding.
    ///
    /// # Errors
    /// Rejects an unknown version, trailing/short bytes, nonzero reserved data,
    /// false EOF/sync flags, invalid stream limits or a checksum mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CAPTURE_COMPLETE_RECORD_BYTES_V2 || bytes.get(..8) != Some(MAGIC)
            || bytes.get(8..12) != Some([0, 2, 0, 0].as_slice())
            || bytes.get(636..644) != Some([1, 1, 1, 0, 0, 0, 0, 0].as_slice())
            || bytes[541..548] != [0; 7] || bytes[540] > 1
            || bytes[597..604] != [0; 7] || bytes[596] > 1
        {
            return Err(CaptureCompleteRecordErrorV2);
        }
        let checksum = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..644]).finalize();
        if bytes[644..] != checksum[..] { return Err(CaptureCompleteRecordErrorV2); }
        let value = Self {
            source_digest: ObjectDigest::from_bytes(take(bytes, 12)?),
            attempt: take(bytes, 44)?,
            durable_attempt_digest: ObjectDigest::from_bytes(take(bytes, 60)?),
            execution: take(bytes, 92)?,
            create_operation: take(bytes, 108)?,
            output_record_digest: ObjectDigest::from_bytes(take(bytes, 124)?),
            claim_digest: ObjectDigest::from_bytes(take(bytes, 156)?),
            assignment_digest: ObjectDigest::from_bytes(take(bytes, 188)?),
            dataset_binding: ObjectDigest::from_bytes(take(bytes, 220)?),
            mount_id: u64::from_be_bytes(take(bytes, 252)?),
            catalog_generation: u64::from_be_bytes(take(bytes, 260)?),
            catalog_digest: ObjectDigest::from_bytes(take(bytes, 268)?),
            physical_row_digest: ObjectDigest::from_bytes(take(bytes, 300)?),
            before_observation_digest: ObjectDigest::from_bytes(take(bytes, 332)?),
            mounted_observation_digest: ObjectDigest::from_bytes(take(bytes, 364)?),
            after_observation_digest: ObjectDigest::from_bytes(take(bytes, 396)?),
            worker_request_digest: ObjectDigest::from_bytes(take(bytes, 428)?),
            worker_result_digest: ObjectDigest::from_bytes(take(bytes, 460)?),
            host_settlement_digest: ObjectDigest::from_bytes(take(bytes, 492)?),
            stdout: CaptureCompleteStreamDataV2 {
                maximum_bytes: u64::from_be_bytes(take(bytes, 524)?),
                captured_bytes: u64::from_be_bytes(take(bytes, 532)?),
                truncated: bytes[540] == 1,
                content_digest: ObjectDigest::from_bytes(take(bytes, 548)?),
            },
            stderr: CaptureCompleteStreamDataV2 {
                maximum_bytes: u64::from_be_bytes(take(bytes, 580)?),
                captured_bytes: u64::from_be_bytes(take(bytes, 588)?),
                truncated: bytes[596] == 1,
                content_digest: ObjectDigest::from_bytes(take(bytes, 604)?),
            },
        };
        value.require_valid()?;
        Ok(value)
    }

    /// Returns the commitment to the entire canonical complete record.
    ///
    /// # Errors
    /// Rejects the same invalid fields as the canonical encoder.
    pub fn digest(self) -> Result<ObjectDigest> {
        let bytes = self.encode()?;
        let checksum = take(&bytes, CAPTURE_COMPLETE_RECORD_BYTES_V2 - 32)?;
        Ok(ObjectDigest::from_bytes(checksum))
    }

    /// Constructs the existing portable final output model from both descriptors.
    ///
    /// # Errors
    /// Rejects invalid complete DATA or an invalid Core content descriptor.
    pub fn captured_output(self) -> Result<ExecutionCapturedOutputV1> {
        self.require_valid()?;
        Ok(ExecutionCapturedOutputV1::Complete { streams: [
            self.stdout.captured_stream(ExecutionCapturedStreamKindV1::Stdout)?,
            self.stderr.captured_stream(ExecutionCapturedStreamKindV1::Stderr)?,
        ] })
    }

    /// Bounds canonical bytes, compiled result carriers and portable descriptors.
    ///
    /// This passive geometry grants no funds, native provenance or owner. It
    /// includes actual Core media-type backing and no namespace metadata fee.
    #[must_use]
    pub fn receiving_demand_v2() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(CAPTURE_COMPLETE_RECORD_BYTES_V2.checked_mul(3)?)?
            .checked_add(std::mem::size_of::<ExecutionCapturedOutputV1>().checked_mul(2)?)?
            .checked_add(PortableMediaType::Content.as_str().len().checked_mul(4)?)?;
        Some(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes,
            u64::try_from(bytes).ok()?))
    }
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(CaptureCompleteRecordErrorV2)?;
    bytes.get(offset..end).ok_or(CaptureCompleteRecordErrorV2)?
        .try_into().map_err(|_| CaptureCompleteRecordErrorV2)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn complete() -> CaptureCompleteRecordDataV2 {
        let digest = ObjectDigest::from_bytes([7; 32]);
        CaptureCompleteRecordDataV2 {
            source_digest: digest, attempt: [1; 16], durable_attempt_digest: digest,
            execution: [2; 16], create_operation: [3; 16], output_record_digest: digest,
            claim_digest: digest, assignment_digest: digest, dataset_binding: digest,
            mount_id: 4, catalog_generation: 5, catalog_digest: digest,
            physical_row_digest: digest, before_observation_digest: digest,
            mounted_observation_digest: digest, after_observation_digest: digest,
            worker_request_digest: digest, worker_result_digest: digest,
            host_settlement_digest: digest,
            stdout: CaptureCompleteStreamDataV2 { maximum_bytes: 4, captured_bytes: 4,
                truncated: true, content_digest: ObjectDigest::from_bytes(Sha256::digest(b"abcd").into()) },
            stderr: CaptureCompleteStreamDataV2 { maximum_bytes: 0, captured_bytes: 0,
                truncated: false, content_digest: ObjectDigest::from_bytes(Sha256::digest([]).into()) },
        }
    }

    #[test]
    fn whole_result_preserves_empty_and_truncated_stream_descriptors() {
        let original = complete();
        let encoded = original.encode().unwrap();
        assert_eq!(encoded.len(), CAPTURE_COMPLETE_RECORD_BYTES_V2);
        assert_eq!(CaptureCompleteRecordDataV2::decode(&encoded).unwrap(), original);
        let output = original.captured_output().unwrap();
        assert_eq!(output.streams()[0].captured_bytes(), 4);
        assert!(output.streams()[0].truncated());
        assert_eq!(output.streams()[1].descriptor().encoded_size(), 0);
        assert_eq!(original.digest().unwrap().as_bytes(), &encoded[644..]);
    }

    #[test]
    fn valid_checksum_cannot_hide_missing_eof_or_impossible_truncation() {
        let original = complete();
        for (offset, byte) in [(636, 0), (637, 0), (638, 0), (639, 1), (541, 1), (596, 2)] {
            let mut encoded = original.encode().unwrap();
            encoded[offset] = byte;
            let digest = Sha256::new().chain_update(DOMAIN).chain_update(&encoded[..644]).finalize();
            encoded[644..].copy_from_slice(&digest);
            assert!(CaptureCompleteRecordDataV2::decode(&encoded).is_err());
        }
        let mut invalid = original;
        invalid.stdout.captured_bytes = 3;
        assert!(invalid.encode().is_err());
        invalid = original;
        invalid.stderr.content_digest = ObjectDigest::from_bytes([8; 32]);
        assert!(invalid.encode().is_err());
        assert!(CaptureCompleteRecordDataV2::decode(&original.encode().unwrap()[..675]).is_err());
    }
}
