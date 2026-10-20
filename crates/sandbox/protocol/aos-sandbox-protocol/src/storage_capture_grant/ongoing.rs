//! Binds short Capture acquisition to a separately admitted execution lifetime.
//!
//! This version preserves the complete embedded acquisition fragment and its short
//! request cutoff. The signed wrapper additionally commits the actual canonical
//! specification and immutable original assignment/lease clock provenance.
//! Neither decoding nor matching these DATA starts a worker or renews a bound.
//!
//! ```text
//! AOSSCG02 | acquisition-source-AOSSCG01[512] | execution-lifetime-AOSCLF02[424]
//! ```

use super::*;
use crate::storage_capture_lifetime::{
    StorageCaptureExecutionLifetimeDataV2, STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2,
};

/// Exact complete source width, including its distinct lifetime provenance.
pub const STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2: usize =
    8 + STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1 + STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2;
const MAGIC: &[u8; 8] = b"AOSSCG02";
const DOMAIN: &[u8] = b"aos.sandbox.storage.capture-grant-source.v2\0";
const ARGUMENT_DOMAIN_V2: &[u8] = b"aos.sandbox.storage.capture-grant-argument.v2\0";

/// Contains complete acquisition and ongoing-lifetime comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCaptureGrantSourceV2 {
    bytes: [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2],
    original: StorageCaptureGrantSourceV1,
    lifetime: StorageCaptureExecutionLifetimeDataV2,
}

impl StorageCaptureGrantSourceV2 {
    /// Forms a fresh acquisition over exact historical46 records and full lifetime.
    ///
    /// # Errors
    /// Rejects a foreign first candidate/records/request, expired candidate
    /// bound or a substituted immutable execution-lifetime association.
    pub fn from_candidate_data_v2(
        query: &crate::storage_capture_candidate::StorageCaptureCandidateQueryV1,
        candidate: &crate::storage_capture_candidate::ValidatedStorageCaptureCandidateV1,
        original: &crate::storage_output_reserve::StorageOutputReserveRecordsV1,
        request_id: [u8; 16], acquisition_deadline_boottime_nanoseconds: u64,
        lifetime: StorageCaptureExecutionLifetimeDataV2,
    ) -> Result<Self, ProtocolValidationError> {
        let acquisition = StorageCaptureGrantSourceV1::from_candidate_data_v2(
            query, candidate, original, request_id, acquisition_deadline_boottime_nanoseconds)?;
        Self::from_original_data_v2(acquisition, lifetime)
    }

    /// Joins the existing acquisition source to the exact independently derived lifetime.
    ///
    /// # Errors
    /// Rejects foreign execution/Create/assignment/boot, invalid chronology or
    /// exhausted first acquisition. Authority remains with actual native owners.
    pub(crate) fn from_original_data_v2(original: StorageCaptureGrantSourceV1,
        lifetime: StorageCaptureExecutionLifetimeDataV2) -> Result<Self, ProtocolValidationError>
    {
        let mut bytes = [0; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..520].copy_from_slice(original.canonical_bytes());
        bytes[520..].copy_from_slice(lifetime.canonical_bytes_v2());
        Self::from_canonical_bytes_v2(&bytes)
    }

    /// Decodes complete versioned DATA using the sole existing source/lifetime codecs.
    ///
    /// # Errors
    /// Rejects malformed framing or a changed execution/Create/assignment/boot.
    /// A fresh Query may read expired historical DATA; native admission remains
    /// responsible for checking both acquisition and ongoing bounds before work.
    pub fn from_canonical_bytes_v2(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        let bytes: [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2] = bytes.try_into()
            .map_err(|_| invalid("ongoing Capture source width"))?;
        if &bytes[..8] != MAGIC { return Err(invalid("ongoing Capture source version")); }
        let original = StorageCaptureGrantSourceV1::from_canonical_bytes(&bytes[8..520])?;
        let lifetime = StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&bytes[520..])?;
        let before = lifetime.first_pre_spawn_clock_v2();
        if lifetime.execution_v2() != original.settlement().execution()
            || lifetime.original_create_operation_v2() != original.settlement().create_operation()
            || lifetime.assignment_v2() != original.assignment()
            || before.host_boot_id() != original.host_boot_id()
            || lifetime.original_target_clock_v2().host_boot_id() != original.host_boot_id()
            || before.boottime_nanoseconds() >= original.original_deadline_boottime_nanoseconds()
        { return Err(invalid("ongoing Capture source association")); }
        Ok(Self { bytes, original, lifetime })
    }

    /// Borrows the original short acquisition source without an ongoing permit.
    #[must_use]
    pub const fn original_source_v1(&self) -> &StorageCaptureGrantSourceV1 { &self.original }

    /// Borrows exact immutable ongoing-lifetime provenance DATA.
    #[must_use]
    pub const fn lifetime_v2(&self) -> &StorageCaptureExecutionLifetimeDataV2 { &self.lifetime }

    /// Borrows all bytes committed by the version-two signed grant.
    #[must_use]
    pub const fn canonical_bytes_v2(&self) -> &[u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2] { &self.bytes }

    /// Returns a commitment to both the acquisition and complete ongoing lifetime.
    #[must_use]
    pub fn source_digest_v2(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::new().chain_update(DOMAIN).chain_update(self.bytes).finalize().into())
    }

    /// Returns the immutable explicit execution bound, never a fresh request window.
    #[must_use]
    pub fn effective_execution_deadline_v2(&self) -> u64 {
        self.lifetime.deadline_boottime_nanoseconds_v2()
    }

    /// Returns response comparison coordinates with the versioned ongoing bound.
    #[must_use]
    pub fn locator_v2(&self) -> StorageCaptureAttemptLocatorV1 {
        StorageCaptureAttemptLocatorV1 {
            execution: self.original.settlement().execution(),
            create_operation: self.original.settlement().create_operation(),
            original_reserve_request_id: self.original.original_reserve_request_id(),
            source_digest: self.source_digest_v2(),
            output_record_digest: self.original.output_record_digest(),
            original_deadline_boottime_nanoseconds: self.effective_execution_deadline_v2(),
        }
    }

    /// Builds the whole-source, method-separated signed argument commitment.
    ///
    /// # Errors
    /// Rejects absent/reused request IDs under the existing exact acquisition law.
    pub fn argument_commitment_v2(&self, method: StorageCaptureGrantMethodV1,
        request_id: [u8; 16]) -> Result<BrokerArgumentCommitment, ProtocolValidationError>
    {
        capture_argument_commitment_data_v2(method, request_id,
            self.original.original_reserve_request_id(), ARGUMENT_DOMAIN_V2, &self.bytes)
    }

    /// Builds signed semantics for this exact versioned source and request.
    ///
    /// # Errors
    /// Rejects absent/reused request IDs or an invalid canonical grant.
    pub fn broker_grant_v2(&self, method: StorageCaptureGrantMethodV1,
        request_id: [u8; 16]) -> Result<BrokerGrant, ProtocolValidationError>
    {
        BrokerGrant::new(method.broker_verb(), BrokerGrantTarget::Assignment,
            self.argument_commitment_v2(method, request_id)?, MAXIMUM_REQUEST_BODY_BYTES as u32, 0)
            .map_err(|_| invalid("ongoing Capture grant"))
    }
}
