//! Immutable original accepted Start coordinates, never resumed authorization.
//!
//! ```text
//! clock-provenance[16] | boot[16] | wall:i64le | BOOTTIME:u64le |
//! original-TLS-cutoff:u64le | capability-expiry:i64le | policy-expiry:i64le |
//! signed-operation-timeout-nanoseconds:u64le
//! ```
//!
//! Every coordinate is historical DATA. Native consumers must rejoin the actual
//! accepted operation, same Controller and boot before using its shrinking limit.

use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use crate::domain_ledger::public_operation::PublicOperationDataError;

/// Bounds the complete immutable Start admission tail.
pub const ACCEPTED_START_ORIGIN_BYTES: usize = 80;

/// Holds original protected-clock and signed-request bounds for accepted Start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedStartOriginDataV1 {
    clock: RawPairedClockSample,
    peer_cutoff: u64,
    capability_expires: i64,
    policy_expires: i64,
    timeout_ns: u64,
}

impl AcceptedStartOriginDataV1 {
    /// Validates historical coordinate structure without authenticating an owner.
    ///
    /// # Errors
    /// Rejects exhausted or overflowing original bounds and unsupported timeouts.
    pub fn from_data_v1(clock: RawPairedClockSample, peer_cutoff: u64,
        capability_expires: i64, policy_expires: i64, timeout_ns: u64,
    ) -> Result<Self, PublicOperationDataError> {
        let value = Self { clock, peer_cutoff, capability_expires, policy_expires, timeout_ns };
        if clock.boottime_nanoseconds() >= peer_cutoff
            || capability_expires <= clock.wall_seconds()
            || policy_expires <= clock.wall_seconds()
            || !(1..=crate::public_api::limits::MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout_ns)
            || value.signed_timeout_wall_expiry_v1().is_none()
            || clock.boottime_nanoseconds().checked_add(timeout_ns).is_none()
        {
            return Err(PublicOperationDataError::CorruptLedger("invalid accepted Start origin"));
        }
        Ok(value)
    }

    /// Returns the actual historical paid authorization sample as inert DATA.
    pub const fn accepted_clock_v1(self) -> RawPairedClockSample { self.clock }

    /// Returns the original authenticated TLS channel's unchanged cutoff.
    pub const fn original_peer_cutoff_v1(self) -> u64 { self.peer_cutoff }

    /// Returns the signed timeout retained from the original canonical request.
    pub const fn signed_timeout_nanoseconds_v1(self) -> u64 { self.timeout_ns }

    /// Returns the conservative absolute wall expiry of the signed timeout.
    ///
    /// Fractional timeout seconds are discarded, so omitted wall-clock precision
    /// can shorten the limit but can never renew it on a later native turn.
    pub fn signed_timeout_wall_expiry_v1(self) -> Option<i64> {
        self.clock.wall_seconds().checked_add(i64::try_from(self.timeout_ns / 1_000_000_000).ok()?)
    }

    /// Returns the immutable authority ceiling for the initial resident grant.
    ///
    /// This derives only from the original accepted capability and policy. The
    /// common mutating RPC timeout bounds acquisition/completion, not runtime
    /// lifetime. Native callers must authenticate these same protected accepted
    /// coordinates and additionally enforce fresh lease and Host-policy limits.
    #[must_use]
    pub const fn original_resident_authority_expiry_v1(self) -> i64 {
        if self.capability_expires < self.policy_expires {
            self.capability_expires
        } else {
            self.policy_expires
        }
    }

    /// Returns the minimum original acquisition wall expiry without sampling.
    pub fn original_wall_expiry_v1(self) -> Option<i64> {
        Some(self.original_resident_authority_expiry_v1()
            .min(self.signed_timeout_wall_expiry_v1()?))
    }

    /// Clamps a later raw sample to all original bounds without renewing them.
    ///
    /// This pure calculation grants no native, journal or publication authority.
    pub fn cutoff_for_sample_data_v1(self, sample: RawPairedClockSample) -> Option<u64> {
        self.clock.validate_same_boot_elapsed_data_v1(sample).ok()?;
        let cutoff = sample.conservative_expiry_deadline_data_v1(self.original_wall_expiry_v1()?)?
            .min(self.peer_cutoff)
            .min(self.clock.boottime_nanoseconds().checked_add(self.timeout_ns)?);
        (sample.boottime_nanoseconds() < cutoff).then_some(cutoff)
    }

    pub(super) fn encode_into_v1(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.clock.provenance().as_bytes());
        bytes.extend_from_slice(&self.clock.host_boot_id());
        bytes.extend_from_slice(&self.clock.wall_seconds().to_le_bytes());
        bytes.extend_from_slice(&self.clock.boottime_nanoseconds().to_le_bytes());
        bytes.extend_from_slice(&self.peer_cutoff.to_le_bytes());
        bytes.extend_from_slice(&self.capability_expires.to_le_bytes());
        bytes.extend_from_slice(&self.policy_expires.to_le_bytes());
        bytes.extend_from_slice(&self.timeout_ns.to_le_bytes());
    }

    pub(super) fn decode_v1(bytes: &[u8]) -> Result<Self, PublicOperationDataError> {
        let invalid = || PublicOperationDataError::CorruptLedger("invalid accepted Start origin");
        if bytes.len() != ACCEPTED_START_ORIGIN_BYTES { return Err(invalid()); }
        let provenance = RawClockProvenance::new_untrusted(bytes[..16].try_into().map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let clock = RawPairedClockSample::new_untrusted(provenance,
            bytes[16..32].try_into().map_err(|_| invalid())?,
            i64::from_le_bytes(bytes[32..40].try_into().map_err(|_| invalid())?),
            u64::from_le_bytes(bytes[40..48].try_into().map_err(|_| invalid())?),
        ).map_err(|_| invalid())?;
        Self::from_data_v1(clock,
            u64::from_le_bytes(bytes[48..56].try_into().map_err(|_| invalid())?),
            i64::from_le_bytes(bytes[56..64].try_into().map_err(|_| invalid())?),
            i64::from_le_bytes(bytes[64..72].try_into().map_err(|_| invalid())?),
            u64::from_le_bytes(bytes[72..80].try_into().map_err(|_| invalid())?),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::operation::{decode_operation, encode_operation_record,
        OperationRecord, OPERATION_RECORD_V2_BYTES, OPERATION_RECORD_V3_BYTES};
    use crate::domain_ledger::public_operation::{OperationState,
        PublicOperationAdmissionV1, PublicOperationAuthorizationV1};
    use crate::public_api::PublicOperationMethodV1;
    use aos_sandbox_core::{ProjectId, ResourceId, ResourceKind, Selector};

    fn origin() -> AcceptedStartOriginDataV1 {
        let clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16], 100, 10_000_000_000,
        ).unwrap();
        AcceptedStartOriginDataV1::from_data_v1(clock, 90_000_000_000, 150, 140, 60_000_000_000).unwrap()
    }

    fn record(method: PublicOperationMethodV1) -> OperationRecord {
        let authorization = PublicOperationAuthorizationV1::new(
            ProjectId::from_bytes([3; 16]), ResourceKind::Sandbox,
            Selector::Resource { resource: ResourceId::from_bytes([4; 16]) },
        ).unwrap();
        let metadata = PublicOperationAdmissionV1::new(method, 1, [5; 16], 100, authorization)
            .unwrap().durable();
        OperationRecord::new(OperationState::Accepted, 1, false, None, Some(metadata))
    }

    #[test]
    fn start_tail_round_trips_and_survives_state_progress() {
        let original = record(PublicOperationMethodV1::StartSandbox);
        let legacy = encode_operation_record(original);
        assert_eq!(legacy.len(), OPERATION_RECORD_V2_BYTES);
        assert_eq!(legacy[0], 2);

        let extended = original.with_accepted_start_origin_v1(origin());
        let encoded = encode_operation_record(extended);
        assert_eq!(encoded.len(), OPERATION_RECORD_V3_BYTES);
        assert_eq!(&encoded[1..OPERATION_RECORD_V2_BYTES], &legacy[1..]);
        assert_eq!(decode_operation(&encoded).unwrap(), extended);

        let metadata = extended.public_operation().unwrap().advance(OperationState::Applying, 101).unwrap();
        let applying = extended.with_state_and_public_operation(OperationState::Applying, Some(metadata));
        assert_eq!(decode_operation(&encode_operation_record(applying)).unwrap().accepted_start_origin_v1(), Some(origin()));
        assert_eq!(encode_operation_record(original), legacy);
    }

    #[test]
    fn origin_cannot_move_to_another_method_or_replace_accepted_wall() {
        let other = record(PublicOperationMethodV1::CreateSandbox).with_accepted_start_origin_v1(origin());
        assert!(decode_operation(&encode_operation_record(other)).is_err());
        let mut encoded = encode_operation_record(record(PublicOperationMethodV1::StartSandbox)
            .with_accepted_start_origin_v1(origin()));
        encoded[OPERATION_RECORD_V2_BYTES + 32..OPERATION_RECORD_V2_BYTES + 40]
            .copy_from_slice(&101_i64.to_le_bytes());
        assert!(decode_operation(&encoded).is_err());
    }

    #[test]
    fn later_native_pair_only_shrinks_the_original_deadline() {
        let original = origin();
        let later = RawPairedClockSample::new_untrusted(original.clock.provenance(),
            original.clock.host_boot_id(), 110, 20_000_000_000).unwrap();
        assert_eq!(original.cutoff_for_sample_data_v1(later), Some(49_000_000_000));
        let expired = RawPairedClockSample::new_untrusted(original.clock.provenance(),
            original.clock.host_boot_id(), 140, 50_000_000_000).unwrap();
        assert_eq!(original.cutoff_for_sample_data_v1(expired), None);
        let rebooted = RawPairedClockSample::new_untrusted(original.clock.provenance(),
            [9; 16], 110, 20_000_000_000).unwrap();
        assert_eq!(original.cutoff_for_sample_data_v1(rebooted), None);
    }
}

/// Bounds accepted coordinates, the first paid native pair, and its cutoff.
pub const START_NATIVE_ORIGIN_BYTES: usize = ACCEPTED_START_ORIGIN_BYTES + 56;

/// Stores the first actual native Start origin as immutable historical DATA.
///
/// Only a closed native Source producer may attach it to a protected Intent.
/// This parser and its raw clock values confer no journal or launch authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartNativeOriginDataV1 {
    accepted: AcceptedStartOriginDataV1,
    first_native: RawPairedClockSample,
    cutoff: u64,
}

impl StartNativeOriginDataV1 {
    /// Validates the shrinking relation between the two historical origins.
    ///
    /// # Errors
    /// Rejects boot/elapsed mismatch, exhausted original bounds or a renewed cutoff.
    pub fn from_data_v1(accepted: AcceptedStartOriginDataV1,
        first_native: RawPairedClockSample, cutoff: u64,
    ) -> Result<Self, PublicOperationDataError> {
        if accepted.cutoff_for_sample_data_v1(first_native) != Some(cutoff) {
            return Err(PublicOperationDataError::CorruptLedger("invalid first native Start origin"));
        }
        Ok(Self { accepted, first_native, cutoff })
    }

    /// Returns the immutable original public admission coordinates.
    pub const fn accepted_v1(self) -> AcceptedStartOriginDataV1 { self.accepted }

    /// Returns the first paid native sample without resampling or relabeling it.
    pub const fn first_native_clock_v1(self) -> RawPairedClockSample { self.first_native }

    /// Returns the unchanged first-native absolute BOOTTIME cutoff.
    pub const fn cutoff_v1(self) -> u64 { self.cutoff }

    /// Appends the complete canonical fixed-width DATA tail.
    ///
    /// This encoder accepts no record identity, native owner or append authority.
    pub fn encode_into_v1(self, bytes: &mut Vec<u8>) {
        self.accepted.encode_into_v1(bytes);
        bytes.extend_from_slice(&self.first_native.provenance().as_bytes());
        bytes.extend_from_slice(&self.first_native.host_boot_id());
        bytes.extend_from_slice(&self.first_native.wall_seconds().to_le_bytes());
        bytes.extend_from_slice(&self.first_native.boottime_nanoseconds().to_le_bytes());
        bytes.extend_from_slice(&self.cutoff.to_le_bytes());
    }

    /// Decodes one complete canonical historical native-origin tail.
    ///
    /// # Errors
    /// Rejects wrong width, malformed clock DATA or a nonshrinking original bound.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, PublicOperationDataError> {
        let invalid = || PublicOperationDataError::CorruptLedger("invalid first native Start origin");
        if bytes.len() != START_NATIVE_ORIGIN_BYTES { return Err(invalid()); }
        let accepted = AcceptedStartOriginDataV1::decode_v1(&bytes[..ACCEPTED_START_ORIGIN_BYTES])?;
        let bytes = &bytes[ACCEPTED_START_ORIGIN_BYTES..];
        let provenance = RawClockProvenance::new_untrusted(bytes[..16].try_into().map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let sample = RawPairedClockSample::new_untrusted(provenance,
            bytes[16..32].try_into().map_err(|_| invalid())?,
            i64::from_le_bytes(bytes[32..40].try_into().map_err(|_| invalid())?),
            u64::from_le_bytes(bytes[40..48].try_into().map_err(|_| invalid())?),
        ).map_err(|_| invalid())?;
        Self::from_data_v1(accepted, sample,
            u64::from_le_bytes(bytes[48..56].try_into().map_err(|_| invalid())?))
    }
}
