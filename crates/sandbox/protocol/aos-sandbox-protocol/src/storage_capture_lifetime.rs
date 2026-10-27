//! Canonical, nonauthorizing ongoing Capture lifetime provenance.
//!
//! ```text
//! AOSCLF02 | execution[16] | original-Create[16] | accepted-operation[16]
//! | accepted-request-digest[32] | canonical-ExecSpec-digest[32]
//! | BrokerAssignment[80] | original-lease-digest[32] | lease-generation:u64be
//! | original-target-RawPair[48] | original-root-plan-expiry:i64be
//! | original-lease-expiry:i64be | original-lease-skew:u64be
//! | original-residency-D:u64be | first-pre-spawn-RawPair[48]
//! | explicit-ExecSpec-timeout:u64be | execution-parent-plan-expiry:i64be
//! | execution-D:u64be | SHA256(domain || preceding)[32]
//! ```
//!
//! RawPair is provenance[16], host-boot[16], wall:i64be, BOOTTIME:u64be.
//! i64::MIN encodes absence of an original root-plan expiry. All bounds are
//! computed from original samples; decoding or a later query cannot renew one.
//! Parsing grants no entry, residency, effect, cleanup or native completion.

use aos_sandbox_model::{AssignmentEpoch, BrokerAssignment, DesiredGeneration,
    ExecutionId, ExecutionSpecV1, IncarnationId, ObjectDigest, OperationId,
    RawClockProvenance, RawPairedClockSample, SandboxId, execution_spec_digest_v1};
use sha2::{Digest as _, Sha256};
use crate::ProtocolValidationError;

/// Exact complete lifetime provenance width, separate from Source512 and admissionD.
pub const STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2: usize = 424;
const MAGIC: &[u8; 8] = b"AOSCLF02";
const DOMAIN: &[u8] = b"aos.sandbox.storage.capture-execution-lifetime.v2\0";

/// Supplies original comparison inputs obtained by the genuine selected producer.
///
/// These fields authenticate nothing. The issuer must borrow the original
/// assignment owner, actual accepted request and exact canonical ExecSpec,
/// prepay before growth, and sign the full resulting versioned request.
pub struct StorageCaptureLifetimeOriginsDataV2 {
    /// First actual assignment-target sample, never a replacement observation.
    pub original_target_clock: RawPairedClockSample,
    /// Exact independently authenticated original signed lease digest.
    pub original_lease_digest: ObjectDigest,
    /// Exact original signed lease generation.
    pub original_lease_generation: u64,
    /// Original signed lease expiry before skew and safety attenuation.
    pub original_lease_authority_expires_seconds: i64,
    /// Original signed maximum clock skew; Core's safety margin remains additional.
    pub original_lease_maximum_clock_skew_seconds: u64,
    /// Original signed root-plan expiry when acquisition selected a plan.
    pub original_root_plan_expires_seconds: Option<i64>,
    /// Independently retained original residency bound before freshness attenuation.
    pub original_residency_deadline_boottime_nanoseconds: u64,
    /// Earliest paid retained pre-spawn sample for this actual Capture flight.
    pub first_pre_spawn_clock: RawPairedClockSample,
    /// Existing signed execution-parent plan expiry, never a new relative window.
    pub execution_parent_plan_expires_seconds: i64,
}

/// Retains the whole canonical lifetime and its parsed comparison origins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCaptureExecutionLifetimeDataV2 {
    bytes: [u8; STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2],
    assignment: BrokerAssignment,
    original_clock: RawPairedClockSample,
    pre_spawn_clock: RawPairedClockSample,
}

impl StorageCaptureExecutionLifetimeDataV2 {
    /// Prices the complete fixed carriers and canonical-spec digest scratch.
    ///
    /// The selected caller separately pays the existing complete spec model
    /// materialization geometry. No descriptor, namespace or authority is created.
    pub fn receiving_memory_bytes_v2(canonical_spec_bytes: usize) -> Option<usize> {
        canonical_spec_bytes.checked_mul(4)?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(2 * std::mem::size_of::<StorageCaptureLifetimeOriginsDataV2>())?
            .checked_add(2 * STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2)
    }

    /// Encodes exact specification and original-owner comparison inputs.
    ///
    /// # Errors
    /// Rejects foreign target/audit, absent identities, changed original bounds,
    /// overflow, reader substitution, or an exhausted original lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn from_pre_spawn_sources_data_v2(
        specification: &ExecutionSpecV1,
        original_create: OperationId,
        accepted_operation: OperationId,
        accepted_request_digest: ObjectDigest,
        assignment: BrokerAssignment,
        origins: &StorageCaptureLifetimeOriginsDataV2,
    ) -> Result<Self, ProtocolValidationError> {
        let target = specification.target();
        if target.sandbox() != assignment.sandbox() || target.incarnation() != assignment.incarnation()
            || target.assignment_epoch() != assignment.epoch()
            || target.assignment_digest() != assignment.digest()
            || specification.audit().as_bytes() != accepted_operation.as_bytes()
        { return Err(invalid()); }
        let mut bytes = [0; STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(specification.execution().as_bytes());
        bytes[24..40].copy_from_slice(original_create.as_bytes());
        bytes[40..56].copy_from_slice(accepted_operation.as_bytes());
        bytes[56..88].copy_from_slice(accepted_request_digest.as_bytes());
        bytes[88..120].copy_from_slice(execution_spec_digest_v1(specification).as_bytes());
        bytes[120..136].copy_from_slice(assignment.sandbox().as_bytes());
        bytes[136..152].copy_from_slice(assignment.incarnation().as_bytes());
        bytes[152..160].copy_from_slice(&assignment.epoch().get().to_be_bytes());
        bytes[160..168].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
        bytes[168..200].copy_from_slice(assignment.digest().as_bytes());
        bytes[200..232].copy_from_slice(origins.original_lease_digest.as_bytes());
        bytes[232..240].copy_from_slice(&origins.original_lease_generation.to_be_bytes());
        put_clock(&mut bytes[240..288], origins.original_target_clock);
        bytes[288..296].copy_from_slice(&origins.original_root_plan_expires_seconds.unwrap_or(i64::MIN).to_be_bytes());
        bytes[296..304].copy_from_slice(&origins.original_lease_authority_expires_seconds.to_be_bytes());
        bytes[304..312].copy_from_slice(&origins.original_lease_maximum_clock_skew_seconds.to_be_bytes());
        bytes[312..320].copy_from_slice(&origins.original_residency_deadline_boottime_nanoseconds.to_be_bytes());
        put_clock(&mut bytes[320..368], origins.first_pre_spawn_clock);
        bytes[368..376].copy_from_slice(&specification.timeout().nanoseconds().to_be_bytes());
        bytes[376..384].copy_from_slice(&origins.execution_parent_plan_expires_seconds.to_be_bytes());
        let deadline = lifetime_deadline(origins.first_pre_spawn_clock,
            specification.timeout().nanoseconds(),
            origins.original_residency_deadline_boottime_nanoseconds,
            origins.execution_parent_plan_expires_seconds)?;
        bytes[384..392].copy_from_slice(&deadline.to_be_bytes());
        let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..392]).finalize();
        bytes[392..424].copy_from_slice(&digest);
        Self::from_canonical_bytes_v2(&bytes)
    }

    /// Decodes full provenance without adopting an execution or native permit.
    ///
    /// # Errors
    /// Rejects width, magic, checksum, sentinel, pair chronology, substituted
    /// original projection or a different derived execution bound.
    pub fn from_canonical_bytes_v2(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        let bytes: [u8; STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2] = bytes.try_into().map_err(|_| invalid())?;
        if &bytes[..8] != MAGIC || [8..24, 24..40, 40..56, 56..88, 88..120,
            120..136, 136..152, 168..200, 200..232].into_iter().any(|range| bytes[range].iter().all(|byte| *byte == 0))
            || u64_at(&bytes, 232) == 0 || u64_at(&bytes, 368) == 0
        { return Err(invalid()); }
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes(array_at(&bytes, 120)), IncarnationId::from_bytes(array_at(&bytes, 136)),
            AssignmentEpoch::new(u64_at(&bytes, 152)), DesiredGeneration::new(u64_at(&bytes, 160)),
            ObjectDigest::from_bytes(array_at(&bytes, 168)),
        ).map_err(|_| invalid())?;
        let original_clock = clock_at(&bytes, 240)?;
        let pre_spawn_clock = clock_at(&bytes, 320)?;
        original_clock.validate_later_sample(pre_spawn_clock).map_err(|_| invalid())?;
        let mut original_deadline = original_clock.conservative_lease_expiry_deadline_data_v2(
            i64_at(&bytes, 296), u64_at(&bytes, 304),
        ).map_err(|_| invalid())?;
        let root_plan = i64_at(&bytes, 288);
        if root_plan != i64::MIN {
            original_deadline = original_deadline.min(
                original_clock.conservative_expiry_deadline_data_v1(root_plan).ok_or_else(invalid)?);
        }
        let deadline = lifetime_deadline(pre_spawn_clock, u64_at(&bytes, 368), original_deadline, i64_at(&bytes, 376))?;
        let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..392]).finalize();
        if original_deadline != u64_at(&bytes, 312) || deadline != u64_at(&bytes, 384)
            || digest.as_slice() != &bytes[392..424]
        { return Err(invalid()); }
        Ok(Self { bytes, assignment, original_clock, pre_spawn_clock })
    }

    /// Borrows all canonical provenance bytes for the signed request and native77 record.
    pub const fn canonical_bytes_v2(&self) -> &[u8; STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2] { &self.bytes }

    /// Returns the complete lifetime preimage commitment.
    pub fn digest_v2(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, 392)) }

    /// Returns the exact execution identity.
    pub fn execution_v2(&self) -> ExecutionId { ExecutionId::from_bytes(array_at(&self.bytes, 8)) }

    /// Returns the original output Create identity independently of the actual accepted operation.
    pub fn original_create_operation_v2(&self) -> OperationId { OperationId::from_bytes(array_at(&self.bytes, 24)) }

    /// Returns the actual accepted execution operation; later Start cannot use a Create default.
    pub fn accepted_operation_v2(&self) -> OperationId { OperationId::from_bytes(array_at(&self.bytes, 40)) }

    /// Returns the actual accepted request commitment.
    pub fn accepted_request_digest_v2(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, 56)) }

    /// Returns the exact canonical execution-specification commitment.
    pub fn specification_digest_v2(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, 88)) }

    /// Returns the complete assignment comparison tuple.
    pub const fn assignment_v2(&self) -> BrokerAssignment { self.assignment }

    /// Returns the independently authenticated original lease commitment.
    pub fn original_lease_digest_v2(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, 200)) }

    /// Returns the immutable original lease generation.
    pub fn original_lease_generation_v2(&self) -> u64 { u64_at(&self.bytes, 232) }

    /// Returns the first original assignment clock, without relabeling.
    pub const fn original_target_clock_v2(&self) -> RawPairedClockSample { self.original_clock }

    /// Returns the first paid pre-spawn clock, without resampling.
    pub const fn first_pre_spawn_clock_v2(&self) -> RawPairedClockSample { self.pre_spawn_clock }

    /// Returns the exact admitted explicit execution duration.
    pub fn timeout_nanoseconds_v2(&self) -> u64 { u64_at(&self.bytes, 368) }

    /// Returns comparison DATA for the separately versioned ongoing bound.
    pub fn deadline_boottime_nanoseconds_v2(&self) -> u64 { u64_at(&self.bytes, 384) }

    /// Compares the full actual specification and accepted request identity.
    ///
    /// The caller prepays canonical-spec digest scratch before this comparison.
    /// Matching DATA supplies no native authority or completed-IO proof.
    ///
    /// # Errors
    /// Rejects a foreign execution, accepted operation/request, target,
    /// timeout or any changed canonical specification byte.
    pub fn require_specification_data_v2(&self, specification: &ExecutionSpecV1,
        original_create: OperationId, accepted_operation: OperationId,
        accepted_request_digest: ObjectDigest) -> Result<(), ProtocolValidationError>
    {
        let target = specification.target();
        if self.execution_v2() != specification.execution()
            || self.original_create_operation_v2() != original_create
            || self.accepted_operation_v2() != accepted_operation
            || self.accepted_request_digest_v2() != accepted_request_digest
            || specification.audit().as_bytes() != accepted_operation.as_bytes()
            || self.specification_digest_v2() != execution_spec_digest_v1(specification)
            || self.timeout_nanoseconds_v2() != specification.timeout().nanoseconds()
            || target.sandbox() != self.assignment.sandbox()
            || target.incarnation() != self.assignment.incarnation()
            || target.assignment_epoch() != self.assignment.epoch()
            || target.assignment_digest() != self.assignment.digest()
        { return Err(invalid()); }
        Ok(())
    }

    /// Compares the original lease identity and bounds with the actual verified lease.
    ///
    /// # Errors
    /// Rejects changed signed lease identity, generation, expiry or declared skew.
    pub fn require_original_lease_data_v2(&self, digest: ObjectDigest, generation: u64,
        authority_expires_seconds: i64, maximum_clock_skew_seconds: u64)
        -> Result<(), ProtocolValidationError>
    {
        if self.original_lease_digest_v2() != digest || self.original_lease_generation_v2() != generation
            || i64_at(&self.bytes, 296) != authority_expires_seconds
            || u64_at(&self.bytes, 304) != maximum_clock_skew_seconds
        { return Err(invalid()); }
        Ok(())
    }

    /// Tightens the original bound against an actual later admitted pair and ceilings.
    ///
    /// The caller must join these inputs to the SAME verified admission and
    /// commit/readback before minting its private ongoing native owner.
    ///
    /// # Errors
    /// Rejects foreign readers/boot, rollback, exhausted time or invalid ceilings.
    pub fn tighten_admitted_deadline_data_v2(&self, actual_admitted: RawPairedClockSample,
        actual_plan_expires_seconds: i64, actual_lease_fail_stop: u64)
        -> Result<u64, ProtocolValidationError>
    {
        self.pre_spawn_clock.validate_later_sample(actual_admitted).map_err(|_| invalid())?;
        let deadline = self.deadline_boottime_nanoseconds_v2().min(actual_lease_fail_stop)
            .min(actual_admitted.conservative_expiry_deadline_data_v1(actual_plan_expires_seconds).ok_or_else(invalid)?);
        if deadline <= actual_admitted.boottime_nanoseconds() { return Err(invalid()); }
        Ok(deadline)
    }
}

fn lifetime_deadline(origin: RawPairedClockSample, timeout: u64, original: u64, plan_expiry: i64)
    -> Result<u64, ProtocolValidationError>
{
    if timeout == 0 { return Err(invalid()); }
    let deadline = origin.boottime_nanoseconds().checked_add(timeout).ok_or_else(invalid)?
        .min(original).min(origin.conservative_expiry_deadline_data_v1(plan_expiry).ok_or_else(invalid)?);
    if deadline <= origin.boottime_nanoseconds() { return Err(invalid()); }
    Ok(deadline)
}

fn put_clock(bytes: &mut [u8], clock: RawPairedClockSample) {
    bytes[..16].copy_from_slice(&clock.provenance().as_bytes());
    bytes[16..32].copy_from_slice(&clock.host_boot_id());
    bytes[32..40].copy_from_slice(&clock.wall_seconds().to_be_bytes());
    bytes[40..48].copy_from_slice(&clock.boottime_nanoseconds().to_be_bytes());
}

fn clock_at(bytes: &[u8], offset: usize) -> Result<RawPairedClockSample, ProtocolValidationError> {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(array_at(bytes, offset)).map_err(|_| invalid())?,
        array_at(bytes, offset + 16), i64_at(bytes, offset + 32), u64_at(bytes, offset + 40),
    ).map_err(|_| invalid())
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 { u64::from_be_bytes(array_at(bytes, offset)) }
fn i64_at(bytes: &[u8], offset: usize) -> i64 { i64::from_be_bytes(array_at(bytes, offset)) }
fn invalid() -> ProtocolValidationError { ProtocolValidationError::InvalidField("Capture execution lifetime provenance") }

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(wall: i64, boot: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [7; 16], wall, boot,
        ).unwrap()
    }

    fn checksum(bytes: &mut [u8; STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2]) {
        let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..392]).finalize();
        bytes[392..].copy_from_slice(&digest);
    }

    // Structural codec DATA only; this fixture creates no native or signed owner.
    fn bytes() -> [u8; STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2] {
        let mut bytes = [1; STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[152..160].copy_from_slice(&1_u64.to_be_bytes());
        bytes[160..168].copy_from_slice(&1_u64.to_be_bytes());
        bytes[232..240].copy_from_slice(&1_u64.to_be_bytes());
        let original = clock(100, 10_000_000_000);
        let pre_spawn = clock(101, 11_000_000_000);
        put_clock(&mut bytes[240..288], original);
        bytes[288..296].copy_from_slice(&250_i64.to_be_bytes());
        bytes[296..304].copy_from_slice(&300_i64.to_be_bytes());
        bytes[304..312].copy_from_slice(&2_u64.to_be_bytes());
        let root = original.conservative_lease_expiry_deadline_data_v2(300, 2).unwrap()
            .min(original.conservative_expiry_deadline_data_v1(250).unwrap());
        bytes[312..320].copy_from_slice(&root.to_be_bytes());
        put_clock(&mut bytes[320..368], pre_spawn);
        bytes[368..376].copy_from_slice(&60_000_000_000_u64.to_be_bytes());
        bytes[376..384].copy_from_slice(&240_i64.to_be_bytes());
        let deadline = lifetime_deadline(pre_spawn, 60_000_000_000, root, 240).unwrap();
        bytes[384..392].copy_from_slice(&deadline.to_be_bytes());
        checksum(&mut bytes);
        bytes
    }

    #[test]
    fn later_admission_only_tightens_and_never_restarts_the_timeout() {
        let original = StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&bytes()).unwrap();
        assert_eq!(original.deadline_boottime_nanoseconds_v2(), 71_000_000_000);
        let before = *original.canonical_bytes_v2();

        assert_eq!(original.tighten_admitted_deadline_data_v2(
            clock(120, 30_000_000_000), 240, 65_000_000_000,
        ).unwrap(), 65_000_000_000);
        assert_eq!(original.tighten_admitted_deadline_data_v2(
            clock(130, 40_000_000_000), 240, 200_000_000_000,
        ).unwrap(), 71_000_000_000);
        assert!(original.tighten_admitted_deadline_data_v2(
            clock(162, 72_000_000_000), 240, 200_000_000_000,
        ).is_err());
        assert_eq!(*original.canonical_bytes_v2(), before);
    }

    #[test]
    fn checksum_does_not_permit_replacement_origins_or_false_projections() {
        for offset in [312, 384] {
            let mut changed = bytes();
            let later = u64_at(&changed, offset) + 1;
            changed[offset..offset + 8].copy_from_slice(&later.to_be_bytes());
            checksum(&mut changed);
            assert!(StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&changed).is_err());
        }
        let mut changed = bytes();
        changed[320..336].fill(8);
        checksum(&mut changed);
        assert!(StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&changed).is_err());

        let mut changed = bytes();
        changed[368..376].fill(0);
        checksum(&mut changed);
        assert!(StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&changed).is_err());
    }

    #[test]
    fn original_lease_identity_cannot_be_replaced_by_a_renewal() {
        let original = StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&bytes()).unwrap();
        let digest = original.original_lease_digest_v2();
        original.require_original_lease_data_v2(digest, 1, 300, 2).unwrap();
        assert!(original.require_original_lease_data_v2(digest, 2, 300, 2).is_err());
        assert!(original.require_original_lease_data_v2(digest, 1, 301, 2).is_err());
        assert!(original.require_original_lease_data_v2(digest, 1, 300, 1).is_err());
    }
}
