//! Encodes current live-lease comparison DATA for independent native readers.
//!
//! A canonical value is deliberately constructible DATA. Only the actual paid
//! Host receiver can issue its signed observation while holding the same native
//! writers and HostState cut. A historical value, even signed, cannot reconstruct
//! that owner, renew its cutoff, or authorize a Controller CAS.
//!
//! ```text
//! AOSHLV02 | scope:u64be | native-first-clock:u64be | native-cutoff:u64be |
//! native-boot:16 | marker-length:u64be | original-availability:368 |
//! actual-accepted-source:216 | marker:384/448 |
//! signed-terminal:32 | terminal-archive-head:32 | HostState-cut:32 |
//! execution-cut:32 | lease-head:32 | challenge:32 | current-Session:32 |
//! signed-current-request:32 | lease-epoch:u64be | observed-clock:u64be |
//! current-request:16 | checksum:32
//! ```

use sha2::{Digest as _, Sha256};

use super::{
    BeforeArgumentNoApplySourceDataV2, HostExecutionNoApplyRecordErrorV1 as Error,
    HostExecutionNoApplyRecordV2, take,
};
use crate::execution_availability::ExecutionAvailabilityPhaseV2;
use crate::host_execution_availability::{
    HostExecutionAvailabilityProposalV2,
    observation::{
        HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2, HostExecutionAvailabilityObservationV2,
    },
};

const MAGIC: &[u8; 8] = b"AOSHLV02";
const DOMAIN: &[u8] = b"aos.sandbox.host.current-no-apply-lease-data.v2\0";
const FIXED_BYTES: usize = 56
    + HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2
    + super::BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2
    + 8 * 32
    + 8
    + 8
    + 16
    + 32;

/// Bounds the complete explicit current-lease grammar including the closed union.
pub const MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2: usize =
    FIXED_BYTES + super::BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2;

/// Separates the original execution interval from fresh cleanup-only custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostNoApplyLeaseScopeV2 {
    /// Retains the original preaccept native baseline and unchanged cutoff.
    Active,
    /// Uses a separately paid fresh native interval over an already durable
    /// irreversible closure; it cannot renew execution or availability authority.
    RecoveryCleanup,
}

/// Carries observed coordinates while the real issuer retains native custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentHostNoApplyLeaseFieldsV2 {
    /// Actual native scope of this observation, independently authenticated.
    pub scope: HostNoApplyLeaseScopeV2,
    /// First paired native clock of that actual scope.
    pub native_first_clock: u64,
    /// Nonrenewable deadline of that actual scope.
    pub native_cutoff: u64,
    /// Actual current native Host boot, distinct from historical marker boot.
    pub native_boot: [u8; 16],
    /// Exact original same-owner accepted-bind availability observation.
    pub availability: HostExecutionAvailabilityObservationV2,
    /// Exact accepted Create source bound by the same actual native interval.
    pub accepted_source: BeforeArgumentNoApplySourceDataV2,
    /// Literal legacy or distinct closed-before-argument terminal marker.
    pub marker: HostExecutionNoApplyRecordV2,
    /// Exact authenticated signed terminal outcome commitment.
    pub signed_terminal_outcome: [u8; 32],
    /// Exact current protected terminal archive head.
    pub terminal_archive_head: [u8; 32],
    /// Actual HostState cut frozen by the same exclusive resident writer.
    pub protected_host_state_cut: [u8; 32],
    /// Actual full execution cut frozen after durable future-Apply closure.
    pub protected_execution_cut: [u8; 32],
    /// Exact current lease head bound by Controller prepare and acknowledgment.
    pub lease_head: [u8; 32],
    /// Original settlement challenge, unchanged throughout floor, CAS and ACK.
    pub challenge: [u8; 32],
    /// Actual current authenticated query Session, independently read by Root.
    pub current_session: [u8; 32],
    /// Digest of that actual signed current query request.
    pub signed_current_request: [u8; 32],
    /// Actual current native lease epoch under the retained writer.
    pub lease_epoch: u64,
    /// Fresh paired native clock on the original baseline and cutoff.
    pub observed_clock: u64,
    /// Actual authenticated current query request identity.
    pub current_request: [u8; 16],
}

/// Retains exact lease comparison DATA without adopting a live lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentHostNoApplyLeaseDataV2 {
    fields: CurrentHostNoApplyLeaseFieldsV2,
}

impl CurrentHostNoApplyLeaseDataV2 {
    /// Constructs structurally consistent current-lease comparison DATA.
    ///
    /// # Errors
    /// Rejects zero bindings, a nonaccepted availability, a foreign terminal
    /// relation, a regressed epoch or a clock outside the unchanged interval.
    pub fn new(fields: CurrentHostNoApplyLeaseFieldsV2) -> Result<Self, Error> {
        let original = fields.availability.fields();
        let accepted = fields.accepted_source.fields();
        let marker_source_matches = match fields.marker {
            HostExecutionNoApplyRecordV2::AfterArgument(marker) => {
                let marker = marker.fields();
                marker.create_operation_id == accepted.create_operation
                    && marker.execution_id == accepted.execution
                    && marker.assignment_digest == accepted.assignment_digest
                    && marker.host_boot_id == accepted.host_boot
            }
            HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) => {
                marker.fields().source == fields.accepted_source
            }
        };
        let (terminal_session, runtime, store, boot, sequence) = match fields.marker {
            HostExecutionNoApplyRecordV2::AfterArgument(marker) => {
                let marker = marker.fields();
                (
                    marker.terminal_session_binding,
                    marker.runtime_handle,
                    marker.execution_store_binding,
                    marker.host_boot_id,
                    marker.commit_sequence,
                )
            }
            HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) => {
                let marker = marker.fields();
                (
                    marker.terminal_session,
                    marker.runtime_handle,
                    marker.execution_store,
                    marker.source.fields().host_boot,
                    marker.commit_sequence,
                )
            }
        };
        if [
            fields.signed_terminal_outcome,
            fields.terminal_archive_head,
            fields.protected_host_state_cut,
            fields.protected_execution_cut,
            fields.lease_head,
            fields.challenge,
            fields.current_session,
            fields.signed_current_request,
        ]
        .contains(&[0; 32])
            || fields.current_request == [0; 16]
            || fields.lease_epoch < sequence
            || original.phase != ExecutionAvailabilityPhaseV2::AcceptedBind
            || terminal_session != original.session
            || runtime != original.runtime_handle
            || store != original.execution_store
            || boot != original.boot
            || !marker_source_matches
            || original.bound_source_digest != *fields.accepted_source.digest().as_bytes()
            || fields.lease_epoch < original.epoch
            // Both terminal variants append one row on this same writer axis.
            // Bind's cut cannot follow the actual preclose cut.
            || sequence.checked_sub(2).is_none_or(|before| original.epoch > before)
            || fields.native_boot == [0; 16]
            || fields.native_first_clock == 0
            || fields.observed_clock < fields.native_first_clock
            || fields.observed_clock >= fields.native_cutoff
            || fields.scope == HostNoApplyLeaseScopeV2::Active
                && (fields.native_first_clock != original.first_clock
                    || fields.native_cutoff != original.cutoff
                    || fields.native_boot != original.boot
                    || fields.observed_clock < original.observed_clock)
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self { fields })
    }

    /// Returns observed fields for independently authenticated comparisons.
    #[must_use]
    pub const fn fields(self) -> CurrentHostNoApplyLeaseFieldsV2 {
        self.fields
    }

    /// Encodes the exact closed union without padding or synthesized H/T fields.
    #[must_use]
    pub fn encode_canonical(self) -> Vec<u8> {
        let marker = match self.fields.marker {
            HostExecutionNoApplyRecordV2::AfterArgument(marker) => {
                marker.encode_canonical().to_vec()
            }
            HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) => {
                marker.encode_canonical().to_vec()
            }
        };
        let mut bytes = Vec::with_capacity(FIXED_BYTES + marker.len());
        bytes.extend_from_slice(MAGIC);
        let scope: u64 = match self.fields.scope {
            HostNoApplyLeaseScopeV2::Active => 1,
            HostNoApplyLeaseScopeV2::RecoveryCleanup => 2,
        };
        bytes.extend_from_slice(&scope.to_be_bytes());
        bytes.extend_from_slice(&self.fields.native_first_clock.to_be_bytes());
        bytes.extend_from_slice(&self.fields.native_cutoff.to_be_bytes());
        bytes.extend_from_slice(&self.fields.native_boot);
        bytes.extend_from_slice(&(marker.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.fields.availability.encode_canonical());
        bytes.extend_from_slice(&self.fields.accepted_source.encode_canonical());
        bytes.extend_from_slice(&marker);
        for field in [
            self.fields.signed_terminal_outcome,
            self.fields.terminal_archive_head,
            self.fields.protected_host_state_cut,
            self.fields.protected_execution_cut,
            self.fields.lease_head,
            self.fields.challenge,
            self.fields.current_session,
            self.fields.signed_current_request,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.fields.lease_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.fields.observed_clock.to_be_bytes());
        bytes.extend_from_slice(&self.fields.current_request);
        let checksum = checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    /// Decodes only the exact live-observation DATA version and closed marker union.
    ///
    /// # Errors
    /// Rejects other versions, unknown marker widths, extra bytes, invalid
    /// terminal/currentness bindings or changed canonical checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(Error::InvalidRecord);
        }
        let mut cursor = 8;
        let scope = match u64::from_be_bytes(take(bytes, &mut cursor)?) {
            1 => HostNoApplyLeaseScopeV2::Active,
            2 => HostNoApplyLeaseScopeV2::RecoveryCleanup,
            _ => return Err(Error::InvalidRecord),
        };
        let native_first_clock = u64::from_be_bytes(take(bytes, &mut cursor)?);
        let native_cutoff = u64::from_be_bytes(take(bytes, &mut cursor)?);
        let native_boot = take(bytes, &mut cursor)?;
        let marker_bytes = match u64::from_be_bytes(take(bytes, &mut cursor)?) {
            384 => 384,
            448 => 448,
            _ => return Err(Error::InvalidRecord),
        };
        if bytes.len() != FIXED_BYTES + marker_bytes {
            return Err(Error::InvalidRecord);
        }
        let availability = HostExecutionAvailabilityObservationV2::decode_canonical(
            &bytes[cursor..cursor + HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2],
        )
        .map_err(|_| Error::InvalidRecord)?;
        cursor += HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2;
        let accepted_source = BeforeArgumentNoApplySourceDataV2::decode_canonical(
            &bytes[cursor..cursor + super::BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2],
        )?;
        cursor += super::BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2;
        let marker =
            HostExecutionNoApplyRecordV2::decode_canonical(&bytes[cursor..cursor + marker_bytes])?;
        cursor += marker_bytes;
        let lease = Self::new(CurrentHostNoApplyLeaseFieldsV2 {
            scope,
            native_first_clock,
            native_cutoff,
            native_boot,
            availability,
            accepted_source,
            marker,
            signed_terminal_outcome: take(bytes, &mut cursor)?,
            terminal_archive_head: take(bytes, &mut cursor)?,
            protected_host_state_cut: take(bytes, &mut cursor)?,
            protected_execution_cut: take(bytes, &mut cursor)?,
            lease_head: take(bytes, &mut cursor)?,
            challenge: take(bytes, &mut cursor)?,
            current_session: take(bytes, &mut cursor)?,
            signed_current_request: take(bytes, &mut cursor)?,
            lease_epoch: u64::from_be_bytes(take(bytes, &mut cursor)?),
            observed_clock: u64::from_be_bytes(take(bytes, &mut cursor)?),
            current_request: take(bytes, &mut cursor)?,
        })?;
        if lease.encode_canonical().as_slice() != bytes {
            return Err(Error::InvalidRecord);
        }
        Ok(lease)
    }

    /// Compares the independently retained compiled proposal to this lease DATA.
    ///
    /// # Errors
    /// Rejects another proposal or a changed before-argument accepted source.
    pub fn require_proposal(
        self,
        proposal: HostExecutionAvailabilityProposalV2,
    ) -> Result<(), Error> {
        if *proposal.digest().as_bytes() != self.fields.availability.fields().proposal_digest {
            return Err(Error::InvalidRecord);
        }
        proposal
            .require_accepted_source(self.fields.accepted_source)
            .map_err(|_| Error::InvalidRecord)?;
        Ok(())
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_execution_availability::observation::HostExecutionAvailabilityObservationFieldsV2;
    use crate::host_execution_no_apply::{
        BeforeArgumentNoApplySourceDataV2, BeforeArgumentNoApplySourceFieldsV2,
        ClosedBeforeArgumentNoApplyRecordFieldsV2, ClosedBeforeArgumentNoApplyRecordV2,
        HostExecutionNoApplyRecordFieldsV1, HostExecutionNoApplyRecordV1,
    };

    fn fields() -> CurrentHostNoApplyLeaseFieldsV2 {
        let source = BeforeArgumentNoApplySourceDataV2::new(BeforeArgumentNoApplySourceFieldsV2 {
            create_operation: [1; 16],
            execution: [2; 16],
            sandbox: [3; 16],
            incarnation: [4; 16],
            node: [5; 16],
            host_boot: [6; 16],
            assignment_epoch: 7,
            desired_generation: 8,
            accepted_request_digest: [9; 32],
            assignment_digest: [10; 32],
        })
        .unwrap();
        let marker =
            ClosedBeforeArgumentNoApplyRecordV2::new(ClosedBeforeArgumentNoApplyRecordFieldsV2 {
                source,
                terminal_request: [11; 16],
                terminal_session: [12; 32],
                signed_terminal_request: [13; 32],
                runtime_handle: [14; 32],
                execution_store: [15; 32],
                observed_preclose_cut: [16; 32],
                observed_epoch: 8,
                commit_sequence: 10,
            })
            .unwrap();
        let availability = HostExecutionAvailabilityObservationV2::new(
            HostExecutionAvailabilityObservationFieldsV2 {
                phase: ExecutionAvailabilityPhaseV2::AcceptedBind,
                proposal_digest: [17; 32],
                request: [18; 16],
                session: [12; 32],
                signed_request: [19; 32],
                runtime_handle: [14; 32],
                execution_store: [15; 32],
                execution_cut: [20; 32],
                host_state_cut: [21; 32],
                boot: [6; 16],
                epoch: 8,
                first_clock: 100,
                cutoff: 1000,
                observed_clock: 200,
                bound_source_digest: *source.digest().as_bytes(),
            },
        )
        .unwrap();
        CurrentHostNoApplyLeaseFieldsV2 {
            scope: HostNoApplyLeaseScopeV2::Active,
            native_first_clock: 100,
            native_cutoff: 1000,
            native_boot: [6; 16],
            availability,
            accepted_source: source,
            marker: HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker),
            signed_terminal_outcome: [22; 32],
            terminal_archive_head: [23; 32],
            protected_host_state_cut: [24; 32],
            protected_execution_cut: [25; 32],
            lease_head: [26; 32],
            challenge: [27; 32],
            current_session: [28; 32],
            signed_current_request: [29; 32],
            lease_epoch: 10,
            observed_clock: 300,
            current_request: [30; 16],
        }
    }

    #[test]
    fn signed_current_query_keeps_terminal_custody_and_binds_fresh_request() {
        use crate::host_execution_no_apply::current_lease_transport::{
            decode_host_no_apply_current_lease_query_v2,
            decode_host_no_apply_current_lease_response_v2,
            encode_host_no_apply_current_lease_query_v2,
        };
        let expected = fields();
        let comparison = CurrentHostNoApplyLeaseDataV2::new(expected).unwrap();
        let mut header = crate::host_execution_no_apply::test_support::header([34; 16]);
        header.deadline_boottime_nanoseconds = 900;
        let (peer, policy) = crate::host_execution_no_apply::test_support::peer_policy();
        let encoded = encode_host_no_apply_current_lease_query_v2(&header, comparison, [35; 32]).unwrap();
        let query = decode_host_no_apply_current_lease_query_v2(&encoded, peer, policy, 400).unwrap();
        assert_eq!(query.comparison_v2(), comparison);
        assert_eq!(query.read_nonce_v2(), [35; 32]);

        let mut observed = expected;
        observed.current_session = [36; 32];
        observed.signed_current_request = [37; 32];
        observed.current_request = [34; 16];
        observed.observed_clock = 450;
        let response = CurrentHostNoApplyLeaseDataV2::new(observed).unwrap().encode_canonical();
        let actual = decode_host_no_apply_current_lease_response_v2(&response, &query, [36; 32], [37; 32]).unwrap();
        assert_eq!(actual.fields().challenge, expected.challenge);
        assert_eq!(actual.fields().terminal_archive_head, expected.terminal_archive_head);
        assert!(decode_host_no_apply_current_lease_response_v2(&response, &query, [38; 32], [37; 32]).is_err());
        assert!(decode_host_no_apply_current_lease_response_v2(&response, &query, [36; 32], [38; 32]).is_err());

        for change in 0..8 {
            let mut foreign = observed;
            match change {
                0 => foreign.terminal_archive_head = [38; 32],
                1 => foreign.signed_terminal_outcome = [38; 32],
                2 => foreign.protected_execution_cut = [38; 32],
                3 => foreign.protected_host_state_cut = [38; 32],
                4 => foreign.lease_head = [38; 32],
                5 => foreign.lease_epoch += 1,
                6 => foreign.challenge = [38; 32],
                7 => foreign.current_request = [38; 16],
                _ => unreachable!(),
            }
            let foreign = CurrentHostNoApplyLeaseDataV2::new(foreign).unwrap().encode_canonical();
            assert!(decode_host_no_apply_current_lease_response_v2(&foreign, &query, [36; 32], [37; 32]).is_err());
        }

        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(decode_host_no_apply_current_lease_query_v2(&changed, peer, policy, 400).is_err());
        }
    }

    #[test]
    fn recovery_query_obeys_fresh_cleanup_interval_and_keeps_original_expiry() {
        use crate::host_execution_no_apply::current_lease_transport::{
            decode_host_no_apply_current_lease_query_v2,
            decode_host_no_apply_current_lease_response_v2,
            encode_host_no_apply_current_lease_query_v2,
        };
        let mut recovery = fields();
        recovery.scope = HostNoApplyLeaseScopeV2::RecoveryCleanup;
        recovery.native_first_clock = 1200;
        recovery.native_cutoff = 2000;
        recovery.native_boot = [39; 16];
        recovery.observed_clock = 1300;
        let comparison = CurrentHostNoApplyLeaseDataV2::new(recovery).unwrap();
        let mut header = crate::host_execution_no_apply::test_support::header([34; 16]);
        header.deadline_boottime_nanoseconds = 2100;
        let (peer, policy) = crate::host_execution_no_apply::test_support::peer_policy();
        let encoded = encode_host_no_apply_current_lease_query_v2(&header, comparison, [35; 32]).unwrap();
        let query = decode_host_no_apply_current_lease_query_v2(&encoded, peer, policy, 1400).unwrap();
        assert_eq!(query.comparison_v2().fields().availability.fields().cutoff, 1000);
        assert!(decode_host_no_apply_current_lease_query_v2(&encoded, peer, policy, 2000).is_err());

        recovery.current_request = [34; 16];
        recovery.current_session = [36; 32];
        recovery.signed_current_request = [37; 32];
        recovery.observed_clock = 1500;
        let response = CurrentHostNoApplyLeaseDataV2::new(recovery).unwrap().encode_canonical();
        assert!(decode_host_no_apply_current_lease_response_v2(&response, &query, [36; 32], [37; 32]).is_ok());
        recovery.scope = HostNoApplyLeaseScopeV2::Active;
        assert!(CurrentHostNoApplyLeaseDataV2::new(recovery).is_err());

        let mut root_policy = policy;
        root_policy.audience = aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_ROOT_MOUNT;
        assert!(decode_host_no_apply_current_lease_query_v2(&encoded, peer, root_policy, 1400).is_err());
    }

    #[test]
    fn closed_union_keeps_literal_markers_and_rejects_every_modified_byte() {
        let mut fields = fields();
        for legacy in [false, true] {
            if legacy {
                fields.marker = HostExecutionNoApplyRecordV2::AfterArgument(
                    HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
                        execution_id: [2; 16],
                        create_operation_id: [1; 16],
                        original_request_id: [31; 16],
                        terminal_request_id: [11; 16],
                        host_boot_id: [6; 16],
                        assignment_digest: [10; 32],
                        source_record_digest: [32; 32],
                        original_session_binding: [12; 32],
                        original_signed_request_digest: [33; 32],
                        terminal_session_binding: [12; 32],
                        terminal_signed_request_digest: [13; 32],
                        runtime_handle: [14; 32],
                        execution_store_binding: [15; 32],
                        commit_sequence: 10,
                    })
                    .unwrap(),
                );
            }
            let data = CurrentHostNoApplyLeaseDataV2::new(fields).unwrap();
            let encoded = data.encode_canonical();
            assert_eq!(
                encoded.len(),
                if legacy {
                    MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2 - 64
                } else {
                    MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2
                }
            );
            assert_eq!(
                CurrentHostNoApplyLeaseDataV2::decode_canonical(&encoded).unwrap(),
                data
            );
            let marker_bytes = match fields.marker {
                HostExecutionNoApplyRecordV2::AfterArgument(marker) => {
                    marker.encode_canonical().to_vec()
                }
                HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) => {
                    marker.encode_canonical().to_vec()
                }
            };
            assert_eq!(
                &encoded[640..640 + marker_bytes.len()],
                marker_bytes.as_slice()
            );
            for index in 0..encoded.len() {
                let mut changed = encoded.clone();
                changed[index] ^= 1;
                assert!(
                    CurrentHostNoApplyLeaseDataV2::decode_canonical(&changed).is_err(),
                    "legacy={legacy}, byte={index}"
                );
            }
        }
    }

    #[test]
    fn fresh_cleanup_data_does_not_renew_original_execution_bounds() {
        let original = fields();
        let mut expired = original;
        expired.observed_clock = 1001;
        assert!(CurrentHostNoApplyLeaseDataV2::new(expired).is_err());
        expired.native_first_clock = 1001;
        expired.native_cutoff = 2000;
        assert!(CurrentHostNoApplyLeaseDataV2::new(expired).is_err());

        expired.scope = HostNoApplyLeaseScopeV2::RecoveryCleanup;
        let cleanup = CurrentHostNoApplyLeaseDataV2::new(expired).unwrap();
        assert_eq!(cleanup.fields().availability, original.availability);
        assert_eq!(cleanup.fields().marker, original.marker);
        assert_eq!(cleanup.fields().availability.fields().cutoff, 1000);
        assert_eq!(cleanup.fields().native_cutoff, 2000);

        expired.observed_clock = expired.native_cutoff;
        assert!(CurrentHostNoApplyLeaseDataV2::new(expired).is_err());
        expired.observed_clock = 1001;
        expired.native_cutoff = expired.native_first_clock + 90_000_000_000;
        assert!(CurrentHostNoApplyLeaseDataV2::new(expired).is_ok());
    }

    #[test]
    fn terminal_and_original_availability_cannot_cross_sources_or_boots() {
        let original = fields();
        for change in 0..3 {
            let mut changed = original;
            match change {
                0 => changed.lease_epoch = 9,
                1 => changed.native_boot = [40; 16],
                _ => {
                    let mut observed = original.availability.fields();
                    observed.bound_source_digest = [41; 32];
                    changed.availability =
                        HostExecutionAvailabilityObservationV2::new(observed).unwrap();
                }
            }
            assert!(CurrentHostNoApplyLeaseDataV2::new(changed).is_err());
        }
    }

    #[test]
    fn legacy_marker_cannot_switch_create_or_execution_under_the_same_assignment() {
        let original = fields();
        let source = original.accepted_source.fields();
        let marker = HostExecutionNoApplyRecordFieldsV1 {
            execution_id: source.execution,
            create_operation_id: source.create_operation,
            original_request_id: [31; 16],
            terminal_request_id: [11; 16],
            host_boot_id: source.host_boot,
            assignment_digest: source.assignment_digest,
            source_record_digest: [32; 32],
            original_session_binding: [12; 32],
            original_signed_request_digest: [33; 32],
            terminal_session_binding: [12; 32],
            terminal_signed_request_digest: [13; 32],
            runtime_handle: [14; 32],
            execution_store_binding: [15; 32],
            commit_sequence: 10,
        };
        let mut fields = original;
        fields.marker = HostExecutionNoApplyRecordV2::AfterArgument(
            HostExecutionNoApplyRecordV1::new(marker).unwrap(),
        );
        assert!(CurrentHostNoApplyLeaseDataV2::new(fields).is_ok());

        for changed in 0..2 {
            let mut foreign = marker;
            if changed == 0 {
                foreign.create_operation_id = [40; 16];
            } else {
                foreign.execution_id = [41; 16];
            }
            fields.marker = HostExecutionNoApplyRecordV2::AfterArgument(
                HostExecutionNoApplyRecordV1::new(foreign).unwrap(),
            );
            assert!(CurrentHostNoApplyLeaseDataV2::new(fields).is_err());
        }
    }

    #[test]
    fn availability_epoch_cannot_follow_its_terminal_preclose_or_current_lease() {
        for epoch in [9, 11] {
            let mut fields = fields();
            let mut observation = fields.availability.fields();
            observation.epoch = epoch;
            fields.availability = HostExecutionAvailabilityObservationV2::new(observation).unwrap();
            assert!(CurrentHostNoApplyLeaseDataV2::new(fields).is_err());
        }
    }
}
