//! Binds one fresh Stop-only cleanup request to immutable protected history.
//!
//! These canonical bytes are comparison DATA. A current OperatorRecover
//! capability decision, paid Source originals, current signed plan and fresh
//! Host native ownership observations remain separate prerequisites. Decoding
//! never restores an old Launch owner or extends its deadline or funding.
//!
//! ```text
//! AOSHSC01 | old AOSHNS04(328) | Recover-operation16 | cleanup-request16 | Recover-request32 |
//! current-boot16 | authorization-revision32 | original-Recover-cutoff:u64le
//! ```
//!
//! `AOSHSC02` has the same width and fields but explicitly names Source dispatch
//! before Host received the old Stop. Its embedded Stop tuple is independently
//! authenticated Source DATA, never a claim that Host has an old Pending row.

use crate::{
    ProtocolValidationError, ValidatedAssignmentFence,
    host_stopped_namespace::HostStoppedNamespaceDataV4,
};

/// Gives the exact canonical width of the finite cleanup subject.
pub const HOST_STOP_CLEANUP_SUBJECT_BYTES_V1: usize = 456;
/// Bounds canonical Stop fields plus tag6, its two-byte length and fixed subject.
pub const MAXIMUM_CANONICAL_HOST_STOP_CLEANUP_BODY_BYTES_V1: usize =
    crate::storage_capture_session::stop_cleanup::MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4
        + 1
        + 2
        + HOST_STOP_CLEANUP_SUBJECT_BYTES_V1;
const MAGIC: &[u8; 8] = b"AOSHSC01";
const DISPATCH_MAGIC: &[u8; 8] = b"AOSHSC02";

/// Distinguishes authenticated Host Pending from Source dispatch before Host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostStopCleanupOriginDataV1 {
    /// The immutable old Stop exists in protected Host history.
    ProtectedPending,
    /// Source saved the actual old dispatch, but Host has no old Stop row.
    DispatchedBeforeHost,
}

/// Retains a new cleanup request beside the unchanged old Launch/Stop scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostStopCleanupSubjectDataV1 {
    historical: HostStoppedNamespaceDataV4,
    recovery: [u8; 16],
    cleanup: [u8; 16],
    request: [u8; 32],
    boot: [u8; 16],
    revision: [u8; 32],
    cutoff: u64,
    origin: HostStopCleanupOriginDataV1,
}

impl HostStopCleanupSubjectDataV1 {
    /// Commits the exact versioned subject as nonauthorizing comparison DATA.
    ///
    /// The Source financial association and independent Root verifier use this
    /// same digest. It authenticates neither history nor current permission.
    #[must_use]
    pub fn digest_data_v1(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        Sha256::new()
            .chain_update(b"aos.sandbox.host-stop-cleanup.subject.v1\0")
            .chain_update(self.encode_v1())
            .finalize()
            .into()
    }

    /// Checks fixed nonauthorizing identities for the new Recover attempt.
    ///
    /// # Errors
    /// Refuses unspecified fields or reuse of either historical request ID.
    pub fn from_data_v1(
        historical: HostStoppedNamespaceDataV4,
        recovery: [u8; 16],
        cleanup: [u8; 16],
        request: [u8; 32],
        boot: [u8; 16],
        revision: [u8; 32],
        cutoff: u64,
    ) -> Result<Self, ProtocolValidationError> {
        if recovery == [0; 16]
            || cleanup == [0; 16]
            || request == [0; 32]
            || boot == [0; 16]
            || revision == [0; 32]
            || cutoff == 0
            || recovery == historical.launch_v4().0
            || recovery == historical.stop_v4().0
            || cleanup == recovery
            || cleanup == historical.launch_v4().0
            || cleanup == historical.stop_v4().0
        {
            return Err(invalid());
        }
        Ok(Self {
            historical,
            recovery,
            cleanup,
            request,
            boot,
            revision,
            cutoff,
            origin: HostStopCleanupOriginDataV1::ProtectedPending,
        })
    }

    /// Joins passive Launch history with separately authenticated Source dispatch.
    ///
    /// The caller must independently prove the actual Source A7, accepted Recover,
    /// desired-absent target and current authorization before signing this origin.
    /// This constructor creates no Host Pending or old native original.
    ///
    /// # Errors
    /// Refuses invalid scope, reused identities or unspecified current coordinates.
    #[allow(clippy::too_many_arguments)]
    pub fn from_dispatched_data_v2(
        launch: crate::host_stopped_namespace::HostLaunchNamespaceDataV1,
        dispatch: crate::host_stopped_namespace::HostStoppedRequestIdentityDataV4,
        recovery: [u8; 16],
        cleanup: [u8; 16],
        request: [u8; 32],
        boot: [u8; 16],
        revision: [u8; 32],
        cutoff: u64,
    ) -> Result<Self, ProtocolValidationError> {
        let historical = HostStoppedNamespaceDataV4::from_data_v4(
            *launch.boot_v1(),
            *launch.fence_v1(),
            *launch.anchor_v1(),
            launch.launch_v1(),
            dispatch,
        )?;
        let mut subject = Self::from_data_v1(
            historical, recovery, cleanup, request, boot, revision, cutoff,
        )?;
        subject.origin = HostStopCleanupOriginDataV1::DispatchedBeforeHost;
        Ok(subject)
    }

    /// Encodes the explicit origin version without changing the scope bytes.
    #[must_use]
    pub fn encode_v1(self) -> [u8; HOST_STOP_CLEANUP_SUBJECT_BYTES_V1] {
        let mut bytes = [0; HOST_STOP_CLEANUP_SUBJECT_BYTES_V1];
        bytes[..8].copy_from_slice(match self.origin {
            HostStopCleanupOriginDataV1::ProtectedPending => MAGIC,
            HostStopCleanupOriginDataV1::DispatchedBeforeHost => DISPATCH_MAGIC,
        });
        bytes[8..336].copy_from_slice(&self.historical.encode_v4());
        bytes[336..352].copy_from_slice(&self.recovery);
        bytes[352..368].copy_from_slice(&self.cleanup);
        bytes[368..400].copy_from_slice(&self.request);
        bytes[400..416].copy_from_slice(&self.boot);
        bytes[416..448].copy_from_slice(&self.revision);
        bytes[448..456].copy_from_slice(&self.cutoff.to_le_bytes());
        bytes
    }

    /// Decodes the fixed subject using the existing historical scope codec.
    ///
    /// # Errors
    /// Refuses a different grammar, trailing data or invalid fixed identities.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_STOP_CLEANUP_SUBJECT_BYTES_V1 {
            return Err(invalid());
        }
        let origin = match &bytes[..8] {
            magic if magic == MAGIC => HostStopCleanupOriginDataV1::ProtectedPending,
            magic if magic == DISPATCH_MAGIC => HostStopCleanupOriginDataV1::DispatchedBeforeHost,
            _ => return Err(invalid()),
        };
        let mut subject = Self::from_data_v1(
            HostStoppedNamespaceDataV4::decode_v4(&bytes[8..336])?,
            field(bytes, 336)?,
            field(bytes, 352)?,
            field(bytes, 368)?,
            field(bytes, 400)?,
            field(bytes, 416)?,
            u64::from_le_bytes(field(bytes, 448)?),
        )?;
        subject.origin = origin;
        Ok(subject)
    }

    /// Returns the explicitly signed closed ancestry purpose/version.
    #[must_use]
    pub const fn origin_v1(&self) -> HostStopCleanupOriginDataV1 {
        self.origin
    }

    /// Compares the new request and assignment without claiming authorization.
    ///
    /// The old scope names the Launch generation. The cleanup request retains
    /// the current Stop generation, which the protected caller must separately
    /// prove is desired-absent; this comparison never advances a generation.
    /// A zero deadline is permitted only for the signed inert template.
    ///
    /// # Errors
    /// Refuses another request/assignment, an older generation or extended D.
    pub fn require_request_data_v1(
        &self,
        request: &[u8; 16],
        fence: &ValidatedAssignmentFence,
        deadline: u64,
    ) -> Result<(), ProtocolValidationError> {
        let old = self.historical.fence_v4();
        if request != &self.cleanup
            || fence.sandbox_id() != old.sandbox_id()
            || fence.incarnation_id() != old.incarnation_id()
            || fence.assignment_epoch() != old.assignment_epoch()
            || fence.assignment_digest() != old.assignment_digest()
            || fence.desired_generation() < old.desired_generation()
            || deadline > self.cutoff
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrows the byte-exact immutable old Launch/Stop scope.
    #[must_use]
    pub const fn historical_scope_v1(&self) -> &HostStoppedNamespaceDataV4 {
        &self.historical
    }

    /// Borrows the actual fresh Recover operation, distinct from old history.
    #[must_use]
    pub const fn recovery_operation_v1(&self) -> &[u8; 16] {
        &self.recovery
    }

    /// Borrows the new Host request ID selected by the actual cleanup source.
    #[must_use]
    pub const fn cleanup_request_v1(&self) -> &[u8; 16] {
        &self.cleanup
    }

    /// Borrows the exact canonical public Recover request digest.
    #[must_use]
    pub const fn recovery_request_digest_v1(&self) -> &[u8; 32] {
        &self.request
    }

    /// Borrows the current kernel boot, independently of the historical boot.
    #[must_use]
    pub const fn current_boot_v1(&self) -> &[u8; 16] {
        &self.boot
    }

    /// Borrows the actual current Recover authorization revision digest.
    #[must_use]
    pub const fn authorization_revision_v1(&self) -> &[u8; 32] {
        &self.revision
    }

    /// Returns the immutable first Recover deadline ceiling.
    #[must_use]
    pub const fn original_cutoff_v1(&self) -> u64 {
        self.cutoff
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host Stop cleanup subject")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::{ApplyRuntimeRequest, Audience, RuntimeAction};
    use buffa::Message as _;

    fn subject() -> HostStopCleanupSubjectDataV1 {
        let fence = ValidatedAssignmentFence {
            sandbox_id: [1; 16],
            incarnation_id: [2; 16],
            assignment_epoch: 3,
            desired_generation: 4,
            assignment_digest: [5; 32],
        };
        let old = HostStoppedNamespaceDataV4::from_data_v4(
            [6; 16],
            fence,
            [7; 32],
            ([8; 16], [9; 32], [10; 32]),
            ([11; 16], [12; 32], [13; 32]),
        )
        .unwrap();
        HostStopCleanupSubjectDataV1::from_data_v1(
            old, [14; 16], [18; 16], [15; 32], [16; 16], [17; 32], 19,
        )
        .unwrap()
    }

    fn request(subject: HostStopCleanupSubjectDataV1) -> ApplyRuntimeRequest {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.request_id = subject.cleanup.to_vec();
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 18;
        header.maximum_response_bytes = 4096;
        let old = subject.historical.fence_v4();
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = old.sandbox_id().to_vec();
        fence.incarnation_id = old.incarnation_id().to_vec();
        fence.assignment_epoch = old.assignment_epoch();
        fence.desired_generation = old.desired_generation();
        fence.assignment_digest = old.assignment_digest().to_vec();
        request.action = RuntimeAction::RUNTIME_ACTION_STOP.into();
        request.host_stop_cleanup_v1 = subject.encode_v1().to_vec();
        request
    }

    fn decode(
        request: &ApplyRuntimeRequest,
    ) -> Result<crate::ValidatedRuntimeRequest, ProtocolValidationError> {
        crate::decode_canonical_host_stop_cleanup_request_v1(
            &request.encode_to_vec(),
            crate::PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(300),
            },
            crate::PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            10,
        )
    }

    #[test]
    fn subject_commitment_binds_explicit_origin_and_fresh_recovery_coordinates() {
        let original = subject();
        let decoded = HostStopCleanupSubjectDataV1::decode_v1(&original.encode_v1()).unwrap();
        assert_eq!(original.digest_data_v1(), decoded.digest_data_v1());

        let mut origin = original;
        origin.origin = HostStopCleanupOriginDataV1::DispatchedBeforeHost;
        let mut recovery = original;
        recovery.recovery = [20; 16];
        let mut cutoff = original;
        cutoff.cutoff += 1;
        for changed in [origin, recovery, cutoff] {
            let decoded = HostStopCleanupSubjectDataV1::decode_v1(&changed.encode_v1()).unwrap();
            assert_ne!(original.digest_data_v1(), decoded.digest_data_v1());
        }
    }

    #[test]
    fn fresh_cleanup_preserves_old_scope_and_has_one_exact_grammar() {
        let original = subject();
        let bytes = original.encode_v1();
        assert_eq!(&bytes[8..336], &original.historical_scope_v1().encode_v4());
        assert_ne!(
            original.current_boot_v1(),
            original.historical_scope_v1().boot_v4()
        );
        assert_eq!(
            HostStopCleanupSubjectDataV1::decode_v1(&bytes).unwrap(),
            original
        );

        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(HostStopCleanupSubjectDataV1::decode_v1(&trailing).is_err());
        let mut old = bytes;
        old[..8].copy_from_slice(b"AOSHSC00");
        assert!(HostStopCleanupSubjectDataV1::decode_v1(&old).is_err());
        let mut reused = bytes;
        reused[336..352].copy_from_slice(&original.historical_scope_v1().stop_v4().0);
        assert!(HostStopCleanupSubjectDataV1::decode_v1(&reused).is_err());
    }

    #[test]
    fn prepared_dispatch_origin_is_explicit_and_signed_semantics_cannot_alias_pending() {
        let pending = subject();
        let dispatched = HostStopCleanupSubjectDataV1::from_dispatched_data_v2(
            pending.historical.launch_scope_v1(),
            pending.historical.stop_v4(),
            pending.recovery,
            pending.cleanup,
            pending.request,
            pending.boot,
            pending.revision,
            pending.cutoff,
        )
        .unwrap();
        assert_eq!(
            pending.origin_v1(),
            HostStopCleanupOriginDataV1::ProtectedPending
        );
        assert_eq!(
            dispatched.origin_v1(),
            HostStopCleanupOriginDataV1::DispatchedBeforeHost
        );
        assert_eq!(&pending.encode_v1()[..8], b"AOSHSC01");
        assert_eq!(&dispatched.encode_v1()[..8], b"AOSHSC02");
        assert_eq!(&pending.encode_v1()[8..], &dispatched.encode_v1()[8..]);
        assert_eq!(
            HostStopCleanupSubjectDataV1::decode_v1(&dispatched.encode_v1()).unwrap(),
            dispatched
        );
        let pending_request = decode(&request(pending)).unwrap();
        let dispatched_request = decode(&request(dispatched)).unwrap();
        assert_ne!(
            crate::semantics::host::canonical_host_semantics_v1(&pending_request).unwrap(),
            crate::semantics::host::canonical_host_semantics_v1(&dispatched_request).unwrap()
        );
    }

    #[test]
    fn request_comparison_refuses_substitution_and_deadline_extension() {
        let original = subject();
        let fence = *original.historical_scope_v1().fence_v4();
        assert!(
            original
                .require_request_data_v1(original.cleanup_request_v1(), &fence, 19)
                .is_ok()
        );
        assert!(
            original
                .require_request_data_v1(original.cleanup_request_v1(), &fence, 0)
                .is_ok()
        );
        assert!(
            original
                .require_request_data_v1(original.cleanup_request_v1(), &fence, 20)
                .is_err()
        );
        assert!(
            original
                .require_request_data_v1(&[20; 16], &fence, 19)
                .is_err()
        );

        let mut foreign = fence;
        foreign.assignment_digest = [18; 32];
        assert!(
            original
                .require_request_data_v1(original.cleanup_request_v1(), &foreign, 19)
                .is_err()
        );
        foreign = fence;
        foreign.desired_generation = 3;
        assert!(
            original
                .require_request_data_v1(original.cleanup_request_v1(), &foreign, 19)
                .is_err()
        );
    }

    #[test]
    fn same_live_and_template_engine_binds_cleanup_without_reusing_ordinary_semantics() {
        let subject = subject();
        let mut wire = request(subject);
        let live = decode(&wire).unwrap();
        let live_semantics = crate::semantics::host::canonical_host_semantics_v1(&live).unwrap();
        assert_eq!(live.host_stop_cleanup_v1(), Some(&subject));
        assert!(wire.encode_to_vec().len() <= MAXIMUM_CANONICAL_HOST_STOP_CLEANUP_BODY_BYTES_V1);
        assert!(
            crate::decode_canonical_live_host_stop_envelope_data_v4(&wire.encode_to_vec()).is_err()
        );

        wire.header
            .get_or_insert_default()
            .deadline_boottime_nanoseconds = 0;
        let template = crate::decode_runtime_template_v1(&wire.encode_to_vec()).unwrap();
        assert_eq!(
            crate::semantics::host::canonical_host_template_semantics_v1(&template).unwrap(),
            live_semantics
        );

        wire.host_stop_cleanup_v1.clear();
        let ordinary = crate::decode_runtime_template_v1(&wire.encode_to_vec()).unwrap();
        assert_ne!(
            crate::semantics::host::canonical_host_template_semantics_v1(&ordinary).unwrap(),
            live_semantics
        );
    }

    #[test]
    fn canonical_subject_changes_are_committed_and_wrong_requests_are_rejected() {
        let original = subject();
        let expected = crate::semantics::host::canonical_host_semantics_v1(
            &decode(&request(original)).unwrap(),
        )
        .unwrap();
        for replacement in [
            HostStopCleanupSubjectDataV1 {
                recovery: [20; 16],
                ..original
            },
            HostStopCleanupSubjectDataV1 {
                cleanup: [21; 16],
                ..original
            },
            HostStopCleanupSubjectDataV1 {
                request: [22; 32],
                ..original
            },
            HostStopCleanupSubjectDataV1 {
                boot: [23; 16],
                ..original
            },
            HostStopCleanupSubjectDataV1 {
                revision: [24; 32],
                ..original
            },
            HostStopCleanupSubjectDataV1 {
                cutoff: 20,
                ..original
            },
        ] {
            let actual = decode(&request(replacement)).unwrap();
            assert_ne!(
                crate::semantics::host::canonical_host_semantics_v1(&actual).unwrap(),
                expected
            );
        }

        let mut wrong = request(original);
        wrong
            .header
            .get_or_insert_default()
            .deadline_boottime_nanoseconds = 20;
        assert!(decode(&wrong).is_err());
        wrong = request(original);
        wrong.header.get_or_insert_default().request_id = vec![20; 16];
        assert!(decode(&wrong).is_err());
        wrong = request(original);
        wrong.action = RuntimeAction::RUNTIME_ACTION_FREEZE.into();
        assert!(decode(&wrong).is_err());
        wrong = request(original);
        wrong.host_stop_cleanup_v1.clear();
        assert!(decode(&wrong).is_err());
        assert!(
            crate::decode_canonical_live_host_stop_cleanup_envelope_data_v1(&vec![
                0;
                MAXIMUM_CANONICAL_HOST_STOP_CLEANUP_BODY_BYTES_V1
                    + 1
            ])
            .is_err()
        );
    }
}
