//! Nonforgeable SourceRoot descriptor observation and committed custody brands.

use std::num::NonZeroU64;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox::mount_manager_startup::{
    FreshManagerSourcePresenceProjectionV1, FreshManagerSourcePresenceV1,
    FreshManagerSourceRemovalReceiptV1, LostMountSourceCustodyV1, MountManagerExecutionDeathKindV1,
    StartupManagerSourcePresenceProjectionV1, StartupManagerSourcePresenceV1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::inventory::{MountId, MountNamespace, MountObservation};
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    ManagerCustodyEvidenceV2, ManagerCustodyLossEvidenceV2, ManagerCustodyLossKindV2,
    ManagerCustodyOriginV2, RecordRefV2, SourceAcquisitionRowV2, SourceProviderQueryAttemptV2,
    SourceProviderSessionV2, manager_custody_evidence_digest_v2,
    manager_custody_loss_evidence_digest_v2,
};
use aos_sandbox_source_provider_protocol::{
    SourceRootObservationV1, source_root_descriptor_commitment_v1,
};
use rustix::fs::{FileType, OFlags};
use rustix::io::FdFlags;
use sha2::{Digest as _, Sha256};

use crate::SourceProviderSecurityError;
use crate::execution::{CurrentKernelBootV1, ProcessExecutionEvidenceV1};
use crate::handshake::CurrentRootMountSourceProviderSessionV1;

#[derive(Clone, Debug, Eq, PartialEq)]
struct DescriptorSnapshotV1 {
    boot_id: [u8; 16],
    status_flags: OFlags,
    descriptor_flags: FdFlags,
    device: u64,
    inode: u64,
    mode: u32,
    mount: MountObservation,
}

/// Owns one SourceRoot descriptor with adapter-issued kernel observation.
///
/// The descriptor and scalar observation cannot be extracted. A future AOSSPL
/// commit receipt must consume this value before PID 1 custody may receive it.
pub struct ObservedSourceRootV1 {
    descriptor: OwnedFd,
    mount_namespace: NamespaceFd,
    provider_execution: ProcessExecutionEvidenceV1,
    descriptor_commitment: ObjectDigest,
    acquisition_id: [u8; 32],
    acquisition_sequence: u64,
    lease_id: [u8; 16],
    lease_digest: ObjectDigest,
    session_binding: ObjectDigest,
    socket_cookie: NonZeroU64,
    signed_outcome_digest: ObjectDigest,
    observation: SourceRootObservationV1,
    snapshot: DescriptorSnapshotV1,
}

pub(crate) enum RetainedMountSourceRootV2 {
    Received(ObservedSourceRootV1),
    Reopened(crate::ReopenedMountSourceRootV2),
    Startup(StartupRetainedMountSourceRootV2),
}

pub(crate) struct StartupRetainedMountSourceRootV2 {
    descriptor: OwnedFd,
    presence: StartupManagerSourcePresenceProjectionV1,
    observation: SourceRootObservationV1,
    provider_acquisition_id: [u8; 32],
    provider_acquisition_sequence: u64,
    lease_id: [u8; 16],
    lease_digest: ObjectDigest,
    session_binding: ObjectDigest,
    signed_outcome_digest: ObjectDigest,
}

impl core::fmt::Debug for ObservedSourceRootV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ObservedSourceRootV1([redacted])")
    }
}

/// Owns a SourceRoot whose authenticated disposition and sequence heads committed.
///
/// This type has no public constructor or descriptor-release operation in the
/// production-inert security tranche.
pub struct CommittedSourceRootV1 {
    pub(crate) observed: ObservedSourceRootV1,
}

impl core::fmt::Debug for CommittedSourceRootV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedSourceRootV1([redacted])")
    }
}

/// Projects exact nonauthorizing SourceRoot lifecycle commitments to Mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountSourceRootCustodyProjectionV2 {
    mount_acquisition_id: Option<[u8; 32]>,
    provider_acquisition_id: [u8; 32],
    provider_acquisition_sequence: u64,
    lease_id: [u8; 16],
    lease_digest: ObjectDigest,
    session_binding: ObjectDigest,
    descriptor_commitment: ObjectDigest,
    signed_outcome_digest: ObjectDigest,
    observation: SourceRootObservationV1,
    source_realization_handle: Option<[u8; 32]>,
    lifecycle_commitment: ObjectDigest,
    manager_custody: Option<ManagerCustodyEvidenceV2>,
    manager_custody_loss: Option<ManagerCustodyLossEvidenceV2>,
}

pub(crate) enum ManagerPresenceAuthorityV2 {
    Fresh(FreshManagerSourcePresenceV1),
    Startup(StartupManagerSourcePresenceProjectionV1),
    RecoveredHistorical,
}

pub(crate) enum ReleaseCustodyV2 {
    Retained {
        observed: RetainedMountSourceRootV2,
        manager_presence: Option<ManagerPresenceAuthorityV2>,
    },
    StartupLost(LostMountSourceCustodyV1),
}

impl ReleaseCustodyV2 {
    pub(crate) fn validate_before_commit(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<(), SourceProviderSecurityError> {
        match self {
            Self::Retained {
                observed,
                manager_presence,
            } => {
                observed
                    .revalidate_retained()
                    .map_err(|error| session.poison(error))?;
                if let Some(presence) = manager_presence {
                    presence.validate_current(journal)?;
                }
                Ok(())
            }
            Self::StartupLost(loss) => loss
                .validate_current(journal)
                .map_err(|_| session.poison(SourceProviderSecurityError::SessionContinuity)),
        }
    }

    pub(crate) fn validate_after_commit(
        &self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<(), SourceProviderSecurityError> {
        match self {
            Self::Retained { observed, .. } => observed
                .revalidate_retained()
                .map_err(|error| session.poison(error)),
            Self::StartupLost(_) => Ok(()),
        }
    }
}

impl ManagerPresenceAuthorityV2 {
    pub(crate) fn validate_current(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<(), SourceProviderSecurityError> {
        match self {
            Self::Fresh(presence) => presence
                .validate_current(journal)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity),
            Self::Startup(_) => Ok(()),
            Self::RecoveredHistorical => Ok(()),
        }
    }
}

/// Retains the sole SourceRoot while Mount durably records descriptor custody.
pub struct PreparedMountSourceRootCustodyV2 {
    pub(crate) observed: RetainedMountSourceRootV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) manager_presence: Option<ManagerPresenceAuthorityV2>,
}

/// Retains an uncommitted SourceRoot and fresh manager-presence proof together.
///
/// This opaque value is the only retry input for descriptor-custody
/// preparation. Validation failure returns the same value without exposing or
/// duplicating either move-only authority.
#[must_use = "prepare descriptor custody or retain this exact retry authority"]
pub struct PendingMountSourceRootCustodyV2 {
    committed: PendingCommittedSourceRootV2,
    manager_presence: FreshManagerSourcePresenceV1,
}

enum PendingCommittedSourceRootV2 {
    Received(CommittedSourceRootV1),
    Reopened(crate::CommittedReopenedMountSourceRootV2),
}

/// Retains one startup-captured SourceRoot while its current held phase is rebound.
pub struct PreparedStartupMountSourceAdoptionV2 {
    pub(crate) observed: RetainedMountSourceRootV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) manager_presence: ManagerPresenceAuthorityV2,
    pub(crate) predecessor: RecordRefV2,
    pub(crate) effective_phase:
        aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2,
    pub(crate) descriptor_custody_digest: ObjectDigest,
    pub(crate) positive_custody_digest: Option<ObjectDigest>,
    pub(crate) cleanup_only: bool,
}

/// Retains a SourceRoot after exact DescriptorCustodied state is protected.
pub struct MountSourceRootCustodyV2 {
    pub(crate) observed: RetainedMountSourceRootV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) manager_presence: Option<ManagerPresenceAuthorityV2>,
}

/// Retains a reobserved SourceRoot while Mount durably records positive custody.
pub struct PreparedActiveMountSourceRootV2 {
    pub(crate) observed: RetainedMountSourceRootV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) manager_presence: Option<ManagerPresenceAuthorityV2>,
}

/// Retains SourceRoot custody after exact Active state is protected.
pub struct ActiveMountSourceRootV2 {
    pub(crate) observed: RetainedMountSourceRootV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) manager_presence: Option<ManagerPresenceAuthorityV2>,
}

/// Retains an Active SourceRoot while Mount commits its consumption companions.
pub struct PreparedMountSourceConsumptionV2 {
    pub(crate) observed: RetainedMountSourceRootV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) manager_presence: Option<ManagerPresenceAuthorityV2>,
}

/// Retains SourceRoot custody after an exact Consumed transition.
pub struct ConsumedMountSourceRootV2 {
    pub(crate) observed: RetainedMountSourceRootV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) manager_presence: Option<ManagerPresenceAuthorityV2>,
}

/// Retains SourceRoot custody while Mount durably fences provider Release.
pub struct PreparedMountSourceReleaseV2 {
    pub(crate) custody: ReleaseCustodyV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
}

/// Authorizes only the exact provider Release lineage retaining this SourceRoot.
pub struct MountSourceReleaseAuthorityV2 {
    pub(crate) custody: ReleaseCustodyV2,
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
}

/// Retains the sole SourceRoot while a fresh manager removal protocol runs.
pub struct RetainedMountSourceReleaseForRemovalV2 {
    observed: RetainedMountSourceRootV2,
    projection: MountSourceRootCustodyProjectionV2,
    expected_presence: FreshManagerSourcePresenceProjectionV1,
}

/// Splits fresh manager-control authority from independently retained FD custody.
#[must_use = "the retained SourceRoot and manager presence must both be completed or preserved"]
pub enum MountSourceRemovalPreparationV2 {
    /// Carries independent retained FD custody and the one-shot manager presence.
    Fresh {
        /// Retains the SourceRoot without granting use or release completion.
        retained: RetainedMountSourceReleaseForRemovalV2,
        /// Authorizes only the manager's exact removal protocol.
        presence: FreshManagerSourcePresenceV1,
    },
    /// Preserves a non-fresh recovery authority for its dedicated startup path.
    StartupRecoveryRequired(MountSourceReleaseAuthorityV2),
    /// Retains a startup loss proof that may only finish cleanup.
    StartupLost(MountSourceReleaseAuthorityV2),
}

/// Couples durably fenced SourceRoot custody with the exact reserved Release request.
pub struct CommittedMountSourceReleaseV2 {
    pub(crate) release_authority: MountSourceReleaseAuthorityV2,
    pub(crate) reserved_request: crate::ReservedMountProviderRequestV2,
}

/// Retains manager-negative SourceRoot proof until exact Released state commits.
pub struct PreparedReleasedMountSourceRootV2 {
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) negative_custody_digest: ObjectDigest,
    pub(crate) fresh_recovery: Option<PendingReleasedMountSourceRootV2>,
}

/// Retains manager-held SourceRoot, terminal provider proof, and removal receipt.
#[must_use = "prepare or retain exact negative-custody completion authority"]
pub struct PendingReleasedMountSourceRootV2 {
    retained: RetainedMountSourceReleaseForRemovalV2,
    outcome: crate::VerifiedMountProviderOutcomeV2,
    removal: FreshManagerSourceRemovalReceiptV1,
}

/// Proves this manager no longer retains the exact released SourceRoot descriptor.
pub struct ReleasedMountSourceRootV2 {
    pub(crate) projection: MountSourceRootCustodyProjectionV2,
    pub(crate) negative_custody_digest: ObjectDigest,
}

/// Restores exactly one manager-held SourceRoot custody phase after provider replacement.
pub enum RecoveredRetainedMountSourceRootV2 {
    /// Restores a row whose descriptor-custody edge committed.
    DescriptorCustodied(MountSourceRootCustodyV2),
    /// Restores a row whose positive Active observation committed.
    Active(ActiveMountSourceRootV2),
    /// Restores a row whose source-consumption companions committed.
    Consumed(ConsumedMountSourceRootV2),
    /// Restores only the exact purpose-limited provider Release authority.
    Releasing(MountSourceReleaseAuthorityV2),
    /// Retains custody only long enough to durably enter provider Release.
    CleanupOnly(PreparedMountSourceReleaseV2),
}

/// Carries the exact phase-specific SourceRoot capability sealed after a durable commit.
pub enum SourceRootPostcommitSuccessV2 {
    /// Retains a newly received Complete-Acquire root.
    Received(CommittedSourceRootV1),
    /// Retains a crash-reopened Complete-Acquire root.
    Reopened(crate::CommittedReopenedMountSourceRootV2),
    /// Retains exact DescriptorCustodied ownership.
    DescriptorCustodied(MountSourceRootCustodyV2),
    /// Retains exact Active positive custody.
    Active(ActiveMountSourceRootV2),
    /// Retains exact Consumed custody after the composite commit.
    Consumed(ConsumedMountSourceRootV2),
    /// Retains exact Releasing custody together with its reserved send authority.
    Releasing(CommittedMountSourceReleaseV2),
    /// Retains the exact phase restored by a protected startup custody rebind.
    StartupAdopted(RecoveredRetainedMountSourceRootV2),
}

/// Reports a SourceRoot postcommit seal or preserves sole custody for recovery.
#[must_use = "postcommit outcomes retain the sole SourceRoot descriptor and must be consumed"]
pub enum SourceRootPostcommitOutcomeV2 {
    /// Contains the phase-specific capability after exact durable readback.
    Success(SourceRootPostcommitSuccessV2),
    /// Retains the descriptor and exact expected durable state for resealing.
    RecoveryRequired(SourceRootPostcommitRecoveryV2),
}

/// Retains one SourceRoot and exact commit evidence after postcommit validation fails.
pub struct SourceRootPostcommitRecoveryV2 {
    error: SourceProviderSecurityError,
    payload: SourceRootPostcommitRecoveryPayloadV2,
}

pub(crate) enum SourceRootPostcommitRecoveryPayloadV2 {
    Received {
        transaction: aos_sandbox::JournalTransaction,
        outcome: crate::VerifiedMountProviderOutcomeV2,
        source_root: ObservedSourceRootV1,
    },
    Reopened {
        transaction: aos_sandbox::JournalTransaction,
        outcome: crate::VerifiedMountProviderOutcomeV2,
        source_root: crate::ReopenedMountSourceRootV2,
    },
    Lifecycle {
        transaction: aos_sandbox::JournalTransaction,
        observed: RetainedMountSourceRootV2,
        projection: MountSourceRootCustodyProjectionV2,
        manager_presence: Option<ManagerPresenceAuthorityV2>,
        expected_phase: SourceRootPostcommitPhaseV2,
    },
    Release {
        transaction: aos_sandbox::JournalTransaction,
        custody: ReleaseCustodyV2,
        projection: MountSourceRootCustodyProjectionV2,
        request: crate::PreparedMountProviderRequestV2,
    },
    Consumption {
        transaction: aos_sandbox::JournalTransaction,
        predecessor_record: Option<Vec<u8>>,
        observed: RetainedMountSourceRootV2,
        projection: MountSourceRootCustodyProjectionV2,
        manager_presence: Option<ManagerPresenceAuthorityV2>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceRootPostcommitPhaseV2 {
    DescriptorCustodied,
    Active,
    StartupAdoption {
        predecessor: RecordRefV2,
        effective_phase:
            aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2,
        descriptor_custody_digest: ObjectDigest,
        positive_custody_digest: Option<ObjectDigest>,
        cleanup_only: bool,
    },
}

/// Reports a terminal negative-custody seal or preserves its proof for recovery.
#[must_use = "negative-custody outcomes retain the sole terminal proof and must be consumed"]
pub enum NegativeCustodyPostcommitOutcomeV2 {
    /// Contains the exact Released capability after durable readback.
    Success(ReleasedMountSourceRootV2),
    /// Retains the move-only negative-custody proof for a later exact reseal.
    RecoveryRequired(NegativeCustodyPostcommitRecoveryV2),
}

/// Retains one manager-negative proof and exact expected Released state.
pub struct NegativeCustodyPostcommitRecoveryV2 {
    pub(crate) error: SourceProviderSecurityError,
    pub(crate) transaction: aos_sandbox::JournalTransaction,
    pub(crate) prepared: PreparedReleasedMountSourceRootV2,
}

impl SourceRootPostcommitRecoveryV2 {
    /// Returns the fail-closed reason while retaining sole descriptor custody.
    #[must_use]
    pub const fn error(&self) -> &SourceProviderSecurityError {
        &self.error
    }

    pub(crate) fn new(
        error: SourceProviderSecurityError,
        payload: SourceRootPostcommitRecoveryPayloadV2,
    ) -> Self {
        Self { error, payload }
    }

    pub(crate) fn into_payload(self) -> SourceRootPostcommitRecoveryPayloadV2 {
        self.payload
    }
}

impl NegativeCustodyPostcommitRecoveryV2 {
    /// Returns the fail-closed reason while retaining the terminal proof.
    #[must_use]
    pub const fn error(&self) -> &SourceProviderSecurityError {
        &self.error
    }
}

impl CommittedMountSourceReleaseV2 {
    /// Consumes the atomic transition into Release custody and send authority.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        MountSourceReleaseAuthorityV2,
        crate::ReservedMountProviderRequestV2,
    ) {
        (self.release_authority, self.reserved_request)
    }
}

/// Owns one authenticated Complete-Acquire record and its sole descriptor.
///
/// The future traffic verifier may construct this type only after decoding and
/// authenticating a canonical Complete Acquire outcome and requiring its
/// ancillary set to contain exactly one `SourceRoot` descriptor. In
/// particular, it must derive these commitments from that verified outcome;
/// it must never accept caller-shaped scalar correlation. No constructor
/// exists in this dormant tranche.
pub(crate) struct AuthenticatedCompleteAcquireRecordV1 {
    pub(crate) descriptor: OwnedFd,
    pub(crate) provider_execution: ProcessExecutionEvidenceV1,
    pub(crate) expected_observation: SourceRootObservationV1,
    pub(crate) descriptor_commitment: ObjectDigest,
    pub(crate) acquisition_id: [u8; 32],
    pub(crate) acquisition_sequence: u64,
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) session_binding: ObjectDigest,
    pub(crate) socket_cookie: NonZeroU64,
    pub(crate) signed_outcome_digest: ObjectDigest,
}

pub(super) struct SourceRootDispositionCommitReceiptV1 {
    descriptor_commitment: ObjectDigest,
    acquisition_id: [u8; 32],
    acquisition_sequence: u64,
    lease_id: [u8; 16],
    lease_digest: ObjectDigest,
    session_binding: ObjectDigest,
    socket_cookie: NonZeroU64,
    signed_outcome_digest: ObjectDigest,
}

impl ObservedSourceRootV1 {
    pub(crate) fn observe(
        record: AuthenticatedCompleteAcquireRecordV1,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        let AuthenticatedCompleteAcquireRecordV1 {
            descriptor,
            provider_execution,
            expected_observation,
            descriptor_commitment,
            acquisition_id,
            acquisition_sequence,
            lease_id,
            lease_digest,
            session_binding,
            socket_cookie,
            signed_outcome_digest,
        } = record;
        if descriptor_commitment == ObjectDigest::from_bytes([0; 32])
            || acquisition_id == [0; 32]
            || acquisition_sequence == 0
            || lease_id == [0; 16]
            || lease_digest.as_bytes() == &[0; 32]
            || signed_outcome_digest == ObjectDigest::from_bytes([0; 32])
        {
            return Err(session.poison(SourceProviderSecurityError::SessionContinuity));
        }
        session.require_complete_acquire_association(
            session_binding,
            socket_cookie,
            &provider_execution,
        )?;
        let mount_namespace = provider_execution
            .mount_namespace()
            .map_err(|error| session.poison(error))?;
        let first =
            observe_once(&descriptor, &mount_namespace).map_err(|error| session.poison(error))?;
        session.require_complete_acquire_association(
            session_binding,
            socket_cookie,
            &provider_execution,
        )?;
        provider_execution
            .require_mount_namespace(&mount_namespace)
            .map_err(|error| session.poison(error))?;
        let second =
            observe_once(&descriptor, &mount_namespace).map_err(|error| session.poison(error))?;
        session.require_complete_acquire_association(
            session_binding,
            socket_cookie,
            &provider_execution,
        )?;
        provider_execution
            .require_mount_namespace(&mount_namespace)
            .map_err(|error| session.poison(error))?;
        if first != second || first.boot_id != provider_execution.boot_id() {
            return Err(session.poison(SourceProviderSecurityError::DescriptorObservation));
        }
        let observation = SourceRootObservationV1::new(
            first.boot_id,
            first.device,
            first.inode,
            first.mount.mount_id.get(),
            true,
            true,
            true,
        )
        .map_err(|_| session.poison(SourceProviderSecurityError::DescriptorObservation))?;
        if observation != expected_observation
            || source_root_descriptor_commitment_v1(&observation) != descriptor_commitment
        {
            return Err(session.poison(SourceProviderSecurityError::DescriptorObservation));
        }
        Ok(Self {
            descriptor,
            mount_namespace,
            provider_execution,
            descriptor_commitment,
            acquisition_id,
            acquisition_sequence,
            lease_id,
            lease_digest,
            session_binding,
            socket_cookie,
            signed_outcome_digest,
            observation,
            snapshot: first,
        })
    }

    pub(crate) fn revalidate(
        &self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<(), SourceProviderSecurityError> {
        session.require_complete_acquire_association(
            self.session_binding,
            self.socket_cookie,
            &self.provider_execution,
        )?;
        self.provider_execution
            .require_mount_namespace(&self.mount_namespace)
            .map_err(|error| session.poison(error))?;
        let first = observe_once(&self.descriptor, &self.mount_namespace)
            .map_err(|error| session.poison(error))?;
        session.require_complete_acquire_association(
            self.session_binding,
            self.socket_cookie,
            &self.provider_execution,
        )?;
        self.provider_execution
            .require_mount_namespace(&self.mount_namespace)
            .map_err(|error| session.poison(error))?;
        let second = observe_once(&self.descriptor, &self.mount_namespace)
            .map_err(|error| session.poison(error))?;
        session.require_complete_acquire_association(
            self.session_binding,
            self.socket_cookie,
            &self.provider_execution,
        )?;
        self.provider_execution
            .require_mount_namespace(&self.mount_namespace)
            .map_err(|error| session.poison(error))?;
        if first == self.snapshot
            && second == self.snapshot
            && first.boot_id == self.provider_execution.boot_id()
            && source_root_descriptor_commitment_v1(&self.observation) == self.descriptor_commitment
        {
            Ok(())
        } else {
            Err(session.poison(SourceProviderSecurityError::DescriptorObservation))
        }
    }

    fn revalidate_retained(&self) -> Result<(), SourceProviderSecurityError> {
        let first = observe_once(&self.descriptor, &self.mount_namespace)?;
        let second = observe_once(&self.descriptor, &self.mount_namespace)?;
        if first == self.snapshot
            && second == self.snapshot
            && first.boot_id == self.provider_execution.boot_id()
            && source_root_descriptor_commitment_v1(&self.observation) == self.descriptor_commitment
        {
            Ok(())
        } else {
            Err(SourceProviderSecurityError::DescriptorObservation)
        }
    }

    pub(crate) const fn protocol_observation(&self) -> &SourceRootObservationV1 {
        &self.observation
    }

    pub(crate) const fn disposition_identity(
        &self,
    ) -> (
        [u8; 32],
        u64,
        [u8; 16],
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
    ) {
        (
            self.acquisition_id,
            self.acquisition_sequence,
            self.lease_id,
            self.lease_digest,
            self.session_binding,
            self.descriptor_commitment,
            self.signed_outcome_digest,
        )
    }
}

impl RetainedMountSourceRootV2 {
    pub(crate) fn revalidate_for_session(
        &self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<(), SourceProviderSecurityError> {
        match self {
            Self::Received(observed) => observed.revalidate(session),
            Self::Reopened(reopened) => {
                session.revalidate()?;
                reopened
                    .revalidate()
                    .map_err(|error| session.poison(error))?;
                session.revalidate()
            }
            Self::Startup(startup) => {
                session.revalidate()?;
                startup
                    .revalidate()
                    .map_err(|error| session.poison(error))?;
                session.revalidate()
            }
        }
    }

    pub(crate) fn revalidate_retained(&self) -> Result<(), SourceProviderSecurityError> {
        match self {
            Self::Received(observed) => observed.revalidate_retained(),
            Self::Reopened(reopened) => reopened.revalidate(),
            Self::Startup(startup) => startup.revalidate(),
        }
    }

    const fn protocol_observation(&self) -> &SourceRootObservationV1 {
        match self {
            Self::Received(observed) => observed.protocol_observation(),
            Self::Reopened(reopened) => reopened.handoff.observation(),
            Self::Startup(startup) => &startup.observation,
        }
    }

    const fn identity(
        &self,
    ) -> (
        [u8; 32],
        u64,
        [u8; 16],
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
    ) {
        match self {
            Self::Received(observed) => observed.disposition_identity(),
            Self::Reopened(reopened) => (
                *reopened.acquisition_id.as_bytes(),
                reopened.acquisition_sequence,
                reopened.lease_id,
                reopened.lease_digest,
                reopened.session_binding,
                reopened.descriptor_commitment,
                reopened.signed_outcome_digest,
            ),
            Self::Startup(startup) => (
                startup.provider_acquisition_id,
                startup.provider_acquisition_sequence,
                startup.lease_id,
                startup.lease_digest,
                startup.session_binding,
                ObjectDigest::from_bytes(startup.presence.evidence.descriptor_commitment),
                startup.signed_outcome_digest,
            ),
        }
    }
}

impl StartupRetainedMountSourceRootV2 {
    fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        let flags = rustix::fs::fcntl_getfl(&self.descriptor)
            .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
        let descriptor_flags = rustix::io::fcntl_getfd(&self.descriptor)
            .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
        let stat = rustix::fs::fstat(&self.descriptor)
            .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
        let mount_id = MountId::from_fd(self.descriptor.as_fd())
            .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
        let evidence = &self.presence.evidence;
        if !flags.contains(OFlags::PATH)
            || !descriptor_flags.contains(FdFlags::CLOEXEC)
            || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_dev != evidence.source_device
            || stat.st_ino != evidence.source_inode
            || mount_id.get() != evidence.source_unique_mount_id
            || source_root_descriptor_commitment_v1(&self.observation).as_bytes()
                != &evidence.descriptor_commitment
        {
            return Err(SourceProviderSecurityError::DescriptorObservation);
        }
        Ok(())
    }
}

impl CommittedSourceRootV1 {
    pub(super) fn mint(
        observed: ObservedSourceRootV1,
        receipt: SourceRootDispositionCommitReceiptV1,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        if !receipt.matches(&observed) {
            return Err(session.poison(SourceProviderSecurityError::SessionContinuity));
        }
        observed.revalidate(session)?;
        if !receipt.matches(&observed) {
            return Err(session.poison(SourceProviderSecurityError::SessionContinuity));
        }
        Ok(Self { observed })
    }

    /// Retains committed response custody with its manager-presence proof.
    #[must_use]
    pub fn retain_manager_presence(
        self,
        manager_presence: FreshManagerSourcePresenceV1,
    ) -> PendingMountSourceRootCustodyV2 {
        PendingMountSourceRootCustodyV2 {
            committed: PendingCommittedSourceRootV2::Received(self),
            manager_presence,
        }
    }
}

impl crate::CommittedReopenedMountSourceRootV2 {
    /// Retains reopened response custody with its manager-presence proof.
    #[must_use]
    pub fn retain_manager_presence(
        self,
        manager_presence: FreshManagerSourcePresenceV1,
    ) -> PendingMountSourceRootCustodyV2 {
        PendingMountSourceRootCustodyV2 {
            committed: PendingCommittedSourceRootV2::Reopened(self),
            manager_presence,
        }
    }
}

impl PendingMountSourceRootCustodyV2 {
    /// Prepares descriptor custody while retaining both inputs on failure.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] together with this unchanged
    /// retry authority for a sentinel or inconsistent Mount row, provider
    /// attempt, provider session, manager proof, or realization identity.
    #[must_use]
    pub fn prepare_mount_custody(
        self,
        row: &SourceAcquisitionRowV2,
        owner_attempt: &SourceProviderQueryAttemptV2,
        owner_session: &SourceProviderSessionV2,
    ) -> Result<
        PreparedMountSourceRootCustodyV2,
        (SourceProviderSecurityError, PendingMountSourceRootCustodyV2),
    > {
        let manager_custody = match fresh_manager_custody_evidence(
            row,
            owner_attempt,
            owner_session,
            &self.manager_presence,
        ) {
            Ok(custody) => custody,
            Err(error) => return Err((error, self)),
        };
        let Some(evidence) = row.evidence.as_ref() else {
            return Err((SourceProviderSecurityError::SessionContinuity, self));
        };
        let observed = match self.committed {
            PendingCommittedSourceRootV2::Received(committed) => {
                RetainedMountSourceRootV2::Received(committed.observed)
            }
            PendingCommittedSourceRootV2::Reopened(committed) => {
                RetainedMountSourceRootV2::Reopened(committed.reopened)
            }
        };
        let projection = lifecycle_projection(
            &observed,
            Some(row.acquisition_id),
            Some(evidence.source_realization_handle),
            1,
            Some(manager_custody),
        );
        Ok(PreparedMountSourceRootCustodyV2 {
            observed,
            projection,
            manager_presence: Some(ManagerPresenceAuthorityV2::Fresh(self.manager_presence)),
        })
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    /// Adopts one startup-captured SourceRoot into descriptor custody.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the move-only presence names the exact current PendingQuery row and its
    /// complete terminal Acquire/session evidence.
    pub fn prepare_startup_mount_source_custody_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        presence: StartupManagerSourcePresenceV1,
    ) -> Result<PreparedMountSourceRootCustodyV2, SourceProviderSecurityError> {
        self.revalidate()?;
        presence
            .validate_current(journal)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        journal
            .validate_mount_source_acquisition_authority()
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let graph = aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            journal
                .mount_source_acquisition_records()
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let manager = presence.custody_evidence();
        let row = graph
            .acquisitions
            .get(&manager.acquisition_id)
            .filter(|row| {
                row.revision == manager.acquisition_revision
                    && row.record_digest == manager.acquisition_record_digest
                    && row.phase
                        == aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2::PendingQuery
                    && row.manager_custody.is_none()
                    && row.manager_custody_loss.is_none()
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let owner_reference = row
            .acquire_terminal_attempt
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let owner_attempt = graph
            .provider_attempts
            .get(&owner_reference.id)
            .filter(|attempt| {
                attempt.revision == owner_reference.revision
                    && attempt.record_digest == owner_reference.record_digest
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let owner_session = graph
            .provider_sessions
            .get(&owner_attempt.session_id)
            .filter(|session| session.record_digest == owner_attempt.session_record_digest)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if manager.source_realization_handle != evidence.source_realization_handle
            || manager.descriptor_commitment != evidence.descriptor_commitment
            || manager.source_kernel_boot_id != evidence.source_kernel_boot_id
            || manager.source_device != evidence.source_device
            || manager.source_inode != evidence.source_inode
            || manager.source_unique_mount_id != evidence.source_unique_mount_id
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let signed_outcome_digest = terminal_outcome_digest(owner_attempt)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let manager_custody = startup_manager_custody_evidence(
            row,
            owner_reference,
            owner_session,
            presence.projection(),
        )?;
        let (descriptor, startup_projection) = presence.into_parts();
        let observation = SourceRootObservationV1::new(
            evidence.source_kernel_boot_id,
            evidence.source_device,
            evidence.source_inode,
            evidence.source_unique_mount_id,
            true,
            true,
            true,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::DescriptorObservation))?;
        let observed = RetainedMountSourceRootV2::Startup(StartupRetainedMountSourceRootV2 {
            descriptor,
            presence: startup_projection.clone(),
            observation,
            provider_acquisition_id: row.provider_acquisition.acquisition_id,
            provider_acquisition_sequence: row.provider_acquisition.acquisition_sequence,
            lease_id: evidence.lease_id,
            lease_digest: ObjectDigest::from_bytes(evidence.signed_lease_digest),
            session_binding: ObjectDigest::from_bytes(owner_session.session_binding),
            signed_outcome_digest,
        });
        observed
            .revalidate_retained()
            .map_err(|error| self.poison(error))?;
        let projection = lifecycle_projection(
            &observed,
            Some(row.acquisition_id),
            Some(evidence.source_realization_handle),
            1,
            Some(manager_custody),
        );
        self.revalidate()?;
        Ok(PreparedMountSourceRootCustodyV2 {
            observed,
            projection,
            manager_presence: Some(ManagerPresenceAuthorityV2::Startup(startup_projection)),
        })
    }

    /// Rebinds one startup-captured descriptor to an already held lifecycle row.
    ///
    /// The returned plan grants no authority until its exact same-phase row
    /// replacement commits through the security-owned postcommit API.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session for a
    /// stale presence, a non-held or descriptor-negative row, incomplete
    /// terminal Acquire lineage, or any physical identity mismatch.
    pub fn prepare_startup_mount_source_adoption_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        presence: StartupManagerSourcePresenceV1,
    ) -> Result<PreparedStartupMountSourceAdoptionV2, SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2;

        self.revalidate()?;
        presence
            .validate_current(journal)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        journal
            .validate_mount_source_acquisition_authority()
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let graph = aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            journal
                .mount_source_acquisition_records()
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let manager = presence.custody_evidence();
        let row = graph
            .acquisitions
            .get(&manager.acquisition_id)
            .filter(|row| {
                row.revision == manager.acquisition_revision
                    && row.record_digest == manager.acquisition_record_digest
                    && row.manager_custody.is_some()
                    && row.manager_custody_loss.is_none()
                    && row.negative_custody_digest.is_none()
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let effective_phase = if row.phase == SourceAcquisitionPhaseV2::Faulted {
            row.faulted_from
                .filter(|phase| {
                    matches!(
                        phase,
                        SourceAcquisitionPhaseV2::DescriptorCustodied
                            | SourceAcquisitionPhaseV2::Active
                            | SourceAcquisitionPhaseV2::Consumed
                            | SourceAcquisitionPhaseV2::Releasing
                    )
                })
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?
        } else {
            row.phase
        };
        if !matches!(
            effective_phase,
            SourceAcquisitionPhaseV2::DescriptorCustodied
                | SourceAcquisitionPhaseV2::Active
                | SourceAcquisitionPhaseV2::Consumed
                | SourceAcquisitionPhaseV2::Releasing
        ) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let owner_reference = row
            .acquire_terminal_attempt
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let owner_attempt = graph
            .provider_attempts
            .get(&owner_reference.id)
            .filter(|attempt| {
                attempt.revision == owner_reference.revision
                    && attempt.record_digest == owner_reference.record_digest
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let owner_session = graph
            .provider_sessions
            .get(&owner_attempt.session_id)
            .filter(|session| session.record_digest == owner_attempt.session_record_digest)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if manager.source_realization_handle != evidence.source_realization_handle
            || manager.descriptor_commitment != evidence.descriptor_commitment
            || manager.source_kernel_boot_id != evidence.source_kernel_boot_id
            || manager.source_device != evidence.source_device
            || manager.source_inode != evidence.source_inode
            || manager.source_unique_mount_id != evidence.source_unique_mount_id
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        let signed_outcome_digest = terminal_outcome_digest(owner_attempt)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let manager_custody = startup_manager_custody_evidence(
            row,
            owner_reference,
            owner_session,
            presence.projection(),
        )?;
        let (descriptor, startup_projection) = presence.into_parts();
        let observation = SourceRootObservationV1::new(
            evidence.source_kernel_boot_id,
            evidence.source_device,
            evidence.source_inode,
            evidence.source_unique_mount_id,
            true,
            true,
            true,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::DescriptorObservation))?;
        let observed = RetainedMountSourceRootV2::Startup(StartupRetainedMountSourceRootV2 {
            descriptor,
            presence: startup_projection.clone(),
            observation,
            provider_acquisition_id: row.provider_acquisition.acquisition_id,
            provider_acquisition_sequence: row.provider_acquisition.acquisition_sequence,
            lease_id: evidence.lease_id,
            lease_digest: ObjectDigest::from_bytes(evidence.signed_lease_digest),
            session_binding: ObjectDigest::from_bytes(owner_session.session_binding),
            signed_outcome_digest,
        });
        observed
            .revalidate_retained()
            .map_err(|error| self.poison(error))?;

        let descriptor_projection = lifecycle_projection(
            &observed,
            Some(row.acquisition_id),
            Some(evidence.source_realization_handle),
            1,
            Some(manager_custody),
        );
        let retained_origin = if effective_phase == SourceAcquisitionPhaseV2::Releasing {
            row.release_from_phase
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?
        } else {
            effective_phase
        };
        let positive_custody_digest = matches!(
            retained_origin,
            SourceAcquisitionPhaseV2::Active | SourceAcquisitionPhaseV2::Consumed
        )
        .then(|| {
            lifecycle_projection(
                &observed,
                Some(row.acquisition_id),
                Some(evidence.source_realization_handle),
                2,
                Some(manager_custody),
            )
            .lifecycle_commitment()
        });
        let cleanup_only = row.phase == SourceAcquisitionPhaseV2::Faulted
            || crate::handshake::current_unix_seconds().map_err(|error| self.poison(error))?
                >= evidence.lease_expires_seconds;
        let capability_stage =
            if cleanup_only || effective_phase == SourceAcquisitionPhaseV2::Releasing {
                4
            } else {
                match effective_phase {
                    SourceAcquisitionPhaseV2::DescriptorCustodied => 1,
                    SourceAcquisitionPhaseV2::Active => 2,
                    SourceAcquisitionPhaseV2::Consumed => 3,
                    _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
                }
            };
        let projection = lifecycle_projection(
            &observed,
            Some(row.acquisition_id),
            Some(evidence.source_realization_handle),
            capability_stage,
            Some(manager_custody),
        );
        self.revalidate()?;
        Ok(PreparedStartupMountSourceAdoptionV2 {
            observed,
            projection,
            manager_presence: ManagerPresenceAuthorityV2::Startup(startup_projection),
            predecessor: RecordRefV2 {
                id: row.acquisition_id,
                revision: row.revision,
                record_digest: row.record_digest,
            },
            effective_phase,
            descriptor_custody_digest: descriptor_projection.lifecycle_commitment(),
            positive_custody_digest,
            cleanup_only,
        })
    }

    /// Converts one complete startup loss proof into cleanup-only Release custody.
    ///
    /// This method derives every provider, lease, physical, and session field
    /// from the exact protected AOSMSA02 graph named by the move-only proof. It
    /// cannot mint Active/use/consumption authority and the proof is consumed.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session if the
    /// startup proof is stale, the acquisition is not its exact pre-Release
    /// subject, or its terminal Acquire/session lineage is incomplete.
    pub fn prepare_lost_mount_source_release_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        loss: LostMountSourceCustodyV1,
    ) -> Result<PreparedMountSourceReleaseV2, SourceProviderSecurityError> {
        self.revalidate()?;
        loss.validate_current(journal)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        journal
            .validate_mount_source_acquisition_authority()
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let graph = aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            journal
                .mount_source_acquisition_records()
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let subject = loss.projection().subject;
        let row = graph
            .acquisitions
            .get(&subject.acquisition_id)
            .filter(|row| {
                row.revision == subject.acquisition_revision
                    && row.record_digest == subject.acquisition_record_digest
                    && row.release.is_none()
                    && row.manager_custody_loss.is_none()
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let terminal = row
            .acquire_terminal_attempt
            .filter(|reference| {
                reference.id == subject.acquire_attempt_id
                    && reference.revision == subject.acquire_attempt_revision
                    && reference.record_digest == subject.acquire_attempt_record_digest
            })
            .and_then(|reference| graph.provider_attempts.get(&reference.id))
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let owner_session = graph
            .provider_sessions
            .get(&terminal.session_id)
            .filter(|stored| stored.record_digest == terminal.session_record_digest)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let signed_outcome_digest = match &terminal.state {
            aos_sandbox_protocol::mount_source_acquisition_state::ProviderAttemptStateV2::DispositionConsumed {
                signed_status_digest,
                signed_result_digest,
                ..
            } => {
                let mut hasher = Sha256::new();
                hasher.update(b"aos.sandbox.mount.source-root-signed-outcome.v2\0");
                hasher.update(signed_status_digest);
                hasher.update(signed_result_digest);
                ObjectDigest::from_bytes(hasher.finalize().into())
            }
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let manager_custody_loss = manager_custody_loss_evidence(loss.projection());
        let observation = SourceRootObservationV1::new(
            evidence.source_kernel_boot_id,
            evidence.source_device,
            evidence.source_inode,
            evidence.source_unique_mount_id,
            true,
            true,
            true,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let projection = lost_release_projection(
            row,
            evidence,
            owner_session,
            observation,
            signed_outcome_digest,
            manager_custody_loss,
        );
        self.revalidate()?;
        Ok(PreparedMountSourceReleaseV2 {
            custody: ReleaseCustodyV2::StartupLost(loss),
            projection,
        })
    }
}

impl MountSourceRootCustodyProjectionV2 {
    /// Returns the Mount row identity after the first protected lifecycle commit.
    #[must_use]
    pub const fn mount_acquisition_id(&self) -> Option<[u8; 32]> {
        self.mount_acquisition_id
    }

    /// Returns the provider acquisition identity and holder-wide sequence.
    #[must_use]
    pub const fn provider_acquisition(&self) -> ([u8; 32], u64) {
        (
            self.provider_acquisition_id,
            self.provider_acquisition_sequence,
        )
    }

    /// Returns the exact provider lease identity.
    #[must_use]
    pub const fn lease(&self) -> ([u8; 16], ObjectDigest) {
        (self.lease_id, self.lease_digest)
    }

    /// Returns the provider session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the exact physical descriptor commitment.
    #[must_use]
    pub const fn descriptor_commitment(&self) -> ObjectDigest {
        self.descriptor_commitment
    }

    /// Returns the exact signed provider-outcome commitment.
    #[must_use]
    pub const fn signed_outcome_digest(&self) -> ObjectDigest {
        self.signed_outcome_digest
    }

    /// Borrows the immutable physical SourceRoot observation.
    #[must_use]
    pub const fn observation(&self) -> &SourceRootObservationV1 {
        &self.observation
    }

    /// Returns the provider realization identity after Mount binds its row.
    #[must_use]
    pub const fn source_realization_handle(&self) -> Option<[u8; 32]> {
        self.source_realization_handle
    }

    /// Returns the security-derived commitment for the requested lifecycle edge.
    #[must_use]
    pub const fn lifecycle_commitment(&self) -> ObjectDigest {
        self.lifecycle_commitment
    }

    /// Returns the exact compact manager-custody evidence Mount must persist.
    #[must_use]
    pub const fn manager_custody(&self) -> Option<ManagerCustodyEvidenceV2> {
        self.manager_custody
    }

    /// Returns startup loss evidence only for a cleanup-only Release plan.
    #[must_use]
    pub const fn manager_custody_loss(&self) -> Option<ManagerCustodyLossEvidenceV2> {
        self.manager_custody_loss
    }

    pub(crate) fn bind_mount_row(
        &self,
        mount_acquisition_id: [u8; 32],
        source_realization_handle: [u8; 32],
    ) -> Self {
        let mut projection = self.clone();
        projection.mount_acquisition_id = Some(mount_acquisition_id);
        projection.source_realization_handle = Some(source_realization_handle);
        projection
    }
}

impl PreparedMountSourceRootCustodyV2 {
    /// Borrows the exact descriptor-custody projection Mount must persist.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }
}

impl PreparedStartupMountSourceAdoptionV2 {
    /// Borrows the exact startup-rebound custody projection.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Returns the exact current row consumed by the same-phase replacement.
    #[must_use]
    pub const fn predecessor(&self) -> RecordRefV2 {
        self.predecessor
    }

    /// Returns the effective held phase, including a Faulted row's origin.
    #[must_use]
    pub const fn effective_phase(
        &self,
    ) -> aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2 {
        self.effective_phase
    }

    /// Returns the replacement descriptor and positive custody commitments.
    #[must_use]
    pub const fn custody_commitments(&self) -> (ObjectDigest, Option<ObjectDigest>) {
        (self.descriptor_custody_digest, self.positive_custody_digest)
    }
}

impl MountSourceRootCustodyV2 {
    /// Borrows the exact committed descriptor-custody projection.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Reobserves the SourceRoot and prepares the exact Active commitment.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// descriptor, execution, namespace, session, or custody facts drift.
    pub fn prepare_active(
        self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<PreparedActiveMountSourceRootV2, SourceProviderSecurityError> {
        session.revalidate()?;
        self.observed
            .revalidate_retained()
            .map_err(|error| session.poison(error))?;
        session.revalidate()?;
        let projection = next_lifecycle_projection(&self.observed, &self.projection, 2);
        Ok(PreparedActiveMountSourceRootV2 {
            observed: self.observed,
            projection,
            manager_presence: self.manager_presence,
        })
    }

    /// Consumes descriptor custody into an exact provider-Release plan.
    #[must_use]
    pub fn prepare_release(self) -> PreparedMountSourceReleaseV2 {
        let projection = next_lifecycle_projection(&self.observed, &self.projection, 4);
        PreparedMountSourceReleaseV2 {
            custody: ReleaseCustodyV2::Retained {
                observed: self.observed,
                manager_presence: self.manager_presence,
            },
            projection,
        }
    }
}

impl PreparedActiveMountSourceRootV2 {
    /// Borrows the exact positive-custody projection Mount must persist.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }
}

impl ActiveMountSourceRootV2 {
    /// Borrows the exact committed Active projection.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Consumes Active custody into an exact source-consumption plan.
    #[must_use]
    pub fn prepare_consumption(self) -> PreparedMountSourceConsumptionV2 {
        let projection = next_lifecycle_projection(&self.observed, &self.projection, 3);
        PreparedMountSourceConsumptionV2 {
            observed: self.observed,
            projection,
            manager_presence: self.manager_presence,
        }
    }

    /// Consumes Active custody into an exact provider-Release plan.
    #[must_use]
    pub fn prepare_release(self) -> PreparedMountSourceReleaseV2 {
        let projection = next_lifecycle_projection(&self.observed, &self.projection, 4);
        PreparedMountSourceReleaseV2 {
            custody: ReleaseCustodyV2::Retained {
                observed: self.observed,
                manager_presence: self.manager_presence,
            },
            projection,
        }
    }
}

impl PreparedMountSourceConsumptionV2 {
    /// Borrows the exact consumption projection Mount must persist atomically.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }
}

impl ConsumedMountSourceRootV2 {
    /// Borrows the exact committed consumption projection.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Consumes retained custody into a post-teardown provider-Release plan.
    #[must_use]
    pub fn prepare_release(self) -> PreparedMountSourceReleaseV2 {
        let projection = next_lifecycle_projection(&self.observed, &self.projection, 4);
        PreparedMountSourceReleaseV2 {
            custody: ReleaseCustodyV2::Retained {
                observed: self.observed,
                manager_presence: self.manager_presence,
            },
            projection,
        }
    }
}

impl PreparedMountSourceReleaseV2 {
    /// Borrows the exact release-custody projection Mount must persist.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }
}

impl MountSourceReleaseAuthorityV2 {
    /// Borrows the exact protected Release authority projection.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Separates manager removal authority while independently retaining the FD.
    ///
    /// Manager protocol failure cannot drop the SourceRoot because the returned
    /// retained value never enters that fallible protocol. Startup-recovered
    /// custody remains intact for its separate startup absence path.
    #[must_use]
    pub fn prepare_manager_removal(self) -> MountSourceRemovalPreparationV2 {
        match self.custody {
            ReleaseCustodyV2::Retained {
                observed,
                manager_presence: Some(ManagerPresenceAuthorityV2::Fresh(presence)),
            } => {
                let expected_presence = presence.projection().clone();
                MountSourceRemovalPreparationV2::Fresh {
                    retained: RetainedMountSourceReleaseForRemovalV2 {
                        observed,
                        projection: self.projection,
                        expected_presence,
                    },
                    presence,
                }
            }
            ReleaseCustodyV2::Retained {
                observed,
                manager_presence,
            } => MountSourceRemovalPreparationV2::StartupRecoveryRequired(
                MountSourceReleaseAuthorityV2 {
                    custody: ReleaseCustodyV2::Retained {
                        observed,
                        manager_presence,
                    },
                    projection: self.projection,
                },
            ),
            ReleaseCustodyV2::StartupLost(loss) => {
                MountSourceRemovalPreparationV2::StartupLost(MountSourceReleaseAuthorityV2 {
                    custody: ReleaseCustodyV2::StartupLost(loss),
                    projection: self.projection,
                })
            }
        }
    }

    /// Converts startup-proven absence plus terminal provider proof into negative custody.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] if this is retained FD custody,
    /// the provider proof names another acquisition, or the loss proof is no
    /// longer current.
    pub fn prepare_lost_negative_custody(
        self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        outcome: crate::VerifiedMountProviderOutcomeV2,
    ) -> Result<PreparedReleasedMountSourceRootV2, SourceProviderSecurityError> {
        let ReleaseCustodyV2::StartupLost(loss) = self.custody else {
            return Err(session.poison(SourceProviderSecurityError::SessionContinuity));
        };
        session.revalidate()?;
        loss.validate_current(journal)
            .map_err(|_| session.poison(SourceProviderSecurityError::SessionContinuity))?;
        let (acquisition_id, acquisition_sequence) = self.projection.provider_acquisition();
        let (lease_id, lease_digest) = self.projection.lease();
        if !outcome.authorizes_negative_custody(
            ObjectDigest::from_bytes(acquisition_id),
            acquisition_sequence,
            lease_id,
            lease_digest,
        ) {
            return Err(session.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.mount.source-root-lost-negative-custody.v2\0");
        hasher.update(self.projection.lifecycle_commitment().as_bytes());
        hasher.update(outcome.commitments().0.as_bytes());
        hasher.update(outcome.response_identity().1.to_be_bytes());
        hasher.update(loss.projection().death_commitment);
        let negative_custody_digest = ObjectDigest::from_bytes(hasher.finalize().into());
        Ok(PreparedReleasedMountSourceRootV2 {
            projection: self.projection,
            negative_custody_digest,
            fresh_recovery: None,
        })
    }
}

impl RetainedMountSourceReleaseForRemovalV2 {
    /// Borrows the exact provider Release lineage retained during manager removal.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Retains the exact terminal and removal proofs before negative custody.
    #[must_use]
    pub fn retain_negative_custody(
        self,
        outcome: crate::VerifiedMountProviderOutcomeV2,
        removal: FreshManagerSourceRemovalReceiptV1,
    ) -> PendingReleasedMountSourceRootV2 {
        PendingReleasedMountSourceRootV2 {
            retained: self,
            outcome,
            removal,
        }
    }
}

impl PendingReleasedMountSourceRootV2 {
    /// Borrows the exact Release lineage retained for manager removal.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.retained.projection
    }

    /// Validates negative custody while returning exact inputs on failure.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session if the
    /// terminal Release or Inventory proof names another acquisition or lease,
    /// or if the physical descriptor changed before close.
    pub fn prepare_negative_custody(
        self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<
        PreparedReleasedMountSourceRootV2,
        (
            SourceProviderSecurityError,
            PendingReleasedMountSourceRootV2,
        ),
    > {
        if let Err(error) = session.revalidate() {
            return Err((error, self));
        }
        if self.removal.validate_current(journal).is_err() {
            return Err((
                session.poison(SourceProviderSecurityError::SessionContinuity),
                self,
            ));
        }
        if self.removal.projection().prior_presence != self.retained.expected_presence {
            return Err((
                session.poison(SourceProviderSecurityError::SessionContinuity),
                self,
            ));
        }
        if let Err(error) = self.retained.observed.revalidate_retained() {
            return Err((session.poison(error), self));
        }
        if let Err(error) = session.revalidate() {
            return Err((error, self));
        }
        let (acquisition_id, acquisition_sequence) =
            self.retained.projection.provider_acquisition();
        let (lease_id, lease_digest) = self.retained.projection.lease();
        if !self.outcome.authorizes_negative_custody(
            ObjectDigest::from_bytes(acquisition_id),
            acquisition_sequence,
            lease_id,
            lease_digest,
        ) {
            return Err((
                session.poison(SourceProviderSecurityError::SessionContinuity),
                self,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.mount.source-root-negative-custody.v2\0");
        hasher.update(self.retained.projection.lifecycle_commitment().as_bytes());
        hasher.update(self.outcome.commitments().0.as_bytes());
        hasher.update(self.outcome.response_identity().1.to_be_bytes());
        hasher.update(self.removal.projection().removal_commitment);
        let negative_custody_digest = ObjectDigest::from_bytes(hasher.finalize().into());
        let projection = self.retained.projection.clone();
        Ok(PreparedReleasedMountSourceRootV2 {
            projection,
            negative_custody_digest,
            fresh_recovery: Some(self),
        })
    }
}

impl PreparedReleasedMountSourceRootV2 {
    /// Borrows the exact release lineage whose manager custody was closed.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Returns the security-computed manager-negative custody commitment.
    #[must_use]
    pub const fn negative_custody_digest(&self) -> ObjectDigest {
        self.negative_custody_digest
    }
}

impl ReleasedMountSourceRootV2 {
    /// Borrows the terminal SourceRoot lineage projection.
    #[must_use]
    pub const fn projection(&self) -> &MountSourceRootCustodyProjectionV2 {
        &self.projection
    }

    /// Returns the committed manager-negative custody digest.
    #[must_use]
    pub const fn negative_custody_digest(&self) -> ObjectDigest {
        self.negative_custody_digest
    }
}

pub(crate) fn lifecycle_projection(
    observed: &RetainedMountSourceRootV2,
    mount_acquisition_id: Option<[u8; 32]>,
    source_realization_handle: Option<[u8; 32]>,
    stage: u8,
    manager_custody: Option<ManagerCustodyEvidenceV2>,
) -> MountSourceRootCustodyProjectionV2 {
    let observation = observed.protocol_observation().clone();
    let (
        provider_acquisition_id,
        provider_acquisition_sequence,
        lease_id,
        lease_digest,
        session_binding,
        descriptor_commitment,
        signed_outcome_digest,
    ) = observed.identity();
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount.source-root-lifecycle.v2\0");
    hasher.update([stage]);
    hasher.update([0; 7]);
    hasher.update(mount_acquisition_id.unwrap_or([0; 32]));
    hasher.update(source_realization_handle.unwrap_or([0; 32]));
    hasher.update(provider_acquisition_id);
    hasher.update(provider_acquisition_sequence.to_be_bytes());
    hasher.update(lease_id);
    hasher.update(lease_digest.as_bytes());
    hasher.update(session_binding.as_bytes());
    hasher.update(descriptor_commitment.as_bytes());
    hasher.update(signed_outcome_digest.as_bytes());
    hasher.update(observation.kernel_boot_id());
    hasher.update(observation.device().to_be_bytes());
    hasher.update(observation.inode().to_be_bytes());
    hasher.update(observation.unique_mount_id().to_be_bytes());
    hasher.update(manager_custody.map_or([0; 32], |custody| custody.evidence_digest));
    MountSourceRootCustodyProjectionV2 {
        mount_acquisition_id,
        provider_acquisition_id,
        provider_acquisition_sequence,
        lease_id,
        lease_digest,
        session_binding,
        descriptor_commitment,
        signed_outcome_digest,
        observation,
        source_realization_handle,
        lifecycle_commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
        manager_custody,
        manager_custody_loss: None,
    }
}

fn fresh_manager_custody_evidence(
    row: &SourceAcquisitionRowV2,
    owner_attempt: &SourceProviderQueryAttemptV2,
    owner_session: &SourceProviderSessionV2,
    presence: &FreshManagerSourcePresenceV1,
) -> Result<ManagerCustodyEvidenceV2, SourceProviderSecurityError> {
    let source = row
        .evidence
        .as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let owner_reference = row
        .acquire_terminal_attempt
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let manager = presence.custody_evidence();
    let fresh = presence.projection();
    if row.phase
        != aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2::PendingQuery
        || row.manager_custody.is_some()
        || owner_reference.id != owner_attempt.attempt_id
        || owner_reference.revision != owner_attempt.revision
        || owner_reference.record_digest != owner_attempt.record_digest
        || owner_attempt.session_id != owner_session.session_id
        || owner_attempt.session_record_digest != owner_session.record_digest
        || owner_attempt.scope != row.scope
        || manager.origin
            != aos_sandbox::mount_manager_startup::ManagerSourcePresenceOriginV1::FreshControlReadback
        || manager.acquisition_id != row.acquisition_id
        || manager.acquisition_revision != row.revision
        || manager.acquisition_record_digest != row.record_digest
        || manager.source_realization_handle != source.source_realization_handle
        || manager.descriptor_commitment != source.descriptor_commitment
        || manager.source_kernel_boot_id != source.source_kernel_boot_id
        || manager.source_device != source.source_device
        || manager.source_inode != source.source_inode
        || manager.source_unique_mount_id != source.source_unique_mount_id
        || manager.manager_execution_commitment == [0; 32]
        || fresh.presence_commitment == [0; 32]
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    let mut evidence = ManagerCustodyEvidenceV2 {
        origin: ManagerCustodyOriginV2::FreshControlReadback,
        admission_predecessor: RecordRefV2 {
            id: row.acquisition_id,
            revision: row.revision,
            record_digest: row.record_digest,
        },
        owner_attempt: owner_reference,
        owner_session_id: owner_session.session_id,
        owner_session_record_digest: owner_session.record_digest,
        manager_kernel_boot_id: manager.manager_execution.kernel_boot_id,
        manager_execution_commitment: manager.manager_execution_commitment,
        capture_sequence: manager.capture_sequence,
        capture_id: manager.capture_id,
        capture_record_digest: manager.capture_record_digest,
        descriptor_count: manager.descriptor_count,
        activation_count: manager.activation_count,
        expected_descriptor_count: manager.expected_descriptor_count,
        source_subject_count: manager.source_subject_count,
        cleanup_subject_count: manager.cleanup_subject_count,
        terminal_subject_count: manager.terminal_subject_count,
        source_entry_commitment: manager.source_entry_commitment,
        presence_commitment: fresh.presence_commitment,
        evidence_digest: [0; 32],
    };
    evidence.evidence_digest = manager_custody_evidence_digest_v2(&evidence);
    Ok(evidence)
}

fn terminal_outcome_digest(attempt: &SourceProviderQueryAttemptV2) -> Option<ObjectDigest> {
    if attempt.method
        != aos_sandbox_protocol::mount_source_acquisition_state::ProviderMethodV2::Acquire
    {
        return None;
    }
    let aos_sandbox_protocol::mount_source_acquisition_state::ProviderAttemptStateV2::DispositionConsumed {
        status,
        signed_status_digest,
        signed_result_digest,
        ..
    } = &attempt.state
    else {
        return None;
    };
    if *status != aos_sandbox_protocol::mount_source_acquisition_state::ProviderStatusV2::Complete {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount.source-root-signed-outcome.v2\0");
    hasher.update(signed_status_digest);
    hasher.update(signed_result_digest);
    Some(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn startup_manager_custody_evidence(
    row: &SourceAcquisitionRowV2,
    owner_reference: RecordRefV2,
    owner_session: &SourceProviderSessionV2,
    startup: &StartupManagerSourcePresenceProjectionV1,
) -> Result<ManagerCustodyEvidenceV2, SourceProviderSecurityError> {
    let manager = &startup.evidence;
    let expected = &startup.expected;
    if manager.origin
        != aos_sandbox::mount_manager_startup::ManagerSourcePresenceOriginV1::StartupCapture
        || manager.acquisition_id != row.acquisition_id
        || manager.acquisition_revision != row.revision
        || manager.acquisition_record_digest != row.record_digest
        || expected.role
            != aos_sandbox_protocol::mount_manager_startup::StartupDescriptorRoleV1::SourceRoot
        || expected.presence
            != aos_sandbox_protocol::mount_manager_startup::StartupDescriptorPresenceV1::Required
        || expected.logical_identity != manager.source_realization_handle
        || expected.kernel_boot_id != Some(manager.source_kernel_boot_id)
        || expected.device != Some(manager.source_device)
        || expected.inode != Some(manager.source_inode)
        || expected.unique_mount_id != Some(manager.source_unique_mount_id)
        || expected.descriptor_commitment != Some(manager.descriptor_commitment)
        || expected.source_acquisition_id != Some(row.acquisition_id)
        || expected.source_acquisition_revision != Some(row.revision)
        || expected.source_acquisition_record_digest != Some(row.record_digest)
        || manager.manager_execution_commitment == [0; 32]
        || manager.capture_sequence == 0
        || manager.capture_id == [0; 32]
        || manager.capture_record_digest == [0; 32]
        || manager.source_entry_commitment == [0; 32]
        || startup.expected_entry_digest == [0; 32]
        || startup.descriptor_physical_commitment == [0; 32]
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    let mut presence_hasher = Sha256::new();
    presence_hasher.update(b"aos.sandbox.mount-manager.startup-custody-presence.v2\0");
    presence_hasher.update(manager.capture_id);
    presence_hasher.update(manager.capture_record_digest);
    presence_hasher.update(startup.expected_entry_digest);
    presence_hasher.update(startup.descriptor_physical_commitment);
    presence_hasher.update(manager.source_entry_commitment);
    let presence_commitment = presence_hasher.finalize().into();

    let mut evidence = ManagerCustodyEvidenceV2 {
        origin: ManagerCustodyOriginV2::StartupCapture,
        admission_predecessor: RecordRefV2 {
            id: row.acquisition_id,
            revision: row.revision,
            record_digest: row.record_digest,
        },
        owner_attempt: owner_reference,
        owner_session_id: owner_session.session_id,
        owner_session_record_digest: owner_session.record_digest,
        manager_kernel_boot_id: manager.manager_execution.kernel_boot_id,
        manager_execution_commitment: manager.manager_execution_commitment,
        capture_sequence: manager.capture_sequence,
        capture_id: manager.capture_id,
        capture_record_digest: manager.capture_record_digest,
        descriptor_count: manager.descriptor_count,
        activation_count: manager.activation_count,
        expected_descriptor_count: manager.expected_descriptor_count,
        source_subject_count: manager.source_subject_count,
        cleanup_subject_count: manager.cleanup_subject_count,
        terminal_subject_count: manager.terminal_subject_count,
        source_entry_commitment: manager.source_entry_commitment,
        presence_commitment,
        evidence_digest: [0; 32],
    };
    evidence.evidence_digest = manager_custody_evidence_digest_v2(&evidence);
    Ok(evidence)
}

fn manager_custody_loss_evidence(
    projection: &aos_sandbox::mount_manager_startup::LostMountSourceCustodyProjectionV1,
) -> ManagerCustodyLossEvidenceV2 {
    let kind = match projection.death_kind {
        None => ManagerCustodyLossKindV2::NoPriorCustody,
        Some(MountManagerExecutionDeathKindV1::BootReplaced) => {
            ManagerCustodyLossKindV2::BootReplaced
        }
        Some(MountManagerExecutionDeathKindV1::PidfdExited) => {
            ManagerCustodyLossKindV2::PidfdExited
        }
        Some(MountManagerExecutionDeathKindV1::ProcessReplaced) => {
            ManagerCustodyLossKindV2::ProcessReplaced
        }
    };
    let mut evidence = ManagerCustodyLossEvidenceV2 {
        subject: projection.subject,
        capture_id: projection.capture_id,
        capture_record_digest: projection.capture_record_digest,
        kind,
        death_commitment: projection.death_commitment,
        evidence_digest: [0; 32],
    };
    evidence.evidence_digest = manager_custody_loss_evidence_digest_v2(&evidence);
    evidence
}

fn lost_release_projection(
    row: &SourceAcquisitionRowV2,
    evidence: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionEvidenceV2,
    owner_session: &SourceProviderSessionV2,
    observation: SourceRootObservationV1,
    signed_outcome_digest: ObjectDigest,
    manager_custody_loss: ManagerCustodyLossEvidenceV2,
) -> MountSourceRootCustodyProjectionV2 {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount.source-root-lifecycle.v2\0");
    hasher.update([4]);
    hasher.update([0; 7]);
    hasher.update(row.acquisition_id);
    hasher.update(evidence.source_realization_handle);
    hasher.update(row.provider_acquisition.acquisition_id);
    hasher.update(row.provider_acquisition.acquisition_sequence.to_be_bytes());
    hasher.update(evidence.lease_id);
    hasher.update(evidence.signed_lease_digest);
    hasher.update(owner_session.session_binding);
    hasher.update(evidence.descriptor_commitment);
    hasher.update(signed_outcome_digest.as_bytes());
    hasher.update(observation.kernel_boot_id());
    hasher.update(observation.device().to_be_bytes());
    hasher.update(observation.inode().to_be_bytes());
    hasher.update(observation.unique_mount_id().to_be_bytes());
    hasher.update(
        row.manager_custody
            .map_or([0; 32], |custody| custody.evidence_digest),
    );
    hasher.update(manager_custody_loss.evidence_digest);
    MountSourceRootCustodyProjectionV2 {
        mount_acquisition_id: Some(row.acquisition_id),
        provider_acquisition_id: row.provider_acquisition.acquisition_id,
        provider_acquisition_sequence: row.provider_acquisition.acquisition_sequence,
        lease_id: evidence.lease_id,
        lease_digest: ObjectDigest::from_bytes(evidence.signed_lease_digest),
        session_binding: ObjectDigest::from_bytes(owner_session.session_binding),
        descriptor_commitment: ObjectDigest::from_bytes(evidence.descriptor_commitment),
        signed_outcome_digest,
        observation,
        source_realization_handle: Some(evidence.source_realization_handle),
        lifecycle_commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
        manager_custody: row.manager_custody,
        manager_custody_loss: Some(manager_custody_loss),
    }
}

/// Reconstructs one retained lifecycle commitment without minting custody.
///
/// This is used only after a complete startup inventory has proven the exact
/// durable graph. It contains no descriptor and cannot be converted into
/// Active or Consumed authority.
pub(crate) fn durable_lifecycle_projection(
    row: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
    session_binding: ObjectDigest,
    signed_outcome_digest: ObjectDigest,
    stage: u8,
) -> Result<MountSourceRootCustodyProjectionV2, SourceProviderSecurityError> {
    if !(1..=4).contains(&stage) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let evidence = row
        .evidence
        .as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let manager_custody = row
        .manager_custody
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let observation = SourceRootObservationV1::new(
        evidence.source_kernel_boot_id,
        evidence.source_device,
        evidence.source_inode,
        evidence.source_unique_mount_id,
        true,
        true,
        true,
    )
    .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
    let descriptor_commitment = source_root_descriptor_commitment_v1(&observation);
    if descriptor_commitment.as_bytes() != &evidence.descriptor_commitment {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount.source-root-lifecycle.v2\0");
    hasher.update([stage]);
    hasher.update([0; 7]);
    hasher.update(row.acquisition_id);
    hasher.update(evidence.source_realization_handle);
    hasher.update(row.provider_acquisition.acquisition_id);
    hasher.update(row.provider_acquisition.acquisition_sequence.to_be_bytes());
    hasher.update(evidence.lease_id);
    hasher.update(evidence.signed_lease_digest);
    hasher.update(session_binding.as_bytes());
    hasher.update(descriptor_commitment.as_bytes());
    hasher.update(signed_outcome_digest.as_bytes());
    hasher.update(observation.kernel_boot_id());
    hasher.update(observation.device().to_be_bytes());
    hasher.update(observation.inode().to_be_bytes());
    hasher.update(observation.unique_mount_id().to_be_bytes());
    hasher.update(manager_custody.evidence_digest);
    Ok(MountSourceRootCustodyProjectionV2 {
        mount_acquisition_id: Some(row.acquisition_id),
        provider_acquisition_id: row.provider_acquisition.acquisition_id,
        provider_acquisition_sequence: row.provider_acquisition.acquisition_sequence,
        lease_id: evidence.lease_id,
        lease_digest: ObjectDigest::from_bytes(evidence.signed_lease_digest),
        session_binding,
        descriptor_commitment,
        signed_outcome_digest,
        observation,
        source_realization_handle: Some(evidence.source_realization_handle),
        lifecycle_commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
        manager_custody: Some(manager_custody),
        manager_custody_loss: None,
    })
}

fn next_lifecycle_projection(
    observed: &RetainedMountSourceRootV2,
    current: &MountSourceRootCustodyProjectionV2,
    stage: u8,
) -> MountSourceRootCustodyProjectionV2 {
    let projection = lifecycle_projection(
        observed,
        current.mount_acquisition_id,
        current.source_realization_handle,
        stage,
        current.manager_custody,
    );
    match (
        current.mount_acquisition_id,
        current.source_realization_handle,
    ) {
        (Some(acquisition_id), Some(realization)) => {
            projection.bind_mount_row(acquisition_id, realization)
        }
        _ => projection,
    }
}

impl SourceRootDispositionCommitReceiptV1 {
    pub(crate) const fn from_observed(observed: &ObservedSourceRootV1) -> Self {
        Self {
            descriptor_commitment: observed.descriptor_commitment,
            acquisition_id: observed.acquisition_id,
            acquisition_sequence: observed.acquisition_sequence,
            lease_id: observed.lease_id,
            lease_digest: observed.lease_digest,
            session_binding: observed.session_binding,
            socket_cookie: observed.socket_cookie,
            signed_outcome_digest: observed.signed_outcome_digest,
        }
    }

    pub(crate) fn matches(&self, observed: &ObservedSourceRootV1) -> bool {
        self.descriptor_commitment == observed.descriptor_commitment
            && self.acquisition_id == observed.acquisition_id
            && self.acquisition_sequence == observed.acquisition_sequence
            && self.lease_id == observed.lease_id
            && self.lease_digest == observed.lease_digest
            && self.session_binding == observed.session_binding
            && self.socket_cookie == observed.socket_cookie
            && self.signed_outcome_digest == observed.signed_outcome_digest
    }
}

fn observe_once(
    descriptor: &OwnedFd,
    mount_namespace: &NamespaceFd,
) -> Result<DescriptorSnapshotV1, SourceProviderSecurityError> {
    let boot = CurrentKernelBootV1::capture()?;
    let status_flags = rustix::fs::fcntl_getfl(descriptor)
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
    let mount_id = MountId::from_fd(descriptor.as_fd())
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
    let mount = MountNamespace::pinned(mount_namespace)
        .and_then(|namespace| namespace.observe(mount_id))
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
    if !status_flags.contains(OFlags::PATH)
        || !descriptor_flags.contains(FdFlags::CLOEXEC)
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_dev == 0
        || stat.st_ino == 0
        || mount.mount_id != mount_id
        || mount.device_major != rustix::fs::major(stat.st_dev)
        || mount.device_minor != rustix::fs::minor(stat.st_dev)
        || !mount.is_read_only()
    {
        return Err(SourceProviderSecurityError::DescriptorObservation);
    }
    boot.revalidate()?;
    Ok(DescriptorSnapshotV1 {
        boot_id: boot.boot_id(),
        status_flags,
        descriptor_flags,
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        mount,
    })
}
