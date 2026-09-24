//! Sealed backend observation and execution boundary.
//!
//! The durable ledger never serializes or reconstructs live descriptors. A
//! backend can execute only by consuming a permit issued after the reservation
//! transaction synchronizes. Completion consumes a sealed observation.

use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox::ProtectedJournalSnapshot;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderProofV1, SourceResourceV1, SourceRootObservationV1,
    source_root_descriptor_commitment_v1,
};
use rustix::fs::{FileType, OFlags};
use rustix::io::FdFlags;
use sha2::{Digest as _, Sha256};

pub use crate::ledger::evidence::{
    BackendEvidenceClassV1, BackendEvidenceStateV1, BackendEvidenceV1, LocalLiveEvidenceBindingV1,
};
pub use crate::ledger::reopen::ReopenIdentityV1;

use crate::model::SourceRootIdentityV1;

/// Owns a descriptor after repeated kernel-backed physical validation.
///
/// The private fields prevent adapters from pairing arbitrary scalar claims
/// with a descriptor. It remains nonauthorizing until the runtime matches its
/// plan binding, persistent evidence, and reopen identity.
pub struct ProviderPhysicalSourceRootV1 {
    descriptor: OwnedFd,
    plan_binding: ObjectDigest,
    identity: SourceRootIdentityV1,
    observation: SourceRootObservationV1,
    physical_snapshot: PhysicalSnapshotV1,
    observed_seconds: i64,
}

impl core::fmt::Debug for ProviderPhysicalSourceRootV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderPhysicalSourceRootV1([redacted])")
    }
}

impl ProviderPhysicalSourceRootV1 {
    pub(crate) fn revalidate(&self) -> Result<(), crate::ProviderLedgerError> {
        validate_physical_identity(
            &self.descriptor,
            self.identity,
            &self.observation,
            &self.physical_snapshot,
        )
    }

    pub(crate) fn descriptor_commitment(&self) -> ObjectDigest {
        source_root_descriptor_commitment_v1(&self.observation)
    }

    pub(crate) fn into_security_handoff(
        self,
    ) -> Result<
        aos_sandbox_source_provider_security::ProviderSourceRootHandoffV1,
        crate::ProviderLedgerError,
    > {
        self.revalidate()?;
        aos_sandbox_source_provider_security::ProviderSourceRootHandoffV1::observe(self.descriptor)
            .map_err(Into::into)
    }
}

/// Describes an immutable acquire effect without carrying execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquirePlanV1 {
    pub(crate) provider_id: [u8; 16],
    pub(crate) holder_id: [u8; 16],
    pub(crate) session_binding: ObjectDigest,
    pub(crate) attempt_digest: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) effect_id: [u8; 16],
    pub(crate) normalized_intent_digest: ObjectDigest,
    pub(crate) backend_id: [u8; 32],
}

impl AcquirePlanV1 {
    /// Repeatedly validates and binds one backend descriptor to this plan.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] if kernel boot, descriptor,
    /// mount-ID, namespace, directory, `O_PATH`, `CLOEXEC`, or read-only facts
    /// cannot be established twice without drift.
    pub(crate) fn observe_source_root(
        &self,
        descriptor: OwnedFd,
    ) -> Result<ProviderPhysicalSourceRootV1, crate::ProviderLedgerError> {
        observe_physical_source_root(descriptor, self.lineage_digest())
    }

    /// Returns the provider authority identity.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 16] {
        self.provider_id
    }

    /// Returns the holder authority identity.
    #[must_use]
    pub const fn holder_id(&self) -> [u8; 16] {
        self.holder_id
    }

    /// Returns the immutable session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the exact durable attempt commitment.
    #[must_use]
    pub const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt_digest
    }

    /// Returns the stable acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the exact durable effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 16] {
        self.effect_id
    }

    /// Returns the normalized durable intent commitment.
    #[must_use]
    pub const fn normalized_intent_digest(&self) -> ObjectDigest {
        self.normalized_intent_digest
    }

    /// Returns the exact selected backend-plan identity.
    #[must_use]
    pub const fn backend_id(&self) -> [u8; 32] {
        self.backend_id
    }

    /// Seals an already-applied observation to this exact durable plan.
    ///
    /// The returned observation is nonauthorizing by itself and can complete
    /// only alongside the original move-only reservation permit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal_observed_acquisition(
        &self,
        physical_root: ProviderPhysicalSourceRootV1,
        resource: SourceResourceV1,
        proof: SourceProviderProofV1,
        evidence: BackendEvidenceV1,
        reopen_identity: ReopenIdentityV1,
        backend_id: [u8; 32],
    ) -> Result<ObservedBackendAcquisitionV1, crate::ProviderLedgerError> {
        if physical_root.plan_binding != self.lineage_digest() {
            return Err(crate::ProviderLedgerError::BackendConflict);
        }
        let descriptor_observation = physical_root.observation.clone();
        let source_root = physical_root.identity;
        let observed_seconds = physical_root.observed_seconds;
        Ok(ObservedBackendAcquisitionV1 {
            lineage_digest: self.lineage_digest(),
            physical_root,
            descriptor_observation,
            resource,
            proof,
            evidence,
            reopen_identity,
            source_root,
            backend_id,
            observed_seconds,
        })
    }

    pub(crate) fn lineage_digest(&self) -> ObjectDigest {
        lineage_digest(
            b"aos.sandbox.source-provider.acquire-lineage.v1\0",
            self.provider_id,
            self.holder_id,
            self.session_binding,
            self.attempt_digest,
            self.acquisition_id,
            self.effect_id,
            None,
            None,
            self.backend_id,
        )
    }

    pub(crate) fn matches_effect_acquisition(
        &self,
        acquisition: &crate::model::AcquisitionRecordV1,
    ) -> bool {
        self.provider_id == acquisition.provider.authority_id()
            && self.holder_id == acquisition.holder.authority_id()
            && self.attempt_digest == acquisition.effect_attempt_digest
            && self.acquisition_id == acquisition.acquisition_id
            && self.effect_id == acquisition.effect_id
            && self.normalized_intent_digest == acquisition.normalized_intent.digest()
            && self.backend_id == acquisition.backend_id
    }
}

/// Describes an immutable release effect without carrying execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePlanV1 {
    pub(crate) provider_id: [u8; 16],
    pub(crate) holder_id: [u8; 16],
    pub(crate) session_binding: ObjectDigest,
    pub(crate) attempt_digest: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) effect_id: [u8; 16],
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) backend_id: [u8; 32],
    pub(crate) acquired_evidence: BackendEvidenceV1,
}

impl ReleasePlanV1 {
    /// Returns the provider authority identity.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 16] {
        self.provider_id
    }

    /// Returns the holder authority identity.
    #[must_use]
    pub const fn holder_id(&self) -> [u8; 16] {
        self.holder_id
    }

    /// Returns the immutable session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the exact durable attempt commitment.
    #[must_use]
    pub const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt_digest
    }

    /// Returns the stable acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the exact durable effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 16] {
        self.effect_id
    }

    /// Returns the exact provider lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the digest of the exact signed provider lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the exact selected backend identity.
    #[must_use]
    pub const fn backend_id(&self) -> [u8; 32] {
        self.backend_id
    }

    /// Returns the protected acquired-evidence class being released.
    #[must_use]
    pub const fn evidence_class(&self) -> BackendEvidenceClassV1 {
        self.acquired_evidence.class()
    }

    /// Returns the exact protected acquired evidence being released.
    #[must_use]
    pub const fn acquired_evidence(&self) -> &BackendEvidenceV1 {
        &self.acquired_evidence
    }

    /// Seals an already-completed release observation to this exact plan.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when the physical observation
    /// is not bound to this exact durable acquisition plan.
    pub(crate) fn seal_observed_release(
        &self,
        evidence: BackendEvidenceV1,
        backend_id: [u8; 32],
    ) -> Result<ObservedBackendReleaseV1, crate::ProviderLedgerError> {
        if backend_id != self.backend_id {
            return Err(crate::ProviderLedgerError::BackendConflict);
        }
        self.validate_released_evidence(&evidence)?;

        Ok(ObservedBackendReleaseV1 {
            lineage_digest: self.lineage_digest(),
            evidence,
            released_seconds: current_unix_seconds()?,
            backend_id,
        })
    }

    pub(crate) fn validate_released_evidence(
        &self,
        evidence: &BackendEvidenceV1,
    ) -> Result<(), crate::ProviderLedgerError> {
        if self.acquired_evidence.state() != BackendEvidenceStateV1::Acquired
            || evidence.state() != BackendEvidenceStateV1::Released
            || evidence.class() != self.acquired_evidence.class()
            || evidence.backend_authority_id() != self.acquired_evidence.backend_authority_id()
            || evidence.backend_generation() != self.acquired_evidence.backend_generation()
            || evidence.backend_digest() != self.acquired_evidence.backend_digest()
            || evidence.observation_generation() <= self.acquired_evidence.observation_generation()
            || evidence.predecessor_observation_generation()?
                != self.acquired_evidence.observation_generation()
            || evidence.predecessor_observation_digest()?
                != self.acquired_evidence.observation_digest()
        {
            return Err(crate::ProviderLedgerError::BackendConflict);
        }

        if evidence.class() == BackendEvidenceClassV1::LocalLiveExport
            && evidence
                .local_live_binding()
                .map_err(|_| crate::ProviderLedgerError::BackendConflict)?
                != self
                    .acquired_evidence
                    .local_live_binding()
                    .map_err(|_| crate::ProviderLedgerError::BackendConflict)?
        {
            return Err(crate::ProviderLedgerError::BackendConflict);
        }

        Ok(())
    }

    pub(crate) fn lineage_digest(&self) -> ObjectDigest {
        lineage_digest(
            b"aos.sandbox.source-provider.release-lineage.v1\0",
            self.provider_id,
            self.holder_id,
            self.session_binding,
            self.attempt_digest,
            self.acquisition_id,
            self.effect_id,
            Some(self.lease_id),
            Some(self.lease_digest),
            self.backend_id,
        )
    }

    pub(crate) fn matches_effect_release(
        &self,
        acquisition: &crate::model::AcquisitionRecordV1,
        release: &crate::model::ReleaseRecordV1,
    ) -> bool {
        self.provider_id == acquisition.provider.authority_id()
            && self.holder_id == acquisition.holder.authority_id()
            && self.attempt_digest == release.effect_attempt_digest
            && self.acquisition_id == acquisition.acquisition_id
            && self.effect_id == release.effect_id
            && self.lease_id == release.lease_id
            && self.lease_digest == release.lease_digest
            && self.backend_id == release.backend_id
            && self.acquired_evidence.state() == BackendEvidenceStateV1::Acquired
            && acquisition.backend_evidence.as_ref() == Some(&self.acquired_evidence)
    }
}

pub(crate) fn acquired_evidence(
    acquisition: &crate::model::AcquisitionRecordV1,
) -> Result<BackendEvidenceV1, crate::ProviderLedgerError> {
    acquisition
        .backend_evidence
        .as_ref()
        .filter(|evidence| evidence.state() == BackendEvidenceStateV1::Acquired)
        .cloned()
        .ok_or(crate::ProviderLedgerError::Corrupt(
            "missing acquired backend evidence",
        ))
}

/// Describes one active acquisition for fresh exact reopen observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveAcquisitionSnapshotV1 {
    pub(crate) provider_id: [u8; 16],
    pub(crate) holder_id: [u8; 16],
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) effect_id: [u8; 16],
    pub(crate) backend_lineage_digest: ObjectDigest,
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) backend_id: [u8; 32],
    pub(crate) evidence: BackendEvidenceV1,
    pub(crate) reopen_identity: ReopenIdentityV1,
    pub(crate) source_root: SourceRootIdentityV1,
}

impl ActiveAcquisitionSnapshotV1 {
    /// Returns the provider authority identity.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 16] {
        self.provider_id
    }

    /// Returns the holder authority identity.
    #[must_use]
    pub const fn holder_id(&self) -> [u8; 16] {
        self.holder_id
    }

    /// Repeatedly validates a reopened descriptor against this acquisition.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] if physical kernel facts cannot
    /// be established without drift or do not match the retained root.
    pub(crate) fn observe_reopened_source_root(
        &self,
        descriptor: OwnedFd,
    ) -> Result<ProviderPhysicalSourceRootV1, crate::ProviderLedgerError> {
        let binding = active_reopen_binding(self);
        let observed = observe_physical_source_root(descriptor, binding)?;
        if observed.identity != self.source_root {
            return Err(crate::ProviderLedgerError::BackendConflict);
        }
        Ok(observed)
    }

    /// Returns the stable acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the original durable acquisition effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 16] {
        self.effect_id
    }

    /// Returns the complete durable backend-lineage commitment.
    #[must_use]
    pub const fn backend_lineage_digest(&self) -> ObjectDigest {
        self.backend_lineage_digest
    }

    /// Returns the exact active provider lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the digest of the exact signed active lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the stable backend identity.
    #[must_use]
    pub const fn backend_id(&self) -> [u8; 32] {
        self.backend_id
    }

    /// Returns the persistent evidence that must be revalidated.
    #[must_use]
    pub const fn evidence(&self) -> &BackendEvidenceV1 {
        &self.evidence
    }

    /// Returns the stable reopen identity that must match.
    #[must_use]
    pub const fn reopen_identity(&self) -> &ReopenIdentityV1 {
        &self.reopen_identity
    }

    /// Returns the retained descriptor identity that must match.
    #[must_use]
    pub const fn source_root(&self) -> SourceRootIdentityV1 {
        self.source_root
    }

    /// Seals a freshly reopened descriptor to this retained acquisition.
    pub(crate) fn seal_reopened_source_root(
        &self,
        physical_root: ProviderPhysicalSourceRootV1,
    ) -> Result<ReopenedSourceRootV1, crate::ProviderLedgerError> {
        if physical_root.plan_binding != active_reopen_binding(self)
            || physical_root.identity != self.source_root
        {
            return Err(crate::ProviderLedgerError::BackendConflict);
        }
        let descriptor_observation = physical_root.observation.clone();
        let source_root = physical_root.identity;
        let observed_seconds = physical_root.observed_seconds;
        Ok(ReopenedSourceRootV1 {
            physical_root,
            descriptor_observation,
            acquisition_id: self.acquisition_id,
            source_root,
            backend_id: self.backend_id,
            backend_evidence: self.evidence.clone(),
            reopen_identity: self.reopen_identity.clone(),
            observed_seconds,
        })
    }
}

/// Grants exactly one backend acquire execution after durable reservation.
pub struct DurableAcquireEffectPermitV1 {
    pub(crate) plan: AcquirePlanV1,
    pub(crate) completion_session_binding: ObjectDigest,
    pub(crate) completion_attempt_digest: ObjectDigest,
    pub(crate) reservation_digest: ObjectDigest,
    pub(crate) journal_snapshot: ProtectedJournalSnapshot,
    pub(crate) completion_capacity: crate::transaction::CompletionCapacityV1,
    pub(crate) signing_authorization:
        aos_sandbox_source_provider_security::ProviderOutcomeAuthorizationV1,
}

/// Grants exactly one backend release execution after durable reservation.
pub struct DurableReleaseEffectPermitV1 {
    pub(crate) plan: ReleasePlanV1,
    pub(crate) completion_session_binding: ObjectDigest,
    pub(crate) completion_attempt_digest: ObjectDigest,
    pub(crate) reservation_digest: ObjectDigest,
    pub(crate) journal_snapshot: ProtectedJournalSnapshot,
    pub(crate) completion_capacity: crate::transaction::CompletionCapacityV1,
    pub(crate) signing_authorization:
        aos_sandbox_source_provider_security::ProviderOutcomeAuthorizationV1,
}

impl DurableAcquireEffectPermitV1 {
    /// Returns the immutable plan without exposing the reservation authority.
    #[must_use]
    pub const fn plan(&self) -> &AcquirePlanV1 {
        &self.plan
    }

    /// Seals execution output and returns the permit for owner-side completion.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when a valid internal realtime
    /// observation cannot be captured.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_execution(
        self,
        physical_root: ProviderPhysicalSourceRootV1,
        resource: SourceResourceV1,
        proof: SourceProviderProofV1,
        evidence: BackendEvidenceV1,
        reopen_identity: ReopenIdentityV1,
        backend_id: [u8; 32],
    ) -> Result<(Self, ObservedBackendAcquisitionV1), crate::ProviderLedgerError> {
        let observed = self.plan.seal_observed_acquisition(
            physical_root,
            resource,
            proof,
            evidence,
            reopen_identity,
            backend_id,
        )?;
        Ok((self, observed))
    }
}

impl DurableReleaseEffectPermitV1 {
    /// Returns the immutable plan without exposing the reservation authority.
    #[must_use]
    pub const fn plan(&self) -> &ReleasePlanV1 {
        &self.plan
    }

    /// Seals execution output and returns the permit for owner-side completion.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when a valid internal realtime
    /// observation cannot be captured.
    pub fn seal_execution(
        self,
        evidence: BackendEvidenceV1,
        backend_id: [u8; 32],
    ) -> Result<(Self, ObservedBackendReleaseV1), crate::ProviderLedgerError> {
        let observed = self.plan.seal_observed_release(evidence, backend_id)?;
        Ok((self, observed))
    }
}

impl core::fmt::Debug for DurableAcquireEffectPermitV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableAcquireEffectPermitV1([redacted])")
    }
}

impl core::fmt::Debug for DurableReleaseEffectPermitV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableReleaseEffectPermitV1([redacted])")
    }
}

/// Owns a live acquired source root and exact durable completion facts.
#[derive(Debug)]
pub struct ObservedBackendAcquisitionV1 {
    pub(crate) lineage_digest: ObjectDigest,
    physical_root: ProviderPhysicalSourceRootV1,
    pub(crate) descriptor_observation: SourceRootObservationV1,
    pub(crate) resource: SourceResourceV1,
    pub(crate) proof: SourceProviderProofV1,
    pub(crate) evidence: BackendEvidenceV1,
    pub(crate) reopen_identity: ReopenIdentityV1,
    pub(crate) source_root: SourceRootIdentityV1,
    pub(crate) backend_id: [u8; 32],
    pub(crate) observed_seconds: i64,
}

impl ObservedBackendAcquisitionV1 {
    pub(crate) fn revalidate_physical(&self) -> Result<(), crate::ProviderLedgerError> {
        self.physical_root.revalidate()
    }

    pub(crate) fn into_physical_root(self) -> ProviderPhysicalSourceRootV1 {
        self.physical_root
    }
}

/// Proves a fresh reopen matched all retained durable source facts.
#[derive(Debug)]
pub struct ReopenedSourceRootV1 {
    physical_root: ProviderPhysicalSourceRootV1,
    pub(crate) descriptor_observation: SourceRootObservationV1,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) source_root: SourceRootIdentityV1,
    pub(crate) backend_id: [u8; 32],
    pub(crate) backend_evidence: BackendEvidenceV1,
    pub(crate) reopen_identity: ReopenIdentityV1,
    pub(crate) observed_seconds: i64,
}

impl ReopenedSourceRootV1 {
    pub(crate) fn revalidate_physical(&self) -> Result<(), crate::ProviderLedgerError> {
        self.physical_root.revalidate()
    }

    pub(crate) fn into_physical_root(self) -> ProviderPhysicalSourceRootV1 {
        self.physical_root
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PhysicalSnapshotV1 {
    boot_id: [u8; 16],
    status_flags: OFlags,
    descriptor_flags: FdFlags,
    device: u64,
    inode: u64,
    mode: u32,
    mount_id: u64,
    mount_namespace_id: u64,
    mount_attributes: u64,
}

fn observe_physical_source_root(
    descriptor: OwnedFd,
    plan_binding: ObjectDigest,
) -> Result<ProviderPhysicalSourceRootV1, crate::ProviderLedgerError> {
    let first = physical_snapshot(&descriptor)?;
    let second = physical_snapshot(&descriptor)?;
    if first != second {
        return Err(crate::ProviderLedgerError::BackendConflict);
    }
    let identity =
        SourceRootIdentityV1::new(first.boot_id, first.device, first.inode, first.mount_id)?;
    let observation = SourceRootObservationV1::new(
        first.boot_id,
        first.device,
        first.inode,
        first.mount_id,
        true,
        true,
        true,
    )?;
    Ok(ProviderPhysicalSourceRootV1 {
        descriptor,
        plan_binding,
        identity,
        observation,
        physical_snapshot: first,
        observed_seconds: current_unix_seconds()?,
    })
}

fn current_unix_seconds() -> Result<i64, crate::ProviderLedgerError> {
    let seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if seconds < 0 {
        Err(crate::ProviderLedgerError::Unavailable)
    } else {
        Ok(seconds)
    }
}

fn physical_snapshot(
    descriptor: &OwnedFd,
) -> Result<PhysicalSnapshotV1, crate::ProviderLedgerError> {
    let boot_id = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| crate::ProviderLedgerError::Unavailable)?
        .into_bytes();
    let status_flags =
        rustix::fs::fcntl_getfl(descriptor).map_err(|_| crate::ProviderLedgerError::Unavailable)?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| crate::ProviderLedgerError::Unavailable)?;
    let stat =
        rustix::fs::fstat(descriptor).map_err(|_| crate::ProviderLedgerError::Unavailable)?;
    let mount_id = aos_sandbox_linux::inventory::MountId::from_fd(descriptor.as_fd())
        .map_err(|_| crate::ProviderLedgerError::Unavailable)?;
    let mount = aos_sandbox_linux::inventory::MountNamespace::current()
        .observe(mount_id)
        .map_err(|_| crate::ProviderLedgerError::Unavailable)?;
    if !status_flags.contains(OFlags::PATH)
        || !descriptor_flags.contains(FdFlags::CLOEXEC)
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_dev == 0
        || stat.st_ino == 0
        || mount.device_major != rustix::fs::major(stat.st_dev)
        || mount.device_minor != rustix::fs::minor(stat.st_dev)
        || !mount.is_read_only()
    {
        return Err(crate::ProviderLedgerError::BackendConflict);
    }
    Ok(PhysicalSnapshotV1 {
        boot_id,
        status_flags,
        descriptor_flags,
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        mount_id: mount_id.get(),
        mount_namespace_id: mount.mount_namespace_id,
        mount_attributes: mount.mount_attributes,
    })
}

fn validate_physical_identity(
    descriptor: &OwnedFd,
    identity: SourceRootIdentityV1,
    observation: &SourceRootObservationV1,
    retained: &PhysicalSnapshotV1,
) -> Result<(), crate::ProviderLedgerError> {
    let first = physical_snapshot(descriptor)?;
    let second = physical_snapshot(descriptor)?;
    if first != second
        || first != *retained
        || first.boot_id != identity.kernel_boot_id()
        || first.device != identity.device()
        || first.inode != identity.inode()
        || first.mount_id != identity.unique_mount_id()
        || observation.kernel_boot_id() != identity.kernel_boot_id()
        || observation.device() != identity.device()
        || observation.inode() != identity.inode()
        || observation.unique_mount_id() != identity.unique_mount_id()
    {
        return Err(crate::ProviderLedgerError::BackendConflict);
    }
    Ok(())
}

fn active_reopen_binding(value: &ActiveAcquisitionSnapshotV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.active-reopen.v1\0");
    hasher.update(value.provider_id);
    hasher.update(value.holder_id);
    hasher.update(value.acquisition_id.as_bytes());
    hasher.update(value.effect_id);
    hasher.update(value.backend_lineage_digest.as_bytes());
    hasher.update(value.lease_id);
    hasher.update(value.lease_digest.as_bytes());
    hasher.update(value.backend_id);
    hasher.update(value.evidence.encode());
    hasher.update(value.reopen_identity.encode());
    hasher.update(value.source_root.kernel_boot_id());
    hasher.update(value.source_root.device().to_be_bytes());
    hasher.update(value.source_root.inode().to_be_bytes());
    hasher.update(value.source_root.unique_mount_id().to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Retains sealed persistent evidence that a release completed.
#[derive(Debug)]
pub struct ObservedBackendReleaseV1 {
    pub(crate) lineage_digest: ObjectDigest,
    pub(crate) evidence: BackendEvidenceV1,
    pub(crate) released_seconds: i64,
    pub(crate) backend_id: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn lineage_digest(
    domain: &[u8],
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    session_binding: ObjectDigest,
    attempt_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    effect_id: [u8; 16],
    lease_id: Option<[u8; 16]>,
    lease_digest: Option<ObjectDigest>,
    backend_id: [u8; 32],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(provider_id);
    hasher.update(holder_id);
    hasher.update(session_binding.as_bytes());
    hasher.update(attempt_digest.as_bytes());
    hasher.update(acquisition_id.as_bytes());
    hasher.update(effect_id);
    hasher.update(lease_id.unwrap_or([0; 16]));
    hasher.update(
        lease_digest
            .unwrap_or(ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    hasher.update(backend_id);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Identifies one durable release tombstone after its completion sync.
#[derive(Debug)]
pub struct DurableReleaseTombstoneV1 {
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) lease_id: [u8; 16],
    pub(crate) release_generation: u64,
}

impl DurableReleaseTombstoneV1 {
    /// Returns the terminal acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the terminal lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the monotonic release generation.
    #[must_use]
    pub const fn release_generation(&self) -> u64 {
        self.release_generation
    }
}

/// Owns a response and optional source-root descriptor after completion sync.
#[derive(Debug)]
pub struct DurableProviderReplyV1 {
    pub(crate) response: Vec<u8>,
    pub(crate) source_root: Option<ProviderPhysicalSourceRootV1>,
    pub(crate) durability: DurableReplyAuthorityV1,
}

pub(crate) enum DurableReplyAuthorityV1 {
    Fresh(aos_sandbox_source_provider_security::CommittedProviderOutcomeV1),
    RevalidatedReplay {
        snapshot: ProtectedJournalSnapshot,
        attempt_key: Vec<u8>,
    },
}

impl core::fmt::Debug for DurableReplyAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableReplyAuthorityV1([protected durability])")
    }
}

impl DurableProviderReplyV1 {
    /// Consumes this reply into the authenticated session carrier.
    ///
    /// The security boundary revalidates the exact journal witness, canonical
    /// response/session identity, and the zero-or-one `SourceRoot` descriptor
    /// role immediately before the SCM_RIGHTS handoff.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] for journal/session drift,
    /// response substitution, descriptor-shape mismatch, or carrier failure.
    pub(crate) fn send(
        self,
        session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<(), crate::ProviderLedgerError> {
        let source_root = self
            .source_root
            .map(ProviderPhysicalSourceRootV1::into_security_handoff)
            .transpose()?;
        match self.durability {
            DurableReplyAuthorityV1::Fresh(committed) => {
                session.send_committed_reply(journal, committed, source_root)?
            }
            DurableReplyAuthorityV1::RevalidatedReplay {
                snapshot,
                attempt_key,
            } => {
                let replay = session.authorize_recovered_reply(
                    journal,
                    snapshot,
                    &attempt_key,
                    self.response,
                    source_root.is_some(),
                )?;
                session.send_revalidated_reply(journal, replay, source_root)?;
            }
        }
        Ok(())
    }

    pub(crate) fn session_binding(&self) -> Result<ObjectDigest, crate::ProviderLedgerError> {
        use aos_sandbox_source_provider_protocol::{
            decode_acquire_response, decode_inventory_response, decode_release_response,
        };

        if let Ok(response) = decode_acquire_response(&self.response) {
            return Ok(response.signed_status().subject().session_binding());
        }
        if let Ok(response) = decode_release_response(&self.response) {
            return Ok(response.signed_status().subject().session_binding());
        }
        if let Ok(response) = decode_inventory_response(&self.response) {
            return Ok(response.signed_status().subject().session_binding());
        }
        Err(crate::ProviderLedgerError::Corrupt(
            "durable reply response framing",
        ))
    }
}

/// Classifies backend observation of a reserved acquisition.
#[derive(Debug)]
pub enum AcquireObservationV1 {
    /// The backend has not applied the effect and may consume the permit once.
    NotApplied,
    /// The exact effect is already durably present.
    Applied(ObservedBackendAcquisitionV1),
    /// Backend facts contradict the durable plan.
    Conflict,
}

/// Classifies backend observation of a reserved release.
#[derive(Debug)]
pub enum ReleaseObservationV1 {
    /// The exact selected backend object remains present.
    StillPresent,
    /// The exact release already completed.
    Released(ObservedBackendReleaseV1),
    /// Backend facts contradict the durable plan.
    Conflict,
}

/// Classifies fresh reopen of one active acquisition.
#[derive(Debug)]
pub enum ReopenObservationV1 {
    /// All exact backend and descriptor facts matched.
    Reopened(ReopenedSourceRootV1),
    /// The source is unavailable without weakening authority.
    Unavailable,
    /// Backend facts contradict the durable record.
    Conflict,
}

/// Defines the provider-owned backend adapter boundary.
///
/// This trait is sealed. Its sole implementation is constructed by the fixed
/// owner with protected class-verifier custody, so an external transport cannot
/// replace evidence authentication with an unconditional success path. Effect
/// methods receive the move-only durable permit and must return it with output
/// sealed through [`DurableAcquireEffectPermitV1::seal_execution`] or
/// [`DurableReleaseEffectPermitV1::seal_execution`].
pub trait SourceProviderBackendV1: sealed::SealedBackendV1 {
    /// Observes whether an acquisition reservation was already applied.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when transport, protected
    /// verifier, descriptor, or retained backend facts cannot be validated.
    fn observe_acquire(
        &mut self,
        plan: &AcquirePlanV1,
    ) -> Result<AcquireObservationV1, crate::ProviderLedgerError>;

    /// Consumes a durable permit to execute one acquisition effect.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when execution or its protected
    /// class-specific evidence cannot be completed and sealed.
    fn execute_acquire(
        &mut self,
        permit: DurableAcquireEffectPermitV1,
    ) -> Result<
        (DurableAcquireEffectPermitV1, ObservedBackendAcquisitionV1),
        crate::ProviderLedgerError,
    >;

    /// Reopens and revalidates one exact active source.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when the retained source cannot
    /// be classified or its descriptor and verifier attestations do not match.
    fn reopen_active(
        &mut self,
        acquisition: &ActiveAcquisitionSnapshotV1,
    ) -> Result<ReopenObservationV1, crate::ProviderLedgerError>;

    /// Observes whether a release reservation was already applied.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when transport or protected
    /// class-specific readback verification cannot complete.
    fn observe_release(
        &mut self,
        plan: &ReleasePlanV1,
    ) -> Result<ReleaseObservationV1, crate::ProviderLedgerError>;

    /// Consumes a durable permit to execute one release effect.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] when execution or its protected
    /// terminal evidence cannot be completed and sealed.
    fn execute_release(
        &mut self,
        permit: DurableReleaseEffectPermitV1,
    ) -> Result<(DurableReleaseEffectPermitV1, ObservedBackendReleaseV1), crate::ProviderLedgerError>;
}

impl<Transport: crate::backend_adapter::SourceProviderBackendTransportV1 + ?Sized>
    sealed::SealedBackendV1
    for crate::backend_adapter::FixedSourceProviderBackendV1<'_, Transport>
{
}

mod sealed {
    pub trait SealedBackendV1 {}
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::ObjectDigest;

    use super::{BackendEvidenceClassV1, BackendEvidenceV1, ReleasePlanV1};

    fn digest(value: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([value; 32])
    }

    #[test]
    fn local_live_release_preserves_the_acquired_binding() {
        let binding = vec![1; 128];
        let acquired = BackendEvidenceV1::new_acquired(
            BackendEvidenceClassV1::LocalLiveExport,
            [2; 16],
            3,
            digest(4),
            5,
            digest(6),
            binding.clone(),
        )
        .unwrap();
        let plan = ReleasePlanV1 {
            provider_id: [7; 16],
            holder_id: [8; 16],
            session_binding: digest(9),
            attempt_digest: digest(10),
            acquisition_id: digest(11),
            effect_id: [12; 16],
            lease_id: [13; 16],
            lease_digest: digest(14),
            backend_id: [15; 32],
            acquired_evidence: acquired.clone(),
        };
        let released = BackendEvidenceV1::new_released(
            BackendEvidenceClassV1::LocalLiveExport,
            acquired.backend_authority_id(),
            acquired.backend_generation(),
            acquired.backend_digest(),
            6,
            digest(16),
            acquired.observation_generation(),
            acquired.observation_digest(),
            binding,
        )
        .unwrap();
        assert!(plan.validate_released_evidence(&released).is_ok());

        let mut changed_binding = released.local_live_binding().unwrap().encode();
        changed_binding[64] = 2;
        let substituted = BackendEvidenceV1::new_released(
            BackendEvidenceClassV1::LocalLiveExport,
            acquired.backend_authority_id(),
            acquired.backend_generation(),
            acquired.backend_digest(),
            7,
            digest(17),
            acquired.observation_generation(),
            acquired.observation_digest(),
            changed_binding.to_vec(),
        )
        .unwrap();
        assert!(plan.validate_released_evidence(&substituted).is_err());
    }
}
