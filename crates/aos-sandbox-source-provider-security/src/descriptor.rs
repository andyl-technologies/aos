//! Nonforgeable SourceRoot descriptor observation and committed custody brands.

use std::num::NonZeroU64;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::inventory::{MountId, MountNamespace, MountObservation};
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_source_provider_protocol::{
    SourceRootObservationV1, source_root_descriptor_commitment_v1,
};
use rustix::fs::{FileType, OFlags};
use rustix::io::FdFlags;

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
    lease_id: [u8; 16],
    session_binding: ObjectDigest,
    socket_cookie: NonZeroU64,
    signed_outcome_digest: ObjectDigest,
    observation: SourceRootObservationV1,
    snapshot: DescriptorSnapshotV1,
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
    observed: ObservedSourceRootV1,
}

impl core::fmt::Debug for CommittedSourceRootV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedSourceRootV1([redacted])")
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
    descriptor: OwnedFd,
    provider_execution: ProcessExecutionEvidenceV1,
    expected_observation: SourceRootObservationV1,
    descriptor_commitment: ObjectDigest,
    acquisition_id: [u8; 32],
    lease_id: [u8; 16],
    session_binding: ObjectDigest,
    socket_cookie: NonZeroU64,
    signed_outcome_digest: ObjectDigest,
}

pub(super) struct SourceRootDispositionCommitReceiptV1 {
    descriptor_commitment: ObjectDigest,
    acquisition_id: [u8; 32],
    lease_id: [u8; 16],
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
            lease_id,
            session_binding,
            socket_cookie,
            signed_outcome_digest,
        } = record;
        if descriptor_commitment == ObjectDigest::from_bytes([0; 32])
            || acquisition_id == [0; 32]
            || lease_id == [0; 16]
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
            lease_id,
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

    pub(crate) const fn protocol_observation(&self) -> &SourceRootObservationV1 {
        &self.observation
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
}

impl SourceRootDispositionCommitReceiptV1 {
    fn matches(&self, observed: &ObservedSourceRootV1) -> bool {
        self.descriptor_commitment == observed.descriptor_commitment
            && self.acquisition_id == observed.acquisition_id
            && self.lease_id == observed.lease_id
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
