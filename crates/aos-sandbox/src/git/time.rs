//! Typed monotonic time and closed pack-lease state.

use aos_sandbox_core::{ObjectDigest, ResourceId, Revision};
use sha2::{Digest as _, Sha256};

use super::history::{GitPackLeaseV1, GitRepositoryStateV1};
use super::{GitExportGenerationDigestV1, GitModelError, GitPackGenerationDigestV1};

/// Maximum records retained in one in-memory replay window.
pub const MAXIMUM_GIT_HISTORY_RECORDS: usize = 262_144;
/// Maximum pin and lease records retained by one repository history.
pub const MAXIMUM_GIT_PACK_LEASES: usize = 65_536;

/// Names the consumer retaining an immutable pack generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GitPackConsumerV1 {
    /// A repository cheap fork depends on the pack.
    Repository(ResourceId),
    /// An immutable export remains served from the pack.
    Export(ResourceId),
}

/// Selects the durable dependency state of one cheap fork.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GitCheapForkStatusV1 {
    /// The target repository actively depends on the source pack.
    Attached = 1,
    /// Service is detached while conversion or tombstoning completes.
    Detached = 2,
    /// Independent storage durably replaced the source-pack dependency.
    Converted = 3,
    /// The target repository was durably tombstoned.
    Tombstoned = 4,
}

/// Selects the durable current state of one pack lease.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GitPackLeaseStatusV1 {
    /// The lease currently retains its exact pack generation.
    Active = 1,
    /// The owner explicitly released the lease.
    Released = 2,
    /// The lease was closed after its exact expiry became current.
    Expired = 3,
    /// A current-boot successor invalidated a prior-boot deadline.
    Invalidated = 4,
}

/// Carries one monotonic `CLOCK_BOOTTIME` nanosecond observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitBoottimeV1(u64);

impl GitBoottimeV1 {
    /// Constructs a bounded non-sentinel boot-time observation.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for zero or `u64::MAX`.
    pub fn new(value: u64) -> Result<Self, GitModelError> {
        if value == 0 || value == u64::MAX {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns monotonic boot-time nanoseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(super) fn from_stored(value: u64) -> Result<Self, GitModelError> {
        Self::new(value).map_err(|_| GitModelError::CorruptEncoding)
    }
}

/// Proves a monotonic observation came from the trusted journal clock boundary.
///
/// The handle has no public scalar constructor. A dormant journal verifier may
/// issue it after sampling and authenticating the current boot clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitTrustedBoottimeV1 {
    boot: GitBootIdV1,
    observed: GitBoottimeV1,
}

/// Identifies the exact kernel boot owning monotonic Git lease deadlines.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitBootIdV1(ObjectDigest);

impl GitBootIdV1 {
    pub(crate) fn from_verified(value: ObjectDigest) -> Result<Self, GitModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(Self(value))
        }
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, GitModelError> {
        Self::from_verified(value).map_err(|_| GitModelError::CorruptEncoding)
    }

    /// Returns the opaque boot-identity commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

impl GitTrustedBoottimeV1 {
    pub(crate) fn from_verified_observation(
        boot: ObjectDigest,
        observed: GitBoottimeV1,
    ) -> Result<Self, GitModelError> {
        Ok(Self {
            boot: GitBootIdV1::from_verified(boot)?,
            observed,
        })
    }

    /// Returns the verifier-owned current boot-time observation.
    #[must_use]
    pub const fn observed(self) -> GitBoottimeV1 {
        self.observed
    }

    /// Returns the verified kernel-boot identity.
    #[must_use]
    pub const fn boot(self) -> GitBootIdV1 {
        self.boot
    }
}

/// Retains a cheap-fork lineage edge and its required current pack lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCheapForkV1 {
    target: GitRepositoryStateV1,
    source_repository: ResourceId,
    source_revision: Revision,
    source_export: GitExportGenerationDigestV1,
    pack: GitPackGenerationDigestV1,
    lease: GitPackLeaseV1,
    observed_at: GitBoottimeV1,
    record_revision: Revision,
    predecessor: Option<ObjectDigest>,
    status: GitCheapForkStatusV1,
    closed_at: Option<GitBoottimeV1>,
}

impl GitCheapForkV1 {
    /// Constructs an attached dependency observed under a current lease.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless the target is repository
    /// genesis and the exact target lease is active and unexpired at observation.
    pub fn new(
        target: GitRepositoryStateV1,
        source_repository: ResourceId,
        source_revision: Revision,
        source_export: GitExportGenerationDigestV1,
        pack: GitPackGenerationDigestV1,
        lease: GitPackLeaseV1,
        current_boottime: &GitTrustedBoottimeV1,
    ) -> Result<Self, GitModelError> {
        let observed_at = current_boottime.observed();
        if target.repository().revision().get() != 1
            || target.predecessor().is_some()
            || source_repository.as_bytes() == &[0; 16]
            || source_revision.get() == 0
            || source_revision.get() == u64::MAX
            || lease.consumer() != GitPackConsumerV1::Repository(target.repository().repository())
            || lease.generation_digest() != pack
            || lease.status() != GitPackLeaseStatusV1::Active
            || lease.boot() != current_boottime.boot()
            || lease.expires_at() <= observed_at.get()
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            target,
            source_repository,
            source_revision,
            source_export,
            pack,
            lease,
            observed_at,
            record_revision: Revision::new(1),
            predecessor: None,
            status: GitCheapForkStatusV1::Attached,
            closed_at: None,
        })
    }

    /// Advances the dependency through detach, conversion, or tombstoning.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a stale revision, regressed
    /// observation, terminal record, or invalid closure transition.
    pub fn close_dependency(
        &self,
        expected_revision: Revision,
        status: GitCheapForkStatusV1,
        current_boottime: &GitTrustedBoottimeV1,
    ) -> Result<Self, GitModelError> {
        self.close_dependency_at(
            expected_revision,
            status,
            current_boottime.boot(),
            current_boottime.observed(),
        )
    }

    /// Rebinds a live dependency to the immediate successor of its exact lease.
    ///
    /// This transition must be committed in the same durable join as the lease
    /// renewal and every other attached or detached fork using that lease.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a stale fork revision,
    /// changed lease lineage, non-immediate renewal, terminal dependency, or
    /// renewal that is not current and unexpired on this boot.
    pub fn rebind_lease(
        &self,
        expected_revision: Revision,
        renewed: GitPackLeaseV1,
        current_boottime: &GitTrustedBoottimeV1,
    ) -> Result<Self, GitModelError> {
        if renewed.boot() != current_boottime.boot()
            || renewed.observed_at() > current_boottime.observed()
            || renewed.expires_at() <= current_boottime.observed().get()
        {
            return Err(GitModelError::InvalidModel);
        }
        self.rebind_lease_at(expected_revision, renewed)
    }

    /// Closes this dependency in the same atomic group as its terminal lease.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless `terminal_lease` is the
    /// current immediate lease successor, its close is current, and any boot
    /// change is authenticated by `rollover`.
    pub fn close_for_terminal_lease(
        &self,
        expected_revision: Revision,
        status: GitCheapForkStatusV1,
        terminal_lease: GitPackLeaseV1,
        current_boottime: &GitTrustedBoottimeV1,
        rollover: Option<&super::GitBootRolloverAuthorityV1>,
    ) -> Result<Self, GitModelError> {
        if terminal_lease.boot() != current_boottime.boot()
            || terminal_lease.observed_at() > current_boottime.observed()
            || terminal_lease.predecessor_boot().is_some_and(|boot| {
                rollover.is_none_or(|authority| {
                    authority.current() != terminal_lease.boot()
                        || !authority.accepts_predecessor(boot)
                })
            })
            || (terminal_lease.predecessor_boot().is_none()
                && terminal_lease.boot() != self.lease.boot())
        {
            return Err(GitModelError::InvalidModel);
        }
        self.close_with_terminal_lease_at(expected_revision, status, terminal_lease)
    }

    pub(super) fn rebind_lease_at(
        &self,
        expected_revision: Revision,
        renewed: GitPackLeaseV1,
    ) -> Result<Self, GitModelError> {
        let live = matches!(
            self.status,
            GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
        );
        let immediate_lease = self
            .lease
            .lease_revision()
            .checked_next()
            .is_ok_and(|revision| revision == renewed.lease_revision());
        if expected_revision != self.record_revision
            || !live
            || renewed.status() != GitPackLeaseStatusV1::Active
            || !immediate_lease
            || renewed.lease() != self.lease.lease()
            || renewed.project() != self.lease.project()
            || renewed.repository() != self.lease.repository()
            || renewed.pack_generation() != self.lease.pack_generation()
            || renewed.generation() != self.lease.generation()
            || renewed.generation_digest() != self.lease.generation_digest()
            || renewed.export() != self.lease.export()
            || renewed.export_generation() != self.lease.export_generation()
            || renewed.export_digest() != self.lease.export_digest()
            || renewed.consumer() != self.lease.consumer()
            || renewed.principal() != self.lease.principal()
            || renewed.boot() != self.lease.boot()
            || renewed.observed_at() <= self.lease.observed_at()
            || renewed.expires_at() <= self.lease.expires_at()
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            lease: renewed,
            observed_at: renewed.observed_at(),
            record_revision: self
                .record_revision
                .checked_next()
                .map_err(|_| GitModelError::InvalidModel)?,
            predecessor: Some(self.complete_digest()),
            ..self.clone()
        })
    }

    pub(super) fn close_dependency_at(
        &self,
        expected_revision: Revision,
        status: GitCheapForkStatusV1,
        boot: GitBootIdV1,
        observed_at: GitBoottimeV1,
    ) -> Result<Self, GitModelError> {
        let valid_edge = matches!(
            (self.status, status),
            (
                GitCheapForkStatusV1::Attached,
                GitCheapForkStatusV1::Detached
            ) | (
                GitCheapForkStatusV1::Attached,
                GitCheapForkStatusV1::Converted
            ) | (
                GitCheapForkStatusV1::Attached,
                GitCheapForkStatusV1::Tombstoned
            ) | (
                GitCheapForkStatusV1::Detached,
                GitCheapForkStatusV1::Converted
            ) | (
                GitCheapForkStatusV1::Detached,
                GitCheapForkStatusV1::Tombstoned
            )
        );
        if expected_revision != self.record_revision
            || boot != self.lease.boot()
            || observed_at < self.observed_at
            || !valid_edge
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            record_revision: self
                .record_revision
                .checked_next()
                .map_err(|_| GitModelError::InvalidModel)?,
            predecessor: Some(self.complete_digest()),
            status,
            closed_at: Some(observed_at),
            ..self.clone()
        })
    }

    pub(super) fn close_with_terminal_lease_at(
        &self,
        expected_revision: Revision,
        status: GitCheapForkStatusV1,
        terminal_lease: GitPackLeaseV1,
    ) -> Result<Self, GitModelError> {
        let valid_status = matches!(
            status,
            GitCheapForkStatusV1::Converted | GitCheapForkStatusV1::Tombstoned
        );
        let immediate_lease = self
            .lease
            .lease_revision()
            .checked_next()
            .is_ok_and(|revision| revision == terminal_lease.lease_revision());
        if expected_revision != self.record_revision
            || !matches!(
                self.status,
                GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
            )
            || !valid_status
            || terminal_lease.status() == GitPackLeaseStatusV1::Active
            || !immediate_lease
            || terminal_lease.lease() != self.lease.lease()
            || terminal_lease.project() != self.lease.project()
            || terminal_lease.repository() != self.lease.repository()
            || terminal_lease.pack_generation() != self.lease.pack_generation()
            || terminal_lease.generation() != self.lease.generation()
            || terminal_lease.generation_digest() != self.lease.generation_digest()
            || terminal_lease.export() != self.lease.export()
            || terminal_lease.export_generation() != self.lease.export_generation()
            || terminal_lease.export_digest() != self.lease.export_digest()
            || terminal_lease.consumer() != self.lease.consumer()
            || terminal_lease.principal() != self.lease.principal()
            || terminal_lease.closed_at().is_none()
        {
            return Err(GitModelError::InvalidModel);
        }
        let observed_at = terminal_lease.observed_at();
        Ok(Self {
            lease: terminal_lease,
            observed_at,
            record_revision: self
                .record_revision
                .checked_next()
                .map_err(|_| GitModelError::InvalidModel)?,
            predecessor: Some(self.complete_digest()),
            status,
            closed_at: Some(observed_at),
            ..self.clone()
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_stored(
        target: GitRepositoryStateV1,
        source_repository: ResourceId,
        source_revision: Revision,
        source_export: GitExportGenerationDigestV1,
        pack: GitPackGenerationDigestV1,
        lease: GitPackLeaseV1,
        observed_at: GitBoottimeV1,
        record_revision: Revision,
        predecessor: Option<ObjectDigest>,
        status: GitCheapForkStatusV1,
        closed_at: Option<GitBoottimeV1>,
    ) -> Result<Self, GitModelError> {
        let valid_shape = match status {
            GitCheapForkStatusV1::Attached => {
                (record_revision.get() == 1) == predecessor.is_none() && closed_at.is_none()
            }
            GitCheapForkStatusV1::Detached
            | GitCheapForkStatusV1::Converted
            | GitCheapForkStatusV1::Tombstoned => {
                record_revision.get() > 1 && predecessor.is_some() && closed_at.is_some()
            }
        };
        if target.repository().revision().get() != 1
            || target.predecessor().is_some()
            || source_repository.as_bytes() == &[0; 16]
            || source_revision.get() == 0
            || source_revision.get() == u64::MAX
            || lease.consumer() != GitPackConsumerV1::Repository(target.repository().repository())
            || lease.generation_digest() != pack
            || (matches!(
                status,
                GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
            ) && (lease.status() != GitPackLeaseStatusV1::Active
                || lease.expires_at() <= observed_at.get()))
            || record_revision.get() == u64::MAX
            || closed_at.is_some_and(|time| time < observed_at)
            || !valid_shape
        {
            return Err(GitModelError::CorruptEncoding);
        }
        Ok(Self {
            target,
            source_repository,
            source_revision,
            source_export,
            pack,
            lease,
            observed_at,
            record_revision,
            predecessor,
            status,
            closed_at,
        })
    }

    /// Returns the canonical complete dependency-record commitment.
    #[must_use]
    pub fn complete_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.git.cheap-fork-record.v1\0")
                .chain_update(self.target.complete_digest().as_bytes())
                .chain_update(self.source_repository.as_bytes())
                .chain_update(self.source_revision.get().to_be_bytes())
                .chain_update(self.source_export.digest().as_bytes())
                .chain_update(self.pack.digest().as_bytes())
                .chain_update(self.lease.project().as_bytes())
                .chain_update(self.lease.repository().as_bytes())
                .chain_update(self.lease.pack_generation().as_bytes())
                .chain_update(self.lease.generation().get().to_be_bytes())
                .chain_update(self.lease.generation_digest().digest().as_bytes())
                .chain_update(self.lease.export().as_bytes())
                .chain_update(self.lease.export_generation().get().to_be_bytes())
                .chain_update(self.lease.export_digest().digest().as_bytes())
                .chain_update(self.lease.lease().as_bytes())
                .chain_update(self.lease.lease_revision().get().to_be_bytes())
                .chain_update(self.lease.principal().as_bytes())
                .chain_update(self.lease.boot().digest().as_bytes())
                .chain_update(self.lease.observed_at().get().to_be_bytes())
                .chain_update(self.lease.expires_at().to_be_bytes())
                .chain_update(self.lease.pin_receipt().as_bytes())
                .chain_update([self.lease.status() as u8])
                .chain_update(self.lease.closed_at().unwrap_or(0).to_be_bytes())
                .chain_update(
                    self.lease
                        .predecessor_boot()
                        .map_or(ObjectDigest::from_bytes([0; 32]), |boot| boot.digest())
                        .as_bytes(),
                )
                .chain_update(self.observed_at.get().to_be_bytes())
                .chain_update(self.record_revision.get().to_be_bytes())
                .chain_update(
                    self.predecessor
                        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                        .as_bytes(),
                )
                .chain_update([self.status as u8])
                .chain_update(self.closed_at.map_or(0, GitBoottimeV1::get).to_be_bytes())
                .finalize()
                .into(),
        )
    }

    /// Borrows the target repository genesis state.
    #[must_use]
    pub const fn target(&self) -> &GitRepositoryStateV1 {
        &self.target
    }

    /// Returns the source repository identity.
    #[must_use]
    pub const fn source_repository(&self) -> ResourceId {
        self.source_repository
    }

    /// Returns the source repository revision.
    #[must_use]
    pub const fn source_revision(&self) -> Revision {
        self.source_revision
    }

    /// Returns the exact source export commitment.
    #[must_use]
    pub const fn source_export(&self) -> GitExportGenerationDigestV1 {
        self.source_export
    }

    /// Returns the retained pack-generation commitment.
    #[must_use]
    pub const fn pack(&self) -> GitPackGenerationDigestV1 {
        self.pack
    }

    /// Returns the exact pack lease protecting this dependency.
    #[must_use]
    pub const fn lease(&self) -> GitPackLeaseV1 {
        self.lease
    }

    /// Returns the time at which lease currentness was observed.
    #[must_use]
    pub const fn observed_at(&self) -> GitBoottimeV1 {
        self.observed_at
    }

    /// Returns the dependency-record revision.
    #[must_use]
    pub const fn record_revision(&self) -> Revision {
        self.record_revision
    }

    /// Returns the exact predecessor dependency commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Returns the current dependency-closure state.
    #[must_use]
    pub const fn status(&self) -> GitCheapForkStatusV1 {
        self.status
    }

    /// Returns the exact detach, conversion, or tombstone observation.
    #[must_use]
    pub const fn closed_at(&self) -> Option<GitBoottimeV1> {
        self.closed_at
    }
}
