//! Ephemeral pairing of protected registry authority with a live directory.

use aos_sandbox_core::{NodeId, ObjectDigest, PrincipalId};
use aos_sandbox_linux::immutable_file::FsVerityPublicationRoot;

use super::{
    PublicationFilesystemProfileV1, PublicationRootId, PublicationRootRecordV1,
    PublicationRootRegistry, PublicationRootRegistryError, PublicationRootStateV1,
};

/// Carries fresh service identity observed on the local authenticated carrier.
///
/// Construction is crate-private so decoded local messages cannot manufacture
/// the observation. The boot commitment is session-local and must never be
/// serialized into a protected root record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshServiceObservationV1 {
    node: NodeId,
    principal: PrincipalId,
    boot_commitment: ObjectDigest,
}

impl FreshServiceObservationV1 {
    /// Records one fresh local service observation from a trusted carrier.
    pub(crate) const fn new(
        node: NodeId,
        principal: PrincipalId,
        boot_commitment: ObjectDigest,
    ) -> Self {
        Self {
            node,
            principal,
            boot_commitment,
        }
    }
}

/// Reports failure to pair durable logical authority with current custody.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RootObservationError {
    /// The protected root is absent, inactive, or otherwise unusable.
    #[error(transparent)]
    Registry(#[from] PublicationRootRegistryError),
    /// Fresh node, service principal, or boot evidence differs.
    #[error("fresh publication-root service observation differs")]
    ServiceMismatch,
    /// Requested filesystem mechanics are unsupported by this custody type.
    #[error("publication-root filesystem profile differs")]
    FilesystemProfileMismatch,
}

/// Owns a live protected directory paired with one active registry generation.
///
/// The Linux value retains its descriptor privately. Device and inode values
/// remain diagnostics inside that mechanical boundary and are neither exposed
/// here nor included in any durable authority commitment.
#[derive(Debug)]
pub struct PublicationRootCustody {
    root: FsVerityPublicationRoot,
    record: PublicationRootRecordV1,
    boot_commitment: ObjectDigest,
}

/// Borrows exact active root authority and its still-live descriptor custody.
///
/// There is no decoder or public constructor. Dropping custody invalidates all
/// borrows, and every new operation must obtain a fresh pairing.
#[derive(Debug)]
pub struct AuthorizedPublicationRoot<'custody> {
    custody: &'custody PublicationRootCustody,
}

impl PublicationRootCustody {
    /// Pairs a fixed protected-owner recovery root without live session authority.
    ///
    /// This constructor is crate-private and is called only while an opaque
    /// protected executor-fence claim is consumed. The recovery commitment is
    /// retained as the boot-incarnation custody key and grants observation, not
    /// new admission.
    pub(crate) fn pair_fixed_recovery(
        registry: &mut PublicationRootRegistry,
        root_id: PublicationRootId,
        expected_record_digest: ObjectDigest,
        root: FsVerityPublicationRoot,
        recovery_commitment: ObjectDigest,
    ) -> Result<Self, RootObservationError> {
        let record = registry.active(root_id)?.clone();
        if record.record_digest != expected_record_digest
            || recovery_commitment.as_bytes() == &[0; 32]
            || record.filesystem_profile != PublicationFilesystemProfileV1::FsVeritySha256NoReplace
        {
            return Err(RootObservationError::ServiceMismatch);
        }
        root.recheck_protected_path()
            .map_err(|_| RootObservationError::ServiceMismatch)?;
        registry.retain_custody(root_id, recovery_commitment)?;
        Ok(Self {
            root,
            record,
            boot_commitment: recovery_commitment,
        })
    }

    /// Pairs one already mechanically protected descriptor with registry state.
    ///
    /// # Errors
    ///
    /// Returns [`RootObservationError`] unless the registry head is active, the
    /// fresh carrier identity matches it exactly, and the filesystem profile is
    /// the closed fs-verity/no-replace profile.
    pub(crate) fn pair(
        registry: &mut PublicationRootRegistry,
        root_id: PublicationRootId,
        root: FsVerityPublicationRoot,
        observation: FreshServiceObservationV1,
    ) -> Result<Self, RootObservationError> {
        let record = registry.active(root_id)?.clone();
        if observation.node != record.service_node
            || observation.principal != record.service_principal
            || observation.boot_commitment.as_bytes() == &[0; 32]
        {
            return Err(RootObservationError::ServiceMismatch);
        }
        if record.filesystem_profile != PublicationFilesystemProfileV1::FsVeritySha256NoReplace {
            return Err(RootObservationError::FilesystemProfileMismatch);
        }
        registry.retain_custody(root_id, observation.boot_commitment)?;
        Ok(Self {
            root,
            record,
            boot_commitment: observation.boot_commitment,
        })
    }

    /// Rechecks the retained logical generation before minting operation use.
    ///
    /// # Errors
    ///
    /// Returns [`RootObservationError`] if the registry head changed, began
    /// draining, or no longer equals the paired protected record.
    pub fn authorize<'custody>(
        &'custody self,
        registry: &PublicationRootRegistry,
    ) -> Result<AuthorizedPublicationRoot<'custody>, RootObservationError> {
        let current = registry.active(self.record.root_id)?;
        if current.state != PublicationRootStateV1::Active
            || current.record_digest != self.record.record_digest
            || current.generation != self.record.generation
            || self.boot_commitment.as_bytes() == &[0; 32]
        {
            return Err(RootObservationError::ServiceMismatch);
        }
        Ok(AuthorizedPublicationRoot { custody: self })
    }

    /// Reauthorizes exact retained completion while the root drains.
    ///
    /// This path never authorizes a new admission. It retains the originally
    /// paired generation so an already-issued artifact-bound permit can finish
    /// after the registry head advances to `Draining`.
    ///
    /// # Errors
    ///
    /// Returns [`RootObservationError`] if the original generation disappeared,
    /// custody changed, or the current root has already retired.
    pub(crate) fn authorize_retained_completion(
        &self,
        registry: &PublicationRootRegistry,
    ) -> Result<AuthorizedPublicationRoot<'_>, RootObservationError> {
        let retained = registry.generation_digest(self.record.root_id, self.record.generation);
        let head = registry
            .head(self.record.root_id)
            .ok_or(PublicationRootRegistryError::Absent)?;
        if retained != Some(self.record.record_digest)
            || head.state == PublicationRootStateV1::Retired
            || head.generation < self.record.generation
            || self.boot_commitment.as_bytes() == &[0; 32]
        {
            return Err(RootObservationError::ServiceMismatch);
        }
        Ok(AuthorizedPublicationRoot { custody: self })
    }

    /// Reauthorizes reads of already-cataloged entries while the root drains.
    ///
    /// Draining blocks new publication but deliberately preserves disclosure
    /// already granted by the independent read registry. Retirement cannot
    /// occur until those entries are evicted and all descriptor pins release.
    ///
    /// # Errors
    ///
    /// Returns [`RootObservationError`] if the retained generation disappeared,
    /// descriptor custody changed, or the registry has retired the root.
    pub(crate) fn authorize_retained_read(
        &self,
        registry: &PublicationRootRegistry,
    ) -> Result<AuthorizedPublicationRoot<'_>, RootObservationError> {
        self.authorize_retained_completion(registry)
    }

    /// Returns the logical root identity without granting effect authority.
    #[must_use]
    pub const fn root_id(&self) -> PublicationRootId {
        self.record.root_id
    }

    /// Borrows the fixed Linux mechanics retained by this authenticated custody.
    pub(crate) const fn mechanics(&self) -> &FsVerityPublicationRoot {
        &self.root
    }

    /// Borrows the exact protected record paired with this custody.
    pub(crate) const fn record(&self) -> &PublicationRootRecordV1 {
        &self.record
    }

    /// Releases this exact live custody from the registry retirement guard.
    ///
    /// Consuming `self` prevents subsequent authorization from the released
    /// descriptor. If release is not recorded, retirement remains blocked.
    ///
    /// # Errors
    ///
    /// Returns [`RootObservationError`] when the registry does not retain this
    /// exact root and boot-incarnation commitment.
    pub(crate) fn release(
        self,
        registry: &mut PublicationRootRegistry,
    ) -> Result<(), RootObservationError> {
        registry.release_custody(self.record.root_id, self.boot_commitment)?;
        Ok(())
    }
}

impl AuthorizedPublicationRoot<'_> {
    /// Returns the exact protected record digest for admission commitments.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.custody.record.record_digest
    }

    /// Returns the exact protected root generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.custody.record.generation
    }

    /// Borrows the logical registry record for exact scope checks.
    #[must_use]
    pub const fn record(&self) -> &PublicationRootRecordV1 {
        &self.custody.record
    }

    /// Borrows Linux mechanics without exporting descriptor or path authority.
    pub(crate) const fn mechanics(&self) -> &FsVerityPublicationRoot {
        &self.custody.root
    }
}
