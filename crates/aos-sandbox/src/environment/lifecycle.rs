//! Dormant environment activation, lease, retention, and history contracts.
//!
//! Activation records select immutable generation identities only. They do not
//! expose a store path, garbage-collector operation, runtime handle, or permit
//! a caller to change the currently active environment.

use std::collections::BTreeMap;

use aos_sandbox_core::{
    ExecutionId, ObjectDescriptor, ObjectDigest, ProjectId, ResourceId, Revision, SandboxId,
    SnapshotId, ViewId,
};
use sha2::{Digest as _, Sha256};

use super::{
    environment_manifest_digest_v1, EnvironmentGenerationManifestV1, EnvironmentManifestDigestV1,
    EnvironmentModelError, MAXIMUM_ENVIRONMENT_INPUTS,
};

/// Selects one exact immutable environment generation and facade view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSelectorV1 {
    manifest_record: EnvironmentGenerationManifestV1,
    generation: Revision,
    manifest: EnvironmentManifestDigestV1,
    view: ViewId,
    view_revision: Revision,
    view_descriptor: ObjectDescriptor,
    closure: Vec<ObjectDescriptor>,
}

impl EnvironmentSelectorV1 {
    /// Derives a selector from one canonical, replay-validatable manifest.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] if canonical manifest encoding cannot
    /// be allocated within its fixed ceiling.
    pub fn from_manifest(
        manifest: &EnvironmentGenerationManifestV1,
    ) -> Result<Self, EnvironmentModelError> {
        let facade = manifest.facade();
        let mut closure = Vec::new();
        closure
            .try_reserve_exact(manifest.environment().closure().len())
            .map_err(|_| EnvironmentModelError::Allocation)?;
        closure.extend_from_slice(manifest.environment().closure());
        Ok(Self {
            manifest_record: manifest.clone(),
            generation: manifest.generation(),
            manifest: environment_manifest_digest_v1(manifest)?,
            view: facade.view(),
            view_revision: facade.revision(),
            view_descriptor: facade.descriptor().clone(),
            closure,
        })
    }

    /// Returns the selected immutable generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }

    /// Returns the exact generation-manifest commitment.
    #[must_use]
    pub const fn manifest(&self) -> EnvironmentManifestDigestV1 {
        self.manifest
    }

    /// Borrows the canonical manifest from which every selector field derives.
    #[must_use]
    pub const fn manifest_record(&self) -> &EnvironmentGenerationManifestV1 {
        &self.manifest_record
    }

    /// Returns the exact facade view identity.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.view
    }

    /// Returns the exact immutable facade revision.
    #[must_use]
    pub const fn view_revision(&self) -> Revision {
        self.view_revision
    }

    /// Borrows the exact facade descriptor.
    #[must_use]
    pub const fn view_descriptor(&self) -> &ObjectDescriptor {
        &self.view_descriptor
    }

    /// Borrows the complete immutable closure selected by the manifest.
    #[must_use]
    pub fn closure(&self) -> &[ObjectDescriptor] {
        &self.closure
    }
}

/// Names the immutable consumer protected by an environment lease.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EnvironmentLeaseConsumerV1 {
    /// An admitted execution still references the generation.
    Execution(ExecutionId),
    /// A portable snapshot still references the generation.
    Snapshot(SnapshotId),
}

/// Selects whether an environment generation lease still retains its object.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EnvironmentGenerationLeaseStatusV1 {
    /// The lease is current only in its exact recorded boot.
    Active = 1,
    /// Boot rollover invalidated the prior-boot deadline fail closed.
    Invalidated = 2,
}

/// Carries one bounded monotonic lease observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentLeaseTimeV1(u64);

impl EnvironmentLeaseTimeV1 {
    /// Constructs a non-sentinel monotonic observation.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for zero or `u64::MAX`.
    pub fn new(value: u64) -> Result<Self, EnvironmentModelError> {
        if value == 0 || value == u64::MAX {
            Err(EnvironmentModelError::InvalidModel)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the monotonic observation scalar.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(super) fn from_stored(value: u64) -> Result<Self, EnvironmentModelError> {
        Self::new(value).map_err(|_| EnvironmentModelError::CorruptEncoding)
    }
}

/// Proves the environment journal clock verified a current observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvironmentTrustedTimeV1 {
    boot: EnvironmentBootIdV1,
    observed: EnvironmentLeaseTimeV1,
}

/// Identifies the exact kernel boot in which monotonic lease time is valid.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentBootIdV1(ObjectDigest);

impl EnvironmentBootIdV1 {
    pub(crate) fn from_verified(value: ObjectDigest) -> Result<Self, EnvironmentModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(EnvironmentModelError::InvalidModel)
        } else {
            Ok(Self(value))
        }
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, EnvironmentModelError> {
        Self::from_verified(value).map_err(|_| EnvironmentModelError::CorruptEncoding)
    }

    /// Returns the opaque boot-identity commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

impl EnvironmentTrustedTimeV1 {
    pub(crate) fn from_verified_observation(
        boot: ObjectDigest,
        observed: EnvironmentLeaseTimeV1,
    ) -> Result<Self, EnvironmentModelError> {
        Ok(Self {
            boot: EnvironmentBootIdV1::from_verified(boot)?,
            observed,
        })
    }

    /// Returns the verifier-owned current observation.
    #[must_use]
    pub const fn observed(self) -> EnvironmentLeaseTimeV1 {
        self.observed
    }

    /// Returns the verified kernel-boot identity.
    #[must_use]
    pub const fn boot(self) -> EnvironmentBootIdV1 {
        self.boot
    }
}

/// Retains one bounded execution or snapshot environment lease.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentGenerationLeaseV1 {
    consumer: EnvironmentLeaseConsumerV1,
    generation: Revision,
    lease: ResourceId,
    revision: Revision,
    boot: EnvironmentBootIdV1,
    observed_at: EnvironmentLeaseTimeV1,
    expires_at: u64,
    status: EnvironmentGenerationLeaseStatusV1,
    closed_at: Option<EnvironmentLeaseTimeV1>,
    predecessor_boot: Option<EnvironmentBootIdV1>,
}

impl EnvironmentGenerationLeaseV1 {
    /// Constructs a non-authorizing lease record.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for sentinel fields.
    pub fn new(
        consumer: EnvironmentLeaseConsumerV1,
        generation: Revision,
        lease: ResourceId,
        expires_at: u64,
        current: &EnvironmentTrustedTimeV1,
    ) -> Result<Self, EnvironmentModelError> {
        let observed_at = current.observed();
        let consumer_valid = match consumer {
            EnvironmentLeaseConsumerV1::Execution(id) => id.as_bytes() != &[0; 16],
            EnvironmentLeaseConsumerV1::Snapshot(id) => id.as_bytes() != &[0; 16],
        };
        if !consumer_valid
            || generation.get() == 0
            || generation.get() == u64::MAX
            || lease.as_bytes() == &[0; 16]
            || expires_at == 0
            || expires_at == u64::MAX
            || expires_at <= observed_at.get()
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(Self {
            consumer,
            generation,
            lease,
            revision: Revision::new(1),
            boot: current.boot(),
            observed_at,
            expires_at,
            status: EnvironmentGenerationLeaseStatusV1::Active,
            closed_at: None,
            predecessor_boot: None,
        })
    }

    /// Renews this exact lease before its current deadline.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for a stale revision,
    /// expired lease, non-monotone observation, or non-increasing expiry.
    pub fn renew(
        self,
        expected_revision: Revision,
        expires_at: u64,
        current: &EnvironmentTrustedTimeV1,
    ) -> Result<Self, EnvironmentModelError> {
        let observed_at = current.observed();
        if self.status != EnvironmentGenerationLeaseStatusV1::Active
            || expected_revision != self.revision
            || current.boot() != self.boot
            || observed_at <= self.observed_at
            || observed_at.get() >= self.expires_at
            || expires_at <= self.expires_at
            || expires_at <= observed_at.get()
            || expires_at == u64::MAX
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(Self {
            revision: self
                .revision
                .checked_next()
                .map_err(|_| EnvironmentModelError::InvalidModel)?,
            observed_at,
            expires_at,
            ..self
        })
    }

    /// Invalidates a prior-boot active lease under authenticated rollover.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] unless this is the
    /// immediate successor of an active lease from an authenticated predecessor
    /// boot and the new observation belongs to the authority's current boot.
    pub fn invalidate_after_boot_rollover(
        self,
        expected_revision: Revision,
        current: &EnvironmentTrustedTimeV1,
        rollover: &super::EnvironmentBootRolloverAuthorityV1,
    ) -> Result<Self, EnvironmentModelError> {
        if self.status != EnvironmentGenerationLeaseStatusV1::Active
            || expected_revision != self.revision
            || current.boot() != rollover.current()
            || !rollover.accepts_predecessor(self.boot)
            || current.boot() == self.boot
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(Self {
            revision: self
                .revision
                .checked_next()
                .map_err(|_| EnvironmentModelError::InvalidModel)?,
            boot: current.boot(),
            observed_at: current.observed(),
            status: EnvironmentGenerationLeaseStatusV1::Invalidated,
            closed_at: Some(current.observed()),
            predecessor_boot: Some(self.boot),
            ..self
        })
    }

    pub(super) fn from_stored(
        consumer: EnvironmentLeaseConsumerV1,
        generation: Revision,
        lease: ResourceId,
        revision: Revision,
        boot: EnvironmentBootIdV1,
        observed_at: EnvironmentLeaseTimeV1,
        expires_at: u64,
        status: EnvironmentGenerationLeaseStatusV1,
        closed_at: Option<EnvironmentLeaseTimeV1>,
        predecessor_boot: Option<EnvironmentBootIdV1>,
    ) -> Result<Self, EnvironmentModelError> {
        let consumer_valid = match consumer {
            EnvironmentLeaseConsumerV1::Execution(id) => id.as_bytes() != &[0; 16],
            EnvironmentLeaseConsumerV1::Snapshot(id) => id.as_bytes() != &[0; 16],
        };
        if !consumer_valid
            || generation.get() == 0
            || generation.get() == u64::MAX
            || lease.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || expires_at == 0
            || expires_at == u64::MAX
            || match status {
                EnvironmentGenerationLeaseStatusV1::Active => {
                    expires_at <= observed_at.get()
                        || closed_at.is_some()
                        || predecessor_boot.is_some()
                }
                EnvironmentGenerationLeaseStatusV1::Invalidated => {
                    closed_at != Some(observed_at)
                        || predecessor_boot.is_none_or(|previous| previous == boot)
                }
            }
        {
            return Err(EnvironmentModelError::CorruptEncoding);
        }
        Ok(Self {
            consumer,
            generation,
            lease,
            revision,
            boot,
            observed_at,
            expires_at,
            status,
            closed_at,
            predecessor_boot,
        })
    }

    /// Returns the retained generation.
    #[must_use]
    pub const fn generation(self) -> Revision {
        self.generation
    }

    /// Returns the protected immutable consumer.
    #[must_use]
    pub const fn consumer(self) -> EnvironmentLeaseConsumerV1 {
        self.consumer
    }

    /// Returns the lease record identity.
    #[must_use]
    pub const fn lease(self) -> ResourceId {
        self.lease
    }

    /// Returns the durable lease revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    /// Returns the exact kernel boot owning this lease deadline.
    #[must_use]
    pub const fn boot(self) -> EnvironmentBootIdV1 {
        self.boot
    }

    /// Returns the trusted observation admitting this lease revision.
    #[must_use]
    pub const fn observed_at(self) -> EnvironmentLeaseTimeV1 {
        self.observed_at
    }

    /// Returns the lease expiry timestamp.
    #[must_use]
    pub const fn expires_at(self) -> u64 {
        self.expires_at
    }

    /// Returns the durable lease status.
    #[must_use]
    pub const fn status(self) -> EnvironmentGenerationLeaseStatusV1 {
        self.status
    }

    /// Returns the exact current-boot invalidation observation.
    #[must_use]
    pub const fn closed_at(self) -> Option<EnvironmentLeaseTimeV1> {
        self.closed_at
    }

    /// Returns the authenticated predecessor boot invalidated by this record.
    #[must_use]
    pub const fn predecessor_boot(self) -> Option<EnvironmentBootIdV1> {
        self.predecessor_boot
    }
}

/// Retains one durable garbage-collection-root acknowledgement.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentGcRootAcknowledgementV1 {
    generation: Revision,
    descriptor: ObjectDescriptor,
    root: ResourceId,
    revision: Revision,
    receipt: ObjectDigest,
}

impl EnvironmentGcRootAcknowledgementV1 {
    /// Constructs an exact non-secret GC-root acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for sentinel fields.
    pub fn new(
        generation: Revision,
        descriptor: ObjectDescriptor,
        root: ResourceId,
        revision: Revision,
        receipt: ObjectDigest,
    ) -> Result<Self, EnvironmentModelError> {
        if generation.get() == 0
            || generation.get() == u64::MAX
            || descriptor.digest().as_bytes() == &[0; 32]
            || root.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || receipt.as_bytes() == &[0; 32]
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(Self {
            generation,
            descriptor,
            root,
            revision,
            receipt,
        })
    }

    /// Returns the rooted generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }

    /// Borrows the exact closure object retained by the root.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Returns the garbage-collection-root identity.
    #[must_use]
    pub const fn root(&self) -> ResourceId {
        self.root
    }

    /// Returns the durable acknowledgement receipt.
    #[must_use]
    pub const fn receipt(&self) -> ObjectDigest {
        self.receipt
    }

    /// Returns the durable root-record revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

/// Selects a monotone environment-activation phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EnvironmentActivationPhaseV1 {
    /// Desired selection and predecessor are durable.
    Desired = 1,
    /// New generation roots and leases are durable.
    Prepared = 2,
    /// Current selection atomically changed to desired.
    Committed = 3,
    /// Runtime observation confirms the current selection.
    Observed = 4,
    /// Unreferenced predecessor generations were released.
    Released = 5,
}

/// Stores one complete environment activation transaction snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentActivationTransactionV1 {
    transaction: ResourceId,
    project: ProjectId,
    sandbox: SandboxId,
    revision: Revision,
    predecessor_record: Option<ObjectDigest>,
    desired: EnvironmentSelectorV1,
    current: Option<EnvironmentSelectorV1>,
    observed: Option<EnvironmentSelectorV1>,
    leases: Vec<EnvironmentGenerationLeaseV1>,
    gc_roots: Vec<EnvironmentGcRootAcknowledgementV1>,
    retained_old_generations: Vec<EnvironmentSelectorV1>,
    phase: EnvironmentActivationPhaseV1,
}

impl EnvironmentActivationTransactionV1 {
    /// Constructs a bounded, internally coherent activation record.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for broken lineage,
    /// selector state, non-canonical evidence, or premature old-generation release.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction: ResourceId,
        project: ProjectId,
        sandbox: SandboxId,
        revision: Revision,
        predecessor_record: Option<ObjectDigest>,
        desired: EnvironmentSelectorV1,
        current: Option<EnvironmentSelectorV1>,
        observed: Option<EnvironmentSelectorV1>,
        leases: Vec<EnvironmentGenerationLeaseV1>,
        gc_roots: Vec<EnvironmentGcRootAcknowledgementV1>,
        retained_old_generations: Vec<EnvironmentSelectorV1>,
        phase: EnvironmentActivationPhaseV1,
        current_time: &EnvironmentTrustedTimeV1,
    ) -> Result<Self, EnvironmentModelError> {
        let value = Self::from_stored(
            transaction,
            project,
            sandbox,
            revision,
            predecessor_record,
            desired,
            current,
            observed,
            leases,
            gc_roots,
            retained_old_generations,
            phase,
        )?;
        value.validate_current_leases(current_time)?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_stored(
        transaction: ResourceId,
        project: ProjectId,
        sandbox: SandboxId,
        revision: Revision,
        predecessor_record: Option<ObjectDigest>,
        desired: EnvironmentSelectorV1,
        current: Option<EnvironmentSelectorV1>,
        observed: Option<EnvironmentSelectorV1>,
        leases: Vec<EnvironmentGenerationLeaseV1>,
        gc_roots: Vec<EnvironmentGcRootAcknowledgementV1>,
        retained_old_generations: Vec<EnvironmentSelectorV1>,
        phase: EnvironmentActivationPhaseV1,
    ) -> Result<Self, EnvironmentModelError> {
        let bounded = leases.len() <= MAXIMUM_ENVIRONMENT_INPUTS
            && gc_roots.len() <= MAXIMUM_ENVIRONMENT_INPUTS
            && retained_old_generations.len() <= MAXIMUM_ENVIRONMENT_INPUTS;
        let canonical = leases.windows(2).all(|pair| pair[0] < pair[1])
            && leases.iter().all(|lease| {
                std::iter::once(&desired)
                    .chain(current.iter())
                    .chain(observed.iter())
                    .chain(retained_old_generations.iter())
                    .any(|selector| selector.generation() == lease.generation())
            })
            && gc_roots.windows(2).all(|pair| pair[0] < pair[1])
            && retained_old_generations
                .windows(2)
                .all(|pair| pair[0].generation() < pair[1].generation())
            && retained_old_generations
                .iter()
                .all(|old| old.generation() < desired.generation());
        let desired_roots = gc_roots
            .iter()
            .filter(|acknowledgement| acknowledgement.generation() == desired.generation());
        let desired_rooted = desired_roots.clone().count() == desired.closure().len()
            && desired.closure().iter().all(|descriptor| {
                desired_roots
                    .clone()
                    .any(|acknowledgement| acknowledgement.descriptor() == descriptor)
            });
        let selector_roots_are_complete = std::iter::once(&desired)
            .chain(current.iter())
            .chain(observed.iter())
            .chain(retained_old_generations.iter())
            .all(|selector| {
                let root_count = gc_roots
                    .iter()
                    .filter(|root| root.generation() == selector.generation())
                    .count();
                root_count == 0
                    || (root_count == selector.closure().len()
                        && selector.closure().iter().all(|descriptor| {
                            gc_roots.iter().any(|root| {
                                root.generation() == selector.generation()
                                    && root.descriptor() == descriptor
                            })
                        }))
            });
        let roots_name_selected_descriptors = gc_roots.iter().all(|root| {
            std::iter::once(&desired)
                .chain(current.iter())
                .chain(observed.iter())
                .chain(retained_old_generations.iter())
                .any(|selector| {
                    selector.generation() == root.generation()
                        && selector.closure().binary_search(root.descriptor()).is_ok()
                })
        });
        let protected_old = retained_old_generations.iter().all(|old| {
            leases.iter().any(|lease| {
                lease.generation() == old.generation()
                    && lease.status() == EnvironmentGenerationLeaseStatusV1::Active
            }) || old.closure().iter().all(|descriptor| {
                gc_roots.iter().any(|root| {
                    root.generation() == old.generation() && root.descriptor() == descriptor
                })
            })
        });
        let admitted_old_retained = current.as_ref().is_none_or(|selected| {
            selected == &desired || retained_old_generations.iter().any(|old| old == selected)
        });
        let selectors_scoped = std::iter::once(&desired)
            .chain(current.iter())
            .chain(observed.iter())
            .chain(retained_old_generations.iter())
            .all(|selector| {
                selector.manifest_record().project() == project
                    && selector.manifest_record().sandbox() == sandbox
            });
        let selectors = match phase {
            EnvironmentActivationPhaseV1::Desired => {
                observed == current && current.as_ref() != Some(&desired)
            }
            EnvironmentActivationPhaseV1::Prepared => {
                current.as_ref() != Some(&desired) && observed == current && desired_rooted
            }
            EnvironmentActivationPhaseV1::Committed => {
                current.as_ref() == Some(&desired)
                    && observed.as_ref() != Some(&desired)
                    && desired_rooted
            }
            EnvironmentActivationPhaseV1::Observed => {
                current.as_ref() == Some(&desired)
                    && observed.as_ref() == Some(&desired)
                    && desired_rooted
            }
            EnvironmentActivationPhaseV1::Released => {
                current.as_ref() == Some(&desired)
                    && observed.as_ref() == Some(&desired)
                    && desired_rooted
                    && retained_old_generations.is_empty()
                    && leases
                        .iter()
                        .all(|lease| lease.generation() == desired.generation())
                    && gc_roots
                        .iter()
                        .all(|root| root.generation() == desired.generation())
            }
        };
        if transaction.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || (revision.get() == 1) != predecessor_record.is_none()
            || !bounded
            || !canonical
            || !selector_roots_are_complete
            || !roots_name_selected_descriptors
            || !protected_old
            || !admitted_old_retained
            || !selectors_scoped
            || !selectors
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        let value = Self {
            transaction,
            project,
            sandbox,
            revision,
            predecessor_record,
            desired,
            current,
            observed,
            leases,
            gc_roots,
            retained_old_generations,
            phase,
        };
        super::activation_format::activation_encoded_length(&value)?;
        Ok(value)
    }

    pub(super) fn validate_current_leases(
        &self,
        current_time: &EnvironmentTrustedTimeV1,
    ) -> Result<(), EnvironmentModelError> {
        let current = current_time.observed();
        if self.leases.iter().any(|lease| match lease.status() {
            EnvironmentGenerationLeaseStatusV1::Active => {
                lease.boot() != current_time.boot()
                    || lease.observed_at() > current
                    || lease.expires_at() <= current.get()
            }
            EnvironmentGenerationLeaseStatusV1::Invalidated => false,
        }) {
            Err(EnvironmentModelError::InvalidModel)
        } else {
            Ok(())
        }
    }

    pub(super) fn validate_current_leases_with_rollover(
        &self,
        current_time: &EnvironmentTrustedTimeV1,
        rollover: &super::EnvironmentBootRolloverAuthorityV1,
    ) -> Result<(), EnvironmentModelError> {
        self.validate_current_leases(current_time)?;
        self.validate_authenticated_lease_boots(rollover)
    }

    pub(super) fn validate_authenticated_lease_boots(
        &self,
        rollover: &super::EnvironmentBootRolloverAuthorityV1,
    ) -> Result<(), EnvironmentModelError> {
        if self.leases.iter().any(|lease| {
            let recorded_boot = lease.boot();
            let recorded_is_authenticated = rollover.authenticates(recorded_boot);
            let invalidation_is_authenticated = lease.status()
                != EnvironmentGenerationLeaseStatusV1::Invalidated
                || lease
                    .predecessor_boot()
                    .is_some_and(|boot| boot != recorded_boot && rollover.authenticates(boot));
            !recorded_is_authenticated || !invalidation_is_authenticated
        }) {
            Err(EnvironmentModelError::InvalidModel)
        } else {
            Ok(())
        }
    }

    /// Returns the owning sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the activation transaction identity.
    #[must_use]
    pub const fn transaction(&self) -> ResourceId {
        self.transaction
    }

    /// Returns the owning project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the record revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the predecessor record commitment.
    #[must_use]
    pub const fn predecessor_record(&self) -> Option<ObjectDigest> {
        self.predecessor_record
    }

    /// Borrows the exact desired selector.
    #[must_use]
    pub const fn desired(&self) -> &EnvironmentSelectorV1 {
        &self.desired
    }

    /// Borrows the durable current selector, when published.
    #[must_use]
    pub const fn current(&self) -> Option<&EnvironmentSelectorV1> {
        self.current.as_ref()
    }

    /// Borrows the latest runtime-observed selector.
    #[must_use]
    pub const fn observed(&self) -> Option<&EnvironmentSelectorV1> {
        self.observed.as_ref()
    }

    /// Borrows all active execution and snapshot leases.
    #[must_use]
    pub fn leases(&self) -> &[EnvironmentGenerationLeaseV1] {
        &self.leases
    }

    /// Borrows the exact durable GC-root acknowledgement set.
    #[must_use]
    pub fn gc_roots(&self) -> &[EnvironmentGcRootAcknowledgementV1] {
        &self.gc_roots
    }

    /// Borrows old immutable generations retained across activation.
    #[must_use]
    pub fn retained_old_generations(&self) -> &[EnvironmentSelectorV1] {
        &self.retained_old_generations
    }

    /// Returns the durable activation phase.
    #[must_use]
    pub const fn phase(&self) -> EnvironmentActivationPhaseV1 {
        self.phase
    }
}

/// Replays activation records by sandbox without dispatching activation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentActivationHistoryV1 {
    pub(super) latest: BTreeMap<SandboxId, EnvironmentActivationTransactionV1>,
    pub(super) records: BTreeMap<(SandboxId, Revision), EnvironmentActivationTransactionV1>,
    pub(super) floors: BTreeMap<SandboxId, Revision>,
    pub(super) retained_bytes: usize,
}

/// Stores a replay-validated activation history at a compaction boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentActivationCheckpointV1 {
    pub(super) history: EnvironmentActivationHistoryV1,
    pub(super) digest: ObjectDigest,
    pub(super) accepted_record: Option<ObjectDigest>,
}

/// Maximum activation records accepted in one replay window.
pub const MAXIMUM_ENVIRONMENT_ACTIVATION_RECORDS: usize = 262_144;
/// Maximum canonical activation bytes accepted in one replay window.
pub const MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES: usize = 512 * 1024 * 1024;

impl EnvironmentActivationHistoryV1 {
    /// Replays canonical activation records against retained manifest history.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] for malformed records, lineage
    /// conflicts, or fixed count and aggregate-byte ceiling exhaustion.
    pub fn replay(
        records: super::EnvironmentAcceptedRecordSetV1,
        manifests: &super::EnvironmentGenerationHistoryV1,
        verifier: &super::EnvironmentJournalVerifierV1,
    ) -> Result<Self, EnvironmentModelError> {
        let mut history = Self::default();
        history.replay_suffix(records, manifests, verifier)?;
        Ok(history)
    }

    /// Replays a bounded suffix after a trusted materialized checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] under the same conditions as
    /// [`Self::replay`].
    pub fn replay_after(
        checkpoint: &EnvironmentActivationCheckpointV1,
        records: super::EnvironmentAcceptedRecordSetV1,
        manifests: &super::EnvironmentGenerationHistoryV1,
        verifier: &super::EnvironmentJournalVerifierV1,
    ) -> Result<Self, EnvironmentModelError> {
        let accepted = checkpoint
            .accepted_record
            .filter(|digest| verifier.accepts_checkpoint(*digest))
            .ok_or(EnvironmentModelError::InvalidModel)?;
        if accepted.as_bytes() == &[0; 32] {
            return Err(EnvironmentModelError::InvalidModel);
        }
        let mut history = checkpoint.restore()?;
        history.replay_suffix(records, manifests, verifier)?;
        Ok(history)
    }

    fn replay_suffix(
        &mut self,
        records: super::EnvironmentAcceptedRecordSetV1,
        manifests: &super::EnvironmentGenerationHistoryV1,
        verifier: &super::EnvironmentJournalVerifierV1,
    ) -> Result<(), EnvironmentModelError> {
        let mut count = 0_usize;
        let mut total = 0_usize;
        for accepted in records.into_kind(
            super::EnvironmentJournalRecordKindV1::Activation,
            Some(verifier.authority()),
        )? {
            let encoded = accepted.payload();
            count = count
                .checked_add(1)
                .ok_or(EnvironmentModelError::InvalidModel)?;
            total = total
                .checked_add(encoded.len())
                .ok_or(EnvironmentModelError::InvalidModel)?;
            if count > MAXIMUM_ENVIRONMENT_ACTIVATION_RECORDS
                || total > MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES
            {
                return Err(EnvironmentModelError::InvalidModel);
            }
            let record =
                super::activation_format::decode_environment_activation_v1(encoded, manifests)?;
            let ownership = accepted.ownership();
            if ownership.project() != record.project()
                || ownership.sandbox() != record.sandbox()
                || ownership.revision() != record.revision()
            {
                return Err(EnvironmentModelError::InvalidModel);
            }
            self.apply_stored(record, Some(verifier.boot_rollover()))?;
        }
        for record in self.records.values() {
            record.validate_authenticated_lease_boots(verifier.boot_rollover())?;
        }
        for record in self.latest.values() {
            record.validate_current_leases_with_rollover(
                &verifier.current_time(),
                verifier.boot_rollover(),
            )?;
        }
        Ok(())
    }

    /// Captures a trusted materialized activation checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] if a retained canonical activation
    /// record cannot be represented or allocated within the fixed ceiling.
    pub fn checkpoint(&self) -> Result<EnvironmentActivationCheckpointV1, EnvironmentModelError> {
        Ok(EnvironmentActivationCheckpointV1 {
            history: self.clone(),
            digest: activation_history_digest(self)?,
            accepted_record: None,
        })
    }

    /// Compacts one sandbox only through its exact current record.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for an unknown sandbox,
    /// a stale/regressing floor, or a floor that is not the current record.
    pub(super) fn compact_through(
        &mut self,
        sandbox: SandboxId,
        floor: Revision,
    ) -> Result<(), EnvironmentModelError> {
        let latest = self
            .latest
            .get(&sandbox)
            .ok_or(EnvironmentModelError::InvalidModel)?;
        if latest.revision() != floor
            || self
                .floors
                .get(&sandbox)
                .is_some_and(|previous| floor <= *previous)
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        self.records
            .retain(|(owner, revision), _| *owner != sandbox || *revision == floor);
        self.retained_bytes = retained_activation_bytes(&self.records)?;
        self.floors.insert(sandbox, floor);
        Ok(())
    }
    /// Returns the latest validated activation record for a sandbox.
    #[must_use]
    pub fn latest(&self, sandbox: SandboxId) -> Option<&EnvironmentActivationTransactionV1> {
        self.latest.get(&sandbox)
    }

    /// Returns one exact retained activation revision.
    #[must_use]
    pub fn record(
        &self,
        sandbox: SandboxId,
        revision: Revision,
    ) -> Option<&EnvironmentActivationTransactionV1> {
        self.records.get(&(sandbox, revision))
    }

    /// Visits every exact manifest selector retained by current activation state.
    ///
    /// The result includes desired, current, observed, explicitly retained old
    /// generations, and every generation named by an execution or snapshot
    /// lease. Lease-only generations are resolved through the selectors already
    /// carried by the same record, so an unresolvable lease fails closed.
    pub(super) fn retained_manifest_selectors(
        &self,
        sandbox: SandboxId,
    ) -> Result<Option<Vec<&EnvironmentSelectorV1>>, EnvironmentModelError> {
        let Some(record) = self.latest.get(&sandbox) else {
            return Ok(None);
        };
        let mut selectors = Vec::new();
        selectors
            .try_reserve_exact(
                3_usize
                    .checked_add(record.retained_old_generations().len())
                    .ok_or(EnvironmentModelError::InvalidModel)?,
            )
            .map_err(|_| EnvironmentModelError::Allocation)?;
        selectors.push(record.desired());
        selectors.extend(record.current());
        selectors.extend(record.observed());
        selectors.extend(record.retained_old_generations());
        selectors.sort_by_key(|selector| selector.generation());
        selectors.dedup_by_key(|selector| selector.generation());

        let leases_are_resolvable = record.leases().iter().all(|lease| {
            selectors
                .binary_search_by_key(&lease.generation(), |selector| selector.generation())
                .is_ok()
        });
        Ok(leases_are_resolvable.then_some(selectors))
    }

    /// Applies one already decoded activation record to the durable history.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for a forked record or
    /// changed transaction, project, desired selector, or non-monotone phase.
    pub fn apply(
        &mut self,
        accepted: super::EnvironmentAcceptedRecordV1,
        manifests: &super::EnvironmentGenerationHistoryV1,
        verifier: &super::EnvironmentJournalVerifierV1,
    ) -> Result<(), EnvironmentModelError> {
        let ownership = accepted.ownership();
        if ownership.kind() != super::EnvironmentJournalRecordKindV1::Activation
            || ownership.journal_authority() != verifier.authority()
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        let record = super::activation_format::decode_environment_activation_v1(
            accepted.payload(),
            manifests,
        )?;
        if ownership.project() != record.project()
            || ownership.sandbox() != record.sandbox()
            || ownership.revision() != record.revision()
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        record.validate_current_leases_with_rollover(
            &verifier.current_time(),
            verifier.boot_rollover(),
        )?;
        self.apply_stored(record, Some(verifier.boot_rollover()))
    }

    pub(super) fn apply_stored(
        &mut self,
        record: EnvironmentActivationTransactionV1,
        rollover: Option<&super::EnvironmentBootRolloverAuthorityV1>,
    ) -> Result<(), EnvironmentModelError> {
        if self
            .floors
            .get(&record.sandbox)
            .is_some_and(|floor| record.revision <= *floor)
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        if let Some(previous) = self.latest.get(&record.sandbox) {
            let predecessor_digest =
                super::activation_format::environment_activation_digest_v1(previous)?;
            let next = previous
                .revision
                .checked_next()
                .map_err(|_| EnvironmentModelError::InvalidModel)?;
            let same_transaction = record.transaction == previous.transaction;
            let transaction_progress = same_transaction
                && record.project == previous.project
                && record.desired == previous.desired
                && activation_progress_is_monotone(previous, &record, rollover);
            let sequential_activation = !same_transaction
                && previous.phase == EnvironmentActivationPhaseV1::Released
                && record.phase == EnvironmentActivationPhaseV1::Desired
                && record.project == previous.project
                && record.current == previous.current
                && record.observed == previous.observed
                && previous.current.as_ref().is_some_and(|current| {
                    record
                        .retained_old_generations
                        .binary_search_by_key(
                            &current.generation(),
                            EnvironmentSelectorV1::generation,
                        )
                        .is_ok()
                })
                && leases_may_follow(&previous.leases, &record.leases, false)
                && roots_are_retained(&previous.gc_roots, &record.gc_roots);
            if record.revision != next
                || record.predecessor_record != Some(predecessor_digest)
                || (!transaction_progress && !sequential_activation)
            {
                return Err(EnvironmentModelError::InvalidModel);
            }
        } else if record.revision.get() != 1 || record.predecessor_record.is_some() {
            return Err(EnvironmentModelError::InvalidModel);
        }
        let key = (record.sandbox, record.revision);
        let encoded_length = super::activation_format::activation_encoded_length(&record)?;
        let retained_bytes = self
            .retained_bytes
            .checked_add(encoded_length)
            .ok_or(EnvironmentModelError::InvalidModel)?;
        if self.records.len() >= MAXIMUM_ENVIRONMENT_ACTIVATION_RECORDS
            || retained_bytes > MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES
            || self.records.contains_key(&key)
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        self.records.insert(key, record.clone());
        self.latest.insert(record.sandbox, record);
        self.retained_bytes = retained_bytes;
        Ok(())
    }
}

impl EnvironmentActivationCheckpointV1 {
    /// Restores only a checkpoint matching its complete canonical history digest.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] if checkpoint material
    /// was changed after validation.
    pub(super) fn restore(&self) -> Result<EnvironmentActivationHistoryV1, EnvironmentModelError> {
        if activation_history_digest(&self.history)? != self.digest {
            Err(EnvironmentModelError::InvalidModel)
        } else {
            Ok(self.history.clone())
        }
    }

    /// Returns the complete checkpoint commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

pub(super) fn activation_history_digest(
    history: &EnvironmentActivationHistoryV1,
) -> Result<ObjectDigest, EnvironmentModelError> {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.environment-activation-checkpoint.v1\0")
        .chain_update((history.retained_bytes as u64).to_be_bytes());
    for (sandbox, floor) in &history.floors {
        hasher = hasher
            .chain_update(sandbox.as_bytes())
            .chain_update(floor.get().to_be_bytes());
    }
    for ((sandbox, revision), record) in &history.records {
        let encoded = super::activation_format::encode_environment_activation_v1(record)?;
        hasher = hasher
            .chain_update(sandbox.as_bytes())
            .chain_update(revision.get().to_be_bytes())
            .chain_update(
                u64::try_from(encoded.len())
                    .map_err(|_| EnvironmentModelError::InvalidModel)?
                    .to_be_bytes(),
            )
            .chain_update(encoded);
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn retained_activation_bytes(
    records: &BTreeMap<(SandboxId, Revision), EnvironmentActivationTransactionV1>,
) -> Result<usize, EnvironmentModelError> {
    records.values().try_fold(0_usize, |total, record| {
        total
            .checked_add(super::activation_format::activation_encoded_length(record)?)
            .filter(|value| *value <= MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES)
            .ok_or(EnvironmentModelError::InvalidModel)
    })
}

fn activation_progress_is_monotone(
    previous: &EnvironmentActivationTransactionV1,
    successor: &EnvironmentActivationTransactionV1,
    rollover: Option<&super::EnvironmentBootRolloverAuthorityV1>,
) -> bool {
    let phase_edge = successor.phase as u8 == previous.phase as u8
        || successor.phase as u8 == previous.phase as u8 + 1;
    let may_release = successor.phase == EnvironmentActivationPhaseV1::Released;
    let leases_progress = leases_may_follow(&previous.leases, &successor.leases, may_release);
    let roots_retained = may_release || roots_are_retained(&previous.gc_roots, &successor.gc_roots);
    let old_retained = previous.retained_old_generations.iter().all(|old| {
        successor
            .retained_old_generations
            .binary_search_by_key(&old.generation(), EnvironmentSelectorV1::generation)
            .is_ok()
    });
    let selector_progress = previous.current.as_ref().is_none_or(|current| {
        successor.current.as_ref() == Some(current)
            || successor.current.as_ref() == Some(&successor.desired)
    }) && previous.observed.as_ref().is_none_or(|observed| {
        successor.observed.as_ref() == Some(observed)
            || successor.observed.as_ref() == Some(&successor.desired)
    });
    phase_edge
        && selector_progress
        && leases_progress
        && lease_rollovers_are_authorized(&previous.leases, &successor.leases, rollover)
        && roots_retained
        && (may_release || old_retained)
}

fn lease_rollovers_are_authorized(
    previous: &[EnvironmentGenerationLeaseV1],
    successor: &[EnvironmentGenerationLeaseV1],
    rollover: Option<&super::EnvironmentBootRolloverAuthorityV1>,
) -> bool {
    successor.iter().all(|next| {
        let Some(old) = previous.iter().find(|old| old.lease() == next.lease()) else {
            return next.status() == EnvironmentGenerationLeaseStatusV1::Active;
        };
        if next.boot() == old.boot() {
            return next.predecessor_boot().is_none();
        }
        next.status() == EnvironmentGenerationLeaseStatusV1::Invalidated
            && next.predecessor_boot() == Some(old.boot())
            && rollover.is_some_and(|authority| {
                authority.authenticates(next.boot()) && authority.authenticates(old.boot())
            })
    })
}

fn roots_are_retained(
    previous: &[EnvironmentGcRootAcknowledgementV1],
    successor: &[EnvironmentGcRootAcknowledgementV1],
) -> bool {
    previous
        .iter()
        .all(|root| successor.binary_search(root).is_ok())
}

fn leases_may_follow(
    previous: &[EnvironmentGenerationLeaseV1],
    successor: &[EnvironmentGenerationLeaseV1],
    may_release: bool,
) -> bool {
    let mut successor_leases = Vec::new();
    if successor_leases.try_reserve_exact(successor.len()).is_err() {
        return false;
    }
    successor_leases.extend(successor.iter().map(|lease| (lease.lease(), *lease)));
    successor_leases.sort_unstable_by_key(|entry| entry.0);
    if successor_leases
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return false;
    }

    let mut previous_leases = Vec::new();
    if previous_leases.try_reserve_exact(previous.len()).is_err() {
        return false;
    }
    previous_leases.extend(previous.iter().map(|lease| (lease.lease(), *lease)));
    previous_leases.sort_unstable_by_key(|entry| entry.0);
    if previous_leases
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return false;
    }

    previous_leases.iter().all(|(identity, old)| {
        successor_leases
            .binary_search_by_key(identity, |entry| entry.0)
            .ok()
            .map_or(
                may_release || old.status() == EnvironmentGenerationLeaseStatusV1::Invalidated,
                |position| {
                    let new = &successor_leases[position].1;
                    new == old
                        || (new.lease() == old.lease()
                            && new.consumer() == old.consumer()
                            && new.generation() == old.generation()
                            && old
                                .revision()
                                .checked_next()
                                .is_ok_and(|revision| revision == new.revision())
                            && ((old.status() == EnvironmentGenerationLeaseStatusV1::Active
                                && new.status() == EnvironmentGenerationLeaseStatusV1::Active
                                && new.boot() == old.boot()
                                && new.observed_at() > old.observed_at()
                                && new.observed_at().get() < old.expires_at()
                                && new.expires_at() > old.expires_at())
                                || (old.status() == EnvironmentGenerationLeaseStatusV1::Active
                                    && new.status()
                                        == EnvironmentGenerationLeaseStatusV1::Invalidated
                                    && new.boot() != old.boot()
                                    && new.predecessor_boot() == Some(old.boot())
                                    && new.closed_at() == Some(new.observed_at()))))
                },
            )
    }) && successor_leases.iter().all(|(identity, lease)| {
        previous_leases
            .binary_search_by_key(identity, |entry| entry.0)
            .is_ok()
            || lease.revision().get() == 1
    })
}
