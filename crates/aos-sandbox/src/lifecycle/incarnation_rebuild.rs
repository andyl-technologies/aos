//! LIFE-03 fork and restore planning with fresh identity and policy intersection.

use aos_sandbox_core::{
    AssignmentEpoch, AttachmentId, DesiredGeneration, IncarnationId, NamespaceGeneration,
    ObjectDigest, ResourceId, SandboxId, SnapshotId,
};
use sha2::{Digest as _, Sha256};

use super::{
    CurrentLifecycleEffectV1, CurrentLifecycleOperationV1, CurrentLifecycleTargetAssignmentV1,
    LifecycleEffectDomainV1, LifecycleEffectObservationV1, LifecycleIntentV1, LifecycleMethodV1,
    LifecyclePhase6ErrorV1, LifecycleResourceV1, LifecycleSnapshotAvailabilityContractV1,
    LifecycleSnapshotTransferJoinV1, ResourceExpectedStateV1,
};

/// Selects whether a new sandbox is a fork or a restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleRebuildModeV1 {
    /// Creates a distinct child from an immutable snapshot.
    Fork,
    /// Recreates a logical sandbox from a committed snapshot.
    Restore,
    /// Resumes a hibernated sandbox through restore semantics.
    HibernateResume,
}

/// Retains the exact current-policy intersection used for rebuild admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecyclePolicyIntersectionV1 {
    historical_policy: ObjectDigest,
    current_policy: ObjectDigest,
    historical: Vec<ResourceId>,
    current: Vec<ResourceId>,
    effective: Vec<ResourceId>,
    required: Vec<ResourceId>,
    commitment: ObjectDigest,
}

impl LifecyclePolicyIntersectionV1 {
    /// Computes the exact set intersection and rejects required-policy loss.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for noncanonical sets, excessive
    /// policy inputs, or a required capability removed by current policy.
    pub fn intersect(
        historical_policy: ObjectDigest,
        current_policy: ObjectDigest,
        historical: Vec<ResourceId>,
        current: Vec<ResourceId>,
        required: Vec<ResourceId>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if historical_policy.as_bytes() == &[0; 32] || current_policy.as_bytes() == &[0; 32] {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        for values in [&historical, &current, &required] {
            if values.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
                || values.iter().any(|value| value.as_bytes() == &[0; 16])
                || !values.windows(2).all(|pair| pair[0] < pair[1])
            {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        }
        let effective = historical
            .iter()
            .filter(|value| current.binary_search(value).is_ok())
            .copied()
            .collect::<Vec<_>>();
        if required
            .iter()
            .any(|value| effective.binary_search(value).is_err())
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let commitment = policy_intersection_digest(
            historical_policy,
            current_policy,
            &historical,
            &current,
            &effective,
            &required,
        );
        Ok(Self {
            historical_policy,
            current_policy,
            historical,
            current,
            effective,
            required,
            commitment,
        })
    }

    /// Borrows the effective attenuated capability set.
    #[must_use]
    pub fn effective(&self) -> &[ResourceId] {
        &self.effective
    }

    /// Returns the complete current-policy intersection commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }

    /// Returns the immutable historical policy descriptor.
    #[must_use]
    pub const fn historical_policy(&self) -> ObjectDigest {
        self.historical_policy
    }

    /// Returns the current policy descriptor applied at restore.
    #[must_use]
    pub const fn current_policy(&self) -> ObjectDigest {
        self.current_policy
    }
}

/// Reconstructs one attachment without reusing descriptor or lease authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleAttachmentReconstructionV1 {
    source_index: u32,
    attachment: AttachmentId,
    generation: DesiredGeneration,
    immutable_view: ObjectDigest,
    prior_descriptor: ObjectDigest,
    new_descriptor_plan: ObjectDigest,
    prior_lease: ObjectDigest,
    new_lease_plan: ObjectDigest,
}

impl LifecycleAttachmentReconstructionV1 {
    /// Constructs one fresh attachment reconstruction plan.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for sentinel fields or reuse of a
    /// historical descriptor/lease commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_index: u32,
        attachment: AttachmentId,
        generation: DesiredGeneration,
        immutable_view: ObjectDigest,
        prior_descriptor: ObjectDigest,
        new_descriptor_plan: ObjectDigest,
        prior_lease: ObjectDigest,
        new_lease_plan: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if attachment.as_bytes() == &[0; 16]
            || generation.get() == 0
            || generation.get() == u64::MAX
            || [
                immutable_view,
                prior_descriptor,
                new_descriptor_plan,
                prior_lease,
                new_lease_plan,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
            || prior_descriptor == new_descriptor_plan
            || prior_lease == new_lease_plan
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            source_index,
            attachment,
            generation,
            immutable_view,
            prior_descriptor,
            new_descriptor_plan,
            prior_lease,
            new_lease_plan,
        })
    }
}

/// Selects the next fresh-incarnation rebuild action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleRebuildActionV1 {
    /// Clones or restores private storage from immutable snapshot roots.
    RestoreStorage = 1,
    /// Reconstructs every attachment from immutable manifest revisions.
    RebuildAttachments = 2,
    /// Installs the newly intersected policy and fresh leases.
    InstallCurrentPolicy = 3,
    /// Admits the new assignment and incarnation.
    AdmitIncarnation = 4,
    /// The inert rebuild plan is complete.
    Complete = 5,
}

/// Retains a no-reuse fork/restore state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleIncarnationRebuildV1 {
    mode: LifecycleRebuildModeV1,
    snapshot: SnapshotId,
    target: SandboxId,
    old_incarnation: IncarnationId,
    new_incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    namespace_generation: NamespaceGeneration,
    availability: ObjectDigest,
    transfer_completion: ObjectDigest,
    target_state: ObjectDigest,
    policy: LifecyclePolicyIntersectionV1,
    attachments: Vec<LifecycleAttachmentReconstructionV1>,
    operation: aos_sandbox_core::OperationId,
    method_plan: super::LifecycleMethodPlanV1,
    action: LifecycleRebuildActionV1,
}

impl LifecycleIncarnationRebuildV1 {
    /// Builds a method-specific fork/restore plan from fixed-current intent.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for source/target mismatch, reused
    /// incarnation, non-monotone assignment fencing, or incomplete attachment
    /// reconstruction.
    #[allow(clippy::too_many_arguments)]
    pub fn plan(
        current: &CurrentLifecycleOperationV1<'_>,
        availability: &LifecycleSnapshotAvailabilityContractV1,
        transfer: &LifecycleSnapshotTransferJoinV1,
        target_assignment: &CurrentLifecycleTargetAssignmentV1<'_>,
        old_incarnation: IncarnationId,
        new_incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        namespace_generation: NamespaceGeneration,
        policy: LifecyclePolicyIntersectionV1,
        attachments: Vec<LifecycleAttachmentReconstructionV1>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        current.require_method(&[
            LifecycleMethodV1::Fork,
            LifecycleMethodV1::Restore,
            LifecycleMethodV1::Resume,
        ])?;
        let (mode, snapshot, target) = match current.operation().intent() {
            LifecycleIntentV1::Fork { source, target } => {
                (LifecycleRebuildModeV1::Fork, *source, *target)
            }
            LifecycleIntentV1::Restore { snapshot, sandbox } => {
                (LifecycleRebuildModeV1::Restore, *snapshot, *sandbox)
            }
            LifecycleIntentV1::Resume {
                sandbox,
                source: super::LifecycleResumeSourceV1::Hibernated { snapshot, .. },
            } => (LifecycleRebuildModeV1::HibernateResume, *snapshot, *sandbox),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if availability.snapshot() != snapshot
            || availability.projection_root() != current.projection_root()
            || transfer.operation() != current.operation().operation_id()
            || transfer.project() != current.operation().project()
            || transfer.snapshot() != snapshot
            || transfer.lifecycle_manifest() != availability.manifest()
            || transfer.availability() != availability.commitment()
            || transfer.projection_root() != current.projection_root()
            || transfer.completion().is_none()
            || target_assignment.sandbox() != target
            || target_assignment.operation() != current.operation().operation_id()
            || target_assignment.operation_record() != current.record()
            || target_assignment.projection_root() != current.projection_root()
            || policy.historical_policy() != availability.historical_policy()
            || !current
                .operation()
                .expectations()
                .iter()
                .any(|expectation| {
                    expectation.resource()
                        == LifecycleResourceV1::Project(current.operation().project())
                        && matches!(
                            expectation.expected(),
                            ResourceExpectedStateV1::Present { state_digest, .. }
                                if state_digest.digest() == policy.current_policy()
                        )
                })
            || (mode == LifecycleRebuildModeV1::Fork && target == availability.source_sandbox())
            || old_incarnation != availability.source_incarnation()
            || new_incarnation.as_bytes() == &[0; 16]
            || new_incarnation == old_incarnation
            || assignment_epoch.get() <= target_assignment.assignment_epoch().get()
            || assignment_epoch.get() == u64::MAX
            || namespace_generation.get() <= target_assignment.namespace_generation().get()
            || namespace_generation.get() == u64::MAX
            || attachments.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
            || attachments.len() != availability.attachment_views().len()
            || !attachments.windows(2).all(|pair| {
                pair[0].source_index.checked_add(1) == Some(pair[1].source_index)
                    && pair[0].attachment != pair[1].attachment
            })
            || attachments
                .first()
                .is_some_and(|attachment| attachment.source_index != 0)
            || attachments.iter().enumerate().any(|(index, attachment)| {
                attachments[..index]
                    .iter()
                    .any(|prior| prior.attachment == attachment.attachment)
            })
            || attachments
                .iter()
                .zip(availability.attachment_views())
                .any(|(attachment, view)| attachment.immutable_view != *view)
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let method_plan = super::LifecycleMethodPlanV1::from_current(current, 4)?;
        let mut rebuilt = Self {
            mode,
            snapshot,
            target,
            old_incarnation,
            new_incarnation,
            assignment_epoch,
            namespace_generation,
            availability: availability.commitment(),
            transfer_completion: transfer
                .completion()
                .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?,
            target_state: target_assignment.state(),
            policy,
            attachments,
            operation: current.operation().operation_id(),
            method_plan,
            action: LifecycleRebuildActionV1::RestoreStorage,
        };
        rebuilt.validate_method_plan(current)?;
        rebuilt.action = rebuilt.persisted_action(current)?;
        Ok(rebuilt)
    }

    /// Advances after the exact current lower-domain action is observed.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for an out-of-order action or zero
    /// protected observation commitment.
    pub fn observe(
        mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        observation: LifecycleEffectObservationV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request() != self.next_effect(current)?.request() {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.action = match self.action {
            LifecycleRebuildActionV1::RestoreStorage => {
                LifecycleRebuildActionV1::RebuildAttachments
            }
            LifecycleRebuildActionV1::RebuildAttachments => {
                LifecycleRebuildActionV1::InstallCurrentPolicy
            }
            LifecycleRebuildActionV1::InstallCurrentPolicy => {
                LifecycleRebuildActionV1::AdmitIncarnation
            }
            LifecycleRebuildActionV1::AdmitIncarnation => LifecycleRebuildActionV1::Complete,
            LifecycleRebuildActionV1::Complete => {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        };
        Ok(self)
    }

    /// Derives the exact next inert lower-domain request.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for stale current authority or a
    /// completed rebuild.
    pub fn next_effect<'current>(
        &self,
        current: &CurrentLifecycleOperationV1<'current>,
    ) -> Result<CurrentLifecycleEffectV1<'current>, LifecyclePhase6ErrorV1> {
        if current.operation().operation_id() != self.operation {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let domain = match self.action {
            LifecycleRebuildActionV1::RestoreStorage => LifecycleEffectDomainV1::Storage,
            LifecycleRebuildActionV1::RebuildAttachments => LifecycleEffectDomainV1::Mount,
            LifecycleRebuildActionV1::InstallCurrentPolicy => LifecycleEffectDomainV1::Network,
            LifecycleRebuildActionV1::AdmitIncarnation => LifecycleEffectDomainV1::Controller,
            LifecycleRebuildActionV1::Complete => {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        };
        current.recover_reserved_effect(
            domain,
            self.action as u32,
            *self.target.as_bytes(),
            self.target_state,
            rebuild_digest(self),
        )
    }

    fn persisted_action(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<LifecycleRebuildActionV1, LifecyclePhase6ErrorV1> {
        let actions = [
            LifecycleRebuildActionV1::RestoreStorage,
            LifecycleRebuildActionV1::RebuildAttachments,
            LifecycleRebuildActionV1::InstallCurrentPolicy,
            LifecycleRebuildActionV1::AdmitIncarnation,
        ];
        match self.method_plan.cursor_index(current)? {
            Some(index) => {
                let action = *actions
                    .get(index)
                    .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
                self.action = action;
                self.next_effect(current)?;
                Ok(action)
            }
            None if current
                .require_persisted_completion(&[
                    LifecycleMethodV1::Fork,
                    LifecycleMethodV1::Restore,
                    LifecycleMethodV1::Resume,
                ])
                .is_ok_and(|completion| completion.plan() == self.method_plan.commitment()) =>
            {
                Ok(LifecycleRebuildActionV1::Complete)
            }
            None => Err(LifecyclePhase6ErrorV1::InvalidTransition),
        }
    }

    fn validate_method_plan(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        for (index, action) in [
            LifecycleRebuildActionV1::RestoreStorage,
            LifecycleRebuildActionV1::RebuildAttachments,
            LifecycleRebuildActionV1::InstallCurrentPolicy,
            LifecycleRebuildActionV1::AdmitIncarnation,
        ]
        .into_iter()
        .enumerate()
        {
            self.action = action;
            let expected =
                super::LifecycleStepPlanDigestV1::commit(rebuild_digest(self).as_bytes());
            if current.operation().steps()[index].plan() != expected {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        }
        Ok(())
    }
}

fn policy_intersection_digest(
    historical_policy: ObjectDigest,
    current_policy: ObjectDigest,
    historical: &[ResourceId],
    current: &[ResourceId],
    effective: &[ResourceId],
    required: &[ResourceId],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.policy-intersection.v1\0")
        .chain_update(historical_policy.as_bytes())
        .chain_update(current_policy.as_bytes());
    for values in [historical, current, effective, required] {
        hasher = hasher.chain_update((values.len() as u32).to_be_bytes());
        for value in values {
            hasher = hasher.chain_update(value.as_bytes());
        }
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn rebuild_digest(value: &LifecycleIncarnationRebuildV1) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.incarnation-rebuild.v1\0")
        .chain_update([value.mode as u8])
        .chain_update(value.snapshot.as_bytes())
        .chain_update(value.target.as_bytes())
        .chain_update(value.old_incarnation.as_bytes())
        .chain_update(value.new_incarnation.as_bytes())
        .chain_update(value.assignment_epoch.get().to_be_bytes())
        .chain_update(value.namespace_generation.get().to_be_bytes())
        .chain_update(value.availability.as_bytes())
        .chain_update(value.transfer_completion.as_bytes())
        .chain_update(value.target_state.as_bytes())
        .chain_update(value.policy.commitment().as_bytes())
        .chain_update((value.attachments.len() as u32).to_be_bytes());
    for attachment in &value.attachments {
        hasher = hasher
            .chain_update(attachment.source_index.to_be_bytes())
            .chain_update(attachment.attachment.as_bytes())
            .chain_update(attachment.generation.get().to_be_bytes())
            .chain_update(attachment.immutable_view.as_bytes())
            .chain_update(attachment.prior_descriptor.as_bytes())
            .chain_update(attachment.new_descriptor_plan.as_bytes())
            .chain_update(attachment.prior_lease.as_bytes())
            .chain_update(attachment.new_lease_plan.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
