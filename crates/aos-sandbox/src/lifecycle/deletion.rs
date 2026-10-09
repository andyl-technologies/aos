//! LIFE-05 iterative leaf-first deletion, deferred reap, and terminal receipts.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    CurrentLifecycleCoordinationV1, CurrentLifecycleEffectV1, CurrentLifecycleOperationV1,
    LifecycleCascadeTombstonePlanV1, LifecycleEffectDomainV1, LifecycleEffectObservationV1,
    LifecycleEffectRequestV1, LifecycleIntentV1, LifecycleMethodV1, LifecyclePhase6ErrorV1,
    LifecycleResourceV1,
};

/// Selects one ordered cleanup edge for the current postorder resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleDeletionActionV1 {
    /// Atomically revokes new admissions and commits all tombstones.
    RevokeAdmission = 1,
    /// Detaches runtime, mount, and network references.
    Detach = 2,
    /// Waits for descriptors, holds, and writable clones to reach zero.
    Drain = 3,
    /// Releases controller-owned cache and retention pins.
    ReleasePins = 4,
    /// Destroys the now-unreferenced storage object.
    DestroyStorage = 5,
    /// Publishes the exact per-resource reap record.
    Reap = 6,
    /// Cleanup is durably deferred with its cursor preserved.
    Deferred = 7,
    /// Every resource has a terminal reap receipt.
    Complete = 8,
}

/// Carries one protected lower-domain deletion observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleDeletionObservationV1 {
    request: LifecycleEffectRequestV1,
    action: LifecycleDeletionActionV1,
    resource: LifecycleResourceV1,
    drain_readback: Option<ObjectDigest>,
    receipt: ObjectDigest,
}

impl LifecycleDeletionObservationV1 {
    fn from_domain_readback(
        observation: LifecycleEffectObservationV1,
        action: LifecycleDeletionActionV1,
        resource: LifecycleResourceV1,
        drain_readback: Option<ObjectDigest>,
        receipt: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if matches!(
            action,
            LifecycleDeletionActionV1::Deferred | LifecycleDeletionActionV1::Complete
        ) || receipt.as_bytes() == &[0; 32]
            || (action == LifecycleDeletionActionV1::Drain)
                != drain_readback.is_some_and(|value| value.as_bytes() != &[0; 32])
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            request: observation.request(),
            action,
            resource,
            drain_readback,
            receipt,
        })
    }

    pub(crate) fn from_mount_detach(
        observation: LifecycleEffectObservationV1,
        resource: LifecycleResourceV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request().domain() != LifecycleEffectDomainV1::Mount
            || observation.request().target() != *resource.as_bytes()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Self::from_domain_readback(
            observation,
            LifecycleDeletionActionV1::Detach,
            resource,
            None,
            observation.result(),
        )
    }

    pub(crate) fn from_runtime_drain(
        observation: LifecycleEffectObservationV1,
        resource: LifecycleResourceV1,
        drain_readback: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request().domain() != LifecycleEffectDomainV1::Runtime
            || observation.request().target() != *resource.as_bytes()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Self::from_domain_readback(
            observation,
            LifecycleDeletionActionV1::Drain,
            resource,
            Some(drain_readback),
            observation.result(),
        )
    }

    pub(crate) fn from_cache_release(
        observation: LifecycleEffectObservationV1,
        resource: LifecycleResourceV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request().domain() != LifecycleEffectDomainV1::Cache
            || observation.request().target() != *resource.as_bytes()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Self::from_domain_readback(
            observation,
            LifecycleDeletionActionV1::ReleasePins,
            resource,
            None,
            observation.result(),
        )
    }

    pub(crate) fn from_storage_destroy(
        observation: LifecycleEffectObservationV1,
        resource: LifecycleResourceV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request().domain() != LifecycleEffectDomainV1::Storage
            || observation.request().target() != *resource.as_bytes()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Self::from_domain_readback(
            observation,
            LifecycleDeletionActionV1::DestroyStorage,
            resource,
            None,
            observation.result(),
        )
    }

    pub(crate) fn from_controller_commit(
        observation: LifecycleEffectObservationV1,
        action: LifecycleDeletionActionV1,
        resource: LifecycleResourceV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request().domain() != LifecycleEffectDomainV1::Controller
            || observation.request().target() != *resource.as_bytes()
            || !matches!(
                action,
                LifecycleDeletionActionV1::RevokeAdmission | LifecycleDeletionActionV1::Reap
            )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Self::from_domain_readback(observation, action, resource, None, observation.result())
    }
}

/// Commits the complete leaf-first cleanup result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleDeletionReceiptV1 {
    plan: ObjectDigest,
    final_reap: ObjectDigest,
    deleted_resources: u32,
    receipt: ObjectDigest,
}

impl LifecycleDeletionReceiptV1 {
    /// Returns the protected cascade-plan commitment.
    #[must_use]
    pub const fn plan(self) -> ObjectDigest {
        self.plan
    }

    /// Returns the final root-resource reap receipt.
    #[must_use]
    pub const fn final_reap(self) -> ObjectDigest {
        self.final_reap
    }

    /// Returns the complete terminal deletion commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.receipt
    }

    /// Returns the exact number of leaf-first resources reaped.
    #[must_use]
    pub const fn deleted_resources(self) -> u32 {
        self.deleted_resources
    }
}

/// Retains an iterative, restartable deletion cursor over a protected postorder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleDeletionPlanV1 {
    plan: LifecycleCascadeTombstonePlanV1,
    operation: aos_sandbox_core::OperationId,
    method_plan: super::LifecycleMethodPlanV1,
    cascade: bool,
    cursor: usize,
    action: LifecycleDeletionActionV1,
    reap_receipts: Vec<ObjectDigest>,
    deferred: Option<super::LifecycleDeferredEffectCursorV1>,
}

impl LifecycleDeletionPlanV1 {
    /// Starts deletion from a protected, dependency-complete tombstone plan.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless method and root resource match,
    /// or when non-cascade deletion still has dependents.
    pub fn start(
        current: &CurrentLifecycleOperationV1<'_>,
        coordination: &CurrentLifecycleCoordinationV1<'_>,
        plan: LifecycleCascadeTombstonePlanV1,
        cascade: bool,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        current.require_method(&[
            LifecycleMethodV1::DeleteSandbox,
            LifecycleMethodV1::DeleteSnapshot,
        ])?;
        let root = match current.operation().intent() {
            LifecycleIntentV1::DeleteSandbox { sandbox, .. } => {
                LifecycleResourceV1::Sandbox(*sandbox)
            }
            LifecycleIntentV1::DeleteSnapshot { snapshot, .. } => {
                LifecycleResourceV1::Snapshot(*snapshot)
            }
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if coordination.projection_root() != current.projection_root()
            || !plan.is_bound_to(coordination.coordination())
            || plan.postorder().last().copied() != Some(root)
            || (!cascade && (plan.postorder().len() != 1 || !plan.dependency_edges().is_empty()))
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut reap_receipts = Vec::new();
        reap_receipts
            .try_reserve_exact(plan.postorder().len())
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        let expected_steps = plan
            .postorder()
            .len()
            .checked_mul(6)
            .ok_or(LifecyclePhase6ErrorV1::Capacity)?;
        let method_plan = super::LifecycleMethodPlanV1::from_current(current, expected_steps)?;
        let mut deletion = Self {
            plan,
            operation: current.operation().operation_id(),
            method_plan,
            cascade,
            cursor: 0,
            action: LifecycleDeletionActionV1::RevokeAdmission,
            reap_receipts,
            deferred: None,
        };
        deletion.validate_method_plan(current)?;
        deletion.restore_persisted_cursor(current)?;
        Ok(deletion)
    }

    /// Returns the next leaf-first resource and its cleanup edge.
    #[must_use]
    pub fn next(&self) -> Option<(LifecycleResourceV1, LifecycleDeletionActionV1)> {
        self.plan
            .postorder()
            .get(self.cursor)
            .copied()
            .map(|resource| (resource, self.action))
    }

    /// Advances from an exact protected observation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for substitution, out-of-order
    /// completion, or an attempted pin/storage release before complete drain.
    pub fn observe(
        mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        observation: LifecycleDeletionObservationV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let resource = self
            .plan
            .postorder()
            .get(self.cursor)
            .copied()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        if observation.request != self.next_effect(current)?.request()
            || observation.resource != resource
            || observation.action != self.action
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        if self.action == LifecycleDeletionActionV1::Drain
            && observation
                .drain_readback
                .is_none_or(|readback| readback.as_bytes() == &[0; 32])
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.action = match self.action {
            LifecycleDeletionActionV1::RevokeAdmission => LifecycleDeletionActionV1::Detach,
            LifecycleDeletionActionV1::Detach => LifecycleDeletionActionV1::Drain,
            LifecycleDeletionActionV1::Drain => LifecycleDeletionActionV1::ReleasePins,
            LifecycleDeletionActionV1::ReleasePins => LifecycleDeletionActionV1::DestroyStorage,
            LifecycleDeletionActionV1::DestroyStorage => LifecycleDeletionActionV1::Reap,
            LifecycleDeletionActionV1::Reap => {
                self.reap_receipts.push(
                    super::LifecycleStepResultDigestV1::commit(observation.receipt.as_bytes())
                        .digest(),
                );
                self.cursor += 1;
                if self.cursor == self.plan.postorder().len() {
                    LifecycleDeletionActionV1::Complete
                } else {
                    LifecycleDeletionActionV1::RevokeAdmission
                }
            }
            LifecycleDeletionActionV1::Deferred | LifecycleDeletionActionV1::Complete => {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        };
        Ok(self)
    }

    /// Defers an indeterminate cleanup without losing the exact cursor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for terminal state or a zero reason.
    pub fn defer(
        mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        reason: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if self.action == LifecycleDeletionActionV1::Complete || reason.as_bytes() == &[0; 32] {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.revalidate(current)?;
        if self.action == LifecycleDeletionActionV1::Deferred {
            return self
                .deferred
                .filter(|deferred| {
                    deferred.operation_record() == current.record() && deferred.reason() == reason
                })
                .map(|_| self)
                .ok_or(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let deferred = super::LifecycleDeferredEffectCursorV1::from_current_residual(
            current,
            self.method_plan,
            self.action as u32,
        )?;
        let expected_step = u32::try_from(
            self.cursor
                .checked_mul(6)
                .and_then(|index| index.checked_add(self.action as usize - 1))
                .ok_or(LifecyclePhase6ErrorV1::Capacity)?,
        )
        .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        if deferred.step() != expected_step || deferred.reason() != reason {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.deferred = Some(deferred);
        self.action = LifecycleDeletionActionV1::Deferred;
        Ok(self)
    }

    /// Returns the exact durable Residual cursor that must be retried.
    #[must_use]
    pub const fn deferred_cursor(&self) -> Option<super::LifecycleDeferredEffectCursorV1> {
        self.deferred
    }

    /// Resumes the preserved cursor after current protected state is rechecked.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the same lifecycle operation
    /// remains current.
    pub fn resume(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        self.revalidate(current)?;
        if self.action != LifecycleDeletionActionV1::Deferred {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let deferred = self
            .deferred
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        let mut resumed = self.clone();
        resumed.restore_persisted_cursor(current)?;
        let cursor = current
            .persisted_effect_cursor()?
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        if cursor.step() != deferred.step()
            || cursor.direction() != deferred.direction()
            || cursor.attempt() != deferred.retry_attempt()
            || cursor.state() != super::LifecycleAttemptStateV1::Reserved
            || resumed.action as u32 != deferred.action()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        resumed.deferred = None;
        *self = resumed;
        Ok(())
    }

    /// Derives the next inert protected-domain cleanup handoff.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for stale, deferred, or terminal state.
    pub fn next_effect<'current>(
        &self,
        current: &CurrentLifecycleOperationV1<'current>,
    ) -> Result<CurrentLifecycleEffectV1<'current>, LifecyclePhase6ErrorV1> {
        self.revalidate(current)?;
        let (resource, action) = self
            .next()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        let domain = match action {
            LifecycleDeletionActionV1::RevokeAdmission | LifecycleDeletionActionV1::Reap => {
                LifecycleEffectDomainV1::Controller
            }
            LifecycleDeletionActionV1::Detach => LifecycleEffectDomainV1::Mount,
            LifecycleDeletionActionV1::Drain => LifecycleEffectDomainV1::Runtime,
            LifecycleDeletionActionV1::ReleasePins => LifecycleEffectDomainV1::Cache,
            LifecycleDeletionActionV1::DestroyStorage => LifecycleEffectDomainV1::Storage,
            LifecycleDeletionActionV1::Deferred | LifecycleDeletionActionV1::Complete => {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        };
        current.recover_reserved_effect(
            domain,
            u32::try_from(self.cursor)
                .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?
                .saturating_mul(8)
                .saturating_add(action as u32),
            *resource.as_bytes(),
            self.plan.plan().digest(),
            deletion_effect_digest(self, resource, action),
        )
    }

    /// Authenticates a Controller-owned revoke or reap from exact commit readback.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the current edge is the exact
    /// Controller action committed by the supplied lifecycle transaction.
    pub fn observe_controller_commit(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
        applied: &super::AppliedLifecycleJournalTransactionV1,
    ) -> Result<LifecycleDeletionObservationV1, LifecyclePhase6ErrorV1> {
        let (resource, action) = self
            .next()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        if !matches!(
            action,
            LifecycleDeletionActionV1::RevokeAdmission | LifecycleDeletionActionV1::Reap
        ) {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let observation = self
            .next_effect(current)?
            .observe_lifecycle_commit(applied)?;
        LifecycleDeletionObservationV1::from_controller_commit(observation, action, resource)
    }

    /// Returns a terminal receipt only after every resource is reaped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] while any cleanup edge remains.
    pub fn receipt(&self) -> Result<LifecycleDeletionReceiptV1, LifecyclePhase6ErrorV1> {
        if self.action != LifecycleDeletionActionV1::Complete
            || self.reap_receipts.len() != self.plan.postorder().len()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let final_reap = *self
            .reap_receipts
            .last()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        let deleted_resources = u32::try_from(self.reap_receipts.len())
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        let receipt = deletion_receipt_digest(&self.plan, &self.reap_receipts);
        Ok(LifecycleDeletionReceiptV1 {
            plan: self.plan.plan().digest(),
            final_reap,
            deleted_resources,
            receipt,
        })
    }

    fn revalidate(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        if current.operation().operation_id() != self.operation {
            Err(LifecyclePhase6ErrorV1::StaleAuthority)
        } else {
            Ok(())
        }
    }

    fn restore_persisted_cursor(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        self.restore_reap_receipts(current)?;

        let actions = [
            LifecycleDeletionActionV1::RevokeAdmission,
            LifecycleDeletionActionV1::Detach,
            LifecycleDeletionActionV1::Drain,
            LifecycleDeletionActionV1::ReleasePins,
            LifecycleDeletionActionV1::DestroyStorage,
            LifecycleDeletionActionV1::Reap,
        ];
        if let Some(index) = self.method_plan.cursor_index(current)? {
            self.deferred = None;
            self.cursor = index / actions.len();
            self.action = *actions
                .get(index % actions.len())
                .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
            let _current_effect = self.next_effect(current)?;
            return Ok(());
        }
        match self.restore_deferred_cursor(current) {
            Ok(deferred) => {
                self.cursor = usize::try_from(deferred.step())
                    .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?
                    / actions.len();
                self.action = LifecycleDeletionActionV1::Deferred;
                self.deferred = Some(deferred);
                return Ok(());
            }
            Err(_)
                if current
                    .operation()
                    .steps()
                    .iter()
                    .any(|step| step.state() == super::LifecycleStepStateV1::Residual) =>
            {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
            Err(_) => {}
        }
        if current
            .require_persisted_completion(&[
                LifecycleMethodV1::DeleteSandbox,
                LifecycleMethodV1::DeleteSnapshot,
            ])
            .is_ok_and(|completion| completion.plan() == self.method_plan.commitment())
        {
            self.cursor = self.plan.postorder().len();
            self.action = LifecycleDeletionActionV1::Complete;
            return Ok(());
        }
        Err(LifecyclePhase6ErrorV1::InvalidTransition)
    }

    fn restore_deferred_cursor(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<super::LifecycleDeferredEffectCursorV1, LifecyclePhase6ErrorV1> {
        let residual = current
            .operation()
            .steps()
            .iter()
            .filter(|step| step.state() == super::LifecycleStepStateV1::Residual)
            .collect::<Vec<_>>();
        if residual.len() != 1 {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let index =
            usize::try_from(residual[0].index()).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        let actions = [
            LifecycleDeletionActionV1::RevokeAdmission,
            LifecycleDeletionActionV1::Detach,
            LifecycleDeletionActionV1::Drain,
            LifecycleDeletionActionV1::ReleasePins,
            LifecycleDeletionActionV1::DestroyStorage,
            LifecycleDeletionActionV1::Reap,
        ];
        let action = *actions
            .get(index % actions.len())
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        super::LifecycleDeferredEffectCursorV1::from_current_residual(
            current,
            self.method_plan,
            action as u32,
        )
    }

    fn validate_method_plan(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let actions = [
            LifecycleDeletionActionV1::RevokeAdmission,
            LifecycleDeletionActionV1::Detach,
            LifecycleDeletionActionV1::Drain,
            LifecycleDeletionActionV1::ReleasePins,
            LifecycleDeletionActionV1::DestroyStorage,
            LifecycleDeletionActionV1::Reap,
        ];
        for cursor in 0..self.plan.postorder().len() {
            self.cursor = cursor;
            let resource = self.plan.postorder()[cursor];
            for (offset, action) in actions.into_iter().enumerate() {
                self.action = action;
                let expected = super::LifecycleStepPlanDigestV1::commit(
                    deletion_effect_digest(self, resource, action).as_bytes(),
                );
                let step_index = cursor
                    .checked_mul(actions.len())
                    .and_then(|index| index.checked_add(offset))
                    .ok_or(LifecyclePhase6ErrorV1::Capacity)?;
                if current.operation().steps()[step_index].plan() != expected {
                    return Err(LifecyclePhase6ErrorV1::InvalidInput);
                }
            }
        }
        Ok(())
    }

    fn restore_reap_receipts(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        self.reap_receipts.clear();
        for cursor in 0..self.plan.postorder().len() {
            self.cursor = cursor;
            self.action = LifecycleDeletionActionV1::Reap;
            let resource = self.plan.postorder()[cursor];
            let plan = super::LifecycleStepPlanDigestV1::commit(
                deletion_effect_digest(self, resource, LifecycleDeletionActionV1::Reap).as_bytes(),
            );
            let step_index = cursor
                .checked_mul(6)
                .and_then(|index| index.checked_add(5))
                .ok_or(LifecyclePhase6ErrorV1::Capacity)?;
            let Some(step) = current.operation().steps().get(step_index) else {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            };
            if step.plan() != plan
                || step.state() != super::LifecycleStepStateV1::Applied
                || step.result().is_none()
            {
                break;
            }
            self.reap_receipts.push(
                step.result()
                    .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?
                    .digest(),
            );
        }
        Ok(())
    }
}

fn deletion_effect_digest(
    value: &LifecycleDeletionPlanV1,
    resource: LifecycleResourceV1,
    action: LifecycleDeletionActionV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.deletion-effect.v1\0")
            .chain_update(value.plan.plan().digest().as_bytes())
            .chain_update((value.cursor as u64).to_be_bytes())
            .chain_update([resource.code(), action as u8, u8::from(value.cascade)])
            .chain_update(resource.as_bytes())
            .finalize()
            .into(),
    )
}

fn deletion_receipt_digest(
    plan: &LifecycleCascadeTombstonePlanV1,
    reap_receipts: &[ObjectDigest],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.deletion-receipt.v1\0")
        .chain_update(plan.plan().digest().as_bytes())
        .chain_update((reap_receipts.len() as u32).to_be_bytes());
    for receipt in reap_receipts {
        hasher = hasher.chain_update(receipt.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
