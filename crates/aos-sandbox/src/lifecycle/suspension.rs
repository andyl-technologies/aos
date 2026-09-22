//! LIFE-04 memory suspension, resume, and hibernation cleanup orchestration.

use aos_sandbox_core::{ObjectDigest, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{
    CurrentLifecycleCoordinationV1, CurrentLifecycleEffectV1, CurrentLifecycleOperationV1,
    CurrentLifecycleRuntimeLivenessV1, CurrentLifecycleSuspendObservationV1,
    LifecycleEffectDomainV1, LifecycleEffectObservationV1, LifecycleIntentV1, LifecycleMethodV1,
    LifecyclePhase6EffectPlanV1, LifecyclePhase6ErrorV1, LifecyclePhaseV1,
    LifecycleSnapshotBarrierActionV1, LifecycleSnapshotBarrierV1, LifecycleStepClassV1,
    LifecycleStepV1, LiveRuntimeFenceV1, lifecycle_phase6_planned_step_v1,
};

/// Selects the exact suspend or resume protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleSuspensionModeV1 {
    /// Freezes and retains one live in-memory incarnation.
    MemorySuspend = 1,
    /// Resumes the same observed in-memory incarnation.
    MemoryResume = 2,
    /// Snapshots, stops, and releases one live incarnation.
    Hibernate = 3,
}

/// Selects the next action in a suspend, resume, or hibernate sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleSuspensionActionV1 {
    /// Revokes new execution and attachment admissions.
    CloseAdmission = 1,
    /// Drains writers and mutable publications.
    Quiesce = 2,
    /// Freezes the exact fenced runtime.
    FreezeRuntime = 3,
    /// Persists the memory-suspend observation.
    RecordSuspension = 4,
    /// Runs the LIFE-01 snapshot barrier for hibernation.
    Snapshot = 5,
    /// Stops the snapshotted runtime.
    StopRuntime = 6,
    /// Detaches ephemeral mount and network state.
    DetachEphemeral = 7,
    /// Releases node-local reservations after detach.
    ReleaseReservations = 8,
    /// Reopens the exact retained in-memory runtime.
    ResumeRuntime = 9,
    /// The requested lifecycle transition is complete.
    Complete = 10,
    /// Thaws the runtime frozen before entering the hibernation barrier.
    CompensateOuterThaw = 11,
}

/// Retains one method-specific suspension protocol without dispatch authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleSuspensionPlanV1 {
    mode: LifecycleSuspensionModeV1,
    sandbox: SandboxId,
    fence: LiveRuntimeFenceV1,
    operation: aos_sandbox_core::OperationId,
    method_plan: super::LifecycleMethodPlanV1,
    host_boot: Option<[u8; 16]>,
    runtime_inventory: Option<ObjectDigest>,
    hibernation_barrier: Option<LifecycleSnapshotBarrierV1>,
    action: LifecycleSuspensionActionV1,
}

impl LifecycleSuspensionPlanV1 {
    /// Compiles the immutable four-step memory-suspension plan.
    ///
    /// The first three actions are reversible preparation. Recording the
    /// protected suspension observation is post-commit forward work. Each
    /// effect body is the exact body later reconstructed by [`Self::next_effect`].
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless `current` is an accepted,
    /// wholly unbound memory-suspension operation with a matching runtime
    /// fence, or when a canonical step cannot be constructed.
    pub fn planned_memory_suspend_steps(
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<Vec<LifecycleStepV1>, LifecyclePhase6ErrorV1> {
        current.require_method(&[LifecycleMethodV1::SuspendMemory])?;
        let (sandbox, fence) = match current.operation().intent() {
            LifecycleIntentV1::SuspendMemory { sandbox, fence } => (*sandbox, *fence),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        require_unbound_admission(current)?;
        if fence.sandbox() != sandbox {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }

        let actions = [
            LifecycleSuspensionActionV1::CloseAdmission,
            LifecycleSuspensionActionV1::Quiesce,
            LifecycleSuspensionActionV1::FreezeRuntime,
            LifecycleSuspensionActionV1::RecordSuspension,
        ];
        actions
            .into_iter()
            .enumerate()
            .map(|(index, action)| {
                let class = if action == LifecycleSuspensionActionV1::RecordSuspension {
                    LifecycleStepClassV1::PostCommitForward
                } else {
                    LifecycleStepClassV1::PreCommitReversible
                };
                planned_suspension_step(
                    current.operation().operation_id(),
                    u32::try_from(index).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?,
                    class,
                    LifecycleSuspensionModeV1::MemorySuspend,
                    action,
                    Some(action),
                    sandbox,
                    fence,
                    None,
                    None,
                    None,
                )
            })
            .collect()
    }

    /// Compiles the immutable eleven-step hibernation plan.
    ///
    /// Admission closure, outer quiesce/freeze, and the five-action snapshot
    /// barrier form the reversible pre-commit prefix. Runtime stop, ephemeral
    /// detach, and reservation release execute only after snapshot retention is
    /// semantically committed. The outer and barrier freezes retain distinct
    /// thaw compensation commitments.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the accepted unbound Hibernate
    /// operation and protected coordination transaction agree exactly, or when
    /// a canonical step cannot be constructed.
    pub fn planned_hibernate_steps(
        current: &CurrentLifecycleOperationV1<'_>,
        protected_transaction: &CurrentLifecycleCoordinationV1<'_>,
    ) -> Result<Vec<LifecycleStepV1>, LifecyclePhase6ErrorV1> {
        current.require_method(&[LifecycleMethodV1::Hibernate])?;
        let (sandbox, snapshot, fence) = match current.operation().intent() {
            LifecycleIntentV1::Hibernate {
                sandbox,
                snapshot,
                fence,
                ..
            } => (*sandbox, *snapshot, *fence),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        require_unbound_admission(current)?;
        let transaction = protected_transaction.coordination().transaction();
        if protected_transaction.projection_root() != current.projection_root()
            || transaction.sandbox() != sandbox
            || transaction.live_fence() != fence
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }

        let operation = current.operation().operation_id();
        let barrier_identity = super::snapshot_barrier::barrier_plan_identity(transaction);
        let mut steps = Vec::with_capacity(11);
        let outer_actions = [
            LifecycleSuspensionActionV1::CloseAdmission,
            LifecycleSuspensionActionV1::Quiesce,
            LifecycleSuspensionActionV1::FreezeRuntime,
        ];
        for (index, action) in outer_actions.into_iter().enumerate() {
            let compensation = if action == LifecycleSuspensionActionV1::FreezeRuntime {
                LifecycleSuspensionActionV1::CompensateOuterThaw
            } else {
                action
            };
            steps.push(planned_suspension_step(
                operation,
                u32::try_from(index).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?,
                LifecycleStepClassV1::PreCommitReversible,
                LifecycleSuspensionModeV1::Hibernate,
                action,
                Some(compensation),
                sandbox,
                fence,
                None,
                None,
                Some(barrier_identity),
            )?);
        }

        let barrier_actions = [
            LifecycleSnapshotBarrierActionV1::LockClosure,
            LifecycleSnapshotBarrierActionV1::QuiesceWriters,
            LifecycleSnapshotBarrierActionV1::FreezeRuntimes,
            LifecycleSnapshotBarrierActionV1::SnapshotDatasets,
            LifecycleSnapshotBarrierActionV1::CommitRetention,
        ];
        for (relative, action) in barrier_actions.into_iter().enumerate() {
            let compensation = if action == LifecycleSnapshotBarrierActionV1::FreezeRuntimes {
                LifecycleSnapshotBarrierActionV1::CompensateThaw
            } else {
                action
            };
            steps.push(super::snapshot_barrier::planned_barrier_step(
                operation,
                u32::try_from(relative + 3).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?,
                LifecycleStepClassV1::PreCommitReversible,
                sandbox,
                snapshot,
                transaction,
                action,
                Some(compensation),
            )?);
        }

        let postcommit_actions = [
            LifecycleSuspensionActionV1::StopRuntime,
            LifecycleSuspensionActionV1::DetachEphemeral,
            LifecycleSuspensionActionV1::ReleaseReservations,
        ];
        for (relative, action) in postcommit_actions.into_iter().enumerate() {
            steps.push(planned_suspension_step(
                operation,
                u32::try_from(relative + 8).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?,
                LifecycleStepClassV1::PostCommitForward,
                LifecycleSuspensionModeV1::Hibernate,
                action,
                None,
                sandbox,
                fence,
                None,
                None,
                Some(barrier_identity),
            )?);
        }
        Ok(steps)
    }

    /// Compiles the immutable one-step same-incarnation resume plan.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the accepted operation,
    /// protected suspension observation, and fresh runtime liveness record all
    /// identify the same live suspended incarnation.
    pub fn planned_memory_resume_steps(
        current: &CurrentLifecycleOperationV1<'_>,
        protected_observation: &CurrentLifecycleSuspendObservationV1<'_>,
        liveness: &CurrentLifecycleRuntimeLivenessV1<'_>,
    ) -> Result<Vec<LifecycleStepV1>, LifecyclePhase6ErrorV1> {
        current.require_method(&[LifecycleMethodV1::Resume])?;
        let (sandbox, fence) = match current.operation().intent() {
            LifecycleIntentV1::Resume {
                sandbox,
                source: super::LifecycleResumeSourceV1::Memory { fence },
            } => (*sandbox, *fence),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        require_unbound_admission(current)?;
        let observation = protected_observation.observation();
        if protected_observation.projection_root() != current.projection_root()
            || liveness.projection_root() != current.projection_root()
            || liveness.operation() != current.operation().operation_id()
            || liveness.operation_record() != current.record()
            || observation.fence() != fence
            || observation.host_boot() != liveness.host_boot()
            || liveness.fence() != fence
            || liveness.host_boot() == [0; 16]
            || liveness.inventory().as_bytes() == &[0; 32]
            || fence.sandbox() != sandbox
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }

        Ok(vec![planned_suspension_step(
            current.operation().operation_id(),
            0,
            LifecycleStepClassV1::PostCommitForward,
            LifecycleSuspensionModeV1::MemoryResume,
            LifecycleSuspensionActionV1::ResumeRuntime,
            None,
            sandbox,
            fence,
            Some(liveness.host_boot()),
            Some(liveness.inventory()),
            None,
        )?])
    }

    /// Plans memory suspension or hibernation for an exact live incarnation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless current intent is a matching
    /// memory-suspend or hibernate operation with an exact runtime fence.
    pub fn suspend(
        current: &CurrentLifecycleOperationV1<'_>,
        hibernation_barrier: Option<LifecycleSnapshotBarrierV1>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        current.require_method(&[
            LifecycleMethodV1::SuspendMemory,
            LifecycleMethodV1::Hibernate,
        ])?;
        let (mode, sandbox, fence) = match current.operation().intent() {
            LifecycleIntentV1::SuspendMemory { sandbox, fence } => {
                (LifecycleSuspensionModeV1::MemorySuspend, *sandbox, *fence)
            }
            LifecycleIntentV1::Hibernate { sandbox, fence, .. } => {
                (LifecycleSuspensionModeV1::Hibernate, *sandbox, *fence)
            }
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if fence.sandbox() != sandbox
            || (mode == LifecycleSuspensionModeV1::Hibernate && hibernation_barrier.is_none())
            || (mode != LifecycleSuspensionModeV1::Hibernate && hibernation_barrier.is_some())
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let expected_steps = match mode {
            LifecycleSuspensionModeV1::MemorySuspend => 4,
            LifecycleSuspensionModeV1::Hibernate => 11,
            LifecycleSuspensionModeV1::MemoryResume => {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        };
        let method_plan = super::LifecycleMethodPlanV1::from_current(current, expected_steps)?;
        let mut plan = Self {
            mode,
            sandbox,
            fence,
            operation: current.operation().operation_id(),
            method_plan,
            host_boot: None,
            runtime_inventory: None,
            hibernation_barrier,
            action: LifecycleSuspensionActionV1::CloseAdmission,
        };
        plan.validate_method_plan(current)?;
        plan.action = plan.persisted_action(current)?;
        Ok(plan)
    }

    /// Plans same-incarnation memory resume from a protected suspend record.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless current resume intent names
    /// the exact still-live fence carried by the protected observation.
    pub fn resume_memory(
        current: &CurrentLifecycleOperationV1<'_>,
        protected_observation: &CurrentLifecycleSuspendObservationV1<'_>,
        liveness: &CurrentLifecycleRuntimeLivenessV1<'_>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        current.require_method(&[LifecycleMethodV1::Resume])?;
        let (sandbox, fence) = match current.operation().intent() {
            LifecycleIntentV1::Resume {
                sandbox,
                source: super::LifecycleResumeSourceV1::Memory { fence },
            } => (*sandbox, *fence),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        let observation = protected_observation.observation();
        if protected_observation.projection_root() != current.projection_root()
            || liveness.projection_root() != current.projection_root()
            || liveness.operation() != current.operation().operation_id()
            || liveness.operation_record() != current.record()
            || observation.fence() != fence
            || observation.host_boot() != liveness.host_boot()
            || liveness.fence() != fence
            || liveness.host_boot() == [0; 16]
            || liveness.inventory().as_bytes() == &[0; 32]
            || fence.sandbox() != sandbox
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let method_plan = super::LifecycleMethodPlanV1::from_current(current, 1)?;
        let mut plan = Self {
            mode: LifecycleSuspensionModeV1::MemoryResume,
            sandbox,
            fence,
            operation: current.operation().operation_id(),
            method_plan,
            host_boot: Some(liveness.host_boot()),
            runtime_inventory: Some(liveness.inventory()),
            hibernation_barrier: None,
            action: LifecycleSuspensionActionV1::ResumeRuntime,
        };
        plan.validate_method_plan(current)?;
        plan.action = plan.persisted_action(current)?;
        Ok(plan)
    }

    /// Returns the exact next protocol action.
    #[must_use]
    pub const fn action(&self) -> LifecycleSuspensionActionV1 {
        self.action
    }

    /// Advances after an exact protected lower-domain observation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for an out-of-order action, a zero
    /// observation, or hibernation before its snapshot barrier is complete.
    pub fn observe(
        mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        observation: LifecycleEffectObservationV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request() != self.next_effect(current)?.request() {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.action = match (self.mode, self.action) {
            (_, LifecycleSuspensionActionV1::CloseAdmission) => {
                LifecycleSuspensionActionV1::Quiesce
            }
            (_, LifecycleSuspensionActionV1::Quiesce) => LifecycleSuspensionActionV1::FreezeRuntime,
            (
                LifecycleSuspensionModeV1::MemorySuspend,
                LifecycleSuspensionActionV1::FreezeRuntime,
            ) => LifecycleSuspensionActionV1::RecordSuspension,
            (LifecycleSuspensionModeV1::Hibernate, LifecycleSuspensionActionV1::FreezeRuntime) => {
                LifecycleSuspensionActionV1::Snapshot
            }
            (
                LifecycleSuspensionModeV1::MemorySuspend,
                LifecycleSuspensionActionV1::RecordSuspension,
            )
            | (
                LifecycleSuspensionModeV1::MemoryResume,
                LifecycleSuspensionActionV1::ResumeRuntime,
            )
            | (
                LifecycleSuspensionModeV1::Hibernate,
                LifecycleSuspensionActionV1::CompensateOuterThaw,
            ) => LifecycleSuspensionActionV1::Complete,
            (LifecycleSuspensionModeV1::Hibernate, LifecycleSuspensionActionV1::StopRuntime) => {
                LifecycleSuspensionActionV1::DetachEphemeral
            }
            (
                LifecycleSuspensionModeV1::Hibernate,
                LifecycleSuspensionActionV1::DetachEphemeral,
            ) => LifecycleSuspensionActionV1::ReleaseReservations,
            (
                LifecycleSuspensionModeV1::Hibernate,
                LifecycleSuspensionActionV1::ReleaseReservations,
            ) => LifecycleSuspensionActionV1::Complete,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidTransition),
        };
        Ok(self)
    }

    /// Replaces the in-progress hibernation barrier with its exact successor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] outside the hibernate snapshot edge.
    pub fn update_hibernation_barrier(
        mut self,
        barrier: LifecycleSnapshotBarrierV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if self.mode != LifecycleSuspensionModeV1::Hibernate
            || self.action != LifecycleSuspensionActionV1::Snapshot
            || !barrier.is_bound_to(self.sandbox)
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let complete = barrier.action() == super::LifecycleSnapshotBarrierActionV1::Complete;
        let compensated = barrier.completed_by_compensation();
        self.hibernation_barrier = Some(barrier);
        if complete {
            self.action = if compensated {
                LifecycleSuspensionActionV1::Complete
            } else {
                LifecycleSuspensionActionV1::StopRuntime
            };
        }
        Ok(self)
    }

    /// Re-enters the hibernation barrier for mandatory post-freeze thaw.
    ///
    /// A successful hibernation barrier intentionally leaves the source
    /// runtime frozen while Stop and ephemeral cleanup proceed. Any failure
    /// before Stop becomes durable must therefore return to the barrier's
    /// protected thaw-compensation edge, including failures after dataset and
    /// retention commit.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1::InvalidTransition`] outside a
    /// hibernation sequence or after durable thaw/compensation.
    pub fn require_hibernation_compensation(mut self) -> Result<Self, LifecyclePhase6ErrorV1> {
        if self.mode != LifecycleSuspensionModeV1::Hibernate
            || !matches!(
                self.action,
                LifecycleSuspensionActionV1::Snapshot | LifecycleSuspensionActionV1::StopRuntime
            )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let barrier = self
            .hibernation_barrier
            .take()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        if barrier.outer_freeze_requires_thaw() {
            self.hibernation_barrier = Some(barrier);
            self.action = LifecycleSuspensionActionV1::CompensateOuterThaw;
            return Ok(self);
        }
        let barrier = barrier.require_compensation()?;
        self.hibernation_barrier = Some(barrier);
        self.action = LifecycleSuspensionActionV1::Snapshot;
        Ok(self)
    }

    /// Derives the next inert lower-domain handoff.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for stale authority or completion.
    pub fn next_effect<'current>(
        &self,
        current: &CurrentLifecycleOperationV1<'current>,
    ) -> Result<CurrentLifecycleEffectV1<'current>, LifecyclePhase6ErrorV1> {
        if current.operation().operation_id() != self.operation {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        if self.action == LifecycleSuspensionActionV1::Snapshot {
            return self
                .hibernation_barrier
                .as_ref()
                .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?
                .next_effect(current);
        }
        let domain = match self.action {
            LifecycleSuspensionActionV1::CloseAdmission
            | LifecycleSuspensionActionV1::Quiesce
            | LifecycleSuspensionActionV1::RecordSuspension => LifecycleEffectDomainV1::Controller,
            LifecycleSuspensionActionV1::FreezeRuntime
            | LifecycleSuspensionActionV1::StopRuntime
            | LifecycleSuspensionActionV1::ResumeRuntime
            | LifecycleSuspensionActionV1::CompensateOuterThaw => LifecycleEffectDomainV1::Runtime,
            LifecycleSuspensionActionV1::Snapshot => {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
            LifecycleSuspensionActionV1::DetachEphemeral => LifecycleEffectDomainV1::Mount,
            LifecycleSuspensionActionV1::ReleaseReservations => LifecycleEffectDomainV1::Network,
            LifecycleSuspensionActionV1::Complete => {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        };
        current.recover_reserved_effect(
            domain,
            self.action as u32,
            *self.sandbox.as_bytes(),
            self.runtime_inventory
                .unwrap_or_else(|| suspension_fence_digest(self.fence)),
            suspension_digest(self),
        )
    }

    fn persisted_action(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<LifecycleSuspensionActionV1, LifecyclePhase6ErrorV1> {
        match self.method_plan.cursor_index(current)? {
            Some(index) => {
                let action = match self.mode {
                    LifecycleSuspensionModeV1::MemorySuspend => [
                        LifecycleSuspensionActionV1::CloseAdmission,
                        LifecycleSuspensionActionV1::Quiesce,
                        LifecycleSuspensionActionV1::FreezeRuntime,
                        LifecycleSuspensionActionV1::RecordSuspension,
                    ]
                    .get(index)
                    .copied(),
                    LifecycleSuspensionModeV1::MemoryResume => {
                        (index == 0).then_some(LifecycleSuspensionActionV1::ResumeRuntime)
                    }
                    LifecycleSuspensionModeV1::Hibernate => match index {
                        0 => Some(LifecycleSuspensionActionV1::CloseAdmission),
                        1 => Some(LifecycleSuspensionActionV1::Quiesce),
                        2 => Some(LifecycleSuspensionActionV1::FreezeRuntime),
                        3..=7 => Some(LifecycleSuspensionActionV1::Snapshot),
                        8 => Some(LifecycleSuspensionActionV1::StopRuntime),
                        9 => Some(LifecycleSuspensionActionV1::DetachEphemeral),
                        10 => Some(LifecycleSuspensionActionV1::ReleaseReservations),
                        _ => None,
                    },
                }
                .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
                let cursor = current
                    .persisted_effect_cursor()?
                    .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
                let action = if self.mode == LifecycleSuspensionModeV1::Hibernate
                    && index == 2
                    && cursor.direction() == super::LifecycleEffectDirectionV1::Compensation
                {
                    LifecycleSuspensionActionV1::CompensateOuterThaw
                } else {
                    action
                };
                self.action = action;
                let _current_effect = self.next_effect(current)?;
                Ok(action)
            }
            None if current
                .require_persisted_completion(match self.mode {
                    LifecycleSuspensionModeV1::MemorySuspend => &[LifecycleMethodV1::SuspendMemory],
                    LifecycleSuspensionModeV1::MemoryResume => &[LifecycleMethodV1::Resume],
                    LifecycleSuspensionModeV1::Hibernate => &[LifecycleMethodV1::Hibernate],
                })
                .is_ok_and(|completion| completion.plan() == self.method_plan.commitment()) =>
            {
                Ok(LifecycleSuspensionActionV1::Complete)
            }
            None if self.mode == LifecycleSuspensionModeV1::Hibernate
                && self.hibernation_barrier.as_ref().is_some_and(|barrier| {
                    barrier.action() == super::LifecycleSnapshotBarrierActionV1::Complete
                }) =>
            {
                Ok(
                    if self
                        .hibernation_barrier
                        .as_ref()
                        .is_some_and(LifecycleSnapshotBarrierV1::completed_by_compensation)
                    {
                        LifecycleSuspensionActionV1::Complete
                    } else {
                        LifecycleSuspensionActionV1::StopRuntime
                    },
                )
            }
            None => Err(LifecyclePhase6ErrorV1::InvalidTransition),
        }
    }

    fn validate_method_plan(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let indexed_actions: &[(usize, LifecycleSuspensionActionV1)] = match self.mode {
            LifecycleSuspensionModeV1::MemorySuspend => &[
                (0, LifecycleSuspensionActionV1::CloseAdmission),
                (1, LifecycleSuspensionActionV1::Quiesce),
                (2, LifecycleSuspensionActionV1::FreezeRuntime),
                (3, LifecycleSuspensionActionV1::RecordSuspension),
            ],
            LifecycleSuspensionModeV1::MemoryResume => {
                &[(0, LifecycleSuspensionActionV1::ResumeRuntime)]
            }
            LifecycleSuspensionModeV1::Hibernate => &[
                (0, LifecycleSuspensionActionV1::CloseAdmission),
                (1, LifecycleSuspensionActionV1::Quiesce),
                (2, LifecycleSuspensionActionV1::FreezeRuntime),
                (8, LifecycleSuspensionActionV1::StopRuntime),
                (9, LifecycleSuspensionActionV1::DetachEphemeral),
                (10, LifecycleSuspensionActionV1::ReleaseReservations),
            ],
        };
        for (index, action) in indexed_actions {
            self.action = *action;
            let expected =
                super::LifecycleStepPlanDigestV1::commit(suspension_digest(self).as_bytes());
            if current.operation().steps()[*index].plan() != expected {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        }
        if self.mode == LifecycleSuspensionModeV1::Hibernate {
            self.action = LifecycleSuspensionActionV1::CompensateOuterThaw;
            let expected =
                super::LifecycleStepPlanDigestV1::commit(suspension_digest(self).as_bytes());
            if current.operation().steps()[2].compensation_plan() != Some(expected) {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        }
        Ok(())
    }
}

fn suspension_digest(value: &LifecycleSuspensionPlanV1) -> ObjectDigest {
    suspension_digest_parts(
        value.mode,
        value.action,
        value.sandbox,
        value.fence,
        value.host_boot,
        value.runtime_inventory,
        value
            .hibernation_barrier
            .as_ref()
            .map(LifecycleSnapshotBarrierV1::plan_identity),
    )
}

fn suspension_digest_parts(
    mode: LifecycleSuspensionModeV1,
    action: LifecycleSuspensionActionV1,
    sandbox: SandboxId,
    fence: LiveRuntimeFenceV1,
    host_boot: Option<[u8; 16]>,
    runtime_inventory: Option<ObjectDigest>,
    hibernation_barrier: Option<ObjectDigest>,
) -> ObjectDigest {
    let barrier = hibernation_barrier.unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]));
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.suspension-plan.v1\0")
            .chain_update([mode as u8, action as u8])
            .chain_update(sandbox.as_bytes())
            .chain_update(fence.incarnation().as_bytes())
            .chain_update(fence.assignment_epoch().get().to_be_bytes())
            .chain_update(fence.namespace_generation().get().to_be_bytes())
            .chain_update(host_boot.unwrap_or([0; 16]))
            .chain_update(
                runtime_inventory
                    .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                    .as_bytes(),
            )
            .chain_update(barrier.as_bytes())
            .finalize()
            .into(),
    )
}

#[allow(clippy::too_many_arguments)]
fn planned_suspension_step(
    operation: aos_sandbox_core::OperationId,
    index: u32,
    class: LifecycleStepClassV1,
    mode: LifecycleSuspensionModeV1,
    action: LifecycleSuspensionActionV1,
    compensation_action: Option<LifecycleSuspensionActionV1>,
    sandbox: SandboxId,
    fence: LiveRuntimeFenceV1,
    host_boot: Option<[u8; 16]>,
    runtime_inventory: Option<ObjectDigest>,
    hibernation_barrier: Option<ObjectDigest>,
) -> Result<LifecycleStepV1, LifecyclePhase6ErrorV1> {
    let domain = suspension_effect_domain(action)?;
    let prerequisite = runtime_inventory.unwrap_or_else(|| suspension_fence_digest(fence));
    let plan = suspension_digest_parts(
        mode,
        action,
        sandbox,
        fence,
        host_boot,
        runtime_inventory,
        hibernation_barrier,
    );
    let forward = LifecyclePhase6EffectPlanV1::new(
        domain,
        action as u32,
        *sandbox.as_bytes(),
        prerequisite,
        plan,
    )?;
    let compensation = compensation_action
        .map(|compensation_action| {
            LifecyclePhase6EffectPlanV1::new(
                suspension_effect_domain(compensation_action)?,
                compensation_action as u32,
                *sandbox.as_bytes(),
                prerequisite,
                suspension_digest_parts(
                    mode,
                    compensation_action,
                    sandbox,
                    fence,
                    host_boot,
                    runtime_inventory,
                    hibernation_barrier,
                ),
            )
        })
        .transpose()?;

    lifecycle_phase6_planned_step_v1(operation, index, class, forward, compensation)
}

fn suspension_effect_domain(
    action: LifecycleSuspensionActionV1,
) -> Result<LifecycleEffectDomainV1, LifecyclePhase6ErrorV1> {
    match action {
        LifecycleSuspensionActionV1::CloseAdmission
        | LifecycleSuspensionActionV1::Quiesce
        | LifecycleSuspensionActionV1::RecordSuspension => Ok(LifecycleEffectDomainV1::Controller),
        LifecycleSuspensionActionV1::FreezeRuntime
        | LifecycleSuspensionActionV1::StopRuntime
        | LifecycleSuspensionActionV1::ResumeRuntime
        | LifecycleSuspensionActionV1::CompensateOuterThaw => Ok(LifecycleEffectDomainV1::Runtime),
        LifecycleSuspensionActionV1::DetachEphemeral => Ok(LifecycleEffectDomainV1::Mount),
        LifecycleSuspensionActionV1::ReleaseReservations => Ok(LifecycleEffectDomainV1::Network),
        LifecycleSuspensionActionV1::Snapshot | LifecycleSuspensionActionV1::Complete => {
            Err(LifecyclePhase6ErrorV1::InvalidInput)
        }
    }
}

fn require_unbound_admission(
    current: &CurrentLifecycleOperationV1<'_>,
) -> Result<(), LifecyclePhase6ErrorV1> {
    let operation = current.operation();
    if operation.phase() != LifecyclePhaseV1::Accepted
        || operation.steps().is_empty()
        || !operation.steps().iter().all(LifecycleStepV1::is_unbound)
    {
        return Err(LifecyclePhase6ErrorV1::InvalidTransition);
    }
    Ok(())
}

fn suspension_fence_digest(fence: LiveRuntimeFenceV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.suspension-fence.v1\0")
            .chain_update(fence.sandbox().as_bytes())
            .chain_update(fence.incarnation().as_bytes())
            .chain_update(fence.assignment_epoch().get().to_be_bytes())
            .chain_update(fence.namespace_generation().get().to_be_bytes())
            .finalize()
            .into(),
    )
}
