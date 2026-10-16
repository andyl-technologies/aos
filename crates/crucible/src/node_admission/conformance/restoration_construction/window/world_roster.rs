//! Orders the real three-node World release before selected scheduling Observe.
//!
//! The common installer retains all ledgers and scheduler owners first. Each
//! exact historical ticket then selects its same runtime-owned native node.
//! Source-owned phase evidence, rather than an erased callback's return value,
//! completes each phase. An interrupted roster remains spent and retains every
//! native/SDK partial; Host2 never enters this native-only dispatch.

use super::super::activation::{
    OriginalInstalledRestorationActivationLedger, OriginalInstalledRestorationActivationPhase,
};
use super::*;
use crate::node_contract::{OriginalLineageNativeScope, WorldActivation};

#[derive(Clone, Copy, Eq, PartialEq)]
enum WorldRosterStage {
    AwaitingInstallation,
    Installed,
    Started,
    Complete,
    Failed,
}

pub(super) struct OriginalRestorationWorldRoster(Cell<WorldRosterStage>);

// The fixed borrowed guard survives every effect callback. Drop invalidates
// the whole census on normal return, early refusal and unwinding alike.
struct WorldRosterObservation<'a> {
    roster: &'a OriginalRestorationWorldRoster,
    observation: &'a observation::OriginalRestorationWholeObservation,
}

impl Drop for WorldRosterObservation<'_> {
    fn drop(&mut self) {
        self.observation.require_observation();
        if self.roster.0.get() == WorldRosterStage::Started {
            self.roster.0.set(WorldRosterStage::Failed);
        }
    }
}

impl OriginalRestorationWorldRoster {
    pub(super) fn new() -> Self {
        Self(Cell::new(WorldRosterStage::AwaitingInstallation))
    }

    fn installed(&self) -> Result<(), RuntimeError> {
        if self.0.replace(WorldRosterStage::Failed) != WorldRosterStage::AwaitingInstallation {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.0.set(WorldRosterStage::Installed);
        Ok(())
    }

    fn begin(&self) -> Result<(), RuntimeError> {
        if self.0.replace(WorldRosterStage::Failed) != WorldRosterStage::Installed {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.0.set(WorldRosterStage::Started);
        Ok(())
    }

    fn authenticate_started(&self) -> Result<(), RuntimeError> {
        if self.0.get() != WorldRosterStage::Started {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn complete(&self) -> Result<(), RuntimeError> {
        self.authenticate_started()?;
        self.0.set(WorldRosterStage::Complete);
        Ok(())
    }

    pub(super) fn authenticate_complete(&self) -> Result<(), RuntimeError> {
        if self.0.get() != WorldRosterStage::Complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

fn authenticate_roster_phase(
    phases: &[OriginalInstalledRestorationActivationLedger; 3],
    expected: OriginalInstalledRestorationActivationPhase,
) -> Result<(), RuntimeError> {
    for phase in phases {
        if !phase.is_verified(expected) {
            return Err(RuntimeError::OutstandingObligations);
        }
    }
    Ok(())
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn complete_original_common_installation_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &NodeRuntime,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.runtime
            .authenticate_runtime_data(runtime, &scope.target.world_binding_hash)?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        if !self.install_started.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Only the concrete caller reaches this after common installation and
        // its full context reauthentication both succeeded. This sequencing
        // marker cannot replace the fresh observation or any Source evidence.
        self.world_roster.installed()?;
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn dispatch_original_installed_worlds_data(
        &self,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        runtime: &mut NodeRuntime,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let _observation = WorldRosterObservation {
            roster: &self.world_roster,
            observation: &self.whole_observation,
        };
        // Spend before any member callback. A swallowed reentrant invocation
        // poisons this same group instead of reopening its outer success tail.
        self.world_roster.begin()?;
        let result = self.dispatch_original_world_roster_inner(plan, world, runtime);
        if result.is_err() {
            self.world_roster.0.set(WorldRosterStage::Failed);
        }
        // The borrowed guard keeps the full census pending on every exit.
        // Actual output owners and ledgers stay in their same node and Window.
        result
    }

    fn dispatch_original_world_roster_inner(
        &self,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        runtime: &mut NodeRuntime,
    ) -> Result<(), RuntimeError> {
        self.whole_observation.authenticate_dispatch_data()?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_world_roster_member_data(plan, scope, world)?;
        self.runtime
            .authenticate_runtime_data(runtime, &scope.target.world_binding_hash)?;
        authenticate_roster_phase(
            &self.activation_phases,
            OriginalInstalledRestorationActivationPhase::Arm,
        )?;
        for selected in 0..3 {
            self.world_roster.authenticate_started()?;
            self.authenticate_original_world_roster_member_data(plan, scope, world)?;
            let target = self.targets[selected]
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let [node] = target.ticket_data()?.owner()?.participants.as_slice() else {
                return Err(RuntimeError::UnsupportedFacet);
            };
            runtime.activate_original_installed_restoration_node_world(node, world)?;
            self.world_roster.authenticate_started()?;
            self.authenticate_original_world_roster_member_data(plan, scope, world)?;
            if !self.activation_phases[selected]
                .is_verified(OriginalInstalledRestorationActivationPhase::WorldActivate)
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        authenticate_roster_phase(
            &self.activation_phases,
            OriginalInstalledRestorationActivationPhase::WorldActivate,
        )?;
        self.runtime
            .authenticate_runtime_data(runtime, &scope.target.world_binding_hash)?;
        self.world_roster.complete()
    }

    fn authenticate_original_world_roster_member_data(
        &self,
        plan: &InstalledConformancePlan,
        scope: &OriginalLineageNativeScope,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        if !self
            .activation_world
            .get()
            .is_some_and(|original| original.same_authority(world))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.runtime
            .authenticate_world_activation_data(world, &scope.target)?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        // The member callback cannot exchange a world or silently revive a
        // different runtime after the native phase's SourceRead has completed.
        self.runtime
            .authenticate_world_activation_data(world, &scope.target)
    }
}

pub(super) fn counter_scratch_data() -> Result<usize, RuntimeError> {
    checked_sum(
        &[
            size_of::<[usize; 35]>(),
            size_of::<OriginalRestorationWorldRoster>(),
            size_of::<&OriginalRestorationWorldRoster>(),
            size_of::<WorldRosterObservation<'static>>(),
            size_of::<&mut WorldRosterObservation<'static>>(),
            size_of::<&observation::OriginalRestorationWholeObservation>(),
            size_of::<&[OriginalInstalledRestorationActivationLedger; 3]>(),
            size_of::<Option<&scope_owner::OriginalRestorationScopeOwner>>(),
            size_of::<Result<&scope_owner::OriginalRestorationScopeOwner, RuntimeError>>(),
            size_of::<WorldRosterStage>(),
            size_of::<&CompleteOriginalRestorationWindow>(),
            size_of::<&Rc<CompleteOriginalRestorationWindow>>(),
            size_of::<&InstalledConformancePlan>(),
            size_of::<&OriginalLineageNativeScope>(),
            size_of::<Result<&OriginalLineageNativeScope, RuntimeError>>(),
            size_of::<&WorldActivation>(),
            size_of::<Option<&WorldActivation>>(),
            size_of::<Result<&WorldActivation, RuntimeError>>(),
            size_of::<&mut NodeRuntime>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<usize>(),
            size_of::<Option<&CompleteOriginalRestorationTransactionTarget>>(),
            size_of::<Result<&CompleteOriginalRestorationTransactionTarget, RuntimeError>>(),
            size_of::<&CompleteOriginalNativeTicket>(),
            size_of::<Result<&CompleteOriginalNativeTicket, RuntimeError>>(),
            size_of::<&crate::node_state::NativeOwnerState>(),
            size_of::<Result<&crate::node_state::NativeOwnerState, RuntimeError>>(),
            size_of::<&[Id]>(),
            size_of::<&Id>(),
            size_of::<std::slice::Iter<'static, OriginalInstalledRestorationActivationLedger>>(),
            size_of::<&OriginalInstalledRestorationActivationLedger>(),
            size_of::<OriginalInstalledRestorationActivationPhase>(),
            size_of::<bool>(),
            2 * size_of::<Result<(), RuntimeError>>(),
            NodeRuntime::original_installed_world_dispatch_counter_scratch_data(),
        ],
        usize::MAX,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_guard_exit_keeps_the_census_pending_and_interruptions_spent() {
        let roster = OriginalRestorationWorldRoster::new();
        let observation = observation::OriginalRestorationWholeObservation::new_pending();
        roster.installed().unwrap();
        observation.complete_observation();
        {
            let _guard = WorldRosterObservation {
                roster: &roster,
                observation: &observation,
            };
            roster.begin().unwrap();
            // Early return or unwind drops this same inert borrowed guard.
        }
        assert!(observation.authenticate_dispatch_data().is_err());
        assert!(roster.begin().is_err());
        assert!(roster.complete().is_err());

        let complete = OriginalRestorationWorldRoster::new();
        complete.installed().unwrap();
        observation.complete_observation();
        {
            let _guard = WorldRosterObservation {
                roster: &complete,
                observation: &observation,
            };
            complete.begin().unwrap();
            complete.complete().unwrap();
        }
        assert!(observation.authenticate_dispatch_data().is_err());
        assert!(complete.0.get() == WorldRosterStage::Complete);
    }

    #[test]
    fn common_installation_precedes_a_single_world_roster_dispatch() {
        let missing = OriginalRestorationWorldRoster::new();
        assert!(missing.begin().is_err());
        assert!(missing.installed().is_err());

        let roster = OriginalRestorationWorldRoster::new();
        roster.installed().unwrap();
        roster.begin().unwrap();
        roster.authenticate_started().unwrap();
        roster.complete().unwrap();
        assert!(roster.begin().is_err());
        assert!(roster.complete().is_err());
    }

    #[test]
    fn swallowed_reentry_cannot_complete_the_outer_world_roster() {
        let roster = OriginalRestorationWorldRoster::new();
        roster.installed().unwrap();
        roster.begin().unwrap();

        assert!(roster.begin().is_err());
        assert!(roster.authenticate_started().is_err());
        assert!(roster.complete().is_err());
    }

    #[test]
    fn arm_or_two_world_receipts_cannot_complete_the_three_world_gate() {
        let phases = std::array::from_fn(|_| OriginalInstalledRestorationActivationLedger::new());
        let arm = OriginalInstalledRestorationActivationPhase::Arm;
        let world = OriginalInstalledRestorationActivationPhase::WorldActivate;
        assert!(authenticate_roster_phase(&phases, world).is_err());
        for phase in &phases {
            phase.begin(arm).unwrap();
            phase.complete_verified(arm).unwrap();
        }
        authenticate_roster_phase(&phases, arm).unwrap();
        assert!(authenticate_roster_phase(&phases, world).is_err());
        for phase in &phases[..2] {
            phase.begin(world).unwrap();
            phase.complete_verified(world).unwrap();
        }
        assert!(authenticate_roster_phase(&phases, world).is_err());
        phases[2].begin(world).unwrap();
        assert!(authenticate_roster_phase(&phases, world).is_err());
        phases[2].complete_verified(world).unwrap();
        authenticate_roster_phase(&phases, world).unwrap();
        assert!(authenticate_roster_phase(&phases, arm).is_err());
    }
}
