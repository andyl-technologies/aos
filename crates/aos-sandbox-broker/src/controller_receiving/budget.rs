//! Tracks monotonic dominant demand for the Controller's actual fixed owners.
//!
//! This is private accounting DATA, not an admission, reservation, or payer
//! factory. The genuine original opening derives its own residual B and checks
//! this schedule before actual growth. Complete bounds for the same retained
//! owner replace earlier requirements only through a componentwise high water;
//! distinct owners remain charged together. Refusal permanently closes entry.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use aos_sandbox_core::component_receiving::{ComponentServiceReceivingLedgerV1, complete_bound_delta_v1};
use super::ControllerReceivingErrorV1;

/// Identifies the fixed owner whose complete retained requirement is raised.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) enum BaselineOwner {
    Fixed,
    SelectedProfile,
    ControllerLaunch,
    RuntimeFixed,
    RuntimeCredentials,
    ControllerNative,
    SourceNative,
    CacheBootstrapNative,
    CacheHoldNative,
    CacheClockNative,
    CacheAuthorityNative,
    CacheStateNative,
    ImportModels,
    CacheSourceModels,
    CacheAuthorityModels,
    CachePhysical,
    CoordinatorRepresentation,
    InitialHostSession,
    InitialMountSession,
    InitialStorageSession,
    InitialNetworkSession,
    SourceSuccessorIssue,
    CreateProvisioning,
    GlobalInitialProgram,
    OperatorRecover,
    RecoveryReserve,
    PredecessorBaselineCarry,
    RecoveredDeleteIntake,
    RecoveredExecutionIntake,
    RecoveredLifecycleStop,
    RecoveredEnrollment,
    RecoveredOrdinarySessionContext,
    RecoveredHostSession,
    RecoveredMountSession,
    RecoveredStorageSession,
    RecoveredNetworkSession,
    CatalogMaintenance,
}

impl BaselineOwner {
    const COUNT: usize = 37;

    fn participates_in_initial_program_v1(self) -> bool {
        matches!(self, Self::SelectedProfile | Self::RuntimeFixed
            | Self::InitialHostSession | Self::InitialMountSession
            | Self::InitialStorageSession | Self::InitialNetworkSession)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Entry {
    Ready,
    Entered,
    Closed,
}

/// Retains accepted owner high waters beside the shared Core-backed ledger.
pub(super) struct BaselineDemand {
    owners: [ResourceVector; BaselineOwner::COUNT],
    ledger: Option<ComponentServiceReceivingLedgerV1>,
    original_baseline: Option<ResourceVector>,
    entry: Entry,
    initial_program_required: Option<bool>,
}

impl BaselineDemand {
    pub(super) const fn new() -> Self {
        Self {
            owners: [ResourceVector::ZERO; BaselineOwner::COUNT],
            ledger: None,
            original_baseline: None,
            entry: Entry::Ready,
            initial_program_required: None,
        }
    }

    // The genuine selected pair supplies this partition before profile growth.
    // Both entries use the SAME immutable B ledger. No old owner highwater is
    // reconstructed; a whole-envelope precharge conservatively retains it.
    pub(super) fn bind_baseline_partition_v1(&mut self, baseline: ResourceVector,
        normal: ResourceVector, recovery: ResourceVector, generation: u64)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.ledger.is_some() || generation > 1 {
            self.entry = Entry::Closed;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        if normal.checked_add(recovery).map_or(true, |combined| combined != baseline) {
            self.entry = Entry::Closed;
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.begin()?;
        if generation == 0 {
            self.raise(BaselineOwner::RecoveryReserve, recovery, baseline)
        } else {
            self.raise(BaselineOwner::PredecessorBaselineCarry, normal, baseline)
        }
    }

    // The immutable range precharges every ordinal globally. This local SAME-B
    // ledger reserves everything outside the one genuine current allowance;
    // no old highwater or completed owner is released into this recipient.
    pub(super) fn bind_recipient_range_v2(&mut self, baseline: ResourceVector,
        normal: ResourceVector, recovery: ResourceVector, allowance: ResourceVector,
        recipients: u64, ordinal: u64) -> Result<(), ControllerReceivingErrorV1>
    {
        let result = (|| {
            if self.ledger.is_some() || ordinal > recipients || recipients == 0
                || normal.checked_add(recovery)? != baseline {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            for dimension in D::ALL {
                let reserved = allowance.get(dimension).checked_mul(recipients)
                    .ok_or(ControllerReceivingErrorV1::Conflict)?;
                if reserved > recovery.get(dimension) {
                    return Err(ControllerReceivingErrorV1::Conflict);
                }
            }
            self.begin()?;
            if ordinal == 0 {
                self.raise(BaselineOwner::RecoveryReserve, recovery, baseline)
            } else {
                self.raise(BaselineOwner::PredecessorBaselineCarry,
                    baseline.checked_sub(allowance)?, baseline)
            }
        })();
        if result.is_err() { self.entry = Entry::Closed; }
        result
    }

    // Called only from the paired opaque capture before its first profile
    // liability. The delivery selects accounting, never native success.
    pub(super) fn bind_initial_program_mode_v1(&mut self, required: bool)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.is_closed() || self.initial_program_required.is_some()
            || [BaselineOwner::SelectedProfile, BaselineOwner::RuntimeFixed,
                BaselineOwner::InitialHostSession, BaselineOwner::InitialMountSession,
                BaselineOwner::InitialStorageSession, BaselineOwner::InitialNetworkSession]
                .into_iter().any(|owner| self.owners[owner as usize] != ResourceVector::ZERO)
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.initial_program_required = Some(required);
        Ok(())
    }

    pub(super) fn initial_program_required_v1(&self)
        -> Result<bool, ControllerReceivingErrorV1>
    {
        self.initial_program_required.ok_or(ControllerReceivingErrorV1::Conflict)
    }

    pub(super) fn require_initial_program_mode_v1(&self, required: bool)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.initial_program_required == Some(required) { Ok(()) }
        else { Err(ControllerReceivingErrorV1::Conflict) }
    }

    pub(super) fn owner_complete(&self, owner: BaselineOwner) -> ResourceVector {
        self.owners[owner as usize]
    }

    // Only arithmetic DATA from the SAME Core ledger. No new account or
    // reservation is produced, and a poisoned owner cannot use it to heal.
    pub(super) fn remaining_data_v2(&self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        if self.is_closed() { return Err(ControllerReceivingErrorV1::Conflict); }
        self.ledger.as_ref().ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?
            .remaining().map_err(Into::into)
    }

    pub(super) fn is_closed(&self) -> bool {
        self.entry != Entry::Ready || self.ledger.as_ref().is_some_and(|ledger| ledger.failure().is_some())
    }

    // Actual original/layout/extent derivation follows this once-only entry.
    // An early return leaves Entered resident, so later attempts cannot heal it.
    pub(super) fn begin(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.is_closed() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.entry = Entry::Entered;
        Ok(())
    }

    pub(super) fn raise(
        &mut self,
        owner: BaselineOwner,
        demand: ResourceVector,
        original_baseline: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.entry != Entry::Entered {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.entry = Entry::Closed;
        match self.original_baseline {
            Some(original) if original != original_baseline => {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            Some(_) => {}
            None => {
                self.original_baseline = Some(original_baseline);
                self.ledger = Some(ComponentServiceReceivingLedgerV1::new(original_baseline));
            }
        }

        if matches!(owner, BaselineOwner::GlobalInitialProgram) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let previous = self.owners[owner as usize];
        let (high_water, mut additional) = complete_bound_delta_v1(previous, demand)?;
        let mut program = None;
        if self.initial_program_required == Some(true) && owner.participates_in_initial_program_v1() {
            // Preserve the full old per-owner highwaters for diagnostics and
            // recipe arithmetic. Only their FD projection is consolidated on
            // the same ledger. Until a closed native phase supplies a proven
            // resident bound, retain the complete conservative historical sum.
            let files = [BaselineOwner::SelectedProfile, BaselineOwner::RuntimeFixed,
                BaselineOwner::InitialHostSession, BaselineOwner::InitialMountSession,
                BaselineOwner::InitialStorageSession, BaselineOwner::InitialNetworkSession]
                .into_iter().try_fold(0_u64, |total, candidate| {
                    let bound = if candidate as usize == owner as usize { high_water }
                        else { self.owners[candidate as usize] };
                    total.checked_add(bound.get(D::OpenFiles))
                        .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)
                })?;
            let (whole, delta) = complete_bound_delta_v1(
                self.owners[BaselineOwner::GlobalInitialProgram as usize],
                ResourceVector::ZERO.with(D::OpenFiles, files),
            )?;
            additional = additional.with(D::OpenFiles, 0).checked_add(delta)?;
            program = Some(whole);
        }
        let ledger = self.ledger.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?;
        ledger.reserve(additional).map_err(|cause| ControllerReceivingErrorV1::Accounting(*cause))?;

        self.owners[owner as usize] = high_water;
        if let Some(whole) = program {
            self.owners[BaselineOwner::GlobalInitialProgram as usize] = whole;
        }
        self.entry = Entry::Ready;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ResourceDimension;

    #[test]
    fn finite_recipient_uses_only_its_full_allowance_and_never_releases_the_carry() {
        let baseline = ResourceVector::new([1000; D::COUNT]);
        let normal = ResourceVector::new([700; D::COUNT]);
        let recovery = ResourceVector::new([300; D::COUNT]);
        let allowance = ResourceVector::new([100; D::COUNT]);

        for ordinal in 1..=3 {
            let mut actual = BaselineDemand::new();
            actual.bind_recipient_range_v2(baseline, normal, recovery, allowance, 3, ordinal).unwrap();
            assert_eq!(actual.owner_complete(BaselineOwner::PredecessorBaselineCarry),
                baseline.checked_sub(allowance).unwrap());
            actual.begin().unwrap();
            actual.raise(BaselineOwner::OperatorRecover, allowance, baseline).unwrap();
            actual.begin().unwrap();
            assert!(actual.raise(BaselineOwner::RuntimeFixed,
                ResourceVector::new([1; D::COUNT]), baseline).is_err());
            assert!(actual.bind_recipient_range_v2(baseline, normal, recovery, allowance, 3, ordinal).is_err());
        }

        let mut exhausted = BaselineDemand::new();
        assert!(exhausted.bind_recipient_range_v2(baseline, normal, recovery, allowance, 3, 4).is_err());
        let mut unfunded = BaselineDemand::new();
        assert!(unfunded.bind_recipient_range_v2(baseline, normal, recovery, allowance, 4, 1).is_err());
    }

    #[test]
    fn same_b_ledger_keeps_normal_and_recovery_disjoint_in_every_dimension() {
        let baseline = ResourceVector::new([1000; D::COUNT]);
        let normal = ResourceVector::new([800; D::COUNT]);
        let recovery = ResourceVector::new([200; D::COUNT]);
        let mut initial = BaselineDemand::new();
        initial.bind_baseline_partition_v1(baseline, normal, recovery, 0).unwrap();
        initial.begin().unwrap();
        initial.raise(BaselineOwner::CreateProvisioning, normal, baseline).unwrap();
        initial.begin().unwrap();
        assert!(initial.raise(BaselineOwner::RuntimeFixed,
            ResourceVector::new([1; D::COUNT]), baseline).is_err());

        // A new process has no copied old owner23 highwater. Its genuine pair
        // instead reserves the whole durable normal envelope on the SAME B.
        let mut successor = BaselineDemand::new();
        successor.bind_baseline_partition_v1(baseline, normal, recovery, 1).unwrap();
        assert_eq!(successor.owner_complete(BaselineOwner::PredecessorBaselineCarry), normal);
        successor.begin().unwrap();
        successor.raise(BaselineOwner::OperatorRecover, recovery, baseline).unwrap();
        successor.begin().unwrap();
        assert!(successor.raise(BaselineOwner::Fixed,
            ResourceVector::new([1; D::COUNT]), baseline).is_err());
        assert!(successor.bind_baseline_partition_v1(baseline, normal, recovery, 1).is_err());
    }

    #[test]
    fn partition_cannot_be_installed_after_growth_or_with_another_generation() {
        let baseline = ResourceVector::new([1000; D::COUNT]);
        let normal = ResourceVector::new([800; D::COUNT]);
        let recovery = ResourceVector::new([200; D::COUNT]);
        let mut wrong = BaselineDemand::new();
        assert!(wrong.bind_baseline_partition_v1(baseline, normal, recovery, 2).is_err());
        let mut entered = BaselineDemand::new();
        entered.begin().unwrap();
        entered.raise(BaselineOwner::Fixed, ResourceVector::new([1; D::COUNT]), baseline).unwrap();
        assert!(entered.bind_baseline_partition_v1(baseline, normal, recovery, 0).is_err());
    }

    fn resources(memory: u64, metadata: u64) -> ResourceVector {
        ResourceVector::ZERO
            .with(ResourceDimension::MemoryBytes, memory)
            .with(ResourceDimension::MetadataEntries, metadata)
    }

    #[test]
    fn required_program_selection_precedes_liability_and_preserves_conservative_charge() {
        let capacity = ResourceVector::ZERO.with(D::MemoryBytes, 100).with(D::OpenFiles, 100);
        let first = ResourceVector::ZERO.with(D::MemoryBytes, 10).with(D::OpenFiles, 20);
        let second = ResourceVector::ZERO.with(D::MemoryBytes, 15).with(D::OpenFiles, 30);
        let mut actual = BaselineDemand::new();
        actual.bind_initial_program_mode_v1(true).unwrap();
        actual.begin().unwrap();
        actual.raise(BaselineOwner::SelectedProfile, first, capacity).unwrap();
        actual.begin().unwrap();
        actual.raise(BaselineOwner::RuntimeFixed, second, capacity).unwrap();
        assert_eq!(actual.ledger.as_ref().unwrap().charged(), first.checked_add(second).unwrap());
        assert_eq!(actual.owner_complete(BaselineOwner::SelectedProfile), first);
        assert_eq!(actual.owner_complete(BaselineOwner::GlobalInitialProgram),
            ResourceVector::ZERO.with(D::OpenFiles, 50));
        actual.require_initial_program_mode_v1(true).unwrap();
        assert!(actual.require_initial_program_mode_v1(false).is_err());
        assert!(actual.bind_initial_program_mode_v1(true).is_err());

        let mut late = BaselineDemand::new();
        late.begin().unwrap();
        late.raise(BaselineOwner::SelectedProfile, first, capacity).unwrap();
        assert!(late.bind_initial_program_mode_v1(true).is_err());
        assert_eq!(late.ledger.as_ref().unwrap().charged(), first);
    }

    #[test]
    fn recover_keeps_the_prior_create_liability_on_the_same_residual_ledger() {
        let capacity = resources(100, 100);
        let create = resources(60, 0);
        let recover = resources(50, 0);
        let mut demand = BaselineDemand::new();

        demand.begin().unwrap();
        demand.raise(BaselineOwner::CreateProvisioning, create, capacity).unwrap();
        let charged = demand.ledger.as_ref().unwrap().charged();
        demand.begin().unwrap();
        let refused = demand.raise(BaselineOwner::OperatorRecover, recover, capacity);

        assert!(refused.is_err());
        assert!(demand.is_closed());
        assert_eq!(demand.owner_complete(BaselineOwner::CreateProvisioning), create);
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), charged);
        assert!(demand.begin().is_err());
    }

    #[test]
    fn interleaved_complete_bounds_keep_prior_dimensions_and_distinct_owners() {
        let capacity = resources(100, 100);
        let mut demand = BaselineDemand::new();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::CacheAuthorityModels, resources(80, 10), capacity).unwrap();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::CacheSourceModels, resources(10, 80), capacity).unwrap();

        // Later inventory includes the earlier authority evidence. It grows
        // memory without discounting the earlier metadata obligation.
        demand.begin().unwrap();
        demand.raise(BaselineOwner::CacheAuthorityModels, resources(90, 5), capacity).unwrap();
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(100, 90));
        assert!(!demand.is_closed());

        // A different real Source owner still needs its additional byte.
        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::CacheSourceModels, resources(11, 80), capacity).is_err());
        assert!(demand.is_closed());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(100, 90));
        assert!(demand.begin().is_err());
        assert!(demand.raise(BaselineOwner::CacheAuthorityModels, resources(1, 1), capacity).is_err());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(100, 90));
    }

    #[test]
    fn aggregate_overflow_closes_without_replacing_accepted_ownership() {
        let capacity = resources(u64::MAX, 0);
        let mut demand = BaselineDemand::new();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::ControllerNative, capacity, capacity).unwrap();

        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::SourceNative, resources(1, 0), capacity).is_err());
        assert!(demand.is_closed());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), capacity);
        assert!(demand.begin().is_err());
        assert!(demand.raise(BaselineOwner::SourceNative, ResourceVector::ZERO, capacity).is_err());
    }

    #[test]
    fn interrupted_original_derivation_cannot_reenter_or_discard_prior_charge() {
        let capacity = resources(100, 100);
        let mut demand = BaselineDemand::new();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::ControllerNative, resources(10, 2), capacity).unwrap();
        demand.begin().unwrap();

        // The actual caller can return while deriving its next original.
        assert!(demand.is_closed());
        assert!(demand.begin().is_err());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(10, 2));
    }

    #[test]
    fn provisioning_turns_preserve_other_owners_and_all_prior_traffic() {
        use aos_sandbox_core::component_receiving::operation_traffic_demand_v1;
        use aos_sandbox_core::ResourceDimension as D;
        let capacity = ResourceVector::ZERO.with(D::MemoryBytes, 100).with(D::NetworkBytes, 100);
        let resident = ResourceVector::ZERO.with(D::MemoryBytes, 40).with(D::NetworkBytes, 10);
        let mut demand = BaselineDemand::new();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::InitialStorageSession, resident, capacity).unwrap();

        let first = ResourceVector::ZERO.with(D::MemoryBytes, 30).with(D::NetworkBytes, 20);
        demand.begin().unwrap();
        demand.raise(BaselineOwner::CreateProvisioning, first, capacity).unwrap();
        let extended = ResourceVector::ZERO.with(D::MemoryBytes, 40).with(D::NetworkBytes, 35);
        demand.begin().unwrap();
        demand.raise(BaselineOwner::CreateProvisioning, extended, capacity).unwrap();

        // A fully disposed native turn permits another reached requirement,
        // but every earlier traffic byte stays charged on the SAME ledger.
        let base = operation_traffic_demand_v1(demand.owner_complete(BaselineOwner::CreateProvisioning));
        let next = ResourceVector::ZERO.with(D::MemoryBytes, 25).with(D::NetworkBytes, 15);
        demand.begin().unwrap();
        demand.raise(BaselineOwner::CreateProvisioning, base.checked_add(next).unwrap(), capacity).unwrap();
        assert_eq!(demand.ledger.as_ref().unwrap().charged(),
            ResourceVector::ZERO.with(D::MemoryBytes, 80).with(D::NetworkBytes, 60));
        assert_eq!(demand.owner_complete(BaselineOwner::InitialStorageSession), resident);

        let too_large = ResourceVector::ZERO.with(D::MemoryBytes, 61).with(D::NetworkBytes, 50);
        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::CreateProvisioning, too_large, capacity).is_err());
        assert!(demand.is_closed());
        assert!(demand.begin().is_err());
    }

    #[test]
    fn recovered_intakes_permanently_share_only_remaining_successor_baseline() {
        let baseline = resources(100, 100);
        let carried = resources(60, 20);
        let recover = resources(10, 10);
        let delete = resources(15, 30);
        let execution = resources(10, 35);
        let mut demand = BaselineDemand::new();
        demand.bind_baseline_partition_v1(baseline, carried,
            baseline.checked_sub(carried).unwrap(), 1).unwrap();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::OperatorRecover, recover, baseline).unwrap();

        demand.begin().unwrap();
        demand.raise(BaselineOwner::RecoveredDeleteIntake, delete, baseline).unwrap();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::RecoveredExecutionIntake, execution, baseline).unwrap();

        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(95, 95));
        assert_eq!(demand.remaining_data_v2().unwrap(), resources(5, 5));
        assert_eq!(demand.owner_complete(BaselineOwner::PredecessorBaselineCarry), carried);
        assert_eq!(demand.owner_complete(BaselineOwner::OperatorRecover), recover);
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredDeleteIntake), delete);
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredExecutionIntake), execution);

        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::RecoveredExecutionIntake,
            execution.with(D::MetadataEntries, 41), baseline).is_err());
        assert!(demand.remaining_data_v2().is_err());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(95, 95));
        assert!(demand.begin().is_err());
    }

    #[test]
    fn recovered_capacity_keeps_prior_network_spending_in_the_same_ledger() {
        let baseline = ResourceVector::ZERO.with(D::MemoryBytes, 100).with(D::NetworkBytes, 100);
        let carried = ResourceVector::ZERO.with(D::MemoryBytes, 60).with(D::NetworkBytes, 20);
        let recover = ResourceVector::ZERO.with(D::MemoryBytes, 10).with(D::NetworkBytes, 50);
        let delete = ResourceVector::ZERO.with(D::MemoryBytes, 20).with(D::NetworkBytes, 31);
        let mut demand = BaselineDemand::new();
        demand.bind_baseline_partition_v1(baseline, carried,
            baseline.checked_sub(carried).unwrap(), 1).unwrap();
        demand.begin().unwrap();
        demand.raise(BaselineOwner::OperatorRecover, recover, baseline).unwrap();
        let prior = demand.ledger.as_ref().unwrap().charged();

        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::RecoveredDeleteIntake, delete, baseline).is_err());

        assert_eq!(demand.ledger.as_ref().unwrap().charged(), prior);
        assert_eq!(prior.get(D::NetworkBytes), 70);
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredDeleteIntake), ResourceVector::ZERO);
        assert_eq!(demand.owner_complete(BaselineOwner::PredecessorBaselineCarry), carried);
        assert_eq!(demand.owner_complete(BaselineOwner::OperatorRecover), recover);
        assert!(demand.begin().is_err());
    }

}

#[cfg(test)]
mod recovered_enrollment_tests {
    use super::*;

    #[test]
    fn enrollment_charges_remaining_baseline_after_both_permanent_intakes() {
        let vector = |bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes);
        let baseline = vector(100);
        let carried = vector(50);
        let mut demand = BaselineDemand::new();
        demand.bind_baseline_partition_v1(baseline, carried, vector(50), 1).unwrap();
        for (owner, complete) in [
            (BaselineOwner::OperatorRecover, vector(10)),
            (BaselineOwner::RecoveredDeleteIntake, vector(12)),
            (BaselineOwner::RecoveredExecutionIntake, vector(14)),
            (BaselineOwner::RecoveredEnrollment, vector(8)),
        ] {
            demand.begin().unwrap();
            demand.raise(owner, complete, baseline).unwrap();
        }

        assert_eq!(demand.remaining_data_v2().unwrap(), vector(6));
        assert_eq!(demand.owner_complete(BaselineOwner::PredecessorBaselineCarry), carried);
        assert_eq!(demand.owner_complete(BaselineOwner::OperatorRecover), vector(10));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredDeleteIntake), vector(12));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredExecutionIntake), vector(14));

        // A later enrollment growth refusal retains all funded intake amounts
        // and the accepted enrollment highwater; no capacity is reclaimed.
        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::RecoveredEnrollment, vector(15), baseline).is_err());
        assert!(demand.is_closed());
        assert!(demand.begin().is_err());
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredEnrollment), vector(8));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredDeleteIntake), vector(12));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredExecutionIntake), vector(14));
    }
}

#[cfg(test)]
mod recovered_ordinary_session_tests {
    use super::*;

    #[test]
    fn four_sessions_keep_predecessor_recovery_and_funded_intakes_in_one_baseline() {
        let vector = |memory, network| ResourceVector::ZERO
            .with(D::MemoryBytes, memory).with(D::NetworkBytes, network);
        let baseline = vector(1000, 1000);
        let carried = vector(400, 100);
        let mut demand = BaselineDemand::new();
        demand.bind_baseline_partition_v1(baseline, carried,
            baseline.checked_sub(carried).unwrap(), 1).unwrap();
        for (owner, complete) in [
            (BaselineOwner::OperatorRecover, vector(50, 150)),
            (BaselineOwner::RecoveredDeleteIntake, vector(80, 200)),
            (BaselineOwner::RecoveredExecutionIntake, vector(90, 150)),
            (BaselineOwner::RecoveredEnrollment, vector(20, 20)),
            (BaselineOwner::RecoveredOrdinarySessionContext, vector(30, 10)),
            (BaselineOwner::RecoveredHostSession, vector(40, 40)),
            (BaselineOwner::RecoveredMountSession, vector(40, 40)),
            (BaselineOwner::RecoveredStorageSession, vector(40, 40)),
            (BaselineOwner::RecoveredNetworkSession, vector(40, 40)),
        ] {
            demand.begin().unwrap();
            demand.raise(owner, complete, baseline).unwrap();
        }

        assert_eq!(demand.ledger.as_ref().unwrap().charged(), vector(830, 790));
        assert_eq!(demand.remaining_data_v2().unwrap(), vector(170, 210));
        assert_eq!(demand.owner_complete(BaselineOwner::PredecessorBaselineCarry), carried);
        assert_eq!(demand.owner_complete(BaselineOwner::OperatorRecover), vector(50, 150));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredDeleteIntake), vector(80, 200));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredExecutionIntake), vector(90, 150));
        // New role funding never claims or clears the old initial-role ledger.
        for owner in [BaselineOwner::InitialHostSession, BaselineOwner::InitialMountSession,
            BaselineOwner::InitialStorageSession, BaselineOwner::InitialNetworkSession] {
            assert_eq!(demand.owner_complete(owner), ResourceVector::ZERO);
        }

        demand.begin().unwrap();
        demand.raise(BaselineOwner::RecoveredHostSession, vector(60, 60), baseline).unwrap();
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), vector(850, 810));
        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::RecoveredNetworkSession, vector(40, 231), baseline).is_err());
        assert!(demand.is_closed());
        assert!(demand.begin().is_err());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), vector(850, 810));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredNetworkSession), vector(40, 40));
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredHostSession), vector(60, 60));
        assert_eq!(demand.owner_complete(BaselineOwner::PredecessorBaselineCarry), carried);
    }
}

#[cfg(test)]
mod recovered_stop_tests {
    use super::*;
    use aos_sandbox_core::component_receiving::operation_traffic_demand_v1;

    #[test]
    fn stop_seed_and_later_turns_preserve_carried_debt_other_intakes_and_spent_traffic() {
        let resources = |memory, traffic| ResourceVector::ZERO
            .with(D::MemoryBytes, memory).with(D::NetworkBytes, traffic);
        let baseline = resources(100, 100);
        let carried = resources(35, 15);
        let delete = resources(10, 10);
        let execution = resources(15, 20);
        let seed = resources(12, 8);
        let mut demand = BaselineDemand::new();
        demand.bind_baseline_partition_v1(baseline, carried,
            baseline.checked_sub(carried).unwrap(), 1).unwrap();
        for (owner, complete) in [
            (BaselineOwner::RecoveredDeleteIntake, delete),
            (BaselineOwner::RecoveredExecutionIntake, execution),
            (BaselineOwner::RecoveredLifecycleStop, seed),
        ] {
            demand.begin().unwrap();
            demand.raise(owner, complete, baseline).unwrap();
        }
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(72, 53));

        // Seed native entry consumes the already-paid seed, rather than
        // beginning another debit. The next real Stop turn adds its traffic.
        let base = operation_traffic_demand_v1(demand.owner_complete(BaselineOwner::RecoveredLifecycleStop));
        demand.begin().unwrap();
        demand.raise(BaselineOwner::RecoveredLifecycleStop,
            base.checked_add(resources(9, 7)).unwrap(), baseline).unwrap();
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), resources(72, 60));
        assert_eq!(demand.owner_complete(BaselineOwner::PredecessorBaselineCarry), carried);
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredDeleteIntake), delete);
        assert_eq!(demand.owner_complete(BaselineOwner::RecoveredExecutionIntake), execution);

        let before = demand.ledger.as_ref().unwrap().charged();
        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::RecoveredLifecycleStop,
            resources(41, 50), baseline).is_err());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), before);
        assert!(demand.is_closed());
        assert!(demand.begin().is_err());
    }
}

#[cfg(test)]
mod catalog_maintenance_tests {
    use super::*;

    #[test]
    fn repeated_maintenance_keeps_all_prior_owners_and_cumulative_traffic() {
        let vector = |memory, network| ResourceVector::ZERO
            .with(D::MemoryBytes, memory).with(D::NetworkBytes, network);
        let baseline = vector(1000, 1000);
        let carried = vector(400, 100);
        let mut demand = BaselineDemand::new();
        demand.bind_baseline_partition_v1(baseline, carried,
            baseline.checked_sub(carried).unwrap(), 1).unwrap();
        let earlier = [
            (BaselineOwner::OperatorRecover, vector(100, 200)),
            (BaselineOwner::RecoveredDeleteIntake, vector(100, 50)),
            (BaselineOwner::RecoveredExecutionIntake, vector(100, 50)),
            (BaselineOwner::RecoveredEnrollment, vector(20, 10)),
            (BaselineOwner::RecoveredOrdinarySessionContext, vector(20, 20)),
            (BaselineOwner::RecoveredHostSession, vector(15, 20)),
            (BaselineOwner::RecoveredMountSession, vector(15, 20)),
            (BaselineOwner::RecoveredStorageSession, vector(15, 20)),
            (BaselineOwner::RecoveredNetworkSession, vector(15, 20)),
        ];
        for (owner, complete) in earlier {
            demand.begin().unwrap();
            demand.raise(owner, complete, baseline).unwrap();
        }

        demand.begin().unwrap();
        demand.raise(BaselineOwner::CatalogMaintenance, vector(20, 100), baseline).unwrap();
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), vector(820, 610));

        // The next interval carries its prior traffic, while memory uses the
        // same owner's permanent highwater. It cannot spend on a new account.
        demand.begin().unwrap();
        demand.raise(BaselineOwner::CatalogMaintenance, vector(30, 170), baseline).unwrap();
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), vector(830, 680));
        for (owner, complete) in earlier {
            assert_eq!(demand.owner_complete(owner), complete);
        }
        assert_eq!(demand.owner_complete(BaselineOwner::PredecessorBaselineCarry), carried);

        demand.begin().unwrap();
        assert!(demand.raise(BaselineOwner::CatalogMaintenance, vector(300, 600), baseline).is_err());
        assert!(demand.is_closed());
        assert!(demand.begin().is_err());
        assert_eq!(demand.ledger.as_ref().unwrap().charged(), vector(830, 680));
        assert_eq!(demand.owner_complete(BaselineOwner::CatalogMaintenance), vector(30, 170));
        for (owner, complete) in earlier {
            assert_eq!(demand.owner_complete(owner), complete);
        }
    }
}
