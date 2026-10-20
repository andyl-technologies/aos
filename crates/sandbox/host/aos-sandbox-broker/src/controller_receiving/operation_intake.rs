//! Retains the declared Delete and Execution subdivisions on their original C.
//!
//! These private slots retain either an actual initial reserved claim or a
//! new full permanent debit on the SAME recovered baseline. They create no
//! account and never reuse an unknown predecessor claim. The closed Bank/launch
//! borrower selects a purpose, proves its funding, consumes a finite flight and validates native
//! posts before preparing disposal. Arithmetic cannot authenticate an operation.

use aos_sandbox_model::{AccountingError, ResourceVector};
use aos_sandbox_model::component_receiving::{complete_bound_delta_v1, operation_traffic_demand_v1};
use aos_sandbox_protocol::domain_ledger::resource_bank::{Claim, ClaimPurpose, ClaimState};

use crate::receiving::ComponentReceivingOwnedOperationV1;
use super::ControllerReceivingErrorV1;

/// Selects only the two explicit measured Controller operation subdivisions.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) enum OperationIntakePurposeV1 {
    Delete,
    Execution,
    LifecycleStop,
}

impl OperationIntakePurposeV1 {
    pub(in crate::controller_receiving) const fn index(self) -> usize {
        match self {
            Self::Delete => 0,
            Self::Execution => 1,
            Self::LifecycleStop => 2,
        }
    }

    pub(in crate::controller_receiving) const fn profile_pool_slots(self) -> usize {
        match self { Self::Delete => 8, Self::Execution => 4, Self::LifecycleStop => 0 }
    }

    pub(in crate::controller_receiving) fn declared_amount_v2(self,
        policy: aos_sandbox_protocol::domain_ledger::resource_bank::ImageBootstrapPolicy,
    ) -> Option<ResourceVector> {
        let declared = policy.bootstrap_provisions();
        match self { Self::Delete => declared.delete_operation_intake,
            Self::Execution => declared.execution_operation_intake, Self::LifecycleStop => None }
    }

    pub(in crate::controller_receiving) fn recovered_baseline_owner_v2(self)
        -> super::budget::BaselineOwner {
        match self { Self::Delete => super::budget::BaselineOwner::RecoveredDeleteIntake,
            Self::Execution => super::budget::BaselineOwner::RecoveredExecutionIntake,
            Self::LifecycleStop => super::budget::BaselineOwner::RecoveredLifecycleStop }
    }

    pub(in crate::controller_receiving) const fn claim_purpose(self) -> Option<ClaimPurpose> {
        match self {
            Self::Delete => Some(ClaimPurpose::DeleteOperationIntake),
            Self::Execution => Some(ClaimPurpose::ExecutionOperationIntake),
            Self::LifecycleStop => None,
        }
    }
}

/// Keeps funding provenance distinct while sharing one intake/profile engine.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) enum OperationIntakeFundingV2 {
    InitialReservedClaim(Claim),
    RecoveredBaseline(super::original::RecoveredOperationIntakeFundingV2),
    RecoveredLifecycleStop(super::original::RecoveredLifecycleStopFundingV3),
}

impl OperationIntakeFundingV2 {
    pub(in crate::controller_receiving) fn initial_claim_v2(self) -> Option<Claim> {
        match self { Self::InitialReservedClaim(claim) => Some(claim), Self::RecoveredBaseline(_) | Self::RecoveredLifecycleStop(_) => None }
    }

    fn complete_capacity_v2(self) -> ResourceVector {
        match self { Self::InitialReservedClaim(claim) => claim.native_fields().amount,
            Self::RecoveredBaseline(receipt) => receipt.complete_v2(),
            Self::RecoveredLifecycleStop(receipt) => receipt.record_data_v3().complete_v3() }
    }

    fn has_purpose_v2(self, purpose: OperationIntakePurposeV1) -> bool {
        match self { Self::InitialReservedClaim(claim) => Some(claim.native_fields().purpose) == purpose.claim_purpose(),
            Self::RecoveredBaseline(receipt) => receipt.purpose_v2() == purpose,
            Self::RecoveredLifecycleStop(_) => purpose == OperationIntakePurposeV1::LifecycleStop }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Vacant,
    Idle,
    Active,
    Disposal,
    Closed,
}

/// Keeps both declared reservations inside the same actual Controller original.
pub(in crate::controller_receiving) struct ControllerOperationIntakesV1 {
    slots: [OperationIntakeSlotV1; 3],
}

impl ControllerOperationIntakesV1 {
    pub(in crate::controller_receiving) const fn new() -> Self {
        Self { slots: [OperationIntakeSlotV1::new(), OperationIntakeSlotV1::new(), OperationIntakeSlotV1::new()] }
    }

    pub(in crate::controller_receiving) fn slot(
        &self, purpose: OperationIntakePurposeV1,
    ) -> &OperationIntakeSlotV1 { &self.slots[purpose.index()] }

    pub(in crate::controller_receiving) fn slot_mut(
        &mut self,
        purpose: OperationIntakePurposeV1,
    ) -> &mut OperationIntakeSlotV1 {
        &mut self.slots[purpose.index()]
    }

    pub(in crate::controller_receiving) fn is_unfinished(&self) -> bool {
        self.slots.iter().any(|slot| {
            matches!(slot.phase, Phase::Active | Phase::Disposal | Phase::Closed)
        })
    }
}

pub(in crate::controller_receiving) struct OperationIntakeSlotV1 {
    funding: Option<OperationIntakeFundingV2>,
    resident: ResourceVector,
    flight_capacity: ResourceVector,
    required: ResourceVector,
    traffic_spent: ResourceVector,
    current_traffic: ResourceVector,
    upper_complete: ResourceVector,
    cold_session_complete: ResourceVector,
    cold_session_entered: bool,
    traffic_armed: bool,
    traffic_reservation: Option<Result<ResourceVector, AccountingError>>,
    operation: Option<ComponentReceivingOwnedOperationV1>,
    first: Option<ControllerReceivingErrorV1>,
    phase: Phase,
    // Outer0..3 retain the original once-only Producer scopes. D alone has
    // separate4..7 destinations, cleared only after real upper/native positive
    // disposal and freshly paid before each next turn. X never selects them.
    profile_entered: [bool; 8],
    profile_retired: [bool; 8],
    profile_prepared: [bool; 8],
    preaccept_active: bool,
    preaccept_prepared: bool,
    preaccept_turns: u64,
    preaccept_resident: ResourceVector,
}

impl OperationIntakeSlotV1 {
    const fn new() -> Self {
        Self {
            funding: None,
            resident: ResourceVector::ZERO,
            flight_capacity: ResourceVector::ZERO,
            required: ResourceVector::ZERO,
            traffic_spent: ResourceVector::ZERO,
            current_traffic: ResourceVector::ZERO,
            upper_complete: ResourceVector::ZERO,
            cold_session_complete: ResourceVector::ZERO,
            cold_session_entered: false,
            traffic_armed: false,
            traffic_reservation: None,
            operation: None,
            first: None,
            phase: Phase::Vacant,
            profile_entered: [false; 8],
            profile_retired: [false; 8],
            profile_prepared: [false; 8],
            preaccept_active: false, preaccept_prepared: false, preaccept_turns: 0,
            preaccept_resident: ResourceVector::ZERO,
        }
    }

    // Only the actual Bank/launch join supplies this exact decoded reserved
    // claim from its SAME held writer and SAME original measured policy.
    pub(in crate::controller_receiving) fn claim_once(
        &mut self,
        purpose: OperationIntakePurposeV1,
        claim: Claim,
        resident: ResourceVector,
        flight_capacity: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.phase != Phase::Vacant {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        self.phase = Phase::Closed;
        self.funding = Some(OperationIntakeFundingV2::InitialReservedClaim(claim));
        if Some(claim.native_fields().purpose) != purpose.claim_purpose() || claim.native_fields().state != ClaimState::Reserved {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        let complete = resident.checked_add(flight_capacity).map_err(ControllerReceivingErrorV1::from);
        let admitted = complete.and_then(|complete| claim.native_fields().amount.checked_sub(complete)
            .map(|_| ()).map_err(Into::into));
        if let Err(cause) = admitted {
            return self.refuse(cause);
        }
        self.resident = resident;
        self.flight_capacity = flight_capacity;
        self.phase = Phase::Idle;
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_vacant_recovered_v2(&mut self)
        -> Result<(), ControllerReceivingErrorV1> {
        if self.phase != Phase::Vacant || self.funding.is_some() || self.first.is_some() {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn bind_recovered_once_v2(
        &mut self, purpose: OperationIntakePurposeV1,
        funded: Result<super::original::RecoveredOperationIntakeFundingV2, ControllerReceivingErrorV1>,
        resident: ResourceVector, flight_capacity: ResourceVector,
    ) -> Result<OperationIntakeFundingV2, ControllerReceivingErrorV1> {
        self.require_vacant_recovered_v2()?;
        self.phase = Phase::Closed;
        let receipt = match funded { Ok(receipt) => receipt,
            Err(cause) => return Err(self.retain_refusal_v2(cause)),
        };
        let complete = match resident.checked_add(flight_capacity) {
            Ok(complete) => complete,
            Err(cause) => return Err(self.retain_refusal_v2(cause.into())),
        };
        if receipt.purpose_v2() != purpose || receipt.complete_v2() != complete {
            return Err(self.retain_refusal_v2(ControllerReceivingErrorV1::Conflict));
        }
        let funding = OperationIntakeFundingV2::RecoveredBaseline(receipt);
        self.funding = Some(funding);
        self.resident = resident;
        self.flight_capacity = flight_capacity;
        self.phase = Phase::Idle;
        Ok(funding)
    }

    pub(in crate::controller_receiving) fn require_same_funding_v2(&self,
        funding: OperationIntakeFundingV2,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.first.is_some() || self.funding != Some(funding) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_claimed_idle(
        &self,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.phase != Phase::Idle || self.funding.is_none() || self.first.is_some() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn begin_once(
        &mut self,
        required: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.begin_with_traffic_v1(required, required)
    }

    // Only the genuine named whole-declared borrower separates its capacity
    // gate from actual already-prepaid traffic. Generic bounded entry supplies
    // the same complete requirement to both planes through begin_once.
    pub(in crate::controller_receiving) fn begin_with_traffic_v1(
        &mut self,
        required: ResourceVector,
        prepaid_traffic: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.phase != Phase::Idle || self.first.is_some() || self.operation.is_some() {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        // Arm before preflight. Every failed or unfinished predecessor remains
        // resident here; a later call cannot clear its actual arithmetic owner.
        self.phase = Phase::Active;
        self.required = required;
        self.traffic_armed = false;
        self.profile_entered = [false; 8];
        self.profile_retired = [false; 8];
        self.profile_prepared = [false; 8];
        self.preaccept_active = false;
        self.preaccept_prepared = false;
        self.preaccept_turns = 0;
        self.preaccept_resident = ResourceVector::ZERO;
        self.operation = Some(ComponentReceivingOwnedOperationV1::preflight(
            self.flight_capacity, required,
        ));
        let operation = match self.operation.as_mut() {
            Some(operation) => operation,
            None => return self.refuse(ControllerReceivingErrorV1::Conflict),
        };
        if operation.consume_once().is_err() {
            let cause = operation.failure().map(|cause| ControllerReceivingErrorV1::Accounting(*cause))
                .unwrap_or(ControllerReceivingErrorV1::Conflict);
            return self.refuse(cause);
        }
        self.current_traffic = ResourceVector::ZERO;
        self.upper_complete = ResourceVector::ZERO;
        self.cold_session_complete = ResourceVector::ZERO;
        self.cold_session_entered = false;
        self.reserve_complete_traffic_v1(prepaid_traffic)?;
        self.traffic_armed = true;
        Ok(())
    }

    // Extends only this flight's cumulative reached traffic before work. The
    // enclosing original retains the failed arithmetic and permanently spent
    // predecessors. Positive disposal never changes either traffic plane.
    pub(in crate::controller_receiving) fn reserve_complete_traffic_v1(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.upper_complete = self.upper_complete.componentwise_max(complete);
        self.reserve_joined_complete_v2()
    }

    // Only a genuine active Execution Source scope can arm this finite cold
    // plane. It remains on the SAME consumed slot; subsequent upper admissions
    // automatically preserve its co-resident graph and reached traffic.
    pub(in crate::controller_receiving) fn begin_cold_session_v2(&mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.require_active()?;
        if self.cold_session_entered {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        self.cold_session_entered = true;
        self.reserve_cold_session_complete_v2(complete)
    }

    pub(in crate::controller_receiving) fn reserve_cold_session_complete_v2(&mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.require_active()?;
        if !self.cold_session_entered {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        self.cold_session_complete = self.cold_session_complete.componentwise_max(complete);
        self.reserve_joined_complete_v2()
    }

    fn reserve_joined_complete_v2(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.phase != Phase::Active || self.first.is_some()
            || self.operation.as_ref().is_none_or(|operation| !operation.is_consumed_current())
        {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        let complete = match self.upper_complete.checked_add(self.cold_session_complete)
            .and_then(|complete| {
                if self.cold_session_entered {
                    self.flight_capacity.checked_sub(complete).map(|_| complete)
                } else {
                    Ok(complete)
                }
            })
        {
            Ok(complete) => complete,
            Err(cause) => return self.refuse(ControllerReceivingErrorV1::Accounting(cause)),
        };
        let current = self.current_traffic.componentwise_max(operation_traffic_demand_v1(complete));
        self.traffic_reservation = Some(current.checked_sub(self.current_traffic)
            .and_then(|delta| self.traffic_spent.checked_add(delta))
            .and_then(|spent| operation_traffic_demand_v1(self.flight_capacity)
                .checked_sub(spent).map(|_| spent)));
        match self.traffic_reservation {
            Some(Ok(spent)) => {
                self.traffic_spent = spent;
                self.current_traffic = current;
                Ok(())
            }
            Some(Err(cause)) => self.refuse(ControllerReceivingErrorV1::Accounting(cause)),
            None => self.refuse(ControllerReceivingErrorV1::Conflict),
        }
    }

    pub(in crate::controller_receiving) fn require_active(&self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.phase != Phase::Active || self.first.is_some()
            || self.operation.as_ref().is_none_or(|operation| !operation.is_consumed_current())
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    // Complete reached resident demand is separate from consumed flight
    // traffic. Its monotone peak never resets at disposal or credits a refund.
    pub(in crate::controller_receiving) fn raise_resident(
        &mut self,
        required: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.require_active()?;
        let result = (|| {
            let (complete, _) = complete_bound_delta_v1(self.resident, required)?;
            let funding = self.funding.ok_or(ControllerReceivingErrorV1::Conflict)?;
            funding.complete_capacity_v2().checked_sub(complete.checked_add(self.flight_capacity)?)?;
            Ok(complete)
        })();
        match result {
            Ok(complete) => { self.resident = complete; Ok(()) }
            Err(cause) => self.refuse(cause),
        }
    }

    pub(in crate::controller_receiving) fn enter_profile_once(
        &mut self,
        slot: usize,
    ) -> Result<(), ControllerReceivingErrorV1> {
        // A prearmed post can run after primary poison. Its finite slot and
        // actually consumed flight must still exist. No new operation begins.
        if slot >= 8 || (slot >= 4 && (!self.preaccept_active
                || self.funding.is_none_or(|funding| !funding.has_purpose_v2(OperationIntakePurposeV1::Delete))))
            || self.profile_entered[slot]
            || !self.traffic_armed
            || !matches!(self.phase, Phase::Active | Phase::Closed)
            || self.operation.as_ref().is_none_or(|operation| !operation.is_consumed_current())
        {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        self.profile_entered[slot] = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn prepare_profile_disposal_once(&mut self, slot: usize)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if slot >= 8 || !self.profile_entered[slot] || self.profile_prepared[slot]
            || self.profile_retired[slot]
        {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        self.profile_prepared[slot] = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn retire_profile_after_disposal(&mut self, slot: usize) {
        if slot >= 8 || !self.profile_entered[slot] || !self.profile_prepared[slot] || self.profile_retired[slot] {
            std::process::abort();
        }
        self.profile_retired[slot] = true;
    }

    // Only the genuine D loan uses these four distinct recurring destinations.
    // Outer slots0..3 retain their original once-only laws. Every new turn is
    // prepaid before arming, and only actual upper disposal can clear4..7.
    pub(in crate::controller_receiving) fn refuse_delete_preaccept_turn_v1(&mut self) {
        let _ = self.refuse(ControllerReceivingErrorV1::Conflict);
    }

    pub(in crate::controller_receiving) fn next_delete_preaccept_turn_v1(&mut self)
        -> Result<u64, ControllerReceivingErrorV1>
    {
        self.require_active()?;
        if self.preaccept_active || self.preaccept_prepared
            || self.funding.is_none_or(|funding| !funding.has_purpose_v2(OperationIntakePurposeV1::Delete))
            || self.profile_entered[4..].iter().any(|entered| *entered)
        { return self.refuse(ControllerReceivingErrorV1::Conflict).map(|()| 0); }
        match self.preaccept_turns.checked_add(1) {
            Some(next) => Ok(next),
            None => self.refuse(ControllerReceivingErrorV1::Conflict).map(|()| 0),
        }
    }

    pub(in crate::controller_receiving) fn delete_preaccept_resident_v1(&self) -> ResourceVector {
        self.preaccept_resident
    }

    pub(in crate::controller_receiving) fn arm_delete_preaccept_turn_v1(&mut self, next: u64, resident: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        let expected = self.next_delete_preaccept_turn_v1()?;
        if next != expected { return self.refuse(ControllerReceivingErrorV1::Conflict); }
        self.preaccept_turns = next;
        self.preaccept_resident = self.preaccept_resident.componentwise_max(resident);
        self.preaccept_active = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn prepare_delete_preaccept_disposal_v1(&mut self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.require_active()?;
        if !self.preaccept_active || self.preaccept_prepared
            || self.profile_retired[4..] != [true; 4]
        { return self.refuse(ControllerReceivingErrorV1::Conflict); }
        self.preaccept_prepared = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn complete_delete_preaccept_disposal_v1(&mut self) {
        if !self.preaccept_active || !self.preaccept_prepared
            || self.profile_retired[4..] != [true; 4]
        { std::process::abort(); }
        self.profile_entered[4..].fill(false);
        self.profile_prepared[4..].fill(false);
        self.profile_retired[4..].fill(false);
        self.preaccept_active = false;
        self.preaccept_prepared = false;
        // Neither cumulative per-flight turns nor permanently spent traffic is
        // refunded. A later turn must prepay its next complete schedule.
    }

    pub(in crate::controller_receiving) fn prepare_disposal(&mut self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.require_active()?;
        if self.profile_retired[..4] != [true; 4] || self.preaccept_active
            || self.profile_entered[4..].iter().any(|entered| *entered)
        {
            return self.refuse(ControllerReceivingErrorV1::Conflict);
        }
        // The closed borrower has already checked every actual native post.
        // Forgetting its exclusive token leaves Disposal and prevents reentry.
        self.phase = Phase::Disposal;
        Ok(())
    }

    pub(in crate::controller_receiving) fn complete_after_disposal(&mut self) {
        if self.phase != Phase::Disposal || self.first.is_some() {
            std::process::abort();
        }
        match self.operation.take() {
            Some(operation) => operation.complete_after_disposal(),
            None => std::process::abort(),
        }
        self.phase = Phase::Idle;
    }

    pub(in crate::controller_receiving) fn failure(&self) -> Option<&ControllerReceivingErrorV1> {
        self.first.as_ref()
    }

    pub(in crate::controller_receiving) fn close(&mut self) {
        self.phase = Phase::Closed;
    }

    fn refuse(&mut self, cause: ControllerReceivingErrorV1)
        -> Result<(), ControllerReceivingErrorV1>
    {
        Err(self.retain_refusal_v2(cause))
    }

    fn retain_refusal_v2(&mut self, cause: ControllerReceivingErrorV1) -> ControllerReceivingErrorV1 {
        if self.first.is_none() { self.first = Some(cause); }
        self.phase = Phase::Closed;
        ControllerReceivingErrorV1::Conflict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::ResourceDimension as D;
    use aos_sandbox_protocol::domain_ledger::resource_bank as bank;
    use sha2::{Digest as _, Sha256};

    // Only canonical arithmetic DATA is built here. No actual native original,
    // Bank writer, profile, accepted operation or effect authority is fabricated.
    fn declared_claim() -> Claim {
        let unit = D::ALL.into_iter().fold(ResourceVector::ZERO, |value, dimension| {
            value.with(dimension, 1_048_576_000)
        });
        let mut bytes = Vec::with_capacity(bank::OPERATION_INTAKE_IMAGE_POLICY_BYTES);
        bytes.extend_from_slice(b"AOSRSB08");
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&[2; 16]);
        for scale in [40, 1, 10, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] {
            for dimension in D::ALL {
                bytes.extend_from_slice(&(unit.get(dimension) * scale).to_be_bytes());
            }
        }
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        let policy = bank::decode_component_image_policy(&bytes).unwrap();
        let mut delivery = Vec::from(&b"AOSRSE01"[..]);
        delivery.extend_from_slice(&[1; 16]);
        delivery.extend_from_slice(&[2; 16]);
        delivery.extend_from_slice(&[3; 16]);
        delivery.extend_from_slice(&[4; 16]);
        delivery.extend_from_slice(&[5; 32]);
        delivery.extend_from_slice(&[6; 16]);
        delivery.extend_from_slice(&Sha256::digest(&delivery));
        let (identity, _) = bank::decode_pid1_delivery(&delivery).unwrap();
        bank::delete_operation_intake_claim(identity, policy).unwrap().unwrap()
    }

    #[test]
    fn refused_recovered_debit_retains_first_accounting_cause_and_cannot_claim_old_capacity() {
        let mut slot = OperationIntakeSlotV1::new();
        let capacity = ResourceVector::ZERO.with(D::NetworkBytes, 10);
        let excessive = capacity.with(D::NetworkBytes, 11);
        let cause = capacity.checked_sub(excessive).unwrap_err();

        assert!(slot.bind_recovered_once_v2(OperationIntakePurposeV1::Delete,
            Err(cause.into()), ResourceVector::ZERO, capacity).is_err());
        let first = slot.failure().unwrap() as *const ControllerReceivingErrorV1;
        assert!(matches!(slot.failure(), Some(ControllerReceivingErrorV1::Accounting(_))));
        assert!(slot.funding.is_none());
        assert!(slot.phase == Phase::Closed);

        let old_claim = declared_claim();
        assert!(slot.claim_once(OperationIntakePurposeV1::Delete, old_claim,
            ResourceVector::ZERO, old_claim.native_fields().amount).is_err());
        assert!(slot.bind_recovered_once_v2(OperationIntakePurposeV1::Execution,
            Err(ControllerReceivingErrorV1::Conflict), ResourceVector::ZERO, capacity).is_err());
        assert_eq!(slot.failure().unwrap() as *const ControllerReceivingErrorV1, first);
        assert!(slot.funding.is_none());
        assert!(slot.begin_once(ResourceVector::ZERO).is_err());
    }

    #[test]
    fn cold_and_upper_graphs_coexist_across_interleaved_growth() {
        let mut slot = OperationIntakeSlotV1::new();
        let capacity = ResourceVector::ZERO.with(D::MemoryBytes, 100).with(D::NetworkBytes, 100);
        slot.claim_once(OperationIntakePurposeV1::Delete, declared_claim(), ResourceVector::ZERO, capacity).unwrap();
        slot.begin_once(ResourceVector::ZERO).unwrap();

        slot.begin_cold_session_v2(ResourceVector::ZERO.with(D::MemoryBytes, 30).with(D::NetworkBytes, 10)).unwrap();
        slot.reserve_complete_traffic_v1(ResourceVector::ZERO.with(D::MemoryBytes, 40).with(D::NetworkBytes, 20)).unwrap();
        slot.reserve_complete_traffic_v1(ResourceVector::ZERO.with(D::MemoryBytes, 60).with(D::NetworkBytes, 25)).unwrap();

        assert_eq!(slot.current_traffic.get(D::NetworkBytes), 35);
        assert_eq!(slot.traffic_spent.get(D::NetworkBytes), 35);
        assert_eq!(slot.cold_session_complete.get(D::MemoryBytes), 30);
        assert!(slot.reserve_cold_session_complete_v2(ResourceVector::ZERO.with(D::MemoryBytes, 45)).is_err());
        let first = std::ptr::from_ref(slot.failure().unwrap());
        assert!(matches!(slot.failure(), Some(ControllerReceivingErrorV1::Accounting(_))));
        assert!(slot.reserve_complete_traffic_v1(ResourceVector::ZERO).is_err());
        assert_eq!(std::ptr::from_ref(slot.failure().unwrap()), first);
    }

    #[test]
    fn cold_reentry_never_restarts_or_refunds_the_consumed_flight() {
        let mut slot = OperationIntakeSlotV1::new();
        let capacity = ResourceVector::ZERO.with(D::NetworkBytes, 100);
        slot.claim_once(OperationIntakePurposeV1::Delete, declared_claim(), ResourceVector::ZERO, capacity).unwrap();
        slot.begin_once(ResourceVector::ZERO).unwrap();
        slot.begin_cold_session_v2(ResourceVector::ZERO.with(D::NetworkBytes, 20)).unwrap();
        slot.reserve_cold_session_complete_v2(ResourceVector::ZERO.with(D::NetworkBytes, 30)).unwrap();

        assert!(slot.begin_cold_session_v2(ResourceVector::ZERO).is_err());
        assert_eq!(slot.traffic_spent.get(D::NetworkBytes), 30);
        assert!(slot.operation.as_ref().unwrap().is_consumed_current());
        assert!(slot.reserve_cold_session_complete_v2(ResourceVector::ZERO).is_err());
        assert_eq!(slot.traffic_spent.get(D::NetworkBytes), 30);
    }

    #[test]
    fn every_dimension_refuses_before_consumption_without_replacing_the_first_cause() {
        let claim = declared_claim();
        let capacity = claim.native_fields().amount;
        for dimension in D::ALL {
            let mut slot = OperationIntakeSlotV1::new();
            slot.claim_once(OperationIntakePurposeV1::Delete, claim, ResourceVector::ZERO, capacity).unwrap();
            let excessive = ResourceVector::ZERO.with(dimension, capacity.get(dimension) + 1);

            assert!(slot.begin_once(excessive).is_err());
            let first = std::ptr::from_ref(slot.failure().unwrap());
            assert!(slot.begin_once(ResourceVector::ZERO).is_err());

            assert_eq!(first, std::ptr::from_ref(slot.failure().unwrap()));
            assert!(slot.operation.as_ref().is_some_and(|operation| !operation.is_consumed_current()));
        }
    }

    #[test]
    fn unfinished_positive_preparation_cannot_rearm_or_offer_a_second_disposal() {
        let claim = declared_claim();
        let capacity = claim.native_fields().amount;
        let mut slot = OperationIntakeSlotV1::new();
        slot.claim_once(OperationIntakePurposeV1::Delete, claim, ResourceVector::ZERO, capacity).unwrap();
        slot.begin_once(ResourceVector::ZERO).unwrap();
        for index in 0..4 {
            slot.enter_profile_once(index).unwrap();
            slot.prepare_profile_disposal_once(index).unwrap();
            slot.retire_profile_after_disposal(index);
        }
        slot.prepare_disposal().unwrap();

        assert!(slot.prepare_disposal().is_err());
        assert!(slot.begin_once(ResourceVector::ZERO).is_err());
        assert!(slot.operation.as_ref().is_some_and(ComponentReceivingOwnedOperationV1::is_consumed_current));
    }

    #[test]
    fn positive_flights_keep_the_original_resident_debt_and_claim() {
        let claim = declared_claim();
        let resident = ResourceVector::ZERO.with(D::MemoryBytes, 4096);
        let capacity = claim.native_fields().amount.checked_sub(resident).unwrap();
        let required = ResourceVector::ZERO.with(D::NetworkBytes, 4096).with(D::OutputBytes, 1024);
        let mut slot = OperationIntakeSlotV1::new();
        slot.claim_once(OperationIntakePurposeV1::Delete, claim, resident, capacity).unwrap();
        for ordinal in 1..=2 {
            slot.begin_once(required).unwrap();
            for index in 0..4 {
                slot.enter_profile_once(index).unwrap();
                slot.prepare_profile_disposal_once(index).unwrap();
                slot.retire_profile_after_disposal(index);
            }
            slot.prepare_disposal().unwrap();
            slot.complete_after_disposal();

            assert_eq!(slot.resident, resident);
            assert_eq!(slot.funding.and_then(OperationIntakeFundingV2::initial_claim_v2), Some(claim));
            assert_eq!(slot.flight_capacity, capacity);
            assert_eq!(slot.traffic_spent.get(D::NetworkBytes), 4096 * ordinal);
            assert_eq!(slot.traffic_spent.get(D::OutputBytes), 1024 * ordinal);
            assert_eq!(slot.traffic_spent.get(D::MemoryBytes), 0);
        }
    }

    #[test]
    fn positive_disposal_never_restores_any_consumable_dimension() {
        let claim = declared_claim();
        let capacity = claim.native_fields().amount;
        let traffic = operation_traffic_demand_v1(capacity);
        for dimension in D::ALL.into_iter().filter(|dimension| traffic.get(*dimension) != 0) {
            let mut slot = OperationIntakeSlotV1::new();
            slot.claim_once(OperationIntakePurposeV1::Delete, claim,
                ResourceVector::ZERO, capacity).unwrap();
            let full = ResourceVector::ZERO.with(dimension, capacity.get(dimension));
            slot.begin_once(full).unwrap();
            for index in 0..4 {
                slot.enter_profile_once(index).unwrap();
                slot.prepare_profile_disposal_once(index).unwrap();
                slot.retire_profile_after_disposal(index);
            }
            slot.prepare_disposal().unwrap();
            slot.complete_after_disposal();

            assert_eq!(slot.traffic_spent, full);
            assert!(slot.begin_once(ResourceVector::ZERO.with(dimension, 1)).is_err());
            let first = std::ptr::from_ref(slot.failure().unwrap());
            assert!(matches!(slot.traffic_reservation,
                Some(Err(AccountingError::InsufficientAmount { dimension: failed, .. })) if failed == dimension));
            assert_eq!(slot.traffic_spent, full);
            assert!(slot.enter_profile_once(0).is_err());
            assert_eq!(slot.profile_entered, [false; 8]);
            assert!(slot.begin_once(ResourceVector::ZERO).is_err());
            assert_eq!(first, std::ptr::from_ref(slot.failure().unwrap()));
            assert_eq!(slot.funding.and_then(OperationIntakeFundingV2::initial_claim_v2), Some(claim));
            assert_eq!(slot.flight_capacity, capacity);
        }
    }

    #[test]
    fn whole_capacity_gate_keeps_two_actual_stage_schedules_and_refuses_a_later_growth() {
        let claim = declared_claim();
        let capacity = claim.native_fields().amount;
        let mut slot = OperationIntakeSlotV1::new();
        slot.claim_once(OperationIntakePurposeV1::Delete, claim,
            ResourceVector::ZERO, capacity).unwrap();
        let quarter = ResourceVector::ZERO
            .with(D::NetworkBytes, capacity.get(D::NetworkBytes) / 4)
            .with(D::OutputBytes, capacity.get(D::OutputBytes) / 4);
        let per_flight = quarter.checked_add(quarter).unwrap();
        for ordinal in 1..=2 {
            slot.begin_with_traffic_v1(capacity, quarter).unwrap();
            slot.reserve_complete_traffic_v1(per_flight).unwrap();
            // Rechecking an already-paid frontier cannot spend it twice.
            slot.reserve_complete_traffic_v1(quarter).unwrap();
            for index in 0..4 {
                slot.enter_profile_once(index).unwrap();
                slot.prepare_profile_disposal_once(index).unwrap();
                slot.retire_profile_after_disposal(index);
            }
            slot.prepare_disposal().unwrap();
            slot.complete_after_disposal();

            assert_eq!(slot.funding.and_then(OperationIntakeFundingV2::initial_claim_v2), Some(claim));
            assert_eq!(slot.flight_capacity, capacity);
            assert_eq!(slot.traffic_spent.get(D::NetworkBytes), per_flight.get(D::NetworkBytes) * ordinal);
            assert_eq!(slot.traffic_spent.get(D::OutputBytes), per_flight.get(D::OutputBytes) * ordinal);
        }
        assert!(slot.begin_with_traffic_v1(capacity,
            ResourceVector::ZERO.with(D::NetworkBytes, 1)).is_err());
        assert!(slot.enter_profile_once(0).is_err());
        let first = std::ptr::from_ref(slot.failure().unwrap());
        assert!(slot.begin_once(ResourceVector::ZERO).is_err());
        assert_eq!(first, std::ptr::from_ref(slot.failure().unwrap()));
    }


    #[test]
    fn reached_traffic_refusal_keeps_prepaid_independent_posts_available() {
        let claim = declared_claim();
        let capacity = claim.native_fields().amount;
        let mut slot = OperationIntakeSlotV1::new();
        slot.claim_once(OperationIntakePurposeV1::Delete, claim,
            ResourceVector::ZERO, capacity).unwrap();
        let half = ResourceVector::ZERO.with(D::NetworkBytes, capacity.get(D::NetworkBytes) / 2);
        slot.begin_with_traffic_v1(capacity, half).unwrap();
        for index in 0..4 {
            slot.enter_profile_once(index).unwrap();
            slot.prepare_profile_disposal_once(index).unwrap();
            slot.retire_profile_after_disposal(index);
        }
        slot.prepare_disposal().unwrap();
        slot.complete_after_disposal();

        slot.begin_with_traffic_v1(capacity, half).unwrap();
        slot.enter_profile_once(0).unwrap();
        assert!(slot.reserve_complete_traffic_v1(
            half.with(D::NetworkBytes, half.get(D::NetworkBytes) + 1)).is_err());
        let first = std::ptr::from_ref(slot.failure().unwrap());

        // This is the already-paid after slot, not a new healthy operation.
        slot.enter_profile_once(2).unwrap();
        assert!(slot.begin_once(ResourceVector::ZERO).is_err());
        assert_eq!(first, std::ptr::from_ref(slot.failure().unwrap()));
        assert_eq!(slot.traffic_spent.get(D::NetworkBytes), capacity.get(D::NetworkBytes));
    }

    #[test]
    fn delete_preaccept_positive_retirement_keeps_outer_slots_and_spent_traffic() {
        let claim = declared_claim();
        let capacity = claim.native_fields().amount;
        let mut slot = OperationIntakeSlotV1::new();
        slot.claim_once(OperationIntakePurposeV1::Delete, claim, ResourceVector::ZERO, capacity).unwrap();
        slot.begin_once(ResourceVector::ZERO.with(D::NetworkBytes, 10)).unwrap();
        for index in 0..2 {
            slot.enter_profile_once(index).unwrap();
            slot.prepare_profile_disposal_once(index).unwrap();
            slot.retire_profile_after_disposal(index);
        }

        let next = slot.next_delete_preaccept_turn_v1().unwrap();
        slot.reserve_complete_traffic_v1(ResourceVector::ZERO.with(D::NetworkBytes, 20)).unwrap();
        slot.arm_delete_preaccept_turn_v1(next, ResourceVector::ZERO).unwrap();
        for index in 4..8 {
            slot.enter_profile_once(index).unwrap();
            slot.prepare_profile_disposal_once(index).unwrap();
            slot.retire_profile_after_disposal(index);
        }
        slot.prepare_delete_preaccept_disposal_v1().unwrap();
        slot.complete_delete_preaccept_disposal_v1();

        assert_eq!(slot.profile_retired[..4], [true, true, false, false]);
        assert_eq!(slot.profile_entered[4..], [false; 4]);
        assert_eq!(slot.traffic_spent.get(D::NetworkBytes), 20);
        assert_eq!(slot.next_delete_preaccept_turn_v1().unwrap(), 2);
        assert!(slot.operation.as_ref().unwrap().is_consumed_current());
    }

    #[test]
    fn poisoned_delete_turn_still_admits_its_prepaid_after_and_outer_debts() {
        let claim = declared_claim();
        let capacity = claim.native_fields().amount;
        let mut slot = OperationIntakeSlotV1::new();
        slot.claim_once(OperationIntakePurposeV1::Delete, claim, ResourceVector::ZERO, capacity).unwrap();
        slot.begin_once(ResourceVector::ZERO).unwrap();
        slot.arm_delete_preaccept_turn_v1(1, ResourceVector::ZERO).unwrap();
        slot.enter_profile_once(4).unwrap();
        slot.refuse_delete_preaccept_turn_v1();
        let first = std::ptr::from_ref(slot.failure().unwrap());

        slot.enter_profile_once(6).unwrap();
        slot.enter_profile_once(7).unwrap();
        slot.enter_profile_once(2).unwrap();
        slot.enter_profile_once(3).unwrap();

        assert!(slot.prepare_delete_preaccept_disposal_v1().is_err());
        assert!(slot.next_delete_preaccept_turn_v1().is_err());
        assert_eq!(first, std::ptr::from_ref(slot.failure().unwrap()));
        assert!(slot.preaccept_active);
        assert!(slot.operation.as_ref().unwrap().is_consumed_current());
    }

}

impl OperationIntakeSlotV1 {
    // A closed financial comparison, not an intake or old-claim adopter.
    pub(in crate::controller_receiving) fn recovered_idle_funding_v2(&self)
        -> Result<super::original::RecoveredOperationIntakeFundingV2, ControllerReceivingErrorV1>
    {
        if self.phase != Phase::Idle || self.first.is_some() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        match self.funding {
            Some(OperationIntakeFundingV2::RecoveredBaseline(receipt)) => Ok(receipt),
            _ => Err(ControllerReceivingErrorV1::Conflict),
        }
    }
}

#[cfg(test)]
mod recovered_enrollment_tests {
    use super::*;

    #[test]
    fn idle_without_a_genuine_recovered_debit_is_not_enrollment_funding() {
        let mut slot = OperationIntakeSlotV1::new();
        assert!(slot.recovered_idle_funding_v2().is_err());

        // Even a forged phase in this private test cannot replace the actual
        // opaque same-ledger debit receipt; production has no phase setter.
        slot.phase = Phase::Idle;
        assert!(slot.recovered_idle_funding_v2().is_err());
        assert!(slot.funding.is_none());
    }
}

impl OperationIntakeSlotV1 {
    pub(in crate::controller_receiving) fn bind_stop_seed_once_v3(&mut self,
        receipt: super::original::RecoveredLifecycleStopFundingV3,
    ) -> Result<OperationIntakeFundingV2, ControllerReceivingErrorV1> {
        self.require_vacant_recovered_v2()?;
        self.phase = Phase::Closed;
        let funding = OperationIntakeFundingV2::RecoveredLifecycleStop(receipt);
        self.resident = receipt.record_data_v3().complete_v3();
        self.funding = Some(funding);
        self.phase = Phase::Idle;
        Ok(funding)
    }

    pub(in crate::controller_receiving) fn require_stop_seed_v3(&self)
        -> Result<(), ControllerReceivingErrorV1> {
        if self.phase != Phase::Idle || self.first.is_some()
            || !matches!(self.funding, Some(OperationIntakeFundingV2::RecoveredLifecycleStop(_)))
        { return Err(ControllerReceivingErrorV1::Conflict); }
        Ok(())
    }
}
