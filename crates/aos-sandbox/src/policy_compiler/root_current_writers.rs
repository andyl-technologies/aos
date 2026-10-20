//! Retains the two actual fixed Root writers before variable current-cut replay.
//!
//! Authority precedes compiler state, preserving Root-last lock order. Both
//! roles reuse the same captured Native engine as startup and Storage. This
//! custody never grants RootR, a current cut, signing or a phase transition.

use std::path::Path;

use aos_sandbox_core::ResourceVector;

use crate::journal::{
    Journal, JournalError, JournalLimits, ProtectedJournalPreopenReplayExtentV1,
    ProtectedWriterOpenOriginalsV1, RecoveryReport,
};

use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL, PROTECTED_POLICY_ROOT,
    policy_authority_journal_limits, policy_state_journal_limits,
};

#[derive(Clone, Copy)]
pub(crate) enum RootCurrentWriterRoleV1 {
    Authority,
    Policy,
}

impl RootCurrentWriterRoleV1 {
    pub(crate) const ALL: [Self; 2] = [Self::Authority, Self::Policy];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Authority => 0,
            Self::Policy => 1,
        }
    }

    fn native_purpose(self) -> crate::journal::root_construction::RootJournalPurposeV1 {
        match self {
            Self::Authority => crate::journal::root_construction::RootJournalPurposeV1::CurrentAuthority,
            Self::Policy => crate::journal::root_construction::RootJournalPurposeV1::CurrentPolicy,
        }
    }

}

struct RootCurrentCapturedWriterV1 {
    native: crate::journal::root_construction::RootJournalConstructionOriginalV1,
    names_before: Option<Result<(), JournalError>>,
    names_after: Option<Result<(), JournalError>>,
    opened: Option<(Journal, RecoveryReport)>,
    attempted: bool,
    replayed: bool,
    closed: bool,
}

impl Default for RootCurrentCapturedWriterV1 {
    fn default() -> Self {
        Self {
            native: crate::journal::root_construction::RootJournalConstructionOriginalV1::new(),
            names_before: None,
            names_after: None,
            opened: None,
            attempted: false,
            replayed: false,
            closed: false,
        }
    }
}

/// Parks only the actual fixed authority/state current-cut native recipes.
///
/// The constructor is private to the Root compiler owner. Neither role selector
/// nor a captured extent constructs an original receiving grant or writer.
pub(crate) struct RootCreateStorageCurrentWritersV1 {
    slots: [RootCurrentCapturedWriterV1; 2],
}

impl RootCreateStorageCurrentWritersV1 {
    pub(super) fn new() -> Self {
        Self { slots: std::array::from_fn(|_| RootCurrentCapturedWriterV1::default()) }
    }

    pub(crate) fn fixed_preparation_demand() -> Result<ResourceVector, JournalError> {
        let mut demand = ResourceVector::ZERO;
        for role in RootCurrentWriterRoleV1::ALL {
            let fixed = crate::journal::root_construction::RootJournalConstructionOriginalV1::fixed_demand_v1(
                role.native_purpose(),
            )?;
            demand = demand.checked_add(fixed).map_err(|_| JournalError::ProtectedBoundary)?;
        }
        Ok(demand)
    }

    pub(crate) fn prepare_once(
        &mut self,
        role: RootCurrentWriterRoleV1,
        initial: &mut aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1,
    ) {
        let slot = &mut self.slots[role.index()];
        if slot.attempted || slot.closed {
            slot.closed = true;
            initial.latch_root_refusal_v1();
            return;
        }
        slot.attempted = true;
        slot.native.prepare_once(initial, role.native_purpose());
        // Current-cut names are sampled at the same former pre-extent frontier.
        slot.native.observe_names_before_once();
        slot.names_before = Some(if slot.native.failure().is_none() && slot.native.extent().is_some() {
            Ok(())
        } else { Err(JournalError::ProtectedBoundary) });
    }

    pub(crate) fn index_demand_v1(&self, role: RootCurrentWriterRoleV1) -> Result<ResourceVector, JournalError> {
        self.slots[role.index()].native.index_demand_v1()
    }

    pub(crate) fn captured_extent(
        &self,
        role: RootCurrentWriterRoleV1,
    ) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        let slot = &self.slots[role.index()];
        if slot.closed || !matches!(slot.names_before, Some(Ok(()))) {
            return None;
        }
        slot.native.extent()
    }

    pub(crate) fn replay_once(&mut self, role: RootCurrentWriterRoleV1) {
        let slot = &mut self.slots[role.index()];
        if slot.closed || slot.replayed || !matches!(slot.names_before, Some(Ok(()))) {
            slot.closed = true;
            return;
        }
        slot.replayed = true;
        slot.native.replay_once();
    }

    pub(crate) fn finish_names_once(&mut self, role: RootCurrentWriterRoleV1) {
        let slot = &mut self.slots[role.index()];
        if slot.names_after.is_some() {
            slot.closed = true;
            return;
        }
        // Even a failed replay or denied variable permit owes this independent
        // original-name post; no parser retry or second prefix capture occurs.
        slot.native.finish_names_once();
        slot.names_after = Some(if slot.native.failure().is_none() { Ok(()) }
            else { Err(JournalError::ProtectedBoundary) });
    }

    pub(crate) fn replay_ready(&self, role: RootCurrentWriterRoleV1) -> bool {
        let slot = &self.slots[role.index()];
        !slot.closed && slot.replayed && slot.native.ready()
            && matches!(slot.names_before, Some(Ok(())))
            && matches!(slot.names_after, Some(Ok(())))
    }

    pub(crate) fn take_opened_once(&mut self, role: RootCurrentWriterRoleV1) {
        if !self.replay_ready(role) {
            self.slots[role.index()].closed = true;
            return;
        }
        let slot = &mut self.slots[role.index()];
        if slot.opened.is_some() {
            slot.closed = true;
            return;
        }
        slot.native.take_opened_once();
        slot.opened = slot.native.take_pair_once();
        if slot.opened.is_none() {
            slot.closed = true;
        }
    }

    pub(crate) fn opened_ready(&self, role: RootCurrentWriterRoleV1) -> bool {
        let slot = &self.slots[role.index()];
        !slot.closed && slot.opened.is_some()
    }

    pub(super) fn authority_and_policy(
        &mut self,
    ) -> Result<(&mut Journal, &Journal), JournalError> {
        let (authority, policy) = self.slots.split_at_mut(1);
        let authority = authority[0].opened.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let policy = policy[0].opened.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        Ok((&mut authority.0, &policy.0))
    }

    // The terminal producer admits this construction term before creating its
    // two private identity carriers. Cloning their existing Arc allocates no
    // new instance, native owner or financial account.
    pub(crate) fn serving_identity_demand_v1() -> Result<ResourceVector, JournalError> {
        crate::journal::root_construction::RootJournalServingIdentityV1::pair_demand_v1()
    }

    pub(crate) fn serving_identities_v1(
        &self,
    ) -> Result<[crate::journal::root_construction::RootJournalServingIdentityV1; 2], JournalError> {
        let authority = self.serving_journal_v1(RootCurrentWriterRoleV1::Authority)?;
        let policy = self.serving_journal_v1(RootCurrentWriterRoleV1::Policy)?;
        Ok([authority.root_serving_identity_v1()?, policy.root_serving_identity_v1()?])
    }

    pub(crate) fn require_serving_identities_v1(
        &self,
        identities: &[crate::journal::root_construction::RootJournalServingIdentityV1; 2],
    ) -> Result<(), JournalError> {
        for role in RootCurrentWriterRoleV1::ALL {
            self.serving_journal_v1(role)?
                .require_root_serving_identity_v1(&identities[role.index()])?;
        }
        Ok(())
    }

    pub(crate) fn require_serving_financial_v1(
        &self,
        expected: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> Result<(), JournalError> {
        for role in RootCurrentWriterRoleV1::ALL {
            self.serving_journal_v1(role)?.require_root_serving_financial_v1(expected)?;
        }
        Ok(())
    }

    /// Joins completed issuer custody to this same held policy writer.
    ///
    /// # Errors
    /// Preserves unavailable writer, incomplete capture or changed saved pins.
    pub(crate) fn require_serving_pins_v1(
        &self,
        pins: &super::create_storage_current::pins::RootCurrentPinsStateV1,
    ) -> Result<(), super::create_storage_current::pins::RootServingPinsErrorV1> {
        let policy = self.serving_journal_v1(RootCurrentWriterRoleV1::Policy)
            .map_err(super::create_storage_current::pins::RootServingPinsErrorV1::Writers)?;
        pins.require_serving_policy_v1(policy)
    }

    pub(super) fn serving_policy_interval_journal_v1(&self, role: RootCurrentWriterRoleV1)
        -> Result<&Journal, JournalError>
    {
        self.serving_journal_v1(role)
    }

    pub(super) fn owed_policy_interval_journal_v1(&self, role: RootCurrentWriterRoleV1)
        -> Result<&Journal, JournalError>
    {
        self.slots[role.index()].opened.as_ref().map(|(journal, _)| journal)
            .ok_or(JournalError::ProtectedBoundary)
    }

    fn serving_journal_v1(&self, role: RootCurrentWriterRoleV1) -> Result<&Journal, JournalError> {
        let slot = &self.slots[role.index()];
        if slot.closed || !slot.replayed || slot.native.failure().is_some()
            || !matches!(slot.names_before, Some(Ok(())))
            || !matches!(slot.names_after, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        slot.opened.as_ref().map(|(journal, _)| journal)
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Borrows this writer stage's actual failures without a shared phase marker.
    ///
    /// Later Root stages may close the same invocation after both writers have
    /// succeeded. Their own causes must remain visible to the outer attempt.
    pub(crate) fn concrete_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for slot in &self.slots {
            if let Some(cause) = slot.opened.as_ref().and_then(|(journal, _)| journal.retained_selected_failure_v1()) {
                return Some(cause);
            }
            if let Some(cause) = slot.native.concrete_failure_v1() {
                return Some(cause);
            }
        }
        for slot in &self.slots {
            if let Some(Err(cause)) = &slot.names_before { return Some(cause); }
            if let Some(Err(cause)) = &slot.names_after { return Some(cause); }
        }
        None
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.concrete_failure_v1().or_else(|| {
            self.slots.iter().find_map(|slot| slot.native.failure())
        })
    }
}
