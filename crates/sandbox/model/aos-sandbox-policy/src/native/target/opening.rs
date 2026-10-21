//! Transfers the actual fixed Policy opening into its genuine target owner.

use super::{RootPolicyTargetOriginalV1, currentness::PolicyTargetCurrentCustodyV1};
use crate::native::{
    PolicyNativeJournalErrorV1 as ErrorV1,
    journal::{RootPolicyJournalConstructionOriginalV1, RootPolicyJournalPurposeV1},
};
use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1;
use aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

/// Parks the original Policy acquisition until full replay and owed name posts.
#[must_use]
pub struct RootPolicyTargetConstructionOriginalV1 {
    physical: RootPolicyJournalConstructionOriginalV1,
    selected_entered: bool,
    ordinary: Option<Result<crate::native::journal::RootPolicyJournalV1, ErrorV1>>,
    completed: bool,
}

impl RootPolicyTargetConstructionOriginalV1 {
    /// Creates an inert destination before acquisition or receiving work.
    #[must_use]
    pub fn new() -> Self {
        Self {
            physical: RootPolicyJournalConstructionOriginalV1::new(),
            selected_entered: false,
            ordinary: None,
            completed: false,
        }
    }

    /// Prices the actual target/header planes and existing fixed native opener.
    ///
    /// # Errors
    /// Preserves native supplier errors and checked representation overflow.
    pub fn fixed_demand_v1() -> Result<ResourceVector, ErrorV1> {
        // The lower invoice already pays its inline constructor and journal.
        // Only the larger enclosing owner/header planes are additional here.
        let bytes = std::mem::size_of::<Self>()
            .checked_sub(std::mem::size_of::<RootPolicyJournalConstructionOriginalV1>())
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<RootPolicyTargetOriginalV1>()
                    .checked_sub(std::mem::size_of::<crate::native::journal::RootPolicyJournalV1>())?
            ))
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        RootPolicyJournalConstructionOriginalV1::fixed_demand_v1(
            RootPolicyJournalPurposeV1::CurrentPolicy,
        )?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        .map_err(|_| ErrorV1::geometry())?
        .checked_add(PolicyTargetCurrentCustodyV1::constructor_demand_v1()?)
        .map_err(|_| ErrorV1::geometry())?
        .checked_add(super::owed_names::PolicyTargetOwedNamesCustodyV1::constructor_demand_v1()?)
        .map_err(|_| ErrorV1::geometry())
    }

    /// Enters the same Initial's once-only fixed Policy capture and before names.
    pub fn prepare_once(&mut self, initial: &mut RootInitialReceivingOriginalV1) {
        if self.selected_entered || self.ordinary.is_some() || self.completed {
            return;
        }
        self.selected_entered = true;
        self.physical
            .prepare_once(initial, RootPolicyJournalPurposeV1::CurrentPolicy);
        self.physical.observe_names_before_once();
    }

    // Current constructs its full captured-extent geometry before the original
    // names-before observation, exactly like the former private writer owner.
    pub(in crate::native) fn prepare_current_capture_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) {
        if self.selected_entered || self.ordinary.is_some() || self.completed {
            return;
        }
        self.selected_entered = true;
        self.physical.prepare_once(initial, RootPolicyJournalPurposeV1::CurrentPolicy);
    }

    pub(in crate::native) fn observe_current_names_before_once_v1(&mut self) {
        self.physical.observe_names_before_once();
    }

    /// Opens only the explicit ordinary fixed compiler-state target.
    ///
    /// This preserves the existing ordinary allocation policy. It creates no
    /// selected Initial, financial original or publication eligibility. The
    /// caller owns its actual entered ordinary Authority before this operation.
    /// Failed acquisition remains parked here; it cannot select another mode.
    pub fn open_fixed_ordinary_once_v1(&mut self) {
        if self.selected_entered || self.ordinary.is_some() || self.completed {
            return;
        }
        self.ordinary = Some(
            crate::native::journal::RootPolicyJournalV1::open_fixed_ordinary_policy_v1(),
        );
    }

    /// Reports successful replay of the original selected opening.
    #[must_use]
    pub fn replay_ready_v1(&self) -> bool {
        self.physical.ready()
    }

    /// Borrows the same captured prefix without constructing another native reader.
    #[must_use]
    pub fn extent(&self) -> Option<&CanonicalReplayExtentDataV1> {
        self.physical.extent()
    }

    /// Prices the captured prefix's actual index before construction.
    ///
    /// # Errors
    /// Refuses missing capture or native index geometry overflow.
    pub fn index_demand_v1(&self) -> Result<ResourceVector, ErrorV1> {
        self.physical.index_demand_v1()
    }

    pub(in crate::native) fn variable_components_v1(
        &self,
    ) -> Result<[ResourceVector; 3], ErrorV1> {
        self.physical.variable_components_v1()
    }

    /// Executes the same full semantic recipe on the original opening cursor.
    pub fn replay_once(&mut self) {
        if !self.selected_entered || self.ordinary.is_some() {
            return;
        }
        self.physical.replay_once();
    }

    /// Completes independently owed name observations after every replay result.
    pub fn finish_names_once(&mut self) {
        if !self.selected_entered || self.ordinary.is_some() {
            return;
        }
        self.physical.finish_names_once();
    }

    /// Transfers only the actual completed same-opening native target.
    ///
    /// Failure leaves all reached native prefixes in the original constructor.
    #[must_use]
    pub fn take_target_once(&mut self) -> Option<RootPolicyTargetOriginalV1> {
        if self.completed {
            return None;
        }
        self.completed = true;
        let journal = match self.ordinary.take() {
            Some(Ok(journal)) => Some(journal),
            Some(Err(error)) => {
                self.ordinary = Some(Err(error));
                None
            }
            None if self.selected_entered => self.physical.take_journal_once(),
            None => None,
        }?;
        Some(RootPolicyTargetOriginalV1 {
            journal,
            current: PolicyTargetCurrentCustodyV1::new(),
            owed_names: super::owed_names::PolicyTargetOwedNamesCustodyV1::new(),
        })
    }

    pub(in crate::native) fn prefix_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ordinary.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.physical.prefix_failure_v1())
    }

    pub(in crate::native) fn remaining_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.physical.remaining_failure_v1()
    }

    pub(in crate::native) fn concrete_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ordinary.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.physical.concrete_failure_v1())
    }

    /// Borrows the actual original failure without retrying or replacing its cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ordinary.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.physical.failure())
    }
}
