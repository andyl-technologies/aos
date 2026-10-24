//! Retains the initial Open's independently owed writer, peer and clock posts.
//!
//! This owner is distinct from the append crossing. Its genuine history arm is
//! acquired before initial identity/clock preparation and remains owned across
//! every preparation, append and readback refusal. No completed DATA is adopted.

use std::error::Error;

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootAcceptedHistoryBorrowerV1, RootObservationErrorV1, RootSelectedStartupBorrowV1,
    RootUpperMutationGuardV1,
};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use crate::native::journal::names::{
    RootFixedNameRecipeV1, RootFixedNameRoleV1, RootPolicyNameObservationOriginalV1,
};
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{
    RootInitialOpenErrorV1 as E, RootInitialOpenPreparedOriginalV1,
    RootInitialClockErrorV1, observe_names_v1,
};
use super::writers::RootCurrentWritersOriginalV1;

type NamesResult = Option<Result<ProtectedJournalNamesV1, E>>;

pub(super) struct RootInitialOpenPostsOriginalV1 {
    history: Option<RootCurrentHistoryPostOriginalV1>,
    authority_physical: RootPolicyNameObservationOriginalV1,
    policy_physical: RootPolicyNameObservationOriginalV1,
    authority_location: RootPolicyNameObservationOriginalV1,
    policy_location: RootPolicyNameObservationOriginalV1,
    authority_names: NamesResult,
    policy_names: NamesResult,
    authority_location_returned: Option<Result<(), E>>,
    policy_location_returned: Option<Result<(), E>>,
    names_binding: Option<Result<(), E>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    clock_original: RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>,
    clock: Option<Result<aos_sandbox_model::RawPairedClockSample, RootInitialClockErrorV1>>,
    final_clock: Option<Result<(), E>>,
    reentered: bool,
}

impl RootInitialOpenPostsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            history: None,
            authority_physical: RootPolicyNameObservationOriginalV1::new(),
            policy_physical: RootPolicyNameObservationOriginalV1::new(),
            authority_location: RootPolicyNameObservationOriginalV1::new(),
            policy_location: RootPolicyNameObservationOriginalV1::new(),
            authority_names: None,
            policy_names: None,
            authority_location_returned: None,
            policy_location_returned: None,
            names_binding: None,
            peer: None,
            clock_original: RetainedKernelPairedClockAttemptV1::default(),
            clock: None,
            final_clock: None,
            reentered: false,
        }
    }

    pub(super) fn arm_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.history.is_some() || self.peer.is_some() {
            self.reentered = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
            predecessor,
            startup,
            exclusion,
        ));
        self.history.as_ref().ok_or(RootObservationErrorV1::Service)?.require_armed_v1()
    }

    pub(super) fn borrow_for_preparation_v1<'cut, 'startup>(
        &'cut mut self,
        producer: &'cut crate::native::startup::RootStartupControllerPeerOriginalV1<'startup>,
        stream: &'cut RetainedUnixStream,
    ) -> Result<RootAcceptedHistoryBorrowerV1<'cut, 'startup>, RootObservationErrorV1> {
        self.history.as_mut().ok_or(RootObservationErrorV1::Service)?
            .borrow_accepted_v1(producer, stream)
    }

    pub(super) fn observe_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        prepared: &RootInitialOpenPreparedOriginalV1,
        producer: &crate::native::startup::RootStartupControllerPeerOriginalV1<'_>,
        stream: &RetainedUnixStream,
    ) {
        let returned_original = match &self.history {
            Some(history) => history.has_native_original_v1(),
            None => false,
        };
        if !returned_original || self.peer.is_some() {
            self.reentered = true;
            self.peer.get_or_insert(Err(RootObservationErrorV1::Service));
            return;
        }

        // Actual held writer observations stay owed after body/append refusal.
        // Only presence of those same opened owners is needed at this slot.
        let opened = match writers.opened_pair_v1() {
            Ok(pair) => pair.authority_and_policy_v1(),
            Err(error) => Err(error),
        };
        match opened {
            Ok((authority, policy)) => {
                self.authority_names = Some(observe_names_v1(
                    authority,
                    RootFixedNameRoleV1::Authority,
                    RootFixedNameRecipeV1::Physical,
                    &mut self.authority_physical,
                ));
                self.policy_names = Some(policy
                    .observe_held_physical_names_once_v1(&mut self.policy_physical)
                    .map_err(|()| E::Boundary));
                self.authority_location_returned = Some(self.authority_location
                    .observe_once(authority, RootFixedNameRoleV1::Authority, RootFixedNameRecipeV1::Location)
                    .map_err(|()| E::Boundary));
                self.policy_location_returned = Some(policy
                    .observe_fixed_location_once_v1(&mut self.policy_location)
                    .map_err(|()| E::Boundary));
            }
            Err(error) => {
                self.authority_location_returned = Some(Err(E::Root(error)));
                self.policy_location_returned = Some(Err(E::Boundary));
            }
        }
        self.names_binding = Some(self.require_names_binding_v1(prepared));

        // These independent owed observations run even if names or binding
        // failed. The original first-clock owner is compared only afterward.
        self.peer = Some(match self.history.as_mut() {
            Some(history) => match history.borrow_accepted_v1(producer, stream) {
                Ok(mut accepted) => accepted.observe_shared_once_v1(),
                Err(error) => Err(error),
            },
            None => Err(RootObservationErrorV1::Service),
        });
        self.clock = Some(self.clock_original.observe_once(None));
        self.final_clock = Some(self.require_final_clock_v1(prepared));
    }

    fn require_names_binding_v1(&self, prepared: &RootInitialOpenPreparedOriginalV1) -> Result<(), E> {
        let body = prepared.body_v1()?;
        if *positive(&self.authority_names)? != body.authority_names
            || *positive(&self.policy_names)? != body.policy_names
        {
            return Err(E::Boundary);
        }
        Ok(())
    }

    fn require_final_clock_v1(&self, prepared: &RootInitialOpenPreparedOriginalV1) -> Result<(), E> {
        prepared.clock_original_v1().initial_data_v1()?;
        let current = *positive(&self.clock)?;
        let body = prepared.body_v1()?;
        prepared.clock_original_v1().require_current_v1(current, body.cutoff)?;
        Ok(())
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if self.reentered {
            return Err(E::Boundary);
        }
        positive(&self.authority_names)?;
        positive(&self.policy_names)?;
        positive(&self.names_binding)?;
        positive(&self.authority_location_returned)?;
        positive(&self.policy_location_returned)?;
        positive(&self.peer)?;
        positive(&self.final_clock).map(|_| ())
    }

    pub(super) fn authority_names_v1(&self) -> Result<ProtectedJournalNamesV1, E> {
        self.require_complete_v1()?;
        positive(&self.authority_names).copied()
    }

    pub(super) fn sample_v1(&self) -> Result<aos_sandbox_model::RawPairedClockSample, E> {
        positive(&self.clock).copied()
    }

    pub(super) fn arm_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::arm_failure_v1)
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::arm_failure_v1)
            .or_else(|| self.authority_physical.failure())
            .or_else(|| cause(&self.authority_names))
            .or_else(|| self.policy_physical.failure())
            .or_else(|| cause(&self.policy_names))
            .or_else(|| self.authority_location.failure())
            .or_else(|| cause(&self.authority_location_returned))
            .or_else(|| self.policy_location.failure())
            .or_else(|| cause(&self.policy_location_returned))
            .or_else(|| cause(&self.names_binding))
            .or_else(|| self.history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::observation_failure_v1))
            .or_else(|| cause(&self.peer))
            .or_else(|| self.clock_original.failure())
            .or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.final_clock))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Boundary)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
