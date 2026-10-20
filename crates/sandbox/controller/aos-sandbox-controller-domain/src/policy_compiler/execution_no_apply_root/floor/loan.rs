//! Lends only the actual paid Execution Root floor producer to native append.
//!
//! The loan borrows the real accepted flight, endpoint, same two writers,
//! independent Controller readers and signed43 original. Neither canonical
//! floor DATA nor another Root purpose can construct this private crossing.

use std::error::Error;

use aos_sandbox_broker::receiving::RootWriterPostOriginalV1;
use aos_sandbox_linux::unix_stream::RetainedUnixStream;

use crate::controller_resource_reservation::service_interval::ObserverLifetime;
use crate::journal::{
    Journal, JournalError, JournalTransaction, root_construction::RootJournalServingIdentityV1,
};
use crate::normal_root::{
    NormalRootStartupErrorV1, RootControllerPeerCurrentSampleV1, RootPolicyAcceptedFlightV1,
};
use crate::policy_compiler::{
    continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
    create_storage_current::pins::RootCurrentPinsStateV1,
    provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1,
    root_current_writers::{RootCreateStorageCurrentWritersV1, RootCurrentWriterRoleV1},
};

use super::{
    Floor, RootExecutionNoApplyHostLeaseOriginalV2, RootExecutionNoApplyHostTrustOriginalV2,
};

mod readonly;

pub(in crate::policy_compiler::execution_no_apply_root) struct Crossing {
    posts: [Option<Result<RootWriterPostOriginalV1, JournalError>>; 4],
    before: [Option<Result<(), JournalError>>; 2],
    after: [Option<Result<(), JournalError>>; 2],
    transition: Option<Result<(), JournalError>>,
    binding: Option<Result<(), JournalError>>,
    peer: RootControllerPeerCurrentSampleV1,
    peer_result: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    clock: Option<Result<(), JournalError>>,
    completion: Option<Result<(), JournalError>>,
    external_trust: bool,
    reentry: Option<JournalError>,
}

impl Crossing {
    pub(in crate::policy_compiler::execution_no_apply_root) fn new() -> Self {
        Self {
            posts: std::array::from_fn(|_| None),
            before: std::array::from_fn(|_| None),
            after: std::array::from_fn(|_| None),
            transition: None,
            binding: None,
            peer: RootControllerPeerCurrentSampleV1::new(ObserverLifetime::begin()),
            peer_result: None,
            peer_settlement: None,
            clock: None,
            completion: None,
            external_trust: false,
            reentry: None,
        }
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn arm_once(
        &mut self,
        authority: &Journal,
        policy: &Journal,
    ) -> Result<(), JournalError> {
        if self.posts.iter().any(Option::is_some) {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        // Arm both independently owed after posts before the first slow read.
        for index in 0..4 {
            self.posts[index] =
                Some(if index % 2 == 0 { authority } else { policy }.arm_root_names_post_once_v1());
        }
        for post in &self.posts {
            positive(post)?;
        }
        Ok(())
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn finish_after_once(&mut self, writers: &RootCreateStorageCurrentWritersV1) {
        for index in 0..4 {
            let result = if index < 2 {
                &mut self.before[index]
            } else {
                &mut self.after[index - 2]
            };
            if result.is_some() {
                continue;
            }
            if let Some(Ok(post)) = &mut self.posts[index] {
                *result = Some(
                    writers
                        .owed_policy_interval_journal_v1(RootCurrentWriterRoleV1::ALL[index % 2])
                        .and_then(|journal| journal.finish_root_names_post_once_v1(post)),
                );
            }
        }
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn require_complete(&self) -> Result<(), JournalError> {
        if self.reentry.is_some() || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        positive(&self.completion)?;
        for post in &self.after {
            positive(post)?;
        }
        Ok(())
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn external_trust_failed(&self) -> bool {
        self.external_trust
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        for post in &self.posts[..2] {
            match post {
                Some(Err(cause)) => return Some(cause),
                Some(Ok(post)) => {
                    if let Some(cause) = post.failure() {
                        return Some(cause);
                    }
                }
                None => {}
            }
        }
        self.transition
            .as_ref()
            .and_then(|v| v.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.before
                    .iter()
                    .find_map(|v| v.as_ref()?.as_ref().err().map(|cause| cause as _))
            })
            .or_else(|| {
                self.binding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.peer.failure())
            .or_else(|| {
                self.peer_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.peer_settlement
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                (!self.external_trust)
                    .then_some(())
                    .and_then(|()| self.clock.as_ref()?.as_ref().err().map(|cause| cause as _))
            })
            .or_else(|| {
                (!self.external_trust).then_some(()).and_then(|()| {
                    self.completion
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
            })
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
    pub(super) fn after_failure(&self) -> Option<&(dyn Error + 'static)> {
        for post in &self.posts[2..] {
            match post {
                Some(Err(cause)) => return Some(cause),
                Some(Ok(post)) => {
                    if let Some(cause) = post.failure() {
                        return Some(cause);
                    }
                }
                None => {}
            }
        }
        self.after
            .iter()
            .find_map(|v| v.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
    pub(in crate::policy_compiler::execution_no_apply_root) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_failure().or_else(|| self.after_failure())
    }
}

/// Borrows one exact genuine Root producer; only its enclosing owner constructs it.
pub(crate) struct RootExecutionNoApplyFloorAppendLoanV2<'cut, 'listener, 'startup> {
    flight: &'cut mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
    original: &'cut RetainedUnixStream,
    policy: &'cut Journal,
    pins: &'cut RootCurrentPinsStateV1,
    interval: &'cut RootExecutionNoApplyPolicyOriginalV2,
    readonly: &'cut RootCreateFinalityReadonlyOriginalV1,
    host: &'cut RootExecutionNoApplyHostLeaseOriginalV2,
    trust: &'cut mut RootExecutionNoApplyHostTrustOriginalV2,
    before: &'cut [RootJournalServingIdentityV1; 2],
    floor: Floor,
    transaction: &'cut JournalTransaction,
    crossing: &'cut mut Crossing,
}

impl<'cut, 'listener, 'startup> RootExecutionNoApplyFloorAppendLoanV2<'cut, 'listener, 'startup> {
    pub(super) fn new(
        flight: &'cut mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
        original: &'cut RetainedUnixStream,
        policy: &'cut Journal,
        pins: &'cut RootCurrentPinsStateV1,
        interval: &'cut RootExecutionNoApplyPolicyOriginalV2,
        readonly: &'cut RootCreateFinalityReadonlyOriginalV1,
        host: &'cut RootExecutionNoApplyHostLeaseOriginalV2,
        trust: &'cut mut RootExecutionNoApplyHostTrustOriginalV2,
        before: &'cut [RootJournalServingIdentityV1; 2],
        floor: Floor,
        transaction: &'cut JournalTransaction,
        crossing: &'cut mut Crossing,
    ) -> Self {
        Self {
            flight,
            original,
            policy,
            pins,
            interval,
            readonly,
            host,
            trust,
            before,
            floor,
            transaction,
            crossing,
        }
    }
}

impl RootExecutionNoApplyFloorAppendLoanV2<'_, '_, '_> {
    pub(crate) fn require_transition(
        &mut self,
        journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if self.crossing.transition.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.crossing.transition = Some((|| {
            if transaction != self.transaction
                || journal.snapshot_sequence() != self.floor.fields().authority_next
            {
                return Err(JournalError::ProtectedBoundary);
            }
            self.require_held_inputs(journal)?;
            super::history::inspect_history_data_v2(journal, self.floor.fields().operation)?;
            // The exact prepared transaction was built by this private owner;
            // no omitted or additional namespace is accepted by this boundary.
            if transaction.records().iter().any(|row| {
                row.namespace() != crate::journal::RecordNamespace::RootExecutionNoApplyFloorV2
            }) || !matches!(transaction.records().len(), 2 | 3)
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        positive(&self.crossing.transition).map(|_| ())
    }

    pub(crate) fn require_prechecked_floor_successor_v2(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        positive(&self.crossing.transition)?;
        if transaction != self.transaction {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn require_held_inputs(&self, journal: &Journal) -> Result<(), JournalError> {
        journal.require_root_serving_identity_v1(&self.before[0])?;
        self.policy
            .require_root_serving_identity_v1(&self.before[1])?;
        self.interval
            .require_prepared_floor_pair_v2(journal, self.policy, self.pins)?;
        self.readonly.require_complete_v1()?;
        if self
            .readonly
            .execution_no_apply_current_data_v2()?
            .global_controller_cut_data_v2()?
            != self.floor.fields().controller_cut
            || self.host.lease_data_v2()? != self.floor.fields().host_lease
            || self.host.signed_outcome_data_v2()? != self.floor.fields().signed_current_outcome
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn final_crossing(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if self.crossing.completion.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        // These independent before destinations coexist with both owed posts.
        for index in 0..2 {
            if let Some(Ok(post)) = &mut self.crossing.posts[index] {
                self.crossing.before[index] = Some(
                    if index == 0 { journal } else { self.policy }
                        .finish_root_names_post_once_v1(post),
                );
            }
        }
        self.crossing.binding = Some(self.require_held_inputs(journal));
        self.crossing.peer_result =
            Some(self.flight.observe_execution_no_apply_floor_peer_once_v2(
                self.original,
                &mut self.crossing.peer,
            ));
        self.crossing.peer_settlement = Some(self.crossing.peer.settle_after_root_post_once_v1());
        self.crossing.clock = Some(self.trust.next_sample_v2().and_then(|sample| {
            let sources = self
                .interval
                .verified_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            if sample.wall_seconds() >= sources.0.head().expires_at().min(sources.1.expires_at()) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        }));
        self.crossing.external_trust = self.trust.failure().is_some();
        self.crossing.completion = Some((|| {
            positive(&self.crossing.transition)?;
            for before in &self.crossing.before {
                positive(before)?;
            }
            positive(&self.crossing.binding)?;
            positive(&self.crossing.peer_result)?;
            positive(&self.crossing.peer_settlement)?;
            positive(&self.crossing.clock)?;
            Ok(())
        })());
        positive(&self.crossing.completion).map(|_| ())
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
