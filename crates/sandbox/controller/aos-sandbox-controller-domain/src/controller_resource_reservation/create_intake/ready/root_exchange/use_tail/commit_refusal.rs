//! Retains the independently owed Root post for an actual refused U commit.
//!
//! This destination consumes only the previous Root5 turn's prepaid refusal
//! slot. A missing committed position remains a failed comparison throughout
//! the existing native Root observation and both control bookends.

use super::*;
use crate::controller_resource_reservation::create_intake::ready::root_exchange::{
    CreateStorageRootExchangeClosedV1 as Closed, OriginalCreateStorageRootExchangeV1,
    RootExchangeOriginalsV1, RootPostFrontierV1,
};
use crate::controller_resource_reservation::create_intake::ready::use_reserved::{
    commit::UseCommitOriginalsV1, UseReceivingOriginalsV1,
};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
struct RootUseCommitRefusalOriginalsV1 {
    entered: bool,
    position: Option<Result<super::super::CreateStorageWriterPositionV1, ResourceReservationErrorV1>>,
    post: Option<Result<(), Closed>>,
}

impl RootUseCommitRefusalOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn post_is_owed_v1(&self) -> bool { self.entered && self.post.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failed_position_post_is_active_v1(&self) -> bool {
        self.post_is_owed_v1() && matches!(self.position, Some(Err(_)))
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failure<'cause>(&'cause self, peer: &'cause CreateStorageRootPeerReceivingOriginalsV1)
        -> Option<&'cause (dyn Error + 'static)> {
        peer.failure().or_else(|| cause(&self.post))
    }
}

impl RootExchangeOriginalsV1 {
    // The actual U owner keeps its earlier admission/append error. This method
    // owns only the separately owed Root post and cannot issue completion.
    pub(in crate::controller_resource_reservation::create_intake)
    fn observe_use_commit_entry_refusal_once(&mut self,
        parent: &super::super::ProjectPreparationReservationAttemptV1,
        intake: &mut super::super::Q04OriginalIntakeAttemptV1,
        controller: &mut super::super::Journal,
        source: &mut super::super::ProtectedSourceDomainJournalOwnerV1,
        profile: &super::super::ProductionControllerNormalRootProfileV1,
        cache: &mut super::super::OriginalCreateStorageCacheLoanV1<'_>,
        attempt: &UseCommitOriginalsV1,
        receiving: &mut UseReceivingOriginalsV1,
    ) -> Result<(), Closed> {
        if !attempt.started() || self.turn.use_tail.commit_refusal.entered {
            return Err(Closed);
        }
        self.turn.use_tail.commit_refusal.entered = true;
        self.turn.use_tail.commit_refusal.position = Some(attempt.position());
        self.turn.expected_controller = self.turn.use_tail.commit_refusal.position.as_ref()
            .and_then(|position| position.as_ref().ok()).copied();
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent, intake, controller, source, profile, cache,
            state: &mut self.turn, use_receiving: Some(receiving),
        };
        loan.state.owed_post = Some(RootPostFrontierV1::UseCommitRefusal);
        let post = self.peer.recheck_once(&mut loan);
        loan.state.use_tail.commit_refusal.post = Some(post);
        Err(Closed)
    }
}
