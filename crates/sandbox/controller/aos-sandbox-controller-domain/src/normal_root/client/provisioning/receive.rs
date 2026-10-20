//! Adapts genuine C23 Apply to the sole fixed Root resource stream loops.

use super::*;
use super::super::resource_stream::{self, RootClientLoanV1, RootClientFundingV1,
    RootReplyPurposeV1, RootReplyReceiveV1, RootSubjectDataV1, RootStreamStageV1};

impl RootStorageApplyClientOriginalV1 {
    pub(super) fn send_subject(&mut self, _loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        _controller: &Journal, ready: &[u8], outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), First> {
        let state = &mut *self.state;
        let subject = StorageApplySubjectDataV1 {ready,
            prepare_request: outcome.request().canonical_packet(),
            prepare_outcome: outcome.canonical_packet(), root_closed: &state.root_closed,
            controller_account: &state.controller_head};
        resource_stream::send_subject_v1(RootSubjectDataV1::Apply(subject),
            &mut state.connection, &mut state.sender, &mut state.sent,
            &mut state.send_scratch, &mut state.data_failure, self.cutoff).map_err(stream_stage)
    }

    pub(super) fn receive_reply(&mut self, loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<(), First> {
        let mut funding = RootClientFundingV1 {complete: self.complete,
            observations: &mut self.observations, wire: &mut self.wire, output: &mut self.output,
            received_bound: &mut self.received_bound, admission: &mut self.admission,
            funding_original: &mut self.funding_original};
        let state = &mut *self.state;
        let mut receive = RootReplyReceiveV1 {connection: &mut state.connection,
            received: &mut state.received, preparation: &mut state.preparation,
            extension: &mut state.extension, chunk: &mut state.chunk,
            data_failure: &mut state.data_failure,
            peer_before: state.peer_before.as_deref().ok_or(First::Receive)?,
            profile: self.profile.as_ref(), cutoff: self.cutoff};
        receive.receive_reply(RootReplyPurposeV1::Apply, &mut RootClientLoanV1::Apply(loan),
            controller, &mut funding).map_err(stream_stage)
    }
}

fn stream_stage(stage: RootStreamStageV1) -> First {
    match stage {
        RootStreamStageV1::Query => First::Query,
        RootStreamStageV1::Send => First::Send,
        RootStreamStageV1::Admission => First::Admission,
        RootStreamStageV1::Receive => First::Receive,
        RootStreamStageV1::Reply => First::Reply,
    }
}
