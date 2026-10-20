//! Keeps Source and Root bookends resident for one actual serving stage.
//!
//! The same genuine F operation consumes its full shape before any native
//! sample or PID1 work. Its private caller alone observes actual IO and may
//! finish that loan after every positive bookend and Joined/Ended outcome.

use std::error::Error;

use aos_sandbox_broker::receiving::ComponentReceivingOperationLoanV1;
use crate::signer::root_observation::{SourceRootPeerConnectionV1, SourceRootPeerStageV1};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;

use super::{SourceServingOriginalLoanV1, SourceReceivingClosedV1, CLOSED};
use super::super::currentness::SourceCurrentnessSampleV1;

#[derive(Clone, Copy)]
enum Failure { Consumption, SourceBefore, RootBefore, RootAfter, SourceAfter, Closed }

pub(super) struct SourceStageSampleV1 {
    consumption: Option<Result<(), SourceReceivingClosedV1>>,
    before: SourceCurrentnessSampleV1,
    before_result: Option<Result<(), SourceReceivingClosedV1>>,
    peer: SourceRootPeerStageV1,
    peer_before: Option<Result<(), aos_sandbox_broker::receiving::RootObservationErrorV1>>,
    peer_after: Option<Result<(), aos_sandbox_broker::receiving::RootObservationErrorV1>>,
    after: SourceCurrentnessSampleV1,
    after_result: Option<Result<(), SourceReceivingClosedV1>>,
    first: Option<Failure>,
}

impl SourceStageSampleV1 {
    pub(super) fn new(lifetime: aos_sandbox_broker::receiving::ObservationLifetimeV1) -> Self {
        Self {
            consumption: None, before: Default::default(), before_result: None,
            // This stage is entered only by the genuine selected Source F
            // serving loan; its actual Root producer has four fixed roles.
            peer: SourceRootPeerStageV1::selected(lifetime), peer_before: None, peer_after: None,
            after: Default::default(), after_result: None, first: None,
        }
    }

    pub(super) fn begin_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        peer: &mut SourceRootPeerConnectionV1,
        stream: &RetainedUnixStream,
        operation: &mut ComponentReceivingOperationLoanV1<'_>,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.consumption.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(CLOSED);
        }
        self.consumption = Some(operation.consume_flight_once().map_err(|_| CLOSED));
        if !matches!(self.consumption, Some(Ok(()))) {
            self.first = Some(Failure::Consumption);
            return Err(CLOSED);
        }
        self.before_result = Some(original.observe_source_into(&mut self.before));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first = Some(Failure::SourceBefore);
            return Err(CLOSED);
        }
        self.peer_before = Some(self.peer.begin_once(original.inputs, peer, stream));
        if !matches!(self.peer_before, Some(Ok(()))) {
            self.first = Some(Failure::RootBefore);
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(super) fn finish_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        peer: &mut SourceRootPeerConnectionV1,
        stream: &RetainedUnixStream,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.after_result.is_some() || !matches!(self.consumption, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Closed);
            return Err(CLOSED);
        }
        if self.peer_before.is_some() {
            self.peer_after = Some(self.peer.finish_once(original.inputs, peer, stream));
            if !matches!(self.peer_after, Some(Ok(()))) {
                self.first.get_or_insert(Failure::RootAfter);
            }
        }
        self.after_result = Some(original.observe_source_into(&mut self.after));
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(Failure::SourceAfter);
        }
        if self.can_dispose() { Ok(()) } else { Err(CLOSED) }
    }

    pub(super) fn can_dispose(&self) -> bool {
        self.first.is_none() && self.peer.can_dispose()
            && matches!(self.consumption, Some(Ok(())))
            && matches!(self.before_result, Some(Ok(()))) && matches!(self.after_result, Some(Ok(())))
    }

    pub(super) fn failure<'a>(
        &'a self,
        inputs: &'a crate::signer::root_observation::SourceRootPeerInputsV1,
        peer: &'a SourceRootPeerConnectionV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            Failure::Consumption => super::failure(&self.consumption),
            Failure::SourceBefore => self.before.failure().or_else(|| super::failure(&self.before_result)),
            Failure::RootBefore | Failure::RootAfter => self.peer.failure(inputs, peer),
            Failure::SourceAfter => self.after.failure().or_else(|| super::failure(&self.after_result)),
            Failure::Closed => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED as &(dyn Error + 'static)))
    }
}
