//! Retains Source's initial accept/adoption bookends before any request byte.

use super::super::currentness::SourceCurrentnessSampleV1;
use super::{SourceReceivingClosedV1, SourceServingOriginalLoanV1, CLOSED};
use aos_sandbox_broker::receiving::ComponentReceivingOperationLoanV1;

pub(super) struct SourceAcceptSampleV1 {
    consumption: Option<Result<(), SourceReceivingClosedV1>>,
    before: SourceCurrentnessSampleV1,
    before_result: Option<Result<(), SourceReceivingClosedV1>>,
    after: SourceCurrentnessSampleV1,
    after_result: Option<Result<(), SourceReceivingClosedV1>>,
}

impl SourceAcceptSampleV1 {
    pub(super) fn new() -> Self {
        Self {
            consumption: None,
            before: Default::default(),
            before_result: None,
            after: Default::default(),
            after_result: None,
        }
    }

    pub(super) fn begin_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut ComponentReceivingOperationLoanV1<'_>,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.consumption.is_some() { return Err(CLOSED); }
        self.consumption = Some(operation.consume_flight_once().map_err(|_| CLOSED));
        if !matches!(self.consumption, Some(Ok(()))) { return Err(CLOSED); }
        self.before_result = Some(original.observe_source_into(&mut self.before));
        if matches!(self.before_result, Some(Ok(()))) { Ok(()) } else { Err(CLOSED) }
    }

    pub(super) fn finish_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.after_result.is_some() || !matches!(self.consumption, Some(Ok(()))) {
            return Err(CLOSED);
        }
        self.after_result = Some(original.observe_source_into(&mut self.after));
        if self.positive() { Ok(()) } else { Err(CLOSED) }
    }

    pub(super) fn positive(&self) -> bool {
        matches!(self.consumption, Some(Ok(())))
            && matches!(self.before_result, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        super::failure(&self.consumption).or_else(|| self.before.failure())
            .or_else(|| super::failure(&self.before_result))
    }

    pub(super) fn after_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.after.failure().or_else(|| super::failure(&self.after_result))
    }
}
