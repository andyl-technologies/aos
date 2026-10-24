//! Keeps Source's two permanently paid exclusive full-vector operation lanes.
//!
//! These slots own arithmetic only. The connected Source owner disposes its
//! actual positive root-stage or chunk sample before opening a later flight;
//! a failed loan cannot be replaced, refunded or converted into a fresh F.

use aos_sandbox_model::ResourceVector;

use aos_sandbox_broker::receiving::ComponentReceivingOperationV1;
use super::super::{SourceReceivingClosedV1, CLOSED};

pub(super) struct SourceOperationV1 {
    capacity: ResourceVector,
    flight: Option<ComponentReceivingOperationV1>,
    closed: bool,
}

impl SourceOperationV1 {
    pub(super) fn new(capacity: ResourceVector) -> Self {
        Self { capacity, flight: None, closed: false }
    }

    // The private connected owner already disposed the positive sample. This
    // checks the actual old flight, never a caller Boolean or decoded witness.
    pub(super) fn begin_after_positive_disposal(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.closed || self.flight.as_ref().is_some_and(|flight| !flight.is_positive() || flight.is_closed()) {
            self.closed = true;
            return Err(CLOSED);
        }
        drop(self.flight.take());
        self.flight = Some(ComponentReceivingOperationV1::preflight(self.capacity, self.capacity));
        Ok(())
    }

    pub(super) fn flight_mut(&mut self) -> Result<&mut ComponentReceivingOperationV1, SourceReceivingClosedV1> {
        self.flight.as_mut().ok_or(CLOSED)
    }

    pub(super) fn positive(&self) -> bool {
        !self.closed && self.flight.as_ref().is_some_and(|flight| flight.is_positive() && !flight.is_closed())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.flight.as_ref().and_then(|flight| flight.failure()).map(|error| error as _)
            .or_else(|| self.closed.then_some(&CLOSED as &dyn std::error::Error))
    }
}
