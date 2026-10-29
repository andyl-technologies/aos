//! Pairs admitted verification boundaries while retaining pre-admission retries.

use std::cell::Cell;

use super::super::verification_capacity::object_observation;
use super::{self as observation};

/// Tracks whether a delivery entered the bounded verification operation.
pub(crate) struct QueueObservation {
    event: observation::Event,
    started: Cell<bool>,
}

impl QueueObservation {
    /// Creates an unstarted observation for one original delivery attempt.
    pub(crate) fn new(event: observation::Event) -> Self {
        Self {
            event,
            started: Cell::new(false),
        }
    }

    /// Emits the start only after actual object capacity has been acquired.
    pub(crate) fn start(&self) {
        let mut event = self.event.clone();
        let active = object_observation();
        event.aggregate_active = active.aggregate_active;
        event.bulk_active = active.bulk_active;
        event.metadata_active = active.metadata_active;
        observation::emit(&event);
        self.started.set(true);
    }

    /// Finishes admitted work and returns the event for the actual ack or retry.
    pub(crate) fn finish(self, succeeded: bool, replayed: Option<bool>) -> observation::Event {
        let mut event = self.event;
        let active = object_observation();
        event.aggregate_active = active.aggregate_active;
        event.bulk_active = active.bulk_active;
        event.metadata_active = active.metadata_active;
        event.outcome = if succeeded {
            observation::Outcome::Positive
        } else {
            observation::Outcome::Refused
        };
        event.replayed = replayed;

        // Capacity and protection can refuse a delivery before verification
        // starts. Retain its retry without inventing an unmatched finish.
        if self.started.get() {
            event.kind = observation::Kind::QueueFinish;
            observation::emit(&event);
        }
        event.kind = if succeeded {
            observation::Kind::QueueAck
        } else {
            observation::Kind::QueueRetry
        };
        event
    }
}

#[cfg(test)]
mod tests;
