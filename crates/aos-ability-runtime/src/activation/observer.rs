//! Optional instrumentation at native activation durability boundaries.
//!
//! Observers receive identities and phase names only. Their acknowledgements
//! cannot supply handler results or change desired configuration. An observer
//! error stops execution with the durable activation journal intact.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::Action;
use crate::adapter::CancellationToken;

/// Names a boundary around a journaled invocation or recovery observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Boundary {
    /// The exact invocation has been durably recorded before dispatch.
    IntentDurable,
    /// Dispatch is about to be attempted for the exact durable intent.
    ///
    /// Acknowledgement precedes the call and does not prove that the handler
    /// ran: interruption can occur between this boundary and dispatch.
    DispatchStarted,
    /// A handler returned, but its outcome has not been recorded.
    DispatchReturned,
    /// The checked outcome has been durably recorded.
    OutcomeDurable,
    /// Recovery or reuse is about to observe the exact retained invocation.
    ObservationStarted,
    /// Observation returned, before any resulting mutation or outcome record.
    ObservationReturned,
}

/// Describes one boundary without exposing arguments, credentials, or results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryEvent {
    /// Names the native boundary event schema.
    pub schema: String,
    /// Identifies the owning journal transaction.
    pub transaction: String,
    /// Identifies the logical effect.
    pub effect: String,
    /// Identifies the exact resolved invocation.
    pub revision: String,
    /// Distinguishes application and removal of the resource.
    pub action: Action,
    /// Identifies the durable intent frame, unchanged across recovery attempts.
    pub journal_sequence: u64,
    /// Names the execution phase being observed.
    pub boundary: Boundary,
}

/// Acknowledges or stops explicitly instrumented activation execution.
pub trait BoundaryObserver {
    /// Observes a bounded event without changing the operation's outcome.
    ///
    /// Implementations must bound transport time and honor cancellation.
    /// Repeated events for the same durable intent must be handled idempotently.
    ///
    /// # Errors
    /// Returns an error when observation cannot be acknowledged or execution
    /// must stop. A pending invocation will be observed on the next recovery.
    fn boundary(&mut self, event: &BoundaryEvent, cancellation: &CancellationToken) -> Result<()>;
}
