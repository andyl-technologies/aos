//! Live control-plane event-log streaming API.
//!
//! The API surface is a thin in-process facade over the session actor's single
//! event-log hub. It exposes cursor-backed subscription without introducing a
//! second log, a command mailbox round trip, or a scheduler-visible mutation.

pub use crucible_session::{
    EventLogCursor, SESSION_EVENT_LOG_BROADCAST_CAPACITY, SESSION_EVENT_LOG_REPLAY_BATCH_SIZE,
    SessionEventLog as SessionEventLogHub, SessionEventLogFrame, SessionEventLogStream,
    SessionEventLogStreamError,
};

/// Control-plane facade for cursor-backed event-log subscriptions.
#[derive(Clone, Debug)]
pub struct ControlPlaneEventLog {
    hub: SessionEventLogHub,
}

impl ControlPlaneEventLog {
    /// Builds an API facade over a session-owned event-log hub.
    #[must_use]
    pub fn new(hub: SessionEventLogHub) -> Self {
        Self { hub }
    }

    /// Returns a cursor positioned after the currently retained entries.
    #[must_use]
    pub fn current_cursor(&self) -> EventLogCursor {
        self.hub.current_cursor()
    }

    /// Subscribes to event-log entries from `cursor` onward.
    ///
    /// The subscription is observation-only: it does not enqueue a session
    /// command, advance the scheduler, or alter the deterministic live
    /// snapshot.
    #[must_use]
    pub fn subscribe(&self, cursor: EventLogCursor) -> SessionEventLogStream {
        self.hub.subscribe(cursor)
    }

    /// Returns the wrapped session event-log hub.
    #[must_use]
    pub fn into_inner(self) -> SessionEventLogHub {
        self.hub
    }
}

impl From<SessionEventLogHub> for ControlPlaneEventLog {
    fn from(value: SessionEventLogHub) -> Self {
        Self::new(value)
    }
}
