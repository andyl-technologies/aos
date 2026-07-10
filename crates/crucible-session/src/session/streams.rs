//! Session event-log and state-transition broadcast streams.

use super::*;

/// Cursor into a session event-log stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventLogCursor {
    /// Next dense event-log sequence number to deliver.
    pub next_sequence: u64,
}

impl EventLogCursor {
    /// Builds a cursor at `next_sequence`.
    #[must_use]
    pub const fn new(next_sequence: u64) -> Self {
        Self { next_sequence }
    }
}

/// One event-log entry delivered to a control-plane subscriber.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEventLogFrame {
    /// Event-log stream generation that produced this frame.
    pub generation: u64,
    /// Cursor position of this entry.
    pub cursor: EventLogCursor,
    /// Cursor position immediately after this entry.
    pub next_cursor: EventLogCursor,
    /// Full causal or observational event-log entry.
    pub entry: SchedulerEventLogEntry,
}

impl SessionEventLogFrame {
    pub(super) fn new(entry: SchedulerEventLogEntry, generation: u64) -> Self {
        let sequence = entry.sequence();
        Self {
            generation,
            cursor: EventLogCursor::new(sequence),
            next_cursor: EventLogCursor::new(sequence.saturating_add(1)),
            entry,
        }
    }
}

/// Log-derived summary captured at stream attach time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEventLogSnapshot {
    /// Cursor through which the snapshot was folded.
    pub through: EventLogCursor,
    /// Number of event-log entries folded into the snapshot.
    pub event_count: u64,
    /// Number of causal entries folded into the snapshot.
    pub causal_count: u64,
    /// Number of observational entries folded into the snapshot.
    pub observational_count: u64,
    /// Last sequence folded into the snapshot, when any entry was present.
    pub last_sequence: Option<u64>,
}

/// Error returned while reading a live event-log stream.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SessionEventLogStreamError {
    /// The subscriber lagged behind the bounded live tail.
    #[error("session event-log stream skipped {skipped} frames")]
    Lagged {
        /// Number of skipped broadcast frames reported by the live tail.
        skipped: u64,
    },
}

/// Session-owned event-log hub used by the control plane.
#[derive(Clone, Debug)]
pub struct SessionEventLog {
    inner: Arc<SessionEventLogInner>,
}

#[derive(Debug)]
pub(super) struct SessionEventLogInner {
    entries: Mutex<Vec<SchedulerEventLogEntry>>,
    generation: AtomicU64,
    generation_start: AtomicU64,
    tail: broadcast::Sender<SessionEventLogFrame>,
}

impl SessionEventLog {
    /// Builds an empty event-log hub.
    #[must_use]
    pub fn new() -> Self {
        let (tail, _) = broadcast::channel(SESSION_EVENT_LOG_BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(SessionEventLogInner {
                entries: Mutex::new(Vec::new()),
                generation: AtomicU64::new(0),
                generation_start: AtomicU64::new(0),
                tail,
            }),
        }
    }

    /// Returns the number of retained event-log entries.
    #[must_use]
    pub fn len(&self) -> u64 {
        usize_to_u64(self.lock_entries().len())
    }

    /// Returns whether no event-log entries are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock_entries().is_empty()
    }

    /// Returns a cursor positioned at the retained log tail.
    #[must_use]
    pub fn current_cursor(&self) -> EventLogCursor {
        let entries = self.lock_entries();
        Self::current_cursor_for(&entries)
    }

    /// Subscribes to entries from `cursor` onward.
    ///
    /// The returned stream first drains a cursor snapshot from the retained log,
    /// then continues with the live broadcast tail. Subscribing does not enqueue
    /// a session command and does not await the scheduler.
    #[must_use]
    pub fn subscribe(&self, cursor: EventLogCursor) -> SessionEventLogStream {
        let (_current_tail, stream) = self.subscribe_with_replay_tail(cursor);
        stream
    }

    /// Subscribes and returns the replay tail captured for the attach response.
    ///
    /// The returned cursor is the retained log tail observed by the attach path;
    /// the stream starts with replay from `cursor` up to that tail and then
    /// continues with the live broadcast tail.
    #[must_use]
    pub fn subscribe_with_replay_tail(
        &self,
        cursor: EventLogCursor,
    ) -> (EventLogCursor, SessionEventLogStream) {
        let receiver = self.inner.tail.subscribe();
        let current_tail = self.current_cursor();
        let next_cursor = EventLogCursor::new(cursor.next_sequence.min(current_tail.next_sequence));
        (
            current_tail,
            SessionEventLogStream {
                hub: self.clone(),
                generation: self.generation(),
                next_cursor,
                replay_tail: current_tail,
                replay_exhausted: false,
                backlog: VecDeque::new(),
                receiver,
            },
        )
    }

    /// Returns a log-derived snapshot summary through `cursor`.
    #[must_use]
    pub fn snapshot_through(&self, cursor: EventLogCursor) -> SessionEventLogSnapshot {
        let entries = self.lock_entries();
        let mut event_count = 0_u64;
        let mut causal_count = 0_u64;
        let mut observational_count = 0_u64;
        let mut last_sequence = None;
        for entry in entries
            .iter()
            .take_while(|entry| entry.sequence() < cursor.next_sequence)
        {
            event_count = event_count.saturating_add(1);
            match entry.class() {
                SchedulerEventLogClass::Causal => causal_count = causal_count.saturating_add(1),
                SchedulerEventLogClass::Observational => {
                    observational_count = observational_count.saturating_add(1);
                }
            }
            last_sequence = Some(entry.sequence());
        }
        SessionEventLogSnapshot {
            through: cursor,
            event_count,
            causal_count,
            observational_count,
            last_sequence,
        }
    }

    pub(super) fn append_entries(&self, entries: &[SchedulerEventLogEntry]) {
        if entries.is_empty() {
            return;
        }

        let generation = self.generation();
        let frames = entries
            .iter()
            .cloned()
            .map(|entry| SessionEventLogFrame::new(entry, generation))
            .collect::<Vec<_>>();
        self.lock_entries().extend(entries.iter().cloned());
        for frame in frames {
            let _ = self.inner.tail.send(frame);
        }
    }

    pub(super) fn truncate_to_len(&self, len: usize) {
        let mut entries = self.lock_entries();
        if entries.len() > len {
            entries.truncate(len);
            self.inner
                .generation_start
                .store(usize_to_u64(len), Ordering::Release);
            self.inner.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    fn generation_start_cursor(&self) -> EventLogCursor {
        EventLogCursor::new(self.inner.generation_start.load(Ordering::Acquire))
    }

    pub(super) fn lock_entries(&self) -> std::sync::MutexGuard<'_, Vec<SchedulerEventLogEntry>> {
        match self.inner.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn current_cursor_for(entries: &[SchedulerEventLogEntry]) -> EventLogCursor {
        entries
            .last()
            .map(|entry| EventLogCursor::new(entry.sequence().saturating_add(1)))
            .unwrap_or_default()
    }

    fn replay_batch_from(
        &self,
        cursor: EventLogCursor,
        replay_tail: EventLogCursor,
        generation: u64,
    ) -> VecDeque<SessionEventLogFrame> {
        let entries = self.lock_entries();
        let start = entries.partition_point(|entry| entry.sequence() < cursor.next_sequence);
        entries
            .iter()
            .skip(start)
            .take_while(|entry| entry.sequence() < replay_tail.next_sequence)
            .take(SESSION_EVENT_LOG_REPLAY_BATCH_SIZE)
            .cloned()
            .map(|entry| SessionEventLogFrame::new(entry, generation))
            .collect()
    }
}

impl Default for SessionEventLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable snapshot of the deterministic command stream recorded for replay.
#[derive(Clone, Debug)]
pub struct SessionReproductionLog {
    inner: Arc<Mutex<Vec<SessionControlLogEntry>>>,
}

impl SessionReproductionLog {
    /// Builds an empty reproduction-log snapshot handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a point-in-time copy of the recorded command stream.
    #[must_use]
    pub fn snapshot(&self) -> Vec<SessionControlLogEntry> {
        self.lock_entries().clone()
    }

    /// Returns the number of recorded boundary controls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_entries().len()
    }

    /// Returns whether no boundary controls have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock_entries().is_empty()
    }

    pub(super) fn sync_from_boundary_log(&self, entries: &[SessionControlLogEntry]) {
        let mut current = self.lock_entries();
        if current.as_slice() == entries {
            return;
        }
        current.clear();
        current.extend_from_slice(entries);
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, Vec<SessionControlLogEntry>> {
        match self.inner.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Default for SessionReproductionLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(debug_assertions, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    //! Test-support helpers for integration tests.

    use crucible::SchedulerEventLogEntry;

    use crate::SessionEventLog;

    /// Appends event-log entries to a session event-log hub for integration tests.
    pub fn append_event_log_entries_for_test(
        hub: &SessionEventLog,
        entries: &[SchedulerEventLogEntry],
    ) {
        hub.append_entries(entries);
    }

    /// Truncates a session event-log hub to `len` entries for integration tests.
    pub fn truncate_event_log_for_test(hub: &SessionEventLog, len: usize) {
        hub.truncate_to_len(len);
    }
}

/// Cursor-backed event-log stream for one subscriber.
#[derive(Debug)]
pub struct SessionEventLogStream {
    hub: SessionEventLog,
    generation: u64,
    next_cursor: EventLogCursor,
    replay_tail: EventLogCursor,
    replay_exhausted: bool,
    backlog: VecDeque<SessionEventLogFrame>,
    receiver: broadcast::Receiver<SessionEventLogFrame>,
}

impl SessionEventLogStream {
    /// Returns the next cursor position expected by this stream.
    #[must_use]
    pub const fn cursor(&self) -> EventLogCursor {
        self.next_cursor
    }

    /// Receives the next event-log frame.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEventLogStreamError::Lagged`] when this subscriber falls
    /// behind the bounded live broadcast tail.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<SessionEventLogFrame>, SessionEventLogStreamError> {
        loop {
            if let Some(frame) = self.take_ready_backlog_frame() {
                return Ok(Some(frame));
            }
            match self.receiver.recv().await {
                Ok(frame) => {
                    if let Some(frame) = self.deliver_frame(frame) {
                        return Ok(Some(frame));
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(None),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    return Err(SessionEventLogStreamError::Lagged { skipped });
                }
            }
        }
    }

    /// Polls for the next frame without awaiting, returning `Ok(None)` when no
    /// frame is immediately available.
    ///
    /// This is a deterministic, wall-clock-free probe: it drains any replay
    /// backlog and reads at most one already-buffered broadcast frame, never
    /// parking the task on a timer.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEventLogStreamError::Lagged`] when this subscriber has
    /// fallen behind the bounded live broadcast tail.
    pub fn try_recv(&mut self) -> Result<Option<SessionEventLogFrame>, SessionEventLogStreamError> {
        loop {
            if let Some(frame) = self.take_ready_backlog_frame() {
                return Ok(Some(frame));
            }
            match self.receiver.try_recv() {
                Ok(frame) => {
                    if let Some(frame) = self.deliver_frame(frame) {
                        return Ok(Some(frame));
                    }
                }
                Err(broadcast::error::TryRecvError::Empty)
                | Err(broadcast::error::TryRecvError::Closed) => return Ok(None),
                Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                    return Err(SessionEventLogStreamError::Lagged { skipped });
                }
            }
        }
    }

    /// Advances stream state for a broadcast frame, returning it to deliver or `None` when stale.
    fn deliver_frame(&mut self, frame: SessionEventLogFrame) -> Option<SessionEventLogFrame> {
        if frame.generation < self.generation {
            return None;
        }
        if frame.generation > self.generation {
            self.generation = frame.generation;
            self.replay_exhausted = true;
            self.backlog.clear();
        } else if frame.cursor.next_sequence < self.next_cursor.next_sequence {
            return None;
        }
        self.next_cursor = frame.next_cursor;
        Some(frame)
    }

    /// Refills the drained replay backlog and pops the next non-stale frame,
    /// returning `None` when it is exhausted and the tail should be consulted.
    fn take_ready_backlog_frame(&mut self) -> Option<SessionEventLogFrame> {
        loop {
            let hub_generation = self.hub.generation();
            if hub_generation > self.generation {
                self.generation = hub_generation;
                self.next_cursor = self.next_cursor.min(self.hub.generation_start_cursor());
                self.replay_tail = self.hub.current_cursor();
                self.replay_exhausted = false;
                self.backlog.clear();
            }
            if self.backlog.is_empty() && !self.replay_exhausted {
                self.backlog =
                    self.hub
                        .replay_batch_from(self.next_cursor, self.replay_tail, self.generation);
                self.replay_exhausted = self.backlog.is_empty();
            }
            let frame = self.backlog.pop_front()?;
            if frame.generation < self.generation
                || frame.cursor.next_sequence < self.next_cursor.next_sequence
            {
                continue;
            }
            self.next_cursor = frame.next_cursor;
            return Some(frame);
        }
    }
}

/// One run-state transition delivered to a control-plane subscriber.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStateTransitionFrame {
    /// Monotone actor-local transition sequence.
    pub sequence: u64,
    /// Full actor state observed before the transition was published.
    pub from_state: EngineState,
    /// Full actor state observed after the transition was published.
    pub to_state: EngineState,
    /// Lock-free snapshot observed before the transition was published.
    pub from: LiveSnapshotView,
    /// Lock-free snapshot observed after the transition was published.
    pub to: LiveSnapshotView,
}

/// Error returned while reading a live state-transition stream.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SessionStateTransitionStreamError {
    /// The subscriber lagged behind the bounded live tail.
    #[error("session state-transition stream skipped {skipped} frames")]
    Lagged {
        /// Number of skipped broadcast frames reported by the live tail.
        skipped: u64,
    },
}

/// Session-owned state-transition hub used by the control plane.
#[derive(Clone, Debug)]
pub struct SessionStateTransitionBus {
    tail: broadcast::Sender<SessionStateTransitionFrame>,
}

impl SessionStateTransitionBus {
    /// Builds an empty state-transition bus.
    #[must_use]
    pub fn new() -> Self {
        let (tail, _) = broadcast::channel(SESSION_STATE_BROADCAST_CAPACITY);
        Self { tail }
    }

    /// Subscribes to future state transitions.
    ///
    /// Subscribing clones only a broadcast receiver. It does not enqueue a
    /// session command, take an engine lock, or await the scheduler.
    #[must_use]
    pub fn subscribe(&self) -> SessionStateTransitionStream {
        SessionStateTransitionStream {
            receiver: self.tail.subscribe(),
        }
    }

    pub(super) fn publish(&self, frame: SessionStateTransitionFrame) {
        let _ = self.tail.send(frame);
    }
}

impl Default for SessionStateTransitionBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Live state-transition stream for one subscriber.
#[derive(Debug)]
pub struct SessionStateTransitionStream {
    receiver: broadcast::Receiver<SessionStateTransitionFrame>,
}

impl SessionStateTransitionStream {
    /// Receives the next state-transition frame.
    ///
    /// # Errors
    ///
    /// Returns [`SessionStateTransitionStreamError::Lagged`] when this
    /// subscriber falls behind the bounded live broadcast tail.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<SessionStateTransitionFrame>, SessionStateTransitionStreamError> {
        match self.receiver.recv().await {
            Ok(frame) => Ok(Some(frame)),
            Err(broadcast::error::RecvError::Closed) => Ok(None),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                Err(SessionStateTransitionStreamError::Lagged { skipped })
            }
        }
    }
}
