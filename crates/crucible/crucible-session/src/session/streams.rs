//! Session event-log and state-transition broadcast streams.
//!
//! The event-log hub keeps the session's log as sealed segments plus a
//! bounded resident tail ([`super::session_segmented_log`]). A subscriber
//! first replays from its cursor, reading one sealed segment at a time, then
//! follows the bounded live broadcast ring. A lagging subscriber falls back
//! to cursor replay, so no subscriber needs the whole log in memory.

use super::session_segmented_log::{LogChunk, SegmentedEntryLog};
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
    /// A sealed segment needed for cursor replay could not be read back.
    #[error("session event-log replay is unavailable: {0}")]
    Unavailable(#[from] SessionEventLogStoreError),
}

/// Session-owned event-log hub used by the control plane.
#[derive(Clone, Debug)]
pub struct SessionEventLog {
    inner: Arc<SessionEventLogInner>,
}

#[derive(Debug)]
pub(super) struct SessionEventLogInner {
    log: Mutex<SegmentedEntryLog>,
    generation: AtomicU64,
    generation_start: AtomicU64,
    tail: broadcast::Sender<SessionEventLogFrame>,
}

impl SessionEventLog {
    /// Builds an empty event-log hub that seals into process memory.
    ///
    /// Use [`Self::with_segment_store`] to keep sealed segments on disk.
    #[must_use]
    pub fn new() -> Self {
        Self::with_segment_store(Arc::new(crucible_engine::MemoryDagStore::new()))
    }

    /// Builds an empty event-log hub that seals its segments into `store`.
    ///
    /// Only the entries since the last seal stay resident; replay reads older
    /// entries back from `store` one segment at a time.
    #[must_use]
    pub fn with_segment_store(store: Arc<dyn DagStore>) -> Self {
        Self::from_log(SegmentedEntryLog::new(store))
    }

    /// Builds a hub with a small seal target for segment-crossing tests.
    #[cfg(test)]
    pub(super) fn with_seal_target_for_test(store: Arc<dyn DagStore>, seal_target: u64) -> Self {
        Self::from_log(SegmentedEntryLog::with_seal_target(store, seal_target))
    }

    fn from_log(log: SegmentedEntryLog) -> Self {
        let (tail, _) = broadcast::channel(SESSION_EVENT_LOG_BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(SessionEventLogInner {
                log: Mutex::new(log),
                generation: AtomicU64::new(0),
                generation_start: AtomicU64::new(0),
                tail,
            }),
        }
    }

    /// Returns the number of retained event-log entries.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.lock_log().len()
    }

    /// Returns whether no event-log entries are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock_log().is_empty()
    }

    /// Returns a cursor positioned at the retained log tail.
    #[must_use]
    pub fn current_cursor(&self) -> EventLogCursor {
        EventLogCursor::new(self.lock_log().end())
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
                chunk: None,
                receiver,
            },
        )
    }

    /// Returns a log-derived snapshot summary through `cursor`.
    ///
    /// The hub keeps cumulative class counts per sealed segment, so a cursor
    /// at the log tail needs no read and an earlier cursor decodes at most
    /// one segment.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEventLogStoreError`] when the segment containing
    /// `cursor` cannot be read back and authenticated.
    pub fn snapshot_through(
        &self,
        cursor: EventLogCursor,
    ) -> Result<SessionEventLogSnapshot, SessionEventLogStoreError> {
        let (counts, last_sequence) = self.lock_log().counts_through(cursor.next_sequence)?;
        Ok(SessionEventLogSnapshot {
            through: cursor,
            event_count: counts.total(),
            causal_count: counts.causal,
            observational_count: counts.observational,
            last_sequence,
        })
    }

    pub(super) fn append_entries(
        &self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SessionEventLogStoreError> {
        if entries.is_empty() {
            return Ok(());
        }

        let generation = self.generation();
        self.lock_log().append(entries)?;
        for entry in entries {
            let _ = self
                .inner
                .tail
                .send(SessionEventLogFrame::new(entry.clone(), generation));
        }
        Ok(())
    }

    /// Drops every entry at or after sequence `len` and starts a new stream
    /// generation when anything was dropped.
    pub(super) fn truncate_to_len(&self, len: usize) -> Result<(), SessionEventLogStoreError> {
        let len = usize_to_u64(len);
        let mut log = self.lock_log();
        if log.end() > len && !log.is_empty() {
            log.truncate(len)?;
            self.inner.generation_start.store(len, Ordering::Release);
            self.inner.generation.fetch_add(1, Ordering::AcqRel);
        }
        Ok(())
    }

    /// Collects every retained entry for test inspection.
    #[cfg(test)]
    pub(super) fn entries_for_test(&self) -> Vec<SchedulerEventLogEntry> {
        match self.lock_log().collect_through(u64::MAX) {
            Ok(entries) => entries,
            Err(error) => panic!("session event log must read back: {error}"),
        }
    }

    fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    fn generation_start_cursor(&self) -> EventLogCursor {
        EventLogCursor::new(self.inner.generation_start.load(Ordering::Acquire))
    }

    fn lock_log(&self) -> std::sync::MutexGuard<'_, SegmentedEntryLog> {
        match self.inner.log.lock() {
            Ok(log) => log,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn replay_chunk_from(
        &self,
        cursor: EventLogCursor,
    ) -> Result<Option<LogChunk>, SessionEventLogStoreError> {
        self.lock_log()
            .chunk_from(cursor.next_sequence, SESSION_EVENT_LOG_REPLAY_BATCH_SIZE)
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

    use crucible_engine::SchedulerEventLogEntry;

    use crate::{SessionEventLog, SessionEventLogStoreError};

    /// Appends event-log entries to a session event-log hub for integration tests.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEventLogStoreError`] when the entries are not dense
    /// after the hub's tail or a full tail cannot be sealed.
    pub fn append_event_log_entries_for_test(
        hub: &SessionEventLog,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SessionEventLogStoreError> {
        hub.append_entries(entries)
    }

    /// Truncates a session event-log hub to `len` entries for integration tests.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEventLogStoreError`] when a cut inside a sealed
    /// segment cannot read that segment back.
    pub fn truncate_event_log_for_test(
        hub: &SessionEventLog,
        len: usize,
    ) -> Result<(), SessionEventLogStoreError> {
        hub.truncate_to_len(len)
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
    // One decoded segment or tail slice, reused while replay walks it.
    chunk: Option<LogChunk>,
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
    /// A subscriber that falls behind the bounded live broadcast tail resumes
    /// from the retained event log at its current cursor. Returns
    /// [`SessionEventLogStreamError::Unavailable`] when cursor replay cannot
    /// read a sealed segment back.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<SessionEventLogFrame>, SessionEventLogStreamError> {
        loop {
            if let Some(frame) = self.take_ready_backlog_frame()? {
                return Ok(Some(frame));
            }
            match self.receiver.recv().await {
                Ok(frame) => {
                    if let Some(frame) = self.deliver_frame(frame) {
                        return Ok(Some(frame));
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(None),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    self.resume_from_retained_log();
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
    /// A subscriber that falls behind the bounded live broadcast tail resumes
    /// from the retained event log at its current cursor. Returns
    /// [`SessionEventLogStreamError::Unavailable`] when cursor replay cannot
    /// read a sealed segment back.
    pub fn try_recv(&mut self) -> Result<Option<SessionEventLogFrame>, SessionEventLogStreamError> {
        loop {
            if let Some(frame) = self.take_ready_backlog_frame()? {
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
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    self.resume_from_retained_log();
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

    /// Switches a lagged live receiver back to cursor-based retained replay.
    fn resume_from_retained_log(&mut self) {
        self.replay_tail = self.hub.current_cursor();
        self.replay_exhausted = false;
        self.backlog.clear();
    }

    /// Refills the drained replay backlog and pops the next non-stale frame,
    /// returning `None` when it is exhausted and the tail should be consulted.
    fn take_ready_backlog_frame(
        &mut self,
    ) -> Result<Option<SessionEventLogFrame>, SessionEventLogStoreError> {
        loop {
            let hub_generation = self.hub.generation();
            if hub_generation > self.generation {
                self.generation = hub_generation;
                self.next_cursor = self.next_cursor.min(self.hub.generation_start_cursor());
                self.replay_tail = self.hub.current_cursor();
                self.replay_exhausted = false;
                self.backlog.clear();
                // A truncation can replace entries at already decoded sequences.
                self.chunk = None;
            }
            if self.backlog.is_empty() && !self.replay_exhausted {
                self.backlog = self.replay_batch()?;
                self.replay_exhausted = self.backlog.is_empty();
            }
            let Some(frame) = self.backlog.pop_front() else {
                return Ok(None);
            };
            if frame.generation < self.generation
                || frame.cursor.next_sequence < self.next_cursor.next_sequence
            {
                continue;
            }
            self.next_cursor = frame.next_cursor;
            return Ok(Some(frame));
        }
    }

    /// Reads up to one replay batch from the cursor toward the replay tail.
    ///
    /// A decoded sealed segment is kept and walked batch by batch before the
    /// next one is read, so replay holds at most one segment.
    fn replay_batch(
        &mut self,
    ) -> Result<VecDeque<SessionEventLogFrame>, SessionEventLogStoreError> {
        let cursor = self.next_cursor.next_sequence;
        if cursor >= self.replay_tail.next_sequence {
            return Ok(VecDeque::new());
        }
        if self
            .chunk
            .as_ref()
            .is_none_or(|chunk| chunk.get(cursor).is_none())
        {
            self.chunk = self.hub.replay_chunk_from(self.next_cursor)?;
        }
        let Some(chunk) = self.chunk.as_ref() else {
            return Ok(VecDeque::new());
        };

        let end = chunk.end().min(self.replay_tail.next_sequence);
        let frames = (cursor.max(chunk.first_sequence)..end)
            .take(SESSION_EVENT_LOG_REPLAY_BATCH_SIZE)
            .filter_map(|sequence| chunk.get(sequence).cloned())
            .map(|entry| SessionEventLogFrame::new(entry, self.generation))
            .collect();
        Ok(frames)
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
            sequence_floor: 0,
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
    sequence_floor: u64,
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

    /// Receives the next transition, coalescing a lagged retained tail to its
    /// greatest immediately available sequence.
    pub async fn recv_latest(&mut self) -> Option<SessionStateTransitionFrame> {
        loop {
            let frame = match self.receiver.recv().await {
                Ok(frame) => Some(frame),
                Err(broadcast::error::RecvError::Closed) => return None,
                Err(broadcast::error::RecvError::Lagged(_)) => self.drain_latest_ready(),
            };
            let Some(frame) = frame else {
                continue;
            };
            if frame.sequence <= self.sequence_floor {
                continue;
            }
            self.sequence_floor = frame.sequence;
            return Some(frame);
        }
    }

    /// Sets the greatest state-transition sequence already represented by the
    /// subscriber's attach snapshot.
    pub fn set_sequence_floor(&mut self, sequence: u64) {
        self.sequence_floor = self.sequence_floor.max(sequence);
    }

    fn drain_latest_ready(&mut self) -> Option<SessionStateTransitionFrame> {
        let mut latest = None;
        loop {
            match self.receiver.try_recv() {
                Ok(frame) => latest = Some(frame),
                Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(
                    broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed,
                ) => return latest,
            }
        }
    }
}
