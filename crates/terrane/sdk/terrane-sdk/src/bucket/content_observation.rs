//! Observes actual typed content attempts within one native test bucket.
//!
//! Counters follow the bucket's shared inner allocation and do not supply
//! content, alter validation, or confer publication authority. Snapshots and
//! resets are intended for quiescent fixture boundaries.

use std::sync::atomic::{AtomicUsize, Ordering};

use terrane_format::identity::IdentityKind;

/// Counts actual typed content attempts and metadata-validator Node decodes.
#[derive(Default)]
pub(crate) struct ContentObservation {
    chunk_gets: AtomicUsize,
    node_gets: AtomicUsize,
    node_puts: AtomicUsize,
    commit_gets: AtomicUsize,
    commit_puts: AtomicUsize,
    node_decodes: AtomicUsize,
    get_close_pause: std::sync::Mutex<Option<std::sync::Arc<GetClosePause>>>,
}

/// Pauses an actual verified get before its first fresh closing observation.
#[derive(Default)]
pub(crate) struct GetClosePause {
    /// Signals that the real get has consumed and verified its payload inputs.
    pub(crate) arrived: tokio::sync::Notify,
    /// Lets that same request begin its unchanged closing validation.
    pub(crate) release: tokio::sync::Notify,
}

/// Captures the counters at a quiescent native fixture boundary.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct ContentCounts {
    /// Chunk get attempts before catalog access, including rejected or missing reads.
    pub(crate) chunk_gets: usize,
    /// Node get attempts, including missing identities and rejected reads.
    pub(crate) node_gets: usize,
    /// Node put attempts, including validation failures and deduplication.
    pub(crate) node_puts: usize,
    /// Commit get attempts, independently of pack-file I/O.
    pub(crate) commit_gets: usize,
    /// Commit put attempts, independently of pack-file I/O.
    pub(crate) commit_puts: usize,
    /// Actual calls to the configured metadata validator's Node decoder.
    pub(crate) node_decodes: usize,
}

impl ContentObservation {
    /// Installs one pause in the next real native request, without changing data.
    ///
    /// # Panics
    /// Panics if the isolated fixture's observation mutex is poisoned.
    pub(crate) fn pause_next_get(&self) -> std::sync::Arc<GetClosePause> {
        let pause = std::sync::Arc::new(GetClosePause::default());
        *self
            .get_close_pause
            .lock()
            .unwrap_or_else(|_| panic!("native content observation pause mutex poisoned")) =
            Some(std::sync::Arc::clone(&pause));
        pause
    }

    /// Hands an armed fixture the genuine pre-closing boundary once.
    ///
    /// # Panics
    /// Panics if the isolated fixture's observation mutex is poisoned.
    pub(super) async fn before_get_close(&self) {
        let pause = self
            .get_close_pause
            .lock()
            .unwrap_or_else(|_| panic!("native content observation pause mutex poisoned"))
            .take();
        if let Some(pause) = pause {
            pause.arrived.notify_one();
            pause.release.notified().await;
        }
    }

    /// Reads each counter without claiming an atomic cross-counter snapshot.
    pub(crate) fn snapshot(&self) -> ContentCounts {
        ContentCounts {
            chunk_gets: self.chunk_gets.load(Ordering::SeqCst),
            node_gets: self.node_gets.load(Ordering::SeqCst),
            node_puts: self.node_puts.load(Ordering::SeqCst),
            commit_gets: self.commit_gets.load(Ordering::SeqCst),
            commit_puts: self.commit_puts.load(Ordering::SeqCst),
            node_decodes: self.node_decodes.load(Ordering::SeqCst),
        }
    }

    /// Clears counters between measured operations while the fixture is idle.
    pub(crate) fn reset(&self) {
        for counter in [
            &self.chunk_gets,
            &self.node_gets,
            &self.node_puts,
            &self.commit_gets,
            &self.commit_puts,
            &self.node_decodes,
        ] {
            counter.store(0, Ordering::SeqCst);
        }
    }

    /// Records a typed read before catalog access or body verification.
    pub(super) fn get(&self, kind: IdentityKind) {
        if kind == IdentityKind::Chunk {
            self.chunk_gets.fetch_add(1, Ordering::SeqCst);
            return;
        }
        self.operation(kind, &self.node_gets, &self.commit_gets);
    }

    /// Records a typed admission before validation or deduplication.
    pub(super) fn put(&self, kind: IdentityKind) {
        self.operation(kind, &self.node_puts, &self.commit_puts);
    }

    /// Records one actual metadata-validator decoder invocation.
    pub(crate) fn node_decode(&self) {
        self.node_decodes.fetch_add(1, Ordering::SeqCst);
    }

    fn operation(&self, kind: IdentityKind, node: &AtomicUsize, commit: &AtomicUsize) {
        let counter = match kind {
            IdentityKind::Node => node,
            IdentityKind::Commit => commit,
            _ => return,
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

#[path = "content_observation/tests.rs"]
mod tests;
