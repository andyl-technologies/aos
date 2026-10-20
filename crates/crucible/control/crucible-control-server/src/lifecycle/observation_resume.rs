//! Bounded preparation for campaign-authenticated observation resumes.
//!
//! This module owns cancellation, deadlines, in-flight permits, and the
//! pending-to-prepared transition used before the lifecycle registry publishes
//! a resumed session.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{Configuration, LifecycleApiError, ResumeSessionRequest};

type CancellationHandler = Arc<dyn Fn() + Send + Sync>;

struct CancellationState {
    canceled: AtomicBool,
    next_handler: AtomicU64,
    handlers: Mutex<BTreeMap<u64, CancellationHandler>>,
}

impl fmt::Debug for CancellationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResumeObservationCancellationState")
            .field("canceled", &self.canceled.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Cloneable cancellation signal for one portable observation preparation.
#[derive(Clone, Debug)]
pub struct ResumeObservationCancellation {
    state: Arc<CancellationState>,
}

impl Default for ResumeObservationCancellation {
    fn default() -> Self {
        Self {
            state: Arc::new(CancellationState {
                canceled: AtomicBool::new(false),
                next_handler: AtomicU64::new(0),
                handlers: Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

impl ResumeObservationCancellation {
    /// Returns whether request abandonment, shutdown, or the deadline requested cancellation.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.state.canceled.load(Ordering::Acquire)
    }

    /// Registers a callback for prompt backend cancellation.
    ///
    /// A callback registered after cancellation runs before this method
    /// returns. Dropping the returned registration removes the callback.
    #[must_use]
    pub fn register(
        &self,
        handler: impl Fn() + Send + Sync + 'static,
    ) -> ResumeObservationCancellationRegistration {
        let key = self.state.next_handler.fetch_add(1, Ordering::Relaxed);
        let handler: CancellationHandler = Arc::new(handler);
        let canceled = {
            let mut handlers = match self.state.handlers.lock() {
                Ok(handlers) => handlers,
                Err(poisoned) => poisoned.into_inner(),
            };
            if self.is_canceled() {
                true
            } else {
                handlers.insert(key, Arc::clone(&handler));
                false
            }
        };
        if canceled {
            handler();
        }
        ResumeObservationCancellationRegistration {
            state: Arc::clone(&self.state),
            key,
        }
    }

    pub(crate) fn cancel(&self) {
        if self.state.canceled.swap(true, Ordering::AcqRel) {
            return;
        }
        let handlers = {
            let handlers = match self.state.handlers.lock() {
                Ok(handlers) => handlers,
                Err(poisoned) => poisoned.into_inner(),
            };
            handlers.values().cloned().collect::<Vec<_>>()
        };
        for handler in handlers {
            handler();
        }
    }
}

/// Active cancellation callback for one portable observation preparation.
#[derive(Debug)]
pub struct ResumeObservationCancellationRegistration {
    state: Arc<CancellationState>,
    key: u64,
}

impl Drop for ResumeObservationCancellationRegistration {
    fn drop(&mut self) {
        let mut handlers = match self.state.handlers.lock() {
            Ok(handlers) => handlers,
            Err(poisoned) => poisoned.into_inner(),
        };
        handlers.remove(&self.key);
    }
}

/// Bounded authority supplied to campaign-owned observation preparation.
#[derive(Clone, Debug)]
pub struct ResumeObservationPreparationContext {
    pub(super) cancellation: ResumeObservationCancellation,
    pub(super) deadline: Instant,
}

impl ResumeObservationPreparationContext {
    pub(super) fn new(timeout: Duration) -> Self {
        let started = observation_preparation_now();
        Self {
            cancellation: ResumeObservationCancellation::default(),
            deadline: started.checked_add(timeout).unwrap_or(started),
        }
    }

    pub(super) fn is_expired(&self) -> bool {
        observation_preparation_now() >= self.deadline
    }

    /// Returns the cancellation signal shared with request and daemon shutdown.
    #[must_use]
    pub const fn cancellation(&self) -> &ResumeObservationCancellation {
        &self.cancellation
    }

    /// Returns the absolute wall-clock deadline for preparation and restore.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}

// Monotonic host time bounds only operational source preparation and never
// enters scenario, schedule, proof, checkpoint, or restored lifecycle state.
// crucible-lint: allow clippy-disallowed-method -- this deadline is an operational admission bound only.
#[allow(clippy::disallowed_methods)]
fn observation_preparation_now() -> Instant {
    Instant::now()
}

/// Factory that authenticates a portable observation source and returns its restored loop.
///
/// The implementation must reproduce the source through campaign ownership and
/// finish exact checkpoint restore before returning. HTTP and in-process
/// clients invoke it off the async runtime and outside the lifecycle registry
/// lock, before actor construction or session allocation.
pub type ResumeObservationLoopFactory<L> = Arc<
    dyn Fn(
            &ResumeSessionRequest,
            &Configuration,
            &ResumeObservationPreparationContext,
        ) -> Result<L, LifecycleApiError>
        + Send
        + Sync,
>;

pub(crate) struct PendingObservationResume<L> {
    pub(super) request: ResumeSessionRequest,
    pub(super) configuration: Configuration,
    pub(super) factory: ResumeObservationLoopFactory<L>,
    pub(super) context: ResumeObservationPreparationContext,
    pub(super) permit: ResumeObservationPreparationPermit,
}

impl<L> PendingObservationResume<L> {
    pub(crate) fn context(&self) -> &ResumeObservationPreparationContext {
        &self.context
    }

    pub(crate) fn authenticate(self) -> Result<PreparedObservationResume<L>, LifecycleApiError> {
        let loop_instance = (self.factory)(&self.request, &self.configuration, &self.context)?;
        if self.context.cancellation.is_canceled() {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: String::from("portable observation source preparation was canceled"),
            });
        }
        Ok(PreparedObservationResume {
            request: self.request,
            configuration: self.configuration,
            loop_instance,
            context: self.context,
            _permit: self.permit,
        })
    }
}

pub(crate) struct PreparedObservationResume<L> {
    pub(super) request: ResumeSessionRequest,
    pub(super) configuration: Configuration,
    pub(super) loop_instance: L,
    pub(super) context: ResumeObservationPreparationContext,
    _permit: ResumeObservationPreparationPermit,
}

impl<L> PreparedObservationResume<L> {
    pub(crate) fn context(&self) -> &ResumeObservationPreparationContext {
        &self.context
    }
}

pub(crate) struct ResumeObservationPreparationPermit {
    pub(super) active: Arc<AtomicU64>,
}

impl Drop for ResumeObservationPreparationPermit {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

pub(crate) struct ResumeObservationCancellationGuard {
    cancellation: ResumeObservationCancellation,
    armed: bool,
}

impl ResumeObservationCancellationGuard {
    pub(crate) fn new(cancellation: ResumeObservationCancellation) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    pub(crate) fn cancel(&mut self) {
        self.cancellation.cancel();
        self.armed = false;
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ResumeObservationCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}
