//! Cooperative lifetime/deadline and approximate SQLite VM work budgets.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use super::{
    ScratchCancellation, ScratchResult, ScratchVerificationError, ScratchVerificationLimits,
};

#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct TestControls {
    pub started: Option<Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>>,
    pub cleaned: Option<Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>>,
    pub pause_final_progress: bool,
}

#[cfg(not(test))]
#[derive(Clone, Default)]
pub(super) struct TestControls;

#[derive(Clone)]
pub(super) struct WorkBudget {
    active: Arc<AtomicBool>,
    cancellation: ScratchCancellation,
    callbacks: Arc<AtomicU64>,
    deadline: Instant,
    maximum_callbacks: u64,
    #[cfg(test)]
    final_checks: Arc<AtomicBool>,
    #[cfg(test)]
    controls: TestControls,
}

impl WorkBudget {
    pub(super) fn new(
        limits: ScratchVerificationLimits,
        cancellation: ScratchCancellation,
        controls: TestControls,
    ) -> ScratchResult<Self> {
        let deadline = Instant::now()
            .checked_add(limits.max_duration)
            .ok_or(ScratchVerificationError::InvalidLimits)?;
        #[cfg(not(test))]
        let _ = controls;
        Ok(Self {
            active: Arc::new(AtomicBool::new(true)),
            cancellation,
            callbacks: Arc::new(AtomicU64::new(0)),
            deadline,
            maximum_callbacks: limits.max_progress_callbacks,
            #[cfg(test)]
            final_checks: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            controls,
        })
    }

    pub(super) fn check(&self) -> ScratchResult<()> {
        if !self.active.load(Ordering::Acquire) || self.cancellation.0.load(Ordering::Acquire) {
            return Err(ScratchVerificationError::Cancelled);
        }
        if Instant::now() >= self.deadline
            || self.callbacks.load(Ordering::Relaxed) > self.maximum_callbacks
        {
            return Err(ScratchVerificationError::Limits);
        }
        Ok(())
    }

    pub(super) fn error_or(&self, other: ScratchVerificationError) -> ScratchVerificationError {
        self.check().err().unwrap_or(other)
    }

    // rusqlite's handler returns true to INTERRUPT, unlike SQLx's continue flag.
    pub(super) fn interrupt(&self) -> bool {
        self.callbacks.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        if self.final_checks.load(Ordering::Acquire) {
            if let Some(started) = &self.controls.started {
                if let Ok(mut sender) = started.lock() {
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(());
                    }
                }
            }
            if self.controls.pause_final_progress {
                while self.check().is_ok() {
                    std::thread::yield_now();
                }
            }
        }
        self.check().is_err()
    }

    pub(super) fn begin_final_checks(&self) {
        #[cfg(test)]
        self.final_checks.store(true, Ordering::Release);
    }

    pub(super) fn cleaned(&self) {
        #[cfg(test)]
        if let Some(cleaned) = &self.controls.cleaned {
            if let Ok(mut sender) = cleaned.lock() {
                if let Some(sender) = sender.take() {
                    let _ = sender.send(());
                }
            }
        }
    }
}

pub(super) struct CancelOnDrop(WorkBudget);

impl CancelOnDrop {
    pub(super) fn new(budget: WorkBudget) -> Self {
        Self(budget)
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::Release);
    }
}
