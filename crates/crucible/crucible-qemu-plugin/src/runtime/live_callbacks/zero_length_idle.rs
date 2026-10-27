//! Which advance the plugin's latest zero-length idle publication answered.
//!
//! An idle wake at or before the node's coordinate is the shared protocol's
//! quiesced-boundary encoding, and it is a claim about one advance. The settle
//! at a clamp ceiling leaves one behind, and so does every stop the node takes
//! while running toward a ceiling: a network or console output stop, a
//! selectable or campaign-marker VMStop, a checkpoint pause, or an idle pass
//! whose wake is due now. The slot cannot tell these apart once a later
//! advance is published, because the stale ceiling marker and a fresh stop at
//! the same coordinate store the same fields.
//!
//! This process wrote all of them, so it records the advance publication each
//! one answered. When QEMU's main loop answers a control request below the
//! ceiling, the control-boundary writer compares that record with the advance
//! it loads itself: an idle left by an earlier advance is dropped and the node
//! publishes running, while a stop taken for this advance is preserved.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{IdleHotLoopError, LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};

/// No zero-length idle has been recorded.
const UNRECORDED: u64 = u64::MAX;

/// The advance sequence of the latest zero-length idle this plugin published.
pub(super) struct ZeroLengthIdleAnswer(AtomicU64);

impl ZeroLengthIdleAnswer {
    pub(super) const fn new() -> Self {
        Self(AtomicU64::new(UNRECORDED))
    }

    pub(super) fn get(&self) -> Option<u64> {
        let advance = self.0.load(Ordering::Acquire);
        (advance != UNRECORDED).then_some(advance)
    }

    pub(super) fn set(&self, advance: Option<u64>) {
        self.0
            .store(advance.unwrap_or(UNRECORDED), Ordering::Release);
    }
}

impl LiveVcpuTimeCallbackState {
    /// Loads the advance a zero-length idle about to be published answers.
    ///
    /// The host publishes a newer advance only after it accepted a boundary
    /// of this one, so a stop written after this load still answers it; the
    /// load precedes the write so that a racing publication can only make the
    /// record older, never credit an earlier stop to the newer advance.
    pub(super) fn zero_length_idle_advance(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        self.slot
            .get()
            .load_scheduler_advance_publication()
            .map(|advance| advance.sequence())
            .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop {
                source: IdleHotLoopError::AdvanceStopCondition { source },
            })
    }

    /// Records that a published zero-length idle answered `advance`.
    pub(super) fn record_zero_length_idle(&self, advance: u64) {
        self.zero_length_idle_answer.set(Some(advance));
    }
}
