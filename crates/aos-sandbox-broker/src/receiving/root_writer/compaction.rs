//! Adapts genuine Root ownership to the sole shared physical replacement engine.
//!
//! Root's actual coordinator pays before this closed entry and runs its SAME
//! semantic loop over the shared cursor. The native stage creates no semantic
//! grant, vector or File escape. Unfinished work closes the SAME invocation.

use std::sync::Arc;

use aos_sandbox_journal::protected_storage::FileIdentity;
use crate::canonical_journal::coordinator::replacement::{
    CanonicalReplacementFailureOriginalV1, CanonicalSelectedReplacementV1,
    selected_replacement_demand_v1,
};
use crate::receiving::root_permanent::RootPermanentNativeOriginalV1;
use super::{RootCoordinatorWriterV1, RootWriterErrorV1, RootWriterReplayV1};

/// Retains one Root replacement through its complete semantic and post interval.
pub struct RootPreparedReplacementV1<P> {
    original: Arc<RootPermanentNativeOriginalV1>,
    stage: Option<CanonicalSelectedReplacementV1<P>>,
}

impl<P> RootCoordinatorWriterV1<P> {
    /// Prices this actual input before replacement/model/encoder growth.
    ///
    /// The upper same-R owner adds its complete semantic and original-post
    /// suppliers before invoking this native port. This DATA grants no payment.
    ///
    /// # Errors
    /// Refuses checked actual-row/node/byte geometry overflow.
    pub fn replacement_demand_v1(&self)
        -> Result<aos_sandbox_core::ResourceVector, RootWriterErrorV1>
    {
        use aos_sandbox_core::{ResourceDimension, ResourceVector};

        let native = selected_replacement_demand_v1::<P>(
            self.physical.native.native().state(), self.physical.native.native().limits(),
            self.physical.location.name(),
        )?;
        let bytes = std::mem::size_of::<RootPreparedReplacementV1<P>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<RootReplacementFailureOriginalV1<P>>().checked_mul(3)?,
            )).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(RootWriterErrorV1::Closed)?;
        native.checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
            .map_err(|_| RootWriterErrorV1::Closed)
    }

    /// Starts the fixed writer's already-paid physical replacement.
    ///
    /// # Errors
    /// Refuses fresh entry on an unhealthy invocation, writer or pending stage.
    /// A native failure returns its complete stage with the cause resident.
    pub fn prepare_replacement_once(&mut self)
        -> Result<RootPreparedReplacementV1<P>, RootWriterErrorV1>
    {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        // The invocation is already locked: inspect native/sinks directly,
        // without reentering the phase getter.
        if !self.native_stage_is_idle() {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        let stage = match self.physical.prepare_replacement_once() {
            Ok(stage) => stage,
            Err(cause) => {
                guard.refuse();
                return Err(cause.into());
            }
        };
        if stage.failure().is_some() { guard.refuse(); }
        Ok(RootPreparedReplacementV1 {
            original: Arc::clone(&self.original), stage: Some(stage),
        })
    }

    /// Installs the SAME replayed native prefix after upper final checks.
    ///
    /// # Errors
    /// Retains physical/native refusal or rejects a foreign/unfinished original.
    pub fn install_replacement_once(&mut self, stage: &mut RootPreparedReplacementV1<P>)
        -> Result<(), RootWriterErrorV1>
    {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| {
            if !Arc::ptr_eq(&self.original, &stage.original) {
                return Err(RootWriterErrorV1::Closed);
            }
            let native = stage.stage.as_mut().ok_or(RootWriterErrorV1::Closed)?;
            self.physical.install_replacement_once(native)?;
            self.durable_end = native.installed_durable_end_v1().ok_or(RootWriterErrorV1::Closed)?;
            Ok(())
        })();
        if result.is_err() { guard.refuse(); }
        result
    }

    /// Retires the completed replacement only after all upper owed posts.
    ///
    /// # Errors
    /// Refuses foreign, failed or unfinished disposition without refund.
    pub fn finish_replacement_after_posts_once(
        &mut self, stage: &mut RootPreparedReplacementV1<P>,
    ) -> Result<(), RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        let result = (|| {
            if !Arc::ptr_eq(&self.original, &stage.original) {
                return Err(RootWriterErrorV1::Closed);
            }
            let native = stage.stage.as_mut().ok_or(RootWriterErrorV1::Closed)?;
            self.physical.finish_replacement_after_posts_once(native)?;
            Ok(())
        })();
        if result.is_err() { guard.refuse(); }
        result
    }
}

impl<P> RootPreparedReplacementV1<P> {
    /// Borrows the original reached physical/parser/index failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stage.as_ref().and_then(CanonicalSelectedReplacementV1::failure)
            .or_else(|| self.original.invocation().failure().map(|cause| cause as _))
    }

    /// Samples the prepared replacement at its actual pre-parser frontier.
    ///
    /// # Errors
    /// Retains identity partials and closes the same invocation on failure.
    pub fn prepare_identity_once(&mut self) -> Result<FileIdentity, RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        let result = self.stage.as_mut().ok_or(RootWriterErrorV1::Closed)
            .and_then(|stage| stage.prepare_identity_once().map_err(RootWriterErrorV1::from));
        if result.is_err() { guard.refuse(); }
        result
    }

    /// Borrows the indexed cursor inside its continuous Root phase guard.
    ///
    /// # Errors
    /// Retains native failure; an unfinished semantic window closes the original.
    pub fn begin_replay_once(&mut self) -> Result<RootWriterReplayV1<'_, '_>, RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        let stage = match self.stage.as_mut() {
            Some(stage) => stage,
            None => {
                guard.refuse();
                return Err(RootWriterErrorV1::Closed);
            }
        };
        let cursor = match stage.begin_replay_once() {
            Ok(cursor) => cursor,
            Err(cause) => {
                guard.refuse();
                return Err(cause.into());
            }
        };
        Ok(RootWriterReplayV1::from_initial(guard, cursor))
    }

    /// Parks the negative stage beside its permanent original error source.
    #[must_use]
    pub fn into_failure_original_v1(mut self) -> RootReplacementFailureOriginalV1<P> {
        self.original.invocation().latch_refusal();
        RootReplacementFailureOriginalV1 {
            original: Arc::clone(&self.original),
            stage: self.stage.take().map(CanonicalSelectedReplacementV1::into_failure_original),
        }
    }
}

impl<P> Drop for RootPreparedReplacementV1<P> {
    fn drop(&mut self) {
        if self.stage.as_ref().is_some_and(CanonicalSelectedReplacementV1::has_resident_body) {
            self.original.invocation().latch_refusal();
            // The nested guard parks before the original Arc can release.
            drop(self.stage.take());
        }
    }
}

/// Keeps the SAME Root and physical failure after the top error drops.
pub struct RootReplacementFailureOriginalV1<P> {
    original: Arc<RootPermanentNativeOriginalV1>,
    stage: Option<CanonicalReplacementFailureOriginalV1<P>>,
}

impl<P> RootReplacementFailureOriginalV1<P> {
    /// Borrows the retained native cause before later invocation markers.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stage.as_ref().and_then(CanonicalReplacementFailureOriginalV1::failure)
            .or_else(|| self.original.invocation().failure().map(|cause| cause as _))
    }
}

impl<P> std::fmt::Debug for RootReplacementFailureOriginalV1<P> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("RootReplacementFailureOriginalV1")
            .field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl<P> std::fmt::Display for RootReplacementFailureOriginalV1<P> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("Root replacement original was refused"),
        }
    }
}

impl<P: 'static> std::error::Error for RootReplacementFailureOriginalV1<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
}
