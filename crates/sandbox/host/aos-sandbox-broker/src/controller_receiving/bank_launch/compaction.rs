//! Adapts the genuine Controller writer to the sole physical replacement engine.
//!
//! Domain keeps all semantic and final-crossing gates in its existing engine.
//! This closed C adapter prepays the actual replacement and upper representation,
//! joins the same writer identity, and retains native uncertainty through posts.
//! No file, mutable native view, role loan or semantic success can escape here.

use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension, ResourceVector};
use aos_sandbox_journal::protected_storage::FileIdentity;

use crate::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayV1;
use crate::canonical_journal::coordinator::replacement::{
    CanonicalReplacementFailureOriginalV1, CanonicalSelectedReplacementV1,
    selected_replacement_demand_v1,
};

use super::identity::ControllerWriterIdentityV1;
use super::{ControllerBankLaunchErrorV1, ControllerCoordinatorWriterV1};

/// Retains one same-C replacement through semantic replay and all owed posts.
///
/// Only the genuine fixed coordinator constructs it. The common stage owns the
/// actual replacement File, cleanup obligation and native/index destinations.
pub struct ControllerPreparedReplacementV1<P> {
    identity: Arc<ControllerWriterIdentityV1>,
    stage: Option<CanonicalSelectedReplacementV1<P>>,
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Debits the trusted upper replacement owner's compiled byte representation.
    ///
    /// This monotone DATA port returns no native stage, readiness, continuation
    /// or account. Domain supplies the concrete sole semantic owner's bytes
    /// before constructing it. Replacement admission and its semantic gates
    /// remain independently required on this same genuine C writer.
    ///
    /// # Errors
    /// Retains geometry or same-C capacity refusal and closes fresh reuse.
    #[doc(hidden)]
    pub fn debit_replacement_semantic_bytes_v1(
        &mut self,
        bytes: usize,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.fixed.require_healthy()?;
        let bytes = bytes.max(self.fixed.replacement_semantic_bytes.unwrap_or(0));
        let demand = match self.replacement_representation_demand(bytes) {
            Ok(demand) => demand,
            Err(cause) => {
                self.fixed.borrow_debit_failure = Some(cause);
                self.fixed.fence();
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
        };
        self.fixed.require_role_borrow_representation(demand)?;
        self.fixed.replacement_semantic_bytes = Some(bytes);
        Ok(())
    }

    fn replacement_representation_demand(
        &self,
        semantic_bytes: usize,
    ) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let physical = selected_replacement_demand_v1::<P>(
            self.fixed.physical.native.native().state(), self.fixed.limits(),
            self.fixed.physical.location.name(),
        )?;
        let bytes = std::mem::size_of::<ControllerPreparedReplacementV1<P>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<ControllerReplacementFailureOriginalV1<P>>().checked_mul(3)?,
            ))
            .and_then(|bytes| bytes.checked_add(semantic_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(physical.checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))?
            .checked_add(super::ControllerNativePostOriginalV1::receiving_demand_v1()?)?)
    }

    /// Starts the same fixed writer's physical replacement after its full debit.
    ///
    /// # Errors
    /// Refuses unhealthy, active or unfunded entry. Native preparation failure
    /// remains in the returned whole stage, which must survive the owed posts.
    pub fn prepare_controller_replacement_once(
        &mut self,
    ) -> Result<ControllerPreparedReplacementV1<P>, ControllerBankLaunchErrorV1> {
        self.fixed.require_healthy()?;
        let semantic = self.fixed.replacement_semantic_bytes
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        self.debit_replacement_semantic_bytes_v1(semantic)?;
        let stage = self.fixed.physical.prepare_replacement_once()?;
        if stage.failure().is_some() {
            self.fixed.fence();
        }
        Ok(ControllerPreparedReplacementV1 {
            identity: Arc::clone(self.fixed.identity()),
            stage: Some(stage),
        })
    }

    /// Borrows the first replacement cause retained on the same permanent sink.
    #[must_use]
    pub fn retained_replacement_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.physical.replacement_custody.parked_body()
            .and_then(crate::canonical_journal::coordinator::replacement::SelectedReplacementBodyV1::failure)
    }

    /// Installs the same replayed replacement after the upper semantic gates.
    ///
    /// # Errors
    /// Rejects foreign or incomplete work and retains the actual physical cause.
    /// This entered operation does not use a fresh healthy-entry guard.
    pub fn install_controller_replacement_once(
        &mut self,
        replacement: &mut ControllerPreparedReplacementV1<P>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let result = (|| {
            if !Arc::ptr_eq(self.fixed.identity(), &replacement.identity) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            let stage = replacement.stage.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            self.fixed.physical.install_replacement_once(stage)?;
            let end = stage.installed_durable_end_v1().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            self.fixed.record_durable_end(end);
            Ok(())
        })();
        if result.is_err() {
            self.fixed.fence();
        }
        result
    }

    /// Retires completed physical work only after all same-C owed posts settle.
    ///
    /// # Errors
    /// Rejects foreign, failed or unfinished disposition without refunding debt.
    pub fn finish_controller_replacement_after_posts_once(
        &mut self,
        replacement: &mut ControllerPreparedReplacementV1<P>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let result = (|| {
            if !Arc::ptr_eq(self.fixed.identity(), &replacement.identity) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            let stage = replacement.stage.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            self.fixed.physical.finish_replacement_after_posts_once(stage)?;
            Ok(())
        })();
        if result.is_err() {
            self.fixed.fence();
        }
        result
    }
}

impl<P> ControllerPreparedReplacementV1<P> {
    /// Borrows the actual native, parser or resident index cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stage.as_ref().and_then(CanonicalSelectedReplacementV1::failure)
    }

    /// Samples the same installed replacement at the original parser frontier.
    ///
    /// # Errors
    /// Retains actual native identity evidence and refuses repeated preparation.
    pub fn prepare_identity_once(&mut self) -> Result<FileIdentity, ControllerBankLaunchErrorV1> {
        Ok(self.stage.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .prepare_identity_once()?)
    }

    /// Lends the common indexed cursor to the sole upper semantic replay loop.
    ///
    /// # Errors
    /// Retains physical failure or refuses absent and unfinished preparation.
    pub fn begin_replay_once(
        &mut self,
    ) -> Result<CanonicalIndexedReplayV1<'_, '_>, ControllerBankLaunchErrorV1> {
        Ok(self.stage.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .begin_replay_once()?)
    }

    /// Parks unfinished work beside the same actual permanent failure original.
    #[must_use]
    pub fn into_failure_original_v1(mut self) -> ControllerReplacementFailureOriginalV1<P> {
        ControllerReplacementFailureOriginalV1 {
            identity: Arc::clone(&self.identity),
            stage: self.stage.take().map(CanonicalSelectedReplacementV1::into_failure_original),
        }
    }
}

impl<P> Drop for ControllerPreparedReplacementV1<P> {
    fn drop(&mut self) {
        if self.stage.as_ref().is_some_and(CanonicalSelectedReplacementV1::has_resident_body) {
            // Park physical uncertainty before the same-C association releases.
            drop(self.stage.take());
        }
    }
}

/// Preserves the same C identity and actual permanently parked native cause.
pub struct ControllerReplacementFailureOriginalV1<P> {
    identity: Arc<ControllerWriterIdentityV1>,
    stage: Option<CanonicalReplacementFailureOriginalV1<P>>,
}

impl<P> ControllerReplacementFailureOriginalV1<P> {
    /// Borrows the original physical cause without reconstructing a diagnostic.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stage.as_ref().and_then(CanonicalReplacementFailureOriginalV1::failure)
    }
}

impl<P> std::fmt::Debug for ControllerReplacementFailureOriginalV1<P> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("ControllerReplacementFailureOriginalV1")
            .field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl<P> std::fmt::Display for ControllerReplacementFailureOriginalV1<P> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("Controller replacement original was refused"),
        }
    }
}

impl<P: 'static> std::error::Error for ControllerReplacementFailureOriginalV1<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}
