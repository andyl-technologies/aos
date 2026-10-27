//! Dispatches paid read-only execution observation before catalog refresh.
//!
//! The actual executor owns purpose18, Source and Broker originals. This bridge
//! grants no new execution effect or automatic terminal projection from rows.

use super::*;

impl<C: ActivatedOperationCompiler, E: SingleNodeEffectExecutor> NodeController<C, E> {
    /// Observes one existing execution through the executor's original custody.
    ///
    /// # Errors
    /// Returns the retained observation refusal without changing public phase.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn observe_current_executions_v4(&mut self) -> Result<(), crate::EffectFailure> {
        self.reconciler.observe_current_executions_v4()
    }
}
