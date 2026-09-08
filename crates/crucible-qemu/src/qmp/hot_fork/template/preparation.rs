//! Drives retained template acquisition before branch-private resource staging.

use std::thread;

use super::{
    QMP_HOT_FORK_PLUGIN_RING_PROOF, QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS,
    QmpHotForkTemplateOutcome, QmpHotForkTemplateState,
};
use crate::{QmpClient, QmpError, QmpHotForkBlockSnapshotBinding, QmpTimeoutStream};

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Acquires the retained template barriers before child-resource staging.
    ///
    /// Each exchange advances the same QEMU-owned preparation transaction.
    /// Merely querying it cannot advance the main-loop acquisition phases.
    /// The configured job poll count and blocking interval bound this wait;
    /// each exchange also retains its ordinary QMP I/O deadline. This operation
    /// stops before the plugin-ring proof, which needs branch-private resources.
    ///
    /// An error leaves the source and any retained transaction owned by the
    /// caller. It does not silently abort or start a replacement generation.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when a QMP exchange fails, preparation terminates
    /// without retaining its barriers, the transaction generation changes, or
    /// the configured poll bound expires before every non-plugin-ring proof.
    pub fn prepare_hot_fork_template_barriers(
        &mut self,
        block_snapshot_bindings: &[QmpHotForkBlockSnapshotBinding],
    ) -> Result<QmpHotForkTemplateState, QmpError> {
        let required = QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS & !QMP_HOT_FORK_PLUGIN_RING_PROOF;
        let mut generation = 0;
        let mut missing_proofs = required;

        for poll in 0..self.job_poll_policy.max_polls {
            let state = self.prepare_hot_fork_template(block_snapshot_bindings)?;
            if generation != 0 && generation != state.generation() {
                return Err(QmpError::HotForkTemplateGenerationChanged {
                    expected: generation,
                    actual: state.generation(),
                });
            }
            generation = state.generation();
            if !state.transaction_active()
                || !matches!(
                    state.outcome(),
                    QmpHotForkTemplateOutcome::Draining | QmpHotForkTemplateOutcome::Prepared
                )
            {
                return Err(QmpError::HotForkTemplateNotRetained {
                    generation,
                    outcome: state.outcome(),
                });
            }

            missing_proofs = required & !state.acknowledged_proofs();
            if missing_proofs == 0 {
                return Ok(state);
            }
            if poll + 1 < self.job_poll_policy.max_polls {
                thread::sleep(self.job_poll_policy.poll_interval);
            }
        }

        Err(QmpError::HotForkTemplateNotQuiescent {
            generation,
            polls: self.job_poll_policy.max_polls,
            missing_proofs,
        })
    }
}
