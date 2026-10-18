//! Clock-free attribution around the original guarded replay executor operations.

use super::{QemuReplayValidationExecutor, QemuVmRealizationError, ReplayPhase};

impl QemuReplayValidationExecutor {
    /// Measures an original operation while returning its result unchanged.
    ///
    /// # Errors
    ///
    /// Returns exactly the original operation's error; diagnostic failures are ignored.
    pub(super) fn measure_replay<T>(
        &mut self,
        phase: ReplayPhase,
        operation: impl FnOnce(&mut Self) -> Result<T, QemuVmRealizationError>,
    ) -> Result<T, QemuVmRealizationError> {
        let measurement = self.performance.begin(phase);
        let result = operation(self);
        if let Some(measurement) = measurement {
            self.performance
                .finish(measurement, self.next_generation, result.is_err());
            if result.is_err() {
                self.performance.report("error");
            } else if matches!(phase, ReplayPhase::Comparison) {
                self.performance.report("completed");
            }
        }
        result
    }
}
