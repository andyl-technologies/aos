//! Branch-reseed handling for device scheduling sub-nodes.

use super::DeviceSchedulingSubNode;
use crate::Seed;

impl DeviceSchedulingSubNode {
    /// Re-seeds decisions for requests COMPUTEd after a branch boundary.
    ///
    /// Decisions already resolved into the fork prefix remain frozen exactly as
    /// recorded. Newly collected completions start at cursor zero under `seed`.
    pub fn reseed_future_decisions(&mut self, seed: Seed) {
        self.frozen_modeled.extend(
            self.resolved
                .iter()
                .map(|completion| completion.modeled_key),
        );
        self.frozen_rng_position = Some(0);
        self.seed = seed;
        self.rng_position = 0;
    }
}
