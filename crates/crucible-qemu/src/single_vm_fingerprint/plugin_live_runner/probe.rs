//! Instruction-exact probe backend for the live Rust-plugin fingerprint runner.
//!
//! Refinement replays each fixed run by RESTART to an exact aggregate icount: a
//! fresh QEMU process is driven from cold to the requested boundary and the
//! plugin-published fingerprint sample there is folded into the cumulative
//! prefix. Snapshot restore (`loadvm`) is deliberately not used — it stays
//! policy-disabled per [`crate::single_vm_fingerprint`]'s savevm fallback
//! contract (see `savevm_policy.rs` / the phase2 `qemuSavevmFallback` gate),
//! which forbids restoring VM state into the deterministic replay path. Every
//! probe therefore reproduces state from the same immutable launch inputs.
//! Full divergence dumps use two additional fresh runs. At the requested exact
//! boundary, the plugin terminally pauses QEMU and exports complete register,
//! writable-RAM, and non-RAM VMState bytes through the patched raw-state API.

use crucible_shmem::FingerprintSample;

use crate::single_vm_fingerprint::{
    SingleVmFingerprintBisectionError, SingleVmFingerprintProbe, SingleVmFingerprintProbeRequest,
    SingleVmFingerprintProbeRunner, SingleVmFingerprintRunOrdinal, SingleVmFingerprintScenario,
    SingleVmFingerprintStateDumpProbe, initial_single_vm_rolling_fingerprint,
};

use super::raw_dump::build_state_dump_pair;
use super::{PluginFingerprintRunner, PluginFingerprintRunnerError, RunRole, SAMPLE_ICOUNTS};

impl SingleVmFingerprintProbeRunner for PluginFingerprintRunner {
    fn probe_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintProbe, SingleVmFingerprintBisectionError> {
        self.probe_count = self.probe_count.saturating_add(1);
        let scenario = request.scenario();
        let target = request.target_icount();
        let prefix = self
            .prefix_fingerprint_at(scenario, request.ordinal(), target)
            .map_err(to_bisection_error)?;
        let definition_digest = digest_array(scenario.fingerprint_definition_digest())?;
        let run_inputs_digest = scenario.run_inputs().content_digest();
        SingleVmFingerprintProbe::new(
            request.ordinal(),
            super::RUNNER_NODE,
            target,
            definition_digest,
            run_inputs_digest,
            prefix,
        )
    }

    fn dump_single_vm_fingerprint_state(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintStateDumpProbe, SingleVmFingerprintBisectionError> {
        let target = request.target_icount();
        if self
            .state_dump_cache
            .as_ref()
            .is_none_or(|cached| cached.target_icount != target)
        {
            let first = self
                .run_to_targets_with_state_dump(RunRole::Reference, target)
                .map_err(to_bisection_error)?;
            let second_role = self.role_for(SingleVmFingerprintRunOrdinal::Second);
            let second = self
                .run_to_targets_with_state_dump(second_role, target)
                .map_err(to_bisection_error)?;
            self.state_dump_cache =
                Some(build_state_dump_pair(target, first, second).map_err(to_bisection_error)?);
        }
        let cached = self.state_dump_cache.as_ref().ok_or_else(|| {
            SingleVmFingerprintBisectionError::new("terminal state-dump cache was not populated")
        })?;
        let state = match request.ordinal() {
            SingleVmFingerprintRunOrdinal::First => cached.first.clone(),
            SingleVmFingerprintRunOrdinal::Second => cached.second.clone(),
        };
        Ok(SingleVmFingerprintStateDumpProbe::new(
            request.ordinal(),
            digest_array(request.scenario().fingerprint_definition_digest())?,
            request.scenario().run_inputs().content_digest(),
            state,
        ))
    }
}

impl PluginFingerprintRunner {
    /// Restarts one fresh run and folds the cumulative prefix through `target`.
    ///
    /// The fold sequence is a deterministic function of `target`: every cadence
    /// target strictly below `target`, then `target` itself. Target zero is the
    /// paused pre-execution genesis prefix (the definition's initial rolling
    /// fingerprint), which needs no launch.
    fn prefix_fingerprint_at(
        &self,
        scenario: &SingleVmFingerprintScenario,
        ordinal: SingleVmFingerprintRunOrdinal,
        target: u64,
    ) -> Result<[u8; 32], PluginFingerprintRunnerError> {
        if target == 0 {
            let initial =
                initial_single_vm_rolling_fingerprint(scenario.fingerprint_definition_digest())
                    .map_err(PluginFingerprintRunnerError::BuildStream)?;
            return digest_array_runner(&initial);
        }
        let mut sub_targets: Vec<u64> = SAMPLE_ICOUNTS
            .into_iter()
            .filter(|cadence| *cadence < target)
            .collect();
        sub_targets.push(target);
        let samples: Vec<(u64, FingerprintSample)> =
            self.run_to_targets(self.role_for(ordinal), &sub_targets)?;
        let stream = self.stream_from_samples(&samples, target)?;
        digest_array_runner(&stream.final_fingerprint)
    }
}

/// Converts a 32-byte digest slice into a fixed array, erroring on width drift.
fn digest_array(digest: &[u8]) -> Result<[u8; 32], SingleVmFingerprintBisectionError> {
    digest.try_into().map_err(|_error| {
        SingleVmFingerprintBisectionError::new(format!(
            "definition digest width {} is not the canonical 32 bytes",
            digest.len()
        ))
    })
}

/// Converts a 32-byte digest slice into a fixed array in the runner error domain.
fn digest_array_runner(digest: &[u8]) -> Result<[u8; 32], PluginFingerprintRunnerError> {
    digest.try_into().map_err(|_error| {
        PluginFingerprintRunnerError::BuildStream(
            crate::single_vm_fingerprint::SingleVmFingerprintGateError::InvalidStream {
                reason: "prefix fingerprint width is not the canonical 32 bytes",
            },
        )
    })
}

/// Converts a runner error into the trait-level bisection error.
fn to_bisection_error(error: PluginFingerprintRunnerError) -> SingleVmFingerprintBisectionError {
    SingleVmFingerprintBisectionError::new(error.to_string())
}
