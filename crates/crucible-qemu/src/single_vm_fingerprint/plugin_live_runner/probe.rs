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
//!
//! Because both fixed runs are the same deterministic guest, every probe pair
//! matches; the runner asserts this launch-identity equality by echoing the
//! scenario's definition and run-input digests into each probe, so a probe that
//! silently drifted to a different launch could never validate. The coarse gate
//! proves equality, so the divergence state dump is unreached there; capturing
//! full both-side architectural state at a real divergence depends on the live
//! whitebox register/memory value capture that lands with M4/M5, so
//! [`PluginFingerprintRunner::dump_single_vm_fingerprint_state`] fails loudly
//! rather than fabricating a dump.

use crucible_shmem::FingerprintSample;

use crate::single_vm_fingerprint::{
    SingleVmFingerprintBisectionError, SingleVmFingerprintProbe, SingleVmFingerprintProbeRequest,
    SingleVmFingerprintProbeRunner, SingleVmFingerprintScenario, SingleVmFingerprintStateDumpProbe,
    initial_single_vm_rolling_fingerprint,
};

use super::{PluginFingerprintRunner, PluginFingerprintRunnerError, RunRole, TARGET_ICOUNTS};

impl SingleVmFingerprintProbeRunner for PluginFingerprintRunner {
    fn probe_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintProbe, SingleVmFingerprintBisectionError> {
        self.probe_count = self.probe_count.saturating_add(1);
        let scenario = request.scenario();
        let target = request.target_icount();
        let prefix = self
            .prefix_fingerprint_at(scenario, target)
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
        Err(SingleVmFingerprintBisectionError::new(format!(
            "live both-side state dump at icount {} requires full whitebox register/memory value \
             capture (M4/M5); the deterministic run-twice gate proves equality, so this divergence \
             path is unreached",
            request.target_icount()
        )))
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
        target: u64,
    ) -> Result<[u8; 32], PluginFingerprintRunnerError> {
        if target == 0 {
            let initial =
                initial_single_vm_rolling_fingerprint(scenario.fingerprint_definition_digest())
                    .map_err(PluginFingerprintRunnerError::BuildStream)?;
            return digest_array_runner(&initial);
        }
        let mut sub_targets: Vec<u64> = TARGET_ICOUNTS
            .into_iter()
            .filter(|cadence| *cadence < target)
            .collect();
        sub_targets.push(target);
        let samples: Vec<(u64, FingerprintSample)> =
            self.run_to_targets(RunRole::Probe, &sub_targets)?;
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
