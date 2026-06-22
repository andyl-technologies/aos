//! Run-twice gate driver for single-VM fingerprints.

use super::compare::compare_single_vm_fingerprint_streams;
use super::types::{
    SingleVmFingerprintGateError, SingleVmFingerprintGateReport, SingleVmFingerprintRunOrdinal,
    SingleVmFingerprintRunRequest, SingleVmFingerprintRunner, SingleVmFingerprintScenario,
    SingleVmFingerprintStream, validate_digest_len, validate_final_icount, validate_samples,
};

/// Runs `gate:single-vm-fingerprint` for one fixed scenario.
///
/// # Errors
///
/// Returns [`SingleVmFingerprintGateError`] when either run fails, a returned
/// stream is invalid, or the two stream comparisons find any mismatch.
pub fn run_single_vm_fingerprint_gate<Runner>(
    runner: &mut Runner,
    scenario: &SingleVmFingerprintScenario,
) -> Result<SingleVmFingerprintGateReport, SingleVmFingerprintGateError>
where
    Runner: SingleVmFingerprintRunner,
{
    let first_stream = run_one(runner, scenario, SingleVmFingerprintRunOrdinal::First)?;
    let second_stream = run_one(runner, scenario, SingleVmFingerprintRunOrdinal::Second)?;

    compare_single_vm_fingerprint_streams(
        &first_stream,
        &second_stream,
        scenario.run_horizon_icount,
    )
    .map_err(|mismatch| SingleVmFingerprintGateError::Mismatch {
        mismatch,
        first_stream: Box::new(first_stream.clone()),
        second_stream: Box::new(second_stream.clone()),
    })?;

    Ok(SingleVmFingerprintGateReport {
        scenario_id: scenario.id.clone(),
        matching_final_fingerprint: first_stream.final_fingerprint.clone(),
        sample_count: first_stream.samples.len(),
        first_stream,
        second_stream,
    })
}

fn run_one<Runner>(
    runner: &mut Runner,
    scenario: &SingleVmFingerprintScenario,
    ordinal: SingleVmFingerprintRunOrdinal,
) -> Result<SingleVmFingerprintStream, SingleVmFingerprintGateError>
where
    Runner: SingleVmFingerprintRunner,
{
    let request = SingleVmFingerprintRunRequest::new(scenario.clone(), ordinal);
    let stream = runner
        .run_single_vm_fingerprint(&request)
        .map_err(|source| SingleVmFingerprintGateError::RunFailed { ordinal, source })?;
    validate_stream_for_run(scenario, &stream, ordinal)?;
    Ok(stream)
}

fn validate_stream_for_run(
    scenario: &SingleVmFingerprintScenario,
    stream: &SingleVmFingerprintStream,
    ordinal: SingleVmFingerprintRunOrdinal,
) -> Result<(), SingleVmFingerprintGateError> {
    if stream.definition_digest != scenario.fingerprint_definition_digest {
        return Err(SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal,
            reason: "stream definition digest differs from scenario definition",
        });
    }
    validate_samples(&stream.samples, scenario.run_horizon_icount).map_err(|_| {
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal,
            reason: "stream samples are not canonical for the scenario horizon",
        }
    })?;
    validate_final_icount(stream.final_icount, scenario.run_horizon_icount).map_err(|_| {
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal,
            reason: "stream final fingerprint icount is before the scenario horizon",
        }
    })?;
    validate_digest_len("final_fingerprint", &stream.final_fingerprint).map_err(|_| {
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal,
            reason: "stream final fingerprint has invalid digest length",
        }
    })?;
    Ok(())
}
