//! Run-twice gate driver for single-VM fingerprints.

use super::compare::compare_single_vm_fingerprint_streams;
use super::types::{
    SingleVmFingerprintBisectionRequest, SingleVmFingerprintGateError,
    SingleVmFingerprintGateReport, SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest,
    SingleVmFingerprintRunner, SingleVmFingerprintScenario, SingleVmFingerprintStream,
    validate_digest_len, validate_final_icount, validate_samples,
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

    match compare_single_vm_fingerprint_streams(
        &first_stream,
        &second_stream,
        scenario.run_horizon_icount,
    ) {
        Ok(()) => {}
        Err(mismatch) => {
            let request = SingleVmFingerprintBisectionRequest::new(
                scenario.clone(),
                mismatch.clone(),
                first_stream.clone(),
                second_stream.clone(),
            );
            let bisection = runner
                .bisect_single_vm_fingerprint_mismatch(&request)
                .map_err(|source| SingleVmFingerprintGateError::BisectionFailed {
                    mismatch: Box::new(mismatch.clone()),
                    first_stream: Box::new(first_stream.clone()),
                    second_stream: Box::new(second_stream.clone()),
                    source,
                })?;
            validate_bisection_report_for_mismatch(
                &bisection,
                &mismatch,
                &first_stream,
                &second_stream,
            )?;
            return Err(SingleVmFingerprintGateError::Mismatch {
                mismatch: Box::new(mismatch),
                first_stream: Box::new(first_stream),
                second_stream: Box::new(second_stream),
                bisection: Box::new(bisection),
            });
        }
    }

    Ok(SingleVmFingerprintGateReport {
        scenario_id: scenario.id().to_owned(),
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

fn validate_bisection_report_for_mismatch(
    bisection: &super::types::SingleVmFingerprintBisectionReport,
    mismatch: &super::compare::SingleVmFingerprintMismatch,
    first_stream: &SingleVmFingerprintStream,
    second_stream: &SingleVmFingerprintStream,
) -> Result<(), SingleVmFingerprintGateError> {
    if bisection.sample_index() != mismatch.sample_index {
        return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
            reason: "bisection sample index must match the first stream mismatch",
        });
    }
    if bisection.previous_matching_icount() != mismatch.previous_matching_icount {
        return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
            reason: "bisection previous matching icount must match the stream mismatch",
        });
    }
    if let Some(first_different_icount) = mismatch.first_different_icount
        && bisection.first_different_sample_icount() != first_different_icount
    {
        return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
            reason: "bisection sample icount must match the first differing stream icount",
        });
    }
    let first_node = first_stream
        .samples
        .get(mismatch.sample_index)
        .or_else(|| first_stream.samples.last())
        .map(|sample| sample.node.as_str());
    let second_node = second_stream
        .samples
        .get(mismatch.sample_index)
        .or_else(|| second_stream.samples.last())
        .map(|sample| sample.node.as_str());
    if first_node != second_node || first_node != Some(bisection.responsible_node()) {
        return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
            reason: "bisection responsible node must match both differing samples",
        });
    }

    Ok(())
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
    validate_samples(
        &stream.definition_digest,
        &stream.samples,
        scenario.run_horizon_icount,
        Some(scenario.nvcpu_contract()),
    )
    .map_err(|_| SingleVmFingerprintGateError::InvalidStreamForRun {
        ordinal,
        reason: "stream samples are not canonical for the scenario horizon",
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
