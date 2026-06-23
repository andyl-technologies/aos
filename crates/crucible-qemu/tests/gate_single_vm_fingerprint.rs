//! Checks `gate:single-vm-fingerprint` over the QEMU host hook.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

use crucible_qemu::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintGateError, SingleVmFingerprintMismatchKind, SingleVmFingerprintRunError,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunner,
    SingleVmFingerprintSample, SingleVmFingerprintScenario, SingleVmFingerprintStream,
    SingleVmFingerprintTrigger, SingleVmHostProfile, compare_single_vm_fingerprint_streams,
    run_single_vm_fingerprint_gate,
};

#[test]
fn gate_single_vm_fingerprint_runs_fixed_scenario_twice() {
    let scenario = scenario();
    let stream = stream(&[1, 2, 3], 9);
    let mut runner = FakeRunner::new(vec![Ok(stream.clone()), Ok(stream.clone())]);

    let report = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(report) => report,
        Err(error) => panic!("identical streams should pass: {error}"),
    };

    assert_eq!(report.scenario_id, scenario.id());
    assert_eq!(report.sample_count, 3);
    assert_eq!(report.matching_final_fingerprint, digest(9));
    assert_eq!(report.first_stream, stream);
    assert_eq!(report.second_stream, stream);
    assert_eq!(
        runner
            .requests
            .iter()
            .map(SingleVmFingerprintRunRequest::ordinal)
            .collect::<Vec<_>>(),
        vec![
            SingleVmFingerprintRunOrdinal::First,
            SingleVmFingerprintRunOrdinal::Second,
        ]
    );
    assert!(
        runner
            .requests
            .iter()
            .all(|request| request.scenario() == &scenario)
    );
}

#[test]
fn gate_single_vm_fingerprint_reports_first_sample_window() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mut runner = FakeRunner::with_bisections(
        vec![Ok(first.clone()), Ok(second.clone())],
        vec![Ok(bisection_report(1, Some(4096), 8192, 6144, 6145))],
    );

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("different streams should fail"),
        Err(error) => error,
    };

    let SingleVmFingerprintGateError::Mismatch {
        mismatch,
        first_stream,
        second_stream,
        bisection,
    } = error
    else {
        panic!("sample divergence should report a mismatch");
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Sample { .. }
    ));
    assert_eq!(mismatch.sample_index, 1);
    assert_eq!(mismatch.previous_matching_icount, Some(4096));
    assert_eq!(mismatch.first_different_icount, Some(8192));
    assert_eq!(*first_stream, first);
    assert_eq!(*second_stream, second);
    assert_eq!(bisection.sample_index(), 1);
    assert_eq!(bisection.first_different_sample_icount(), 8192);
    assert_eq!(bisection.last_matching_icount(), 6144);
    assert_eq!(bisection.first_different_icount(), 6145);
    assert_eq!(
        bisection.state_dump_artifact(),
        "artifact://single-vm-bisect"
    );
    assert_eq!(runner.bisection_requests.len(), 1);
    assert_eq!(
        runner.bisection_requests[0].scenario().id(),
        "contract-a-single-vm"
    );
    assert_eq!(runner.bisection_requests[0].mismatch().sample_index, 1);
    assert_eq!(runner.bisection_requests[0].first_stream(), &first);
    assert_eq!(runner.bisection_requests[0].second_stream(), &second);
}

#[test]
fn gate_single_vm_fingerprint_reports_final_mismatch_at_horizon() {
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 2, 3], 8);
    let mismatch = match compare_single_vm_fingerprint_streams(&first, &second, 12_288) {
        Ok(()) => panic!("different final fingerprints should fail"),
        Err(mismatch) => mismatch,
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Final { .. }
    ));
    assert_eq!(mismatch.sample_index, 3);
    assert_eq!(mismatch.previous_matching_icount, Some(12_288));
    assert_eq!(mismatch.first_different_icount, Some(12_288));
}

#[test]
fn gate_single_vm_fingerprint_rejects_definition_drift() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let mut second = first.clone();
    second.definition_digest = digest(5);
    let mut runner = FakeRunner::new(vec![Ok(first), Ok(second)]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("changed definition digest should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal: SingleVmFingerprintRunOrdinal::Second,
            ..
        }
    ));
}

#[test]
fn gate_single_vm_fingerprint_compares_definition_before_samples() {
    let first = stream(&[1, 2, 3], 9);
    let mut second = stream(&[4, 5, 6], 8);
    second.definition_digest = digest(5);
    let mismatch = match compare_single_vm_fingerprint_streams(&first, &second, 12_288) {
        Ok(()) => panic!("definition drift should fail"),
        Err(mismatch) => mismatch,
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Definition { .. }
    ));
    assert_eq!(mismatch.sample_index, 0);
    assert_eq!(mismatch.previous_matching_icount, None);
    assert_eq!(mismatch.first_different_icount, None);
}

#[test]
fn gate_single_vm_fingerprint_rejects_invalid_streams() {
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), Vec::new(), 12_288, digest(9), 12_288),
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include at least one sample",
        })
    );
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(0, 4096, 1)], 4096, vec![9], 4096),
        Err(SingleVmFingerprintGateError::InvalidDigestLength {
            field: "final_fingerprint",
            len: 1,
        })
    );
    assert!(matches!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(1, 4096, 1)], 4096, digest(9), 4096,),
        Err(SingleVmFingerprintGateError::InvalidStream { .. })
    ));
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(0, 4096, 1)], 8192, digest(9), 8192),
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include a sample at the scenario horizon",
        })
    );
    assert_eq!(
        SingleVmFingerprintStream::new(digest(1), vec![sample(0, 4096, 1)], 2048, digest(9), 4096),
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "final fingerprint icount must be at or beyond the scenario horizon",
        })
    );
}

#[test]
fn gate_single_vm_fingerprint_rejects_truncated_backend_streams() {
    let scenario = scenario();
    let truncated = SingleVmFingerprintStream {
        definition_digest: digest(1),
        samples: vec![sample(0, 4096, 1), sample(1, 8192, 2)],
        final_icount: 12_288,
        final_fingerprint: digest(9),
    };
    let mut runner = FakeRunner::new(vec![Ok(truncated.clone()), Ok(truncated)]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("streams missing the horizon sample should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::InvalidStreamForRun {
            ordinal: SingleVmFingerprintRunOrdinal::First,
            ..
        }
    ));
    assert_eq!(runner.requests.len(), 1);
}

#[test]
fn gate_single_vm_fingerprint_reports_final_icount_mismatch() {
    let first = stream(&[1, 2, 3], 9);
    let mut second = stream(&[1, 2, 3], 9);
    second.final_icount = 16_384;

    let mismatch = match compare_single_vm_fingerprint_streams(&first, &second, 12_288) {
        Ok(()) => panic!("different final icounts should fail"),
        Err(mismatch) => mismatch,
    };

    assert!(matches!(
        mismatch.kind,
        SingleVmFingerprintMismatchKind::Final { .. }
    ));
    assert_eq!(mismatch.sample_index, 3);
    assert_eq!(mismatch.previous_matching_icount, Some(12_288));
    assert_eq!(mismatch.first_different_icount, Some(12_288));
}

#[test]
fn gate_single_vm_fingerprint_surfaces_backend_failure_without_extra_runs() {
    let scenario = scenario();
    let mut runner = FakeRunner::new(vec![
        Ok(stream(&[1, 2, 3], 9)),
        Err(SingleVmFingerprintRunError::new("planned backend failure")),
        Ok(stream(&[9, 9, 9], 9)),
    ]);

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("backend failure should stop the gate"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        SingleVmFingerprintGateError::RunFailed {
            ordinal: SingleVmFingerprintRunOrdinal::Second,
            ..
        }
    ));
    assert_eq!(runner.requests.len(), 2);
    assert!(runner.bisection_requests.is_empty());
}

#[test]
fn gate_single_vm_fingerprint_requires_bisection_on_mismatch() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mut runner = FakeRunner::with_bisections(
        vec![Ok(first.clone()), Ok(second.clone())],
        vec![Err(SingleVmFingerprintBisectionError::new(
            "planned bisection failure",
        ))],
    );

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("missing bisection should fail the gate"),
        Err(error) => error,
    };

    let SingleVmFingerprintGateError::BisectionFailed {
        mismatch,
        first_stream,
        second_stream,
        source,
    } = error
    else {
        panic!("bisection failure should be reported distinctly");
    };

    assert_eq!(mismatch.sample_index, 1);
    assert_eq!(source.message(), "planned bisection failure");
    assert_eq!(*first_stream, first);
    assert_eq!(*second_stream, second);
    assert_eq!(runner.bisection_requests.len(), 1);
}

#[test]
fn gate_single_vm_fingerprint_rejects_misaligned_bisection_report() {
    let scenario = scenario();
    let first = stream(&[1, 2, 3], 9);
    let second = stream(&[1, 7, 3], 9);
    let mut runner = FakeRunner::with_bisections(
        vec![Ok(first), Ok(second)],
        vec![Ok(bisection_report(2, Some(4096), 8192, 6144, 6145))],
    );

    let error = match run_single_vm_fingerprint_gate(&mut runner, &scenario) {
        Ok(_) => panic!("misaligned bisection report should fail the gate"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        SingleVmFingerprintGateError::InvalidBisectionReport {
            reason: "bisection sample index must match the first stream mismatch",
        }
    );
}

#[derive(Debug)]
struct FakeRunner {
    streams: VecDeque<Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>>,
    bisections:
        VecDeque<Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError>>,
    requests: Vec<SingleVmFingerprintRunRequest>,
    bisection_requests: Vec<SingleVmFingerprintBisectionRequest>,
}

impl FakeRunner {
    fn new(streams: Vec<Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>>) -> Self {
        Self::with_bisections(streams, Vec::new())
    }

    fn with_bisections(
        streams: Vec<Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>>,
        bisections: Vec<
            Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError>,
        >,
    ) -> Self {
        Self {
            streams: streams.into(),
            bisections: bisections.into(),
            requests: Vec::new(),
            bisection_requests: Vec::new(),
        }
    }
}

impl SingleVmFingerprintRunner for FakeRunner {
    fn run_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, SingleVmFingerprintRunError> {
        self.requests.push(request.clone());
        match self.streams.pop_front() {
            Some(result) => result,
            None => Err(SingleVmFingerprintRunError::new("missing planned stream")),
        }
    }

    fn bisect_single_vm_fingerprint_mismatch(
        &mut self,
        request: &SingleVmFingerprintBisectionRequest,
    ) -> Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError> {
        self.bisection_requests.push(request.clone());
        match self.bisections.pop_front() {
            Some(result) => result,
            None => Err(SingleVmFingerprintBisectionError::new(
                "missing planned bisection",
            )),
        }
    }
}

fn scenario() -> SingleVmFingerprintScenario {
    match SingleVmFingerprintScenario::new(
        "contract-a-single-vm",
        digest(1),
        12_288,
        SingleVmHostProfile::phase1_adversarial(),
    ) {
        Ok(scenario) => scenario,
        Err(error) => panic!("test scenario should be valid: {error}"),
    }
}

fn stream(sample_bytes: &[u8], final_byte: u8) -> SingleVmFingerprintStream {
    let samples = sample_bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| sample(index as u64, 4096 * (index as u64 + 1), *byte))
        .collect();
    match SingleVmFingerprintStream::new(digest(1), samples, 12_288, digest(final_byte), 12_288) {
        Ok(stream) => stream,
        Err(error) => panic!("test stream should be valid: {error}"),
    }
}

fn sample(seq: u64, icount: u64, rolling_byte: u8) -> SingleVmFingerprintSample {
    SingleVmFingerprintSample {
        seq,
        node: "node-a".to_owned(),
        icount,
        trigger: SingleVmFingerprintTrigger::Periodic,
        rolling_fingerprint: digest(rolling_byte),
    }
}

fn bisection_report(
    sample_index: usize,
    previous_matching_icount: Option<u64>,
    first_different_sample_icount: u64,
    last_matching_icount: u64,
    first_different_icount: u64,
) -> SingleVmFingerprintBisectionReport {
    match SingleVmFingerprintBisectionReport::new(
        sample_index,
        previous_matching_icount,
        first_different_sample_icount,
        last_matching_icount,
        first_different_icount,
        "artifact://single-vm-bisect",
    ) {
        Ok(report) => report,
        Err(error) => panic!("test bisection report should be valid: {error}"),
    }
}

fn digest(byte: u8) -> Vec<u8> {
    vec![byte; SINGLE_VM_FINGERPRINT_DIGEST_BYTES]
}
