//! Deliberately limited native peer for independent execution fault injection.
//!
//! This executable supplies explicit fixture placements without performing any
//! model validation or verification. The real trusted runner must reject false
//! feasibility claims and contain peers that crash, stall, or corrupt frames.

use std::{
    error::Error,
    io::{self, Write},
    time::Duration,
};

use dispatch_model::{Assignment, Binding, Problem};
use dispatch_protocol::{
    framing,
    wire::{self, worker_envelope::Body},
};

fn main() -> Result<(), Box<dyn Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "valid".into());
    if mode == "leaf" {
        loop {
            std::thread::sleep(Duration::from_secs(30));
        }
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut maximum = 65_536;

    loop {
        let request = match framing::read_frame(&mut input, maximum) {
            Ok(request) => request,
            Err(_) => return Ok(()),
        };
        let body = match request.body.as_ref() {
            Some(Body::Hello(hello)) => {
                if let Some(path) = std::env::args().nth(2) {
                    let mut trace = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?;
                    writeln!(trace, "{}", std::process::id())?;
                }
                let limits = hello.limits.clone().unwrap_or_default();
                maximum = limits.max_frame_bytes.max(65_536);
                Body::Capabilities(wire::Capabilities {
                    protocol_version: request.protocol_version,
                    model_versions: hello.model_versions.clone(),
                    limits: Some(limits),
                    backend_name: "conformance-fixture".into(),
                    backend_build_id: "conformance-fixture-v1".into(),
                    capabilities: vec![],
                    constraint_kinds: vec![
                        "capacity".into(),
                        "admission".into(),
                        "eligibility".into(),
                        "fixed_placement".into(),
                        "atomic_admission".into(),
                        "co_location".into(),
                        "spread".into(),
                        "movement_budget".into(),
                    ],
                    objective_kinds: vec![
                        "admitted_count".into(),
                        "admitted_priority".into(),
                        "assignment_cost".into(),
                        "movement_cost".into(),
                        "used_targets".into(),
                        "repair_debt".into(),
                        "maximum_utilization".into(),
                        "utilization_range".into(),
                        "total_absolute_deviation".into(),
                    ],
                    maximum_exact_integer: 1_u64 << 53,
                    graceful_cancel: false,
                    candidate_stream: true,
                    incremental_updates: false,
                    prepared_native_state: false,
                    search_modes: vec![wire::SearchMode::LocalSearch as i32],
                    seed_supported: false,
                    stage_timings: false,
                })
            }
            Some(Body::Solve(solve)) => {
                if mode == "budget"
                    && solve
                        .options
                        .as_ref()
                        .is_none_or(|options| options.wall_time_millis != 3000)
                {
                    let response = wire::WorkerEnvelope {
                        body: Some(Body::Error(wire::ProtocolError {
                            code: wire::ErrorCode::CommitmentMismatch as i32,
                            detail: "the committed request budget was overwritten by transfer time"
                                .into(),
                            unsupported_features: Vec::new(),
                        })),
                        ..request.clone()
                    };
                    framing::write_frame(&mut output, &response, maximum)?;
                    continue;
                }
                if let Some(path) = std::env::args().nth(3) {
                    let mut trace = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?;
                    writeln!(trace, "{}", request.request_id)?;
                }
                if mode == "forged_validation_binding" {
                    // The envelope correlates correctly. Native code still has
                    // no authority to originate the runner's validation facts.
                    let forged = wire::WorkerEnvelope {
                        body: Some(Body::Progress(wire::Progress {
                            stage: wire::ExecutionStage::Materializing as i32,
                            validation_binding: Some(wire::ValidationBinding {
                                model_digest: echoed_digest(&solve.model_digest, true),
                                request_digest: echoed_digest(&solve.request_digest, true),
                                observation_basis_json: br#"{"revision":"forged-native"}"#.to_vec(),
                            }),
                            ..Default::default()
                        })),
                        ..request.clone()
                    };
                    framing::write_frame(&mut output, &forged, maximum)?;
                }
                match mode.as_str() {
                    "tree_stall" => {
                        // The fixture deliberately refuses to reap or terminate
                        // this descendant; the trusted runner owns containment.
                        #[allow(clippy::zombie_processes)]
                        let child = std::process::Command::new(std::env::current_exe()?)
                            .arg("leaf")
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .spawn()?;
                        if let Some(path) = std::env::args().nth(4) {
                            std::fs::write(path, child.id().to_string())?;
                        }
                        loop {
                            std::thread::sleep(Duration::from_secs(30));
                        }
                    }
                    "stall" => loop {
                        std::thread::sleep(Duration::from_secs(30));
                    },
                    "crash" => std::process::exit(77),
                    "oversized" => {
                        output.write_all(&u32::MAX.to_be_bytes())?;
                        output.flush()?;
                        continue;
                    }
                    "truncated" => {
                        output.write_all(&[0, 0, 0, 100, 0])?;
                        output.flush()?;
                        return Ok(());
                    }
                    _ => {}
                }
                let problem: Problem = serde_json::from_slice(&solve.problem_json)?;
                let destination = problem.targets.keys().next().cloned();
                let assignment = Assignment {
                    bindings: problem
                        .items
                        .keys()
                        .map(|item| {
                            let binding = if mode == "invalid" {
                                Binding::Deferred
                            } else {
                                destination
                                    .clone()
                                    .map(|target| Binding::Target { target })
                                    .unwrap_or(Binding::Deferred)
                            };
                            (item.clone(), binding)
                        })
                        .collect(),
                };
                Body::Finished(wire::Finished {
                    termination: wire::Termination::Completed as i32,
                    assignment_json: serde_json::to_vec(&assignment)?,
                    model_digest: echoed_digest(&solve.model_digest, mode == "wrong_model_digest"),
                    request_digest: echoed_digest(
                        &solve.request_digest,
                        mode == "wrong_request_digest",
                    ),
                    backend_build_id: "conformance-fixture-v1".into(),
                    effective_options: solve.options.clone(),
                    verification_class: wire::VerificationClass::FullyFeasible as i32,
                    detail: "fixture claims feasibility; the runner must independently check it"
                        .into(),
                    ..Default::default()
                })
            }
            Some(Body::Prepare(prepare)) => Body::Prepared(wire::Prepared {
                handle: "fixture-input".into(),
                model_digest: prepare.model_digest.clone(),
            }),
            Some(Body::Release(release)) => Body::Released(wire::Released {
                handle: release.handle.clone(),
            }),
            Some(Body::Cancel(_)) => continue,
            _ => return Ok(()),
        };
        let response = wire::WorkerEnvelope {
            protocol_version: request.protocol_version,
            session_generation: request.session_generation,
            worker_generation: request.worker_generation
                + u64::from(mode == "wrong_generation" && matches!(body, Body::Finished(_))),
            request_id: request.request_id,
            body: Some(body),
        };
        framing::write_frame(&mut output, &response, maximum)?;
    }
}

// Keep valid envelope correlation and a valid candidate while corrupting only
// the semantic echo. The runner must reject it before relabeling provenance.
fn echoed_digest(committed: &[u8], corrupt: bool) -> Vec<u8> {
    let mut digest = committed.to_vec();
    if corrupt && let Some(first) = digest.first_mut() {
        *first ^= 0xff;
    }
    digest
}
