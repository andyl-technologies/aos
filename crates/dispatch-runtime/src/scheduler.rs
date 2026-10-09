//! Deadline-aware bounded job dispatch and single terminal-state publication.

use std::sync::Arc;

use dispatch_protocol::wire;
use tokio::{sync::watch, time::Instant};

use crate::{
    CandidateClass, EffectiveOptions, EvidenceKind, ExecutionProfile, RejectionReason,
    RuntimeError, SearchEvidence, SearchMode, SeedPolicy, SolveOptions, SolveResult, StageTiming,
    Termination, UnavailabilityReason,
    lease::WorkerLease,
    session::{Inner, Input, JobEvent, JobState},
};

pub(crate) async fn execute(
    inner: Arc<Inner>,
    job: Arc<JobState>,
    input: Arc<Input>,
    hint: Option<Arc<Input>>,
    options: SolveOptions,
    deadline: Instant,
) {
    let mut cancel = job.cancel.subscribe();
    let mut worker: Option<WorkerLease> = None;
    let mut pending = true;
    let mut reusable = false;
    let request = ExecutionRequest {
        input: &input,
        hint: hint.as_deref(),
        options: &options,
        deadline,
    };
    let mut result = tokio::select! {
        biased;
        _ = cancellation(&mut cancel) => empty_result(&inner, &job, Termination::Cancelled, "cancelled before execution"),
        _ = tokio::time::sleep_until(deadline) => empty_result(&inner, &job, Termination::LimitReached, "submission deadline expired"),
        outcome = run(&inner, &job, &request, &mut worker, &mut pending) => {
            match outcome {
                Ok(finished) => {
                    reusable = true;
                    match decode_result(&inner, &job, finished) {
                        Ok(result) => result,
                        Err(error) => { reusable = false; empty_result(&inner, &job, Termination::ExecutionFailed, &error.to_string()) }
                    }
                }
                Err(RuntimeError::Unsupported(detail)) => {
                    let mut result = empty_result(&inner, &job, Termination::Rejected, &detail);
                    result.rejection = Some(RejectionReason::UnsupportedModel);
                    result
                }
                Err(error) => empty_result(&inner, &job, Termination::ExecutionFailed, &error.to_string()),
            }
        }
    };
    result.requested_options = Some(EffectiveOptions {
        mode: options.mode,
        wall_time_millis: u64::try_from(options.deadline.as_millis()).unwrap_or(u64::MAX),
        threads: options.threads,
        seed: options.seed,
        memory_bytes: 0,
        cpu_time_millis: 0,
        maximum_iterations: 0,
    });
    if let Some(capabilities) = inner.negotiated_capabilities.get().or_else(|| {
        worker
            .as_ref()
            .and_then(|lease| lease.worker.as_ref())
            .map(|worker| &worker.capabilities)
    }) {
        if result.backend_build_id.is_none() {
            result.backend_build_id = Some(capabilities.backend_build_id.clone());
        }
        result.seed_policy = Some(if !capabilities.seed_supported {
            SeedPolicy::Unsupported
        } else if options.seed.is_some() {
            SeedPolicy::Explicit
        } else {
            SeedPolicy::BackendSelectedUnreported
        });
    }
    if let Some(worker) = worker.as_ref().and_then(|lease| lease.worker.as_ref()) {
        result.worker_generation = Some(worker.generation);
        if result.backend_build_id.is_none() {
            result.backend_build_id = Some(worker.capabilities.backend_build_id.clone());
        }
        if result.termination == Termination::ExecutionFailed
            && let Ok(report) =
                tokio::time::timeout_at(deadline, worker.connection.control.failure_report()).await
        {
            result.failure_report = report;
        }
    }
    if let Some(binding) = input.binding.get() {
        if result.model_digest.is_none() {
            result.model_digest = Some(binding.digest.clone());
        }
        if result.observation_basis.is_none() {
            result.observation_basis = Some(binding.basis.clone());
        }
    }
    result.provenance_unavailable = unavailable_fields(&result);
    // The supervising task is the only terminal publisher. Intentional pipe
    // closure after this decision cannot rewrite cancellation as a crash.
    job.events
        .send_replace(JobEvent::Terminal(Arc::new(result)));
    let expires_at = Instant::now()
        .checked_add(inner.limits.result_retention)
        .unwrap_or_else(Instant::now);

    if let Some(mut worker) = worker {
        let can_reuse = reusable
            && inner.profile == ExecutionProfile::Warm
            && inner.lock().is_ok_and(|state| !state.closed);
        if can_reuse {
            worker.reuse();
        } else {
            worker.retire().await;
        }
    }
    drop(input);
    drop(hint);
    if let Ok(mut state) = inner.lock() {
        if pending {
            state.pending = state.pending.saturating_sub(1);
        }
        state.active_jobs = state.active_jobs.saturating_sub(1);
        state.completed_jobs = state.completed_jobs.saturating_add(1);
    }
    inner.changed.notify_waiters();
    tokio::time::sleep_until(expires_at).await;
    job.events.send_replace(JobEvent::Expired);
    if let Ok(mut state) = inner.lock() {
        state.retained = state.retained.saturating_sub(1);
        state.jobs.remove(&job.id);
    }
}

struct ExecutionRequest<'a> {
    input: &'a Arc<Input>,
    hint: Option<&'a Input>,
    options: &'a SolveOptions,
    deadline: Instant,
}

async fn run(
    inner: &Arc<Inner>,
    job: &Arc<JobState>,
    request: &ExecutionRequest<'_>,
    worker: &mut Option<WorkerLease>,
    pending: &mut bool,
) -> Result<wire::Finished, RuntimeError> {
    *worker = Some(
        inner
            .acquire_worker(|| {
                let mut state = inner.lock()?;
                state.pending = state.pending.saturating_sub(1);
                *pending = false;
                job.events.send_replace(JobEvent::Running);
                Ok(())
            })
            .await?,
    );
    let worker = worker
        .as_mut()
        .and_then(|lease| lease.worker.as_mut())
        .ok_or_else(|| {
            RuntimeError::Unsupported("worker startup yielded no execution slot".into())
        })?;
    worker.connection.control.begin_job().await?;
    let hint_json = request
        .hint
        .map(|hint| hint.bytes.clone())
        .unwrap_or_default();
    let mode = match request.options.mode {
        SearchMode::LocalSearch => wire::SearchMode::LocalSearch,
        SearchMode::Mip => wire::SearchMode::Mip,
    };
    let native_options = wire::SolveOptions {
        mode: mode as i32,
        threads: request.options.threads,
        seed: request.options.seed,
        wall_time_millis: u64::try_from(request.options.deadline.as_millis()).unwrap_or(u64::MAX),
        ..Default::default()
    };
    worker
        .solve(
            inner.generation,
            request.input.bytes.clone(),
            hint_json,
            native_options,
            request.deadline.saturating_duration_since(Instant::now()),
        )
        .await
}

pub(crate) async fn cancellation(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

fn empty_result(
    inner: &Inner,
    job: &JobState,
    termination: Termination,
    detail: &str,
) -> SolveResult {
    SolveResult {
        job_id: job.id,
        session_generation: inner.generation,
        termination,
        rejection: None,
        worker_generation: None,
        candidate: CandidateClass::Absent,
        assignment: None,
        evaluation: None,
        evaluator_version: None,
        model_digest: None,
        request_digest: None,
        backend_build_id: None,
        observation_basis: None,
        requested_options: None,
        seed_policy: None,
        effective_options: None,
        search_evidence: SearchEvidence::default(),
        timings: Vec::new(),
        diagnostics_truncated: detail.chars().count() > 4096,
        provenance_unavailable: Default::default(),
        failure_report: None,
        detail: detail.chars().take(4096).collect(),
        grant: inner.grant.clone(),
    }
}

fn decode_result(
    inner: &Inner,
    job: &JobState,
    finished: wire::Finished,
) -> Result<SolveResult, RuntimeError> {
    let termination = match wire::Termination::try_from(finished.termination) {
        Ok(wire::Termination::Completed) => Termination::Completed,
        Ok(wire::Termination::LimitReached) => Termination::LimitReached,
        Ok(wire::Termination::Cancelled) => Termination::Cancelled,
        Ok(wire::Termination::Rejected) => Termination::Rejected,
        Ok(wire::Termination::ExecutionFailed) => Termination::ExecutionFailed,
        _ => {
            return Err(RuntimeError::Protocol(
                "unknown termination classification".into(),
            ));
        }
    };
    let candidate = match wire::VerificationClass::try_from(finished.verification_class) {
        Ok(wire::VerificationClass::Absent) => CandidateClass::Absent,
        Ok(wire::VerificationClass::Rejected) => CandidateClass::Rejected,
        Ok(wire::VerificationClass::FullyFeasible) => CandidateClass::FullyFeasible,
        Ok(wire::VerificationClass::RepairProposal) => CandidateClass::RepairProposal,
        _ => {
            return Err(RuntimeError::Protocol(
                "runner omitted candidate classification".into(),
            ));
        }
    };
    let assignment = if finished.assignment_json.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&finished.assignment_json)?)
    };
    let evaluation = if finished.evaluation_json.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&finished.evaluation_json)?)
    };
    if matches!(
        candidate,
        CandidateClass::FullyFeasible | CandidateClass::RepairProposal
    ) && (assignment.is_none()
        || evaluation.is_none()
        || finished.model_digest.len() != 32
        || finished.request_digest.len() != 32)
    {
        return Err(RuntimeError::Protocol(
            "verified runner result is missing its binding or evaluation".into(),
        ));
    }
    Ok(SolveResult {
        job_id: job.id,
        session_generation: inner.generation,
        termination,
        worker_generation: None,
        rejection: if termination == Termination::Rejected {
            Some(
                match finished
                    .error_code
                    .and_then(|code| wire::ErrorCode::try_from(code).ok())
                {
                    Some(wire::ErrorCode::InvalidMessage | wire::ErrorCode::CommitmentMismatch) => {
                        RejectionReason::InvalidInput
                    }
                    _ => RejectionReason::UnsupportedModel,
                },
            )
        } else {
            None
        },
        candidate,
        assignment,
        evaluation,
        evaluator_version: (!finished.evaluator_version.is_empty())
            .then_some(finished.evaluator_version),
        model_digest: (!finished.model_digest.is_empty()).then_some(finished.model_digest),
        request_digest: (!finished.request_digest.is_empty()).then_some(finished.request_digest),
        backend_build_id: (!finished.backend_build_id.is_empty())
            .then_some(finished.backend_build_id),
        observation_basis: if finished.observation_basis_json.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&finished.observation_basis_json)?)
        },
        requested_options: None,
        seed_policy: None,
        effective_options: finished
            .effective_options
            .map(effective_options)
            .transpose()?,
        search_evidence: finished
            .evidence
            .map(search_evidence)
            .transpose()?
            .unwrap_or_default(),
        timings: finished
            .timings
            .into_iter()
            .map(|timing| StageTiming {
                stage: match wire::ExecutionStage::try_from(timing.stage) {
                    Ok(wire::ExecutionStage::Materializing) => "materializing",
                    Ok(wire::ExecutionStage::Searching) => "searching",
                    Ok(wire::ExecutionStage::Verifying) => "verifying",
                    _ => "unavailable",
                }
                .into(),
                wall_time_micros: timing.wall_time_micros,
                cpu_time_micros: timing.cpu_time_micros,
            })
            .collect(),
        diagnostics_truncated: finished.diagnostics_truncated
            || finished.detail.chars().count() > 4096,
        provenance_unavailable: Default::default(),
        failure_report: None,
        detail: finished.detail.chars().take(4096).collect(),
        grant: inner.grant.clone(),
    })
}

fn effective_options(options: wire::SolveOptions) -> Result<EffectiveOptions, RuntimeError> {
    let mode = match wire::SearchMode::try_from(options.mode) {
        Ok(wire::SearchMode::LocalSearch) => SearchMode::LocalSearch,
        Ok(wire::SearchMode::Mip) => SearchMode::Mip,
        _ => {
            return Err(RuntimeError::Protocol(
                "invalid effective search mode".into(),
            ));
        }
    };
    Ok(EffectiveOptions {
        mode,
        wall_time_millis: options.wall_time_millis,
        threads: options.threads,
        seed: options.seed,
        memory_bytes: options.memory_bytes,
        cpu_time_millis: options.cpu_time_millis,
        maximum_iterations: options.maximum_iterations,
    })
}

fn search_evidence(evidence: wire::SearchEvidence) -> Result<SearchEvidence, RuntimeError> {
    let kind = match wire::EvidenceKind::try_from(evidence.kind) {
        Ok(wire::EvidenceKind::None) => EvidenceKind::None,
        Ok(wire::EvidenceKind::LocalSearchExhausted) => EvidenceKind::LocalSearchExhausted,
        Ok(wire::EvidenceKind::BackendReportedBound) => EvidenceKind::BackendReportedBound,
        Ok(wire::EvidenceKind::BackendReportedInfeasible) => {
            EvidenceKind::BackendReportedInfeasible
        }
        Ok(wire::EvidenceKind::BackendReportedOptimal) => EvidenceKind::BackendReportedOptimal,
        _ => {
            return Err(RuntimeError::Protocol(
                "unknown search evidence classification".into(),
            ));
        }
    };
    Ok(SearchEvidence {
        kind,
        objective_tier: evidence.objective_tier,
        bound: if evidence.bound_json.is_empty() {
            None
        } else {
            Some(dispatch_protocol::json::from_slice(
                &evidence.bound_json,
                dispatch_protocol::json::JsonLimits::default(),
            )?)
        },
        restriction: evidence.restriction,
        tolerance: evidence.tolerance,
    })
}

fn unavailable_fields(
    result: &SolveResult,
) -> std::collections::BTreeMap<String, UnavailabilityReason> {
    let mut unavailable = std::collections::BTreeMap::new();
    for (field, absent, reason) in [
        (
            "model_digest",
            result.model_digest.is_none(),
            UnavailabilityReason::NotValidated,
        ),
        (
            "request_digest",
            result.request_digest.is_none(),
            UnavailabilityReason::NotValidated,
        ),
        (
            "observation_basis",
            result.observation_basis.is_none(),
            UnavailabilityReason::NotValidated,
        ),
        (
            "worker_generation",
            result.worker_generation.is_none(),
            UnavailabilityReason::NotStarted,
        ),
        (
            "backend_build_id",
            result.backend_build_id.is_none(),
            UnavailabilityReason::NotNegotiated,
        ),
        (
            "seed_policy",
            result.seed_policy.is_none(),
            UnavailabilityReason::NotNegotiated,
        ),
        (
            "effective_options",
            result.effective_options.is_none(),
            UnavailabilityReason::NotReported,
        ),
        (
            "evaluator_version",
            result.evaluator_version.is_none(),
            UnavailabilityReason::NotValidated,
        ),
        (
            "failure_report",
            result.failure_report.is_none(),
            UnavailabilityReason::NotReported,
        ),
    ] {
        if absent {
            unavailable.insert(field.into(), reason);
        }
    }
    for stage in ["materializing", "searching", "verifying"] {
        let timing = result.timings.iter().find(|timing| timing.stage == stage);
        if timing.is_none_or(|timing| timing.wall_time_micros.is_none()) {
            unavailable.insert(
                format!("timings.{stage}.wall_time_micros"),
                UnavailabilityReason::NotMeasured,
            );
        }
        if timing.is_none_or(|timing| timing.cpu_time_micros.is_none()) {
            unavailable.insert(
                format!("timings.{stage}.cpu_time_micros"),
                UnavailabilityReason::NotMeasured,
            );
        }
    }
    unavailable
}
