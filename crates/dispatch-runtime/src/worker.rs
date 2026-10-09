//! Trusted native-backend supervision, bounded validation, and exact checking.

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};

use dispatch_model::{
    Assignment, ModelErrorKind, Problem, ValidatedProblem, VerificationClass, VerificationError,
    validate, verify,
};
use dispatch_protocol::{
    canonical::{model_digest, request_digest_for_backend},
    framing::{read_frame_async, write_frame_async},
    json::{JsonLimits, from_slice},
    wire::{self, worker_envelope::Body},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    process::{Child, Command},
    sync::mpsc,
    time::Instant,
};

use crate::{
    RuntimeError,
    connection::{check_response, protocol_error, version},
};

/// Supplies trusted executable configuration to the native runner.
#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// The native backend selected by application configuration.
    pub backend: PathBuf,
    /// Literal backend arguments, never interpreted as shell text.
    pub arguments: Vec<String>,
    /// The runner's maximum frame allocation before negotiated reduction.
    pub max_frame_bytes: u32,
    /// Requests whole-group owner-loss cleanup only for a dedicated runner group.
    pub owner_group_cleanup: bool,
}

/// Executes the worker protocol while independently checking native candidates.
///
/// Input EOF is owner loss, independent of result watchers. It ends execution
/// and reaps the native process even while native search is stalled.
///
/// # Errors
/// Returns startup, framing, negotiation, or owner-connection errors.
pub async fn run<R, W>(
    config: RunnerConfig,
    mut reader: R,
    mut writer: W,
) -> Result<(), RuntimeError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    let hello = read_frame_async(&mut reader, 65_536)
        .await
        .map_err(protocol_error)?;
    let (sender, mut input) = mpsc::channel(1);
    let maximum = config.max_frame_bytes;
    let owner_group_cleanup = config.owner_group_cleanup;
    let reader_task = tokio::spawn(async move {
        let mut reader = reader;
        loop {
            let result = read_frame_async(&mut reader, maximum).await;
            let failed = result.is_err();
            if failed {
                terminate_owned_group(owner_group_cleanup);
            }
            if sender.send(result).await.is_err() || failed {
                break;
            }
        }
    });
    let mut native: Option<Native> = None;
    let result = serve(&config, hello, &mut input, &mut writer, &mut native).await;
    reader_task.abort();
    if let Some(mut native) = native {
        let _ = native.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), native.child.wait()).await;
    }
    terminate_owned_group(config.owner_group_cleanup);
    result
}

fn terminate_owned_group(enabled: bool) {
    #[cfg(unix)]
    if enabled && rustix::process::getpid() == rustix::process::getpgrp() {
        // EOF supervision remains responsive on its own Tokio thread while
        // validation or exact verification performs synchronous computation.
        let _ = rustix::process::kill_process_group(
            rustix::process::getpgrp(),
            rustix::process::Signal::KILL,
        );
    }
    #[cfg(not(unix))]
    let _ = enabled;
}

type InputReceiver = mpsc::Receiver<Result<wire::WorkerEnvelope, dispatch_protocol::ProtocolError>>;

struct Native {
    child: Child,
    reader: tokio::process::ChildStdout,
    writer: tokio::process::ChildStdin,
    capabilities: wire::Capabilities,
}

async fn serve<W: AsyncWrite + Unpin>(
    config: &RunnerConfig,
    hello: wire::WorkerEnvelope,
    input: &mut InputReceiver,
    writer: &mut W,
    native_slot: &mut Option<Native>,
) -> Result<(), RuntimeError> {
    let Some(Body::Hello(requested)) = hello.body.as_ref() else {
        return Err(RuntimeError::Protocol(
            "Hello must be the first owner message".into(),
        ));
    };
    if hello.session_generation == 0
        || hello.worker_generation == 0
        || hello.request_id == 0
        || !requested.protocol_versions.contains(&version())
    {
        return Err(RuntimeError::Protocol(
            "invalid session generation or protocol version".into(),
        ));
    }
    let mut command = Command::new(&config.backend);
    command
        .args(&config.arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut backend_reader = child
        .stdout
        .take()
        .ok_or_else(|| RuntimeError::Protocol("native stdout missing".into()))?;
    let mut backend_writer = child
        .stdin
        .take()
        .ok_or_else(|| RuntimeError::Protocol("native stdin missing".into()))?;
    write_frame_async(&mut backend_writer, &hello, 65_536)
        .await
        .map_err(protocol_error)?;
    let mut response = tokio::select! {
        message = read_frame_async(&mut backend_reader, 65_536) => message.map_err(protocol_error)?,
        _ = input.recv() => return Err(RuntimeError::Protocol("owner disconnected or sent work before negotiation completed".into())),
    };
    check_response(&hello, &response)?;
    let Some(Body::Capabilities(capabilities)) = response.body.as_ref() else {
        return Err(RuntimeError::Protocol(
            "native engine omitted capabilities".into(),
        ));
    };
    let negotiated = dispatch_protocol::negotiation::negotiate(requested, capabilities)?;
    let limits = negotiated.limits;
    let frame_limit = limits.max_frame_bytes;
    let mut capabilities = capabilities.clone();
    capabilities.limits = Some(limits.clone());
    response.body = Some(Body::Capabilities(capabilities.clone()));
    *native_slot = Some(Native {
        child,
        reader: backend_reader,
        writer: backend_writer,
        capabilities,
    });
    write_frame_async(writer, &response, 65_536)
        .await
        .map_err(protocol_error)?;
    let mut last_request = hello.request_id;
    let mut prepared: BTreeMap<String, ValidatedProblem> = BTreeMap::new();
    let mut prepared_bytes: u64 = 0;
    let mut prepared_sizes: BTreeMap<String, u64> = BTreeMap::new();
    loop {
        let request = receive(input).await?;
        dispatch_protocol::framing::encode_frame(&request, frame_limit).map_err(protocol_error)?;
        if request.session_generation != hello.session_generation
            || request.worker_generation != hello.worker_generation
            || request.request_id <= last_request
            || request.protocol_version != hello.protocol_version
        {
            return Err(RuntimeError::Protocol(
                "stale generation, version, or request identity".into(),
            ));
        }
        last_request = request.request_id;
        let response = match request.body.as_ref() {
            Some(Body::Prepare(prepare)) => {
                if prepared.len() >= usize::try_from(limits.max_prepared).unwrap_or(usize::MAX) {
                    error_response(
                        &request,
                        wire::ErrorCode::ResourceLimit,
                        "prepared input count exceeded",
                    )
                } else {
                    match parse_problem(&prepare.problem_json, &limits) {
                        Ok(problem) => {
                            let size =
                                u64::try_from(prepare.problem_json.len()).unwrap_or(u64::MAX);
                            let total = prepared_bytes.checked_add(size);
                            let digest = model_digest(&problem).map_err(protocol_error)?.to_vec();
                            if total.is_none_or(|total| total > limits.max_prepared_bytes) {
                                error_response(
                                    &request,
                                    wire::ErrorCode::ResourceLimit,
                                    "prepared bytes exceeded",
                                )
                            } else if !prepare.model_digest.is_empty()
                                && prepare.model_digest != digest
                            {
                                error_response(
                                    &request,
                                    wire::ErrorCode::CommitmentMismatch,
                                    "prepared model commitment mismatch",
                                )
                            } else {
                                let handle = request.request_id.to_string();
                                prepared.insert(handle.clone(), problem);
                                prepared_sizes.insert(handle.clone(), size);
                                prepared_bytes = total.unwrap_or(prepared_bytes);
                                with_body(
                                    &request,
                                    Body::Prepared(wire::Prepared {
                                        handle,
                                        model_digest: digest,
                                    }),
                                )
                            }
                        }
                        Err(error) => {
                            error_response(&request, input_error_code(&error), &error.to_string())
                        }
                    }
                }
            }
            Some(Body::Release(release)) => {
                if prepared.remove(&release.handle).is_some() {
                    prepared_bytes = prepared_bytes
                        .saturating_sub(prepared_sizes.remove(&release.handle).unwrap_or(0));
                    with_body(
                        &request,
                        Body::Released(wire::Released {
                            handle: release.handle.clone(),
                        }),
                    )
                } else {
                    error_response(
                        &request,
                        wire::ErrorCode::StaleHandle,
                        "prepared handle is stale",
                    )
                }
            }
            Some(Body::Solve(solve)) => {
                let native = native_slot
                    .as_mut()
                    .ok_or_else(|| RuntimeError::Protocol("native connection missing".into()))?;
                solve_request(&request, solve, &prepared, native, input, writer, &limits).await?
            }
            _ => error_response(
                &request,
                wire::ErrorCode::InvalidMessage,
                "message is not valid in idle state",
            ),
        };
        write_frame_async(writer, &response, frame_limit)
            .await
            .map_err(protocol_error)?;
        if matches!(&response.body, Some(Body::Error(error)) if error.code == wire::ErrorCode::CommitmentMismatch as i32)
        {
            return Err(dispatch_protocol::ProtocolError::CommitmentMismatch.into());
        }
    }
}

async fn solve_request<W: AsyncWrite + Unpin>(
    request: &wire::WorkerEnvelope,
    solve: &wire::Solve,
    prepared: &BTreeMap<String, ValidatedProblem>,
    native: &mut Native,
    input: &mut InputReceiver,
    writer: &mut W,
    limits: &wire::WireLimits,
) -> Result<wire::WorkerEnvelope, RuntimeError> {
    let started = Instant::now();
    let model = if solve.prepared_handle.is_empty() {
        parse_problem(&solve.problem_json, limits)
    } else if !solve.problem_json.is_empty() {
        Err(RuntimeError::Protocol(
            "solve cannot combine inline and prepared input".into(),
        ))
    } else {
        prepared
            .get(&solve.prepared_handle)
            .cloned()
            .ok_or(RuntimeError::StaleHandle)
    };
    let problem = match model {
        Ok(problem) => problem,
        Err(error) => {
            return Ok(rejected(
                request,
                input_error_code(&error),
                &error.to_string(),
            ));
        }
    };
    let Some(options) = &solve.options else {
        return rejected_model(
            request,
            &problem,
            &native.capabilities,
            wire::ErrorCode::InvalidMessage,
            "solve options missing",
        );
    };
    if options.threads == 0 {
        return rejected_model(
            request,
            &problem,
            &native.capabilities,
            wire::ErrorCode::InvalidMessage,
            "thread count must be positive",
        );
    }
    if !native.capabilities.search_modes.contains(&options.mode)
        || options.seed.is_some() && !native.capabilities.seed_supported
    {
        return rejected_model(
            request,
            &problem,
            &native.capabilities,
            wire::ErrorCode::UnsupportedModel,
            "requested search options are unsupported",
        );
    }
    let hint: Option<Assignment> = if solve.hint_json.is_empty() {
        None
    } else {
        match from_slice(&solve.hint_json, json_limits(limits)).map_err(protocol_error) {
            Ok(hint) => Some(hint),
            Err(error) => {
                return rejected_model(
                    request,
                    &problem,
                    &native.capabilities,
                    input_error_code(&error),
                    &error.to_string(),
                );
            }
        }
    };
    let digest = model_digest(&problem).map_err(protocol_error)?.to_vec();
    let request_digest = request_digest_for_backend(
        &problem,
        &native.capabilities.backend_name,
        options,
        hint.as_ref(),
    )
    .map_err(protocol_error)?
    .to_vec();
    if !solve.model_digest.is_empty() && solve.model_digest != digest
        || !solve.request_digest.is_empty() && solve.request_digest != request_digest
    {
        let mut response = rejected_model(
            request,
            &problem,
            &native.capabilities,
            wire::ErrorCode::CommitmentMismatch,
            "solve commitment mismatch",
        )?;
        if let Some(Body::Finished(finished)) = response.body.as_mut() {
            finished.request_digest = request_digest;
        }
        return Ok(response);
    }
    // Validation authority belongs to this runner. Publish the immutable
    // request facts before native execution so later failure cannot erase them.
    let observation_basis_json = serde_json::to_vec(&problem.problem().observation_basis)?;
    let binding = validation_progress(
        request,
        digest.clone(),
        request_digest.clone(),
        observation_basis_json.clone(),
    );
    write_frame_async(writer, &binding, limits.max_frame_bytes)
        .await
        .map_err(protocol_error)?;
    let remaining = solve
        .remaining_wall_time_millis
        .unwrap_or(options.wall_time_millis);
    let deadline = started
        .checked_add(Duration::from_millis(remaining))
        .ok_or_else(|| RuntimeError::Unsupported("worker deadline exceeds clock range".into()))?;
    let mut forwarded = solve.clone();
    forwarded.problem_json = serde_json::to_vec(problem.problem())?;
    forwarded.prepared_handle.clear();
    forwarded.model_digest = digest.clone();
    forwarded.request_digest = request_digest.clone();
    // Request options are committed immutable input. Remaining budget is
    // conveyed separately so native search cannot change their identity.
    forwarded.remaining_wall_time_millis = Some(
        u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .unwrap_or(u64::MAX),
    );
    let forwarded = with_body(request, Body::Solve(forwarded));
    write_frame_async(&mut native.writer, &forwarded, limits.max_frame_bytes)
        .await
        .map_err(protocol_error)?;
    loop {
        let response = tokio::select! {
            response = read_frame_async(&mut native.reader, limits.max_frame_bytes) => response.map_err(protocol_error)?,
            _ = input.recv() => return Err(RuntimeError::Protocol("owner disconnected or pipelined messages during native search".into())),
        };
        check_response(request, &response)?;
        match response.body {
            Some(Body::Progress(progress)) => {
                if progress.validation_binding.is_some() {
                    return Ok(error_response(
                        request,
                        wire::ErrorCode::CommitmentMismatch,
                        "native backend attempted a reserved trusted validation binding",
                    ));
                }
                continue;
            }
            Some(Body::Finished(mut finished)) => {
                if finished.model_digest != digest || finished.request_digest != request_digest {
                    return Ok(error_response(
                        request,
                        wire::ErrorCode::CommitmentMismatch,
                        "native model or request commitment mismatch",
                    ));
                }
                finished.model_digest = digest;
                finished.request_digest = request_digest;
                finished.backend_build_id = native.capabilities.backend_build_id.clone();
                finished.observation_basis_json = observation_basis_json;
                let verification_started = Instant::now();
                verify_finished(&problem, &mut finished, limits)?;
                finished
                    .timings
                    .retain(|timing| timing.stage != wire::ExecutionStage::Verifying as i32);
                finished.timings.push(wire::StageTiming {
                    stage: wire::ExecutionStage::Verifying as i32,
                    wall_time_micros: Some(
                        u64::try_from(verification_started.elapsed().as_micros())
                            .unwrap_or(u64::MAX),
                    ),
                    cpu_time_micros: None,
                });
                if Instant::now() >= deadline {
                    finished.termination = wire::Termination::LimitReached as i32;
                    finished.assignment_json.clear();
                    finished.evaluation_json.clear();
                    finished.evaluator_version.clear();
                    finished.verification_class = wire::VerificationClass::Absent as i32;
                }
                return Ok(with_body(request, Body::Finished(finished)));
            }
            Some(Body::Error(error)) => {
                let mut response = rejected(
                    request,
                    wire::ErrorCode::try_from(error.code).unwrap_or(wire::ErrorCode::Internal),
                    &error.detail,
                );
                if let Some(Body::Finished(finished)) = response.body.as_mut() {
                    finished.model_digest = digest;
                    finished.request_digest = request_digest;
                    finished.backend_build_id = native.capabilities.backend_build_id.clone();
                    finished.observation_basis_json = observation_basis_json;
                    if let Some(Body::Solve(forwarded)) = &forwarded.body {
                        finished.effective_options = forwarded.options.clone();
                    }
                    if !matches!(
                        wire::ErrorCode::try_from(error.code),
                        Ok(wire::ErrorCode::UnsupportedModel
                            | wire::ErrorCode::ResourceLimit
                            | wire::ErrorCode::InvalidMessage)
                    ) {
                        finished.termination = wire::Termination::ExecutionFailed as i32;
                    }
                }
                return Ok(response);
            }
            _ => {
                return Err(RuntimeError::Protocol(
                    "unexpected native search response".into(),
                ));
            }
        }
    }
}

pub(crate) fn verify_finished(
    problem: &ValidatedProblem,
    finished: &mut wire::Finished,
    limits: &wire::WireLimits,
) -> Result<(), RuntimeError> {
    // Native status and evaluation fields cannot confer verification authority.
    finished.evaluation_json.clear();
    finished.evaluator_version.clear();
    finished.verification_class = wire::VerificationClass::Absent as i32;
    if finished.assignment_json.is_empty() {
        return Ok(());
    }
    let candidate: Assignment =
        from_slice(&finished.assignment_json, json_limits(limits)).map_err(protocol_error)?;
    match verify(problem, candidate) {
        Ok(verified) => {
            finished.assignment_json = serde_json::to_vec(verified.assignment())?;
            finished.evaluation_json = serde_json::to_vec(verified.evaluation())?;
            finished.evaluator_version =
                concat!("dispatch-model/", env!("CARGO_PKG_VERSION"), ";model=1.0").into();
            finished.verification_class = match verified.classification() {
                VerificationClass::Feasible => wire::VerificationClass::FullyFeasible,
                VerificationClass::Repair => wire::VerificationClass::RepairProposal,
            } as i32;
        }
        Err(error) => {
            finished.assignment_json.clear();
            finished.verification_class = wire::VerificationClass::Rejected as i32;
            if let VerificationError::Model(model_error) = &error
                && model_error.kind != ModelErrorKind::Malformed
            {
                // An exhausted exact evaluator establishes no candidate
                // verdict. Resource failure cannot become a rejection proof.
                finished.termination = wire::Termination::ExecutionFailed as i32;
                finished.verification_class = wire::VerificationClass::Absent as i32;
                finished.error_code =
                    Some(input_error_code(&RuntimeError::Model(model_error.clone())) as i32);
            }
            let detail = error.to_string();
            finished.diagnostics_truncated |= detail.chars().count() > 4096;
            finished.detail = detail.chars().take(4096).collect();
            if let VerificationError::Violations { evaluation } = error {
                finished.evaluation_json = serde_json::to_vec(&evaluation)?;
                finished.evaluator_version =
                    concat!("dispatch-model/", env!("CARGO_PKG_VERSION"), ";model=1.0").into();
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_problem(
    bytes: &[u8],
    limits: &wire::WireLimits,
) -> Result<ValidatedProblem, RuntimeError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.max_problem_bytes {
        return Err(RuntimeError::Overloaded("worker problem bytes"));
    }
    let raw: Problem = from_slice(bytes, json_limits(limits)).map_err(protocol_error)?;
    check_model_limits(&raw, limits)?;
    validate(raw).map_err(RuntimeError::Model)
}

fn check_model_limits(problem: &Problem, limits: &wire::WireLimits) -> Result<(), RuntimeError> {
    fn bounded(count: usize, maximum: u64, name: &'static str) -> Result<(), RuntimeError> {
        if u64::try_from(count).unwrap_or(u64::MAX) > maximum {
            return Err(RuntimeError::Overloaded(name));
        }
        Ok(())
    }
    bounded(problem.items.len(), limits.max_items, "items")?;
    bounded(problem.targets.len(), limits.max_targets, "targets")?;
    bounded(
        problem.dimensions.len(),
        limits.max_dimensions,
        "dimensions",
    )?;
    bounded(
        problem.constraints.len(),
        limits.max_constraints,
        "constraints",
    )?;
    let mut objectives = 0usize;
    for tier in &problem.objectives {
        objectives = objectives
            .checked_add(tier.terms.len())
            .ok_or(RuntimeError::Overloaded("objectives"))?;
    }
    bounded(objectives, limits.max_objectives, "objectives")?;
    let mut memberships = 0usize;
    for set in problem.groups.values().chain(problem.target_sets.values()) {
        memberships = memberships
            .checked_add(set.len())
            .ok_or(RuntimeError::Overloaded("memberships"))?;
    }
    for family in problem.scope_families.values() {
        for member in family.values() {
            memberships = memberships
                .checked_add(member.len())
                .ok_or(RuntimeError::Overloaded("memberships"))?;
        }
    }
    bounded(memberships, limits.max_memberships, "memberships")?;
    let mut expanded_edges = 0usize;
    let mut overrides = 0usize;
    for item in problem.items.values() {
        let domain_len = problem.domains.get(&item.domain).map_or(0, Vec::len);
        expanded_edges = expanded_edges
            .checked_add(domain_len)
            .ok_or(RuntimeError::Overloaded("expanded candidate domains"))?;
        for demand in item.demands.values() {
            overrides = overrides
                .checked_add(demand.overrides.len())
                .ok_or(RuntimeError::Overloaded("demand overrides"))?;
        }
    }
    bounded(
        expanded_edges,
        limits.max_domain_entries,
        "expanded candidate domains",
    )?;
    bounded(overrides, limits.max_overrides, "demand overrides")?;
    Ok(())
}

fn json_limits(limits: &wire::WireLimits) -> JsonLimits {
    JsonLimits {
        max_bytes: usize::try_from(limits.max_problem_bytes).unwrap_or(usize::MAX),
        max_decoded_bytes: usize::try_from(limits.max_decoded_bytes).unwrap_or(usize::MAX),
        max_nesting: usize::try_from(limits.max_nesting).unwrap_or(64),
        max_values: usize::try_from(limits.max_decoded_bytes).unwrap_or(usize::MAX),
        max_string_bytes: usize::try_from(limits.max_string_bytes).unwrap_or(4096),
    }
}

async fn receive(input: &mut InputReceiver) -> Result<wire::WorkerEnvelope, RuntimeError> {
    input
        .recv()
        .await
        .ok_or_else(|| RuntimeError::Protocol("owner connection ended".into()))?
        .map_err(protocol_error)
}

fn with_body(request: &wire::WorkerEnvelope, body: Body) -> wire::WorkerEnvelope {
    wire::WorkerEnvelope {
        protocol_version: request.protocol_version,
        session_generation: request.session_generation,
        worker_generation: request.worker_generation,
        request_id: request.request_id,
        body: Some(body),
    }
}

fn error_response(
    request: &wire::WorkerEnvelope,
    code: wire::ErrorCode,
    detail: &str,
) -> wire::WorkerEnvelope {
    with_body(
        request,
        Body::Error(wire::ProtocolError {
            code: code as i32,
            detail: detail.chars().take(4096).collect(),
            unsupported_features: Vec::new(),
        }),
    )
}

pub(crate) fn rejected(
    request: &wire::WorkerEnvelope,
    code: wire::ErrorCode,
    detail: &str,
) -> wire::WorkerEnvelope {
    with_body(
        request,
        Body::Finished(wire::Finished {
            termination: wire::Termination::Rejected as i32,
            verification_class: wire::VerificationClass::Absent as i32,
            detail: detail.chars().take(4096).collect(),
            error_code: Some(code as i32),
            diagnostics_truncated: detail.chars().count() > 4096,
            ..Default::default()
        }),
    )
}

pub(crate) fn rejected_model(
    request: &wire::WorkerEnvelope,
    problem: &ValidatedProblem,
    capabilities: &wire::Capabilities,
    code: wire::ErrorCode,
    detail: &str,
) -> Result<wire::WorkerEnvelope, RuntimeError> {
    let mut response = rejected(request, code, detail);
    if let Some(Body::Finished(finished)) = response.body.as_mut() {
        finished.model_digest = model_digest(problem).map_err(protocol_error)?.to_vec();
        finished.backend_build_id = capabilities.backend_build_id.clone();
        finished.observation_basis_json = serde_json::to_vec(&problem.problem().observation_basis)?;
    }
    Ok(response)
}

pub(crate) fn input_error_code(error: &RuntimeError) -> wire::ErrorCode {
    match error {
        RuntimeError::Overloaded(_)
        | RuntimeError::Wire(dispatch_protocol::ProtocolError::JsonLimit(_)) => {
            wire::ErrorCode::ResourceLimit
        }
        RuntimeError::Model(error) => match error.kind {
            ModelErrorKind::UnsupportedVersion => wire::ErrorCode::UnsupportedModel,
            ModelErrorKind::NumericExhaustion => wire::ErrorCode::ResourceLimit,
            ModelErrorKind::Malformed => wire::ErrorCode::InvalidMessage,
        },
        _ => wire::ErrorCode::InvalidMessage,
    }
}

pub(crate) fn validation_progress(
    request: &wire::WorkerEnvelope,
    model_digest: Vec<u8>,
    request_digest: Vec<u8>,
    observation_basis_json: Vec<u8>,
) -> wire::WorkerEnvelope {
    with_body(
        request,
        Body::Progress(wire::Progress {
            stage: wire::ExecutionStage::Materializing as i32,
            validation_binding: Some(wire::ValidationBinding {
                model_digest,
                request_digest,
                observation_basis_json,
            }),
            ..Default::default()
        }),
    )
}
