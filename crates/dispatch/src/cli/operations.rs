//! Pure operations and local execution use the same published model contracts.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dispatch::runtime::{
    CandidateClass, CloseMode, ExecutionProfile, RejectionReason, SearchMode, Session,
    SessionBuilder, SessionLimits, SolveOptions, SolveResult, SubprocessProvider, Termination,
    WorkerLaunch,
};
use dispatch::{Assignment, Problem, ValidatedProblem, analysis, evaluate, validate, verify};
use dispatch_protocol::request::{SearchRequestOptions, SolveRequest};
use serde::Serialize;
use tokio::time::Instant;

use super::{
    Cli, CliError, Command, ExitCategory, LocalExecution, Profile, Search, SearchConfiguration,
    SolveInput, io,
};

pub(super) async fn execute(cli: Cli) -> Result<ExitCategory, CliError> {
    match cli.command {
        Command::Validate { input, output } => {
            let problem = read_validated(&input.problem, cli.max_input_bytes)?;
            io::write_json(output.as_deref(), problem.problem())?;
        }
        Command::Evaluate {
            input,
            assignment,
            output,
        } => {
            let problem = read_validated(&input.problem, cli.max_input_bytes)?;
            let assignment: Assignment = io::read_json(&assignment, cli.max_input_bytes)?;
            io::write_json(output.as_deref(), &evaluate(&problem, &assignment)?)?;
        }
        Command::Verify {
            input,
            assignment,
            output,
        } => {
            let problem = read_validated(&input.problem, cli.max_input_bytes)?;
            let assignment: Assignment = io::read_json(&assignment, cli.max_input_bytes)?;
            let (classification, evaluation) = match verify(&problem, assignment) {
                Ok(verified) => (
                    Some(verified.classification()),
                    verified.evaluation().clone(),
                ),
                Err(dispatch::VerificationError::Violations { evaluation }) => (None, *evaluation),
                Err(dispatch::VerificationError::Model(error)) => return Err(error.into()),
            };
            let accepted = classification.is_some();
            #[derive(Serialize)]
            struct VerificationReport {
                accepted: bool,
                classification: Option<dispatch::VerificationClass>,
                evaluation: dispatch::Evaluation,
            }
            io::write_json(
                output.as_deref(),
                &VerificationReport {
                    accepted,
                    classification,
                    evaluation,
                },
            )?;
            if !accepted {
                return Ok(ExitCategory::NoCandidate);
            }
        }
        Command::Compare {
            input,
            before,
            after,
            output,
        } => {
            let problem = read_validated(&input.problem, cli.max_input_bytes)?;
            let before = io::read_json(&before, cli.max_input_bytes)?;
            let after = io::read_json(&after, cli.max_input_bytes)?;
            io::write_json(
                output.as_deref(),
                &analysis::compare(&problem, &before, &after)?,
            )?;
        }
        Command::Explain {
            input,
            result,
            output,
        } => {
            let problem = read_validated(&input.problem, cli.max_input_bytes)?;
            let result: SolveResult = io::read_json(&result, cli.max_input_bytes)?;
            check_result_problem(&problem, &result)?;
            let assignment = result
                .assignment
                .as_ref()
                .ok_or_else(|| CliError::Message {
                    category: ExitCategory::NoCandidate,
                    message: "the saved result contains no candidate assignment".to_owned(),
                })?;
            io::write_json(output.as_deref(), &analysis::explain(&problem, assignment)?)?;
        }
        Command::Solve {
            input,
            execution,
            result,
        } => {
            let (problem, options, expected_backend) =
                load_solve_input(&input, &execution.search, cli.max_input_bytes)?;
            let session = open_session(&execution, 1).await?;
            let outcome = async {
                if let Some(expected) = expected_backend
                    && session.capabilities().backend_name != expected
                {
                    return Err(CliError::Message {
                        category: ExitCategory::Unsupported,
                        message: "configured backend does not match the request's selected backend"
                            .into(),
                    });
                }
                solve_once(&session, problem, options).await
            }
            .await;
            close_session(&session).await?;
            let outcome = outcome?;
            io::write_json(result.as_deref(), outcome.as_ref())?;
            return Ok(result_category(&outcome));
        }
        Command::Request {
            input,
            search,
            backend_name,
            hint,
            output,
        } => {
            let problem = read_validated(&input.problem, cli.max_input_bytes)?;
            let hint: Option<Assignment> = hint
                .as_deref()
                .map(|path| io::read_json(path, cli.max_input_bytes))
                .transpose()?;
            if let Some(hint) = &hint {
                // A hint may violate constraints, but its bindings must be complete.
                evaluate(&problem, hint)?;
            }
            let mut request =
                SolveRequest::new(problem.problem().clone(), portable_options(&search), hint);
            request.backend = backend_name;
            request
                .validate_metadata()
                .map_err(|source| CliError::Request { source })?;
            io::write_json(output.as_deref(), &request)?;
        }
        Command::Benchmark {
            input,
            execution,
            iterations,
            output,
        } => {
            let problem: Problem = io::read_json(&input.problem, cli.max_input_bytes)?;
            let initialization = Instant::now();
            let session = open_session(&execution, iterations).await?;
            let initialization_ns = initialization.elapsed().as_nanos().to_string();
            let outcome = benchmark(&session, &problem, &execution, iterations).await;
            close_session(&session).await?;
            let (samples, category) = outcome?;
            io::write_json(
                output.as_deref(),
                &BenchmarkReport {
                    profile: match execution.profile {
                        Profile::Warm => "warm",
                        Profile::Fresh => "fresh",
                    },
                    initialization_wall_ns: initialization_ns,
                    samples,
                },
            )?;
            return Ok(category);
        }
    }
    Ok(ExitCategory::Success)
}

fn read_validated(path: &Path, bound: u64) -> Result<ValidatedProblem, CliError> {
    Ok(validate(io::read_json(path, bound)?)?)
}

async fn open_session(
    execution: &LocalExecution,
    retained_results: u32,
) -> Result<Session, CliError> {
    let limits = SessionLimits {
        max_retained_results: usize::try_from(retained_results).map_err(|_| CliError::Message {
            category: ExitCategory::InvalidInput,
            message: "sample count exceeds the platform's address range".to_owned(),
        })?,
        ..SessionLimits::default()
    };
    let launch = WorkerLaunch {
        runner: execution.runner.clone(),
        native_backend: execution.backend.clone(),
        native_arguments: execution.backend_argument.clone(),
        session_generation: 0,
        worker_generation: 0,
        max_frame_bytes: limits.max_frame_bytes,
    };
    let mut builder = SessionBuilder::new(Arc::new(SubprocessProvider::new()), launch)
        .limits(limits)
        .profile(match execution.profile {
            Profile::Warm => ExecutionProfile::Warm,
            Profile::Fresh => ExecutionProfile::Fresh,
        });
    if let Some(build) = &execution.expected_backend_build {
        builder = builder.expected_backend_build(build);
    }
    Ok(builder.start().await?)
}

async fn solve_once(
    session: &Session,
    problem: Problem,
    options: SolveOptions,
) -> Result<Arc<SolveResult>, CliError> {
    Ok(session.submit(problem, options)?.wait().await?)
}

fn portable_options(search: &SearchConfiguration) -> SearchRequestOptions {
    SearchRequestOptions {
        wall_time_millis: dispatch::Quantity::new(search.deadline_ms.unwrap_or(30_000)),
        threads: dispatch::Quantity::new(u64::from(search.threads.unwrap_or(1))),
        seed: search.seed.map(dispatch::Quantity::new),
        mode: match search.mode.unwrap_or(Search::LocalSearch) {
            Search::LocalSearch => dispatch_protocol::request::SearchMode::LocalSearch,
            Search::Mip => dispatch_protocol::request::SearchMode::Mip,
        },
        ..SearchRequestOptions::default()
    }
}

fn runtime_options(
    options: &SearchRequestOptions,
    hint: Option<Assignment>,
) -> Result<SolveOptions, CliError> {
    let wire = options
        .to_wire()
        .map_err(|source| CliError::Request { source })?;
    if wire.memory_bytes != 0 || wire.cpu_time_millis != 0 || wire.maximum_iterations != 0 {
        return Err(CliError::Message {
            category: ExitCategory::Unsupported,
            message: "the local session does not implement the requested cooperative memory, CPU-time, or iteration option".into(),
        });
    }
    Ok(SolveOptions {
        deadline: Duration::from_millis(wire.wall_time_millis),
        threads: wire.threads,
        seed: wire.seed,
        mode: match options.mode {
            dispatch_protocol::request::SearchMode::LocalSearch => SearchMode::LocalSearch,
            dispatch_protocol::request::SearchMode::Mip => SearchMode::Mip,
        },
        hint,
    })
}

fn load_solve_input(
    input: &SolveInput,
    search: &SearchConfiguration,
    bound: u64,
) -> Result<(Problem, SolveOptions, Option<String>), CliError> {
    if let Some(path) = &input.request {
        if search.deadline_ms.is_some()
            || search.threads.is_some()
            || search.seed.is_some()
            || search.mode.is_some()
        {
            return Err(CliError::Message {
                category: ExitCategory::InvalidInput,
                message: "search flags cannot override an imported request; edit or export a distinct request".into(),
            });
        }
        let request: SolveRequest = io::read_json(path, bound)?;
        request
            .validate_metadata()
            .map_err(|source| CliError::Request { source })?;
        let options = runtime_options(&request.options, request.hint)?;
        return Ok((request.problem, options, Some(request.backend)));
    }
    let path = input.problem.as_ref().ok_or_else(|| CliError::Message {
        category: ExitCategory::InvalidInput,
        message: "a problem or request input is required".into(),
    })?;
    Ok((
        io::read_json(path, bound)?,
        runtime_options(&portable_options(search), None)?,
        None,
    ))
}

async fn close_session(session: &Session) -> Result<(), CliError> {
    let cleanup = session
        .close(CloseMode::Cancel, Duration::from_secs(5))
        .await?;
    if cleanup.unconfirmed != 0 || cleanup.workers_unconfirmed != 0 {
        return Err(CliError::Message {
            category: ExitCategory::ExecutionFailure,
            message: format!(
                "cleanup could not confirm {} jobs and {} workers stopped",
                cleanup.unconfirmed, cleanup.workers_unconfirmed
            ),
        });
    }
    Ok(())
}

fn result_category(result: &SolveResult) -> ExitCategory {
    match result.termination {
        Termination::Rejected => match result.rejection {
            Some(RejectionReason::InvalidInput) => ExitCategory::InvalidInput,
            Some(RejectionReason::UnsupportedModel | RejectionReason::Unauthorized) => {
                ExitCategory::Unsupported
            }
            None => ExitCategory::ExecutionFailure,
        },
        Termination::ExecutionFailed | Termination::Cancelled => ExitCategory::ExecutionFailure,
        Termination::Completed | Termination::LimitReached => match result.candidate {
            CandidateClass::FullyFeasible | CandidateClass::RepairProposal => ExitCategory::Success,
            CandidateClass::Absent | CandidateClass::Rejected => ExitCategory::NoCandidate,
        },
    }
}

fn check_result_problem(problem: &ValidatedProblem, result: &SolveResult) -> Result<(), CliError> {
    let digest = dispatch_protocol::canonical::model_digest(problem).map_err(|source| {
        CliError::PortableJson {
            path: Path::new("result.model_digest").to_owned(),
            source,
        }
    })?;
    if result.model_digest.as_deref() != Some(digest.as_slice()) {
        return Err(CliError::Message {
            category: ExitCategory::InvalidInput,
            message: "saved result does not identify this exact problem".to_owned(),
        });
    }
    Ok(())
}

#[derive(Serialize)]
struct BenchmarkReport {
    profile: &'static str,
    initialization_wall_ns: String,
    samples: Vec<BenchmarkSample>,
}

#[derive(Serialize)]
struct BenchmarkSample {
    index: String,
    request_wall_ns: String,
    cpu_ns: Option<String>,
    termination: Termination,
    candidate: CandidateClass,
    backend_build_id: Option<String>,
}

async fn benchmark(
    session: &Session,
    problem: &Problem,
    execution: &LocalExecution,
    iterations: u32,
) -> Result<(Vec<BenchmarkSample>, ExitCategory), CliError> {
    let mut samples = Vec::new();
    let mut category = ExitCategory::Success;
    for index in 0..iterations {
        let start = Instant::now();
        let result = solve_once(
            session,
            problem.clone(),
            runtime_options(&portable_options(&execution.search), None)?,
        )
        .await?;
        samples.push(BenchmarkSample {
            index: index.to_string(),
            request_wall_ns: start.elapsed().as_nanos().to_string(),
            cpu_ns: None,
            termination: result.termination,
            candidate: result.candidate,
            backend_build_id: result.backend_build_id.clone(),
        });
        let sample_category = result_category(&result);
        if sample_category.code() != 0 {
            category = sample_category;
            break;
        }
    }
    Ok((samples, category))
}
