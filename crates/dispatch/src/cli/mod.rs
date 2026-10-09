//! Command parsing, machine output, and distinct input and execution failures.

mod io;
mod operations;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "dispatch",
    version,
    about = "Build, evaluate, and solve portable assignment problems"
)]
struct Cli {
    /// Bound each JSON input before decoding it.
    #[arg(long, global = true, default_value_t = 67_108_864)]
    max_input_bytes: u64,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a problem without running a solver.
    Validate {
        #[command(flatten)]
        input: ProblemInput,
        /// Write the validated problem to a JSON file, or '-' for stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Evaluate resource use, violations, and objectives exactly.
    Evaluate {
        #[command(flatten)]
        input: ProblemInput,
        /// Read a complete assignment document.
        #[arg(long)]
        assignment: PathBuf,
        /// Write evaluation JSON to a file, or '-' for stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Independently verify a candidate against a problem.
    Verify {
        #[command(flatten)]
        input: ProblemInput,
        /// Read a complete assignment document.
        #[arg(long)]
        assignment: PathBuf,
        /// Write verification JSON to a file, or '-' for stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Solve through an explicitly configured local worker environment.
    Solve {
        #[command(flatten)]
        input: SolveInput,
        #[command(flatten)]
        execution: LocalExecution,
        /// Write the final result to a JSON file, or '-' for stdout.
        #[arg(long, alias = "output")]
        result: Option<PathBuf>,
    },
    /// Export an inspectable solve request without starting a solver.
    Request {
        #[command(flatten)]
        input: ProblemInput,
        #[command(flatten)]
        search: SearchConfiguration,
        /// Name the selected backend policy without choosing an executable.
        #[arg(long, default_value = "rebalancer")]
        backend_name: String,
        /// Read an optional search hint independent of the observed baseline.
        #[arg(long)]
        hint: Option<PathBuf>,
        /// Write request JSON to a file, or '-' for stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Recompute and explain a saved result without trusting saved evaluations.
    Explain {
        #[command(flatten)]
        input: ProblemInput,
        /// Read a solve result containing a candidate assignment.
        #[arg(long)]
        result: PathBuf,
        /// Write explanation JSON to a file, or '-' for stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Compare assignments using one unchanged problem and objective ordering.
    Compare {
        #[command(flatten)]
        input: ProblemInput,
        /// Read the baseline assignment.
        #[arg(long)]
        before: PathBuf,
        /// Read the proposed assignment.
        #[arg(long)]
        after: PathBuf,
        /// Write comparison JSON to a file, or '-' for stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Measure repeated solves through the same session contract.
    Benchmark {
        #[command(flatten)]
        input: ProblemInput,
        #[command(flatten)]
        execution: LocalExecution,
        /// Run this many sequential samples.
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        iterations: u32,
        /// Write benchmark JSON to a file, or '-' for stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Args)]
struct ProblemInput {
    /// Read a model document from a file, or '-' for stdin.
    #[arg(long)]
    problem: PathBuf,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct SolveInput {
    /// Read a model document and use explicit search flags.
    #[arg(long)]
    problem: Option<PathBuf>,
    /// Read a complete portable request with its problem, options, and hint.
    #[arg(long)]
    request: Option<PathBuf>,
}

#[derive(Args)]
struct LocalExecution {
    /// Select reusable workers or a fresh worker for each request.
    #[arg(long, value_enum)]
    profile: Profile,

    /// Select the trusted Rust runner executable.
    #[arg(long, env = "DISPATCH_WORKER")]
    runner: PathBuf,

    /// Select the trusted native solver executable.
    #[arg(long, env = "DISPATCH_BACKEND")]
    backend: PathBuf,

    /// Pass a literal argument to the native solver.
    #[arg(long, allow_hyphen_values = true)]
    backend_argument: Vec<String>,

    #[command(flatten)]
    search: SearchConfiguration,

    /// Require a specific native backend build identity.
    #[arg(long)]
    expected_backend_build: Option<String>,
}

#[derive(Args)]
struct SearchConfiguration {
    /// Bound the entire solve, including queueing and verification.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    deadline_ms: Option<u64>,

    /// Request cooperative native search threads within the execution grant.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    threads: Option<u32>,

    /// Provide a search seed without asserting replay determinism.
    #[arg(long)]
    seed: Option<u64>,

    /// Select an explicitly supported native search algorithm.
    #[arg(long, value_enum)]
    mode: Option<Search>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Profile {
    Warm,
    Fresh,
}

#[derive(Clone, Copy, ValueEnum)]
enum Search {
    LocalSearch,
    Mip,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ExitCategory {
    Success,
    InvalidInput,
    Unsupported,
    Overload,
    ExecutionFailure,
    NoCandidate,
}

impl ExitCategory {
    fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::InvalidInput => 2,
            Self::Unsupported => 3,
            Self::Overload => 4,
            Self::ExecutionFailure => 5,
            Self::NoCandidate => 6,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InvalidInput => "invalid_input",
            Self::Unsupported => "unsupported",
            Self::Overload => "overload",
            Self::ExecutionFailure => "execution_failure",
            Self::NoCandidate => "no_candidate",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum CliError {
    #[error("cannot access {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid portable JSON in {path}: {source}")]
    PortableJson {
        path: PathBuf,
        #[source]
        source: dispatch_protocol::ProtocolError,
    },
    #[error("invalid solve request: {source}")]
    Request {
        #[source]
        source: dispatch_protocol::ProtocolError,
    },
    #[error("{message}")]
    Message {
        category: ExitCategory,
        message: String,
    },
    #[error(transparent)]
    Model(#[from] dispatch::ModelError),
    #[error(transparent)]
    Runtime(#[from] dispatch::runtime::RuntimeError),
}

impl CliError {
    fn category(&self) -> ExitCategory {
        match self {
            Self::Io { .. } => ExitCategory::ExecutionFailure,
            Self::Json { .. } => ExitCategory::ExecutionFailure,
            Self::PortableJson { .. } => ExitCategory::InvalidInput,
            Self::Request { source } => match source {
                dispatch_protocol::ProtocolError::Negotiation(_) => ExitCategory::Unsupported,
                _ => ExitCategory::InvalidInput,
            },
            Self::Model(error) => match error.kind {
                dispatch::ModelErrorKind::Malformed => ExitCategory::InvalidInput,
                dispatch::ModelErrorKind::UnsupportedVersion => ExitCategory::Unsupported,
                dispatch::ModelErrorKind::NumericExhaustion => ExitCategory::ExecutionFailure,
            },
            Self::Message { category, .. } => *category,
            Self::Runtime(error) => match error {
                dispatch::runtime::RuntimeError::InvalidConfiguration(_) => {
                    ExitCategory::InvalidInput
                }
                dispatch::runtime::RuntimeError::Unsupported(_)
                | dispatch::runtime::RuntimeError::UnsupportedGuarantee(_) => {
                    ExitCategory::Unsupported
                }
                dispatch::runtime::RuntimeError::Overloaded(_) => ExitCategory::Overload,
                dispatch::runtime::RuntimeError::Unavailable(_) => ExitCategory::ExecutionFailure,
                _ => ExitCategory::ExecutionFailure,
            },
        }
    }
}

pub(super) async fn run() -> ExitCode {
    let cli = Cli::parse();
    match operations::execute(cli).await {
        Ok(category) => ExitCode::from(category.code()),
        Err(error) => {
            let _ = io::report_error(&error);
            ExitCode::from(error.category().code())
        }
    }
}
