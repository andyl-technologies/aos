//! Killable process supervision for the built-in canonical campaign planner.
//!
//! The authority-bearing daemon never executes the pure planner on its own
//! thread. It starts the packaged `crucible` executable in a hidden worker
//! mode, sends one bounded canonical [`PlannerRequest`], drains all three pipes
//! concurrently, and kills and reaps the child on cancellation or deadline.
//! The child returns only an unauthenticated [`PlannerStepProposal`]; measured
//! fuel and planner authority remain parent-owned.
//!
//! The private process frame is:
//!
//! ```text
//! magic[8] = "CRUCPP01"
//! kind[1]  = request(1) | proposal(2) | rejection(3)
//! reserved[3] = 0
//! body_len_be[4]
//! body[body_len]
//! ```

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use crucible_campaign::{
    CampaignCodecError, CanonicalFrontierPlanner, MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
    PlannerEngineOutput, PlannerExecutionSupervisor, PlannerRequest, PlannerStepProposal,
    PurePlannerEngine, SupervisedPlannerExecution,
};

const FRAME_MAGIC: &[u8; 8] = b"CRUCPP01";
const FRAME_HEADER_BYTES: usize = 16;
const REQUEST_KIND: u8 = 1;
const PROPOSAL_KIND: u8 = 2;
const REJECTION_KIND: u8 = 3;
const MAX_REJECTION_BYTES: usize = 4 * 1024;
const MAX_EXECUTABLE_PATH_BYTES: usize = 4_095;
const MIN_EXECUTION_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_EXECUTION_TIMEOUT: Duration = Duration::from_secs(60);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// Hidden argument selecting the one-request canonical planner worker.
pub const CANONICAL_PLANNER_WORKER_ARGUMENT: &str = "__crucible-campaign-planner-worker-v1";

/// Immutable launch contract for one canonical planner worker process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPlannerProcessConfig {
    executable: PathBuf,
    execution_timeout: Duration,
}

impl CanonicalPlannerProcessConfig {
    /// Builds a bounded exact worker launch contract.
    ///
    /// The executable path must be absolute, free of dot components and NUL,
    /// and at most 4,095 bytes. The executable itself is authenticated before
    /// every launch.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalPlannerProcessError::InvalidConfiguration`] when the
    /// path or timeout is outside the fixed production profile.
    pub fn new(
        executable: impl Into<PathBuf>,
        execution_timeout: Duration,
    ) -> Result<Self, CanonicalPlannerProcessError> {
        let executable = executable.into();
        if !valid_executable_path(&executable) {
            return Err(CanonicalPlannerProcessError::InvalidConfiguration(
                "canonical planner executable path is invalid",
            ));
        }
        if !(MIN_EXECUTION_TIMEOUT..=MAX_EXECUTION_TIMEOUT).contains(&execution_timeout) {
            return Err(CanonicalPlannerProcessError::InvalidConfiguration(
                "canonical planner timeout is outside 1ms..=60s",
            ));
        }
        Ok(Self {
            executable,
            execution_timeout,
        })
    }

    /// Builds a launch contract for the currently running packaged executable.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalPlannerProcessError`] when the current executable
    /// cannot be resolved or violates the exact launch profile.
    pub fn for_current_executable(
        execution_timeout: Duration,
    ) -> Result<Self, CanonicalPlannerProcessError> {
        let executable = std::env::current_exe()
            .map_err(|source| process_io("resolve-current-executable", source))?;
        Self::new(executable, execution_timeout)
    }

    /// Returns the exact worker executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Returns the finite wall-clock limit for one evaluation.
    #[must_use]
    pub const fn execution_timeout(&self) -> Duration {
        self.execution_timeout
    }
}

/// Sticky cancellation authority for one planner process supervisor.
#[derive(Clone, Debug)]
pub struct CanonicalPlannerProcessCancellation {
    canceled: Arc<AtomicBool>,
}

impl CanonicalPlannerProcessCancellation {
    /// Requests cancellation of the current or every future evaluation.
    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
    }

    /// Returns whether sticky cancellation has been requested.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }
}

/// Killable supervisor for the built-in canonical frontier planner.
pub struct CanonicalPlannerProcessSupervisor {
    config: CanonicalPlannerProcessConfig,
    canceled: Arc<AtomicBool>,
}

impl CanonicalPlannerProcessSupervisor {
    /// Creates one process supervisor and its cloneable cancellation handle.
    #[must_use]
    pub fn new(
        config: CanonicalPlannerProcessConfig,
    ) -> (Self, CanonicalPlannerProcessCancellation) {
        let canceled = Arc::new(AtomicBool::new(false));
        (
            Self {
                config,
                canceled: Arc::clone(&canceled),
            },
            CanonicalPlannerProcessCancellation { canceled },
        )
    }

    fn execute_request(
        &mut self,
        request: &PlannerRequest,
    ) -> Result<PlannerEngineOutput, CanonicalPlannerProcessError> {
        if self.canceled.load(Ordering::Acquire) {
            return Err(CanonicalPlannerProcessError::Canceled);
        }
        let executable_before = authenticated_executable(&self.config.executable)?;
        let request_bytes = request.canonical_bytes();
        if request_bytes.len() > MAX_PLANNER_COMPONENT_MESSAGE_BYTES {
            return Err(CanonicalPlannerProcessError::InvalidRequest(
                "canonical planner request exceeds 64 MiB",
            ));
        }
        let deadline = process_now()
            .checked_add(self.config.execution_timeout)
            .ok_or(CanonicalPlannerProcessError::InvalidConfiguration(
                "canonical planner deadline overflow",
            ))?;

        let mut child = Command::new(&self.config.executable)
            .arg(CANONICAL_PLANNER_WORKER_ARGUMENT)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| process_io("spawn-canonical-planner", source))?;
        if let Err(error) = revalidate_executable(&self.config.executable, &executable_before) {
            terminate_and_reap(&mut child);
            return Err(error);
        }

        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            terminate_and_reap(&mut child);
            return Err(CanonicalPlannerProcessError::InvalidConfiguration(
                "canonical planner child pipe is unavailable",
            ));
        };

        let writer = match thread::Builder::new()
            .name(String::from("crucible-planner-request"))
            .spawn(move || write_frame(stdin, REQUEST_KIND, &request_bytes))
        {
            Ok(writer) => writer,
            Err(source) => {
                terminate_and_reap(&mut child);
                return Err(process_io("spawn-planner-request-writer", source));
            }
        };
        let stdout_reader = match thread::Builder::new()
            .name(String::from("crucible-planner-response"))
            .spawn(move || {
                capture_bounded(
                    stdout,
                    FRAME_HEADER_BYTES.saturating_add(MAX_PLANNER_COMPONENT_MESSAGE_BYTES),
                )
            }) {
            Ok(reader) => reader,
            Err(source) => {
                terminate_and_reap(&mut child);
                let _ = writer.join();
                return Err(process_io("spawn-planner-response-reader", source));
            }
        };
        let stderr_reader = match thread::Builder::new()
            .name(String::from("crucible-planner-stderr"))
            .spawn(move || capture_bounded(stderr, MAX_STDERR_BYTES))
        {
            Ok(reader) => reader,
            Err(source) => {
                terminate_and_reap(&mut child);
                let _ = writer.join();
                let _ = stdout_reader.join();
                return Err(process_io("spawn-planner-stderr-reader", source));
            }
        };

        let terminal = loop {
            if self.canceled.load(Ordering::Acquire) {
                terminate_and_reap(&mut child);
                break Err(CanonicalPlannerProcessError::Canceled);
            }
            if process_now() >= deadline {
                terminate_and_reap(&mut child);
                break Err(CanonicalPlannerProcessError::TimedOut);
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(
                    CHILD_POLL_INTERVAL.min(deadline.saturating_duration_since(process_now())),
                ),
                Err(source) => {
                    terminate_and_reap(&mut child);
                    break Err(process_io("poll-canonical-planner", source));
                }
            }
        };

        let write_result = join_worker(writer, "canonical planner request writer")?;
        let stdout = join_worker(stdout_reader, "canonical planner response reader")?
            .map_err(|source| process_io("read-canonical-planner-response", source))?;
        let stderr = join_worker(stderr_reader, "canonical planner stderr reader")?
            .map_err(|source| process_io("read-canonical-planner-stderr", source))?;
        let status = terminal?;
        write_result.map_err(|source| process_io("write-canonical-planner-request", source))?;
        if stdout.overflow {
            return Err(CanonicalPlannerProcessError::OutputLimitExceeded);
        }
        if !status.success() {
            return Err(worker_failed(status, stderr));
        }

        let (kind, body) = parse_frame(&stdout.bytes)?;
        match kind {
            PROPOSAL_KIND => Ok(PlannerEngineOutput::new(
                PlannerStepProposal::from_canonical_bytes(body)?,
            )),
            REJECTION_KIND => Err(CanonicalPlannerProcessError::WorkerRejected(
                String::from_utf8_lossy(body).into_owned(),
            )),
            _ => Err(CanonicalPlannerProcessError::ProtocolViolation(
                "canonical planner returned an unexpected frame kind",
            )),
        }
    }
}

impl PlannerExecutionSupervisor<CanonicalFrontierPlanner> for CanonicalPlannerProcessSupervisor {
    type Error = CanonicalPlannerProcessError;

    fn execute(
        &mut self,
        _engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(CanonicalPlannerProcessError::InvalidRequest(
                "canonical planner measured fuel overflow",
            ))?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(CanonicalPlannerProcessError::InvalidRequest(
                "canonical planner measured fuel exceeds request budget",
            ));
        }
        let output = self.execute_request(request)?;
        Ok(SupervisedPlannerExecution::new(Ok(output), measured_fuel))
    }
}

/// Failure from canonical planner process configuration or supervision.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalPlannerProcessError {
    /// Static worker configuration is outside the production profile.
    #[error("{0}")]
    InvalidConfiguration(&'static str),
    /// The canonical request cannot be executed within its own budget.
    #[error("{0}")]
    InvalidRequest(&'static str),
    /// Sticky cancellation stopped or rejected the evaluation.
    #[error("canonical planner evaluation was canceled")]
    Canceled,
    /// The finite wall-clock limit expired and the worker was killed and reaped.
    #[error("canonical planner evaluation timed out")]
    TimedOut,
    /// The worker emitted more than the fixed response limit.
    #[error("canonical planner response exceeds 64 MiB")]
    OutputLimitExceeded,
    /// The worker rejected the request without producing a proposal.
    #[error("canonical planner worker rejected the request: {0}")]
    WorkerRejected(String),
    /// The worker exited unsuccessfully with bounded diagnostics.
    #[error("canonical planner worker failed with status {status:?}: {diagnostic}")]
    WorkerFailed {
        /// Platform exit status code, when available.
        status: Option<i32>,
        /// Bounded lossy UTF-8 diagnostic.
        diagnostic: String,
    },
    /// The worker violated the fixed process protocol.
    #[error("{0}")]
    ProtocolViolation(&'static str),
    /// A canonical request or proposal body was invalid.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// One process, pipe, or thread operation failed.
    #[error("canonical planner process {operation} failed: {source}")]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Underlying operating-system failure.
        #[source]
        source: io::Error,
    },
    /// One bounded pipe worker panicked.
    #[error("{0} panicked")]
    ThreadPanicked(&'static str),
}

/// Serves one canonical planner process request over arbitrary byte streams.
///
/// The worker owns no planner authority and returns only an unauthenticated
/// proposal or bounded rejection. The parent is responsible for deadline,
/// cancellation, metering, validation, and authentication.
///
/// # Errors
///
/// Returns [`io::Error`] for malformed framing or a failed read or response
/// write. Invalid canonical requests and deterministic planner failures produce
/// a bounded rejection frame.
pub fn serve_canonical_planner_process_once(
    mut input: impl Read,
    mut output: impl Write,
) -> io::Result<()> {
    let (kind, request_bytes) = read_frame(&mut input)?;
    if kind != REQUEST_KIND {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical planner worker expected a request frame",
        ));
    }
    let mut trailing = [0_u8; 1];
    if input.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical planner worker received trailing input",
        ));
    }
    let request = match PlannerRequest::from_canonical_bytes(&request_bytes) {
        Ok(request) => request,
        Err(error) => {
            let rejection = bounded_rejection(&error.to_string());
            return write_frame(&mut output, REJECTION_KIND, rejection.as_bytes());
        }
    };
    let mut engine = CanonicalFrontierPlanner;
    match engine.plan(&request) {
        Ok(result) => write_frame(
            &mut output,
            PROPOSAL_KIND,
            &result.proposal().canonical_bytes(),
        ),
        Err(error) => {
            let rejection = bounded_rejection(&error.to_string());
            write_frame(&mut output, REJECTION_KIND, rejection.as_bytes())
        }
    }
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    overflow: bool,
}

fn authenticated_executable(path: &Path) -> Result<fs::Metadata, CanonicalPlannerProcessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| process_io("stat-canonical-planner-executable", source))?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 || metadata.mode() & 0o111 == 0 {
        return Err(CanonicalPlannerProcessError::InvalidConfiguration(
            "canonical planner executable is not a protected executable regular file",
        ));
    }
    Ok(metadata)
}

fn revalidate_executable(
    path: &Path,
    original: &fs::Metadata,
) -> Result<(), CanonicalPlannerProcessError> {
    let current = authenticated_executable(path)?;
    if current.dev() != original.dev() || current.ino() != original.ino() {
        return Err(CanonicalPlannerProcessError::InvalidConfiguration(
            "canonical planner executable identity changed during spawn",
        ));
    }
    Ok(())
}

fn valid_executable_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && !bytes.contains(&0)
        && bytes.len() <= MAX_EXECUTABLE_PATH_BYTES
}

fn write_frame(mut writer: impl Write, kind: u8, body: &[u8]) -> io::Result<()> {
    let body_len = u32::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "canonical planner frame body exceeds u32",
        )
    })?;
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    header[..8].copy_from_slice(FRAME_MAGIC);
    header[8] = kind;
    header[12..16].copy_from_slice(&body_len.to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(body)?;
    writer.flush()
}

fn read_frame(mut reader: impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    reader.read_exact(&mut header)?;
    if &header[..8] != FRAME_MAGIC || header[9..12] != [0, 0, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical planner frame header is invalid",
        ));
    }
    let length = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid frame length"))?,
    ) as usize;
    if length > MAX_PLANNER_COMPONENT_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical planner frame body exceeds 64 MiB",
        ));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok((header[8], body))
}

fn parse_frame(bytes: &[u8]) -> Result<(u8, &[u8]), CanonicalPlannerProcessError> {
    if bytes.len() < FRAME_HEADER_BYTES || &bytes[..8] != FRAME_MAGIC || bytes[9..12] != [0, 0, 0] {
        return Err(CanonicalPlannerProcessError::ProtocolViolation(
            "canonical planner response header is invalid",
        ));
    }
    let length = u32::from_be_bytes(bytes[12..16].try_into().map_err(|_| {
        CanonicalPlannerProcessError::ProtocolViolation(
            "canonical planner response length is invalid",
        )
    })?) as usize;
    if length > MAX_PLANNER_COMPONENT_MESSAGE_BYTES
        || bytes.len() != FRAME_HEADER_BYTES.saturating_add(length)
    {
        return Err(CanonicalPlannerProcessError::ProtocolViolation(
            "canonical planner response body length is invalid",
        ));
    }
    if bytes[8] == REJECTION_KIND && length > MAX_REJECTION_BYTES {
        return Err(CanonicalPlannerProcessError::ProtocolViolation(
            "canonical planner rejection exceeds 4 KiB",
        ));
    }
    Ok((bytes[8], &bytes[FRAME_HEADER_BYTES..]))
}

fn capture_bounded(mut reader: impl Read, maximum_bytes: usize) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
    let mut overflow = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = maximum_bytes.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        overflow |= retained != read;
    }
    Ok(CapturedOutput { bytes, overflow })
}

fn bounded_rejection(error: &str) -> String {
    let mut end = error.len().min(MAX_REJECTION_BYTES);
    while !error.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    error[..end].to_owned()
}

fn terminate_and_reap(child: &mut Child) {
    let already_exited = child.try_wait().ok().flatten().is_some();
    if !already_exited {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn worker_failed(status: ExitStatus, stderr: CapturedOutput) -> CanonicalPlannerProcessError {
    let mut diagnostic = String::from_utf8_lossy(&stderr.bytes).into_owned();
    if stderr.overflow {
        diagnostic.push_str(" [truncated]");
    }
    CanonicalPlannerProcessError::WorkerFailed {
        status: status.code(),
        diagnostic,
    }
}

fn join_worker<T>(
    worker: thread::JoinHandle<T>,
    name: &'static str,
) -> Result<T, CanonicalPlannerProcessError> {
    worker
        .join()
        .map_err(|_| CanonicalPlannerProcessError::ThreadPanicked(name))
}

fn process_io(operation: &'static str, source: io::Error) -> CanonicalPlannerProcessError {
    CanonicalPlannerProcessError::Io { operation, source }
}

// Monotonic process time bounds only operational worker lifetime. It never
// enters planner input, output, content identity, or deterministic fuel.
#[allow(clippy::disallowed_methods)]
fn process_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests;
