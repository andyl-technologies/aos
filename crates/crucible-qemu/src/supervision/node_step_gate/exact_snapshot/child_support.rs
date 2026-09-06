//! Diagnostics, placement checks, and error helpers shared by the live
//! hot-fork flights.
//!
//! A child that dies before its private QMP greeting is otherwise opaque, so
//! these helpers read its procfs state, quote its diagnostics stream, attach
//! the configured debugger for backtraces, and report how the source reaped
//! it; the placement check holds a child to its dedicated cgroup and
//! unprivileged credentials.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::child_files::{CHILD_REAP_POLL_INTERVAL, CHILD_REAP_POLLS, CHILD_USER_ID};
use super::*;
use crate::{QemuHotForkChildDiagnosticConsumer, QmpHotForkChildProcessPhase};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) length: u64,
    pub(super) modified: Option<std::time::SystemTime>,
}

pub(super) fn file_identity(path: &Path) -> Result<FileIdentity, QemuLiveNodeStepGateError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        fs::metadata(path).map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

pub(super) fn child_open_files(
    process_id: u32,
) -> Result<BTreeSet<(u64, u64)>, QemuLiveNodeStepGateError> {
    use std::os::unix::fs::MetadataExt as _;

    let directory = PathBuf::from(format!("/proc/{process_id}/fd"));
    let entries = fs::read_dir(&directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: directory.clone(),
            source,
        }
    })?;
    let mut files = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: directory.clone(),
            source,
        })?;
        // Descriptors the child is closing race with this scan; skip the ones
        // that vanish and keep every regular file that remains open.
        if let Ok(metadata) = fs::metadata(entry.path())
            && metadata.is_file()
        {
            files.insert((metadata.dev(), metadata.ino()));
        }
    }
    Ok(files)
}

/// Summarizes a forked child's state and cgroup for a failure report.
///
/// The child may already be a zombie or gone; every field degrades to the
/// error that prevented reading it rather than failing the report.
pub(super) fn describe_forked_child(process_id: i64) -> String {
    let process = PathBuf::from(format!("/proc/{process_id}"));
    let status = fs::read_to_string(process.join("status"))
        .map(|status| {
            status
                .lines()
                .filter(|line| {
                    line.starts_with("State:")
                        || line.starts_with("PPid:")
                        || line.starts_with("Uid:")
                })
                .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|source| format!("status unavailable: {source}"));
    let cgroup = fs::read_to_string(process.join("cgroup"))
        .map(|membership| membership.trim().to_owned())
        .unwrap_or_else(|source| format!("cgroup unavailable: {source}"));
    let tasks = describe_child_tasks(&process);
    let backtraces = describe_child_backtraces(process_id);
    format!("child {process_id}: {status}; cgroup {cgroup}; tasks [{tasks}]{backtraces}")
}

/// Quotes what the child wrote on its diagnostics stream while the source
/// still retains the consumer, as it does when retention itself failed.
pub(super) fn describe_retained_child_diagnostics(node: &mut QemuNode) -> String {
    match node.retained_hot_fork_child_diagnostics() {
        Ok(bytes) => format!("child diagnostics: {:?}", String::from_utf8_lossy(&bytes)),
        Err(source) => format!("child diagnostics unavailable: {source}"),
    }
}

/// Quotes what the child wrote on its diagnostics stream through the consumer
/// the launch transferred to this owner.
pub(super) fn describe_child_diagnostics(
    diagnostics: &mut QemuHotForkChildDiagnosticConsumer,
) -> String {
    match diagnostics.drain_available() {
        Ok(_drained) => format!(
            "child diagnostics: {:?}",
            String::from_utf8_lossy(diagnostics.retained())
        ),
        Err(source) => format!("child diagnostics unavailable: {source}"),
    }
}

/// Environment variable naming a debugger that can attach to the child.
///
/// The flight's failure report then carries every child thread's backtrace,
/// which is the only view into a reconstruction that stalls before the
/// child's private QMP greeting.
const CHILD_DEBUGGER_ENVIRONMENT: &str = "CRUCIBLE_HOT_FORK_CHILD_DEBUGGER";

/// A debugger attached to the live child and continued, so that a death by
/// signal during the watched operation is reported with a backtrace.
pub(super) struct ChildDebuggerWatch {
    debugger: std::process::Child,
}

impl ChildDebuggerWatch {
    /// Attaches the configured debugger to the child and lets it run.
    ///
    /// Returns `None` when no debugger is configured or it cannot start.
    pub(super) fn attach(process_id: u32) -> Option<Self> {
        let debugger = std::env::var_os(CHILD_DEBUGGER_ENVIRONMENT)?;
        let debugger = std::process::Command::new(&debugger)
            .args(["--nx", "--batch", "-p", &process_id.to_string()])
            .args(["-ex", "set pagination off"])
            .args(["-ex", "continue"])
            .args(["-ex", "thread apply all bt 24"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .ok()?;
        Some(Self { debugger })
    }

    /// Waits briefly for the debugger to report, detaches it otherwise, and
    /// returns whatever it printed.
    pub(super) fn finish(mut self) -> String {
        // A bounded poll rather than a clock: host monotonic time stays out
        // of this crate, and the debugger reports within moments of a death.
        for _poll in 0..100 {
            match self.debugger.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_source) => break,
            }
        }
        let _killed = self.debugger.kill();
        match self.debugger.wait_with_output() {
            Ok(output) => format!(
                "; debugger watch (status {}):\n{}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(source) => format!("; debugger watch unavailable: {source}"),
        }
    }
}

/// Collects every child thread's backtrace through the configured debugger.
///
/// Returns an empty string when no debugger is configured; a debugger that
/// fails to attach reports its output rather than failing the report.
fn describe_child_backtraces(process_id: i64) -> String {
    let Some(debugger) = std::env::var_os(CHILD_DEBUGGER_ENVIRONMENT) else {
        return String::new();
    };
    let output = std::process::Command::new(&debugger)
        .args(["--nx", "--batch", "-p", &process_id.to_string()])
        .args(["-ex", "set pagination off"])
        .args(["-ex", "thread apply all bt 24"])
        .output();
    match output {
        Ok(output) => format!(
            "; backtraces (status {}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(source) => format!("; backtraces unavailable: {source}"),
    }
}

/// Lists a child's threads with their state, wait channel, and current syscall.
///
/// The flight runs with enough privilege to read these, and a child that
/// never greets on its private QMP endpoint is otherwise opaque.
fn describe_child_tasks(process: &Path) -> String {
    let Ok(entries) = fs::read_dir(process.join("task")) else {
        return String::from("tasks unavailable");
    };
    let maps = fs::read_to_string(process.join("maps")).unwrap_or_default();
    // Names the mapping that holds a syscall argument such as a futex word,
    // which separates the binary's own statics from heap and thread arenas.
    let locate = |argument: &str| {
        let Some(address) = argument
            .strip_prefix("0x")
            .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        else {
            return String::from("?");
        };
        maps.lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let range = fields.next()?;
                let (start, end) = range.split_once('-')?;
                let start = u64::from_str_radix(start, 16).ok()?;
                let end = u64::from_str_radix(end, 16).ok()?;
                (start <= address && address < end).then(|| {
                    let offset = fields.nth(1).unwrap_or("?");
                    let path = fields.nth(2).unwrap_or("[anon]");
                    format!("{path}+{offset}+{:#x}", address - start)
                })
            })
            .unwrap_or_else(|| String::from("unmapped"))
    };
    let mut tasks = Vec::new();
    for entry in entries.flatten() {
        let task = entry.path();
        let read = |name: &str| {
            fs::read_to_string(task.join(name))
                .map(|value| {
                    value
                        .split_whitespace()
                        .take(6)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_else(|_source| String::from("?"))
        };
        // Fields after the command name: state is the first and the start
        // time in clock ticks is the twentieth, which orders unnamed threads
        // by creation.
        let (state, started) = fs::read_to_string(task.join("stat"))
            .ok()
            .and_then(|stat| {
                let tail = stat.rsplit(')').next()?;
                let fields: Vec<&str> = tail.split_whitespace().collect();
                Some((
                    fields.first().copied().unwrap_or("?").to_owned(),
                    fields.get(19).copied().unwrap_or("?").to_owned(),
                ))
            })
            .unwrap_or_else(|| (String::from("?"), String::from("?")));
        let syscall = read("syscall");
        let waited_on = syscall
            .split_whitespace()
            .nth(1)
            .map(locate)
            .unwrap_or_else(|| String::from("?"));
        tasks.push(format!(
            "{} {} {} started={} wchan={} syscall={} at={}",
            entry.file_name().to_string_lossy(),
            read("comm"),
            state,
            started,
            read("wchan"),
            syscall,
            waited_on
        ));
    }
    tasks.join("; ")
}

/// Reports how the source reaped a child that could not be retained.
///
/// A child that failed reconstruction exits with 64 plus its failed step
/// index; the source owns `waitpid` and reports it through the child-process
/// query on its own nonblocking cadence, so this polls with the same bound as
/// the teardown path.
pub(super) fn describe_reaped_child(node: &mut QemuNode, generation: u64) -> String {
    for poll in 0..CHILD_REAP_POLLS {
        let state = match node.query_hot_fork_child_process(generation) {
            Ok(state) => state,
            Err(source) => return format!("child status query failed: {source}"),
        };
        if state.phase() != QmpHotForkChildProcessPhase::Running {
            return format!(
                "source reaped child as {:?} with status {}",
                state.phase(),
                state.status()
            );
        }
        if poll + 1 < CHILD_REAP_POLLS {
            std::thread::sleep(CHILD_REAP_POLL_INTERVAL);
        }
    }
    String::from("source did not reap the child in time")
}

pub(super) fn verify_child_placement(
    process_id: u32,
    cgroup_root: &Path,
) -> Result<(), QemuLiveNodeStepGateError> {
    let process = PathBuf::from(format!("/proc/{process_id}"));
    let membership = fs::read_to_string(process.join("cgroup")).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: process.join("cgroup"),
            source,
        }
    })?;
    let relative = membership
        .trim()
        .strip_prefix("0::/")
        .ok_or_else(|| invariant("child is not in a unified cgroup"))?;
    let group = Path::new("/sys/fs/cgroup").join(relative);
    if group.parent() != Some(cgroup_root) {
        return Err(invariant(&format!(
            "child escaped the dedicated cgroup root: {}",
            group.display()
        )));
    }
    let status = fs::read_to_string(process.join("status")).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: process.join("status"),
            source,
        }
    })?;
    let expected = CHILD_USER_ID.to_string();
    for key in ["Uid:", "Gid:"] {
        let unprivileged = status
            .lines()
            .find(|line| line.starts_with(key))
            .is_some_and(|line| line.split_whitespace().skip(1).all(|id| id == expected));
        if !unprivileged {
            return Err(invariant(
                "child does not run with the unprivileged credentials",
            ));
        }
    }
    Ok(())
}

pub(super) fn wait_for_child_exit(
    node: &mut QemuNode,
    generation: u64,
) -> Result<(), QemuLiveNodeStepGateError> {
    // Bounded polling keeps host wall time out of the state path; the source
    // parent reaps the killed child on its own nonblocking waitpid cadence.
    for poll in 0..CHILD_REAP_POLLS {
        let state = node
            .query_hot_fork_child_process(generation)
            .map_err(|source| qmp_operation("query hot-fork child status", source))?;
        if state.phase() != QmpHotForkChildProcessPhase::Running {
            return Ok(());
        }
        if poll + 1 < CHILD_REAP_POLLS {
            std::thread::sleep(CHILD_REAP_POLL_INTERVAL);
        }
    }
    Err(invariant("killed hot-fork child was not reaped in time"))
}

pub(super) fn realization(
    operation: &'static str,
    source: crate::QemuVmRealizationError,
) -> QemuLiveNodeStepGateError {
    invariant(&format!("{operation} failed: {source}"))
}

pub(super) fn invariant(reason: &str) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: reason.to_owned(),
    }
}

pub(super) fn qmp_operation(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::node_op(
        operation,
        QemuNodeError::from_channel(crate::QemuNodeChannelPlane::QmpMachineControl, source),
    )
}
