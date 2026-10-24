//! Bounded campaign-service stderr and process-state diagnostics.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::os::unix::process::ExitStatusExt;

use super::*;

pub(super) fn matching_lines_bounded(
    reader: impl Read,
    prefix: &str,
    maximum_lines: usize,
    maximum_line_bytes: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    matching_lines(reader, prefix, maximum_lines, maximum_line_bytes, false)
}

/// Streams all stderr while retaining only the latest bounded matching records.
pub(super) fn recent_matching_lines_bounded(
    reader: impl Read,
    prefix: &str,
    maximum_lines: usize,
    maximum_line_bytes: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    matching_lines(reader, prefix, maximum_lines, maximum_line_bytes, true)
}

fn matching_lines(
    mut reader: impl Read,
    prefix: &str,
    maximum_lines: usize,
    maximum_line_bytes: usize,
    retain_recent: bool,
) -> Result<Vec<String>, Box<dyn Error>> {
    if prefix.is_empty() || maximum_lines == 0 || maximum_line_bytes < prefix.len() {
        return Err("stderr prefix capture has invalid bounds".into());
    }

    let prefix = prefix.as_bytes();
    let mut lines = VecDeque::new();
    let mut chunk = [0_u8; 8 * 1024];
    let mut matched_prefix_bytes = 0;
    let mut possible_match = true;
    let mut matching_line = None::<Vec<u8>>;

    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }

        for &byte in &chunk[..count] {
            if byte == b'\n' {
                finish_matching_line(&mut matching_line, &mut lines, maximum_lines, retain_recent)?;
                matched_prefix_bytes = 0;
                possible_match = true;
                continue;
            }

            if let Some(line) = &mut matching_line {
                if line.len() == maximum_line_bytes {
                    return Err(format!(
                        "stderr record beginning with `{}` exceeds {maximum_line_bytes} bytes",
                        String::from_utf8_lossy(prefix)
                    )
                    .into());
                }
                line.push(byte);
                continue;
            }

            if !possible_match || byte != prefix[matched_prefix_bytes] {
                possible_match = false;
                continue;
            }

            matched_prefix_bytes += 1;
            if matched_prefix_bytes == prefix.len() {
                matching_line = Some(prefix.to_vec());
            }
        }
    }

    finish_matching_line(&mut matching_line, &mut lines, maximum_lines, retain_recent)?;
    Ok(lines.into_iter().collect())
}

fn finish_matching_line(
    matching_line: &mut Option<Vec<u8>>,
    lines: &mut VecDeque<String>,
    maximum_lines: usize,
    retain_recent: bool,
) -> Result<(), Box<dyn Error>> {
    let Some(mut line) = matching_line.take() else {
        return Ok(());
    };
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if lines.len() == maximum_lines {
        if !retain_recent {
            return Err(format!("stderr prefix capture exceeds {maximum_lines} records").into());
        }
        lines.pop_front();
    }

    lines.push_back(String::from_utf8(line)?);
    Ok(())
}

#[test]
fn recent_prefix_capture_retains_late_records_after_capacity_and_large_unrelated_lines() {
    const PREFIX: &str = "CRUCIBLE-CONTROL-CALLBACK-V1 ";
    let unrelated = "x".repeat(32 * 1024);
    let mut stderr = String::new();
    for token in 0..100 {
        writeln!(stderr, "{PREFIX}token={token}")
            .unwrap_or_else(|error| panic!("test stderr should format: {error}"));
        writeln!(stderr, "{unrelated}")
            .unwrap_or_else(|error| panic!("test stderr should format: {error}"));
    }

    let records = recent_matching_lines_bounded(std::io::Cursor::new(stderr), PREFIX, 2, 256)
        .unwrap_or_else(|error| panic!("recent witness records should parse: {error}"));

    assert_eq!(
        records,
        [format!("{PREFIX}token=98"), format!("{PREFIX}token=99")]
    );
}

#[test]
fn recent_prefix_capture_enforces_line_size_utf8_and_valid_bounds() {
    const PREFIX: &str = "witness ";
    for (stderr, capacity, line_bytes) in [
        (b"witness oversized\n".as_slice(), 2, 8),
        (b"witness \xff\n".as_slice(), 2, 256),
        (b"witness ok\n".as_slice(), 0, 256),
        (b"witness ok\n".as_slice(), 2, 1),
    ] {
        assert!(
            recent_matching_lines_bounded(
                std::io::Cursor::new(stderr),
                PREFIX,
                capacity,
                line_bytes
            )
            .is_err()
        );
    }
}

#[test]
fn stderr_prefix_capture_survives_unrelated_tail_output() {
    const PREFIX: &str = "CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 ";
    let source = format!("{PREFIX}stage=source-discovery attempt=source");
    let replay = format!("{PREFIX}stage=replay attempt=branch");
    // Start the prefix one byte before the scanner's internal chunk boundary.
    let mut stderr = vec![b'x'; 8 * 1024 - 2];
    stderr.push(b'\n');
    stderr.extend_from_slice(source.as_bytes());
    stderr.extend_from_slice(b"\nunrelated diagnostic\n");
    stderr.extend_from_slice(replay.as_bytes());
    stderr.extend_from_slice(b"\n");
    stderr.extend(std::iter::repeat_n(
        b'y',
        2 * usize::try_from(MAX_CAMPAIGN_SERVICE_STDERR_BYTES).unwrap(),
    ));

    let lines = matching_lines_bounded(std::io::Cursor::new(stderr), PREFIX, 2, 256)
        .expect("capture exact prefixed records");

    assert_eq!(lines, [source, replay]);
}

#[test]
fn stderr_prefix_capture_enforces_exact_record_and_line_bounds() {
    const PREFIX: &str = "BOUNDARY ";
    const MAXIMUM_LINE_BYTES: usize = 32;
    let exact_line = format!("{PREFIX}{}", "x".repeat(MAXIMUM_LINE_BYTES - PREFIX.len()));
    let two_lines = format!("{exact_line}\n{PREFIX}second\n");

    let lines = matching_lines_bounded(
        std::io::Cursor::new(two_lines.as_bytes()),
        PREFIX,
        2,
        MAXIMUM_LINE_BYTES,
    )
    .expect("accept exact record and line bounds");
    assert_eq!(lines, [exact_line.clone(), format!("{PREFIX}second")]);

    let too_many = format!("{two_lines}{PREFIX}third\n");
    assert!(
        matching_lines_bounded(
            std::io::Cursor::new(too_many.as_bytes()),
            PREFIX,
            2,
            MAXIMUM_LINE_BYTES,
        )
        .is_err()
    );

    let oversized = format!("{exact_line}x\n");
    assert!(
        matching_lines_bounded(
            std::io::Cursor::new(oversized.as_bytes()),
            PREFIX,
            2,
            MAXIMUM_LINE_BYTES,
        )
        .is_err()
    );
}

type ProcessCommand = (u32, Vec<String>);

/// Samples only the process tree reached through the owned root's task children.
pub(super) fn descendant_process_commands(
    root_pid: u32,
) -> Result<Vec<ProcessCommand>, Box<dyn Error>> {
    if root_pid == 0 {
        return Err("descendant census requires an owned process ID".into());
    }

    let mut descendants = BTreeSet::from([root_pid]);
    let mut pending = VecDeque::from([root_pid]);
    while let Some(parent_pid) = pending.pop_front() {
        let tasks = match fs::read_dir(format!("/proc/{parent_pid}/task")) {
            Ok(tasks) => tasks,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        // A child belongs to its creating task; the thread-group leader's
        // children file alone would miss births on the service's other threads.
        for task in tasks {
            let task = match task {
                Ok(task) => task,
                Err(error) if process_disappeared(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let children = match fs::read_to_string(task.path().join("children")) {
                Ok(children) => children,
                Err(error) if process_disappeared(&error) && !task.path().try_exists()? => continue,
                Err(error) => return Err(error.into()),
            };
            for child in children.split_whitespace() {
                let child_pid = child.parse::<u32>()?;
                if child_pid == 0 {
                    return Err("task children contained an invalid process ID".into());
                }
                if descendants.insert(child_pid) {
                    pending.push_back(child_pid);
                }
            }
        }
    }

    let mut commands = Vec::new();
    for pid in descendants.into_iter().filter(|pid| *pid != root_pid) {
        let command_line = match fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(command_line) => command_line,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let arguments = command_line
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect::<Vec<_>>();
        commands.push((pid, arguments));
    }
    Ok(commands)
}

fn process_disappeared(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

const CENSUS_TEST_NAME: &str = "descendant_census_follows_owned_thread_births_only";
const CENSUS_ROLE: &str = "CRUCIBLE_DESCENDANT_CENSUS_ROLE";
const CENSUS_DIRECTORY: &str = "CRUCIBLE_DESCENDANT_CENSUS_DIRECTORY";
const CENSUS_READY: &str = "CRUCIBLE_DESCENDANT_CENSUS_READY";

fn census_test_path() -> Result<String, Box<dyn Error>> {
    // This file is both a standalone integration target and a nested gate module.
    let (_, module) = module_path!()
        .split_once("::")
        .ok_or("census helper is missing its containing module")?;
    Ok(format!("{module}::{CENSUS_TEST_NAME}"))
}

/// Keeps every directly owned probe child available for cleanup on assertion failure.
struct CensusChild(Child, PathBuf);

impl CensusChild {
    fn spawn(directory: &Path, role: &str, ready: &str) -> Result<Self, Box<dyn Error>> {
        let test_path = census_test_path()?;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", test_path.as_str(), "--nocapture", "--test-threads=1"])
            .env(CENSUS_ROLE, role)
            .env(CENSUS_DIRECTORY, directory)
            .env(CENSUS_READY, directory.join(ready))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let returned = directory.join(format!("reaped-{}", child.id()));
        Ok(Self(child, returned))
    }

    fn finish(&mut self) -> Result<(), Box<dyn Error>> {
        self.0
            .stdin
            .as_mut()
            .ok_or("probe stdin is absent")?
            .write_all(b"x")?;
        assert!(wait_for_exit(&mut self.0, Duration::from_secs(5))?.success());
        Ok(())
    }
}

impl Drop for CensusChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }

        // EOF lets each nested owner run its own child guard before we resort
        // to killing this direct child. Forced exit cannot prove subtree reap.
        drop(self.0.stdin.take());
        let (disposition, status) = match wait_for_exit(&mut self.0, Duration::from_secs(5)) {
            Ok(status) => ("cooperative", status),
            Err(_) => {
                let _ = self.0.kill();
                match wait_for_exit(&mut self.0, Duration::from_secs(5)) {
                    Ok(status) => ("forced", status),
                    Err(_) => return,
                }
            }
        };
        // Publish only the actual direct-child wait output, after it returned.
        // The negative control requires each nested owner to publish its own.
        let record = format!("{} {disposition} {}\n", self.0.id(), status.into_raw());
        let _ = publish_census_record(&self.1, record.as_bytes());
    }
}

fn publish_census_record(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    // Each actor owns a distinct record; rename exposes its complete contents.
    let pending = path.with_extension("pending");
    fs::write(&pending, bytes)?;
    fs::rename(pending, path)?;
    Ok(())
}

fn run_census_branch(directory: &Path, child_role: &str, record: &str) -> Result<(), Box<dyn Error>> {
    let mut child = CensusChild::spawn(directory, child_role, "leaf-ready")?;
    publish_census_record(&directory.join(record), child.0.id().to_string().as_bytes())?;
    let mut proceed = [0_u8; 1];
    std::io::stdin().read_exact(&mut proceed)?;
    child.finish()
}

#[test]
fn descendant_census_follows_owned_thread_births_only() -> Result<(), Box<dyn Error>> {
    if let Some(role) = std::env::var_os(CENSUS_ROLE) {
        let directory = PathBuf::from(
            std::env::var_os(CENSUS_DIRECTORY).ok_or("probe directory absent")?,
        );
        if role == "branch" || role == "middle" {
            let (child_role, record) = if role == "branch" {
                ("middle", "branch-ready")
            } else {
                ("leaf", "middle-ready")
            };
            // Keep each creating nonleader task alive until its child is reaped.
            return thread::spawn(move || {
                run_census_branch(&directory, child_role, record).map_err(|error| error.to_string())
            })
            .join()
            .map_err(|_| "probe creator thread panicked")?
            .map_err(Into::into);
        }
        assert_eq!(role, "leaf");
        let ready = PathBuf::from(
            std::env::var_os(CENSUS_READY).ok_or("probe readiness path absent")?,
        );
        publish_census_record(&ready, b"ready")?;
        let mut proceed = [0_u8; 1];
        std::io::stdin().read_exact(&mut proceed)?;
        return Ok(());
    }

    let directory = tempfile::tempdir()?;
    let mut branch = CensusChild::spawn(directory.path(), "branch", "unused")?;
    let mut sibling = CensusChild::spawn(directory.path(), "leaf", "sibling-ready")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !["branch-ready", "middle-ready", "leaf-ready", "sibling-ready"]
        .iter()
        .all(|name| directory.path().join(name).exists())
    {
        assert!(
            branch.0.try_wait()?.is_none(),
            "branch exited before readiness"
        );
        assert!(
            sibling.0.try_wait()?.is_none(),
            "sibling exited before readiness"
        );
        if Instant::now() >= deadline {
            return Err("owned census probes did not become ready".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    let middle_pid = fs::read_to_string(directory.path().join("branch-ready"))?.parse::<u32>()?;
    let leaf_pid = fs::read_to_string(directory.path().join("middle-ready"))?.parse::<u32>()?;
    let commands = descendant_process_commands(branch.0.id())?;
    let observed = commands.iter().map(|(pid, _)| *pid).collect::<BTreeSet<_>>();
    assert_eq!(commands.len(), 2);
    assert_eq!(observed, BTreeSet::from([middle_pid, leaf_pid]));
    let test_path = census_test_path()?;
    assert!(
        commands
            .iter()
            .all(|(_, arguments)| arguments.iter().any(|argument| argument == &test_path))
    );
    assert!(!observed.contains(&sibling.0.id()));
    assert!(!observed.contains(&branch.0.id()));

    branch.finish()?;
    sibling.finish()?;
    Ok(())
}

#[test]
fn descendant_census_error_path_reaps_owned_tree_cooperatively() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut branch = CensusChild::spawn(directory.path(), "branch", "unused")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !["branch-ready", "middle-ready", "leaf-ready"]
        .iter()
        .all(|name| directory.path().join(name).exists())
    {
        assert!(
            branch.0.try_wait()?.is_none(),
            "branch exited before negative-control readiness"
        );
        if Instant::now() >= deadline {
            return Err("owned census probes did not become ready".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    let branch_pid = branch.0.id();
    let middle_pid = fs::read_to_string(directory.path().join("branch-ready"))?.parse::<u32>()?;
    let leaf_pid = fs::read_to_string(directory.path().join("middle-ready"))?.parse::<u32>()?;
    let known = BTreeSet::from([branch_pid, middle_pid, leaf_pid]);
    assert_eq!(known.len(), 3);

    // Refuse the ready setup without finish(): leaving this scope must close
    // stdin and run the real recursive guards, rather than the success path.
    let refused: Result<(), Box<dyn Error>> = {
        let _owned_branch = branch;
        Err("intentional refusal after actual tree readiness".into())
    };
    assert_eq!(
        refused.unwrap_err().to_string(),
        "intentional refusal after actual tree readiness"
    );

    for pid in known {
        let record = fs::read_to_string(directory.path().join(format!("reaped-{pid}")))?;
        let fields = record.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].parse::<u32>()?, pid);
        assert_eq!(
            fields[1], "cooperative",
            "force fallback is not recursive reap proof"
        );
        let status = fields[2].parse::<i32>()?;
        assert!(
            libc::WIFEXITED(status),
            "expected an actual EOF-driven normal exit"
        );
    }
    Ok(())
}
