//! Bounded campaign-service stderr and process-state diagnostics.

use std::fmt::Write as _;

use super::*;

pub(super) fn matching_lines_bounded(
    mut reader: impl Read,
    prefix: &str,
    maximum_lines: usize,
    maximum_line_bytes: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    if prefix.is_empty() || maximum_lines == 0 || maximum_line_bytes < prefix.len() {
        return Err("stderr prefix capture has invalid bounds".into());
    }

    let prefix = prefix.as_bytes();
    let mut lines = Vec::new();
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
                finish_matching_line(&mut matching_line, &mut lines, maximum_lines)?;
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

    finish_matching_line(&mut matching_line, &mut lines, maximum_lines)?;
    Ok(lines)
}

fn finish_matching_line(
    matching_line: &mut Option<Vec<u8>>,
    lines: &mut Vec<String>,
    maximum_lines: usize,
) -> Result<(), Box<dyn Error>> {
    let Some(mut line) = matching_line.take() else {
        return Ok(());
    };
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if lines.len() == maximum_lines {
        return Err(format!("stderr prefix capture exceeds {maximum_lines} records").into());
    }

    lines.push(String::from_utf8(line)?);
    Ok(())
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

pub(super) fn append_process_diagnostics(diagnostics: &mut String) {
    diagnostics.push_str("; processes=[");
    let Ok(entries) = fs::read_dir("/proc") else {
        diagnostics.push_str("<proc-unreadable>]");
        return;
    };
    let mut process_directories = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .collect::<Vec<_>>();
    process_directories.sort_by_key(|entry| entry.file_name());
    for entry in process_directories {
        let process = entry.path();
        let command = fs::read(process.join("cmdline"))
            .map(|bytes| {
                String::from_utf8_lossy(&bytes)
                    .replace('\0', " ")
                    .trim()
                    .to_owned()
            })
            .unwrap_or_default();
        if !command.contains("crucible")
            && !command.contains("qemu-system")
            && !command.contains("campaign_store_process")
        {
            continue;
        }
        let status = fs::read_to_string(process.join("status"))
            .unwrap_or_else(|_| String::from("<status-unreadable>"));
        let wait_channel = fs::read_to_string(process.join("wchan"))
            .unwrap_or_else(|_| String::from("<wchan-unreadable>"));
        let _ = write!(
            diagnostics,
            "pid={} cmd={command:?} wchan={:?} status={status:?}; ",
            entry.file_name().to_string_lossy(),
            wait_channel.trim(),
        );
        append_thread_waits(diagnostics, &process);
        append_descriptor_state(diagnostics, &process);
    }
    diagnostics.push(']');
}

fn append_thread_waits(diagnostics: &mut String, process: &Path) {
    diagnostics.push_str("threads=[");
    if let Ok(tasks) = fs::read_dir(process.join("task")) {
        let mut tasks = tasks.filter_map(Result::ok).collect::<Vec<_>>();
        tasks.sort_by_key(|task| task.file_name());
        for task in tasks.into_iter().take(64) {
            let name = fs::read_to_string(task.path().join("comm"))
                .unwrap_or_else(|_| String::from("<comm-unreadable>"));
            let wait = fs::read_to_string(task.path().join("wchan"))
                .unwrap_or_else(|_| String::from("<wchan-unreadable>"));
            let _ = write!(
                diagnostics,
                "tid={} name={:?} wchan={:?};",
                task.file_name().to_string_lossy(),
                name.trim(),
                wait.trim(),
            );
        }
    } else {
        diagnostics.push_str("<tasks-unreadable>");
    }
    diagnostics.push_str("]; ");
}

fn append_descriptor_state(diagnostics: &mut String, process: &Path) {
    diagnostics.push_str("fds=[");
    if let Ok(descriptors) = fs::read_dir(process.join("fd")) {
        let mut descriptors = descriptors.filter_map(Result::ok).collect::<Vec<_>>();
        descriptors.sort_by_key(|descriptor| descriptor.file_name());
        for descriptor in descriptors.into_iter().take(128) {
            let target = fs::read_link(descriptor.path())
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| String::from("<target-unreadable>"));
            let info = fs::read_to_string(process.join("fdinfo").join(descriptor.file_name()))
                .unwrap_or_default();
            let eventfd_count = info
                .lines()
                .find(|line| line.starts_with("eventfd-count:"))
                .unwrap_or("");
            let _ = write!(
                diagnostics,
                "fd={} target={target:?} {eventfd_count};",
                descriptor.file_name().to_string_lossy(),
            );
        }
    } else {
        diagnostics.push_str("<fds-unreadable>");
    }
    diagnostics.push_str("]; ");
}

type ProcessCommand = (u32, Vec<String>);

pub(super) fn descendant_process_commands(
    root_pid: u32,
) -> Result<Vec<ProcessCommand>, Box<dyn Error>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")?.filter_map(Result::ok) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(parent_pid) = process_parent_pid(&stat) else {
            continue;
        };
        processes.push((pid, parent_pid, entry.path()));
    }

    let mut descendants = BTreeSet::from([root_pid]);
    loop {
        let previous_count = descendants.len();
        for (pid, parent_pid, _path) in &processes {
            if descendants.contains(parent_pid) {
                descendants.insert(*pid);
            }
        }
        if descendants.len() == previous_count {
            break;
        }
    }

    let mut commands = Vec::new();
    for (pid, _parent_pid, path) in processes {
        if pid == root_pid || !descendants.contains(&pid) {
            continue;
        }
        let Ok(command_line) = fs::read(path.join("cmdline")) else {
            continue;
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

fn process_parent_pid(stat: &str) -> Option<u32> {
    let after_name = stat.rsplit_once(") ")?.1;
    after_name.split_whitespace().nth(1)?.parse().ok()
}
