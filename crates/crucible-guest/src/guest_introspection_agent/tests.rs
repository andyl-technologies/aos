//! Regression tests for the in-guest introspection agent.

use std::io::Cursor;
use std::time::Duration;

use super::*;

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("synthetic output failure"))
    }
}

#[test]
fn features_match_configured_capabilities() {
    let config = match GuestIntrospectionAgentConfig::new(
        3,
        Some(vec![String::from("/guest/sshd"), String::from("-i")]),
    ) {
        Ok(config) => config,
        Err(error) => panic!("valid config failed: {error}"),
    };
    let agent = match GuestIntrospectionAgent::new(config) {
        Ok(agent) => agent,
        Err(error) => panic!("agent construction failed: {error}"),
    };
    let features = agent.pending.front().map(GuestIntrospectionRecord::message);
    assert!(matches!(
        features,
        Some(GuestIntrospectionMessage::Features(features))
            if features.argv_exec()
                && features.pty()
                && features.resize()
                && features.ssh_bridge()
                && features.max_channels() == 3
    ));
}

#[test]
fn invalid_configuration_fails_closed() {
    assert!(GuestIntrospectionAgentConfig::new(0, None).is_err());
    assert!(
        GuestIntrospectionAgentConfig::new(GUEST_INTROSPECTION_MAX_CHANNELS + 1, None).is_err()
    );
    assert!(GuestIntrospectionAgentConfig::new(1, Some(Vec::new())).is_err());
}

#[test]
fn channel_failure_is_reported_without_terminating_agent() {
    let mut agent = GuestIntrospectionAgent::new(GuestIntrospectionAgentConfig::default())
        .unwrap_or_else(|error| panic!("agent construction failed: {error}"));
    let request = GuestIntrospectionRecord::new(7, GuestIntrospectionMessage::Input(vec![1, 2, 3]))
        .unwrap_or_else(|error| panic!("request construction failed: {error}"));
    let error = match agent.handle_request(request) {
        Ok(()) => panic!("unknown channel unexpectedly succeeded"),
        Err(error) => error,
    };
    agent
        .queue_channel_error(7, &error, false)
        .unwrap_or_else(|error| panic!("queue channel error failed: {error}"));

    assert_eq!(agent.pending.len(), 2);
    assert!(matches!(
        agent.pending.back().map(GuestIntrospectionRecord::message),
        Some(GuestIntrospectionMessage::Error {
            code: GuestIntrospectionFailureCode::UnknownChannel,
            ..
        })
    ));
    assert!(agent.channels.is_empty());
}

#[test]
fn output_reader_applies_fixed_backpressure() {
    let input = Cursor::new(vec![
        0xa5;
        GUEST_INTROSPECTION_MAX_CHUNK_BYTES
            * (GUEST_INTROSPECTION_READER_CAPACITY + 4)
    ]);
    let mut reader = output_reader(GuestOutputStream::Stdout, input, false);
    thread::sleep(Duration::from_millis(10));
    assert!(reader.join.as_ref().is_some_and(|join| !join.is_finished()));

    reader.receiver = None;
    if let Some(join) = reader.join.take() {
        join.join()
            .unwrap_or_else(|_panic| panic!("bounded output reader panicked"));
    }
}

#[test]
fn reader_round_robin_prevents_stdout_from_starving_stderr() {
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(GUEST_INTROSPECTION_READER_CAPACITY);
    let (stderr_sender, stderr_receiver) = mpsc::sync_channel(GUEST_INTROSPECTION_READER_CAPACITY);
    stdout_sender
        .send(OutputReaderEvent::Bytes(vec![1]))
        .unwrap_or_else(|_error| panic!("stdout fixture receiver closed"));
    stdout_sender
        .send(OutputReaderEvent::Bytes(vec![2]))
        .unwrap_or_else(|_error| panic!("stdout fixture receiver closed"));
    stderr_sender
        .send(OutputReaderEvent::Bytes(vec![3]))
        .unwrap_or_else(|_error| panic!("stderr fixture receiver closed"));
    let mut readers = vec![
        OutputReader {
            stream: GuestOutputStream::Stdout,
            receiver: Some(stdout_receiver),
            join: None,
            disconnected: false,
        },
        OutputReader {
            stream: GuestOutputStream::Stderr,
            receiver: Some(stderr_receiver),
            join: None,
            disconnected: false,
        },
    ];
    let mut cursor = 0;
    let first = drain_one_reader(&mut readers, &mut cursor)
        .unwrap_or_else(|error| panic!("first reader drain failed: {error}"));
    assert_eq!(first, Some((GuestOutputStream::Stdout, vec![1])));
    let second = drain_one_reader(&mut readers, &mut cursor)
        .unwrap_or_else(|error| panic!("second reader drain failed: {error}"));
    assert_eq!(second, Some((GuestOutputStream::Stderr, vec![3])));
}

#[test]
fn output_read_failure_becomes_typed_channel_failure() {
    let mut reader = output_reader(GuestOutputStream::Stdout, FailingReader, false);
    for _ in 0..100 {
        match reader.try_receive() {
            Err(GuestIntrospectionAgentError::Process { message }) => {
                assert!(message.contains("synthetic output failure"));
                if let Some(join) = reader.join.take() {
                    join.join()
                        .unwrap_or_else(|_panic| panic!("failing output reader thread panicked"));
                }
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(1)),
            Ok(Some(bytes)) => panic!("failing reader produced bytes: {bytes:?}"),
            Err(error) => panic!("unexpected reader failure: {error}"),
        }
    }
    panic!("output read failure was not delivered");
}

#[test]
fn full_output_backlog_defers_channel_error_without_stopping_agent() {
    let mut agent = GuestIntrospectionAgent::new(GuestIntrospectionAgentConfig::default())
        .unwrap_or_else(|error| panic!("agent construction failed: {error}"));
    agent.pending.clear();
    for index in 0..GUEST_INTROSPECTION_PENDING_CAPACITY {
        agent.pending.push_back(
            output_record(1, GuestOutputStream::Stdout, vec![index as u8])
                .unwrap_or_else(|error| panic!("output fixture failed: {error}")),
        );
    }
    let error = GuestIntrospectionAgentError::Process {
        message: String::from("synthetic reader failure"),
    };
    agent
        .queue_channel_error(7, &error, false)
        .unwrap_or_else(|error| panic!("defer channel error failed: {error}"));
    assert_eq!(agent.deferred_terminal.len(), 1);

    agent.pending.pop_front();
    agent
        .poll_children()
        .unwrap_or_else(|error| panic!("terminal promotion failed: {error}"));
    assert!(agent.deferred_terminal.is_empty());
    assert!(matches!(
        agent.pending.back().map(GuestIntrospectionRecord::message),
        Some(GuestIntrospectionMessage::Error {
            code: GuestIntrospectionFailureCode::ProcessIo,
            ..
        })
    ));
}

#[test]
fn pty_child_probe() {
    let selected_as_child =
        std::env::args().any(|arg| arg == "guest_introspection_agent::tests::pty_child_probe");
    // SAFETY: `isatty` only inspects the valid standard-input descriptor.
    if !selected_as_child || unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return;
    }
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `size` is writable for the duration of the ioctl.
    let status = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut size) };
    assert_eq!(status, 0);
    // SAFETY: `tcgetpgrp` inspects a valid terminal descriptor.
    let foreground_group = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
    // SAFETY: `getpgrp` has no preconditions.
    let process_group = unsafe { libc::getpgrp() };
    assert_eq!(foreground_group, process_group);
    println!("crucible-pty-probe:{}x{}", size.ws_col, size.ws_row);
}

#[test]
fn pty_process_has_a_controlling_terminal_and_owned_resize_handle() {
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| panic!("test executable path unavailable: {error}"));
    let argv = vec![
        executable.to_string_lossy().into_owned(),
        String::from("--exact"),
        String::from("guest_introspection_agent::tests::pty_child_probe"),
        String::from("--nocapture"),
    ];
    let mut channel = ActiveChannel::spawn(
        11,
        &argv,
        ChannelMode::Pty {
            columns: 91,
            rows: 37,
        },
    )
    .unwrap_or_else(|error| panic!("PTY child spawn failed: {error}"));
    channel
        .resize(92, 38)
        .unwrap_or_else(|error| panic!("PTY resize failed: {error}"));

    let mut pending = VecDeque::new();
    for _ in 0..1000 {
        channel
            .poll_status()
            .unwrap_or_else(|error| panic!("PTY child poll failed: {error}"));
        let mut budget = GUEST_INTROSPECTION_PENDING_CAPACITY;
        channel
            .drain_one_output(&mut pending, &mut budget)
            .unwrap_or_else(|error| panic!("PTY output drain failed: {error}"));
        if channel.is_complete() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(channel.is_complete(), "PTY child did not complete");
    channel
        .join_readers()
        .unwrap_or_else(|error| panic!("PTY reader join failed: {error}"));
    let output = pending
        .into_iter()
        .filter_map(|record| match record.message() {
            GuestIntrospectionMessage::Output { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert!(
        String::from_utf8_lossy(&output).contains("crucible-pty-probe:92x38"),
        "PTY child did not observe its controlling terminal and resize: {}",
        String::from_utf8_lossy(&output)
    );

    channel
        .close_input()
        .unwrap_or_else(|error| panic!("PTY close failed: {error}"));
    assert!(matches!(
        channel.resize(80, 24),
        Err(GuestIntrospectionAgentError::ClosedChannel { channel_id: 11 })
    ));
}

#[test]
// crucible-lint: allow rust-allow -- this regression fixture deliberately exits while a descendant retains its output descriptors.
#[allow(
    clippy::zombie_processes,
    reason = "the parent must exit without waiting so channel teardown can reap the inherited process group"
)]
fn inherited_output_descendant_probe() {
    let selected_as_child = std::env::args()
        .any(|arg| arg == "guest_introspection_agent::tests::inherited_output_descendant_probe");
    if !selected_as_child {
        return;
    }
    if std::env::var_os("CRUCIBLE_TEST_DESCENDANT").is_some() {
        thread::sleep(Duration::from_secs(30));
        return;
    }
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| panic!("test executable path unavailable: {error}"));
    let _descendant = Command::new(executable)
        .arg("--exact")
        .arg("guest_introspection_agent::tests::inherited_output_descendant_probe")
        .arg("--nocapture")
        .env("CRUCIBLE_TEST_DESCENDANT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("descendant probe spawn failed: {error}"));
}

#[test]
fn exec_completion_terminates_descendants_holding_output_open() {
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| panic!("test executable path unavailable: {error}"));
    let argv = vec![
        executable.to_string_lossy().into_owned(),
        String::from("--exact"),
        String::from("guest_introspection_agent::tests::inherited_output_descendant_probe"),
        String::from("--nocapture"),
    ];
    let mut channel = ActiveChannel::spawn(12, &argv, ChannelMode::Exec)
        .unwrap_or_else(|error| panic!("exec child spawn failed: {error}"));
    let mut pending = VecDeque::new();
    for _ in 0..1000 {
        channel
            .poll_status()
            .unwrap_or_else(|error| panic!("exec child poll failed: {error}"));
        let mut budget = GUEST_INTROSPECTION_PENDING_CAPACITY;
        channel
            .drain_one_output(&mut pending, &mut budget)
            .unwrap_or_else(|error| panic!("exec output drain failed: {error}"));
        if channel.is_complete() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        channel.is_complete(),
        "descendant holding output open prevented completion"
    );
    channel
        .join_readers()
        .unwrap_or_else(|error| panic!("exec reader join failed: {error}"));
}
