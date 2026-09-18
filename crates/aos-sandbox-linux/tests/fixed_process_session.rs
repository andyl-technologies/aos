//! Single-thread executable proof for the public fixed-process session entry.
//!
//! A standard libtest binary retains a harness thread while running a test.
//! This harness-free target enters the public supervisor from an actually
//! single-threaded process and uses a child mode of the same fixed executable.

#![allow(
    clippy::expect_used,
    reason = "A harness-free qualification executable fails by terminating."
)]
#![allow(
    clippy::unwrap_used,
    reason = "A harness-free qualification executable fails by terminating."
)]

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::Duration;

use aos_sandbox_linux::process::{
    ExchangeStep, FixedLiveChild, FixedProcessControlInterest, FixedProcessControlReadiness,
    FixedProcessRequest, FixedProcessSessionExchange, FixedProcessSessionOutcome,
    FixedProcessSessionRequest, run_fixed_process_session,
    run_fixed_process_session_from_executable_descriptor,
};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

const CHILD_ARGUMENT: &str = "--fixed-session-child";
const DESCRIPTOR_CHILD_ARGUMENT: &str = "--fixed-descriptor-child";

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(CHILD_ARGUMENT)) {
        child();
        return;
    }
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(DESCRIPTOR_CHILD_ARGUMENT))
    {
        descriptor_child();
        return;
    }

    assert_eq!(
        task_count(),
        1,
        "qualification process is not single-threaded"
    );
    staged_public_exchange();
    descriptor_execution_ignores_path_substitution();
    descriptor_exec_failure_is_reaped_before_return();
}

fn descriptor_execution_ignores_path_substitution() {
    let directory = tempfile::tempdir().expect("create descriptor fixture directory");
    let executable_path = directory.path().join("fixed-helper");
    let replacement_path = directory.path().join("replacement");
    let current_executable = std::env::current_exe().expect("resolve qualification executable");
    std::fs::copy(&current_executable, &executable_path).expect("copy retained helper");
    std::fs::set_permissions(&executable_path, std::fs::Permissions::from_mode(0o555))
        .expect("protect retained helper");
    let executable = File::open(&executable_path).expect("open retained helper");

    std::fs::write(&replacement_path, b"hostile non-executable replacement")
        .expect("write hostile replacement");
    std::fs::set_permissions(&replacement_path, std::fs::Permissions::from_mode(0o555))
        .expect("protect hostile replacement");
    std::fs::rename(&replacement_path, &executable_path).expect("substitute helper pathname");

    let expected_argv0 = executable_path.as_os_str().to_owned();
    let parent_bounding = process_status_field("CapBnd");
    let arguments = [
        OsString::from(DESCRIPTOR_CHILD_ARGUMENT),
        expected_argv0.clone(),
    ];
    let (control, _unused_peer) = control_pair();
    let null = File::open("/dev/null").expect("open inherited descriptor fixture");
    let inherited = (0..3)
        .map(|_| {
            null.as_fd()
                .try_clone_to_owned()
                .expect("duplicate inherited fixture")
        })
        .collect();
    let mut exchange = ImmediateExchange::default();
    let outcome = run_fixed_process_session_from_executable_descriptor(
        FixedProcessSessionRequest {
            process: FixedProcessRequest {
                executable: Path::new(&expected_argv0),
                arguments: &arguments,
                timeout: Duration::from_secs(2),
                maximum_stdout_bytes: 4096,
                maximum_stderr_bytes: 4096,
            },
            stdin: None,
            inherited,
            control: control.as_fd(),
        },
        executable.into(),
        &mut exchange,
    )
    .expect("execute retained descriptor after pathname substitution");

    let FixedProcessSessionOutcome::Completed {
        process,
        exchange: value,
    } = outcome
    else {
        panic!("descriptor-backed child did not complete")
    };
    assert_eq!(value, "descriptor-qualified");
    assert_eq!(process.exit_code, Some(0));
    assert_eq!(process.signal, None);
    assert!(process.stderr.is_empty());
    assert_eq!(
        String::from_utf8(process.stdout).expect("child output is UTF-8"),
        format!("descriptor-qualified\nCapBnd={parent_bounding}\n")
    );
    assert_eq!(exchange.starts, 1);
}

fn descriptor_exec_failure_is_reaped_before_return() {
    let directory = tempfile::tempdir().expect("create failed-exec fixture directory");
    let executable_path = directory.path().join("invalid-executable");
    std::fs::write(&executable_path, b"not an executable image")
        .expect("write invalid executable fixture");
    std::fs::set_permissions(&executable_path, std::fs::Permissions::from_mode(0o555))
        .expect("protect invalid executable fixture");
    let executable = File::open(&executable_path).expect("open invalid executable fixture");
    let (control, _unused_peer) = control_pair();
    let mut exchange = ImmediateExchange::default();

    assert!(
        run_fixed_process_session_from_executable_descriptor(
            FixedProcessSessionRequest {
                process: FixedProcessRequest {
                    executable: &executable_path,
                    arguments: &[],
                    timeout: Duration::from_secs(2),
                    maximum_stdout_bytes: 4096,
                    maximum_stderr_bytes: 4096,
                },
                stdin: None,
                inherited: Vec::new(),
                control: control.as_fd(),
            },
            executable.into(),
            &mut exchange,
        )
        .is_err()
    );
    assert_eq!(exchange.starts, 0);
    assert!(
        current_children().is_empty(),
        "failed exec left a child unreaped"
    );
}

#[derive(Default)]
struct ImmediateExchange {
    starts: usize,
}

impl FixedProcessSessionExchange for ImmediateExchange {
    type Output = &'static str;
    type Error = std::io::Error;

    fn start(
        &mut self,
        _child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
    ) -> std::io::Result<ExchangeStep<Self::Output>> {
        self.starts += 1;
        Ok(ExchangeStep::Complete("descriptor-qualified"))
    }

    fn advance(
        &mut self,
        _child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
        _readiness: FixedProcessControlReadiness,
    ) -> std::io::Result<ExchangeStep<Self::Output>> {
        Err(std::io::Error::other("completed exchange advanced"))
    }
}

fn descriptor_child() {
    let expected_argv0 = std::env::args_os().nth(2).expect("expected argv0 argument");
    assert_eq!(
        std::env::args_os().next().as_deref(),
        Some(expected_argv0.as_os_str())
    );

    let executable = std::fs::metadata("/proc/self/exe").expect("inspect running executable");
    let descriptor = std::fs::metadata("/proc/self/fd/6").expect("inspect executable FD 6");
    assert_eq!(
        (descriptor.dev(), descriptor.ino()),
        (executable.dev(), executable.ino())
    );
    for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(
            process_status_field(field),
            "0000000000000000",
            "{field} is not empty"
        );
    }
    assert_eq!(process_status_field("NoNewPrivs"), "1");
    assert_eq!(open_descriptor_numbers(), vec![0, 1, 2, 3, 4, 5, 6]);

    println!("descriptor-qualified");
    println!("CapBnd={}", process_status_field("CapBnd"));
}

fn process_status_field(name: &str) -> String {
    let status = std::fs::read_to_string("/proc/self/status").expect("read process status");
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix(':'))
                .map(str::trim)
        })
        .unwrap_or_else(|| panic!("process status omitted {name}"))
        .to_owned()
}

fn open_descriptor_numbers() -> Vec<i32> {
    let directory = std::fs::read_dir("/proc/self/fd").expect("open descriptor directory");
    let mut descriptors = directory
        .filter_map(|entry| {
            let entry = entry.expect("read descriptor directory");
            entry.file_name().to_string_lossy().parse::<i32>().ok()
        })
        .collect::<Vec<_>>();
    descriptors.sort_unstable();
    let directory_descriptors = descriptors.split_off(7);
    assert_eq!(directory_descriptors.len(), 1);
    descriptors
}

fn current_children() -> String {
    let task = std::fs::read_dir("/proc/self/task")
        .expect("open process task directory")
        .next()
        .expect("process has one task")
        .expect("read process task")
        .file_name();
    std::fs::read_to_string(Path::new("/proc/self/task").join(task).join("children"))
        .expect("read child inventory")
        .trim()
        .to_owned()
}

fn staged_public_exchange() {
    let (control, child_control) = control_pair();
    let executable = std::env::current_exe().expect("resolve qualification executable");
    let arguments = [OsString::from(CHILD_ARGUMENT)];
    let mut exchange = StagedExchange::default();
    let outcome = run_fixed_process_session(
        FixedProcessSessionRequest {
            process: FixedProcessRequest {
                executable: &executable,
                arguments: &arguments,
                timeout: Duration::from_secs(2),
                maximum_stdout_bytes: 4096,
                maximum_stderr_bytes: 4096,
            },
            stdin: None,
            inherited: vec![child_control],
            control: control.as_fd(),
        },
        &mut exchange,
    )
    .expect("run public fixed-process session");

    let FixedProcessSessionOutcome::Completed {
        process,
        exchange: value,
    } = outcome
    else {
        panic!("public fixed-process session did not complete")
    };
    assert_eq!(value, "qualified");
    assert_eq!(process.exit_code, Some(0));
    assert_eq!(process.signal, None);
    assert_eq!(process.stdout, b"firstsecond");
    assert!(process.stderr.is_empty());
    assert_eq!(exchange.starts, 1);
    assert_eq!(exchange.advances, 2);
}

#[derive(Default)]
struct StagedExchange {
    starts: usize,
    advances: usize,
    phase: usize,
}

impl FixedProcessSessionExchange for StagedExchange {
    type Output = &'static str;
    type Error = std::io::Error;

    fn start(
        &mut self,
        child: &FixedLiveChild<'_>,
        control: BorrowedFd<'_>,
    ) -> std::io::Result<ExchangeStep<Self::Output>> {
        self.starts += 1;
        assert!(child.initial_info().pid() > 0);
        assert!(child.pidfd().is_alive().expect("observe live child"));
        send_record(control, b"S")?;
        Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
    }

    fn advance(
        &mut self,
        child: &FixedLiveChild<'_>,
        control: BorrowedFd<'_>,
        readiness: FixedProcessControlReadiness,
    ) -> std::io::Result<ExchangeStep<Self::Output>> {
        self.advances += 1;
        assert!(readiness.is_readable());
        assert!(!readiness.is_writable());
        assert!(child.pidfd().is_alive().expect("reobserve live child"));

        let record = receive_record(control)?;
        if self.phase == 0 {
            assert_eq!(record, b"A");
            send_record(control, b"C")?;
            self.phase = 1;
            return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable));
        }

        assert_eq!(record, b"B");
        send_record(control, b"K")?;
        Ok(ExchangeStep::Complete("qualified"))
    }
}

fn child() {
    // SAFETY: the public request maps the transferred child endpoint to FD 3
    // and no other code in this single-thread mode owns that table entry.
    let control = unsafe { BorrowedFd::borrow_raw(3) };
    assert_eq!(receive_record_waiting(control), b"S");
    write_standard_output(b"first");
    send_record_waiting(control, b"A");
    assert_eq!(receive_record_waiting(control), b"C");
    write_standard_output(b"second");
    send_record_waiting(control, b"B");
    assert_eq!(receive_record_waiting(control), b"K");
}

fn control_pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .expect("create session control pair")
}

fn send_record(descriptor: BorrowedFd<'_>, payload: &[u8]) -> std::io::Result<()> {
    match rustix::io::write(descriptor, payload) {
        Ok(count) if count == payload.len() => Ok(()),
        Ok(_) => Err(std::io::Error::other("partial sequenced-packet send")),
        Err(source) => Err(source.into()),
    }
}

fn receive_record(descriptor: BorrowedFd<'_>) -> std::io::Result<Vec<u8>> {
    let mut payload = [0_u8; 16];
    match rustix::io::read(descriptor, &mut payload) {
        Ok(count) => Ok(payload[..count].to_vec()),
        Err(source) => Err(source.into()),
    }
}

fn send_record_waiting(descriptor: BorrowedFd<'_>, payload: &[u8]) {
    loop {
        match send_record(descriptor, payload) {
            Ok(()) => return,
            Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(source) => panic!("child send failed: {source}"),
        }
    }
}

fn receive_record_waiting(descriptor: BorrowedFd<'_>) -> Vec<u8> {
    loop {
        match receive_record(descriptor) {
            Ok(record) => return record,
            Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(source) => panic!("child receive failed: {source}"),
        }
    }
}

fn write_standard_output(mut payload: &[u8]) {
    while !payload.is_empty() {
        // SAFETY: stdout is the live pipe installed by the fixed supervisor and
        // the slice remains readable for the complete call.
        let written =
            unsafe { libc::write(libc::STDOUT_FILENO, payload.as_ptr().cast(), payload.len()) };
        assert!(written > 0, "child stdout write failed");
        payload = &payload[usize::try_from(written).unwrap()..];
    }
}

fn task_count() -> usize {
    std::fs::read_dir(Path::new("/proc/self/task"))
        .expect("open process task directory")
        .count()
}
