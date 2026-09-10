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
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use aos_sandbox_linux::process::{
    ExchangeStep, FixedLiveChild, FixedProcessControlInterest, FixedProcessControlReadiness,
    FixedProcessRequest, FixedProcessSessionExchange, FixedProcessSessionOutcome,
    FixedProcessSessionRequest, run_fixed_process_session,
};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

const CHILD_ARGUMENT: &str = "--fixed-session-child";

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(CHILD_ARGUMENT)) {
        child();
        return;
    }

    assert_eq!(
        task_count(),
        1,
        "qualification process is not single-threaded"
    );
    staged_public_exchange();
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
