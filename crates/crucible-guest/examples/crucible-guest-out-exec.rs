//! Exercises original SDK frames in one Linux parent across an optional exec.
//!
//! The kernel command line selects `no-child`, `exec-child` or `late-register`.
//! One fixed parent buffer carries registration, setup, semantic and selectable
//! frames. The child has no SDK; its exact status/output precedes the second
//! semantic frame. This fixture makes no guest clock or fork ownership claim.

#![forbid(unsafe_code)]

use std::error::Error;
use std::process::{Command, ExitCode, ExitStatus};

use crucible_guest::{
    DoorbellTransport, GuestCommand, GuestEmitterError, InstructionDoorbellTransport, emit_command,
    emit_selectable_registration, request_selection,
};
use crucible_protocol::{SelectableRegister, SelectionRequest};

const SELECTABLE: &str = "out.ready";
const CAPACITY: usize = 512;
const CHILD_ARGUMENT: &str = "out-probe-no-sdk-v1";
const CHILD_OUTPUT: &[u8] = b"out-probe-child-v1\n";
const MAX_CHILD_OUTPUT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    NoChild,
    ExecChild,
    LateRegister,
}

impl Profile {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "no-child" => Ok(Self::NoChild),
            "exec-child" => Ok(Self::ExecChild),
            "late-register" => Ok(Self::LateRegister),
            _ => Err("unknown Linux OUT probe profile".into()),
        }
    }
}

struct ParentBuffer<T> {
    native: T,
    bytes: [u8; CAPACITY],
}

impl<T> ParentBuffer<T> {
    fn new(native: T) -> Self {
        Self {
            native,
            bytes: [0; CAPACITY],
        }
    }
}

impl<T: DoorbellTransport> DoorbellTransport for ParentBuffer<T> {
    fn ring(&mut self, frame: &mut [u8]) -> Result<(), GuestEmitterError> {
        let Some(buffer) = self.bytes.get_mut(..frame.len()) else {
            return Err(GuestEmitterError::Transport {
                message: "Linux OUT probe frame exceeds fixed parent buffer".into(),
            });
        };
        buffer.copy_from_slice(frame);
        self.native.ring(buffer)?;
        frame.copy_from_slice(buffer);
        Ok(())
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Linux OUT probe: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    if std::process::id() != 1 {
        return Err("Linux OUT probe must be the original init process".into());
    }
    let profile = Profile::parse(&std::env::var("crucible_out_probe")?)?;
    let mut transport = ParentBuffer::new(InstructionDoorbellTransport::native()?);
    exchange(profile, &mut transport, execute_child)?;
    loop {
        std::thread::park();
    }
}

fn exchange<T: DoorbellTransport>(
    profile: Profile,
    transport: &mut T,
    execute: impl FnOnce() -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let registration =
        SelectableRegister::new(1, SELECTABLE, vec![1], vec![1], vec!["readiness".into()])?;
    emit_selectable_registration(&registration, transport)?;
    emit_command(&GuestCommand::setup_complete(), transport)?;
    emit_command(
        &GuestCommand::semantic_marker("out.frame", "first", Vec::new()),
        transport,
    )?;
    request_selection(
        &SelectionRequest::new(2, SELECTABLE, "first", None, 128)?,
        transport,
    )?;

    match profile {
        Profile::ExecChild => execute()?,
        Profile::NoChild => {}
        Profile::LateRegister => {
            emit_selectable_registration(&registration, transport)?;
            return Err("late registration unexpectedly returned".into());
        }
    }

    emit_command(
        &GuestCommand::semantic_marker("out.frame", "second", Vec::new()),
        transport,
    )?;
    request_selection(
        &SelectionRequest::new(3, SELECTABLE, "second", None, 128)?,
        transport,
    )?;
    Ok(())
}

fn execute_child() -> Result<(), Box<dyn Error>> {
    let output = Command::new("/out-probe-child")
        .arg(CHILD_ARGUMENT)
        .output()?;
    require_child_result(output.status, &output.stdout, &output.stderr)
}

fn require_child_result(
    status: ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), Box<dyn Error>> {
    if !status.success() || stdout.len() > MAX_CHILD_OUTPUT || stderr.len() > MAX_CHILD_OUTPUT {
        return Err("static no-SDK child failed or exceeded its output bound".into());
    }
    if stdout != CHILD_OUTPUT || !stderr.is_empty() {
        return Err("static no-SDK child returned unexpected bytes".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "crucible-guest-out-exec/tests.rs"]
mod tests;
