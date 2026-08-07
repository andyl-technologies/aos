//! In-guest argv exec, PTY, and SSH-compatible introspection service.
//!
//! The service polls through the existing deterministic doorbell instruction.
//! It never opens a host shell: every child is created inside the guest from an
//! explicit argv vector, and the optional SSH bridge launches an in-guest
//! server in stdio mode.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};

use crate::DoorbellTransport;
use crucible_protocol::guest_introspection::{
    GUEST_INTROSPECTION_FEATURE_CHANNEL_ID, GUEST_INTROSPECTION_MAX_CHUNK_BYTES,
    GUEST_INTROSPECTION_MAX_ERROR_BYTES, GuestIntrospectionFailureCode, GuestIntrospectionFeatures,
    GuestIntrospectionMessage, GuestIntrospectionRecord, GuestOutputStream,
};
use crucible_protocol::guest_introspection_doorbell::{
    GuestIntrospectionDoorbellFrame, GuestIntrospectionDoorbellKind,
};
mod error;

pub use error::GuestIntrospectionAgentError;

/// Default maximum concurrent guest child processes.
pub const GUEST_INTROSPECTION_DEFAULT_MAX_CHANNELS: u16 = 8;
/// Hard process bound matching the transport's fixed request/response capacity.
pub const GUEST_INTROSPECTION_MAX_CHANNELS: u16 = 64;

const GUEST_INTROSPECTION_PENDING_CAPACITY: usize = 64;
const GUEST_INTROSPECTION_READER_CAPACITY: usize = 2;
const GUEST_INTROSPECTION_IDLE_SPINS: usize = 4096;

/// Runtime configuration for the in-guest introspection service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIntrospectionAgentConfig {
    max_channels: u16,
    ssh_argv: Option<Vec<String>>,
}

impl GuestIntrospectionAgentConfig {
    /// Builds a service configuration.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionAgentError::Configuration`] when the channel
    /// bound is outside `1..=64` or an SSH argv vector is empty or contains
    /// empty entries.
    pub fn new(
        max_channels: u16,
        ssh_argv: Option<Vec<String>>,
    ) -> Result<Self, GuestIntrospectionAgentError> {
        if max_channels == 0 || max_channels > GUEST_INTROSPECTION_MAX_CHANNELS {
            return Err(GuestIntrospectionAgentError::Configuration {
                message: format!(
                    "guest introspection max channels must be in 1..={GUEST_INTROSPECTION_MAX_CHANNELS}"
                ),
            });
        }
        if ssh_argv
            .as_ref()
            .is_some_and(|argv| argv.is_empty() || argv.iter().any(String::is_empty))
        {
            return Err(GuestIntrospectionAgentError::Configuration {
                message: String::from("SSH bridge argv must contain only nonempty entries"),
            });
        }
        Ok(Self {
            max_channels,
            ssh_argv,
        })
    }

    /// Returns the configured channel limit.
    #[must_use]
    pub const fn max_channels(&self) -> u16 {
        self.max_channels
    }

    /// Returns the optional in-guest SSH stdio command.
    #[must_use]
    pub fn ssh_argv(&self) -> Option<&[String]> {
        self.ssh_argv.as_deref()
    }

    fn features(&self) -> GuestIntrospectionFeatures {
        GuestIntrospectionFeatures::new(
            true,
            true,
            true,
            self.ssh_argv.is_some(),
            self.max_channels,
        )
    }
}

impl Default for GuestIntrospectionAgentConfig {
    fn default() -> Self {
        Self {
            max_channels: GUEST_INTROSPECTION_DEFAULT_MAX_CHANNELS,
            ssh_argv: None,
        }
    }
}

/// Runs the guest introspection service until its doorbell transport fails.
///
/// # Errors
///
/// Returns [`GuestIntrospectionAgentError`] for a malformed plugin reply,
/// process/PTY failure, or doorbell transport error.
pub fn run_guest_introspection_agent<T>(
    config: GuestIntrospectionAgentConfig,
    transport: &mut T,
) -> Result<(), GuestIntrospectionAgentError>
where
    T: DoorbellTransport + ?Sized,
{
    let mut agent = GuestIntrospectionAgent::new(config)?;
    loop {
        agent.poll_children()?;
        let response_pending = agent.pending.front().is_some();
        let outgoing = agent
            .pending
            .front()
            .cloned()
            .map_or_else(GuestIntrospectionDoorbellFrame::poll, |record| {
                GuestIntrospectionDoorbellFrame::response(record)
            });
        let mut buffer = outgoing.encode().map_err(protocol_error)?.to_vec();
        transport
            .ring(&mut buffer)
            .map_err(GuestIntrospectionAgentError::Doorbell)?;
        let incoming = GuestIntrospectionDoorbellFrame::decode(&buffer).map_err(protocol_error)?;
        match incoming.kind() {
            GuestIntrospectionDoorbellKind::Idle => {
                if response_pending {
                    agent.pending.pop_front();
                }
                deterministic_idle_backoff();
            }
            GuestIntrospectionDoorbellKind::Request => {
                if response_pending {
                    agent.pending.pop_front();
                }
                let record = incoming.record().cloned().ok_or_else(|| {
                    GuestIntrospectionAgentError::Protocol {
                        message: String::from("request exchange omitted its record"),
                    }
                })?;
                record.validate_host_request().map_err(protocol_error)?;
                let channel_id = record.channel_id();
                let opening_request = matches!(
                    record.message(),
                    GuestIntrospectionMessage::Exec { .. }
                        | GuestIntrospectionMessage::Pty { .. }
                        | GuestIntrospectionMessage::Ssh { .. }
                );
                if let Err(error) = agent.handle_request(record) {
                    agent.terminate_channel(channel_id);
                    agent.queue_channel_error(channel_id, &error, opening_request)?;
                }
            }
            GuestIntrospectionDoorbellKind::Retry if response_pending => {
                deterministic_idle_backoff();
            }
            GuestIntrospectionDoorbellKind::Retry => {
                return Err(GuestIntrospectionAgentError::Protocol {
                    message: String::from("plugin requested retry for an empty guest response"),
                });
            }
            GuestIntrospectionDoorbellKind::Poll | GuestIntrospectionDoorbellKind::Response => {
                return Err(GuestIntrospectionAgentError::Protocol {
                    message: String::from("plugin returned a guest-to-plugin exchange kind"),
                });
            }
        }
    }
}

fn deterministic_idle_backoff() {
    for _ in 0..GUEST_INTROSPECTION_IDLE_SPINS {
        std::hint::spin_loop();
    }
}

struct GuestIntrospectionAgent {
    config: GuestIntrospectionAgentConfig,
    channels: BTreeMap<u64, ActiveChannel>,
    pending: VecDeque<GuestIntrospectionRecord>,
    deferred_terminal: VecDeque<GuestIntrospectionRecord>,
    channel_cursor: usize,
}

impl GuestIntrospectionAgent {
    fn new(config: GuestIntrospectionAgentConfig) -> Result<Self, GuestIntrospectionAgentError> {
        let features = GuestIntrospectionRecord::new(
            GUEST_INTROSPECTION_FEATURE_CHANNEL_ID,
            GuestIntrospectionMessage::Features(config.features()),
        )
        .map_err(protocol_error)?;
        Ok(Self {
            config,
            channels: BTreeMap::new(),
            pending: VecDeque::from([features]),
            deferred_terminal: VecDeque::new(),
            channel_cursor: 0,
        })
    }

    fn handle_request(
        &mut self,
        record: GuestIntrospectionRecord,
    ) -> Result<(), GuestIntrospectionAgentError> {
        let channel_id = record.channel_id();
        match record.message() {
            GuestIntrospectionMessage::Exec { argv, .. } => {
                self.open_channel(channel_id, argv, ChannelMode::Exec)
            }
            GuestIntrospectionMessage::Pty {
                argv,
                columns,
                rows,
                ..
            } => self.open_channel(
                channel_id,
                argv,
                ChannelMode::Pty {
                    columns: *columns,
                    rows: *rows,
                },
            ),
            GuestIntrospectionMessage::Ssh { .. } => {
                let argv = self.config.ssh_argv.clone().ok_or_else(|| {
                    GuestIntrospectionAgentError::Unsupported {
                        message: String::from("SSH bridge requested but not advertised"),
                    }
                })?;
                self.open_channel(channel_id, &argv, ChannelMode::Ssh)
            }
            GuestIntrospectionMessage::Input(bytes) => {
                self.channel_mut(channel_id)?.write_input(bytes)
            }
            GuestIntrospectionMessage::Resize { columns, rows } => {
                self.channel_mut(channel_id)?.resize(*columns, *rows)
            }
            GuestIntrospectionMessage::Close => self.channel_mut(channel_id)?.close_input(),
            GuestIntrospectionMessage::Features(_)
            | GuestIntrospectionMessage::Output { .. }
            | GuestIntrospectionMessage::Exit { .. }
            | GuestIntrospectionMessage::Error { .. } => {
                Err(GuestIntrospectionAgentError::Protocol {
                    message: String::from("host sent a guest-to-host message kind"),
                })
            }
        }
    }

    fn channel_mut(
        &mut self,
        channel_id: u64,
    ) -> Result<&mut ActiveChannel, GuestIntrospectionAgentError> {
        self.channels
            .get_mut(&channel_id)
            .ok_or(GuestIntrospectionAgentError::UnknownChannel { channel_id })
    }

    fn open_channel(
        &mut self,
        channel_id: u64,
        argv: &[String],
        mode: ChannelMode,
    ) -> Result<(), GuestIntrospectionAgentError> {
        if channel_id == GUEST_INTROSPECTION_FEATURE_CHANNEL_ID {
            return Err(GuestIntrospectionAgentError::Protocol {
                message: String::from("feature channel identifier is reserved"),
            });
        }
        if self.channels.contains_key(&channel_id) {
            return Err(GuestIntrospectionAgentError::DuplicateChannel { channel_id });
        }
        if self.channels.len() >= usize::from(self.config.max_channels) {
            return Err(GuestIntrospectionAgentError::ChannelLimit {
                maximum: self.config.max_channels,
            });
        }
        let channel = ActiveChannel::spawn(channel_id, argv, mode)?;
        self.channels.insert(channel_id, channel);
        Ok(())
    }

    fn poll_children(&mut self) -> Result<(), GuestIntrospectionAgentError> {
        self.promote_deferred_terminal();
        let channel_ids = self.channels.keys().copied().collect::<Vec<_>>();
        let mut failures = Vec::new();
        for channel_id in channel_ids {
            let result = self
                .channels
                .get_mut(&channel_id)
                .ok_or(GuestIntrospectionAgentError::UnknownChannel { channel_id })?
                .poll_status();
            if let Err(error) = result {
                failures.push((channel_id, error));
            }
        }
        for (channel_id, error) in failures {
            self.terminate_channel(channel_id);
            self.queue_channel_error(channel_id, &error, false)?;
        }

        self.emit_completed_channels()?;

        if self.pending.len() < GUEST_INTROSPECTION_PENDING_CAPACITY {
            let mut budget = GUEST_INTROSPECTION_PENDING_CAPACITY - self.pending.len();
            let channel_ids = self.channels.keys().copied().collect::<Vec<_>>();
            let start = self.channel_cursor % channel_ids.len().max(1);
            let mut output_failures = Vec::new();
            for offset in 0..channel_ids.len() {
                let channel_id = channel_ids[(start + offset) % channel_ids.len()];
                let result = self
                    .channels
                    .get_mut(&channel_id)
                    .ok_or(GuestIntrospectionAgentError::UnknownChannel { channel_id })?
                    .drain_one_output(&mut self.pending, &mut budget);
                if let Err(error) = result {
                    output_failures.push((channel_id, error));
                }
                if budget == 0 {
                    break;
                }
            }
            if !channel_ids.is_empty() {
                self.channel_cursor = (start + 1) % channel_ids.len();
            }
            for (channel_id, error) in output_failures {
                self.terminate_channel(channel_id);
                self.queue_channel_error(channel_id, &error, false)?;
            }
        }

        self.emit_completed_channels()?;
        Ok(())
    }

    fn emit_completed_channels(&mut self) -> Result<(), GuestIntrospectionAgentError> {
        while self.pending.len() < GUEST_INTROSPECTION_PENDING_CAPACITY {
            let Some(channel_id) = self
                .channels
                .iter()
                .find_map(|(channel_id, channel)| channel.is_complete().then_some(*channel_id))
            else {
                break;
            };
            let mut channel = self
                .channels
                .remove(&channel_id)
                .ok_or(GuestIntrospectionAgentError::UnknownChannel { channel_id })?;
            let status = match channel.take_exit_status() {
                Some(status) => status,
                None => {
                    let error = GuestIntrospectionAgentError::Process {
                        message: String::from("completed guest channel omitted exit status"),
                    };
                    self.queue_channel_error(channel_id, &error, false)?;
                    continue;
                }
            };
            if let Err(error) = channel.join_readers() {
                self.queue_channel_error(channel_id, &error, false)?;
            } else {
                self.pending.push_back(exit_record(channel_id, status)?);
            }
        }
        Ok(())
    }

    fn queue_channel_error(
        &mut self,
        channel_id: u64,
        error: &GuestIntrospectionAgentError,
        opening_request: bool,
    ) -> Result<(), GuestIntrospectionAgentError> {
        let record = GuestIntrospectionRecord::new(
            channel_id,
            GuestIntrospectionMessage::Error {
                code: channel_error_code(error, opening_request),
                message: bounded_error_message(error),
            },
        )
        .map_err(protocol_error)?;
        if self.pending.len() < GUEST_INTROSPECTION_PENDING_CAPACITY {
            self.pending.push_back(record);
        } else if self.deferred_terminal.len() < usize::from(GUEST_INTROSPECTION_MAX_CHANNELS) {
            self.deferred_terminal.push_back(record);
        } else {
            return Err(GuestIntrospectionAgentError::Protocol {
                message: String::from("guest introspection deferred terminal capacity exhausted"),
            });
        }
        Ok(())
    }

    fn promote_deferred_terminal(&mut self) {
        while self.pending.len() < GUEST_INTROSPECTION_PENDING_CAPACITY {
            let Some(record) = self.deferred_terminal.pop_front() else {
                break;
            };
            self.pending.push_back(record);
        }
    }

    fn terminate_channel(&mut self, channel_id: u64) {
        if let Some(mut channel) = self.channels.remove(&channel_id) {
            channel.shutdown();
        }
    }
}

impl Drop for GuestIntrospectionAgent {
    fn drop(&mut self) {
        for channel in self.channels.values_mut() {
            channel.shutdown();
        }
    }
}

#[derive(Clone, Copy)]
enum ChannelMode {
    Exec,
    Pty { columns: u16, rows: u16 },
    Ssh,
}

enum ChannelInput {
    Pipe(ChildStdin),
    Pty(File),
    Ssh(UnixStream),
}

struct OutputReader {
    stream: GuestOutputStream,
    receiver: Option<Receiver<OutputReaderEvent>>,
    join: Option<JoinHandle<()>>,
    disconnected: bool,
}

enum OutputReaderEvent {
    Bytes(Vec<u8>),
    Error(String),
}

struct ActiveChannel {
    channel_id: u64,
    child: Child,
    input: Option<ChannelInput>,
    readers: Vec<OutputReader>,
    pty_control: Option<File>,
    exit_status: Option<ExitStatus>,
    owns_process_group: bool,
    reaped: bool,
    reader_cursor: usize,
    exit_drain_polls: u16,
    descendants_killed: bool,
}

impl ActiveChannel {
    fn spawn(
        channel_id: u64,
        argv: &[String],
        mode: ChannelMode,
    ) -> Result<Self, GuestIntrospectionAgentError> {
        let (program, arguments) =
            argv.split_first()
                .ok_or_else(|| GuestIntrospectionAgentError::Protocol {
                    message: String::from("process argv must not be empty"),
                })?;
        match mode {
            ChannelMode::Exec => {
                let mut command = Command::new(program);
                command
                    .args(arguments)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                // SAFETY: `setsid` is async-signal-safe and gives every
                // channel a private process group for complete teardown.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() == -1 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(())
                        }
                    });
                }
                let mut child = command
                    .spawn()
                    .map_err(|error| process_error("spawn guest process", error))?;
                let input = child.stdin.take().ok_or_else(|| process_missing("stdin"))?;
                let stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| process_missing("stdout"))?;
                let stderr = child
                    .stderr
                    .take()
                    .ok_or_else(|| process_missing("stderr"))?;
                Ok(Self {
                    channel_id,
                    child,
                    input: Some(ChannelInput::Pipe(input)),
                    readers: vec![
                        output_reader(GuestOutputStream::Stdout, stdout, false),
                        output_reader(GuestOutputStream::Stderr, stderr, false),
                    ],
                    pty_control: None,
                    exit_status: None,
                    owns_process_group: true,
                    reaped: false,
                    reader_cursor: 0,
                    exit_drain_polls: 0,
                    descendants_killed: false,
                })
            }
            ChannelMode::Ssh => {
                let (host, guest) = UnixStream::pair()
                    .map_err(|error| process_error("create SSH socket pair", error))?;
                let host_input = host
                    .try_clone()
                    .map_err(|error| process_error("clone SSH host socket", error))?;
                let guest_stdin = guest
                    .try_clone()
                    .map_err(|error| process_error("clone SSH guest socket", error))?;
                let guest_stdin: OwnedFd = guest_stdin.into();
                let guest_stdout: OwnedFd = guest.into();
                let mut command = Command::new(program);
                command
                    .args(arguments)
                    .stdin(Stdio::from(guest_stdin))
                    .stdout(Stdio::from(guest_stdout))
                    .stderr(Stdio::piped());
                // SAFETY: `setsid` is async-signal-safe and gives the SSH
                // server a private process group for complete teardown.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() == -1 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(())
                        }
                    });
                }
                let mut child = command
                    .spawn()
                    .map_err(|error| process_error("spawn guest SSH server", error))?;
                let stderr = child
                    .stderr
                    .take()
                    .ok_or_else(|| process_missing("stderr"))?;
                Ok(Self {
                    channel_id,
                    child,
                    input: Some(ChannelInput::Ssh(host_input)),
                    readers: vec![
                        output_reader(GuestOutputStream::Stdout, host, false),
                        output_reader(GuestOutputStream::Stderr, stderr, false),
                    ],
                    pty_control: None,
                    exit_status: None,
                    owns_process_group: true,
                    reaped: false,
                    reader_cursor: 0,
                    exit_drain_polls: 0,
                    descendants_killed: false,
                })
            }
            ChannelMode::Pty { columns, rows } => {
                let (master, slave) = open_pty(columns, rows)?;
                let stdin = slave
                    .try_clone()
                    .map_err(|error| process_error("clone PTY slave", error))?;
                let stdout = slave
                    .try_clone()
                    .map_err(|error| process_error("clone PTY slave", error))?;
                let mut command = Command::new(program);
                command
                    .args(arguments)
                    .stdin(Stdio::from(stdin))
                    .stdout(Stdio::from(stdout))
                    .stderr(Stdio::from(slave));
                // SAFETY: the closure calls only async-signal-safe syscalls
                // between fork and exec. Standard input has already been
                // duplicated from the PTY slave by `Command` setup.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as libc::c_ulong, 0)
                            == -1
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let child = command
                    .spawn()
                    .map_err(|error| process_error("spawn guest PTY process", error))?;
                let input = master
                    .try_clone()
                    .map_err(|error| process_error("clone PTY master", error))?;
                let pty_control = master
                    .try_clone()
                    .map_err(|error| process_error("clone PTY control descriptor", error))?;
                Ok(Self {
                    channel_id,
                    child,
                    input: Some(ChannelInput::Pty(input)),
                    readers: vec![output_reader(GuestOutputStream::Stdout, master, true)],
                    pty_control: Some(pty_control),
                    exit_status: None,
                    owns_process_group: true,
                    reaped: false,
                    reader_cursor: 0,
                    exit_drain_polls: 0,
                    descendants_killed: false,
                })
            }
        }
    }

    fn write_input(&mut self, bytes: &[u8]) -> Result<(), GuestIntrospectionAgentError> {
        let input = self
            .input
            .as_mut()
            .ok_or(GuestIntrospectionAgentError::ClosedChannel {
                channel_id: self.channel_id,
            })?;
        match input {
            ChannelInput::Pipe(input) => input.write_all(bytes),
            ChannelInput::Pty(input) => input.write_all(bytes),
            ChannelInput::Ssh(input) => input.write_all(bytes),
        }
        .and_then(|()| match input {
            ChannelInput::Pipe(input) => input.flush(),
            ChannelInput::Pty(input) => input.flush(),
            ChannelInput::Ssh(input) => input.flush(),
        })
        .map_err(|error| process_error("write guest process input", error))
    }

    fn resize(&mut self, columns: u16, rows: u16) -> Result<(), GuestIntrospectionAgentError> {
        if self.input.is_none() {
            return Err(GuestIntrospectionAgentError::ClosedChannel {
                channel_id: self.channel_id,
            });
        }
        let control = self
            .pty_control
            .as_ref()
            .ok_or(GuestIntrospectionAgentError::NotPty {
                channel_id: self.channel_id,
            })?;
        set_pty_size(control.as_raw_fd(), columns, rows)
    }

    fn close_input(&mut self) -> Result<(), GuestIntrospectionAgentError> {
        if self.input.is_none() {
            return signal_process_group(
                &self.child,
                libc::SIGTERM,
                "terminate guest process after repeated close",
            );
        }
        let was_pty = matches!(self.input, Some(ChannelInput::Pty(_)));
        self.input = None;
        if was_pty {
            self.pty_control = None;
            signal_process_group(&self.child, libc::SIGHUP, "hang up guest PTY process")?;
        }
        Ok(())
    }

    fn drain_one_output(
        &mut self,
        pending: &mut VecDeque<GuestIntrospectionRecord>,
        budget: &mut usize,
    ) -> Result<(), GuestIntrospectionAgentError> {
        if *budget == 0 || self.readers.is_empty() {
            return Ok(());
        }
        if let Some((stream, bytes)) = drain_one_reader(&mut self.readers, &mut self.reader_cursor)?
        {
            pending.push_back(output_record(self.channel_id, stream, bytes)?);
            *budget -= 1;
        }
        Ok(())
    }

    fn poll_status(&mut self) -> Result<(), GuestIntrospectionAgentError> {
        if self.exit_status.is_none() {
            self.exit_status = self
                .child
                .try_wait()
                .map_err(|error| process_error("poll child", error))?;
            if self.exit_status.is_some() {
                self.reaped = true;
                if self.owns_process_group {
                    signal_process_group(
                        &self.child,
                        libc::SIGHUP,
                        "hang up remaining guest process descendants",
                    )?;
                }
            }
        } else if !self.descendants_killed && self.readers.iter().any(|reader| !reader.disconnected)
        {
            self.exit_drain_polls = self.exit_drain_polls.saturating_add(1);
            if self.exit_drain_polls >= 64 {
                signal_process_group(
                    &self.child,
                    libc::SIGKILL,
                    "kill guest descendants retaining channel output",
                )?;
                self.descendants_killed = true;
            }
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.exit_status.is_some() && self.readers.iter().all(|reader| reader.disconnected)
    }

    fn take_exit_status(&mut self) -> Option<ExitStatus> {
        self.exit_status.take()
    }

    fn join_readers(&mut self) -> Result<(), GuestIntrospectionAgentError> {
        for reader in &mut self.readers {
            if let Some(join) = reader.join.take() {
                join.join()
                    .map_err(|_panic| GuestIntrospectionAgentError::ReaderPanic {
                        channel_id: self.channel_id,
                    })?;
            }
        }
        Ok(())
    }

    fn shutdown(&mut self) {
        self.input = None;
        self.pty_control = None;
        if !self.reaped {
            if self.owns_process_group {
                let _result =
                    signal_process_group(&self.child, libc::SIGKILL, "kill guest process group");
            }
            let _result = self.child.kill();
            self.exit_status = self.child.wait().ok();
            self.reaped = true;
        }
        for reader in &mut self.readers {
            reader.receiver = None;
        }
        let _result = self.join_readers();
    }
}

impl Drop for ActiveChannel {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl OutputReader {
    fn try_receive(&mut self) -> Result<Option<Vec<u8>>, GuestIntrospectionAgentError> {
        let Some(receiver) = self.receiver.as_ref() else {
            self.disconnected = true;
            return Ok(None);
        };
        match receiver.try_recv() {
            Ok(OutputReaderEvent::Bytes(bytes)) => Ok(Some(bytes)),
            Ok(OutputReaderEvent::Error(message)) => {
                self.disconnected = true;
                Err(GuestIntrospectionAgentError::Process { message })
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.disconnected = true;
                Ok(None)
            }
        }
    }
}

fn drain_one_reader(
    readers: &mut [OutputReader],
    cursor: &mut usize,
) -> Result<Option<(GuestOutputStream, Vec<u8>)>, GuestIntrospectionAgentError> {
    if readers.is_empty() {
        return Ok(None);
    }
    let start = *cursor % readers.len();
    for offset in 0..readers.len() {
        let index = (start + offset) % readers.len();
        if let Some(bytes) = readers[index].try_receive()? {
            *cursor = (index + 1) % readers.len();
            return Ok(Some((readers[index].stream, bytes)));
        }
    }
    Ok(None)
}

fn output_reader(
    stream: GuestOutputStream,
    mut input: impl Read + Send + 'static,
    pty_eio_is_eof: bool,
) -> OutputReader {
    let (sender, receiver) = mpsc::sync_channel(GUEST_INTROSPECTION_READER_CAPACITY);
    let join = thread::spawn(move || {
        loop {
            let mut bytes = vec![0_u8; GUEST_INTROSPECTION_MAX_CHUNK_BYTES];
            match input.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => {
                    bytes.truncate(count);
                    if sender.send(OutputReaderEvent::Bytes(bytes)).is_err() {
                        break;
                    }
                }
                Err(error) if pty_eio_is_eof && error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => {
                    let _result = sender.send(OutputReaderEvent::Error(format!(
                        "read guest process output: {error}"
                    )));
                    break;
                }
            }
        }
    });
    OutputReader {
        stream,
        receiver: Some(receiver),
        join: Some(join),
        disconnected: false,
    }
}

fn signal_process_group(
    child: &Child,
    signal: libc::c_int,
    operation: &'static str,
) -> Result<(), GuestIntrospectionAgentError> {
    let pid =
        i32::try_from(child.id()).map_err(|_error| GuestIntrospectionAgentError::Process {
            message: String::from("guest child process identifier exceeds i32"),
        })?;
    // SAFETY: the PTY child created a process group whose identifier is its
    // positive child PID; negating it targets only that guest process group.
    let status = unsafe { libc::kill(-pid, signal) };
    if status == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(process_error(operation, error))
        }
    }
}

fn open_pty(columns: u16, rows: u16) -> Result<(File, File), GuestIntrospectionAgentError> {
    let mut master = -1;
    let mut slave = -1;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: output descriptors point to initialized integers, the optional
    // name/termios pointers are null, and `size` is readable for the call.
    let status = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::addr_of!(size).cast_mut(),
        )
    };
    if status != 0 {
        return Err(process_error(
            "open guest PTY",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful `openpty` returns two newly owned descriptors.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: successful `openpty` returns two newly owned descriptors.
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok((master, slave))
}

fn set_pty_size(fd: RawFd, columns: u16, rows: u16) -> Result<(), GuestIntrospectionAgentError> {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `fd` remains owned by the active PTY channel and `size` is a
    // readable `winsize` for the duration of the ioctl.
    let status = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) };
    if status == 0 {
        Ok(())
    } else {
        Err(process_error(
            "resize guest PTY",
            std::io::Error::last_os_error(),
        ))
    }
}

fn output_record(
    channel_id: u64,
    stream: GuestOutputStream,
    bytes: Vec<u8>,
) -> Result<GuestIntrospectionRecord, GuestIntrospectionAgentError> {
    GuestIntrospectionRecord::new(
        channel_id,
        GuestIntrospectionMessage::Output { stream, bytes },
    )
    .map_err(protocol_error)
}

fn exit_record(
    channel_id: u64,
    status: ExitStatus,
) -> Result<GuestIntrospectionRecord, GuestIntrospectionAgentError> {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    GuestIntrospectionRecord::new(
        channel_id,
        GuestIntrospectionMessage::Exit {
            status: status.code().unwrap_or(-1),
            signal: status
                .signal()
                .and_then(|signal| u32::try_from(signal).ok()),
        },
    )
    .map_err(protocol_error)
}

fn process_missing(stream: &'static str) -> GuestIntrospectionAgentError {
    GuestIntrospectionAgentError::Process {
        message: format!("spawned guest process did not expose {stream}"),
    }
}

fn process_error(operation: &'static str, error: std::io::Error) -> GuestIntrospectionAgentError {
    GuestIntrospectionAgentError::Process {
        message: format!("{operation}: {error}"),
    }
}

fn protocol_error(error: impl ToString) -> GuestIntrospectionAgentError {
    GuestIntrospectionAgentError::Protocol {
        message: error.to_string(),
    }
}

fn channel_error_code(
    error: &GuestIntrospectionAgentError,
    opening_request: bool,
) -> GuestIntrospectionFailureCode {
    match error {
        GuestIntrospectionAgentError::DuplicateChannel { .. } => {
            GuestIntrospectionFailureCode::DuplicateChannel
        }
        GuestIntrospectionAgentError::UnknownChannel { .. } => {
            GuestIntrospectionFailureCode::UnknownChannel
        }
        GuestIntrospectionAgentError::ChannelLimit { .. } => {
            GuestIntrospectionFailureCode::ChannelLimit
        }
        GuestIntrospectionAgentError::ClosedChannel { .. } => {
            GuestIntrospectionFailureCode::ClosedChannel
        }
        GuestIntrospectionAgentError::NotPty { .. } => GuestIntrospectionFailureCode::NotPty,
        GuestIntrospectionAgentError::Unsupported { .. } => {
            GuestIntrospectionFailureCode::Unsupported
        }
        GuestIntrospectionAgentError::Process { .. } if opening_request => {
            GuestIntrospectionFailureCode::OpenFailed
        }
        GuestIntrospectionAgentError::Configuration { .. }
        | GuestIntrospectionAgentError::Protocol { .. }
        | GuestIntrospectionAgentError::Doorbell(_)
        | GuestIntrospectionAgentError::Process { .. }
        | GuestIntrospectionAgentError::ReaderPanic { .. } => {
            GuestIntrospectionFailureCode::ProcessIo
        }
    }
}

fn bounded_error_message(error: &GuestIntrospectionAgentError) -> String {
    let mut message = error.to_string();
    while message.len() > GUEST_INTROSPECTION_MAX_ERROR_BYTES {
        message.pop();
    }
    message
}

#[cfg(test)]
mod tests;
