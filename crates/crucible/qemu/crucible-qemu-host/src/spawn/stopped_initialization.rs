//! Retained original FIFO output for the stopped constructor qualification.
//!
//! The explicitly selected fixed record is diagnostic correlation, never a
//! source-ready receipt. Partial output and the same pipe survive every refusal.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::process::ExitStatus;

use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat};
use rustix::io::Errno;

use crate::{QemuNodeChild, QemuSpawnError};

pub(super) struct StoppedInitializationOutput<const RECORD_BYTES: usize = 128> {
    reader: OwnedFd,
    writer: OwnedFd,
    bytes: Vec<u8>,
    backing_bytes: u64,
    filled: usize,
    attempts: u32,
    exit: Option<ExitStatus>,
    refused: bool,
    complete: bool,
}

enum PipeObservation {
    Progress,
    Drained,
    Interrupted,
}

impl<const RECORD_BYTES: usize> StoppedInitializationOutput<RECORD_BYTES> {
    pub(super) fn new([reader, writer]: [OwnedFd; 2]) -> Result<Self, QemuSpawnError> {
        if !matches!(RECORD_BYTES, 128 | 192) {
            return Err(refusal(io::Error::other("unsupported diagnostic extent")));
        }
        let left = fstat(&reader).map_err(refusal)?;
        let right = fstat(&writer).map_err(refusal)?;
        let read_flags = fcntl_getfl(&reader).map_err(refusal)?;
        let write_flags = fcntl_getfl(&writer).map_err(refusal)?;
        if FileType::from_raw_mode(left.st_mode) != FileType::Fifo
            || FileType::from_raw_mode(right.st_mode) != FileType::Fifo
            || left.st_dev != right.st_dev
            || left.st_ino != right.st_ino
            || !read_flags.contains(OFlags::NONBLOCK)
            || !write_flags.contains(OFlags::NONBLOCK)
            || (read_flags & OFlags::ACCMODE) != OFlags::RDONLY
            || (write_flags & OFlags::ACCMODE) != OFlags::WRONLY
        {
            return Err(refusal(io::Error::other(
                "original nonblocking FIFO pair required",
            )));
        }
        let pipe_capacity =
            u64::try_from(rustix::pipe::fcntl_getpipe_size(&reader).map_err(refusal)?)
                .map_err(|error| refusal(io::Error::other(error.to_string())))?;
        let backing_bytes = pipe_capacity
            .checked_add((RECORD_BYTES + 1) as u64)
            .ok_or_else(|| refusal(io::Error::other("original pipe backing overflow")))?;
        Ok(Self {
            reader,
            writer,
            bytes: Vec::new(),
            backing_bytes,
            filled: 0,
            attempts: 0,
            exit: None,
            refused: false,
            complete: false,
        })
    }

    pub(super) fn required_backing_bytes(&self) -> u64 {
        self.backing_bytes
    }

    pub(super) fn prepare_capture(&mut self) -> Result<(), QemuSpawnError> {
        self.bytes
            .try_reserve_exact(RECORD_BYTES + 1)
            .map_err(|error| refusal(io::Error::other(error.to_string())))?;
        self.bytes.resize(RECORD_BYTES + 1, 0);
        Ok(())
    }

    pub(super) fn writer(&self) -> BorrowedFd<'_> {
        self.writer.as_fd()
    }

    fn read_once(&mut self) -> Result<PipeObservation, QemuSpawnError> {
        if self.attempts == 4096 || self.filled == self.bytes.len() {
            return Err(refusal(io::Error::other(
                "stopped output capacity exhausted",
            )));
        }
        self.attempts += 1;
        match rustix::io::read(&self.reader, &mut self.bytes[self.filled..]) {
            Ok(0) => return Ok(PipeObservation::Drained),
            Ok(bytes) => self.filled += bytes,
            Err(Errno::AGAIN) => return Ok(PipeObservation::Drained),
            Err(Errno::INTR) => return Ok(PipeObservation::Interrupted),
            Err(error) => return Err(refusal(error)),
        }
        if self.filled > RECORD_BYTES {
            return Err(refusal(io::Error::other(
                "stopped output exceeds the selected record extent",
            )));
        }
        Ok(PipeObservation::Progress)
    }

    pub(super) fn poll(
        &mut self,
        child: &mut QemuNodeChild,
    ) -> Result<Option<[u8; RECORD_BYTES]>, QemuSpawnError> {
        if self.refused {
            return Err(refusal(io::Error::other("original stopped output refused")));
        }
        if self.complete {
            return self.record().map(Some);
        }
        let result = self.poll_original(child);
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    fn poll_original(
        &mut self,
        child: &mut QemuNodeChild,
    ) -> Result<Option<[u8; RECORD_BYTES]>, QemuSpawnError> {
        self.read_once()?;
        if self.exit.is_none() {
            self.exit = child
                .try_wait_natural_exit()
                .map_err(|error| refusal(io::Error::other(error.to_string())))?;
        }
        let Some(exit) = self.exit else {
            return Ok(None);
        };
        if !exit.success() {
            return Err(refusal(io::Error::other("original stopped child failed")));
        }
        // Drain once after actual reap. A prefix observed while the child was
        // live cannot establish that no trailing byte was subsequently written.
        if !matches!(self.read_once()?, PipeObservation::Drained) {
            return Ok(None);
        }
        if self.filled != RECORD_BYTES {
            return Err(refusal(io::Error::other(
                "original stopped child output is incomplete",
            )));
        }
        self.complete = true;
        self.record().map(Some)
    }

    fn record(&self) -> Result<[u8; RECORD_BYTES], QemuSpawnError> {
        self.bytes[..RECORD_BYTES]
            .try_into()
            .map_err(|_| refusal(io::Error::other("fixed stopped record extent changed")))
    }
}

pub(super) enum StoppedConstructorOutput {
    Initialization(StoppedInitializationOutput),
    RoundRobinPreparation(StoppedInitializationOutput<192>),
}

impl StoppedConstructorOutput {
    pub(super) fn required_backing_bytes(&self) -> u64 {
        match self {
            Self::Initialization(output) => output.required_backing_bytes(),
            Self::RoundRobinPreparation(output) => output.required_backing_bytes(),
        }
    }

    pub(super) fn prepare_capture(&mut self) -> Result<(), QemuSpawnError> {
        match self {
            Self::Initialization(output) => output.prepare_capture(),
            Self::RoundRobinPreparation(output) => output.prepare_capture(),
        }
    }

    pub(super) fn writer(&self) -> BorrowedFd<'_> {
        match self {
            Self::Initialization(output) => output.writer(),
            Self::RoundRobinPreparation(output) => output.writer(),
        }
    }
}

fn refusal(error: impl Into<io::Error>) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation: "retain original stopped-initialization output",
        source: error.into(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "OS fixture setup and assertions must fail the test directly"
)]
mod tests {
    use super::*;
    use rustix::pipe::{PipeFlags, pipe_with};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const AOS_BASH: &str = "/nix/store/79kkrh8qizk69m98g47h9c7l5dgp0rzi-bash-5.3p15/bin/bash";

    fn helper(script: &str) -> (StoppedInitializationOutput, QemuNodeChild) {
        helper_for::<128>(script)
    }

    fn helper_for<const RECORD_BYTES: usize>(
        script: &str,
    ) -> (StoppedInitializationOutput<RECORD_BYTES>, QemuNodeChild) {
        let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).unwrap();
        let stdout = writer.try_clone().unwrap();
        let mut output =
            StoppedInitializationOutput::<RECORD_BYTES>::new([reader, writer]).unwrap();
        output.prepare_capture().unwrap();
        let child = Command::new(AOS_BASH)
            .env_clear()
            .args(["-c", script])
            .stdout(Stdio::from(stdout))
            .spawn()
            .unwrap();
        (output, QemuNodeChild::new(child))
    }

    fn watchdog_ns() -> i128 {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        i128::from(now.tv_sec) * 1_000_000_000 + i128::from(now.tv_nsec)
    }

    fn finish<const RECORD_BYTES: usize>(
        output: &mut StoppedInitializationOutput<RECORD_BYTES>,
        child: &mut QemuNodeChild,
    ) -> Result<[u8; RECORD_BYTES], QemuSpawnError> {
        let deadline = watchdog_ns() + 5_000_000_000;
        loop {
            match output.poll(child)? {
                Some(record) => return Ok(record),
                None if watchdog_ns() < deadline => std::thread::sleep(Duration::from_millis(5)),
                None => return Err(refusal(io::Error::other("helper deadline"))),
            }
        }
    }

    #[test]
    fn original_pipe_record_requires_exact_reap_and_does_not_repeat_io() {
        let (mut output, mut child) = helper("printf '%0128d' 0");
        let record = finish(&mut output, &mut child).unwrap();
        assert!(child.reaped());
        assert_eq!(record.len(), 128);
        let attempts = output.attempts;
        assert_eq!(output.poll(&mut child).unwrap(), Some(record));
        assert_eq!(output.attempts, attempts);
    }

    #[test]
    fn partial_and_overflow_original_histories_stay_refused() {
        for (script, expected) in [("printf x", 1), ("printf '%0129d' 0", 129)] {
            let (mut output, mut child) = helper(script);
            assert!(finish(&mut output, &mut child).is_err());
            assert_eq!(output.filled, expected);
            let attempts = output.attempts;
            assert!(output.poll(&mut child).is_err());
            assert_eq!(output.attempts, attempts);
            let deadline = watchdog_ns() + 5_000_000_000;
            while !child.reaped() && child.try_wait_natural_exit().unwrap().is_none() {
                assert!(watchdog_ns() < deadline, "original helper must be reaped");
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(child.reaped());
        }
    }

    #[test]
    fn failed_native_exit_cannot_qualify_complete_output() {
        let (mut output, mut child) = helper("printf '%0128d' 0; exit 125");
        assert!(finish(&mut output, &mut child).is_err());
        assert!(child.reaped());
        assert_eq!(output.filled, 128);
    }

    #[test]
    fn blocking_original_pipe_is_refused_before_child_creation() {
        let (reader, writer) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        assert!(StoppedInitializationOutput::<128>::new([reader, writer]).is_err());
    }

    #[test]
    fn rr_record_reserves_extra_capacity_and_waits_for_original_tail() {
        let (mut output, mut child) = helper_for::<192>(
            "printf '%0128d' 0; /nix/store/6i9yb0a1q1k9qx8l3xb4xr25kf8cg4p5-coreutils-9.11/bin/sleep 0.1; printf '%064d' 0",
        );
        let capacity = rustix::pipe::fcntl_getpipe_size(&output.reader).unwrap();
        assert_eq!(output.required_backing_bytes(), capacity as u64 + 193);
        assert_eq!(output.bytes.len(), 193);

        let deadline = watchdog_ns() + 5_000_000_000;
        while output.filled < 128 {
            assert_eq!(output.poll(&mut child).unwrap(), None);
            assert!(watchdog_ns() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!output.complete);
        let record = finish(&mut output, &mut child).unwrap();
        assert!(child.reaped());
        assert_eq!(record.len(), 192);
        let attempts = output.attempts;
        assert_eq!(output.poll(&mut child).unwrap(), Some(record));
        assert_eq!(output.attempts, attempts);
    }

    #[test]
    fn rr_profile_refuses_old_record_extent_and_preserves_overflow() {
        for (script, expected) in [("printf '%0128d' 0", 128), ("printf '%0193d' 0", 193)] {
            let (mut output, mut child) = helper_for::<192>(script);
            assert!(finish(&mut output, &mut child).is_err());
            assert_eq!(output.filled, expected);
            let attempts = output.attempts;
            assert!(output.poll(&mut child).is_err());
            assert_eq!(output.attempts, attempts);

            let deadline = watchdog_ns() + 5_000_000_000;
            while !child.reaped() && child.try_wait_natural_exit().unwrap().is_none() {
                assert!(watchdog_ns() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(child.reaped());
        }
    }
}
