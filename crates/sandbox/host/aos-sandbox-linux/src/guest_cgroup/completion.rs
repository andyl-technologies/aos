//! Keeps PID 1 before systemd exec until its same actual Agent finishes placement.
//!
//! FD10 is the fresh pipe writer inherited only by the actual child. Neither
//! endpoint carries authority. The one read may wait only inside the original
//! Guardian-bound payload; it creates no clock, retry, worker or new lifetime.

use std::os::fd::{AsRawFd as _, OwnedFd};

use crate::{Error, Result};

const DESCRIPTOR: i32 = 10;
const ACK: &[u8; 8] = b"AOSGTA01";

pub(super) struct CompletionOriginalV1 {
    pipe: Option<rustix::io::Result<(OwnedFd, OwnedFd)>>,
    read_duplicate: Option<rustix::io::Result<OwnedFd>>,
    reader: Option<OwnedFd>,
    write_duplicate: Option<rustix::io::Result<OwnedFd>>,
    writer: Option<OwnedFd>,
    flags: [Option<rustix::io::Result<rustix::io::FdFlags>>; 2],
    inheritable: Option<rustix::io::Result<()>>,
    inherited: Option<Result<OwnedFd>>,
    close_on_exec: Option<Result<()>>,
    io: Option<rustix::io::Result<usize>>,
    bytes: [u8; 8],
    body: Option<Result<()>>,
}

impl CompletionOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            pipe: None,
            read_duplicate: None,
            reader: None,
            write_duplicate: None,
            writer: None,
            flags: [None, None],
            inheritable: None,
            inherited: None,
            close_on_exec: None,
            io: None,
            bytes: [0; 8],
            body: None,
        }
    }

    pub(super) fn reserve_pid1_once(&mut self) -> Result<()> {
        if self.pipe.is_some()
            || self.reader.is_some()
            || self.writer.is_some()
            || std::process::id() != 1
        {
            return Err(closed());
        }
        self.pipe = Some(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC));
        let (read, write) = match self.pipe.as_ref() {
            Some(Ok(pair)) => pair,
            _ => return Err(closed()),
        };
        // Keep the fixed table slots free of ordinary startup duplicates.
        self.read_duplicate = Some(rustix::io::fcntl_dupfd_cloexec(read, 64));
        if !matches!(self.read_duplicate, Some(Ok(_))) {
            return Err(closed());
        }
        if write.as_raw_fd() != DESCRIPTOR {
            self.write_duplicate = Some(rustix::io::fcntl_dupfd_cloexec(write, DESCRIPTOR));
            if !self.write_duplicate.as_ref().is_some_and(|result| {
                result
                    .as_ref()
                    .is_ok_and(|file| file.as_raw_fd() == DESCRIPTOR)
            }) {
                return Err(closed());
            }
        }
        let (read, write) = match self.pipe.take() {
            Some(Ok(pair)) => pair,
            _ => std::process::abort(),
        };
        self.reader = match self.read_duplicate.take() {
            Some(Ok(file)) => Some(file),
            _ => std::process::abort(),
        };
        self.writer = if write.as_raw_fd() == DESCRIPTOR {
            Some(write)
        } else {
            drop(write);
            match self.write_duplicate.take() {
                Some(Ok(file)) => Some(file),
                _ => std::process::abort(),
            }
        };
        drop(read);
        let writer = self.writer.as_ref().ok_or_else(closed)?;
        self.flags[0] = Some(rustix::io::fcntl_getfd(writer));
        let flags = match self.flags[0] {
            Some(Ok(flags)) => flags,
            _ => return Err(closed()),
        };
        self.inheritable = Some(rustix::io::fcntl_setfd(
            writer,
            flags & !rustix::io::FdFlags::CLOEXEC,
        ));
        self.flags[1] = Some(rustix::io::fcntl_getfd(writer));
        if !matches!(self.inheritable, Some(Ok(())))
            || !self.flags[1].as_ref().is_some_and(|result| {
                result
                    .as_ref()
                    .is_ok_and(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC))
            })
        {
            return Err(closed());
        }
        Ok(())
    }

    pub(super) fn wait_pid1_once(&mut self) -> Result<()> {
        if self.body.is_some() || self.inherited.is_some() || std::process::id() != 1 {
            return Err(closed());
        }
        self.body = Some((|| {
            // The actual Child already owns its inherited writer. EOF now
            // means refusal; no parent writer can hide the child's death.
            drop(self.writer.take());
            let reader = self.reader.as_ref().ok_or_else(closed)?;
            self.io = Some(rustix::io::read(reader, &mut self.bytes));
            require_ack(&self.io, &self.bytes)
        })());
        if !matches!(self.body, Some(Ok(()))) {
            return Err(closed());
        }
        drop(self.reader.take());
        Ok(())
    }

    pub(super) fn acknowledge_agent_once(&mut self) -> Result<()> {
        if self.body.is_some() || self.inherited.is_some() || std::process::id() == 1 {
            return Err(closed());
        }
        self.body = Some((|| {
            self.inherited = Some(crate::inherited_fd::duplicate_inherited_descriptor(
                DESCRIPTOR,
            ));
            let writer = match self.inherited.as_ref() {
                Some(Ok(file)) => file,
                _ => return Err(closed()),
            };
            self.close_on_exec =
                Some(crate::inherited_fd::mark_inherited_descriptor_close_on_exec(DESCRIPTOR));
            if !matches!(self.close_on_exec, Some(Ok(()))) {
                return Err(closed());
            }
            self.io = Some(rustix::io::write(writer, ACK));
            require_ack(&self.io, ACK)
        })());
        if !matches!(self.body, Some(Ok(()))) {
            return Err(closed());
        }
        // The original numeric FD10 stays CLOEXEC and source charged until
        // Guest death. Only this successful write's private duplicate retires.
        drop(self.inherited.take());
        Ok(())
    }

    pub(super) fn completed(&self) -> bool {
        matches!(self.body, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        cause(&self.pipe)
            .or_else(|| cause(&self.read_duplicate))
            .or_else(|| cause(&self.write_duplicate))
            .or_else(|| cause(&self.flags[0]))
            .or_else(|| cause(&self.inheritable))
            .or_else(|| cause(&self.flags[1]))
            .or_else(|| cause(&self.inherited))
            .or_else(|| cause(&self.close_on_exec))
            .or_else(|| cause(&self.io))
            .or_else(|| cause(&self.body))
    }

    pub(super) fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        // Both pipe ends plus one duplicate at each retained failure frontier.
        Some((
            std::mem::size_of::<Self>()
                .checked_mul(2)?
                .checked_add(4 * 256)?,
            4,
            0,
        ))
    }
}

fn require_ack(result: &Option<rustix::io::Result<usize>>, bytes: &[u8; 8]) -> Result<()> {
    if matches!(result, Some(Ok(8))) && bytes == ACK {
        Ok(())
    } else {
        Err(closed())
    }
}

fn cause<T, E: std::error::Error + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed() -> Error {
    Error::invalid(
        "Guest topology completion",
        "same actual Agent has not completed startup",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_requires_one_full_original_record() {
        assert!(require_ack(&Some(Ok(8)), ACK).is_ok());
        assert!(require_ack(&Some(Ok(7)), ACK).is_err());
        assert!(require_ack(&Some(Err(rustix::io::Errno::INTR)), ACK).is_err());
        assert!(require_ack(&Some(Ok(8)), b"AOSGTA02").is_err());
    }

    #[test]
    fn same_pipe_preserves_eof_and_partial_native_refusals() {
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        assert_eq!(rustix::io::write(&write, &ACK[..4]).unwrap(), 4);
        drop(write);

        let mut bytes = [0; 8];
        let partial = Some(rustix::io::read(&read, &mut bytes));
        assert!(matches!(partial, Some(Ok(4))));
        assert!(require_ack(&partial, &bytes).is_err());
        assert_eq!(rustix::io::read(&read, &mut bytes).unwrap(), 0);
    }
}
