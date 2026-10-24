//! Carries only the completed PID 1 topology into its actual fixed Agent child.
//!
//! ```text
//! FD9 = sealed AOSGTP01 | root_id | provisioning.dev | provisioning.ino
//!       | provisioning.size | execution_root_id | init_scope_id | PID1.start
//! Each scalar is u64 big endian; the complete record is exactly 64 bytes.
//! FD10 = the same child's private AOSGTA01 completion pipe writer.
//! ```
//!
//! Native parent/current-task membership and all original FD4/6/7 joins are
//! independently required by the consumer. This record conveys no resource
//! account, deadline, execution, cancellation or process-adoption permission.

use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};

use crate::immutable_file::SealedMemfdReadOriginalV2;
use aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1;
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;

pub(super) const DESCRIPTOR: i32 = 9;
const NAME: &str = "aos-guest-topology-handoff-v1";
const BYTES: usize = 64;

#[derive(Clone, Copy)]
pub(super) struct TopologyRecordV1 {
    pub(super) root: u64,
    pub(super) provisioning: [u64; 3],
    pub(super) execution: u64,
    pub(super) manager: u64,
    pub(super) parent_start: u64,
}

impl TopologyRecordV1 {
    fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(b"AOSGTP01");
        let values = [
            self.root,
            self.provisioning[0],
            self.provisioning[1],
            self.provisioning[2],
            self.execution,
            self.manager,
            self.parent_start,
        ];
        for (chunk, value) in bytes[8..].chunks_exact_mut(8).zip(values) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BYTES || bytes.get(..8) != Some(b"AOSGTP01") {
            return Err(closed());
        }
        let mut values = [0; 7];
        for (value, chunk) in values.iter_mut().zip(bytes[8..].chunks_exact(8)) {
            *value = u64::from_be_bytes(chunk.try_into().map_err(|_| closed())?);
        }
        if values[3] != 258 {
            return Err(closed());
        }
        Ok(Self {
            root: values[0],
            provisioning: [values[1], values[2], values[3]],
            execution: values[4],
            manager: values[5],
            parent_start: values[6],
        })
    }
}

pub(super) struct TopologyHandoffOriginalV1 {
    placeholder: Option<rustix::io::Result<OwnedFd>>,
    duplicate: Option<rustix::io::Result<OwnedFd>>,
    slot: Option<OwnedFd>,
    creator: Option<Box<SealedReadOnlyCredentialCreateOriginalsV1>>,
    replacement: Option<rustix::io::Result<()>>,
    flags: [Option<rustix::io::Result<rustix::io::FdFlags>>; 2],
    inheritable: Option<rustix::io::Result<()>>,
    parent_close_on_exec: Option<rustix::io::Result<()>>,
    inherited: Option<Result<OwnedFd>>,
    reader: Option<Box<SealedMemfdReadOriginalV2>>,
    record: Option<TopologyRecordV1>,
    body: Option<Result<()>>,
    completion: super::completion::CompletionOriginalV1,
}

impl TopologyHandoffOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            placeholder: None,
            duplicate: None,
            slot: None,
            creator: None,
            replacement: None,
            flags: [None, None],
            inheritable: None,
            parent_close_on_exec: None,
            inherited: None,
            reader: None,
            record: None,
            body: None,
            completion: super::completion::CompletionOriginalV1::new(),
        }
    }

    pub(super) fn reserve_pid1_once(&mut self) -> Result<()> {
        if self.placeholder.is_some() || self.slot.is_some() || std::process::id() != 1 {
            return Err(closed());
        }
        self.placeholder = Some(rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ));
        let source = match self.placeholder.as_ref() {
            Some(Ok(file)) => file,
            _ => return Err(closed()),
        };
        if source.as_raw_fd() == DESCRIPTOR {
            match self.placeholder.take() {
                Some(Ok(file)) => self.slot = Some(file),
                _ => std::process::abort(),
            }
        } else {
            self.duplicate = Some(rustix::io::fcntl_dupfd_cloexec(source, DESCRIPTOR));
            if !self.duplicate.as_ref().is_some_and(|result| {
                result
                    .as_ref()
                    .is_ok_and(|file| file.as_raw_fd() == DESCRIPTOR)
            }) {
                return Err(closed());
            }
            match self.duplicate.take() {
                Some(Ok(file)) => self.slot = Some(file),
                _ => std::process::abort(),
            }
            drop(self.placeholder.take());
        }
        self.completion.reserve_pid1_once()
    }

    pub(super) fn publish_pid1_once(&mut self, record: TopologyRecordV1) -> Result<()> {
        if self.creator.is_some() || self.body.is_some() {
            return Err(closed());
        }
        self.creator = Some(Box::new(SealedReadOnlyCredentialCreateOriginalsV1::new()));
        self.body = Some((|| {
            let creator = self.creator.as_mut().ok_or_else(closed)?;
            creator
                .create_once(NAME, &record.encode(), BYTES)
                .map_err(|_| closed())?;
            let credential = creator.completed().ok_or_else(closed)?;
            let slot = self.slot.as_mut().ok_or_else(closed)?;
            self.replacement = Some(rustix::io::dup2(credential.as_fd(), slot));
            if !matches!(self.replacement, Some(Ok(()))) {
                return Err(closed());
            }
            self.flags[0] = Some(rustix::io::fcntl_getfd(&*slot));
            let flags = match self.flags[0] {
                Some(Ok(flags)) => flags,
                _ => return Err(closed()),
            };
            self.inheritable = Some(rustix::io::fcntl_setfd(
                &*slot,
                flags & !rustix::io::FdFlags::CLOEXEC,
            ));
            self.flags[1] = Some(rustix::io::fcntl_getfd(&*slot));
            if !matches!(self.inheritable, Some(Ok(())))
                || !self.flags[1].as_ref().is_some_and(|result| {
                    result
                        .as_ref()
                        .is_ok_and(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC))
                })
            {
                return Err(closed());
            }
            self.record = Some(record);
            Ok(())
        })());
        if !matches!(self.body, Some(Ok(()))) {
            return Err(closed());
        }
        // Sealing and full readback completed. FD9 is the same successful
        // readonly OFD; only completed creator scratch retires before spawn.
        drop(self.creator.take());
        Ok(())
    }

    pub(super) fn read_agent_once(&mut self) -> Result<TopologyRecordV1> {
        if self.inherited.is_some() || self.reader.is_some() || std::process::id() == 1 {
            return Err(closed());
        }
        self.inherited = Some(crate::inherited_fd::duplicate_inherited_descriptor(
            DESCRIPTOR,
        ));
        let file = match self.inherited.take() {
            Some(Ok(file)) => file,
            other => {
                self.inherited = other;
                return Err(closed());
            }
        };
        self.reader = Some(Box::new(SealedMemfdReadOriginalV2::new()));
        let reader = self.reader.as_mut().ok_or_else(closed)?;
        reader
            .prepare_once(file, BYTES as u64, BYTES as u64)
            .map_err(|_| closed())?;
        let record = reader
            .with_bytes(|bytes, _| TopologyRecordV1::decode(bytes))
            .map_err(|_| closed())??;
        self.record = Some(record);
        Ok(record)
    }

    pub(super) fn prepare_systemd_exec_once(&mut self) -> Result<()> {
        if self.parent_close_on_exec.is_some()
            || !matches!(self.body, Some(Ok(())))
            || !self.completion.completed()
        {
            return Err(closed());
        }
        let slot = self.slot.as_ref().ok_or_else(closed)?;
        self.parent_close_on_exec =
            Some(rustix::io::fcntl_setfd(slot, rustix::io::FdFlags::CLOEXEC));
        if matches!(self.parent_close_on_exec, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    pub(super) fn retire_completed_agent_read(&mut self) {
        // Only the complete outer Agent topology's positive branch calls this
        // after every native source/parent comparison and both actual posts.
        if self.record.is_some() && self.failure().is_none() {
            drop(self.reader.take());
        }
    }

    pub(super) fn wait_pid1_once(&mut self) -> Result<()> {
        self.completion.wait_pid1_once()
    }

    pub(super) fn acknowledge_agent_once(&mut self) -> Result<()> {
        self.completion.acknowledge_agent_once()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        cause(&self.placeholder)
            .or_else(|| cause(&self.duplicate))
            .or_else(|| {
                self.creator
                    .as_ref()
                    .and_then(|original| original.failure())
            })
            .or_else(|| cause(&self.replacement))
            .or_else(|| cause(&self.flags[0]))
            .or_else(|| cause(&self.inheritable))
            .or_else(|| cause(&self.flags[1]))
            .or_else(|| cause(&self.inherited))
            .or_else(|| self.reader.as_ref().and_then(|original| original.failure()))
            .or_else(|| cause(&self.body))
            .or_else(|| cause(&self.parent_close_on_exec))
            .or_else(|| self.completion.failure())
    }

    pub(super) fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let creator =
            SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(NAME.len(), BYTES)?;
        let completion = super::completion::CompletionOriginalV1::receiving_obligations_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(completion.0)?
            .checked_add(creator.memory_bytes)?
            .checked_add(SealedMemfdReadOriginalV2::receiving_memory_bytes_v2()?)?
            .checked_add(4 * BYTES + 8 * 256 + 2 * b"/dev/null\0".len())?;
        Some((
            bytes,
            creator
                .open_files
                .checked_add(3)?
                .checked_add(completion.1)?,
            1,
        ))
    }
}

fn cause<T, E: std::error::Error + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed() -> Error {
    Error::invalid(
        "Guest topology handoff",
        "original PID1/Agent native handoff is incomplete",
    )
}
