//! Reads the two fixed worker argv rosters without an unbounded args clone.
//!
//! The genuine Source and parent-held financial programme precede this read.
//! This module owns only bounded cmdline custody and path DATA; neither the
//! command line nor its shape creates a Source, operation, account or grant.

use std::error::Error;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

use aos_sandbox_broker::receiving::{NetworkChildSourceLoanV2, NetworkWorkerBirthPurposeV2};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::pidfd::SingleThreadedProcess;

const CMDLINE: &str = "/proc/self/cmdline";
const PROCFS_MAGIC: u64 = 0x9fa0;
const MAXIMUM_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the fixed Network worker argument original is closed")]
pub(crate) struct NetworkWorkerArgumentsClosedV2;

#[derive(Clone, Copy)]
enum First {
    Order,
    Source,
    Open,
    Filesystem,
    Before,
    Read,
    End,
    Shape,
    After,
}

/// Retains the one actual cmdline read, exact closed arity and native bookends.
pub(crate) struct NetworkWorkerArgumentsOriginalV2 {
    entered: bool,
    taken: bool,
    purpose: Option<NetworkWorkerBirthPurposeV2>,
    file: Option<std::io::Result<File>>,
    filesystem: Option<rustix::io::Result<rustix::fs::StatFs>>,
    before: Option<std::io::Result<Metadata>>,
    bytes: Vec<u8>,
    read: Option<std::io::Result<usize>>,
    end: Option<std::io::Result<usize>>,
    end_byte: [u8; 1],
    paths: Option<Result<Vec<PathBuf>, NetworkWorkerArgumentsClosedV2>>,
    after: Option<std::io::Result<Metadata>>,
    first: Option<First>,
    closed: NetworkWorkerArgumentsClosedV2,
}

impl NetworkWorkerArgumentsOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            taken: false,
            purpose: None,
            file: None,
            filesystem: None,
            before: None,
            bytes: Vec::new(),
            read: None,
            end: None,
            end_byte: [0],
            paths: None,
            after: None,
            first: None,
            closed: NetworkWorkerArgumentsClosedV2,
        }
    }

    /// Prices the same fixed input buffer, path copies and native file owner.
    /// This supplies no financial admission or permission to inspect argv.
    pub(crate) fn receiving_obligations_data_v2(
        purpose: NetworkWorkerBirthPurposeV2,
    ) -> Option<ResourceVector> {
        let count = argument_count(purpose);
        let bytes = maximum_bytes(purpose)?
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(
                count
                    .checked_mul(2)?
                    .checked_mul(std::mem::size_of::<PathBuf>())?,
            )?
            .checked_add(2 * (CMDLINE.len() + 1))?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, 1)
                .with(D::MetadataEntries, 1),
        )
    }

    /// Reads once under the actual already-paid Source and current-thread proof.
    /// The enclosing startup owner independently brackets this with its fresh
    /// Source observations. A short/non-EOF prefix is refused without retry.
    pub(crate) fn capture_once_v2(
        &mut self,
        purpose: NetworkWorkerBirthPurposeV2,
        source: &NetworkChildSourceLoanV2<'_>,
        _worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkWorkerArgumentsClosedV2> {
        if self.entered {
            return self.refuse(First::Order);
        }
        self.entered = true;
        self.purpose = Some(purpose);
        if !source
            .operation_binding_data_v2()
            .is_some_and(|binding| binding.purpose == purpose as u8)
        {
            return self.refuse(First::Source);
        }
        let _ = self.capture_inner(purpose);
        // The same descriptor post is owed after any reached read/framing
        // refusal. It cannot replace the earlier native/shape cause.
        if let Some(Ok(file)) = self.file.as_ref() {
            self.after = Some(file.metadata());
            if !matches!((&self.before, &self.after), (Some(Ok(before)), Some(Ok(after)))
                if same_file(before, after))
            {
                self.first.get_or_insert(First::After);
            }
        }
        if self.first.is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }

    fn capture_inner(
        &mut self,
        purpose: NetworkWorkerBirthPurposeV2,
    ) -> Result<(), NetworkWorkerArgumentsClosedV2> {
        self.file = Some(File::open(CMDLINE));
        let Some(Ok(file)) = self.file.as_ref() else {
            return self.refuse(First::Open);
        };
        self.filesystem = Some(rustix::fs::fstatfs(file.as_fd()));
        if !matches!(self.filesystem, Some(Ok(ref stat)) if stat.f_type as u64 == PROCFS_MAGIC) {
            return self.refuse(First::Filesystem);
        }
        self.before = Some(file.metadata());
        if !matches!(self.before, Some(Ok(_))) {
            return self.refuse(First::Before);
        }
        let maximum = maximum_bytes(purpose).ok_or(self.closed)?;
        self.bytes.resize(maximum, 0);
        let mut reader = file;
        self.read = Some(reader.read(&mut self.bytes));
        let length = match self.read.as_ref() {
            Some(Ok(length)) if *length != 0 && *length < maximum => *length,
            Some(Ok(_)) => return self.refuse(First::Shape),
            _ => return self.refuse(First::Read),
        };
        self.end = Some(reader.read(&mut self.end_byte));
        if !matches!(self.end, Some(Ok(0))) {
            return self.refuse(First::End);
        }
        self.paths = Some(decode_paths(&self.bytes[..length], purpose));
        if !matches!(self.paths, Some(Ok(_))) {
            return self.refuse(First::Shape);
        }
        Ok(())
    }

    pub(crate) fn take_preparation_paths_once_v2(&mut self) -> Option<[PathBuf; 7]> {
        if self.purpose != Some(NetworkWorkerBirthPurposeV2::Preparation) {
            return None;
        }
        self.take_paths()?.try_into().ok()
    }

    pub(crate) fn take_observation_paths_once_v2(&mut self) -> Option<[PathBuf; 5]> {
        if self.purpose != Some(NetworkWorkerBirthPurposeV2::Observation) {
            return None;
        }
        self.take_paths()?.try_into().ok()
    }

    fn take_paths(&mut self) -> Option<Vec<PathBuf>> {
        if self.taken || self.first.is_some() {
            return None;
        }
        let Some(Ok(_)) = self.paths.as_ref() else {
            return None;
        };
        self.taken = true;
        // Exact EOF/framing and this same file's after already completed. No
        // later consumer borrows the native cmdline file; its original data
        // and financial debt remain, without a reusable FD allowance.
        drop(self.file.take());
        self.paths.take()?.ok()
    }

    fn refuse<T>(&mut self, first: First) -> Result<T, NetworkWorkerArgumentsClosedV2> {
        self.first.get_or_insert(first);
        Err(self.closed)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            First::Open => failed(&self.file),
            First::Filesystem => failed(&self.filesystem),
            First::Before => failed(&self.before),
            First::Read => failed(&self.read),
            First::End => failed(&self.end),
            First::After => failed(&self.after),
            First::Shape => failed(&self.paths),
            _ => None,
        };
        cause.or(Some(&self.closed))
    }
}

fn argument_count(purpose: NetworkWorkerBirthPurposeV2) -> usize {
    match purpose {
        NetworkWorkerBirthPurposeV2::Preparation => 8,
        NetworkWorkerBirthPurposeV2::Observation => 6,
    }
}

fn maximum_bytes(purpose: NetworkWorkerBirthPurposeV2) -> Option<usize> {
    argument_count(purpose)
        .checked_mul(MAXIMUM_PATH_BYTES.checked_add(1)?)?
        .checked_add(1)
}

fn decode_paths(
    bytes: &[u8],
    purpose: NetworkWorkerBirthPurposeV2,
) -> Result<Vec<PathBuf>, NetworkWorkerArgumentsClosedV2> {
    if bytes.last() != Some(&0) {
        return Err(NetworkWorkerArgumentsClosedV2);
    }
    let mut entries = bytes[..bytes.len() - 1].split(|byte| *byte == 0);
    let valid = |value: &[u8]| {
        !value.is_empty() && value.len() <= MAXIMUM_PATH_BYTES && value.first() == Some(&b'/')
    };
    if !entries.next().is_some_and(valid) {
        return Err(NetworkWorkerArgumentsClosedV2);
    }
    let mut paths = Vec::with_capacity(argument_count(purpose) - 1);
    for _ in 1..argument_count(purpose) {
        let bytes = entries
            .next()
            .filter(|value| valid(value))
            .ok_or(NetworkWorkerArgumentsClosedV2)?;
        paths.push(PathBuf::from(OsString::from_vec(bytes.to_vec())));
    }
    if entries.next().is_some() {
        return Err(NetworkWorkerArgumentsClosedV2);
    }
    Ok(paths)
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.size() == after.size()
}

fn failed<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().err())
        .map(|cause| cause as _)
}
