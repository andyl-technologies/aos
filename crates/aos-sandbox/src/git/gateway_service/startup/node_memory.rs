//! Observes node-wide available memory through the same original procfs file.
//!
//! The kernel's estimate is an advisory admission input, not reserved capacity,
//! an allocation fence, currentness or a hard network-memory bound. Only the
//! fixed startup owner can capture these private descriptors; no caller path,
//! descriptor, sample or transport loan is accepted or exported.
//!
//! The bounded selected fields have the ordinary kernel format:
//!
//! ```text
//! MemTotal:       4194304 kB
//! MemAvailable:   2097152 kB
//! ```

use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;

use aos_sandbox_linux::inventory::MountId;
use rustix::fs::{
    CWD, FileType, Mode, OFlags, PROC_SUPER_MAGIC, fcntl_getfl, fstat, fstatfs, openat,
};

use super::Error;

const PROC_PATH: &str = "/proc";
const MEMINFO_NAME: &str = "meminfo";
const MAXIMUM_MEMINFO_BYTES: usize = 16 * 1024;
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);

/// Retains original kernel objects, but does not issue a capacity permit.
pub(super) struct RetainedNodeMemoryObservationV1 {
    root: OwnedFd,
    meminfo: File,
    root_identity: ProcIdentity,
    meminfo_identity: ProcIdentity,
}

impl RetainedNodeMemoryObservationV1 {
    /// Captures only the fixed original procfs directory and kernel meminfo file.
    ///
    /// # Errors
    ///
    /// Rejects failed read-only opens, foreign filesystem/type/mount/ownership,
    /// writable objects or changed original names. No descriptor loan escapes.
    pub(super) fn capture() -> Result<Self, Error> {
        let root = open_root()?;
        let root_identity = identify(root.as_fd(), FileType::Directory)?;
        let meminfo = File::from(open_meminfo(root.as_fd())?);
        let meminfo_identity = identify(meminfo.as_fd(), FileType::RegularFile)?;
        if meminfo_identity.mount != root_identity.mount {
            return Err(Error::NodeMemoryObservation);
        }

        let retained = Self {
            root,
            meminfo,
            root_identity,
            meminfo_identity,
        };
        retained.recheck_objects()?;
        Ok(retained)
    }

    /// Uses a fresh estimate from offset zero, never a caller-supplied sample.
    ///
    /// # Errors
    ///
    /// Rejects changed objects, failed or oversized reads, malformed selected
    /// fields and estimates below the selected minimum. A successful comparison
    /// reserves no capacity and cannot fence concurrent allocations.
    pub(super) fn require_current(&self, minimum_available_bytes: u64) -> Result<(), Error> {
        self.recheck_objects()?;

        // This fixed stack window and sentinel precede decoding. Short reads
        // continue on this same file, never an alternate or newly opened file.
        let mut bytes = [0; MAXIMUM_MEMINFO_BYTES + 1];
        let mut length = 0;
        loop {
            if length == bytes.len() {
                return Err(Error::NodeMemoryObservation);
            }
            let read = self
                .meminfo
                .read_at(&mut bytes[length..], length as u64)
                .map_err(|_| Error::NodeMemoryObservation)?;
            if read == 0 {
                break;
            }
            length += read;
        }

        let observed = parse_meminfo(&bytes[..length])?;
        self.recheck_objects()?;
        observed.require_minimum(minimum_available_bytes)
    }

    fn recheck_objects(&self) -> Result<(), Error> {
        if identify(self.root.as_fd(), FileType::Directory)? != self.root_identity
            || identify(self.meminfo.as_fd(), FileType::RegularFile)? != self.meminfo_identity
        {
            return Err(Error::NodeMemoryObservation);
        }

        // Fresh names must still identify the original objects and mount.
        // The probes are destroyed here; the retained reader is never replaced.
        let named_root = open_root()?;
        if identify(named_root.as_fd(), FileType::Directory)? != self.root_identity {
            return Err(Error::NodeMemoryObservation);
        }
        let named_meminfo = open_meminfo(named_root.as_fd())?;
        if identify(named_meminfo.as_fd(), FileType::RegularFile)? != self.meminfo_identity {
            return Err(Error::NodeMemoryObservation);
        }

        if identify(self.root.as_fd(), FileType::Directory)? != self.root_identity
            || identify(self.meminfo.as_fd(), FileType::RegularFile)? != self.meminfo_identity
        {
            return Err(Error::NodeMemoryObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ProcIdentity {
    device: u64,
    inode: u64,
    mount: MountId,
}

fn open_root() -> Result<OwnedFd, Error> {
    openat(CWD, PROC_PATH, READ_FLAGS | OFlags::DIRECTORY, Mode::empty())
        .map_err(|_| Error::NodeMemoryObservation)
}

fn open_meminfo(root: BorrowedFd<'_>) -> Result<OwnedFd, Error> {
    openat(root, MEMINFO_NAME, READ_FLAGS, Mode::empty())
        .map_err(|_| Error::NodeMemoryObservation)
}

fn identify(descriptor: BorrowedFd<'_>, kind: FileType) -> Result<ProcIdentity, Error> {
    let filesystem = fstatfs(descriptor).map_err(|_| Error::NodeMemoryObservation)?;
    let status = fstat(descriptor).map_err(|_| Error::NodeMemoryObservation)?;
    let flags = fcntl_getfl(descriptor).map_err(|_| Error::NodeMemoryObservation)?;
    if filesystem.f_type != PROC_SUPER_MAGIC
        || FileType::from_raw_mode(status.st_mode) != kind
        || status.st_uid != 0
        || status.st_gid != 0
        || status.st_mode & 0o222 != 0
        || flags.intersects(OFlags::WRONLY | OFlags::RDWR)
        || !flags.contains(OFlags::NONBLOCK)
    {
        return Err(Error::NodeMemoryObservation);
    }

    Ok(ProcIdentity {
        device: status.st_dev,
        inode: status.st_ino,
        mount: MountId::from_fd(descriptor).map_err(|_| Error::NodeMemoryObservation)?,
    })
}

#[derive(Debug, Eq, PartialEq)]
struct NodeMemorySample {
    total_bytes: u64,
    available_bytes: u64,
}

impl NodeMemorySample {
    fn require_minimum(&self, minimum_available_bytes: u64) -> Result<(), Error> {
        if self.available_bytes < minimum_available_bytes {
            return Err(Error::NodeMemoryPressure);
        }
        Ok(())
    }
}

fn parse_meminfo(bytes: &[u8]) -> Result<NodeMemorySample, Error> {
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_MEMINFO_BYTES
        || !bytes.ends_with(b"\n")
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii() || *byte == 0 || *byte == b'\r')
    {
        return Err(Error::NodeMemoryObservation);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::NodeMemoryObservation)?;

    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        let (name, value) = line.split_once(':').ok_or(Error::NodeMemoryObservation)?;
        if name.is_empty() || value.trim().is_empty() {
            return Err(Error::NodeMemoryObservation);
        }
        let destination = match name {
            "MemTotal" => &mut total,
            "MemAvailable" => &mut available,
            _ => continue,
        };
        if destination.is_some() {
            return Err(Error::NodeMemoryObservation);
        }
        *destination = Some(parse_kibibytes(value)?);
    }

    let total_bytes = total.ok_or(Error::NodeMemoryObservation)?;
    let available_bytes = available.ok_or(Error::NodeMemoryObservation)?;
    if total_bytes == 0 || available_bytes > total_bytes {
        return Err(Error::NodeMemoryObservation);
    }
    Ok(NodeMemorySample {
        total_bytes,
        available_bytes,
    })
}

fn parse_kibibytes(value: &str) -> Result<u64, Error> {
    let mut fields = value.split_ascii_whitespace();
    let number = fields.next().ok_or(Error::NodeMemoryObservation)?;
    if fields.next() != Some("kB")
        || fields.next().is_some()
        || number.len() > 1 && number.starts_with('0')
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::NodeMemoryObservation);
    }

    let kibibytes = number.bytes().try_fold(0_u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(Error::NodeMemoryObservation)
    })?;
    kibibytes
        .checked_mul(1024)
        .ok_or(Error::NodeMemoryObservation)
}

#[cfg(test)]
mod tests;
