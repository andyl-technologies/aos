//! Streams independently pinned public artifacts and current host facts.

use std::{
    fs::File,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
};

use crucible_node_format::{ContentRef, HashRef, U64, Validate};
use serde::Serialize;

use super::refused;
use crate::node_qualification::QualificationError;

const MAXIMUM_ARTIFACT: u64 = 512 * 1024 * 1024;
const STREAMING_BUFFER_BYTES: usize = 256 * 1024;
const ROLES: [&str; 8] = [
    "adapter_source",
    "build_closure",
    "contract_source",
    "harness_source",
    "native_source",
    "program_source",
    "provider_source",
    "recipe",
];

/// Selects one complete public file from independent host configuration.
///
/// A content identity is a measurement target, never a certificate. The fixture
/// constructor requires the exact closed role roster and remeasures each file.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PacketFixtureArtifact {
    /// Names one source-owned role from the complete eight-role roster.
    pub role: String,
    /// Names the actual original public source or executable file.
    pub path: PathBuf,
    /// Pins all original bytes, their length and media type.
    pub content: ContentRef,
}

/// Selects original peer, actual host harness and complete source roles.
///
/// This type has no decoder or authority implementation. Only explicit host
/// installation can join these measured files to the native source and oracle.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PacketFixtureMeasurements {
    /// Names and pins the actual packet peer executable.
    pub peer: PacketFixtureArtifact,
    /// Pins the actual current host executable at `/proc/self/exe`.
    pub host: ContentRef,
    /// Retains all eight public source roles, in strictly increasing role order.
    pub sources: Vec<PacketFixtureArtifact>,
}

impl PacketFixtureMeasurements {
    /// Returns the fixed transient buffer required by one complete file read.
    ///
    /// Reads are synchronous and invoke no callbacks while the buffer is live.
    /// Initial authentication has this same fixed stack extent; runtime storage
    /// admission charges the full buffer separately from retained file owners.
    pub const fn streaming_scratch_bytes() -> usize {
        std::mem::size_of::<[u8; STREAMING_BUFFER_BYTES]>()
    }

    /// Remeasures all selected files and the actual current host executable.
    ///
    /// The streaming reader uses a fixed 256 KiB buffer. Complete file identity
    /// and metadata must remain unchanged across the read. This operation grants
    /// no process ownership, readiness, behavioral class or native certificate.
    ///
    /// # Errors
    /// Refuses omitted/repeated roles, nonfinite files, pin drift, changed file
    /// metadata, unavailable host measurements or an over-budget role tuple.
    pub fn authenticate(&self) -> Result<(), QualificationError> {
        if self.peer.role != "executable"
            || self.sources.len() != ROLES.len()
            || self
                .sources
                .iter()
                .zip(ROLES)
                .any(|(file, role)| file.role != role)
        {
            return Err(refused());
        }
        super::super::scope::encoded_size(self, 65_536)?;
        executable(&self.peer.path)?;
        measure(&self.peer.path, &self.peer.content)?;
        executable(Path::new("/proc/self/exe"))?;
        measure(Path::new("/proc/self/exe"), &self.host)?;
        for source in &self.sources {
            measure(&source.path, &source.content)?;
        }
        Ok(())
    }
}

pub(super) fn executable(path: &Path) -> Result<(), QualificationError> {
    let mut file = File::open(path).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    let mut prefix = [0u8; 4];
    file.read_exact(&mut prefix).map_err(io)?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || prefix != *b"\x7fELF" {
        return Err(refused());
    }
    Ok(())
}

pub(super) fn measure(path: &Path, expected: &ContentRef) -> Result<(), QualificationError> {
    expected.validate()?;
    let length = expected.length.get();
    if length == 0 || length > MAXIMUM_ARTIFACT || expected.hash.domain != "cnp.blob.v1" {
        return Err(refused());
    }
    let mut file = File::open(path).map_err(io)?;
    measured_file(&mut file, expected)?;
    Ok(())
}

pub(super) fn measured_file(
    file: &mut File,
    expected: &ContentRef,
) -> Result<std::fs::Metadata, QualificationError> {
    measured_reader(file, expected)
}

/// Hashes the complete original descriptor without changing its shared cursor.
///
/// # Errors
/// Refuses nonfinite extents, complete byte drift, changed file revisions,
/// unavailable reads, and invalid measured content.
pub(super) fn measured_file_at(
    file: &File,
    expected: &ContentRef,
) -> Result<std::fs::Metadata, QualificationError> {
    measured_reader(&mut PositionalFile { file, offset: 0 }, expected)
}

trait MeasurementReader: Read {
    fn metadata(&self) -> std::io::Result<std::fs::Metadata>;
}

impl MeasurementReader for File {
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        File::metadata(self)
    }
}

struct PositionalFile<'a> {
    file: &'a File,
    offset: u64,
}

impl Read for PositionalFile<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.file.read_at(buffer, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("measured file offset overflow"))?;
        Ok(count)
    }
}

impl MeasurementReader for PositionalFile<'_> {
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.file.metadata()
    }
}

pub(super) trait MeasurementFailure {
    fn refused() -> Self;
    fn io(error: std::io::Error) -> Self;
    fn contract(error: crucible_node_format::ContractError) -> Self;
}

impl MeasurementFailure for QualificationError {
    fn refused() -> Self {
        refused()
    }
    fn io(error: std::io::Error) -> Self {
        io(error)
    }
    fn contract(error: crucible_node_format::ContractError) -> Self {
        error.into()
    }
}

impl MeasurementFailure for crucible_engine::node_contract::RuntimeError {
    fn refused() -> Self {
        Self::InvalidReceipt
    }
    fn io(_: std::io::Error) -> Self {
        Self::OwnerUnavailable
    }
    fn contract(_: crucible_node_format::ContractError) -> Self {
        Self::InvalidReceipt
    }
}

pub(super) fn measured_file_at_data<E: MeasurementFailure>(
    file: &File,
    expected: &ContentRef,
) -> Result<std::fs::Metadata, E> {
    measured_reader_data(&mut PositionalFile { file, offset: 0 }, expected)
}

fn measured_reader(
    file: &mut impl MeasurementReader,
    expected: &ContentRef,
) -> Result<std::fs::Metadata, QualificationError> {
    measured_reader_data(file, expected)
}

// Both entry points execute the same complete hash and terminal metadata fences.
// Only refusal representation differs; the selected native action never formats
// a kernel error before returning its bounded raw status.
fn measured_reader_data<E: MeasurementFailure>(
    file: &mut impl MeasurementReader,
    expected: &ContentRef,
) -> Result<std::fs::Metadata, E> {
    expected.validate().map_err(E::contract)?;
    let length = expected.length.get();
    if length == 0 || length > MAXIMUM_ARTIFACT || expected.hash.domain != "cnp.blob.v1" {
        return Err(E::refused());
    }
    let before = file.metadata().map_err(E::io)?;
    if !before.is_file() || before.len() != length {
        return Err(E::refused());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&length.to_be_bytes());
    let mut buffer = [0u8; STREAMING_BUFFER_BYTES];
    let mut received = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(E::io)?;
        if count == 0 {
            break;
        }
        received = received
            .checked_add(count as u64)
            .filter(|size| *size <= length)
            .ok_or_else(E::refused)?;
        hash.update(&buffer[..count]);
    }
    let actual = ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: hash.finalize().to_hex().to_string(),
        },
        length: U64::new(received),
        media_type: expected.media_type.clone(),
    };
    let after = file.metadata().map_err(E::io)?;
    let facts = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if actual != *expected || facts(&before) != facts(&after) {
        return Err(E::refused());
    }
    Ok(after)
}

pub(super) fn kernel() -> Result<String, QualificationError> {
    let file = File::open("/proc/sys/kernel/osrelease").map_err(io)?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).map_err(io)?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(refused());
    }
    String::from_utf8(bytes).map_err(|_| refused())
}

pub(super) fn io(error: std::io::Error) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

#[cfg(test)]
#[path = "measurement/tests.rs"]
mod tests;

/// Counts the selected fixed kernel comparison phase, excluding compiler frames.
pub(in super::super) fn original_kernel_validation_counter_scratch_data() -> usize {
    std::mem::size_of::<[u8; 4097]>()
        + std::mem::size_of::<File>()
        + std::mem::size_of::<std::io::Error>()
        + std::mem::size_of::<std::str::Utf8Error>()
        + std::mem::size_of::<[usize; 2]>()
        + 384
}

/// Compares the same complete kernel release using a fixed bank and raw errors.
///
/// Ordinary kernel measurement retains its original allocating implementation.
///
/// # Errors
/// Refuses unavailable, empty, oversized, invalid UTF-8 or changed kernel data.
pub(in super::super) fn authenticate_original_kernel_data(
    expected: &str,
) -> Result<(), crucible_engine::node_contract::RuntimeError> {
    use crucible_engine::node_contract::RuntimeError;
    let mut file =
        File::open("/proc/sys/kernel/osrelease").map_err(|_| RuntimeError::OwnerUnavailable)?;
    let mut bank = [0u8; 4097];
    let mut used = 0;
    loop {
        let received = match file.read(&mut bank[used..]) {
            Ok(received) => received,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(RuntimeError::OwnerUnavailable),
        };
        if received == 0 {
            break;
        }
        used = used
            .checked_add(received)
            .ok_or(RuntimeError::ResourceLimit)?;
        if used == bank.len() {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    if used == 0
        || std::str::from_utf8(&bank[..used]).map_err(|_| RuntimeError::InvalidReceipt)? != expected
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
mod original_kernel_validation_tests {
    use super::*;

    #[test]
    fn selected_fixed_kernel_comparison_preserves_complete_release_check() {
        let actual = kernel().unwrap();
        authenticate_original_kernel_data(&actual).unwrap();
        assert!(authenticate_original_kernel_data("").is_err());
        let mut changed = actual;
        changed.push('x');
        assert!(authenticate_original_kernel_data(&changed).is_err());
    }
}
