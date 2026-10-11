//! Streams independently pinned public artifacts and current host facts.

use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crucible_node_contract::{ContentRef, HashRef, U64, Validate};
use serde::Serialize;

use super::refused;
use crate::node_qualification::QualificationError;

const MAXIMUM_ARTIFACT: u64 = 512 * 1024 * 1024;
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
#[derive(Clone, Serialize)]
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
#[derive(Clone, Serialize)]
pub struct PacketFixtureMeasurements {
    /// Names and pins the actual packet peer executable.
    pub peer: PacketFixtureArtifact,
    /// Pins the actual current host executable at `/proc/self/exe`.
    pub host: ContentRef,
    /// Retains all eight public source roles, in strictly increasing role order.
    pub sources: Vec<PacketFixtureArtifact>,
}

impl PacketFixtureMeasurements {
    /// Remeasures all selected files and the actual current host executable.
    ///
    /// The streaming reader uses a fixed 64 KiB buffer. Complete file identity
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
    expected.validate()?;
    let length = expected.length.get();
    if length == 0 || length > MAXIMUM_ARTIFACT || expected.hash.domain != "cnp.blob.v1" {
        return Err(refused());
    }
    let before = file.metadata().map_err(io)?;
    if !before.is_file() || before.len() != length {
        return Err(refused());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&length.to_be_bytes());
    let mut buffer = [0u8; 65_536];
    let mut received = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        received = received
            .checked_add(count as u64)
            .filter(|size| *size <= length)
            .ok_or_else(refused)?;
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
    let after = file.metadata().map_err(io)?;
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
        return Err(refused());
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
