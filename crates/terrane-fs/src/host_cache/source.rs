//! Retains genuine domain-bound encoded chunk descriptors for native commands.
//!
//! Each decode is bounded by CDC-12/CDC-13 and re-verifies the bytes actually
//! read. A retained descriptor is not a pin or an allocation reservation.

use super::NativeHostLayout;
use rustix::fs::{Mode, OFlags, open, openat};
use std::{
    fs::{File, Metadata},
    io::{self, Read, Seek, SeekFrom},
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
};
use terrane::host::cache::{
    HostReadLocation, inspect_standalone_length, maximum_encoded_chunk_bytes,
};
use terrane_core::{
    chunking::ChunkProfile,
    codec::Codec,
    identity::{Identity, IdentityKind, TERRANE_V1},
};

/// Retains a verified chunk source from one inspected domain's chunk directory.
///
/// This type grants no surface handle or pin authority. The native command
/// owner must retain the corresponding real pin and reservation throughout use.
pub struct NativeChunkSource {
    file: File,
    domain: String,
    identity: Identity,
    length: usize,
    final_chunk: bool,
    profile: ChunkProfile,
    dictionary: Option<Box<NativeChunkSource>>,
}

impl NativeChunkSource {
    /// Opens and verifies the requested canonical chunk using retained directories.
    ///
    /// The layout comes from trusted composition; this method does not authorize
    /// a request. It never accepts an arbitrary source path or caller descriptor.
    ///
    /// # Errors
    /// Refuses changed directories, absent/malformed/corrupt chunks, profile or
    /// boundary mismatch, oversized bodies and nested dictionary dependencies.
    pub fn open<L: HostReadLocation>(
        layout: &NativeHostLayout<L>,
        identity: Identity,
        length: usize,
        final_chunk: bool,
    ) -> io::Result<Self> {
        Self::open_inner(layout, identity, Some(length), final_chunk, true)
    }

    fn open_inner<L: HostReadLocation>(
        layout: &NativeHostLayout<L>,
        identity: Identity,
        length: Option<usize>,
        final_chunk: bool,
        allow_dictionary: bool,
    ) -> io::Result<Self> {
        layout.recheck()?;
        if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
            return Err(invalid("source is not a configured chunk identity"));
        }
        let hash: String = identity
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if hash.len() != 64 {
            return Err(invalid("source digest has invalid width"));
        }
        let directory = layout
            .directories
            .get("chunks")
            .ok_or_else(|| invalid("missing retained chunk directory"))?;
        let shard = openat(
            directory,
            &hash[..2],
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut file = None;
        for codec in 0_u8..=2 {
            match open_regular_at(&shard, &format!("{hash}.{codec}")) {
                Ok(descriptor) => {
                    file = Some((descriptor, codec));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
        }
        let (mut file, codec) =
            file.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "chunk source absent"))?;
        let profile = layout.layout.chunk_profile().clone();
        let encoded = read_bounded(&mut file, &profile)?;
        if encoded.first() != Some(&codec) {
            return Err(invalid("source codec differs from canonical filename"));
        }
        let declared = match length {
            Some(length) => length,
            None => inspect_standalone_length(&encoded, &profile).map_err(invalid)?,
        };
        if declared > profile.maximum() {
            return Err(invalid("source declaration exceeds chunk profile"));
        }
        let envelope = terrane_core::codec::parse_envelope(&encoded).map_err(invalid)?;
        let dictionary = if let Codec::ZstdDictionary(digest) = envelope.codec {
            if !allow_dictionary {
                return Err(invalid(
                    "dictionary source cannot depend on another dictionary",
                ));
            }
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(invalid)?;
            Some(Box::new(Self::open_inner(
                layout, identity, None, true, false,
            )?))
        } else {
            None
        };
        let mut source = Self {
            file,
            domain: layout.layout.domain().to_owned(),
            identity,
            length: declared,
            final_chunk,
            profile,
            dictionary,
        };
        source.read_verified()?;
        layout.recheck()?;
        Ok(source)
    }

    /// Returns the source's trusted configured domain label.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the identity verified against this source's actual plaintext.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the verified plaintext length.
    pub fn plaintext_length(&self) -> usize {
        self.length
    }

    pub(super) fn matches(
        &self,
        domain: &str,
        identity: &Identity,
        length: usize,
        position: terrane::store::ChunkPosition,
        profile: &ChunkProfile,
    ) -> bool {
        self.domain == domain
            && &self.identity == identity
            && self.length == length
            && self.final_chunk == matches!(position, terrane::store::ChunkPosition::Final)
            && &self.profile == profile
    }

    pub(super) fn read_verified(&mut self) -> io::Result<Vec<u8>> {
        let encoded = read_bounded(&mut self.file, &self.profile)?;
        let dictionary = self
            .dictionary
            .as_mut()
            .map(|source| source.read_verified())
            .transpose()?;
        let verified = terrane::codec::decode_verified(
            &encoded,
            self.length,
            &self.profile,
            self.final_chunk,
            &self.identity,
            dictionary.as_deref(),
        )
        .map_err(invalid)?;
        Ok(verified.plaintext().to_vec())
    }
}

fn read_bounded(file: &mut File, profile: &ChunkProfile) -> io::Result<Vec<u8>> {
    let bound = maximum_encoded_chunk_bytes(profile).map_err(invalid)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > bound as u64 {
        return Err(invalid("source exceeds existing encoded chunk bound"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut encoded = Vec::new();
    file.by_ref()
        .take(
            (bound as u64)
                .checked_add(1)
                .ok_or_else(|| invalid("encoded chunk bound overflow"))?,
        )
        .read_to_end(&mut encoded)?;
    let after = file.metadata()?;
    if encoded.len() > bound
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(invalid("source changed while reading"));
    }
    Ok(encoded)
}

/// Classifies a canonical chunk without invoking a special file's read-open.
fn open_regular_at(parent: impl AsFd, name: &str) -> io::Result<File> {
    let observation = File::from(openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = observation.metadata()?;
    if !before.is_file() {
        return Err(invalid("chunk source is not an ordinary regular inode"));
    }

    // Read the classified inode through its retained descriptor. A replaced
    // canonical name cannot redirect this open to a FIFO, device or symlink.
    let file = File::from(open(
        format!("/proc/self/fd/{}", observation.as_raw_fd()),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !same_file(&before, &file.metadata()?) || !same_file(&before, &observation.metadata()?) {
        return Err(invalid("classified chunk changed during read-only reopen"));
    }
    Ok(file)
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut random)
                .unwrap();
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("terrane-chunk-open-{suffix}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn native_chunk_open_classifies_fifo_symlink_and_character_device_before_read_open() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("chunk"), b"encoded chunk").unwrap();
        let parent = File::open(&fixture.0).unwrap();
        rustix::fs::mkfifoat(&parent, "fifo", Mode::from_raw_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("chunk", fixture.0.join("symlink")).unwrap();

        let mut file = open_regular_at(&parent, "chunk").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"encoded chunk");
        for name in ["fifo", "symlink"] {
            assert_eq!(
                open_regular_at(&parent, name).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            open_regular_at(File::open("/dev").unwrap(), "null")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn native_chunk_source_errors_preserve_typed_causes() {
        let error = invalid(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source denied",
        ));
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
