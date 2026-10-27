//! Retains encoded, admitted-pack and pinned sealed sources for native commands.
//!
//! Each decode is bounded by CDC-12/CDC-13 and re-verifies the bytes actually
//! read. A retained descriptor is not a pin or an allocation reservation.

mod encoded;

use super::NativeHostLayout;
#[cfg(feature = "tokio")]
use super::NativeResidentChunkSource;
use encoded::Dictionary;
use rustix::fs::{Mode, OFlags, open, openat};
#[cfg(feature = "tokio")]
use std::sync::Arc;
use std::{
    fs::{File, Metadata},
    io,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
};
use terrane_format::{
    chunking::ChunkProfile,
    codec::Codec,
    identity::{Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::host::cache::{HostReadLocation, maximum_encoded_chunk_bytes};

/// Retains a verified chunk source from one inspected native domain.
///
/// This grants no surface handle or new pin authority. Encoded sources require
/// their actual owner's original pin and reservation throughout use. Internal
/// sealed sources retain their genuine completed publication job instead. Packed
/// sources retain the original admitted pair under durable container protection.
pub struct NativeChunkSource {
    backing: Backing,
    domain: String,
    identity: Identity,
    length: usize,
    final_chunk: bool,
    profile: ChunkProfile,
    allocation_limit: usize,
}

enum Backing {
    Encoded {
        file: File,
        dictionary: Vec<Dictionary>,
    },
    #[cfg(feature = "tokio")]
    Sealed(Arc<NativeResidentChunkSource>),
    #[cfg(feature = "tokio")]
    Pack(Arc<super::owner::AdmittedPackRead>),
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
        Self::open_inner(layout, identity, Some(length), final_chunk, 2, usize::MAX)
    }

    /// Opens an actual source within the physical owner's per-allocation budget.
    ///
    /// # Errors
    /// Refuses zero or exceeded bounds, changed roots, invalid source bytes and
    /// dictionary dependencies outside the same bounded read policy.
    #[cfg(feature = "tokio")]
    pub(in crate::host_cache) fn open_bounded<L: HostReadLocation>(
        layout: &NativeHostLayout<L>,
        identity: Identity,
        length: usize,
        final_chunk: bool,
        allocation_limit: usize,
        max_members: usize,
    ) -> io::Result<Self> {
        if allocation_limit == 0 || length > allocation_limit {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "chunk source exceeds owner allocation policy",
            ));
        }
        Self::open_inner(
            layout,
            identity,
            Some(length),
            final_chunk,
            max_members,
            allocation_limit,
        )
    }

    fn open_inner<L: HostReadLocation>(
        layout: &NativeHostLayout<L>,
        identity: Identity,
        length: Option<usize>,
        final_chunk: bool,
        max_members: usize,
        allocation_limit: usize,
    ) -> io::Result<Self> {
        layout.recheck()?;
        if max_members == 0 {
            return Err(invalid("source requires a finite nonzero member window"));
        }
        let (file, declared, mut codec) =
            encoded::open(layout, &identity, length, allocation_limit)?;
        let mut dictionary: Vec<Dictionary> = Vec::new();
        while let Codec::ZstdDictionary(digest) = codec {
            if identity.digest() == digest
                || dictionary
                    .iter()
                    .any(|member| member.identity.digest() == digest)
            {
                return Err(invalid("native dictionary dependency cycle"));
            }
            if dictionary.len() >= max_members - 1 {
                return Err(invalid(
                    "native dictionary chain exceeds retained member window",
                ));
            }
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(invalid)?;
            let (file, length, next) = encoded::open(layout, &identity, None, allocation_limit)?;
            dictionary.try_reserve_exact(1).map_err(invalid)?;
            dictionary.push(Dictionary {
                file,
                identity,
                length,
            });
            codec = next;
        }
        let profile = layout.layout.chunk_profile().clone();
        let mut source = Self {
            backing: Backing::Encoded { file, dictionary },
            domain: layout.layout.domain().to_owned(),
            identity,
            length: declared,
            final_chunk,
            profile,
            allocation_limit,
        };
        source.read_verified()?;
        layout.recheck()?;
        Ok(source)
    }

    /// Uses only a genuine retained publication source for an ordered occurrence.
    ///
    /// # Errors
    /// Refuses a source that cannot be nonfinal under the registered profile.
    /// Actual bytes and the occurrence's full boundary context are rechecked
    /// during copying, outside embedded state.
    #[cfg(feature = "tokio")]
    pub(in crate::host_cache) fn from_resident(
        source: Arc<NativeResidentChunkSource>,
        final_chunk: bool,
    ) -> io::Result<Self> {
        let length = source.span().length;
        let profile = source.profile().clone();
        if !final_chunk && length < profile.minimum() {
            return Err(invalid(
                "resident source is too short for a nonfinal occurrence",
            ));
        }
        Ok(Self {
            domain: source.domain().to_owned(),
            identity: source.identity().clone(),
            length,
            final_chunk,
            allocation_limit: profile.maximum(),
            profile,
            backing: Backing::Sealed(source),
        })
    }

    /// Retains an original admitted pair for one ordered chunk occurrence.
    ///
    /// This constructor accepts only the owner's private native read custody.
    /// It grants no new pin; publication synchronizes the container protection
    /// before any copying and retains that protection through durable handoff.
    ///
    /// # Errors
    /// Refuses metadata records or a source too short for a nonfinal occurrence.
    #[cfg(feature = "tokio")]
    pub(in crate::host_cache) fn from_pack(
        source: Arc<super::owner::AdmittedPackRead>,
        final_chunk: bool,
    ) -> io::Result<Self> {
        let (domain, profile, length, allocation_limit) = source.chunk_parameters()?;
        if !final_chunk && length < profile.minimum() {
            return Err(invalid(
                "packed source is too short for a nonfinal occurrence",
            ));
        }
        Ok(Self {
            domain: domain.to_owned(),
            identity: source.identity().clone(),
            length,
            final_chunk,
            profile: profile.clone(),
            allocation_limit,
            backing: Backing::Pack(source),
        })
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

    /// Bounds flat retained dependency descriptors and their owned identity bytes.
    ///
    /// The root source header and identity are owned by the caller's containing
    /// record. Discovery checks existing identities without allocating a second
    /// set; reverse decoding retains only the current plaintext window.
    ///
    /// # Errors
    /// Refuses a zero member limit or overflow in dependency storage arithmetic.
    #[cfg(feature = "tokio")]
    pub(in crate::host_cache) fn dictionary_storage_bytes(max_members: usize) -> io::Result<usize> {
        max_members
            .checked_sub(1)
            .and_then(|count| {
                count.checked_mul(
                    std::mem::size_of::<Dictionary>()
                        + TERRANE_V1.name().len()
                        + TERRANE_V1.digest_len(),
                )
            })
            .ok_or_else(|| invalid("native dictionary storage overflow"))
    }

    /// Borrows actual source and dictionary chain handles for owner binding.
    #[cfg(feature = "tokio")]
    pub(in crate::host_cache) fn handles(&self) -> impl Iterator<Item = (&Identity, usize, &File)> {
        let (source, dictionaries) = match &self.backing {
            Backing::Encoded { file, dictionary } => (
                Some((&self.identity, self.length, file)),
                dictionary.as_slice(),
            ),
            Backing::Sealed(_) | Backing::Pack(_) => (None, &[][..]),
        };
        source.into_iter().chain(
            dictionaries
                .iter()
                .map(|dictionary| (&dictionary.identity, dictionary.length, &dictionary.file)),
        )
    }

    pub(super) fn matches(
        &self,
        domain: &str,
        identity: &Identity,
        length: usize,
        position: terrane_sdk::store::ChunkPosition,
        profile: &ChunkProfile,
    ) -> bool {
        self.domain == domain
            && &self.identity == identity
            && self.length == length
            && self.final_chunk == matches!(position, terrane_sdk::store::ChunkPosition::Final)
            && &self.profile == profile
    }

    /// Reads verified plaintext while preserving existing mutable call sites.
    ///
    /// # Errors
    /// Refuses changed, oversized or invalid source and dictionary bytes.
    pub(super) fn read_verified(&mut self) -> io::Result<Vec<u8>> {
        self.read_verified_at()
    }

    /// Verifies retained bytes without changing any shared open-file cursor.
    ///
    /// The source and dictionary chain use positioned reads. Concurrent
    /// consumers retain independent bounded buffers without a source mutex.
    ///
    /// # Errors
    /// Refuses changed native metadata, invalid identities or boundaries,
    /// decompression failures and allocation beyond the configured bound.
    pub(in crate::host_cache) fn read_verified_at(&self) -> io::Result<Vec<u8>> {
        match &self.backing {
            Backing::Encoded { file, dictionary } => {
                let encoded = read_bounded(file, &self.profile, self.allocation_limit)?;
                let verified = self.decode_encoded(&encoded, dictionary)?;
                Ok(verified.plaintext().to_vec())
            }
            #[cfg(feature = "tokio")]
            Backing::Sealed(source) => self.check_ordered_plaintext(source.read_verified()?),
            #[cfg(feature = "tokio")]
            Backing::Pack(source) => self.check_ordered_plaintext(source.read_verified()?),
        }
    }

    #[cfg(feature = "tokio")]
    fn check_ordered_plaintext(&self, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        if bytes.len() != self.length
            || self.profile.first_boundary(&bytes) != bytes.len()
            || (!self.final_chunk && !self.profile.valid_nonfinal_chunk(&bytes))
        {
            return Err(invalid(
                "native source differs from its ordered chunk context",
            ));
        }
        Ok(bytes)
    }

    /// Returns the original verified envelope, or a raw envelope for a sealed source.
    ///
    /// # Errors
    /// Refuses changed native bytes, invalid identities/boundaries, missing
    /// dictionaries, revoked sealed backing and exceeded allocation bounds.
    #[cfg(feature = "tokio")]
    pub(in crate::host_cache) fn read_encoded_at(&self) -> io::Result<Vec<u8>> {
        match &self.backing {
            Backing::Encoded { file, dictionary } => {
                let encoded = read_bounded(file, &self.profile, self.allocation_limit)?;
                self.decode_encoded(&encoded, dictionary)?;
                Ok(encoded)
            }
            #[cfg(feature = "tokio")]
            Backing::Sealed(source) => {
                let encoded = source.read_encoded()?;
                self.decode_encoded(&encoded, &[])?;
                Ok(encoded)
            }
            Backing::Pack(source) => {
                drop(self.read_verified_at()?);
                source.read_encoded()
            }
        }
    }

    fn decode_encoded<'a>(
        &self,
        encoded: &'a [u8],
        dictionaries: &[Dictionary],
    ) -> io::Result<terrane_sdk::codec::VerifiedChunk<'a>> {
        // Reverse discovery order makes each verified plaintext available to
        // its immediate dependent without recursion or retaining older decodes.
        let mut dictionary: Option<Vec<u8>> = None;
        for dependency in dictionaries.iter().rev() {
            let encoded = read_bounded(&dependency.file, &self.profile, self.allocation_limit)?;
            let verified = terrane_sdk::codec::decode_verified(
                &encoded,
                dependency.length,
                &self.profile,
                true,
                &dependency.identity,
                dictionary.as_deref(),
            )
            .map_err(invalid)?;
            dictionary = Some(verified.plaintext().to_vec());
        }
        terrane_sdk::codec::decode_verified(
            encoded,
            self.length,
            &self.profile,
            self.final_chunk,
            &self.identity,
            dictionary.as_deref(),
        )
        .map_err(invalid)
    }
}

fn read_bounded(
    file: &File,
    profile: &ChunkProfile,
    allocation_limit: usize,
) -> io::Result<Vec<u8>> {
    let profile_bound = maximum_encoded_chunk_bytes(profile).map_err(invalid)?;
    let bound = profile_bound.min(allocation_limit);
    let before = file.metadata()?;
    if !before.is_file() || before.len() > profile_bound as u64 {
        return Err(invalid("source exceeds existing encoded chunk bound"));
    }
    if before.len() > bound as u64 {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "encoded source exceeds owner allocation policy",
        ));
    }
    let length = usize::try_from(before.len()).map_err(invalid)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
    if encoded.capacity() > bound {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "source capacity exceeds owner allocation policy",
        ));
    }
    encoded.resize(length, 0);
    file.read_exact_at(&mut encoded, 0)?;
    // Probe growth on the stack; an adversarial file must not grow a heap
    // allocation beyond the original checked window merely to detect overflow.
    let mut extra = [0];
    if file.read_at(&mut extra, before.len())? != 0 {
        return Err(invalid("source grew beyond its checked allocation"));
    }
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
    use std::io::{Read, Seek, SeekFrom};

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

    #[cfg(feature = "tokio")]
    #[test]
    fn encoded_chain_verifies_terminal_dependencies_without_moving_original_cursors() {
        // Only the retained decode algorithm is exercised here. These ordinary
        // files supply no native owner, funded pin, cache custody or authority.
        let fixture = Fixture::new();
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let base = b"retained dictionary vocabulary ".repeat(32);
        let middle = b"retained dictionary vocabulary for selected content ".repeat(64);
        let body = b"retained dictionary vocabulary for selected content and file ".repeat(128);
        let identity = |bytes: &[u8]| TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
        let encode = |bytes: &[u8], dictionary| {
            terrane_sdk::codec::encode_chunk(bytes, profile.maximum(), 3, dictionary).unwrap()
        };
        let base_encoded = encode(&base, None);
        let middle_encoded = encode(&middle, Some(base.as_slice()));
        let body_encoded = encode(&body, Some(middle.as_slice()));
        for (encoded, dictionary) in [(&middle_encoded, &base), (&body_encoded, &middle)] {
            assert_eq!(
                terrane_format::codec::parse_envelope(encoded)
                    .unwrap()
                    .codec,
                Codec::ZstdDictionary(identity(dictionary).terrane_v1_digest().unwrap())
            );
        }
        let mut files = Vec::new();
        for (name, encoded) in [
            ("body", &body_encoded),
            ("middle", &middle_encoded),
            ("base", &base_encoded),
        ] {
            let path = fixture.0.join(name);
            std::fs::write(&path, encoded).unwrap();
            let mut file = File::open(&path).unwrap();
            file.seek(SeekFrom::Start(7)).unwrap();
            files.push(file);
        }
        let source = NativeChunkSource {
            backing: Backing::Encoded {
                file: files.remove(0),
                dictionary: vec![
                    Dictionary {
                        file: files.remove(0),
                        identity: identity(&middle),
                        length: middle.len(),
                    },
                    Dictionary {
                        file: files.remove(0),
                        identity: identity(&base),
                        length: base.len(),
                    },
                ],
            },
            domain: "public".into(),
            identity: identity(&body),
            length: body.len(),
            final_chunk: true,
            profile,
            allocation_limit: 65_536,
        };

        assert_eq!(source.read_encoded_at().unwrap(), body_encoded);
        assert_eq!(source.read_verified_at().unwrap(), body);
        assert_eq!(source.handles().count(), 3);
        for (_, _, file) in source.handles() {
            assert_eq!(file.try_clone().unwrap().stream_position().unwrap(), 7);
        }

        let corrupt = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
            codec: Codec::Raw,
            body: &vec![b'?'; base.len()],
        });
        std::fs::write(fixture.0.join("base"), corrupt).unwrap();
        assert!(source.read_encoded_at().is_err());
        assert!(source.read_verified_at().is_err());
        for (_, _, file) in source.handles() {
            assert_eq!(file.try_clone().unwrap().stream_position().unwrap(), 7);
        }
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn encoded_consumer_verifies_original_envelope_before_returning_bytes() {
        // This tests bounded codec verification only. No layout, admission,
        // quota, consumer pin or serving authority is manufactured here.
        let fixture = Fixture::new();
        let plaintext = vec![b'E'; 65536];
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let encoded =
            terrane_sdk::codec::encode_chunk(&plaintext, profile.maximum(), 3, None).unwrap();
        assert_eq!(encoded[0], 1);
        let path = fixture.0.join("encoded");
        std::fs::write(&path, &encoded).unwrap();
        let mut file = File::open(&path).unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        let mut source = NativeChunkSource {
            backing: Backing::Encoded {
                file,
                dictionary: Vec::new(),
            },
            domain: "public".into(),
            identity: TERRANE_V1
                .calculate(IdentityKind::Chunk, &plaintext)
                .unwrap(),
            length: plaintext.len(),
            final_chunk: true,
            profile,
            allocation_limit: plaintext.len(),
        };

        assert_eq!(source.read_encoded_at().unwrap(), encoded);
        let Backing::Encoded { file, .. } = &mut source.backing else {
            panic!("encoded fixture changed class")
        };
        assert_eq!(file.stream_position().unwrap(), 7);

        source.allocation_limit = encoded.len() - 1;
        assert_eq!(
            source.read_encoded_at().unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );

        source.allocation_limit = plaintext.len();
        let different = terrane_sdk::codec::encode_chunk(
            &vec![b'F'; plaintext.len()],
            source.profile.maximum(),
            3,
            None,
        )
        .unwrap();
        std::fs::write(&path, different).unwrap();
        assert!(source.read_encoded_at().is_err());

        std::fs::write(&path, &encoded).unwrap();
        source.final_chunk = false;
        assert!(source.read_encoded_at().is_err());
    }

    #[test]
    fn native_chunk_read_enforces_owner_window_before_allocation_or_cursor_changes() {
        let fixture = Fixture::new();
        let bytes = b"bounded source bytes";
        std::fs::write(fixture.0.join("chunk"), bytes).unwrap();
        let mut file = File::open(fixture.0.join("chunk")).unwrap();
        let profile = ChunkProfile::cdc_1m([0; 32]);
        file.seek(SeekFrom::Start(3)).unwrap();

        let error = read_bounded(&file, &profile, bytes.len() - 1).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(file.stream_position().unwrap(), 3);

        let actual = read_bounded(&file, &profile, bytes.len()).unwrap();

        assert_eq!(actual, bytes);
        assert!(actual.capacity() <= bytes.len());
        assert_eq!(file.stream_position().unwrap(), 3);

        // Duplicated descriptors share one open-file cursor. Successful reads
        // must leave it alone even when every reader starts simultaneously.
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    let shared = file.try_clone().unwrap();
                    let barrier = &barrier;
                    let profile = &profile;
                    scope.spawn(move || {
                        barrier.wait();
                        for _ in 0..32 {
                            assert_eq!(read_bounded(&shared, profile, bytes.len()).unwrap(), bytes);
                        }
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
        });
        assert_eq!(file.stream_position().unwrap(), 3);
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
