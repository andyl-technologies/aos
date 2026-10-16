//! Retains genuine domain-bound encoded chunk descriptors for native commands.
//!
//! Each decode is bounded by CDC-12/CDC-13 and re-verifies the bytes actually
//! read. A retained descriptor is not a pin or an allocation reservation.

use super::NativeHostLayout;
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
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
            match openat(
                &shard,
                format!("{hash}.{codec}"),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(descriptor) => {
                    file = Some((File::from(descriptor), codec));
                    break;
                }
                Err(rustix::io::Errno::NOENT) => continue,
                Err(error) => return Err(error.into()),
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

fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}
