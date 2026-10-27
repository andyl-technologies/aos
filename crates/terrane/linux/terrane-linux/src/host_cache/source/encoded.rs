//! Opens canonical encoded members without granting native custody or pin authority.
//!
//! The owner supplies its allocation and member bounds. Each retained descriptor
//! is independently decoded by the parent source only after chain discovery.

use super::{NativeHostLayout, invalid, open_regular_at, read_bounded};
use rustix::fs::{Mode, OFlags, openat};
use std::{fs::File, io};
use terrane_format::{
    codec::Codec,
    identity::{Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::host::cache::{HostReadLocation, inspect_standalone_length};

/// Retains one original dependency descriptor and its independent content declaration.
pub(super) struct Dictionary {
    /// Holds the original no-follow canonical inode.
    pub(super) file: File,
    /// Names the independently verified dictionary plaintext.
    pub(super) identity: Identity,
    /// Records the standalone plaintext declaration.
    pub(super) length: usize,
}

/// Opens an original canonical member within its individual encoded/plaintext bounds.
///
/// # Errors
/// Refuses missing or unsafe canonical entries, invalid identities, codec/name
/// mismatches, malformed frames and encoded or decoded lengths beyond policy.
pub(super) fn open<L: HostReadLocation>(
    layout: &NativeHostLayout<L>,
    identity: &Identity,
    length: Option<usize>,
    allocation_limit: usize,
) -> io::Result<(File, usize, Codec)> {
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
    let (file, codec) =
        file.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "chunk source absent"))?;
    let profile = layout.layout.chunk_profile();
    let encoded = read_bounded(&file, profile, allocation_limit)?;
    if encoded.first() != Some(&codec) {
        return Err(invalid("source codec differs from canonical filename"));
    }
    let declared = match length {
        Some(length) => length,
        None => inspect_standalone_length(&encoded, profile).map_err(invalid)?,
    };
    if declared > profile.maximum() {
        return Err(invalid("source declaration exceeds chunk profile"));
    }
    if declared > allocation_limit {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "decoded source exceeds owner allocation policy",
        ));
    }
    let codec = terrane_format::codec::parse_envelope(&encoded)
        .map_err(invalid)?
        .codec;
    Ok((file, declared, codec))
}
