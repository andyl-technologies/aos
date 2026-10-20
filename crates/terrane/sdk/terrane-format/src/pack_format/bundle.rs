//! Encodes and verifies canonical bundle triples without caching or I/O.
//!
//! ```text
//! {1: root-commit:bytes32, 2: [[kind:uint, hash:bytes32, bytes:bstr], ...]}
//! ```

use super::Error;
use crate::cbor::{Decoder, write_array, write_bytes, write_map, write_uint};
use crate::identity::{Digest, IdentityKind, TERRANE_V1};
use alloc::vec::Vec;

/// The normative maximum number of objects in a bundle.
pub const MAX_BUNDLE_OBJECTS: usize = 1_048_576;
/// The normative maximum encoded bundle size.
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024 * 1024;

/// A borrowed object triple in a bundle's canonical representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleRecord<'a> {
    /// The registered pack-kind byte.
    pub kind: u8,
    /// The content identity in the domain selected by the kind byte.
    pub hash: Digest,
    /// The plaintext chunk or canonical metadata bytes.
    pub bytes: &'a [u8],
}

/// A bundle whose complete object list passed canonical and identity checks.
#[derive(Debug)]
pub struct BundleView<'a> {
    root_commit: Digest,
    objects: Vec<BundleRecord<'a>>,
}

impl<'a> BundleView<'a> {
    /// Returns the commit served by this verified bundle.
    pub const fn root_commit(&self) -> &Digest {
        &self.root_commit
    }

    /// Borrows all verified triples from the original encoded bundle.
    pub fn objects(&self) -> &[BundleRecord<'a>] {
        &self.objects
    }
}

/// Computes encoded bundle size before allocating output bytes.
///
/// # Errors
/// Rejects counts or encoded sizes beyond the normative CDDL limits.
pub fn bundle_size(objects: &[BundleRecord<'_>]) -> Result<usize, Error> {
    if objects.len() > MAX_BUNDLE_OBJECTS {
        return Err(Error::Limit);
    }
    let mut size = 37_usize
        .checked_add(argument_size(objects.len()))
        .ok_or(Error::Limit)?;
    for object in objects {
        size = size
            .checked_add(36)
            .and_then(|size| size.checked_add(argument_size(object.bytes.len())))
            .and_then(|size| size.checked_add(object.bytes.len()))
            .ok_or(Error::Limit)?;
    }
    if size > MAX_BUNDLE_BYTES {
        return Err(Error::Limit);
    }
    Ok(size)
}

/// Encodes canonical CBOR triples in their supplied order.
///
/// Callers supply verified records within [`bundle_size`] limits; decoding
/// verifies every triple before exposing a view of untrusted input bytes.
pub fn encode_bundle(root_commit: &Digest, objects: &[BundleRecord<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_map(&mut bytes, 2);
    write_uint(&mut bytes, 1);
    write_bytes(&mut bytes, root_commit);
    write_uint(&mut bytes, 2);
    write_array(&mut bytes, objects.len());
    for object in objects {
        write_array(&mut bytes, 3);
        write_uint(&mut bytes, u64::from(object.kind));
        write_bytes(&mut bytes, &object.hash);
        write_bytes(&mut bytes, object.bytes);
    }
    bytes
}

/// Verifies canonical schema and all object identities before returning a view.
///
/// # Errors
/// Rejects noncanonical or unknown schema fields, invalid kinds, size limits,
/// malformed canonical metadata, trailing bytes, or mismatching identities.
pub fn decode_bundle(bytes: &[u8]) -> Result<BundleView<'_>, Error> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Limit);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.map(2)? != 2 || decoder.uint()? != 1 {
        return Err(Error::Malformed);
    }
    let root_commit = decoder
        .bytes(32)?
        .try_into()
        .map_err(|_| Error::Malformed)?;
    if decoder.uint()? != 2 {
        return Err(Error::Malformed);
    }
    let count = decoder.array(MAX_BUNDLE_OBJECTS)?;
    let mut objects = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array(3)? != 3 {
            return Err(Error::Malformed);
        }
        let kind = u8::try_from(decoder.uint()?).map_err(|_| Error::Kind)?;
        let identity_kind = identity_kind(kind)?;
        let hash = decoder
            .bytes(32)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let body = decoder.bytes(MAX_BUNDLE_BYTES)?;
        if kind != 0 {
            validate_metadata(kind, body)?;
        }
        if TERRANE_V1
            .calculate(identity_kind, body)?
            .terrane_v1_digest()?
            != hash
        {
            return Err(Error::Identity(
                crate::identity::IdentityError::DigestMismatch,
            ));
        }
        objects.push(BundleRecord {
            kind,
            hash,
            bytes: body,
        });
    }
    decoder.finish()?;
    Ok(BundleView {
        root_commit,
        objects,
    })
}

/// Verifies canonical metadata encoding without interpreting repository schemas.
///
/// Schema interpretation is delegated to the admitting store's configured pure
/// format validator. This check rejects unsupported canonical forms and verifies
/// registered binary index copies rather than treating them as CBOR.
///
/// # Errors
/// Rejects data kinds, unknown kinds, malformed or noncanonical CBOR, and
/// inconsistent binary indexes.
pub fn validate_metadata(kind: u8, bytes: &[u8]) -> Result<(), Error> {
    identity_kind(kind)?;
    if kind == 0 {
        return Err(Error::Kind);
    }
    if kind == 6 {
        if bytes.starts_with(b"TRPK") {
            super::decode_detached_index(bytes)?;
        } else if bytes.starts_with(b"TRIX") {
            let shard = bytes.get(super::PREAMBLE_SIZE).copied().unwrap_or(0);
            super::decode_shard(bytes, shard)?;
        } else {
            return Err(Error::Index);
        }
        return Ok(());
    }
    let mut decoder = Decoder::new(bytes);
    decoder.skip_value(bytes.len())?;
    decoder.finish()?;
    Ok(())
}

fn identity_kind(kind: u8) -> Result<IdentityKind, Error> {
    match kind {
        0 => Ok(IdentityKind::Chunk),
        1 => Ok(IdentityKind::Manifest),
        2 => Ok(IdentityKind::Node),
        3 => Ok(IdentityKind::Commit),
        4 => Ok(IdentityKind::Bundle),
        5 => Ok(IdentityKind::Filter),
        6 => Ok(IdentityKind::Index),
        7 => Ok(IdentityKind::Attribute),
        8 => Ok(IdentityKind::Policy),
        9 => Ok(IdentityKind::Memo),
        _ => Err(Error::Kind),
    }
}

fn argument_size(value: usize) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=4294967295 => 5,
        _ => 9,
    }
}
