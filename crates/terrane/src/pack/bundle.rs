//! Encodes canonical, all-or-nothing verified bundles for a root commit.
//!
//! ```text
//! {1: root-commit:bytes32, 2: [[kind:uint, hash:bytes32, bytes:bstr], ...]}
//! ```

use super::{EntryKind, PackError, digest, verify};
use std::collections::BTreeSet;
use terrane_core::cbor::{Decoder, write_array, write_bytes, write_map, write_uint};
use terrane_core::identity::Digest;

const MAX_OBJECTS: usize = 1_048_576;
const MAX_BYTES: usize = 1024 * 1024 * 1024;

/// One verified immutable carried in a bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleObject {
    kind: EntryKind,
    hash: Digest,
    bytes: Vec<u8>,
}

impl BundleObject {
    /// Validates canonical bytes and computes their registered identity.
    ///
    /// # Errors
    /// Rejects noncanonical metadata or oversized objects.
    pub fn new(kind: EntryKind, bytes: Vec<u8>) -> Result<Self, PackError> {
        if bytes.len() > MAX_BYTES {
            return Err(PackError::Limit);
        }
        if kind != EntryKind::Chunk {
            super::reader::validate_metadata(kind, &bytes)?;
        }
        Ok(Self {
            kind,
            hash: digest(kind, &bytes)?,
            bytes,
        })
    }

    /// Returns the verified identity kind.
    pub const fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Returns the verified content digest.
    pub const fn hash(&self) -> &Digest {
        &self.hash
    }

    /// Borrows the verified canonical object bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A canonical metadata bundle verified before exposing any contained object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bundle {
    root_commit: Digest,
    objects: Vec<BundleObject>,
}

impl Bundle {
    /// Produces a bundle while omitting every identity held by the requester.
    ///
    /// Input order is retained after moving the root commit to the front. The
    /// repository supplies remaining tree objects in root-first traversal order;
    /// this format layer does not inspect tree relationships.
    ///
    /// # Errors
    /// Rejects duplicate objects or encoded bundles exceeding the CDDL limits.
    pub fn new(
        root_commit: Digest,
        mut objects: Vec<BundleObject>,
        held: &[(EntryKind, Digest)],
    ) -> Result<Self, PackError> {
        objects.retain(|object| !held.contains(&(object.kind, object.hash)));
        if let Some(root) = objects
            .iter()
            .position(|object| object.kind == EntryKind::Commit && object.hash == root_commit)
        {
            let object = objects.remove(root);
            objects.insert(0, object);
        }
        validate_objects(&objects)?;
        let bundle = Self {
            root_commit,
            objects,
        };
        if bundle.encode().len() > MAX_BYTES {
            return Err(PackError::Limit);
        }
        Ok(bundle)
    }

    /// Returns the commit served by this bundle.
    pub const fn root_commit(&self) -> &Digest {
        &self.root_commit
    }

    /// Borrows all contained objects only after whole-bundle verification.
    pub fn objects(&self) -> &[BundleObject] {
        &self.objects
    }

    /// Returns this bundle's canonical CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_map(&mut bytes, 2);
        write_uint(&mut bytes, 1);
        write_bytes(&mut bytes, &self.root_commit);
        write_uint(&mut bytes, 2);
        write_array(&mut bytes, self.objects.len());
        for object in &self.objects {
            write_array(&mut bytes, 3);
            write_uint(&mut bytes, object.kind as u64);
            write_bytes(&mut bytes, &object.hash);
            write_bytes(&mut bytes, &object.bytes);
        }
        bytes
    }

    /// Returns the identity of the canonical bundle in its registered domain.
    ///
    /// # Errors
    /// Returns an error if the configured initial identity profile fails.
    pub fn identity(&self) -> Result<Digest, PackError> {
        digest(EntryKind::Bundle, &self.encode())
    }

    /// Decodes and verifies every triple before exposing any of them.
    ///
    /// # Errors
    /// Rejects noncanonical or unknown schema fields, duplicate objects, invalid
    /// kinds, excessive lengths, trailing data, or any mismatching identity.
    pub fn decode(bytes: &[u8]) -> Result<Self, PackError> {
        if bytes.len() > MAX_BYTES {
            return Err(PackError::Limit);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.map(2)? != 2 || decoder.uint()? != 1 {
            return Err(PackError::Index);
        }
        let root_commit = decoder
            .bytes(32)?
            .try_into()
            .map_err(|_| PackError::Index)?;
        if decoder.uint()? != 2 {
            return Err(PackError::Index);
        }
        let count = decoder.array(MAX_OBJECTS)?;
        let mut objects = Vec::with_capacity(count);
        for _ in 0..count {
            if decoder.array(3)? != 3 {
                return Err(PackError::Index);
            }
            let kind =
                EntryKind::try_from(u8::try_from(decoder.uint()?).map_err(|_| PackError::Kind)?)?;
            let hash = decoder
                .bytes(32)?
                .try_into()
                .map_err(|_| PackError::Index)?;
            let body = decoder.bytes(MAX_BYTES)?;
            if kind != EntryKind::Chunk {
                super::reader::validate_metadata(kind, body)?;
            }
            verify(kind, &hash, body)?;
            objects.push(BundleObject {
                kind,
                hash,
                bytes: body.to_vec(),
            });
        }
        decoder.finish()?;
        validate_objects(&objects)?;
        Ok(Self {
            root_commit,
            objects,
        })
    }
}

fn validate_objects(objects: &[BundleObject]) -> Result<(), PackError> {
    if objects.len() > MAX_OBJECTS {
        return Err(PackError::Limit);
    }
    let mut identities = BTreeSet::new();
    for object in objects {
        if !identities.insert(object.hash) {
            return Err(PackError::Duplicate);
        }
    }
    Ok(())
}
