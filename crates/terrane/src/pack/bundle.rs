//! Encodes canonical, all-or-nothing verified bundles for a root commit.
//!
//! ```text
//! {1: root-commit:bytes32, 2: [[kind:uint, hash:bytes32, bytes:bstr], ...]}
//! ```

use super::{EntryKind, PackError, digest};
use terrane_core::identity::Digest;
use terrane_core::pack_format::{self, BundleRecord};

const MAX_OBJECTS: usize = pack_format::MAX_BUNDLE_OBJECTS;
const MAX_BYTES: usize = pack_format::MAX_BUNDLE_BYTES;

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
    /// Rejects encoded bundles exceeding the CDDL object-count or byte limits.
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
        if bundle.encoded_size()? > MAX_BYTES {
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

    fn records(&self) -> Vec<BundleRecord<'_>> {
        self.objects
            .iter()
            .map(|object| BundleRecord {
                kind: object.kind as u8,
                hash: object.hash,
                bytes: &object.bytes,
            })
            .collect()
    }

    fn encoded_size(&self) -> Result<usize, PackError> {
        Ok(pack_format::bundle_size(&self.records())?)
    }

    /// Returns this bundle's canonical CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        pack_format::encode_bundle(&self.root_commit, &self.records())
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
    /// Rejects noncanonical or unknown schema fields, invalid
    /// kinds, excessive lengths, trailing data, or any mismatching identity.
    pub fn decode(bytes: &[u8]) -> Result<Self, PackError> {
        let view = pack_format::decode_bundle(bytes)?;
        let objects = view
            .objects()
            .iter()
            .map(|object| {
                Ok(BundleObject {
                    kind: EntryKind::try_from(object.kind)?,
                    hash: object.hash,
                    bytes: object.bytes.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, PackError>>()?;
        Ok(Self {
            root_commit: *view.root_commit(),
            objects,
        })
    }
}

fn validate_objects(objects: &[BundleObject]) -> Result<(), PackError> {
    if objects.len() > MAX_OBJECTS {
        return Err(PackError::Limit);
    }
    Ok(())
}
