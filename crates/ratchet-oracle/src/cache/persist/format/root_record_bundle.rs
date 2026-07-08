//! Self-validating wire bundle for network-tier root-record exchange (MEMO-2).
//!
//! RFC-0007 doc 29 §5.5's L3 tier moves whole root-cutoff records between
//! machines. A bundle packs the encoded [`RootInstantiationRecord`] together
//! with every closure `.drv` blob it references, so one fetch carries
//! everything needed to install the record into a local cache:
//!
//! ```text
//! magic(16 = "AOS-NIX-MEMOBNDL") || version(u32 LE)
//! record_len(u64 LE) || record bytes            (RootInstantiationRecord)
//! blob_count(u64 LE)
//!   repeated: blob_hash(32) || blob_len(u64 LE) || blob bytes
//! ```
//!
//! Decoding is **validation, not trust** (the remote is never an authority):
//! every bundled blob must re-hash to its declared content hash, the record
//! must decode, every closure reference must be covered by a bundled blob,
//! and the record's root `.drv` must appear in its own closure. A bundle that
//! fails any check is rejected wholesale — the caller treats it as a miss.
//! Content validation makes substitution attacks equivalent to a miss; the
//! record's impure-input slice must additionally be revalidated locally by
//! the caller before the closure may be used, exactly like a disk record.

use super::*;

/// The fixed magic bytes at the start of a root-record network bundle.
pub const PERSIST_ROOT_RECORD_BUNDLE_MAGIC: [u8; 16] = *b"AOS-NIX-MEMOBNDL";
/// The root-record network bundle format version.
pub const PERSIST_ROOT_RECORD_BUNDLE_VERSION: u32 = 1;

/// A decoded, content-validated root-record network bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootRecordBundle {
    record: RootInstantiationRecord,
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
}

impl RootRecordBundle {
    /// Builds a bundle from an in-memory closure, as produced by a cold eval.
    ///
    /// # Errors
    ///
    /// Returns [`RootRecordBundleError::Record`] if the record's impure-input
    /// trace cannot be encoded, or [`RootRecordBundleError::RootMissingFromClosure`]
    /// if `root_drv` names a path absent from `closure`.
    pub fn from_closure(
        root_drv: &[u8],
        closure: &BTreeMap<PathBuf, Vec<u8>>,
        inputs: &[CacheableInputFingerprint],
        run_id: u64,
    ) -> Result<Self, RootRecordBundleError> {
        let mut entries = Vec::with_capacity(closure.len());
        let mut blobs = BTreeMap::new();
        let mut root_present = false;
        for (path, bytes) in closure {
            let path_bytes = path.as_os_str().as_bytes().to_vec();
            root_present |= path_bytes == root_drv;
            let hash = PersistFileBlobHash::for_payload(bytes);
            blobs.insert(hash.as_durable_hash().as_bytes(), bytes.clone());
            entries.push((path_bytes, hash));
        }
        if !root_present {
            return Err(RootRecordBundleError::RootMissingFromClosure);
        }
        let record =
            RootInstantiationRecord::new(root_drv.to_vec(), entries, inputs.to_vec(), run_id);
        // Probe encodability now so `encode` cannot fail later.
        record
            .encode()
            .map_err(|source| RootRecordBundleError::Record { source })?;
        Ok(Self { record, blobs })
    }

    /// Returns the bundled root-instantiation record.
    pub fn record(&self) -> &RootInstantiationRecord {
        &self.record
    }

    /// Reassembles the closure as a `.drv`-path-to-bytes map.
    ///
    /// Infallible for a decoded or constructed bundle: validation already
    /// proved every closure reference is covered by a bundled blob.
    pub fn closure(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut closure = BTreeMap::new();
        for (path, hash) in self.record.entries() {
            if let Some(bytes) = self.blobs.get(&hash.as_durable_hash().as_bytes()) {
                closure.insert(
                    PathBuf::from(std::ffi::OsStr::from_bytes(path)),
                    bytes.clone(),
                );
            }
        }
        closure
    }

    /// Encodes this bundle as stable little-endian wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RootRecordBundleError::Record`] if the record fails to
    /// re-encode (unreachable for bundles built by [`Self::from_closure`] or
    /// [`Self::decode`], which both prove encodability).
    pub fn encode(&self) -> Result<Vec<u8>, RootRecordBundleError> {
        let record_bytes = self
            .record
            .encode()
            .map_err(|source| RootRecordBundleError::Record { source })?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PERSIST_ROOT_RECORD_BUNDLE_MAGIC);
        bytes.extend_from_slice(&PERSIST_ROOT_RECORD_BUNDLE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(record_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&record_bytes);
        bytes.extend_from_slice(&(self.blobs.len() as u64).to_le_bytes());
        for (hash, blob) in &self.blobs {
            bytes.extend_from_slice(hash);
            bytes.extend_from_slice(&(blob.len() as u64).to_le_bytes());
            bytes.extend_from_slice(blob);
        }
        Ok(bytes)
    }

    /// Decodes and fully content-validates wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RootRecordBundleError`] when the header is malformed, any
    /// length field is truncated or oversized, a bundled blob does not re-hash
    /// to its declared content hash, the embedded record fails to decode, a
    /// closure reference lacks a bundled blob, the record's root `.drv` is
    /// absent from its own closure, or trailing bytes remain.
    pub fn decode(bytes: &[u8]) -> Result<Self, RootRecordBundleError> {
        let mut cursor = BundleCursor { bytes, offset: 0 };
        let magic = cursor.take(16)?;
        if magic != PERSIST_ROOT_RECORD_BUNDLE_MAGIC {
            return Err(RootRecordBundleError::BadMagic);
        }
        let version = u32::from_le_bytes(
            cursor
                .take(4)?
                .try_into()
                .map_err(|_| RootRecordBundleError::Truncated)?,
        );
        if version != PERSIST_ROOT_RECORD_BUNDLE_VERSION {
            return Err(RootRecordBundleError::UnsupportedVersion { version });
        }
        let record_bytes = cursor.take_len_prefixed()?;
        let record = RootInstantiationRecord::decode(record_bytes)
            .map_err(|source| RootRecordBundleError::Record { source })?;
        let blob_count = cursor.take_u64()?;
        let mut blobs = BTreeMap::new();
        for _ in 0..blob_count {
            let declared: [u8; 32] = cursor
                .take(32)?
                .try_into()
                .map_err(|_| RootRecordBundleError::Truncated)?;
            let blob = cursor.take_len_prefixed()?;
            let actual = PersistFileBlobHash::for_payload(blob)
                .as_durable_hash()
                .as_bytes();
            if actual != declared {
                return Err(RootRecordBundleError::BlobHashMismatch);
            }
            blobs.insert(declared, blob.to_vec());
        }
        if cursor.offset != bytes.len() {
            return Err(RootRecordBundleError::TrailingBytes);
        }
        let mut root_present = false;
        for (path, hash) in record.entries() {
            if !blobs.contains_key(&hash.as_durable_hash().as_bytes()) {
                return Err(RootRecordBundleError::MissingClosureBlob);
            }
            root_present |= path.as_slice() == record.root_drv();
        }
        if !root_present {
            return Err(RootRecordBundleError::RootMissingFromClosure);
        }
        Ok(Self { record, blobs })
    }
}

/// A root-record network bundle failed to build, encode, or validate.
#[derive(Debug, Error)]
pub enum RootRecordBundleError {
    /// The bundle bytes ended before a declared field boundary.
    #[error("root-record bundle is truncated")]
    Truncated,
    /// The bundle did not start with the expected magic.
    #[error("root-record bundle has an unrecognized magic prefix")]
    BadMagic,
    /// The bundle declared an unsupported format version.
    #[error("root-record bundle version {version} is unsupported")]
    UnsupportedVersion {
        /// The declared version.
        version: u32,
    },
    /// A declared length exceeded the platform or the remaining bytes.
    #[error("root-record bundle length field overflows")]
    LengthOverflow,
    /// The embedded root-instantiation record failed to encode or decode.
    #[error("root-record bundle record payload is invalid")]
    Record {
        /// The underlying record codec error.
        source: PersistPackFormatError,
    },
    /// A bundled blob did not re-hash to its declared content hash.
    #[error("root-record bundle blob fails content-hash validation")]
    BlobHashMismatch,
    /// The record references a closure blob the bundle does not carry.
    #[error("root-record bundle omits a referenced closure blob")]
    MissingClosureBlob,
    /// The record's root `.drv` path is absent from its own closure.
    #[error("root-record bundle root derivation is missing from its closure")]
    RootMissingFromClosure,
    /// Bytes remained after the final declared field.
    #[error("root-record bundle carries trailing bytes")]
    TrailingBytes,
}

/// A bounds-checked forward reader over bundle bytes.
struct BundleCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BundleCursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], RootRecordBundleError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(RootRecordBundleError::Truncated)?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_u64(&mut self) -> Result<u64, RootRecordBundleError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| RootRecordBundleError::Truncated)?,
        ))
    }

    fn take_len_prefixed(&mut self) -> Result<&'a [u8], RootRecordBundleError> {
        let len = self.take_u64()?;
        let len = usize::try_from(len).map_err(|_| RootRecordBundleError::LengthOverflow)?;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_closure() -> BTreeMap<PathBuf, Vec<u8>> {
        let mut closure = BTreeMap::new();
        closure.insert(PathBuf::from("/nix/store/root.drv"), b"root drv".to_vec());
        closure.insert(PathBuf::from("/nix/store/dep.drv"), b"dep drv".to_vec());
        closure
    }

    #[test]
    fn bundle_round_trips() {
        let closure = sample_closure();
        let bundle =
            RootRecordBundle::from_closure(b"/nix/store/root.drv", &closure, &[], 7)
                .expect("bundle builds");
        let bytes = bundle.encode().expect("bundle encodes");
        let decoded = RootRecordBundle::decode(&bytes).expect("bundle decodes");
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.closure(), closure);
        assert_eq!(decoded.record().run_id(), 7);
    }

    #[test]
    fn corrupted_blob_fails_content_validation() {
        let closure = sample_closure();
        let bundle =
            RootRecordBundle::from_closure(b"/nix/store/root.drv", &closure, &[], 0)
                .expect("bundle builds");
        let mut bytes = bundle.encode().expect("bundle encodes");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert!(matches!(
            RootRecordBundle::decode(&bytes),
            Err(RootRecordBundleError::BlobHashMismatch)
        ));
    }

    #[test]
    fn bundle_missing_root_is_rejected() {
        let closure = sample_closure();
        assert!(matches!(
            RootRecordBundle::from_closure(b"/nix/store/absent.drv", &closure, &[], 0),
            Err(RootRecordBundleError::RootMissingFromClosure)
        ));
    }

    #[test]
    fn truncated_bundle_is_rejected() {
        let bundle =
            RootRecordBundle::from_closure(b"/nix/store/root.drv", &sample_closure(), &[], 0)
                .expect("bundle builds");
        let bytes = bundle.encode().expect("bundle encodes");
        assert!(RootRecordBundle::decode(&bytes[..bytes.len() - 3]).is_err());
    }
}
