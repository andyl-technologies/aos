//! Stable on-disk encoding for one durable root-instantiation record.
//!
//! A root-instantiation record captures everything needed to re-emit the
//! derivation closure of a fully warm `instantiate(file, attr)` request without
//! re-evaluating the expression: the selected top-level `.drv` path, the closure
//! as a list of `(drv path, files-blob hash)` references whose ATerm bytes live
//! deduplicated in the `files/` pack, the transitive impure-input trace that
//! must be revalidated before the record may be trusted, and a bookkeeping run
//! id. The impure-input trace section reuses the versioned
//! [`PersistNodeTracePayload`] codec.
//!
//! ```text
//! magic(16) || version(u32 LE) || run_id(u64 LE)
//! root_path_len(u64 LE) || root_path bytes
//! entry_count(u64 LE)
//!   repeated: drv_path_len(u64 LE) || drv_path bytes || blob_hash(32)
//! trace_len(u64 LE) || PersistNodeTracePayload bytes
//! ```

use super::*;

/// One durable root-instantiation record ready for encoding or after decoding.
///
/// The closure references name `files/` blobs by content hash; the caller
/// resolves them to ATerm bytes through the blob pack. The impure inputs are
/// the transitive trace whose revalidation gates reuse of this record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootInstantiationRecord {
    root_drv: Vec<u8>,
    entries: Vec<(Vec<u8>, PersistFileBlobHash)>,
    inputs: Vec<CacheableInputFingerprint>,
    run_id: u64,
}

impl RootInstantiationRecord {
    /// Creates a record from its selected root path, closure references, trace, and run id.
    pub fn new(
        root_drv: impl Into<Vec<u8>>,
        entries: Vec<(Vec<u8>, PersistFileBlobHash)>,
        inputs: Vec<CacheableInputFingerprint>,
        run_id: u64,
    ) -> Self {
        Self {
            root_drv: root_drv.into(),
            entries,
            inputs,
            run_id,
        }
    }

    /// Returns the selected top-level `.drv` path bytes.
    pub fn root_drv(&self) -> &[u8] {
        &self.root_drv
    }

    /// Returns the closure references as `(drv path bytes, files-blob hash)` pairs.
    pub fn entries(&self) -> &[(Vec<u8>, PersistFileBlobHash)] {
        &self.entries
    }

    /// Returns the transitive impure-input trace pinned by this record.
    pub fn inputs(&self) -> &[CacheableInputFingerprint] {
        &self.inputs
    }

    /// Returns the bookkeeping run id recorded when this record was written.
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }

    /// Encodes this record as stable little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError::RootRecordTrace`] if the impure-input
    /// trace cannot be encoded through the node-trace payload codec.
    pub fn encode(&self) -> Result<Vec<u8>, PersistPackFormatError> {
        let trace = PersistNodeTracePayload::from_cacheable_inputs(self.inputs.iter().cloned())
            .and_then(|payload| payload.encode())
            .map_err(|source| PersistPackFormatError::RootRecordTrace {
                source: Box::new(source),
            })?;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PERSIST_ROOT_RECORD_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&PERSIST_ROOT_RECORD_PAYLOAD_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.run_id.to_le_bytes());
        append_len_prefixed(&mut bytes, &self.root_drv);
        bytes.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for (path, blob_hash) in &self.entries {
            append_len_prefixed(&mut bytes, path);
            bytes.extend_from_slice(&blob_hash.as_durable_hash().as_bytes());
        }
        append_len_prefixed(&mut bytes, &trace);
        Ok(bytes)
    }

    /// Decodes a stable root-instantiation record payload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` has the wrong magic or
    /// version, is truncated at any field boundary, carries a length field that
    /// overflows the platform, contains trailing bytes, or embeds an
    /// impure-input trace that cannot be decoded.
    pub fn decode(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        let mut cursor = RecordCursor::new(bytes);
        let magic = cursor.take_array::<16>()?;
        if magic != PERSIST_ROOT_RECORD_PAYLOAD_MAGIC {
            return Err(PersistPackFormatError::InvalidRootRecordMagic { actual: magic });
        }
        let version = u32::from_le_bytes(cursor.take_array::<4>()?);
        if version != PERSIST_ROOT_RECORD_PAYLOAD_VERSION {
            return Err(PersistPackFormatError::UnsupportedRootRecordVersion { version });
        }
        let run_id = u64::from_le_bytes(cursor.take_array::<8>()?);
        let root_drv = cursor.take_len_prefixed()?.to_vec();
        let entry_count = cursor.take_usize_len()?;
        let mut entries = Vec::new();
        for _ in 0..entry_count {
            let path = cursor.take_len_prefixed()?.to_vec();
            let blob_hash = cursor.take_array::<32>()?;
            entries.push((
                path,
                PersistFileBlobHash::from_durable_hash(DurableBlake3Hash::from_bytes(blob_hash)),
            ));
        }
        let trace_bytes = cursor.take_len_prefixed()?;
        let inputs = PersistNodeTracePayload::decode(trace_bytes)
            .map_err(|source| PersistPackFormatError::RootRecordTrace {
                source: Box::new(source),
            })?
            .inputs()
            .to_vec();
        if !cursor.is_empty() {
            return Err(PersistPackFormatError::RootRecordTrailingBytes {
                remaining: cursor.remaining(),
            });
        }
        Ok(Self {
            root_drv,
            entries,
            inputs,
            run_id,
        })
    }
}

fn append_len_prefixed(bytes: &mut Vec<u8>, payload: &[u8]) {
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(payload);
}

/// A forward-only reader over a root-record payload with bounds checks.
struct RecordCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecordCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PersistPackFormatError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(PersistPackFormatError::ShortRootRecordPayload {
                expected: self.offset.saturating_add(len),
                actual: self.bytes.len(),
            })?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], PersistPackFormatError> {
        let mut array = [0; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }

    fn take_usize_len(&mut self) -> Result<usize, PersistPackFormatError> {
        let len = u64::from_le_bytes(self.take_array::<8>()?);
        usize::try_from(len).map_err(|_| PersistPackFormatError::RootRecordLengthOverflow { len })
    }

    fn take_len_prefixed(&mut self) -> Result<&'a [u8], PersistPackFormatError> {
        let len = self.take_usize_len()?;
        self.take(len)
    }
}
