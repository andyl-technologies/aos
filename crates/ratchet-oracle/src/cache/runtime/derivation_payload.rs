//! Cached derivation side payload records and codecs.

use crate::cache::hashing::CacheDigestHasher;
use thiserror::Error;

use crate::cache::hashing::DerivationSidePayloadValueHash;
use crate::cache::{NixSha256Digest, ValueHash};

const DERIVATION_ATERM_PATH_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-derivation-aterm-path-value-hash-v1";
const STATIC_DERIVATION_OUTPUT_PATHS_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-static-derivation-output-paths-value-hash-v1";

/// A cached derivation output store path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CachedDerivationOutputPath {
    name: Vec<u8>,
    path: Vec<u8>,
}

impl CachedDerivationOutputPath {
    /// Creates a cached output path entry from an output name and absolute path bytes.
    pub(crate) fn new(name: Vec<u8>, path: Vec<u8>) -> Self {
        Self { name, path }
    }

    /// Returns the output name bytes.
    pub(crate) fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the absolute output path bytes.
    pub(crate) fn path(&self) -> &[u8] {
        &self.path
    }
}

/// Cached static output paths for a resolved `derivationStrict` expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CachedDerivationOutputPaths {
    hash_derivation_modulo: NixSha256Digest,
    output_paths: Vec<CachedDerivationOutputPath>,
}

impl CachedDerivationOutputPaths {
    /// Creates a cached static-output-path record.
    pub(crate) fn new(
        hash_derivation_modulo: impl Into<NixSha256Digest>,
        mut output_paths: Vec<CachedDerivationOutputPath>,
    ) -> Self {
        output_paths.sort_unstable_by(|left, right| {
            left.name.cmp(&right.name).then(left.path.cmp(&right.path))
        });
        Self {
            hash_derivation_modulo: hash_derivation_modulo.into(),
            output_paths,
        }
    }

    /// Returns the resolved derivation hash modulo bytes.
    pub(crate) const fn hash_derivation_modulo(&self) -> NixSha256Digest {
        self.hash_derivation_modulo
    }

    /// Returns the cached output path entries.
    pub(crate) fn output_paths(&self) -> &[CachedDerivationOutputPath] {
        &self.output_paths
    }

    pub(crate) fn value_hash(&self, pre_output_aterm: &[u8]) -> ValueHash {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(STATIC_DERIVATION_OUTPUT_PATHS_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"pre-output-aterm");
        update_derivation_side_payload_hash_chunk(&mut hasher, pre_output_aterm);
        hasher.update(b"hash-derivation-modulo");
        hasher.update(self.hash_derivation_modulo.as_bytes());
        hasher.update(b"output-paths");
        hasher.update(&(self.output_paths.len() as u128).to_le_bytes());
        for output_path in &self.output_paths {
            update_derivation_side_payload_hash_chunk(&mut hasher, &output_path.name);
            update_derivation_side_payload_hash_chunk(&mut hasher, &output_path.path);
        }
        ValueHash::from_derivation_side_payload_hash(DerivationSidePayloadValueHash::from_hasher(
            hasher,
        ))
    }
}

/// Persistent payload for cached static derivation output paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CachedStaticDerivationOutputPathsPayload {
    pre_output_aterm: Vec<u8>,
    output_paths: CachedDerivationOutputPaths,
}

impl CachedStaticDerivationOutputPathsPayload {
    /// Creates a static-output payload from pre-output ATerm bytes and paths.
    pub(crate) fn new(
        pre_output_aterm: Vec<u8>,
        output_paths: CachedDerivationOutputPaths,
    ) -> Self {
        Self {
            pre_output_aterm,
            output_paths,
        }
    }

    /// Returns the pre-output ATerm bytes this payload belongs to.
    pub(crate) fn pre_output_aterm_bytes(&self) -> &[u8] {
        &self.pre_output_aterm
    }

    /// Consumes the payload and returns the cached static output paths.
    pub(crate) fn into_output_paths(self) -> CachedDerivationOutputPaths {
        self.output_paths
    }

    /// Returns the durable side-payload value hash.
    pub(crate) fn value_hash(&self) -> ValueHash {
        self.output_paths.value_hash(&self.pre_output_aterm)
    }

    /// Encodes this payload for the persistent `values/` pack.
    ///
    /// The encoded bytes are the canonical BLAKE3 preimage used by
    /// [`Self::value_hash`], so the persistent blob hash matches the demand
    /// node's side-payload value hash.
    pub(crate) fn encode_persistent_payload(
        &self,
    ) -> Result<Vec<u8>, CachedDerivationSidePayloadError> {
        let mut out = Vec::new();
        append_derivation_payload_bytes(
            &mut out,
            STATIC_DERIVATION_OUTPUT_PATHS_VALUE_HASH_DOMAIN_VERSION,
        )?;
        append_derivation_payload_bytes(&mut out, b"pre-output-aterm")?;
        append_derivation_length_prefixed_bytes(&mut out, &self.pre_output_aterm)?;
        append_derivation_payload_bytes(&mut out, b"hash-derivation-modulo")?;
        append_derivation_payload_bytes(
            &mut out,
            self.output_paths.hash_derivation_modulo.as_bytes(),
        )?;
        append_derivation_payload_bytes(&mut out, b"output-paths")?;
        append_derivation_payload_u128(&mut out, self.output_paths.output_paths.len() as u128)?;
        for output_path in &self.output_paths.output_paths {
            append_derivation_length_prefixed_bytes(&mut out, &output_path.name)?;
            append_derivation_length_prefixed_bytes(&mut out, &output_path.path)?;
        }
        Ok(out)
    }

    /// Decodes a payload produced by [`Self::encode_persistent_payload`].
    ///
    /// # Errors
    ///
    /// Returns [`CachedDerivationSidePayloadError`] if `bytes` are not a
    /// complete, canonical cached static-output side payload.
    pub(crate) fn decode_persistent_payload(
        bytes: &[u8],
    ) -> Result<Self, CachedDerivationSidePayloadError> {
        let mut cursor = DerivationSidePayloadCursor::new(bytes);
        cursor.take_marker(
            STATIC_DERIVATION_OUTPUT_PATHS_VALUE_HASH_DOMAIN_VERSION,
            "static derivation output paths domain",
        )?;
        cursor.take_marker(b"pre-output-aterm", "pre-output ATerm tag")?;
        let pre_output_aterm = cursor.take_length_prefixed_bytes()?;
        cursor.take_marker(b"hash-derivation-modulo", "derivation modulo hash tag")?;
        let mut hash_derivation_modulo = [0; 32];
        hash_derivation_modulo.copy_from_slice(cursor.take_bytes(32)?);
        cursor.take_marker(b"output-paths", "output paths tag")?;
        let output_count = cursor.take_len()?;
        let mut output_paths = Vec::new();
        output_paths.try_reserve_exact(output_count).map_err(|_| {
            CachedDerivationSidePayloadError::PayloadAllocationFailed { len: output_count }
        })?;
        for _ in 0..output_count {
            let name = cursor.take_length_prefixed_bytes()?;
            let path = cursor.take_length_prefixed_bytes()?;
            output_paths.push(CachedDerivationOutputPath::new(name, path));
        }
        cursor.finish()?;
        Ok(Self {
            pre_output_aterm,
            output_paths: CachedDerivationOutputPaths::new(
                NixSha256Digest::from_bytes(hash_derivation_modulo),
                output_paths,
            ),
        })
    }
}

/// A cached final `.drv` path tied to exact derivation ATerm bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CachedDerivationAtermPath {
    aterm: Vec<u8>,
    path: Vec<u8>,
    hash_derivation_modulo: Option<NixSha256Digest>,
}

impl CachedDerivationAtermPath {
    /// Creates a cached derivation side payload from exact ATerm and path bytes.
    pub(crate) fn new(aterm: Vec<u8>, path: Vec<u8>) -> Self {
        Self {
            aterm,
            path,
            hash_derivation_modulo: None,
        }
    }

    /// Creates a cached derivation side payload with a known modulo hash.
    pub(crate) fn with_hash_derivation_modulo(
        aterm: Vec<u8>,
        path: Vec<u8>,
        hash_derivation_modulo: impl Into<NixSha256Digest>,
    ) -> Self {
        Self {
            aterm,
            path,
            hash_derivation_modulo: Some(hash_derivation_modulo.into()),
        }
    }

    /// Returns the exact derivation ATerm bytes this path belongs to.
    pub(crate) fn aterm_bytes(&self) -> &[u8] {
        &self.aterm
    }

    /// Returns the absolute `.drv` path bytes.
    pub(crate) fn path_bytes(&self) -> &[u8] {
        &self.path
    }

    /// Returns the resolved derivation hash modulo bytes, if this payload stores them.
    pub(crate) const fn hash_derivation_modulo(&self) -> Option<NixSha256Digest> {
        self.hash_derivation_modulo
    }

    /// Returns the durable side-payload value hash.
    pub(crate) fn value_hash(&self) -> ValueHash {
        derivation_aterm_path_payload_value_hash(
            &self.aterm,
            &self.path,
            self.hash_derivation_modulo,
        )
    }

    /// Encodes this payload for the persistent `values/` pack.
    ///
    /// The encoded bytes are the canonical BLAKE3 preimage used by
    /// [`Self::value_hash`], so the persistent blob hash matches the demand
    /// node's side-payload value hash.
    pub(crate) fn encode_persistent_payload(
        &self,
    ) -> Result<Vec<u8>, CachedDerivationSidePayloadError> {
        let len = DERIVATION_ATERM_PATH_VALUE_HASH_DOMAIN_VERSION
            .len()
            .saturating_add(b"aterm".len())
            .saturating_add(16)
            .saturating_add(self.aterm.len())
            .saturating_add(b"drv-path".len())
            .saturating_add(16)
            .saturating_add(self.path.len())
            .saturating_add(
                self.hash_derivation_modulo
                    .map(|_| b"hash-derivation-modulo".len().saturating_add(32))
                    .unwrap_or(0),
            );
        let mut out = Vec::new();
        out.try_reserve_exact(len)
            .map_err(|_| CachedDerivationSidePayloadError::PayloadAllocationFailed { len })?;
        append_derivation_payload_bytes(&mut out, DERIVATION_ATERM_PATH_VALUE_HASH_DOMAIN_VERSION)?;
        append_derivation_payload_bytes(&mut out, b"aterm")?;
        append_derivation_length_prefixed_bytes(&mut out, &self.aterm)?;
        append_derivation_payload_bytes(&mut out, b"drv-path")?;
        append_derivation_length_prefixed_bytes(&mut out, &self.path)?;
        if let Some(hash_derivation_modulo) = self.hash_derivation_modulo {
            append_derivation_payload_bytes(&mut out, b"hash-derivation-modulo")?;
            append_derivation_payload_bytes(&mut out, hash_derivation_modulo.as_bytes())?;
        }
        Ok(out)
    }

    /// Decodes a payload produced by [`Self::encode_persistent_payload`].
    ///
    /// # Errors
    ///
    /// Returns [`CachedDerivationSidePayloadError`] if `bytes` are not a
    /// complete, canonical cached derivation side payload.
    pub(crate) fn decode_persistent_payload(
        bytes: &[u8],
    ) -> Result<Self, CachedDerivationSidePayloadError> {
        let mut cursor = DerivationSidePayloadCursor::new(bytes);
        cursor.take_marker(
            DERIVATION_ATERM_PATH_VALUE_HASH_DOMAIN_VERSION,
            "derivation ATerm path domain",
        )?;
        cursor.take_marker(b"aterm", "derivation ATerm tag")?;
        let aterm = cursor.take_length_prefixed_bytes()?;
        cursor.take_marker(b"drv-path", "derivation path tag")?;
        let path = cursor.take_length_prefixed_bytes()?;
        let hash_derivation_modulo = if cursor.remaining() == 0 {
            None
        } else {
            cursor.take_marker(b"hash-derivation-modulo", "derivation modulo hash tag")?;
            let mut hash = [0; 32];
            hash.copy_from_slice(cursor.take_bytes(32)?);
            Some(NixSha256Digest::from_bytes(hash))
        };
        cursor.finish()?;
        Ok(Self {
            aterm,
            path,
            hash_derivation_modulo,
        })
    }
}

/// Persistent cached derivation side payload encoding failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum CachedDerivationSidePayloadError {
    /// Payload byte storage could not be reserved.
    #[error("failed to reserve cached derivation side payload storage for {len} bytes")]
    PayloadAllocationFailed {
        /// The requested byte capacity.
        len: usize,
    },
    /// Payload byte length arithmetic overflowed.
    #[error("cached derivation side payload length overflow: {current} + {additional}")]
    PayloadLengthOverflow {
        /// The current payload length.
        current: usize,
        /// The additional bytes being appended.
        additional: usize,
    },
    /// The payload ended before a required section was complete.
    #[error("cached derivation side payload has {actual} bytes, expected at least {expected}")]
    ShortPayload {
        /// The minimum required payload length.
        expected: usize,
        /// The available payload length.
        actual: usize,
    },
    /// A fixed payload marker was absent at the current cursor position.
    #[error("cached derivation side payload is missing {marker}")]
    MissingMarker {
        /// The marker name.
        marker: &'static str,
    },
    /// A length field cannot fit in `usize` on this host.
    #[error("cached derivation side payload length {len} cannot fit in usize")]
    LengthOverflow {
        /// The oversized encoded length.
        len: u128,
    },
    /// The decoder did not consume the whole payload.
    #[error("cached derivation side payload has {remaining} trailing bytes")]
    TrailingBytes {
        /// The number of unconsumed bytes.
        remaining: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DerivationAtermPathRecord {
    pub(super) aterm_value_hash: ValueHash,
    pub(super) payload_value_hash: ValueHash,
    path: Vec<u8>,
    hash_derivation_modulo: Option<NixSha256Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StaticDerivationOutputPathRecord {
    pub(super) pre_output_value_hash: ValueHash,
    pub(super) payload_value_hash: ValueHash,
    output_paths: CachedDerivationOutputPaths,
}

impl DerivationAtermPathRecord {
    pub(super) fn new(
        aterm: &[u8],
        path: &[u8],
        hash_derivation_modulo: Option<NixSha256Digest>,
    ) -> Self {
        let payload_value_hash =
            derivation_aterm_path_payload_value_hash(aterm, path, hash_derivation_modulo);
        Self {
            aterm_value_hash: ValueHash::from_derivation_aterm_bytes(aterm),
            payload_value_hash,
            path: path.to_vec(),
            hash_derivation_modulo,
        }
    }

    pub(super) fn path_bytes(&self) -> Vec<u8> {
        self.path.clone()
    }

    pub(super) const fn hash_derivation_modulo(&self) -> Option<NixSha256Digest> {
        self.hash_derivation_modulo
    }
}

fn derivation_aterm_path_payload_value_hash(
    aterm: &[u8],
    path: &[u8],
    hash_derivation_modulo: Option<NixSha256Digest>,
) -> ValueHash {
    let mut hasher = CacheDigestHasher::new();
    hasher.update(DERIVATION_ATERM_PATH_VALUE_HASH_DOMAIN_VERSION);
    hasher.update(b"aterm");
    update_derivation_side_payload_hash_chunk(&mut hasher, aterm);
    hasher.update(b"drv-path");
    update_derivation_side_payload_hash_chunk(&mut hasher, path);
    if let Some(hash_derivation_modulo) = hash_derivation_modulo {
        hasher.update(b"hash-derivation-modulo");
        hasher.update(hash_derivation_modulo.as_bytes());
    }
    ValueHash::from_derivation_side_payload_hash(DerivationSidePayloadValueHash::from_hasher(
        hasher,
    ))
}

impl StaticDerivationOutputPathRecord {
    pub(super) fn new(pre_output_aterm: &[u8], output_paths: CachedDerivationOutputPaths) -> Self {
        let payload_value_hash = output_paths.value_hash(pre_output_aterm);
        Self {
            pre_output_value_hash: ValueHash::from_derivation_aterm_bytes(pre_output_aterm),
            payload_value_hash,
            output_paths,
        }
    }

    pub(super) fn output_paths(&self) -> CachedDerivationOutputPaths {
        self.output_paths.clone()
    }
}

fn update_derivation_side_payload_hash_chunk(hasher: &mut CacheDigestHasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u128).to_le_bytes());
    hasher.update(bytes);
}

fn append_derivation_payload_u128(
    out: &mut Vec<u8>,
    value: u128,
) -> Result<(), CachedDerivationSidePayloadError> {
    append_derivation_payload_bytes(out, &value.to_le_bytes())
}

fn append_derivation_payload_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CachedDerivationSidePayloadError> {
    let len = out.len().checked_add(bytes.len()).ok_or(
        CachedDerivationSidePayloadError::PayloadLengthOverflow {
            current: out.len(),
            additional: bytes.len(),
        },
    )?;
    out.try_reserve_exact(bytes.len())
        .map_err(|_| CachedDerivationSidePayloadError::PayloadAllocationFailed { len })?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn append_derivation_length_prefixed_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CachedDerivationSidePayloadError> {
    append_derivation_payload_u128(out, bytes.len() as u128)?;
    append_derivation_payload_bytes(out, bytes)
}

struct DerivationSidePayloadCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerivationSidePayloadCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn finish(&self) -> Result<(), CachedDerivationSidePayloadError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(CachedDerivationSidePayloadError::TrailingBytes { remaining })
        }
    }

    fn take_marker(
        &mut self,
        marker: &'static [u8],
        name: &'static str,
    ) -> Result<(), CachedDerivationSidePayloadError> {
        let actual = self.take_bytes(marker.len())?;
        if actual == marker {
            Ok(())
        } else {
            Err(CachedDerivationSidePayloadError::MissingMarker { marker: name })
        }
    }

    fn take_u128(&mut self) -> Result<u128, CachedDerivationSidePayloadError> {
        let bytes = self.take_bytes(16)?;
        let mut out = [0; 16];
        out.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(out))
    }

    fn take_len(&mut self) -> Result<usize, CachedDerivationSidePayloadError> {
        let len = self.take_u128()?;
        usize::try_from(len).map_err(|_| CachedDerivationSidePayloadError::LengthOverflow { len })
    }

    fn take_length_prefixed_bytes(&mut self) -> Result<Vec<u8>, CachedDerivationSidePayloadError> {
        let len = self.take_len()?;
        let bytes = self.take_bytes(len)?;
        let mut out = Vec::new();
        out.try_reserve_exact(bytes.len()).map_err(|_| {
            CachedDerivationSidePayloadError::PayloadAllocationFailed { len: bytes.len() }
        })?;
        out.extend_from_slice(bytes);
        Ok(out)
    }

    fn take_bytes(&mut self, len: usize) -> Result<&'a [u8], CachedDerivationSidePayloadError> {
        let end =
            self.offset
                .checked_add(len)
                .ok_or(CachedDerivationSidePayloadError::ShortPayload {
                    expected: usize::MAX,
                    actual: self.bytes.len(),
                })?;
        if end > self.bytes.len() {
            return Err(CachedDerivationSidePayloadError::ShortPayload {
                expected: end,
                actual: self.bytes.len(),
            });
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
}
