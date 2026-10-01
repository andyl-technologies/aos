//! Resolves standalone dictionary chunks and selects explicit deployment mappings.
//!
//! A deployment maps registered content classes to chunk identities; no default
//! dictionaries or training algorithm are implied. Selection requires checked
//! classification evidence. Dictionary plaintext is fetched through the ordinary
//! content path and verified independently of its attribute record identity.

use super::{DictionaryResolver, Error};
use crate::{codec::decode_verified, store::ContentStore};
use std::collections::{BTreeMap, BTreeSet};
use terrane_core::{
    chunking::ChunkProfile,
    codec::{Codec, parse_envelope},
    derived::{AttributeName, AttributeValue, Magic, VerifiedAttributeEvidence},
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
};

/// An explicit immutable mapping from registered content classes to dictionaries.
#[derive(Clone, Debug, Default)]
pub struct DictionarySet {
    classes: BTreeMap<Magic, Digest>,
}

impl DictionarySet {
    /// Validates unique classes and chunk-domain dictionary identities.
    ///
    /// # Errors
    /// Returns an invalid-value error for repeated classes or a non-chunk identity,
    /// or an identity error for an incompatible identity profile.
    pub fn new(entries: impl IntoIterator<Item = (Magic, Identity)>) -> Result<Self, Error> {
        let mut classes = BTreeMap::new();
        for (class, identity) in entries {
            if identity.kind() != IdentityKind::Chunk {
                return Err(terrane_core::derived::Error::InvalidValue.into());
            }
            let digest = identity.terrane_v1_digest()?;
            if classes.insert(class, digest).is_some() {
                return Err(terrane_core::derived::Error::InvalidValue.into());
            }
        }

        Ok(Self { classes })
    }

    /// Selects the exact configured dictionary from authenticated `class.magic`.
    ///
    /// An unconfigured class returns no dictionary. The evidence identifies the
    /// same object for which a caller may publish a `zstd-dictionary` record.
    ///
    /// # Errors
    /// Returns an invalid-value or unsupported-function error for evidence that
    /// does not describe the implemented magic classifier.
    pub fn select(&self, class: &VerifiedAttributeEvidence) -> Result<Option<Digest>, Error> {
        if class.name() != AttributeName::Magic {
            return Err(terrane_core::derived::Error::InvalidValue.into());
        }
        if !class.function().supported(AttributeName::Magic) {
            return Err(terrane_core::derived::Error::UnsupportedFunction.into());
        }
        let AttributeValue::Magic(magic) =
            AttributeValue::decode(AttributeName::Magic, class.value())?
        else {
            return Err(terrane_core::derived::Error::InvalidValue.into());
        };

        Ok(self.classes.get(&magic).copied())
    }
}

/// Fetches and verifies named standalone dictionary chunks through a content store.
pub struct StoreDictionaries<'a, S> {
    store: &'a S,
    profile: &'a ChunkProfile,
}

impl<'a, S: ContentStore> StoreDictionaries<'a, S> {
    /// Borrows the content store and its checked chunk profile.
    pub const fn new(store: &'a S, profile: &'a ChunkProfile) -> Self {
        Self { store, profile }
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: ContentStore + Sync> DictionaryResolver for StoreDictionaries<'_, S> {
    async fn resolve(&self, digest: Digest) -> Result<Vec<u8>, Error> {
        let mut pending = Vec::new();
        let mut visited = BTreeSet::new();
        let mut next = Some(digest);
        while let Some(digest) = next {
            if !visited.insert(digest) {
                return Err(terrane_core::derived::Error::InvalidValue.into());
            }
            let identity = TERRANE_V1.from_digest(IdentityKind::Chunk, &digest)?;
            let encoded = self.store.get(&identity, None).await?;
            let chunk = parse_envelope(&encoded).map_err(crate::codec::FrameError::from)?;
            let length = match chunk.codec {
                Codec::Raw => chunk.body.len(),
                Codec::Zstd | Codec::ZstdDictionary(_) => {
                    let length = zstd::zstd_safe::get_frame_content_size(chunk.body)
                        .map_err(|_| crate::codec::FrameError::InvalidFrame)?
                        .ok_or(crate::codec::FrameError::UnknownContentSize)?;
                    usize::try_from(length).map_err(|_| terrane_core::derived::Error::Limit)?
                }
            };
            // Validate frame and resource bounds before following any dependency.
            crate::codec::inspect_chunk(&encoded, length, self.profile.maximum())?;
            next = match chunk.codec {
                Codec::ZstdDictionary(digest) => Some(digest),
                _ => None,
            };
            pending.push((identity, encoded, length));
        }

        // Decode dependencies first without recursive futures. Each intermediate
        // dictionary is a verified final chunk before it can decode its parent.
        let mut plaintext = None;
        while let Some((identity, encoded, length)) = pending.pop() {
            let verified = decode_verified(
                &encoded,
                length,
                self.profile,
                true,
                &identity,
                plaintext.as_deref(),
            )?;
            plaintext = Some(verified.plaintext().to_vec());
        }

        plaintext.ok_or(Error::InvalidRead)
    }
}
