//! Verifies bounded lower-read dictionary chains before optional native admission.
//!
//! Resolution retains encoded dependencies and only the current dictionary's
//! plaintext. It never creates native custody. The caller's single lower-read
//! deadline covers every fetch and decode, and admission starts only after the
//! complete chain and requested body have been independently verified.

use super::corrupt;
use std::{collections::BTreeSet, future::Future};
use terrane_format::{
    chunking::ChunkProfile,
    codec::{Codec, parse_envelope},
    identity::{Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::store::{StoreErrorKind, StoreFailure};

#[cfg(test)]
mod tests;

/// Retains a verified dependency's original encoding for optional admission.
pub(super) struct Dictionary {
    /// Names the independently verified dictionary plaintext.
    pub(super) identity: Identity,
    /// Preserves the complete stored envelope, including its own dependency.
    pub(super) encoded: Vec<u8>,
    /// Records the verified final-chunk plaintext length.
    pub(super) length: usize,
}

/// Orders verified dependencies before dependents and retains the nearest plaintext.
pub(super) struct Resolved {
    /// Lists terminal dictionaries before their dependents.
    pub(super) entries: Vec<Dictionary>,
    /// Holds only the dictionary immediately required by the requested body.
    pub(super) plaintext: Option<Vec<u8>>,
}

/// Resolves ordinary dictionary chunks iteratively within the native request bounds.
///
/// Each encoded and decoded body must fit the configured individual read limit.
/// The inventory-entry limit also bounds the number of retained dependencies;
/// no recursive future or unbounded chain allocation is created. Encoded bytes
/// retain their original codec so optional warming cannot rewrite their identity
/// or representation. Cycles fail before fetching the repeated dependency.
///
/// # Errors
/// Preserves lower fetch failures, reports capacity when an operator bound is
/// exceeded, and reports corruption for cycles, malformed frames or mismatched
/// dictionary identities. No partially verified chain is returned.
pub(super) async fn resolve<F, R>(
    content: &Identity,
    encoded: &[u8],
    profile: &ChunkProfile,
    max_bytes: usize,
    max_entries: usize,
    mut fetch: F,
) -> Result<Resolved, StoreFailure>
where
    F: FnMut(Identity) -> R,
    R: Future<Output = Result<Vec<u8>, StoreFailure>>,
{
    let mut codec = parse_envelope(encoded)
        .map_err(|error| corrupt(content, error))?
        .codec;
    let mut seen = BTreeSet::from([content
        .terrane_v1_digest()
        .map_err(|error| corrupt(content, error))?]);
    let mut pending = Vec::new();

    while let Codec::ZstdDictionary(digest) = codec {
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, &digest)
            .map_err(|error| corrupt(content, error))?;
        if !seen.insert(digest) {
            return Err(corrupt(
                &identity,
                std::io::Error::other("dictionary dependency cycle"),
            ));
        }
        if pending.len() >= max_entries {
            return Err(capacity());
        }

        let encoded = fetch(identity.clone()).await?;
        if encoded.len() > max_bytes {
            return Err(capacity());
        }
        let length = terrane_sdk::codec::encoded_plaintext_len(&encoded, profile.maximum())
            .map_err(|error| corrupt(&identity, error))?;
        if length > max_bytes {
            return Err(capacity());
        }
        codec = parse_envelope(&encoded)
            .map_err(|error| corrupt(&identity, error))?
            .codec;
        pending.push(Dictionary {
            identity,
            encoded,
            length,
        });
    }

    let mut entries = Vec::with_capacity(pending.len());
    let mut plaintext: Option<Vec<u8>> = None;
    for dictionary in pending.into_iter().rev() {
        let verified = terrane_sdk::codec::decode_verified(
            &dictionary.encoded,
            dictionary.length,
            profile,
            true,
            &dictionary.identity,
            plaintext.as_deref(),
        )
        .map_err(|error| corrupt(&dictionary.identity, error))?;
        plaintext = Some(verified.plaintext().to_vec());
        entries.push(dictionary);
    }

    Ok(Resolved { entries, plaintext })
}

fn capacity() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Capacity)
}
