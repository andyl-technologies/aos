//! Encodes the exact registered disclosure statement and normalized target binding.

use super::super::{EntryLocation, Rejected, VerifiedHistory, same_content};
use super::{DisclosureAuthority, key_name, witness};
use crate::{
    cbor::{self, Decoder},
    identity::Digest,
    properties::Defaults,
    refs::{Commit, EntryOrigin, EntryReceipt},
    tree_format::{ContentRef, Entry, EntryKind},
};
use alloc::vec::Vec;
use ed25519_dalek::{Signer, SigningKey};

/// Calculates the registered whole-destination disclosure binding.
///
/// Only the unsigned commit signature slot and every typed certificate signature
/// slot are normalized. Metadata, opaque blobs and all other commit fields remain.
///
/// # Errors
/// Returns [`Rejected`] if the commit cannot be canonically encoded.
pub fn disclosure_target_binding(commit: &Commit) -> Result<Digest, Rejected> {
    let mut projection = commit.clone();
    for receipt in projection.profile_pair.entry_receipts.iter_mut().flatten() {
        if let Some(proof) = &mut receipt.disclosure_proof {
            proof.signature = [0; 64];
        }
    }
    let bytes = projection.signature_preimage().map_err(|_| Rejected)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"terrane-disclosure-target-v1\0");
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn original(entry: &Entry<'_>) -> Result<Digest, Rejected> {
    let attribute = entry
        .attrs
        .iter()
        .find(|attribute| attribute.name == "provenance.reintroduced-from")
        .ok_or(Rejected)?;
    let mut decoder = Decoder::new(attribute.value);
    let identity = decoder
        .bytes(32)
        .map_err(|_| Rejected)?
        .try_into()
        .map_err(|_| Rejected)?;
    decoder.finish().map_err(|_| Rejected)?;
    Ok(identity)
}

pub(super) fn preimage(
    history: &VerifiedHistory,
    location: &EntryLocation,
    receipt: &EntryReceipt,
    target_domain: &str,
    binding: Digest,
) -> Result<Vec<u8>, Rejected> {
    let record = history.commit(&location.commit).ok_or(Rejected)?.commit();
    let context = record
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or(Rejected)?;
    let proof = receipt.disclosure_proof.as_ref().ok_or(Rejected)?;
    let source = receipt.reintroduced_from.as_ref().ok_or(Rejected)?;
    let entry = history.entry(location)?;
    if receipt.origin != EntryOrigin::Current
        || entry.provenance.is_some()
        || source.commit == location.commit
    {
        return Err(Rejected);
    }

    let mut bytes = b"terrane-disclosure-proof-v1\0".to_vec();
    cbor::write_array(&mut bytes, 8);
    cbor::write_text(&mut bytes, &proof.authority_key);
    cbor::write_text(&mut bytes, &proof.source_domain);
    cbor::write_uint(&mut bytes, proof.observed_at);
    cbor::write_array(&mut bytes, 3);
    cbor::write_bytes(&mut bytes, &source.commit);
    cbor::write_bytes(&mut bytes, &source.root);
    cbor::write_bytes(&mut bytes, &source.path);
    cbor::write_bytes(&mut bytes, &original(&entry)?);
    cbor::write_array(&mut bytes, 4);
    cbor::write_text(&mut bytes, context.reference());
    cbor::write_bytes(&mut bytes, &location.root);
    cbor::write_bytes(&mut bytes, &location.path);
    cbor::write_text(&mut bytes, target_domain);
    match &entry.kind {
        EntryKind::File { size, content, .. } => {
            cbor::write_array(&mut bytes, 3);
            cbor::write_uint(&mut bytes, 1);
            cbor::write_uint(&mut bytes, *size);
            cbor::write_array(&mut bytes, 2);
            let (kind, digest) = match content {
                ContentRef::Inline(id) => (0, id),
                ContentRef::Manifest(id) => (1, id),
            };
            cbor::write_uint(&mut bytes, kind);
            cbor::write_bytes(&mut bytes, digest);
        }
        EntryKind::Directory { .. } => {
            cbor::write_array(&mut bytes, 1);
            cbor::write_uint(&mut bytes, 2);
        }
        EntryKind::Symlink { target } => {
            cbor::write_array(&mut bytes, 2);
            cbor::write_uint(&mut bytes, 3);
            cbor::write_bytes(&mut bytes, target);
        }
        _ => return Err(Rejected),
    }
    cbor::write_bytes(&mut bytes, &binding);
    Ok(bytes)
}

/// Supplies actual canonical source and prototype destination signing witnesses.
///
/// The native source guard retains the configured authority secret and performs
/// fresh current source Read and destination Commit authorization. This pure
/// helper validates immutable witnesses and introduction; it grants no upload
/// or publication permission.
#[derive(Clone, Copy)]
pub struct DisclosureSigning<'a> {
    /// Actual authenticated source history, including original introduction.
    pub source_history: &'a VerifiedHistory,
    /// Signed source commit selected by the source guard.
    pub source_commit: Digest,
    /// Full view-relative selected source path.
    pub source_path: &'a [u8],
    /// Complete canonical prototype destination history with finalized metadata.
    pub destination_history: &'a VerifiedHistory,
    /// Prototype signed destination whose certificate slots may be zeroed.
    pub destination_commit: Digest,
    /// Full view-relative destination entry path.
    pub destination_path: &'a [u8],
    /// Trusted policy defaults of the physical source repository.
    pub source_defaults: Defaults<'a>,
    /// Trusted policy defaults of the physical destination repository.
    pub destination_defaults: Defaults<'a>,
}

/// Signs a certificate after checking the actual source and target witnesses.
///
/// All destination metadata must be finalized before signing any certificate.
/// Each authority uses the same normalized binding; the final destination is
/// then signed normally with the real certificates. Returned bytes alone confer
/// no verified history boundary.
///
/// # Errors
/// Returns [`Rejected`] for a mismatched scoped key, issue time/domain, missing
/// canonical witnesses, different content, wrong source or original introduction,
/// unsupported projection, or malformed destination metadata.
pub fn sign_disclosure(
    witness: DisclosureSigning<'_>,
    authority: DisclosureAuthority<'_>,
    secret: &[u8; 32],
) -> Result<[u8; 64], Rejected> {
    let (source, source_domain) = witness::selected_domain(
        witness.source_history,
        witness.source_commit,
        witness.source_path,
        witness.source_defaults,
    )?;
    let (target, target_domain) = witness::selected_domain(
        witness.destination_history,
        witness.destination_commit,
        witness.destination_path,
        witness.destination_defaults,
    )?;
    let commit = witness
        .destination_history
        .commit(&target.commit)
        .ok_or(Rejected)?
        .commit();
    let receipt = commit
        .profile_pair
        .entry_receipts
        .iter()
        .flatten()
        .find(|receipt| receipt.root == target.root && receipt.path == target.path)
        .ok_or(Rejected)?;
    let proof = receipt.disclosure_proof.as_ref().ok_or(Rejected)?;
    authority.permits(proof.observed_at)?;
    let key = SigningKey::from_bytes(secret);
    let source_entry = witness.source_history.entry(&source)?;
    let target_entry = witness.destination_history.entry(&target)?;
    let claimed = receipt.reintroduced_from.as_ref().ok_or(Rejected)?;
    if authority.public_key != key.verifying_key().to_bytes()
        || key_name(&authority.public_key) != proof.authority_key
        || authority.domain != proof.source_domain
        || authority.domain != source_domain
        || claimed.commit != source.commit
        || claimed.root != source.root
        || claimed.path != source.path
        || !same_content(&source_entry, &target_entry)
        || witness.source_history.introducing_commit(&source)? != original(&target_entry)?
    {
        return Err(Rejected);
    }
    let binding = disclosure_target_binding(commit)?;
    Ok(key
        .sign(&preimage(
            witness.destination_history,
            &target,
            receipt,
            &target_domain,
            binding,
        )?)
        .to_bytes())
}
