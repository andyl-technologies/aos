//! Binds derived records to signed attribute history and checked tree evidence.

use super::{AttrRecord, AttributeName, Error, Function};
use crate::{
    identity::{Digest, Identity},
    provenance::{EntryLocation, VerifiedHistory},
    tree_format::{ContentRef, EntryKind},
};
use alloc::vec::Vec;

/// Binds one immutable attribute record to checked producing-commit evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAttributeEvidence {
    record: Identity,
    object: Digest,
    name: AttributeName,
    function: Function,
    value: Vec<u8>,
    producer: Digest,
    location: EntryLocation,
}

impl VerifiedAttributeEvidence {
    /// Returns the exact immutable record identity, including its signature.
    pub fn record(&self) -> &Identity {
        &self.record
    }

    /// Returns the object digest reached by the checked witness.
    pub const fn object(&self) -> &Digest {
        &self.object
    }

    /// Returns the registered attribute name.
    pub const fn name(&self) -> AttributeName {
        self.name
    }

    /// Returns the implemented exact function identifier and version.
    pub fn function(&self) -> &Function {
        &self.function
    }

    /// Returns the canonical typed attribute value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the authenticated producing commit identity.
    pub const fn producer(&self) -> &Digest {
        &self.producer
    }

    /// Returns the checked signed tree/object witness location.
    pub fn location(&self) -> &EntryLocation {
        &self.location
    }
}

/// Verifies a record's producing commit against signed attribute history.
///
/// Applies [`verify_record_producer`] and discards its typed evidence. Signed
/// records use detached terminal-key signatures and producing tree witnesses;
/// unsigned records use matching inline value and attribute-origin history.
/// This proves attribution independently of recomputation and trust selectors.
///
/// # Errors
/// Returns [`Error::UnsupportedFunction`] for unknown function metadata, a
/// format error for invalid record values, [`Error::UnverifiedContext`] for
/// incomplete disclosure or original root-scope validation, or
/// [`Error::InvalidProvenance`] for inconsistent signed/tree/attribute evidence.
pub fn verify_producer(
    record: &AttrRecord,
    history: &VerifiedHistory,
    location: &EntryLocation,
) -> Result<(), Error> {
    verify_record_producer(record, history, location).map(|_| ())
}

/// Authenticates a record through signed history and a canonical object witness.
///
/// Signed records require a witness in the producing commit itself and a valid
/// detached terminal-key signature. Unsigned legacy records require an exact
/// inline value and its separately verified attribute-origin history. An inline
/// copy at either witness must agree. This proves attribution independently of
/// plaintext recomputation or a reader's trusted principal policy.
/// Both the carrying witness and actual producing commit must have completed
/// their disclosure and original root-scope checks. A certified disclosure
/// boundary does not authenticate its private source as an attribute producer.
///
/// # Errors
/// Returns format or unsupported-function errors, [`Error::UnverifiedContext`]
/// for incomplete witness/producer context, or [`Error::InvalidProvenance`] for
/// absent or contradictory tree, object, origin, or signature evidence.
pub fn verify_record_producer(
    record: &AttrRecord,
    history: &VerifiedHistory,
    location: &EntryLocation,
) -> Result<VerifiedAttributeEvidence, Error> {
    if !record.function.supported(record.value.name()) {
        return Err(Error::UnsupportedFunction);
    }

    // Canonical witnesses remain usable while a disclosure candidate is staged;
    // only completed histories may expose producer or collector authority.
    history
        .require_verified_context(location.commit)
        .map_err(|_| Error::UnverifiedContext)?;
    if record.producer != location.commit {
        history
            .require_verified_context(record.producer)
            .map_err(|_| Error::UnverifiedContext)?;
    }

    let entry = history
        .entry(location)
        .map_err(|_| Error::InvalidProvenance)?;
    let object = match &entry.kind {
        EntryKind::File {
            content: ContentRef::Inline(digest) | ContentRef::Manifest(digest),
            ..
        } => digest,
        _ => return Err(Error::InvalidProvenance),
    };
    if *object != record.object {
        return Err(Error::InvalidProvenance);
    }

    let inline = entry
        .attrs
        .iter()
        .find(|attribute| attribute.name == record.value.name().as_str());
    if let Some(inline) = inline {
        record.agree_inline(inline.value)?;
    }

    if record.signature.is_some() {
        if location.commit != record.producer {
            return Err(Error::InvalidProvenance);
        }
        let producer = history
            .commit(&record.producer)
            .ok_or(Error::InvalidProvenance)?;
        record.verify_signature(&producer.signing_public_key())?;
    } else {
        if inline.is_none() {
            return Err(Error::InvalidProvenance);
        }
        let producer = history
            .attribute_producer(location, record.value.name().as_str())
            .map_err(|_| Error::InvalidProvenance)?;
        if producer != record.producer {
            return Err(Error::InvalidProvenance);
        }
    }

    Ok(VerifiedAttributeEvidence {
        record: record.identity()?,
        object: record.object,
        name: record.value.name(),
        function: record.function.clone(),
        value: record.value.encode()?,
        producer: record.producer,
        location: location.clone(),
    })
}
