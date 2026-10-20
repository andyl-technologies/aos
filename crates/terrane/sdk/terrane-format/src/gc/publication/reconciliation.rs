//! Owns the registered local reconciliation record's ordinary format fields.
//!
//! Its authorization digest, fence pointer, exclusion and index digest are
//! represented data. Encoding or decoding cannot establish current authority
//! or permission for a native operation.
//!
//! ```text
//! LocalGcReconciliation = {0: 1, 1: authorization-digest,
//!                          2: [fence-key, fence-digest],
//!                          3: [pack-id, cycle, epoch], 4: index-digest}
//! ```

use super::{PublicationError, RawDigest, validation};
use crate::cbor::{Decoder, write_array, write_bytes, write_map, write_text, write_uint};
use crate::identity::Digest;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Carries the complete, unverified fields of a local-v1 GC reconciliation.
///
/// The registered map binds a represented authorization, current fence,
/// original exclusion and detached-index identity. These public fields do not
/// prove selection, freshness, verified index contents or permission for an
/// effect. The record itself has no immutable-content identity domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalGcReconciliation {
    /// Claimed raw digest of the immutable deletion authorization bytes.
    pub authorization: RawDigest,
    /// Registered current fence key, without proof of its current selection.
    pub fence_key: String,
    /// Claimed raw digest of the exact current fence bytes.
    pub fence_digest: RawDigest,
    /// Physical pack identifier asserted by the original exclusion.
    pub pack: [u8; 16],
    /// Original exclusion cycle, which need not equal the current fence cycle.
    pub cycle: u64,
    /// Original exclusion's asserted fencing epoch.
    pub epoch: u64,
    /// Claimed detached-index identity, without verification of an index witness.
    pub index: Digest,
}

impl LocalGcReconciliation {
    /// Encodes the ordinary record in its exact registered local-v1 form.
    ///
    /// # Errors
    /// Returns [`PublicationError::Schema`] for an invalid registered fence-key
    /// spelling. Fixed-size fields and unsigned integers are enforced by the
    /// public field types. No current-authority checks are performed.
    pub fn encode(&self) -> Result<Vec<u8>, PublicationError> {
        validation::fence_key(&self.fence_key)?;

        let mut bytes = Vec::new();
        write_map(&mut bytes, 5);
        write_uint(&mut bytes, 0);
        write_uint(&mut bytes, 1);

        write_uint(&mut bytes, 1);
        write_bytes(&mut bytes, &self.authorization);

        write_uint(&mut bytes, 2);
        write_array(&mut bytes, 2);
        write_text(&mut bytes, &self.fence_key);
        write_bytes(&mut bytes, &self.fence_digest);

        write_uint(&mut bytes, 3);
        write_array(&mut bytes, 3);
        write_bytes(&mut bytes, &self.pack);
        write_uint(&mut bytes, self.cycle);
        write_uint(&mut bytes, self.epoch);

        write_uint(&mut bytes, 4);
        write_bytes(&mut bytes, &self.index);
        Ok(bytes)
    }

    /// Decodes complete canonical bytes into ordinary, unverified fields.
    ///
    /// All field shapes, widths, collection and string bounds, the version,
    /// ordered keys, registered fence-key spelling and trailing input are
    /// checked against borrowed bytes before retaining the fence key.
    ///
    /// # Errors
    /// Returns [`PublicationError::Cbor`] for malformed, noncanonical,
    /// input-unbounded or trailing CBOR, including declared lengths above
    /// fixed-field bounds; returns [`PublicationError::Schema`]
    /// for an unsupported version, unknown or missing field, wrong exact shape
    /// or short fixed-width field, or invalid registered fence-key spelling.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicationError> {
        let fields = Borrowed::decode(bytes)?;

        Ok(Self {
            authorization: fields.authorization,
            fence_key: fields.fence_key.to_string(),
            fence_digest: fields.fence_digest,
            pack: fields.pack,
            cycle: fields.cycle,
            epoch: fields.epoch,
            index: fields.index,
        })
    }
}

/// Keeps the sole variable-width field borrowed throughout full validation.
struct Borrowed<'a> {
    authorization: RawDigest,
    fence_key: &'a str,
    fence_digest: RawDigest,
    pack: [u8; 16],
    cycle: u64,
    epoch: u64,
    index: Digest,
}

impl<'a> Borrowed<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, PublicationError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.map(5)? != 5 {
            return Err(PublicationError::Schema);
        }
        key(&mut decoder, 0)?;
        if decoder.uint()? != 1 {
            return Err(PublicationError::Schema);
        }

        key(&mut decoder, 1)?;
        let authorization = fixed(&mut decoder)?;

        key(&mut decoder, 2)?;
        if decoder.array(2)? != 2 {
            return Err(PublicationError::Schema);
        }
        let fence_key = decoder.text(decoder.remaining().len())?;
        let fence_digest = fixed(&mut decoder)?;

        key(&mut decoder, 3)?;
        if decoder.array(3)? != 3 {
            return Err(PublicationError::Schema);
        }
        let pack = fixed(&mut decoder)?;
        let cycle = decoder.uint()?;
        let epoch = decoder.uint()?;

        key(&mut decoder, 4)?;
        let index = fixed(&mut decoder)?;
        decoder.finish()?;
        validation::fence_key(fence_key)?;

        Ok(Self {
            authorization,
            fence_key,
            fence_digest,
            pack,
            cycle,
            epoch,
            index,
        })
    }
}

fn key(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), PublicationError> {
    if decoder.uint()? != expected {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], PublicationError> {
    decoder
        .bytes(N)?
        .try_into()
        .map_err(|_| PublicationError::Schema)
}
