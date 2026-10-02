//! Owns the canonical immutable-content descriptor codec.
//!
//! Descriptors carry a configured algorithm, registered domain, digest and
//! immutable size. Decoding borrows every field and applies bounds derived from
//! the trusted profile before allocating the validated model.
//!
//! ```text
//! [algorithm: text, domain: text, digest: bytes, size: unsigned integer]
//! ```

use alloc::vec::Vec;
use core::fmt;

use super::{Descriptor, IdentityError, IdentityProfile};
use crate::cbor::{self, Decoder};

#[cfg(test)]
mod tests;

/// A rejected descriptor wire encoding or profile binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A field uses malformed, noncanonical, oversized or trailing CBOR.
    Cbor(cbor::Error),
    /// The descriptor does not contain exactly four array fields.
    Shape,
    /// An algorithm, domain or digest does not match the configured profile.
    Identity(IdentityError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(formatter, "descriptor encoding: {error}"),
            Self::Shape => formatter.write_str("descriptor must contain four fields"),
            Self::Identity(error) => write!(formatter, "descriptor identity: {error}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Shape => None,
        }
    }
}

impl From<cbor::Error> for Error {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl From<IdentityError> for Error {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl Descriptor {
    /// Encodes the four descriptor fields as deterministic CBOR.
    ///
    /// Size remains metadata and does not enter the content identity.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, 4);
        cbor::write_text(&mut bytes, self.algorithm());
        cbor::write_text(&mut bytes, self.domain());
        cbor::write_bytes(&mut bytes, self.digest());
        cbor::write_uint(&mut bytes, self.size());
        bytes
    }

    /// Decodes a canonical descriptor under the receiver's configured profile.
    ///
    /// The input supplies no algorithm or domain registration. Field lengths
    /// are bounded by the trusted profile, and complete CBOR and profile
    /// validation precede allocating the owned descriptor. Decoding does not
    /// verify content bytes; [`Self::verify_bytes`] performs that check.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for malformed, noncanonical, oversized or trailing
    /// input, the wrong array shape, an unsupported algorithm, an unregistered
    /// domain or a digest of the wrong configured length.
    pub fn decode(profile: &IdentityProfile, bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array(4)? != 4 {
            return Err(Error::Shape);
        }
        let algorithm = decoder.text(profile.algorithm().len())?;
        let domain_limit = profile
            .domains()
            .iter()
            .map(|registration| registration.name().len())
            .max()
            .unwrap_or(0);
        let domain = decoder.text(domain_limit)?;
        let digest = decoder.bytes(profile.digest_len())?;
        let size = decoder.uint()?;
        decoder.finish()?;

        Ok(Self::from_wire(profile, algorithm, domain, digest, size)?)
    }
}
