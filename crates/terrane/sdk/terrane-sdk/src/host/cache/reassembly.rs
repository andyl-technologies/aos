//! Selects the implemented host reassembly modes without silently enabling smart.

use crate::{
    host::publication::PublicationClaim,
    store::{StoreErrorKind, StoreFailure},
};

/// Selects the host modes implemented on the initial host-tier trunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyMode {
    /// Keeps multi-chunk objects in their existing encoded chunk bodies.
    Never,
    /// Prepares a whole sealed file on first open, including small objects.
    Always,
}

impl TryFrom<&str> for ReassemblyMode {
    type Error = StoreFailure;

    /// Parses an implemented registered mode without substituting another mode.
    ///
    /// # Errors
    /// Returns unsupported for smart or an unknown mode; smart remains deferred.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "never" => Ok(Self::Never),
            "always" => Ok(Self::Always),
            _ => Err(StoreFailure::new(StoreErrorKind::Unsupported)),
        }
    }
}

impl ReassemblyMode {
    /// Reports whether this object needs a sealed backing file under the mode.
    ///
    /// A one-chunk object is directly decompressed and sealed in either mode,
    /// including a manifest-backed object represented by one final chunk.
    pub fn requires_sealed_file(self, claim: &PublicationClaim) -> bool {
        let chunks = claim.manifest().map_or(1, |manifest| manifest.chunks.len());
        chunks == 1 || matches!(self, Self::Always)
    }
}
