//! Selects immutable codec metadata extents without granting native authority.

/// Selects a finite serialized metadata extent for the canonical ACK codec.
///
/// The source selects this data before construction and accounts actual retained
/// metadata independently. It grants no native ACK limit or restoration right.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CanonicalAckCodecMetadataExtent {
    /// Admits at most 512 KiB of the complete immutable codec view.
    CanonicalAck512KiB,
}
