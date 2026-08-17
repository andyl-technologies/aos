//! Process-local shape identifiers and fingerprints.

/// An in-process fingerprint of a shape's symbol-sorted key vector.
///
/// This hash is only a lookup accelerator for future shape tables and hash-cons
/// probes. It is not a Nix-observable hash, not durable across implementations,
/// and not sufficient for equality without comparing the key vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeFingerprint(u64);

impl ShapeFingerprint {
    /// Creates a fingerprint from raw xxh3 bits for shape-module internals.
    pub(super) const fn from_u64(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw xxh3 fingerprint bits.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// An in-process fingerprint of a shaped attrset instance.
///
/// This hash is only a bucket key for hash-cons probes. It is not a
/// Nix-observable hash, not durable across evaluator processes, and not
/// sufficient for equality without [`crate::attrs::shape::ShapedAttrs::raw_eq`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapedAttrsFingerprint(u64);

impl ShapedAttrsFingerprint {
    /// Creates a fingerprint from raw xxh3 bits for shape-module internals.
    pub(super) const fn from_u64(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw xxh3 fingerprint bits.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A process-local dense record id for an interned shape.
///
/// The id is stable only inside one [`crate::attrs::shape::ShapeTable`]. It is not durable, not a
/// serialized cache key, not a pointer, and not meaningful across evaluator
/// processes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeId(u32);

impl ShapeId {
    /// Creates a shape-table id from raw bits.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw process-local id.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}
