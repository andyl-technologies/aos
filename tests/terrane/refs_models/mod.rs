//! Independent public models and CBOR tables for modern commit and ref witnesses.

/// Constructs independent complete public commit models.
pub(super) mod commits;
/// Owns the primitive numbered field tables for every fixture family.
pub(super) mod fields;
/// Reconstructs structural failures outside the owning codecs.
pub(super) mod negative;
/// Constructs public ref, annotation and reflog field alternatives.
pub(super) mod records;
/// Owns independent CBOR primitives and bounded reference readers.
pub(super) mod support;
