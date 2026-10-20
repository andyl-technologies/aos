//! Exposes canonical content and namespace models under the SDK's glossary names.
//!
//! These names reuse the formats defined by specifications 04, 06, and 09
//! (CRATE-20, CRATE-22). Object metadata describes ordered plaintext chunks;
//! its content reference selects the canonical inline or manifest identity.
//! Ref names remain separate from the mutable records compared by the store.

/// Names a plaintext chunk by its domain-separated digest and byte length.
///
/// This is the same [`crate::manifest::ChunkRef`] used in object manifests.
/// Compressed storage envelopes are represented by [`crate::codec::EncodedChunk`].
pub use crate::manifest::ChunkRef as Chunk;

/// Describes a file's ordered chunks, total size, and registered plaintext hashes.
///
/// This is the same [`crate::manifest::Manifest`] used by the canonical codec.
/// [`Object::content_ref`] selects the chunk identity for a small file and the
/// manifest identity for a larger one, without reading plaintext.
pub use crate::manifest::Manifest as Object;

/// Describes the complete mutable commit selection compared by ref CAS.
///
/// This is the same [`crate::refs::RefRecord`] used by the canonical codec.
/// Its store key is supplied separately as a [`crate::refs::RefName`].
pub use crate::refs::RefRecord as Ref;

/// Names the domain-separated root-node digest of a v1 tree.
///
/// This is the same [`crate::identity::Digest`] returned by
/// [`crate::tree_builder::StoredNode::identity`]. The root's canonical node
/// carries its property declarations; an identifier alone conveys no authority
/// to read or modify the corresponding namespace.
pub use crate::identity::Digest as Root;
