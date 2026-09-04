//! Frozen structural admission limits from RFC-0018.
//!
//! Deployments may choose smaller operational blob or quota limits. They must
//! not raise these structural constants without a compatibility review because
//! native Hub, Worker, CLI, and browser parsers rely on the same allocation and
//! traversal bounds.

/// Maximum bytes in a manifest, index, image config, artifact, or error JSON body.
pub const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;

/// Maximum descriptors directly contained by one manifest or index.
pub const MAX_DESCRIPTORS_PER_OBJECT: usize = 1_024;

/// Maximum platform-bearing descriptors in one image index.
pub const MAX_PLATFORMS_PER_INDEX: usize = 256;

/// Maximum filesystem layers in one runnable image.
pub const MAX_LAYERS_PER_IMAGE: usize = 64;

/// Maximum descriptor graph depth in one publication.
pub const MAX_DESCRIPTOR_GRAPH_DEPTH: usize = 8;

/// Maximum descriptors reachable from one publication root.
pub const MAX_REACHABLE_DESCRIPTORS: usize = 65_536;

/// Maximum UTF-8 byte length of one annotation key.
pub const MAX_ANNOTATION_KEY_BYTES: usize = 1_024;

/// Maximum UTF-8 byte length of one annotation value.
pub const MAX_ANNOTATION_VALUE_BYTES: usize = 4 * 1_024;

/// Maximum sum of annotation key and value UTF-8 bytes on one object.
pub const MAX_ANNOTATIONS_BYTES: usize = 64 * 1_024;

/// Maximum byte length of one canonical repository name.
pub const MAX_REPOSITORY_BYTES: usize = 255;

/// Maximum byte length of one canonical tag.
pub const MAX_TAG_BYTES: usize = 128;

/// Maximum byte length of a signed container-release identity field.
pub const MAX_CONTAINER_RELEASE_IDENTITY_BYTES: usize = 255;

/// Maximum byte length of a Nix definition attribute in release provenance.
pub const MAX_NIX_DEFINITION_ATTRIBUTE_BYTES: usize = 255;

/// Maximum byte length of a Nix output name in release provenance.
pub const MAX_NIX_OUTPUT_NAME_BYTES: usize = 64;

/// Maximum byte length of a Nix derivation or output store path.
pub const MAX_NIX_STORE_PATH_BYTES: usize = 4 * 1_024;

/// Maximum upload-session lifetime in seconds.
pub const MAX_UPLOAD_SESSION_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

/// Required OCI and Docker schema 2 document version.
pub const SCHEMA_VERSION: u32 = 2;
