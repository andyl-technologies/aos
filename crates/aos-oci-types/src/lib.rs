//! Shared OCI image and Distribution wire contracts for AOS.
//!
//! This crate is the dependency-light boundary shared by the AOS CLI, native
//! Hub, Cloudflare Worker, and browser console. It performs no I/O and has no
//! async or platform bindings, so the same parser and validation policy can be
//! compiled for native targets and `wasm32-unknown-unknown`.
//!
//! RFC-0015 deliberately distinguishes uploaded bytes from parsed records.
//! Registry implementations retain and digest the exact bytes received; the
//! types here are bounded projections used for admission, graph traversal, and
//! AOS-generated canonical JSON. Generic OCI projections retain unknown
//! annotation keys in [`Annotations`] and may ignore unknown non-annotation
//! fields, so they never replace the original uploaded body. The AOS-owned
//! signed [`ContainerRelease`] schema is deliberately stricter and rejects
//! unknown fields at every nested object.
//!
//! # Module map
//!
//! - [`annotations`] owns the ordered, size-bounded extension map.
//! - [`canonical`] emits deterministic compact JSON without floating point.
//! - [`digest`] owns the v1 SHA-256-only content address.
//! - [`distribution`] owns standard Distribution error payloads and codes.
//! - [`limits`] freezes the RFC-0015 structural admission limits.
//! - [`media_type`] freezes the accepted OCI, Docker schema 2, and AOS media
//!   types.
//! - [`model`] owns descriptors, platforms, manifests, indexes, and image
//!   configuration documents.
//! - [`reference`] owns exact repository, tag, and manifest-reference parsing.
//! - [`release`] owns the strict signed `containers/v1/index.json` contract.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod annotations;
pub mod canonical;
pub mod digest;
pub mod distribution;
pub mod error;
pub mod limits;
pub mod media_type;
pub mod model;
pub mod reference;
pub mod release;

pub use annotations::Annotations;
pub use canonical::to_canonical_json;
pub use digest::Sha256Digest;
pub use distribution::{DistributionError, DistributionErrorCode, DistributionErrorEnvelope};
pub use error::{Error, Result};
pub use media_type::MediaType;
pub use model::{
    Descriptor, EmptyObject, HistoryEntry, ImageConfig, ImageIndex, ImageManifest,
    ImageRuntimeConfig, Platform, RootFs, RootFsType,
};
pub use reference::{ManifestReference, RepositoryName, Tag};
pub use release::{
    CONTAINER_RELEASE_SCHEMA_VERSION, CONTAINER_RELEASE_SIDECAR_PATH, ContainerNixProvenance,
    ContainerOciRelease, ContainerRelease, ContainerReleaseEvidence, ContainerReleaseIdentity,
    NixDefinitionIdentity, NixOutputIdentity,
};
