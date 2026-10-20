//! Verified OCI artifact and Distribution operations for AOS.
//!
//! This native crate complements `aos-oci-types`: the types crate owns the
//! dependency-light wire contracts, while this crate owns filesystem, archive,
//! hashing, decompression, and HTTP effects. The major modules are:
//!
//! - [`layout`] for fail-closed OCI layout inspection and platform selection;
//! - [`archive`] for safe OCI archive ingestion and deterministic export;
//! - [`external_signing`] for private-key-free production release finalization;
//! - [`registry`] for authenticated, resumable Distribution pull and push;
//! - [`mod@reference`] for complete registry references and CLI platform values.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod archive;
pub mod external_signing;
pub mod layout;
pub mod reference;
pub mod registry;

pub use archive::{
    PreparedLayout, prepare_layout, write_docker_archive, write_oci_archive, write_oci_layout,
};
pub use external_signing::{
    FinalizedContainerPublication, container_signature_pae, finalize_container_publication,
    write_container_signature_pae,
};
pub use layout::{VerifiedImage, read_verified_index, verify_layout};
pub use reference::{ArtifactFormat, PlatformSelector, RegistryReference};
pub use registry::{
    PullOptions, PushOptions, PushResult, RegistryClient, ReleaseGraphPushResult, TransferEvent,
    VerifiedPublicationCommit, VerifiedPublicationHook, VerifiedPublicationRequest,
    VerifiedPublicationResult, VerifiedPublicationSession,
};
