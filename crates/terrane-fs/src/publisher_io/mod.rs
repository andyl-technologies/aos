//! Retains publisher-owned directory and inode descriptors across publication.
//!
//! This module implements no socket protocol. Descriptor receipt belongs to
//! the registered local protocol adapter. One adapter owns one domain; callers
//! cannot select another directory by changing a content claim.

#[cfg(feature = "tokio")]
mod bodies;
#[cfg(feature = "tokio")]
mod manifest;
#[cfg(feature = "tokio")]
pub use manifest::NativeManifestWitness;
#[cfg(feature = "tokio")]
pub(crate) use manifest::ReceivedManifest;
mod native;
#[cfg(feature = "tokio")]
mod worker;

pub use native::{NativePublisher, StagedFile};
#[cfg(feature = "tokio")]
pub use worker::{
    NativeBodyHandle, NativeBodyIncarnation, NativeBodyKey, NativeCommandContext,
    NativeCommandResult, NativeOperation, NativePublicationWorker, NativePublishedObject,
    NativePublisherConfig, NativePublisherPrepared, NativeRetirementPolicy, NativeSealProbe,
    NativeWipePolicy,
};

#[cfg(feature = "native-test-fixtures")]
pub use worker::run_native_fixture;
