//! Retains publisher-owned directory and inode descriptors across publication.
//!
//! This module implements no socket protocol. Descriptor receipt belongs to
//! the registered local protocol adapter. One adapter owns one domain; callers
//! cannot select another directory by changing a content claim.

mod native;
#[cfg(feature = "tokio")]
mod worker;

pub use native::{NativePublisher, StagedFile};
#[cfg(feature = "tokio")]
pub use worker::{
    NativeBodyHandle, NativeBodyIncarnation, NativeBodyKey, NativeCommandContext,
    NativeCommandResult, NativeOperation, NativePublicationWorker, NativePublishedObject,
    NativePublisherConfig, NativeRetirementPolicy, NativeSealProbe, NativeWipePolicy,
};
