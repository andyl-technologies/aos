//! Owns the original one-owner collecting world and its positive retirement.
//!
//! This collector executes the actual installed provider beneath the common
//! runtime. Its observations do not constitute an Accepted certificate: all
//! complete clause reviews and adverse native cases remain separately required.

#[path = "singleton_actor.rs"]
mod actor;

use std::{path::PathBuf, sync::mpsc};

use crucible_node_format::ContentRef;

use super::{package::InstalledPublicReferencePackage, run_error::QualificationRunError};

/// Retains the exact installed implementation for source-only collection.
pub struct InstalledSingletonCollector {
    implementation: ContentRef,
}

/// Receives the one original collecting outcome without owning native cleanup.
pub struct OriginalSingletonCollection {
    receiver: mpsc::Receiver<Result<SingletonCollectionObservation, QualificationRunError>>,
}

/// Retains original native observations without providing class acceptance.
pub struct SingletonCollectionObservation {
    pub(super) implementation: ContentRef,
    pub(super) bytes: Vec<u8>,
}

impl InstalledSingletonCollector {
    /// Measures the ordinary implementation pinned into this executable.
    ///
    /// # Errors
    /// Refuses absent, malformed or changed installed source and runtime files.
    pub fn built_in() -> Result<Self, QualificationRunError> {
        let package = InstalledPublicReferencePackage::built_in()?;
        Ok(Self {
            implementation: package.identity().clone(),
        })
    }

    /// Starts one source-selected singleton under its own retained actor.
    ///
    /// Receiver cancellation cannot discard journals, unresolved native custody
    /// or a partial durable attempt. No caller profile or accepted verdict enters
    /// this entry point, and the ordinary factory gate remains independent.
    ///
    /// # Errors
    /// Refuses changed installation, an occupied actor reservation or thread
    /// allocation failure before any native child exists.
    pub fn start(
        &self,
        directory: PathBuf,
    ) -> Result<OriginalSingletonCollection, QualificationRunError> {
        let package = InstalledPublicReferencePackage::built_in()?;
        if package.identity() != &self.implementation {
            return Err(QualificationRunError::Refused(
                "singleton installed source changed",
            ));
        }
        Ok(OriginalSingletonCollection {
            receiver: actor::start(directory)?,
        })
    }
}

impl OriginalSingletonCollection {
    /// Waits for the original result; it never starts a replacement collection.
    ///
    /// # Errors
    /// Returns the original refusal or unavailable actor result. On a native
    /// failure the original actor continues owning all unresolved objects.
    pub fn wait(self) -> Result<SingletonCollectionObservation, QualificationRunError> {
        self.receiver.recv()?
    }
}

impl SingletonCollectionObservation {
    /// Borrows the exact installed implementation identity.
    pub fn implementation(&self) -> &ContentRef {
        &self.implementation
    }

    /// Borrows original observations and the complete unresolved case population.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
