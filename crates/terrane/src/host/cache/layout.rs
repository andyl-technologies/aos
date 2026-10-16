//! Binds each registered host layout to one trusted disclosure-domain root.

use crate::{
    domain::DomainBinding,
    store::{InvalidReason, StoreErrorKind, StoreFailure},
};
use std::path::{Component, Path, PathBuf};
use terrane_core::{chunking::ChunkProfile, properties::Domain};

/// Names one domain's host-cache directories and immutable chunk profile.
#[derive(Clone, Debug)]
pub struct DomainHostLayout {
    root: PathBuf,
    binding: DomainBinding,
    profile: ChunkProfile,
}

impl DomainHostLayout {
    /// Validates an absolute, normalized root and registered disclosure domain.
    ///
    /// This constructs routing configuration, not filesystem or read authority.
    /// Kernel layout validation is performed separately before writable opening.
    ///
    /// # Errors
    /// Rejects relative paths, parent traversal, and malformed domain labels.
    pub fn new(
        root: PathBuf,
        binding: DomainBinding,
        profile: ChunkProfile,
    ) -> Result<Self, StoreFailure> {
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || Domain::parse(&binding.domain).is_err()
        {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::MalformedRequest,
            )));
        }
        Ok(Self {
            root,
            binding,
            profile,
        })
    }

    /// Returns the configured root binding, without granting authorization.
    pub fn domain_binding(&self) -> &DomainBinding {
        &self.binding
    }

    /// Returns the domain's registered filesystem-layout root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the immutable configured chunk profile.
    pub fn chunk_profile(&self) -> &ChunkProfile {
        &self.profile
    }
}
