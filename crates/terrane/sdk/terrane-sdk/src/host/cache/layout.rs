//! Binds each registered host layout to one trusted disclosure-domain root.

use crate::{
    domain::DomainBinding,
    store::{InvalidReason, StoreErrorKind, StoreFailure},
};
use std::path::{Component, Path, PathBuf};
use terrane_format::{chunking::ChunkProfile, properties::Domain};

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
        let normalized: PathBuf = root.components().collect();
        if normalized.as_os_str() != root.as_os_str()
            || !root.is_absolute()
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

/// Configures host-local domain content without repository routing authority.
///
/// This location supplies no ref, tree root or repository path. Native kernel
/// inspection and the host's protected charge-owner configuration separately
/// establish physical custody; the location itself grants no read permission.
#[derive(Clone, Debug)]
pub struct HostDomainLocation {
    root: PathBuf,
    domain: String,
    profile: ChunkProfile,
}

impl HostDomainLocation {
    /// Validates a physical host-local domain location and immutable profile.
    ///
    /// # Errors
    /// Rejects noncanonical/relative roots, traversal and malformed domains.
    pub fn new(root: PathBuf, domain: String, profile: ChunkProfile) -> Result<Self, StoreFailure> {
        let normalized: PathBuf = root.components().collect();
        if normalized.as_os_str() != root.as_os_str()
            || !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || Domain::parse(&domain).is_err()
        {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::MalformedRequest,
            )));
        }
        Ok(Self {
            root,
            domain,
            profile,
        })
    }

    /// Returns the configured physical domain root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the configured canonical disclosure domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the immutable configured chunk profile.
    pub fn chunk_profile(&self) -> &ChunkProfile {
        &self.profile
    }
}

mod sealed {
    /// Restricts implementations to the built-in host location types.
    pub trait Sealed {}
}

/// Supplies fixed host location facts to shared verification machinery.
///
/// Only the repository-bound and host-local location types implement this
/// sealed configuration interface. Neither implementation is authorization,
/// admission, quota or kernel-seal evidence.
pub trait HostReadLocation: sealed::Sealed + crate::bucket::BucketBinding {
    /// Returns the configured physical root.
    fn root(&self) -> &Path;

    /// Returns the configured disclosure domain.
    fn domain(&self) -> &str;

    /// Returns the immutable configured chunk profile.
    fn chunk_profile(&self) -> &ChunkProfile;
}

impl sealed::Sealed for DomainHostLayout {}
impl sealed::Sealed for HostDomainLocation {}

impl HostReadLocation for DomainHostLayout {
    fn root(&self) -> &Path {
        &self.root
    }
    fn domain(&self) -> &str {
        &self.binding.domain
    }
    fn chunk_profile(&self) -> &ChunkProfile {
        &self.profile
    }
}

impl HostReadLocation for HostDomainLocation {
    fn root(&self) -> &Path {
        &self.root
    }
    fn domain(&self) -> &str {
        &self.domain
    }
    fn chunk_profile(&self) -> &ChunkProfile {
        &self.profile
    }
}
