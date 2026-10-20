//! Provides a non-owning view of one host tier's encoded content (STORE-14).
//!
//! Each adapter binds an already configured host domain directory. Reads use
//! the host's concrete verification path; no file is copied, admitted, repaired,
//! or charged to a viewing instance. Sealed plaintext backing files belong to
//! the separate publisher API and never substitute for canonical store bytes.
//! Private domains require consumer-owned pins and wipe-on-release, so they
//! cannot be opened as shared cache tiers (DOM-15).

mod domains;
mod reader;

pub use domains::{ResidentSharedDirRoutes, SharedDirRoutes, SharedRoutes};
pub use reader::HostViewReader;

use crate::bucket::BucketBinding;
use crate::domain::DomainBinding;
use crate::host::cache::{
    DomainHostLayout, HostReadLimits, HostReadOnlyContent, HostResidenceReader, HostResidentContent,
};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, ContentValidator,
    IdentityPrefix, InvalidReason, LocalFs, RefCapability, StoreErrorKind, StoreFailure,
};
use terrane_format::identity::Identity;
use terrane_format::properties::Domain;

/// Reads one non-private domain's existing host content without owning bytes.
///
/// This type implements only [`ContentStore`]. Its capabilities grant neither
/// ref authority nor sealed backing access. A caller must still enforce fresh
/// repository authorization before exposing bytes; [`SharedDirRoutes`] consumes
/// guard-issued operation decisions for that purpose.
pub type SharedDir<F, V> = SharedView<HostReadOnlyContent<F, V>>;

/// Reads encoded content with independently verified sealed-residence fallback.
///
/// The residence binding must retain genuine native custody evidence; this
/// composition alone establishes no seal, pin, or current authorization proof.
pub type ResidentSharedDir<F, V, R> = SharedView<HostResidentContent<F, V, R>>;

/// Wraps one of the supported concrete host readers without admitting bytes.
///
/// Construction is restricted to the ordinary reader factory and its additive
/// residence composition. Arbitrary content stores cannot become host views.
pub struct SharedView<S> {
    reader: S,
    capabilities: Capabilities,
}

impl<F, V> SharedView<HostReadOnlyContent<F, V>>
where
    F: LocalFs + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Opens an existing non-private directory without initialization or probes.
    ///
    /// The layout comes from trusted host configuration. Its domain binding
    /// selects one physical namespace, never a request-provided hash lookup.
    ///
    /// # Errors
    ///
    /// Returns `Unsupported` for private-domain shared caching, `Invalid` for
    /// a malformed domain, or the host reader's verification or I/O failure.
    pub async fn open_existing(
        layout: DomainHostLayout,
        fs: F,
        validator: V,
    ) -> Result<Self, StoreFailure> {
        Self::open_existing_with_limits(layout, fs, validator, HostReadLimits::default()).await
    }

    /// Opens an existing view with an explicit host-read allocation budget.
    ///
    /// Limits govern temporary verification buffers, not format validity or
    /// viewing-instance reservations. Larger valid content returns `Capacity`;
    /// opening never admits bytes or creates accounting records.
    ///
    /// # Errors
    ///
    /// Returns `Unsupported` for private-domain shared caching, `Invalid` for
    /// malformed configuration, or the host reader's verification or I/O failure.
    pub async fn open_existing_with_limits(
        layout: DomainHostLayout,
        fs: F,
        validator: V,
        limits: HostReadLimits,
    ) -> Result<Self, StoreFailure> {
        check_domain(&layout.domain_binding().domain)?;
        let reader =
            HostReadOnlyContent::open_existing_with_limits(layout, fs, validator, limits).await?;
        let mut capabilities = reader.capabilities().clone();
        capabilities.refs = RefCapability::None;
        capabilities.presign = false;
        capabilities.sealed = false;

        Ok(Self {
            reader,
            capabilities,
        })
    }

    /// Adds a trusted residence binding without admitting or reserving content.
    ///
    /// The host wrapper verifies plaintext chunk identity and reconstructs the
    /// registered raw codec envelope. Manifest reads retain canonical metadata.
    /// A portable trait implementation alone does not prove native custody.
    ///
    /// # Errors
    ///
    /// Returns `Capacity` when `max_inventory_entries` is zero.
    pub fn with_residences<R: HostResidenceReader>(
        self,
        residences: R,
        max_inventory_entries: usize,
    ) -> Result<ResidentSharedDir<F, V, R>, StoreFailure> {
        let reader = self
            .reader
            .with_residences(residences, max_inventory_entries)?;

        Ok(SharedView {
            reader,
            capabilities: self.capabilities,
        })
    }
}

impl<S: HostViewReader> SharedView<S> {
    /// Returns configuration provenance without granting root read authority.
    #[must_use]
    pub fn domain_binding(&self) -> &DomainBinding {
        self.reader.host_layout().domain_binding()
    }

    /// Borrows the validated host layout without exposing a writable backend.
    #[must_use]
    pub fn layout(&self) -> &DomainHostLayout {
        self.reader.host_layout()
    }

    /// Returns the host's opening observation solely to reject configured aliases.
    pub(super) fn directory_identity(&self) -> (u64, u64) {
        self.reader.observed_directory_identity()
    }
}

impl<S> CapabilityReport for SharedView<S> {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: HostViewReader> ContentStore for SharedView<S> {
    async fn put(&self, _upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        // Even a dedup hit is a write request; never consult the viewed tier.
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.reader.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.reader.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.reader.list(prefix).await
    }
}

fn check_domain(domain: &str) -> Result<(), StoreFailure> {
    match Domain::parse(domain) {
        Ok(Domain::Private(_)) => Err(StoreFailure::new(StoreErrorKind::Unsupported)),
        Ok(_) => Ok(()),
        Err(_) => Err(StoreFailure::new(StoreErrorKind::Invalid(
            InvalidReason::MalformedRequest,
        ))),
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "tokio", unix))]
mod native_tests;
