//! Constructs trusted vendor authorities inside the existing owning service actor.
//!
//! The factory crosses the thread boundary before native birth. Its installed
//! registry and non-Send participants stay on the original actor thereafter.
//! Portable Compile/Submit selections only name that installation; they cannot
//! construct a source inspector, normal Accepted policy or native permission.

use std::sync::Arc;

use crucible_campaign::CampaignRepository;
use crucible_store::content_store::{ImmutableBlobBackend, MutableRefBackend};

use super::{NodeObservationService, NodeObservationServiceConfig, NodeObservationServiceError};
use crate::node_observed_executor::{InstalledNodeCatalog, NodeObservedError};

pub(super) struct ActorInstallations {
    pub(super) original: Option<super::OriginalLineageHostInstallation>,
    pub(super) vendor: Option<Box<dyn InstalledVendorServiceFactory>>,
}

/// Constructs operator-installed vendor authority on the ordinary owning actor.
///
/// Ordinary provider installation requires independently installed source and
/// complete normal behavioral acceptance. The closed reference route uses
/// `ReferenceVendorInstallation::new` and `install`. A collecting source factory
/// instead occupies the separate unqualified scene slot and cannot register an
/// ordinary selectable class. This factory has no public wire representation;
/// installation performs no native lifecycle and cannot promote decoded data
/// or collecting results into qualification.
pub trait InstalledVendorServiceFactory: Send {
    /// Installs the original registry and normal policy without allocating a Child.
    ///
    /// # Errors
    /// Refuses unavailable source/class scope, invalid ceilings or replacement
    /// of an existing original catalog installation.
    ///
    /// # Panics
    /// Source or normal policy callbacks may unwind. Native effects are forbidden
    /// during this startup callback; the service has not accepted submissions.
    fn install(
        self: Box<Self>,
        catalog: &mut InstalledNodeCatalog,
    ) -> Result<(), NodeObservedError>;
}

type SourceFactory = Box<
    dyn FnOnce() -> Result<
            crate::node_observed_executor::ReferenceVendorInstallationRequest,
            NodeObservedError,
        > + Send,
>;

/// Builds the concrete closed reference installation on its original actor.
///
/// The callback supplies trusted operator authorities, never portable request
/// data. It must perform source inspection only and allocate no native child.
/// The concrete constructor reauthenticates its full source and normal Accepted
/// policy before installing the ordinary registry and selector.
pub struct ReferenceVendorServiceFactory {
    source: SourceFactory,
}

impl ReferenceVendorServiceFactory {
    /// Retains a once-only source installation callback for the owning actor.
    pub fn new<F>(source: F) -> Self
    where
        F: FnOnce() -> Result<
                crate::node_observed_executor::ReferenceVendorInstallationRequest,
                NodeObservedError,
            > + Send
            + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

impl InstalledVendorServiceFactory for ReferenceVendorServiceFactory {
    fn install(
        self: Box<Self>,
        catalog: &mut InstalledNodeCatalog,
    ) -> Result<(), NodeObservedError> {
        let request = (self.source)()?;
        crate::node_observed_executor::ReferenceVendorInstallation::new(request)?.install(catalog)
    }
}

impl NodeObservationService {
    /// Starts ordinary Compile/Submit with a trusted actor-local vendor installation.
    ///
    /// Existing startup uses no vendor factory. The new selector retains the
    /// unchanged ordinary claim, execution nonce, worker, status, scheduler and
    /// complete all-owner activation path.
    ///
    /// # Errors
    /// Refuses invalid service limits, actor startup or incomplete trusted vendor
    /// installation before returning a usable submission handle.
    pub fn start_with_vendor_installation(
        configuration: NodeObservationServiceConfig,
        installation: Box<dyn InstalledVendorServiceFactory>,
        repository: Arc<CampaignRepository>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        Self::start_inner_installed(
            configuration,
            None,
            ActorInstallations {
                original: None,
                vendor: Some(installation),
            },
            repository,
            blobs,
            refs,
        )
    }
}
