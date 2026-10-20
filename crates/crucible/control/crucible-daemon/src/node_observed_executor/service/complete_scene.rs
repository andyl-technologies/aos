//! Adopts only a trusted pinned collecting installation on the ordinary actor.

use super::*;
use crate::{
    node_observed_executor::{InstalledVendorServiceFactory, NodeObservedError},
    node_qualification::InstalledCompleteSceneManifest,
};

/// Carries an operator-pinned complete-source installation to its owning actor.
///
/// The factory carries source declarations only. It creates no ordinary
/// Accepted class or vendor selector and performs no native lifecycle at install.
pub struct CompleteSceneServiceFactory {
    manifest: InstalledCompleteSceneManifest,
}

impl CompleteSceneServiceFactory {
    /// Retains the independent local source pin before starting the actor.
    pub fn new(manifest: InstalledCompleteSceneManifest) -> Self {
        Self { manifest }
    }
}

impl InstalledVendorServiceFactory for CompleteSceneServiceFactory {
    fn install(
        self: Box<Self>,
        catalog: &mut InstalledNodeCatalog,
    ) -> Result<(), NodeObservedError> {
        catalog.install_complete_scene(self.manifest)
    }
}

impl NodeObservationService {
    /// Consumes the installed collecting scene's once-only initial lifecycle.
    ///
    /// # Errors
    /// Refuses an absent, spent or withdrawn installation, any installed native
    /// or source gate, exhausted resources or unavailable actor. Success is
    /// inactive preparation only; it grants no ordinary acceptance or activation.
    pub fn prepare_complete_scene(&self) -> Result<(), NodeObservationServiceError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Command::CompleteScenePrepare { reply })?;
        response
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)?
    }
}
