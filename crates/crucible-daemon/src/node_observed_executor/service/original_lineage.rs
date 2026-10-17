//! Installs original-lineage preparation authorities on the ordinary owning actor.

use super::*;
use crate::node_observed_executor::InstalledOriginalLineageAuthority;
use crate::node_qualification::{AcceptanceLimits, InstalledAcceptancePolicy};

/// Holds two separately configured host authorities without accepting portable policy data.
///
/// No accepted conditional class is supplied by default. A deployment must
/// install independently authenticated complete behavioral records and the
/// immutable original-source inspector; collecting fixtures cannot provide one
/// authority in place of the other.
pub struct OriginalLineageHostInstallation {
    /// Authenticates the original package, journals, typed bodies and exact target substitution.
    pub source: InstalledOriginalLineageAuthority,
    /// Authenticates normal complete class acceptance for the actual selected target.
    pub behavioral: Box<dyn InstalledAcceptancePolicy + Send>,
    /// Bounds the independent behavioral authority's original evidence.
    pub limits: AcceptanceLimits,
}

impl NodeObservationService {
    /// Starts the normal owning actor with both original-lineage host authorities.
    ///
    /// The archive is an owned MAC capability. Neither its signer nor either
    /// installed authority may be selected by a portable request. Original
    /// pair replay and ordinary native selection retain their existing paths.
    ///
    /// # Errors
    /// Refuses changed immutable policy, invalid behavioral credits or the same
    /// installed artifacts, complete custody and actor conditions as [`Self::start`].
    pub fn start_with_original_lineage_authorities(
        configuration: NodeObservationServiceConfig,
        archive: crucible::node_adapters::transcript::TranscriptArchive,
        installation: OriginalLineageHostInstallation,
        repository: Arc<CampaignRepository>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        Self::start_inner_original(
            configuration,
            Some(archive),
            Some(installation),
            repository,
            blobs,
            refs,
        )
    }

    /// Queues once-only inactive preparation on the original owning actor.
    ///
    /// This operation emits no original response, common Ready or capture grant.
    /// The complete signed sources and prepared model capsule stay on the actor;
    /// shutdown transfers inactive models to authentic whole-world reclamation.
    ///
    /// # Errors
    /// Refuses malformed requests, missing independently installed authorities,
    /// changed source policy, incomplete behavioral acceptance, source/native
    /// evidence refusal, actor failure or finite complete custody exhaustion.
    pub fn prepare_original_lineage(
        &self,
        request: crate::node_control::NodeOriginalLineageRequest,
    ) -> Result<(), NodeObservationServiceError> {
        request.validate().map_err(refused)?;
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Command::OriginalLineagePrepare { request, reply })?;
        response
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)?
    }
}

/// Reserves the complete original request before source inspection can run.
///
/// The shared durable claim excludes every preparation route, including an
/// unresolved claim whose per-route publication failed. Historical custody
/// survives actor restart and never supplies a second inspection ticket.
///
/// # Errors
/// Refuses malformed requests, foreign or retained nonce claims, exhausted
/// durable credit, missing retained bodies or unavailable storage.
pub(super) fn reserve_original_claim(
    request: &crate::node_control::NodeOriginalLineageRequest,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
) -> Result<(), NodeObservationServiceError> {
    request.validate().map_err(refused)?;
    let bytes = conditional_preparation::encode(request)?;
    let claims = original_claim::OriginalClaims::new(blobs, refs)?;
    let reservation = claims.reserve(
        &request.execution,
        original_claim::Route::OriginalLineage,
        &bytes,
    )?;
    if reservation != original_claim::Reservation::Original {
        return Err(refused(
            "retained original-lineage claim cannot redispatch source inspection",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
