//! Retained physical namespace custody for an actual durable archive copy.
//!
//! This is one prerequisite for stopped receiving readiness, never Ready by
//! itself. The private fields bind the concrete source/destination backends
//! and an independent archive reader claim to the real publication receipt.

use super::*;
use crucible_campaign::{CampaignArchiveLease, CampaignHash};
use crucible_store::content_store::ImmutableBlobBackend;

/// Retains a real archive publication and its exact physical namespace owners.
///
/// No constructor, clone, deserializer or raw backend accessor is exposed.
/// The destination reader claim and original control credit close only after the
/// physical backend references. This value supplies no executable authority.
pub struct CampaignArchiveExecutionPossession {
    receipt: CampaignArchiveDurabilityReceipt,
    source: Arc<dyn ImmutableBlobBackend>,
    destination: Arc<dyn ImmutableBlobBackend>,
    namespace: CampaignHash,
    _archive: CampaignArchiveLease,
    _credit: crucible_store::owned_decode::DecodeScratch,
}

impl CampaignArchiveExecutionPossession {
    pub(crate) fn verify_binding(
        &self,
        source: &Arc<dyn ImmutableBlobBackend>,
        destination: &Arc<dyn ImmutableBlobBackend>,
        archive: CampaignArchiveManifestId,
        namespace: CampaignHash,
        required_placements: u64,
    ) -> bool {
        Arc::ptr_eq(&self.source, source)
            && Arc::ptr_eq(&self.destination, destination)
            && self.receipt.manifest() == archive
            && self.namespace == namespace
            && !self.receipt.requirement().allows_deferred_write()
            && u64::from(self.receipt.requirement().minimum_durable_placements())
                >= required_placements
            && u64::from(self.receipt.transfer().minimum_observed_durable_placements)
                >= required_placements
    }

    #[cfg(test)]
    pub(crate) fn recorded_transfer(&self) -> CampaignArchiveTransferReport {
        self.receipt.transfer()
    }

    pub(crate) fn publication(&self) -> CampaignHash {
        CampaignHash::from_bytes(self.receipt.operation.0)
    }
}

/// Copies and publishes an archive while retaining actual execution prerequisites.
///
/// Uses the ordinary durable-copy implementation and both original repository
/// accounts. The destination namespace declaration is bound under
/// `crucible.executor.receiver-storage-namespace.v1`; it is not a cross-host
/// principal certificate. The resulting owner must remain with the stopped
/// receiving World through source release, destination commit or abort.
///
/// # Errors
/// Refuses missing original metadata authority, unavailable GC exclusion,
/// failed archive copy/publication, or any original operational boundary.
/// Existing source/destination journals retain their ordinary failure rules.
// crucible-lint: allow rust-allow -- archive transfer inputs preserve both endpoints, exact publication intent, durability and the original boundary.
#[allow(clippy::too_many_arguments)]
pub fn transfer_campaign_archive_for_execution_with_boundary(
    source: &mut CampaignArchiveTransferEndpoint<'_>,
    destination: &mut CampaignArchiveTransferEndpoint<'_>,
    plan: &CampaignArchivePlan,
    archive_name: &str,
    campaign_name: Option<&str>,
    destination_durability: DurabilityRequirement,
    boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
) -> Result<CampaignArchiveExecutionPossession, CampaignArchiveTransferError> {
    boundary().map_err(CampaignRepositoryError::Ram)?;
    if plan.manifest().policy() != crucible_campaign::CampaignArchivePolicy::Executable {
        return Err(CampaignRepositoryError::Store(StoreError::Unsupported {
            capability: "archive-execution-possession-executable-policy",
        })
        .into());
    }

    let original =
        destination
            .repository
            .ram_admission()
            .original()
            .ok_or(CampaignRepositoryError::Store(StoreError::Unsupported {
                capability: "archive-execution-possession-original",
            }))?;
    let credit = original
        .reserve_scratch_bytes(std::mem::size_of::<CampaignArchiveExecutionPossession>() as u64)
        .map_err(|source| {
            CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                original, source,
            ))
        })?;
    let source_backend = source.repository.blob_backend();
    let destination_backend = destination.repository.blob_backend();
    let namespace = CampaignHash::derive(
        "crucible.executor.receiver-storage-namespace.v1",
        destination.identity.as_bytes(),
    );
    let receipt = transfer_campaign_archive_durably_with_boundary(
        source,
        destination,
        plan,
        archive_name,
        campaign_name,
        destination_durability,
        boundary,
    )?;
    let archive = destination
        .repository
        .retain_campaign_archive_ref_with_boundary(archive_name, plan.manifest_id(), boundary)?;
    let possession = CampaignArchiveExecutionPossession {
        receipt,
        source: source_backend,
        destination: destination_backend,
        namespace,
        _archive: archive,
        _credit: credit,
    };
    boundary().map_err(CampaignRepositoryError::Ram)?;
    Ok(possession)
}
