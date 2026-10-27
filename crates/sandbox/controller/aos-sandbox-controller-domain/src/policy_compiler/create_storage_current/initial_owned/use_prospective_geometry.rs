//! Calculates the unsigned future Controller proposal from completed Root DATA.
//!
//! The genuine prepared borrower supplies these dimensions from its completed
//! Controller, Source, Cache and Ownership owners. The proposal does not pay
//! Root's local append or authorize Controller Use. Controller independently
//! recomputes the complete amount before its real reservation.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::RootInitialUseProspectiveInputsDataV1;
use aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1;
use aos_sandbox_policy::storage_session_geometry_data::StorageSessionGeometryRefusalV1;

use crate::controller_resource_reservation::CreateStorageCacheCurrentExtentsDataV1;
use crate::journal::JournalError;
use crate::journal::broker_session_receiving::storage_create_use_receiving_demand_v1;

/// Retains the old Source extent cause separately from receiving refusal.
#[derive(Debug, thiserror::Error)]
pub(super) enum RootUseProspectiveGeometryErrorV1 {
    /// The completed Cache snapshot has invalid bounded extent DATA.
    #[error("the completed Cache snapshot has invalid replay geometry")]
    History,
    /// The original Source extent calculation returned this actual cause.
    #[error(transparent)]
    Source(JournalError),
    /// The complete future Controller receiving calculation refused.
    #[error(transparent)]
    Receiving(StorageSessionGeometryRefusalV1),
}

/// Calculates comparison DATA with the existing complete Controller programme.
///
/// The caller must retain this whole returned outcome before entering the
/// native proposal method. A Source failure remains this upper owner's cause;
/// only the nonissuing unit refusal is passed to the native receiving slot.
///
/// # Errors
/// Refuses malformed Cache extent DATA, preserves the actual Source extent
/// error, or reports the existing complete receiving recipe's checked refusal.
pub(super) fn receiving_demand_v1(
    inputs: RootInitialUseProspectiveInputsDataV1<'_>,
    private: StorageCreateUseSecurityShapeDataV1,
) -> Result<ResourceVector, RootUseProspectiveGeometryErrorV1> {
    use RootUseProspectiveGeometryErrorV1 as E;

    // Cache and Source preserve the old produce_inner calculation order.
    let cache = CreateStorageCacheCurrentExtentsDataV1::from_current_snapshot_v1(
        inputs.cache_snapshot,
    ).map_err(|_| E::History)?;
    let source = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        crate::source_domain::source_domain_journal_limits(), inputs.source_end,
    ).map_err(E::Source)?;

    // These are the same already-positive passive extents held by Controller
    // readonly. Reconstructing the upper representation grants no native loan.
    let session = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        inputs.session_limits, inputs.session_native_bytes,
    ).map_err(|_| E::Receiving(StorageSessionGeometryRefusalV1))?;
    let controller = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        inputs.controller_limits, inputs.controller_native_bytes,
    ).map_err(|_| E::Receiving(StorageSessionGeometryRefusalV1))?;

    storage_create_use_receiving_demand_v1(
        &session, inputs.request_shape_bytes, &controller, &source,
        cache.extents_v1(), private,
    ).map_err(E::Receiving)
}
