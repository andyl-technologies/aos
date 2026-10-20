//! Projects the Host catalog from the same completed three-resource Start.
//!
//! The private-issued Protocol model wrappers bind each sole-decoded model to
//! its original packet. The genuine Root completions and disposed SDK markers
//! authenticate that packet association; the NEW Host loan supplies current C,
//! Source, Start, assignment and original horizon. Projection is not publication.

use super::*;
use aos_sandbox_protocol::{HostCatalogSnapshot, HostCatalogSnapshotError,
    ValidatedNetworkInventory, ValidatedStorageInventory, ValidatedDestinationSlotInventory,
    authenticated_session::all_methods::outcome_capture::CapturedBrokerMethodModelDataV2 as Model,
    mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1,
    domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 as Purpose};
use aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse;
use crate::host_catalog_reconciliation::{self as projection, HostCatalogReconciliationError};
use crate::normal_root::RootStartResourceCompletedOriginalV2;

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;

/// Reports an incomplete/refused projection while retaining its actual cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Start Host catalog projection is incomplete or refused")]
#[doc(hidden)]
pub struct StartHostCatalogProjectionClosedV2;

#[derive(Clone, Copy)]
enum First { Entry, Models, Geometry, Funding, Projection, EncodingGeometry, EncodingFunding, Encoding, Reentry }

/// Retains one current Start's exact catalog projection and all reached Results.
///
/// It creates no installed catalog, pending mutation, Host plan or effect grant.
/// A Root signer must independently recompute this same complete projection.
#[doc(hidden)]
pub struct StartHostCatalogProjectionOriginalV2 {
    entered: bool,
    first: Option<First>,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    entry: [Option<Result<[u8; 32], crate::normal_root::RootHostLaunchClientClosedV1>>; 3],
    models: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    projected: Option<Result<HostCatalogSnapshot, HostCatalogReconciliationError>>,
    encoding_geometry: Option<Result<usize, HostCatalogSnapshotError>>,
    encoding_funding: Option<Result<(), ResourceReservationErrorV1>>,
    encoded: Option<Result<Vec<u8>, HostCatalogSnapshotError>>,
    identity: Option<Arc<()>>,
    parent: Option<OperationId>,
    resident: ResourceVector,
    inventory_packet_digests: Option<[[u8; 32]; 4]>,
    original_selected: bool,
}

impl StartHostCatalogProjectionOriginalV2 {
    /// Creates inert result destinations without native work or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self { entered: false, first: None, current: None, entry: [None, None, None], models: None,
            geometry: None, funding: None, projected: None, encoding_geometry: None,
            encoding_funding: None, encoded: None, identity: None, parent: None,
            resident: ResourceVector::ZERO, inventory_packet_digests: None, original_selected: false }
    }

    /// Projects only genuine completed resources under the new current Host loan.
    ///
    /// Opaque model values are privately issued by the sole Protocol captures;
    /// each exact packet hash must match the intrinsic completed Root exchange.
    /// All C/history/model/encoding growth is paid before its reached frontier.
    ///
    /// # Errors
    /// Retains changed native/proof/model association, geometry, financial,
    /// complete history, resource, UID allocation or canonical encoding refusal.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_once_v2(
        &mut self, loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &mut Journal,
        network_done: &RootStartResourceCompletedOriginalV2,
        storage_done: &RootStartResourceCompletedOriginalV2,
        mount_done: &RootStartResourceCompletedOriginalV2,
        network: &Model<ValidatedNetworkInventory>,
        storage: &Model<(ValidatedStorageInventory, InventoryStorageResourcesResponse)>,
        namespace: &Model<ValidatedAttachmentAnchorResourceV1>,
        destinations: &Model<ValidatedDestinationSlotInventory>,
    ) -> Result<(), StartHostCatalogProjectionClosedV2> {
        if self.entered || loan.native.resources.host_catalog_entered {
            self.first.get_or_insert(First::Reentry);
            return Err(StartHostCatalogProjectionClosedV2);
        }
        self.entered = true;
        loan.native.resources.host_catalog_entered = true;
        self.current = Some(loan.require_current_v1(controller));
        if !matches!(self.current, Some(Ok(()))) {
            self.original_selected = loan.failure_v1().is_some();
            self.first = Some(First::Entry);
            return Err(StartHostCatalogProjectionClosedV2);
        }
        // Each completion checks its own exact historical disposed turn and
        // identity while the same NEW loan checks actual current C and Source.
        for (index, completed) in [network_done, storage_done, mount_done].into_iter().enumerate() {
            self.entry[index] = Some(completed.completed_model_association_v2(loan, controller));
            if !matches!(self.entry[index], Some(Ok(_))) {
                self.first = Some(First::Entry);
                return Err(StartHostCatalogProjectionClosedV2);
            }
        }
        self.models = Some((|| {
            let packets = [network_done.comparison_data_v2(), storage_done.comparison_data_v2(),
                mount_done.comparison_data_v2()];
            if packets[0].binding.purpose != Purpose::NetworkPrepare.into()
                || packets[1].binding.purpose != Purpose::StorageGuestRoot.into()
                || packets[2].binding.purpose != Purpose::MountNamespace.into()
                || !network.matches_outcome_packet_data_v2(packets[0].inventory_outcome)
                || !storage.matches_outcome_packet_data_v2(packets[1].inventory_outcome)
                || !namespace.matches_outcome_packet_data_v2(packets[2].resource_outcome)
                || !destinations.matches_outcome_packet_data_v2(packets[2].inventory_outcome)
            { return Err(CLOSED); }
            Ok(())
        })());
        if !matches!(self.models, Some(Ok(()))) {
            self.first = Some(First::Models);
            return Err(StartHostCatalogProjectionClosedV2);
        }
        // Preserve the exact checked source packets for the paid publication
        // record. Digests are comparison DATA and cannot reconstruct a model.
        self.inventory_packet_digests = Some([
            storage.outcome_packet_digest_data_v2(),
            network.outcome_packet_digest_data_v2(),
            namespace.outcome_packet_digest_data_v2(),
            destinations.outcome_packet_digest_data_v2(),
        ]);
        let storage = &storage.model_data_v2().0;
        let network = network.model_data_v2();
        let destinations = destinations.model_data_v2();
        self.geometry = Some((|| {
            let bytes = size_of::<Self>().checked_mul(2).ok_or(CLOSED)?;
            projection::start_projection_receiving_demand_data_v2(controller, storage, network, destinations)
                .map_err(ResourceReservationErrorV1::Journal)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                    u64::try_from(bytes).map_err(|_| CLOSED)?)).map_err(Into::into)
        })());
        let Some(Ok(demand)) = self.geometry.as_ref() else {
            self.first = Some(First::Geometry);
            return Err(StartHostCatalogProjectionClosedV2);
        };
        self.resident = *demand;
        self.funding = Some(loan.require_complete_v1(controller, *demand));
        if !matches!(self.funding, Some(Ok(()))) {
            self.original_selected = loan.failure_v1().is_some();
            self.first = Some(First::Funding);
            return Err(StartHostCatalogProjectionClosedV2);
        }
        // Retain this paid prefix in every later stage, including independent
        // posts after a refused model fold. No failed owner is discounted.
        loan.native.resources.host_catalog_resident = self.resident;
        self.identity = Some(loan.retained_resource_identity_v2());
        self.parent = Some(loan.parent_operation_v1());
        self.projected = Some((|| {
            let (successor, spec) = loan.start_assignment_v2(controller)
                .map_err(|_| HostCatalogReconciliationError::InventoryConflict)?;
            let (predecessor, _, _) = loan.original_create_v1().publication_material_v1()
                .map_err(|_| HostCatalogReconciliationError::InventoryConflict)?;
            projection::project_start_successor_catalog_data_v2(controller, predecessor,
                successor, spec, storage, network, destinations, namespace.model_data_v2())
        })());
        let Some(Ok(catalog)) = self.projected.as_ref() else {
            self.first = Some(First::Projection);
            return Err(StartHostCatalogProjectionClosedV2);
        };
        self.encoding_geometry = Some(catalog.canonical_encoding_receiving_bytes_v2());
        let Some(Ok(bytes)) = self.encoding_geometry.as_ref() else {
            self.first = Some(First::EncodingGeometry);
            return Err(StartHostCatalogProjectionClosedV2);
        };
        self.encoding_funding = Some((|| {
            let encoding = ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(*bytes).map_err(|_| CLOSED)?);
            let complete = self.resident.checked_add(encoding)?;
            // The prior projection prefix already contributes through the
            // same native resource resident sum; add only new encoded backing.
            loan.require_complete_v1(controller, encoding)?;
            self.resident = complete;
            loan.native.resources.host_catalog_resident = complete;
            Ok(())
        })());
        if !matches!(self.encoding_funding, Some(Ok(()))) {
            self.original_selected = loan.failure_v1().is_some();
            self.first = Some(First::EncodingFunding);
            return Err(StartHostCatalogProjectionClosedV2);
        }
        self.encoded = Some(catalog.encode());
        if !matches!(self.encoded, Some(Ok(_))) {
            self.first = Some(First::Encoding);
            return Err(StartHostCatalogProjectionClosedV2);
        }
        // Every subsequent actual Start stage includes this surviving payload.
        // This changes no Core debit, traffic, capacity or historical highwater.
        loan.native.resources.host_catalog_resident = self.resident;
        Ok(())
    }

    fn require_same_v2(&self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal)
        -> Result<(), StartHostCatalogProjectionClosedV2> {
        if !self.entered || self.first.is_some() || self.parent != Some(loan.parent_operation_v1())
            || self.identity.as_ref().is_none_or(|identity| !Arc::ptr_eq(identity, loan.identity))
            || loan.native.resources.host_catalog_resident != self.resident {
            return Err(StartHostCatalogProjectionClosedV2);
        }
        loan.require_current_v1(controller).map_err(|_| StartHostCatalogProjectionClosedV2)
    }

    /// Borrows exact projected DATA after rechecking the same current loan.
    ///
    /// # Errors
    /// Refuses incomplete projection, reentry, foreign identity or changed loan.
    pub fn catalog_data_v2<'held>(&'held self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal)
        -> Result<&'held HostCatalogSnapshot, StartHostCatalogProjectionClosedV2> {
        self.require_same_v2(loan, controller)?;
        self.projected.as_ref().and_then(|value| value.as_ref().ok()).ok_or(StartHostCatalogProjectionClosedV2)
    }

    /// Borrows the same paid canonical bytes; no installed publication is implied.
    ///
    /// # Errors
    /// Refuses a changed current loan or any incomplete projection/encoding.
    pub fn canonical_catalog_data_v2<'held>(&'held self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal)
        -> Result<&'held [u8], StartHostCatalogProjectionClosedV2> {
        self.require_same_v2(loan, controller)?;
        self.encoded.as_ref().and_then(|value| value.as_ref().ok()).map(Vec::as_slice)
            .ok_or(StartHostCatalogProjectionClosedV2)
    }

    /// Lends only the four exact packets already joined to actual completions.
    ///
    /// These digests populate the existing publication record; they confer no
    /// inventory, currentness, publication or Host authority.
    pub(crate) fn source_comparison_data_v2(
        &self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<[[u8; 32]; 4], StartHostCatalogProjectionClosedV2> {
        self.require_same_v2(loan, controller)?;
        self.inventory_packet_digests.ok_or(StartHostCatalogProjectionClosedV2)
    }

    /// Borrows the actual first reached failure without replacing its source.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Entry => cause(&self.current).or_else(|| self.entry.iter().find_map(cause)),
            First::Models => cause(&self.models),
            First::Geometry => cause(&self.geometry),
            First::Funding => cause(&self.funding),
            First::Projection => cause(&self.projected),
            First::EncodingGeometry => cause(&self.encoding_geometry),
            First::EncodingFunding => cause(&self.encoding_funding),
            First::Encoding => cause(&self.encoded),
            First::Reentry => Some(&CLOSED),
        }
    }

    /// Identifies only the selected real native/financial refusal before posts.
    #[must_use]
    pub const fn has_selected_original_failure_v2(&self) -> bool { self.original_selected }
}

impl Default for StartHostCatalogProjectionOriginalV2 {
    fn default() -> Self { Self::new() }
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    pub(crate) fn require_disposed_resource_models_v2(&self, parent: OperationId, turn: u64,
        identity: &Arc<()>, profile: &Arc<ProductionControllerNormalRootProfileV1>, purpose: Purpose,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        if parent != self.parent_operation_v1() || !Arc::ptr_eq(identity, self.identity)
            || !Arc::ptr_eq(profile, &self.native.profile) { return Err(CLOSED); }
        let kind = match purpose {
            Purpose::NetworkPrepare => resource_state::StartResourceKindV2::Network,
            Purpose::StorageGuestRoot => resource_state::StartResourceKindV2::Storage,
            Purpose::MountNamespace => resource_state::StartResourceKindV2::Mount,
            Purpose::HostLaunch => return Err(CLOSED),
        };
        let member = self.native.resources.member_v2(kind);
        if member.completed_model_turn != Some(turn) || member.completed_resident.is_none() {
            return Err(CLOSED);
        }
        Ok(())
    }
}
