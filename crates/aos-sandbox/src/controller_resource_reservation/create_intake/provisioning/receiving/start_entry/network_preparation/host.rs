//! Retains the Host pair within the existing finite prepared-request owner.
//!
//! The projection accepts only sole-decoded models bound to the three genuine
//! disposed Root completions. Both signing borrows rejoin the same Host Root
//! construction turn; a signed Guardian artifact cannot enter another purpose.

use super::*;
use aos_sandbox_protocol::{
    ValidatedDestinationSlotInventory, ValidatedNetworkInventory, ValidatedStorageInventory,
    authenticated_session::all_methods::outcome_capture::CapturedBrokerMethodModelDataV2 as Model,
    authorization_artifact::{HostLaunchPlanPreparationDataV2, ReturnedSignature},
    authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
    mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1,
};
use aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse;
use crate::normal_root::RootStartResourceCompletedOriginalV2;

/// Keeps resource and Host normalization in one closed prepared family.
pub(super) enum NormalizedStartResourceV2 {
    Resource(StartResourcePlanPreparationDataV1),
    Host(HostLaunchPlanPreparationDataV2),
}

impl NormalizedStartResourceV2 {
    pub(super) fn preparation_v2(&self) -> &BrokerPlanPreparation {
        match self {
            Self::Resource(resource) => &resource.preparation,
            Self::Host(pair) => &pair.host,
        }
    }

    pub(super) fn header_v2(&self) -> &StartResourceRequestHeaderDataV2 {
        match self {
            Self::Resource(resource) => &resource.request_header,
            Self::Host(pair) => &pair.request_header,
        }
    }

    pub(super) fn resource_body_v2(&self) -> Option<&[u8]> {
        match self {
            Self::Resource(resource) => Some(&resource.request_body),
            Self::Host(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Catalog,
    Geometry,
    Funding,
    Body,
    Guardian,
}

/// Holds the actual projection, companion and all reached pure results inline.
pub(super) struct HostPreparedOriginalV2 {
    pub(super) catalog: crate::StartHostCatalogProjectionOriginalV2,
    pub(super) body: Option<Result<Vec<u8>, Cause>>,
    pub(super) guardian: Option<SignedBrokerPlan>,
    pub(super) live_body: Option<Result<Vec<u8>, Cause>>,
    pub(super) io_receiving: Option<ResourceVector>,
    pub(super) demand: Option<Result<ResourceVector, Cause>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    guardian_check: Option<Result<SignedBrokerPlan, Cause>>,
    first: Option<First>,
}

impl HostPreparedOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            catalog: crate::StartHostCatalogProjectionOriginalV2::new(),
            body: None,
            guardian: None,
            live_body: None,
            io_receiving: None,
            demand: None,
            funding: None,
            guardian_check: None,
            first: None,
        }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            Some(First::Catalog) => self.catalog.failure_v2(),
            Some(First::Geometry) => self.demand.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            Some(First::Funding) => error(&self.funding),
            Some(First::Body) => self.body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            Some(First::Guardian) => self.guardian_check.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            None => self.live_body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
        }
    }
}

impl PreparedStartResourceRequestOriginalV2 {
    /// Projects and encodes the Host request from the genuine completed resources.
    ///
    /// The caller retains this same owner through the independently owed native
    /// content post. No external catalog, UID mapping or decoded model tuple is
    /// accepted as publication or launch authority.
    ///
    /// # Errors
    /// Retains a changed current loan, completed packet association, projection,
    /// receiving demand, payment or canonical Host encoding failure.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_host_content_once_v2(
        &mut self,
        original: &mut OriginalStartHostRootLoanV1<'_, '_>,
        controller: &mut Journal,
        network_done: &RootStartResourceCompletedOriginalV2,
        storage_done: &RootStartResourceCompletedOriginalV2,
        mount_done: &RootStartResourceCompletedOriginalV2,
        network: &Model<ValidatedNetworkInventory>,
        storage: &Model<(ValidatedStorageInventory, InventoryStorageResourcesResponse)>,
        namespace: &Model<ValidatedAttachmentAnchorResourceV1>,
        destinations: &Model<ValidatedDestinationSlotInventory>,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.purpose != Purpose::HostLaunch || self.parent.is_some() || self.first.is_some() {
            self.first.get_or_insert(super::First::Reentry);
            return Err(CLOSED);
        }
        self.parent = Some(original.parent_operation_v1());
        let projected = self.host.catalog.prepare_once_v2(original, controller,
            network_done, storage_done, mount_done, network, storage, namespace, destinations);
        if projected.is_err() {
            self.original_selected = self.host.catalog.has_selected_original_failure_v2();
            self.host.first = Some(First::Catalog);
            self.first = Some(super::First::Host);
            return Err(CLOSED);
        }

        let (manifest, specification) = original.start_assignment_v2(controller).map_err(|_| CLOSED)?;
        self.host.demand = Some(aos_sandbox_protocol::authorization_artifact::
            start_host_launch_request_receiving_demand_v2(manifest,
                specification.spec().resource_profile()));
        let Some(Ok(demand)) = self.host.demand.as_ref() else {
            self.host.first = Some(First::Geometry);
            self.first = Some(super::First::Host);
            return Err(CLOSED);
        };
        self.specification_bytes = Some(specification.canonical_bytes().len());
        let demand = *demand;
        self.host.funding = Some((|| {
            let returned = original.require_complete_v1(controller, demand);
            self.original_selected = returned.is_err() && original.failure_v1().is_some();
            returned
        })());
        if !matches!(self.host.funding, Some(Ok(()))) {
            self.host.first = Some(First::Funding);
            self.first = Some(super::First::Host);
            return Err(CLOSED);
        }
        self.content_funding = Some(Ok(()));
        self.host.body = Some((|| -> Result<_, Cause> {
            let (manifest, specification) = original.start_assignment_v2(controller)?;
            aos_sandbox_protocol::authorization_artifact::start_host_launch_request_body_data_v2(
                manifest, specification.spec().resource_profile(),
                self.host.catalog.catalog_data_v2(original, controller)?,
                original.parent_operation_v1().into_bytes(),
            )
        })());
        if !matches!(self.host.body, Some(Ok(_))) {
            self.host.first = Some(First::Body);
            self.first = Some(super::First::Host);
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Borrows the canonical Guardian preparation under the same live Root turn.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete pair, changed Root reply or native
    /// construction turn. The borrowed preparation alone issues no signature.
    #[doc(hidden)]
    pub fn guardian_signing_preparation_v2<'held>(
        &'held self,
        admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &RootStartResourceConstructionTurnV2<'_>,
        original: &OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<&'held BrokerPlanPreparation, PreparedStartResourceRequestClosedV2> {
        self.signing_preparation_v2(admission, construction, original, controller)?;
        match self.normalization.as_ref().and_then(|value| value.as_ref().ok()) {
            Some(NormalizedStartResourceV2::Host(pair)) if self.purpose == Purpose::HostLaunch => {
                Ok(&pair.guardian)
            }
            _ => Err(CLOSED),
        }
    }

    /// Retains the actual Guardian signature before the primary Host artifact.
    ///
    /// # Errors
    /// Retains changed pair/currentness, final clock, signature or repeated entry.
    #[doc(hidden)]
    pub fn retain_guardian_signed_once_v2(
        &mut self,
        signed: &SignedBrokerPlan,
        admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &RootStartResourceConstructionTurnV2<'_>,
        original: &OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.purpose != Purpose::HostLaunch || self.host.guardian_check.is_some()
            || self.signed_check.is_some() || self.first.is_some()
        {
            self.first.get_or_insert(super::First::Reentry);
            return Err(CLOSED);
        }
        self.host.guardian_check = Some((|| -> Result<_, Cause> {
            construction.require_admission_v2(admission, original, controller, true)?;
            let preparation = self.guardian_signing_preparation_v2(
                admission, construction, original, controller)?;
            if signed.canonical_plan() != preparation.canonical_plan()
                || signed.plan() != preparation.plan_data_v1()
            {
                return Err(Box::new(CLOSED));
            }
            let sample = construction.actual_before_clock_v2()?;
            Ok(preparation.clone().complete(ReturnedSignature::Envelope(
                signed.canonical_signature()), sample.wall_seconds())?)
        })());
        let Some(Ok(verified)) = self.host.guardian_check.as_ref() else {
            self.host.first = Some(First::Guardian);
            self.first = Some(super::First::Host);
            return Err(CLOSED);
        };
        // Both live artifacts coexist through Core construction and final posts;
        // the pair normalization supplier includes their actual encoded backing.
        self.host.guardian = Some(verified.clone());
        Ok(())
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Enters Host content only after the genuine three-resource disposition.
    ///
    /// The exact Mount predecessor is checked before advancing C. Projection
    /// independently joins all three completed owners and their opaque models.
    ///
    /// # Errors
    /// Retains incomplete disposition, native entry, projection or owed-post failure.
    #[doc(hidden)]
    pub fn begin_host_content_once_v2(
        &mut self,
        prepared: &PreparedStartResourceRequestOriginalV2,
        intake: &crate::CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        mount_done: &RootStartResourceCompletedOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        let kind = resource_state::StartResourceKindV2::Host;
        if self.failure().is_some() || self.resource_entries.host.predecessor.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.resource_entries.host.predecessor = Some((|| {
            mount_done.require_mount_disposition_v2(self, controller)?;
            if self.native_state.as_ref().is_none_or(|state|
                state.resources.mount.completed_resident.is_none())
            {
                return Err(crate::normal_root::RootHostLaunchClientClosedV1);
            }
            Ok(())
        })());
        if !matches!(self.resource_entries.host.predecessor, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.begin_resource_content_once_v2(kind, prepared, intake, controller, source)
    }

    /// Retains the actual Host body and always observes its entered C post.
    ///
    /// The Runtime borrows the opaque SDK models and constructs the body under
    /// the newly entered current loan between begin and finish. This method
    /// inspects that same paid prepared owner; a supplied Result cannot declare
    /// construction complete. It also closes an entered interval after an SDK
    /// model-borrow refusal, while the Runtime retains that earlier original.
    ///
    /// # Errors
    /// Retains missing/failed actual content, changed owner or an owed native post.
    #[doc(hidden)]
    pub fn finish_host_content_once_v2(
        &mut self,
        prepared: &mut PreparedStartResourceRequestOriginalV2,
        intake: &crate::CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let kind = resource_state::StartResourceKindV2::Host;
        let content = &self.resource_entries.host.content;
        if content.after.is_some() || content.body.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if matches!(content.next, Some(Ok(()))) {
            let body = match self.borrow_host_root_v1(intake, controller, source) {
                Ok(original) => prepared.require_host_content_body_v2(&original, controller)
                    .map_err(ContentEntryFailureV2::Preparation),
                Err(cause) => Err(ContentEntryFailureV2::Loan(cause)),
            };
            self.resource_entries.host.content.body = Some(body);
            self.resource_entries.host.content.selected_preparation = self.resource_entries.host.content.body
                .as_ref().is_some_and(Result::is_err) && prepared.failure().is_some();
            self.resource_entries.host.content.selected_native = prepared.original_selected;
        }
        self.finish_resource_content_once_v2(kind, prepared, controller)
    }

    /// Selects the actual Host prepared cause before later native posts.
    #[doc(hidden)]
    #[must_use]
    pub fn host_content_failure_is_selected_v2(&self) -> bool {
        self.resource_entries.host.content.selected_preparation
            && !self.resource_entries.host.content.selected_native
    }
}

impl PreparedStartResourceRequestOriginalV2 {
    /// Borrows the same qualified catalog after the signed pair's native posts.
    ///
    /// The actual Catalog6 issuer additionally checks its private pending2 and
    /// Root stage. This borrowed projection supplies no publication permission.
    ///
    /// # Errors
    /// Refuses incomplete signing/posts, another purpose/parent or changed loan.
    pub(crate) fn host_catalog_projection_v2<'held>(&'held self,
        original: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<&'held crate::StartHostCatalogProjectionOriginalV2, PreparedStartResourceRequestClosedV2> {
        self.require_completed_v2()?;
        if self.purpose != Purpose::HostLaunch || self.host.guardian.is_none()
            || !matches!(self.host.live_body, Some(Ok(_)))
            || self.parent != Some(original.parent_operation_v1())
        {
            return Err(CLOSED);
        }
        original.require_current_v1(controller).map_err(|_| CLOSED)?;
        self.host.catalog.catalog_data_v2(original, controller).map_err(|_| CLOSED)?;
        Ok(&self.host.catalog)
    }
}

impl PreparedStartResourceRequestOriginalV2 {
    /// Constructs the distinct private child inside the paired signing interval.
    ///
    /// # Errors
    /// Retains incomplete pair/signing, changed Root/current C, model funding or
    /// canonical publication construction. No Core row is written here.
    #[doc(hidden)]
    pub fn construct_host_publication_once_v2(&mut self,
        original: &mut OriginalStartHostRootLoanV1<'_, '_>,
        controller: &mut Journal,
        admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &RootStartResourceConstructionTurnV2<'_>,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.purpose != Purpose::HostLaunch || self.first.is_some()
            || !matches!(self.host.live_body, Some(Ok(_)))
        {
            self.first.get_or_insert(super::First::Reentry);
            return Err(CLOSED);
        }
        let pair = match self.normalization.as_ref().and_then(|value| value.as_ref().ok()) {
            Some(NormalizedStartResourceV2::Host(pair)) => pair,
            _ => return Err(CLOSED),
        };
        let host = self.signed.as_ref().ok_or(CLOSED)?;
        let guardian = self.host.guardian.as_ref().ok_or(CLOSED)?;
        let body = self.host.body.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        let returned = self.publication.construct_once_v2(original, controller,
            admission, construction, &self.host.catalog, body, &pair.host, &pair.guardian,
            host, guardian);
        if returned.is_err() {
            self.original_selected = self.publication.original_selected_v2();
            self.first = Some(super::First::Publication);
            return Err(CLOSED);
        }
        Ok(())
    }
}

impl PreparedStartResourceRequestOriginalV2 {
    /// Prices the new request-time model copy beside the surviving signed pair.
    ///
    /// The same source-owned Host normalization supplier covers canonical
    /// template/companion, plan/signature and envelope parsing. The retained
    /// pair already contributes through its separate native resident plane;
    /// this bound covers the new simultaneously live request representation.
    pub(crate) fn host_request_receiving_demand_v2(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.purpose != Purpose::HostLaunch {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.host.io_receiving.ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl PreparedStartResourceRequestOriginalV2 {
    fn require_host_content_body_v2(&self,
        original: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.purpose != Purpose::HostLaunch || self.first.is_some()
            || self.parent != Some(original.parent_operation_v1())
            || !matches!(self.host.body, Some(Ok(_)))
            || !matches!(self.host.funding, Some(Ok(())))
        {
            return Err(CLOSED);
        }
        original.require_current_v1(controller).map_err(|_| CLOSED)?;
        self.host.catalog.catalog_data_v2(original, controller).map_err(|_| CLOSED)?;
        Ok(())
    }
}
