//! Executes real signed26 while the same exclusive Storage Session stays held.
//!
//! The one upper borrower owns the entered C17 interval. SDK failure closes its
//! primary before C/Root afters; only full success retires the Session window.

use super::*;
use aos_sandbox_broker_session_security::controller_composition::{
    DeleteStoragePreparationSessionIoOriginalV3, OutputPreparationClosedV1,
};

use super::storage_flight::{ActualFlight, First, FlightState};

#[derive(Debug, thiserror::Error)]
enum CatalogErrorV3 {
    #[error(transparent)]
    Session(#[from] OutputPreparationClosedV1),
    #[error(transparent)]
    Binding(#[from] aos_sandbox_protocol::semantics::StorageSemanticsError),
    #[error("the actual completed Storage catalog digest has the wrong fixed width")]
    Digest,
}

#[derive(Default)]
pub(super) struct ControllerDeleteStoragePreparationOriginalV3 {
    sdk: DeleteStoragePreparationSessionIoOriginalV3,
    flight: FlightState,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    catalog: Option<Result<aos_sandbox_protocol::semantics::CatalogBindingV1, CatalogErrorV3>>,
}

impl ControllerDeleteStoragePreparationOriginalV3 {
    pub(super) fn sdk_v3(&self) -> Result<&DeleteStoragePreparationSessionIoOriginalV3, ResourceReservationErrorV1> {
        if self.flight.first.is_some() || !matches!(self.flight.complete, Some(Ok(())))
            || !matches!(self.current, Some(Ok(()))) || !matches!(self.catalog, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.sdk.require_completed_v3().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(&self.sdk)
    }

    pub(super) fn failed(&self) -> bool {
        self.flight.first.is_some()
    }

    pub(super) fn original_selected(&self) -> bool {
        self.flight.original_selected(self.sdk.original_failure_selected_v3())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.flight.first? {
            First::Sdk | First::Retirement => self.sdk.failure_v3(),
            First::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Catalog => self.catalog.as_ref()?.as_ref().err().map(|cause| cause as _),
            _ => self.flight.failure(),
        }
    }
}

impl ControllerDeletePlanningCollectionV2<'_, '_, '_> {
    pub(super) fn prepare_storage_catalog_once_v3(
        &mut self,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.storage_preparation;
        if state.flight.started {
            state.flight.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.flight.started = true;
        let cut = session_preimage_from_originals_v2(&self.fresh_sessions, &self.fresh_models, 2)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let answer = self.fresh_sessions[2]
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let storage = self
            .session_writers
            .storage
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let shape = bank
            .retained_delete_preparation_request_bound_v3(client)
            .and_then(|bound| storage.delete_preparation_shape_v3(bound))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let entered = bank.borrow_retained_delete_storage_preparation_once_v3(
            pending, client, controller, profile, cut, shape,
        );
        let mut loan = match entered {
            Ok(loan) => {
                state.flight.entry = Some(Ok(()));
                loan
            }
            Err(cause) => {
                state.flight.entry = Some(Err(cause));
                state.flight.first = Some(First::Entry);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let mut flight = PreparationFlight { storage, sdk: &mut state.sdk, loan: &mut loan, answer };
        state.flight.run_once(&mut flight);
        drop(flight);
        if state.flight.first.is_none() {
            state.catalog = Some((|| {
                // This is the same successful decoder's response. Its catalog
                // is comparison DATA until Root independently reads/verifies
                // this exact Session successor before it can issue Destroy7.
                let response = state.sdk.completed_preparation_response_data_v3()?;
                let digest = response.catalog_digest.as_slice().try_into()
                    .map_err(|_| CatalogErrorV3::Digest)?;
                Ok(aos_sandbox_protocol::semantics::CatalogBindingV1::from_publisher(
                    response.catalog_generation, aos_sandbox_core::ObjectDigest::from_bytes(digest))?)
            })());
            if !matches!(state.catalog, Some(Ok(_))) { state.flight.first = Some(First::Catalog); }
        }
        if state.flight.first.is_none() {
            state.current = Some(loan.send_completed_preparation_current_once_v3());
            if !matches!(state.current, Some(Ok(()))) { state.flight.first = Some(First::Current); }
        }
        if state.flight.first.is_none() {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}

struct PreparationFlight<'borrow, 'held> {
    storage: &'borrow mut crate::DormantStorageLifecycleInventoryOwnerV1,
    sdk: &'borrow mut DeleteStoragePreparationSessionIoOriginalV3,
    loan: &'borrow mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'held>,
    answer: &'borrow DeleteInventoryAnswerOriginalsV1,
}

impl ActualFlight for PreparationFlight<'_, '_> {
    fn run(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.storage.run_delete_storage_preparation_once_v3(self.sdk, self.loan, self.answer)
    }

    fn refuse_sdk(&mut self) { self.loan.refuse_sdk_primary_v3(); }

    fn after(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.finish_after_sdk_once_v3()
    }

    fn retire(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.storage.retire_delete_storage_preparation_window_once_v3(self.sdk, self.loan)
    }

    fn complete(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.loan.complete_preparation_once_v3()
    }
}
