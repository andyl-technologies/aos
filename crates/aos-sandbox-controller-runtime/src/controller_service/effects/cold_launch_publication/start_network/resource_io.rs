//! Drives each resource request and fresh inventory through the same Start loan.
//!
//! Both flights retain their original signed results and native prefixes in the
//! shared SDK. C and Root posts run after the body result has been retained,
//! including a failed entry, loan, send, receive or final Session observation.

use super::*;
use aos_sandbox::StartResourceSessionPostShapeDataV2;
use aos_sandbox_broker_session_security::controller_composition::{
    StartResourceProvisioningSessionIoOriginalV4, OutputPreparationClosedV1,
};

#[derive(Debug, thiserror::Error)]
enum BodyError {
    #[error(transparent)]
    Loan(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Root(#[from] RootHostLaunchClientClosedV1),
    #[error(transparent)]
    Session(#[from] StartResourceSessionClosedV4),
    #[error(transparent)]
    Flight(#[from] OutputPreparationClosedV1),
}

#[derive(Clone, Copy)]
enum Failure {
    Shape,
    Entry,
    Body,
    Applying,
    Prepare,
    Inventory,
    Applied,
    Posts,
    Completion,
}

pub(super) struct ResourceIoV2 {
    kind: ResourceKindV2,
    flights: Box<StartResourceProvisioningSessionIoOriginalV4>,
    shape: Option<Result<StartResourceSessionPostShapeDataV2, ResourceReservationErrorV1>>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<(), BodyError>>,
    applying: Option<Result<(), ResourceReservationErrorV1>>,
    prepare: Option<Result<(), OutputPreparationClosedV1>>,
    inventory: Option<Result<(), OutputPreparationClosedV1>>,
    applied: Option<Result<(), ResourceReservationErrorV1>>,
    posts: Option<Result<(), ResourceReservationErrorV1>>,
    original_failure_selected: bool,
    first: Option<Failure>,
}

impl ResourceIoV2 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<StartResourceProvisioningSessionIoOriginalV4>(),
        ])
    }

    pub(super) fn flights_mut_v2(&mut self) -> &mut StartResourceProvisioningSessionIoOriginalV4 {
        &mut self.flights
    }

    pub(super) fn completed_v2(&self) -> bool {
        self.require_complete_v2().is_ok()
    }

    pub(super) fn completed_exchange_data_v2(&self)
        -> Result<aos_sandbox_broker_session_security::controller_composition::StartResourceSessionCompletionDataV2<'_>, OutputPreparationClosedV1>
    {
        self.require_complete_v2().map_err(|_| OutputPreparationClosedV1)?;
        self.flights.completed_exchange_data_v2()
    }

    pub(super) fn disposition_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.flights.failure()
    }

    pub(super) fn completed_models_v2(
        &self,
    ) -> Option<&aos_sandbox_broker_session_security::controller_composition::StartResourceCompletedModelsOriginalV2> {
        self.flights.completed_models_v2()
    }

    pub(super) fn dispose_completed_once_v2(&mut self,
        session: &mut StartResourceSessionOpenOriginalV4,
        opening: &mut StartResourceSessionOpeningOriginalV2,
        prepared: &mut PreparedStartResourceRequestOriginalV2,
        completed: &aos_sandbox::normal_root::RootStartResourceCompletedOriginalV2,
        entry: &mut AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), StartResourceSessionClosedV4> {
        self.require_complete_v2().map_err(|_| StartResourceSessionClosedV4)?;
        if self.kind == ResourceKindV2::Storage {
            return self.flights.dispose_completed_storage_once_v2(prepared, completed, entry, controller)
                .map_err(|_| StartResourceSessionClosedV4);
        }
        match self.kind {
            ResourceKindV2::Network => session.dispose_completed_network_once_v2(&mut self.flights, opening, prepared,
            completed, entry, controller),
            ResourceKindV2::Storage => Err(StartResourceSessionClosedV4),
            ResourceKindV2::Mount => session.dispose_completed_mount_once_v2(&mut self.flights, opening, prepared,
            completed, entry, controller),
            ResourceKindV2::Host => session.dispose_completed_host_once_v2(&mut self.flights, opening, prepared,
            completed, entry, controller),
        }
    }

    pub(super) fn new(kind: ResourceKindV2) -> Self {
        Self {
            kind,
            flights: Box::new(match kind {
            ResourceKindV2::Network => StartResourceProvisioningSessionIoOriginalV4::new(),
            ResourceKindV2::Storage => StartResourceProvisioningSessionIoOriginalV4::storage_guest_root_v2(),
            ResourceKindV2::Mount => StartResourceProvisioningSessionIoOriginalV4::mount_namespace_v2(),
            ResourceKindV2::Host => StartResourceProvisioningSessionIoOriginalV4::host_launch_v2(),
        }),
            shape: None,
            entry: None,
            body: None,
            applying: None,
            prepare: None,
            inventory: None,
            applied: None,
            posts: None,
            original_failure_selected: false,
            first: None,
        }
    }

    pub(super) fn progress_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        root: &mut RootHostLaunchClientOriginalV1,
        session: &mut StartResourceSessionOpenOriginalV4,
        opening: &StartResourceSessionOpeningOriginalV2,
        prepared: &PreparedStartResourceRequestOriginalV2,
        mut storage: Option<&mut StorageContextV2<'_>>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.posts.is_some() || self.first.is_some() {
            return self.require_complete_v2();
        }

        self.shape = Some((|| {
            use aos_sandbox_core::ResourceDimension as D;

            let demand =
                StartResourceProvisioningSessionIoOriginalV4::retained_post_receiving_demand_v4()
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
            let allowed = ResourceVector::ZERO
                .with(D::MemoryBytes, demand.get(D::MemoryBytes))
                .with(D::OpenFiles, demand.get(D::OpenFiles));
            if demand != allowed {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(StartResourceSessionPostShapeDataV2 {
                receiving_bytes: usize::try_from(demand.get(D::MemoryBytes))
                    .ok().and_then(|bytes| bytes.checked_add(
                        std::mem::size_of::<ResourceSessionV2<'static>>().checked_mul(2)?))
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                open_files: usize::try_from(demand.get(D::OpenFiles))
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?,
            })
        })());
        let Some(Ok(shape)) = self.shape.as_ref() else {
            self.first = Some(Failure::Shape);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let shape = *shape;

        self.entry = Some(match self.kind {
            ResourceKindV2::Network => entry.begin_network_io_turn_once_v2(root, intake, controller, source),
            ResourceKindV2::Storage => entry.begin_storage_io_turn_once_v2(root, intake, controller, source),
            ResourceKindV2::Mount => entry.begin_mount_io_turn_once_v2(root, intake, controller, source),
            ResourceKindV2::Host => entry.begin_host_io_turn_once_v2(root, intake, controller, source),
        });
        if matches!(self.entry, Some(Ok(()))) {
            self.body = Some((|| -> Result<(), BodyError> {
                if self.kind == ResourceKindV2::Host {
                    let current = {
                        let start = entry.borrow_host_root_v1(intake, controller, source)?;
                        root.borrow_host_current_turn_v2(&start, controller)?
                    };
                    self.applying = Some(entry.begin_host_effect_once_v2(
                        intake, controller, source, &current, prepared));
                    if !matches!(self.applying, Some(Ok(()))) {
                        self.first = Some(Failure::Applying);
                        return Err(BodyError::Loan(ResourceReservationErrorV1::Conflict));
                    }
                }
                let mut start = entry.borrow_host_root_v1(intake, controller, source)?;
                let current = match self.kind {
            ResourceKindV2::Network => root.borrow_network_current_turn_v2(&start, controller),
            ResourceKindV2::Storage => root.borrow_storage_current_turn_v2(&start, controller),
            ResourceKindV2::Mount => root.borrow_mount_current_turn_v2(&start, controller),
            ResourceKindV2::Host => root.borrow_host_current_turn_v2(&start, controller),
        }?;
                let mut io = if self.kind == ResourceKindV2::Storage {
                    let previous = storage.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?.previous;
                    start.borrow_storage_io_once_v2(&current, previous,
                        prepared, controller, shape)?
                } else {
                    let association = opening.completed_session_association_v4()
                        .ok_or(ResourceReservationErrorV1::Conflict)?;
                    match self.kind {
                        ResourceKindV2::Network => start.borrow_network_io_once_v2(
                            &current, association, prepared, controller, shape)?,
                        ResourceKindV2::Mount => start.borrow_mount_io_once_v2(
                            &current, association, prepared, controller, shape)?,
            ResourceKindV2::Host => start.borrow_host_io_once_v2(
                            &current, association, prepared, controller, shape)?,
                        ResourceKindV2::Storage => return Err(BodyError::Loan(ResourceReservationErrorV1::Conflict)),
                    }
                };
                let mut actual_session = if self.kind == ResourceKindV2::Storage {
                    let context = storage.as_deref_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
                    ResourceSessionV2::Storage(&mut *context.session)
                } else {
                    ResourceSessionV2::Opened(session.session_mut_v4(opening)?)
                };

                self.prepare = Some(
                    actual_session.prepare_once_v2(&mut self.flights, &mut io, prepared),
                );
                if !matches!(self.prepare, Some(Ok(()))) {
                    self.original_failure_selected =
                        self.flights.has_selected_original_failure_v4();
                    self.first = Some(Failure::Prepare);
                    return Err(BodyError::Flight(OutputPreparationClosedV1));
                }

                self.inventory = Some(actual_session.inventory_once_v2(&mut self.flights, &mut io, prepared));
                if !matches!(self.inventory, Some(Ok(()))) {
                    self.original_failure_selected =
                        self.flights.has_selected_original_failure_v4();
                    self.first = Some(Failure::Inventory);
                    return Err(BodyError::Flight(OutputPreparationClosedV1));
                }
                // Canonical Applied joins the actual authenticated outcomes
                // and native completed stages after the two SDK methods. A
                // failed/ambiguous flight leaves private Applying resident.
                drop(actual_session);
                drop(io);
                drop(start);
                if self.kind == ResourceKindV2::Host {
                    let outcome = self.flights.completed_prepare_outcome_v4()
                        .ok_or(OutputPreparationClosedV1)?;
                    let inventory = self.flights.completed_inventory_outcome_v4()
                        .ok_or(OutputPreparationClosedV1)?;
                    self.applied = Some(entry.finish_host_effect_once_v2(
                        intake, controller, source, &current, outcome, inventory));
                    if !matches!(self.applied, Some(Ok(()))) {
                        self.first = Some(Failure::Applied);
                        return Err(BodyError::Loan(ResourceReservationErrorV1::Conflict));
                    }
                }
                Ok(())
            })());
            if matches!(self.body, Some(Err(_))) {
                if self.original_failure_selected
                    || (self.first.is_none() && matches!(self.body, Some(Err(BodyError::Loan(_)))))
                {
                    self.original_failure_selected =
                        entry.snapshot_resource_io_failure_v4(opening, prepared);
                }
                self.first.get_or_insert(Failure::Body);
            }
        } else {
            self.first = Some(Failure::Entry);
        }

        // Keep both independent observations owed even when the body refused
        // before borrowing the SDK. Their concrete failures remain resident.
        let body = if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootHostLaunchClientClosedV1)
        };
        self.posts = Some(match self.kind {
            ResourceKindV2::Network => entry.finish_network_root_turn_once_v2(root, controller, body),
            ResourceKindV2::Storage => entry.finish_storage_root_turn_once_v2(root, controller, body),
            ResourceKindV2::Mount => entry.finish_mount_root_turn_once_v2(root, controller, body),
            ResourceKindV2::Host => entry.finish_host_root_turn_once_v2(root, controller, body),
        });
        if !matches!(self.posts, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Posts);
        }
        if self.first.is_none() && self.require_complete_v2().is_err() {
            self.first = Some(Failure::Completion);
        }
        self.require_complete_v2()
    }

    fn require_complete_v2(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some()
            || (self.kind == ResourceKindV2::Host && (!matches!(self.applying, Some(Ok(())))
                || !matches!(self.applied, Some(Ok(())))))
            || !matches!(self.prepare, Some(Ok(())))
            || !matches!(self.inventory, Some(Ok(())))
            || !matches!(self.posts, Some(Ok(())))
            || self.flights.completed_prepare_outcome_v4().is_none()
            || match self.kind {
            ResourceKindV2::Network => self.flights.completed_prepare_result_v4().is_none(),
            ResourceKindV2::Storage => self.flights.completed_storage_guest_root_result_v2().is_none(),
            ResourceKindV2::Mount => self.flights.completed_mount_namespace_result_v2().is_none(),
            ResourceKindV2::Host => self.flights.completed_prepare_outcome_v4().is_none(),
        }
            || self.flights.completed_inventory_outcome_v4().is_none()
            || match self.kind {
            ResourceKindV2::Network => self.flights.completed_inventory_model_v4().is_none(),
            ResourceKindV2::Storage => self.flights.completed_storage_inventory_model_v2().is_none(),
            ResourceKindV2::Mount => self.flights.completed_mount_inventory_model_v2().is_none(),
            ResourceKindV2::Host => self.flights.completed_host_inventory_model_v2().is_none(),
        }
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn failure_with_entry_v2<'held>(
        &'held self,
        entry: &'held AcceptedStartEntryOriginalV1,
        opening: &'held StartResourceSessionOpeningOriginalV2,
        prepared: &'held PreparedStartResourceRequestOriginalV2,
        root: &'held RootHostLaunchClientOriginalV1,
    ) -> Option<&'held (dyn Error + 'static)> {
        if self.original_failure_selected {
            return entry.resource_io_failure_with_original_v4(opening, prepared);
        }
        match self.first? {
            Failure::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Entry | Failure::Posts => {
                if match self.kind {
            ResourceKindV2::Network => entry.network_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Storage => entry.storage_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Mount => entry.mount_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Host => entry.host_current_turn_root_failure_is_selected_v2(),
        } {
                    root.failure()
                } else {
                    entry.failure().or_else(|| root.failure())
                }
            }
            Failure::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Applying | Failure::Applied => entry.failure()
                .or_else(|| if matches!(self.first, Some(Failure::Applying)) {
                    self.applying.as_ref()?.as_ref().err().map(|cause| cause as _)
                } else { self.applied.as_ref()?.as_ref().err().map(|cause| cause as _) }),
            Failure::Prepare | Failure::Inventory => self.flights.failure(),
            Failure::Completion => Some(&ResourceReservationErrorV1::Conflict),
        }
    }

    pub(super) fn fmt_failure_with_entry_v2(
        &self,
        entry: &AcceptedStartEntryOriginalV1,
        opening: &StartResourceSessionOpeningOriginalV2,
        prepared: &PreparedStartResourceRequestOriginalV2,
        root: &RootHostLaunchClientOriginalV1,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        if self.original_failure_selected {
            return entry.fmt_resource_io_failure_v4(opening, prepared, formatter);
        }
        if matches!(self.first, Some(Failure::Applying | Failure::Applied))
            && entry.host_effect_body_failure_entered_v2()
            && entry.failure().is_some()
        {
            return entry.fmt_failure_v1(formatter);
        }
        if matches!(self.first, Some(Failure::Entry | Failure::Posts)) {
            if match self.kind {
            ResourceKindV2::Network => entry.network_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Storage => entry.storage_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Mount => entry.mount_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Host => entry.host_current_turn_root_failure_is_selected_v2(),
        } {
                if let Some(view) = root.failure_view_v2() {
                    return std::fmt::Display::fmt(&view, formatter);
                }
            } else if entry.failure().is_some() {
                return entry.fmt_failure_v1(formatter);
            }
        }
        match self.failure_with_entry_v2(entry, opening, prepared, root) {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Start resource IO failure is unavailable"),
        }
    }
}

// The actual exclusive Session borrower stays alive across both methods.
// Neither variant can choose a payer or reconstruct a Session from history.
enum ResourceSessionV2<'held> {
    Opened(aos_sandbox_broker_session_security::StartResourceSessionBorrowV4<'held>),
    Storage(&'held mut super::super::super::super::inventory::DormantStorageLifecycleInventoryOwnerV1),
}

impl ResourceSessionV2<'_> {
    fn prepare_once_v2(&mut self,
        flights: &mut StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        match self {
            Self::Opened(session) => flights.prepare_once_v4(session, original, prepared),
            Self::Storage(session) => session.populate_original_start_storage_once_v2(flights, original, prepared),
        }
    }

    fn inventory_once_v2(&mut self,
        flights: &mut StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        match self {
            Self::Opened(session) => flights.inventory_once_v4(session, original, prepared),
            Self::Storage(session) => session.inventory_original_start_storage_once_v2(flights, original, prepared),
        }
    }
}
