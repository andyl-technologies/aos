//! Drives private admission, catalog publication and activation on one Host owner.
//!
//! The three windows use the same Root/C bookend engine. The actual catalog
//! flight and source remain resident on every failure; positive operation
//! disposal retains the same authenticated Session for the later stage1 rejoin.

use super::*;
use aos_sandbox_controller_domain::normal_root::RootHostPublicationTurnKindV2 as Phase;
use aos_sandbox_controller_domain::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2;
use aos_sandbox_broker_session_security::controller_composition::StartHostCatalogSessionIoOriginalV2;

#[derive(Clone, Copy)]
enum First {
    Predecessor,
    Entry,
    Body,
    Posts,
    Completion,
}

#[derive(Default)]
struct Window {
    predecessor: Option<Result<(), Cause>>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<(), Cause>>,
    posts: Option<Result<(), ResourceReservationErrorV1>>,
    completion: Option<Result<(), Cause>>,
    first: Option<First>,
}

pub(super) struct HostPublicationV2 {
    admission: Window,
    catalog: Window,
    activation: Window,
    source: Box<StartHostCatalogPublicationOriginalV2>,
    post_shape: Option<Result<aos_sandbox_controller_domain::StartResourceSessionPostShapeDataV2, ResourceReservationErrorV1>>,
    survivors: Option<Result<ResourceVector, StartResourceSessionClosedV4>>,
    survivor_shape: Option<Result<aos_sandbox_controller_domain::StartResourceSessionResidentShapeDataV4, ResourceReservationErrorV1>>,
    survivor_handoff: Option<Result<(), ResourceReservationErrorV1>>,
    flight: Box<StartHostCatalogSessionIoOriginalV2>,
}

impl HostPublicationV2 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<StartHostCatalogPublicationOriginalV2>(),
            boxed_bytes::<StartHostCatalogSessionIoOriginalV2>(),
        ])
    }

    pub(super) fn new() -> Self {
        Self {
            admission: Window::default(),
            catalog: Window::default(),
            activation: Window::default(),
            source: Box::new(StartHostCatalogPublicationOriginalV2::new()),
            post_shape: None,
            survivors: None,
            survivor_shape: None,
            survivor_handoff: None,
            flight: Box::new(StartHostCatalogSessionIoOriginalV2::new()),
        }
    }

    fn window(&self, phase: Phase) -> &Window {
        match phase {
            Phase::Admission => &self.admission,
            Phase::Catalog => &self.catalog,
            Phase::Activation => &self.activation,
        }
    }

    fn window_mut(&mut self, phase: Phase) -> &mut Window {
        match phase {
            Phase::Admission => &mut self.admission,
            Phase::Catalog => &mut self.catalog,
            Phase::Activation => &mut self.activation,
        }
    }

    pub(super) fn progress_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        root: &mut RootHostLaunchClientOriginalV1,
        prepared: &PreparedStartResourceRequestOriginalV2,
        session: &mut StartResourceSessionOpenOriginalV4,
        opening: &mut StartResourceSessionOpeningOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        for phase in [Phase::Admission, Phase::Catalog, Phase::Activation] {
            if self.window(phase).first.is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if matches!(self.window(phase).completion, Some(Ok(()))) {
                continue;
            }
            if phase == Phase::Activation {
                // Validate the actual disposed Catalog17 Session BEFORE native5
                // advances C; the qualifier cannot be manufactured from DATA.
                let predecessor = (|| -> Result<(), Cause> {
                    let mut actual = session.session_mut_v4(opening)?;
                    let qualified = self.flight.qualified_session_v2(&mut actual)?;
                    qualified.require_native_completion_v2(entry.host_catalog_native_completion_v2()
                        .ok_or(OriginalCreateProvisioningClosedV1)?)?;
                    Ok(())
                })();
                if predecessor.is_err() { self.window_mut(phase).first = Some(First::Predecessor); }
                self.window_mut(phase).predecessor = Some(predecessor);
                if self.window(phase).first.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
            }
            if phase == Phase::Catalog {
                self.post_shape = Some((|| {
                    use aos_sandbox_model::ResourceDimension as D;
                    let demand = StartHostCatalogSessionIoOriginalV2::retained_post_receiving_demand_v2()
                        .ok_or(ResourceReservationErrorV1::Conflict)?;
                    let allowed = ResourceVector::ZERO.with(D::MemoryBytes, demand.get(D::MemoryBytes))
                        .with(D::OpenFiles, demand.get(D::OpenFiles));
                    if demand != allowed { return Err(ResourceReservationErrorV1::Conflict); }
                    Ok(aos_sandbox_controller_domain::StartResourceSessionPostShapeDataV2 {
                        receiving_bytes: usize::try_from(demand.get(D::MemoryBytes)).ok()
                            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                                aos_sandbox_broker_session_security::StartResourceSessionBorrowV4<'static>>()
                                    .checked_mul(2)?)).ok_or(ResourceReservationErrorV1::Conflict)?,
                        open_files: usize::try_from(demand.get(D::OpenFiles))
                            .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                    })
                })());
                if !matches!(self.post_shape, Some(Ok(_))) {
                    self.window_mut(phase).first = Some(First::Predecessor);
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            self.window_mut(phase).entry = Some(entry.begin_host_publication_turn_once_v2(
                phase, root, intake, controller, source));
            if matches!(self.window(phase).entry, Some(Ok(()))) {
                let body = (|| -> Result<(), Cause> {
                    let current = {
                        let loan = entry.borrow_host_root_v1(intake, controller, source)?;
                        root.borrow_host_publication_turn_v2(phase, &loan, controller)?
                    };
                    match phase {
                        Phase::Admission => entry.admit_host_publication_once_v2(
                            intake, controller, source, &current)?,
                        Phase::Catalog => {
                            {
                                let mut publication = entry.borrow_host_catalog_publication_once_v2(
                                    intake, source, &current, prepared, controller)?;
                                self.source.prepare_pending_once_v2(&mut publication, controller, prepared)?;
                            }
                            {
                                let mut loan = entry.borrow_host_root_v1(intake, controller, source)?;
                                let mut opening_loan = loan.borrow_host_catalog_opening_once_v2(
                                    &current, opening, controller)?;
                                session.open_once_v4(&mut opening_loan)?;
                            }
                            {
                                let mut loan = entry.borrow_host_root_v1(intake, controller, source)?;
                                let mut io = loan.borrow_host_catalog_io_once_v2(
                                    &current, opening, &self.source, controller,
                                    *self.post_shape.as_ref().and_then(|shape| shape.as_ref().ok())
                                        .ok_or(OriginalCreateProvisioningClosedV1)?)?;
                                let mut actual = session.session_mut_v4(opening)?;
                                self.flight.publish_once_v2(&mut actual, &mut io, &self.source)?;
                                self.flight.complete_native_once_v2(&mut actual, &mut io, &self.source)?;
                            }
                            {
                                let mut publication = entry.borrow_host_catalog_publication_once_v2(
                                    intake, source, &current, prepared, controller)?;
                                let outcome = self.flight.completed_outcome_v2()
                                    .ok_or(OriginalCreateProvisioningClosedV1)?;
                                self.source.confirm_once_v2(&mut publication, controller, outcome)?;
                            }
                        }
                        Phase::Activation => {
                            entry.activate_host_publication_once_v2(
                                intake, controller, source, &current)?;
                        }
                    }
                    Ok(())
                })();
                if body.is_err() { self.window_mut(phase).first = Some(First::Body); }
                self.window_mut(phase).body = Some(body);
            } else {
                self.window_mut(phase).first = Some(First::Entry);
            }
            // The complete primary Result is resident before either independent
            // post. Failed entry/body never suppresses the owed Root/C finisher.
            let body = if matches!(self.window(phase).body, Some(Ok(()))) { Ok(()) }
                else { Err(RootHostLaunchClientClosedV1) };
            let posts = entry.finish_host_root_turn_once_v2(root, controller, body);
            if posts.is_err() { self.window_mut(phase).first.get_or_insert(First::Posts); }
            self.window_mut(phase).posts = Some(posts);
            if self.window(phase).first.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
            let complete = (|| -> Result<(), Cause> {
                match phase {
                    Phase::Admission => entry.finish_host_admission_after_posts_once_v2(controller)?,
                    Phase::Catalog => {
                        // SDK widths describe its actual live controls/models.
                        // Domain separately joins the native post17 final extent;
                        // the opening's old pre-publication extent is insufficient.
                        self.survivors = Some(session.completed_receiving_demand_v4(opening));
                        let demand = self.survivors.as_ref().and_then(|demand| demand.as_ref().ok())
                            .ok_or(StartResourceSessionClosedV4)?;
                        self.survivor_shape = Some((|| {
                            use aos_sandbox_model::ResourceDimension as D;
                            let shape = aos_sandbox_controller_domain::StartResourceSessionResidentShapeDataV4 {
                                memory_bytes: demand.get(D::MemoryBytes), open_files: demand.get(D::OpenFiles),
                                namespace_entries: demand.get(D::MetadataEntries),
                            };
                            if *demand != ResourceVector::ZERO.with(D::MemoryBytes, shape.memory_bytes)
                                .with(D::OpenFiles, shape.open_files).with(D::MetadataEntries, shape.namespace_entries) {
                                return Err(ResourceReservationErrorV1::Conflict);
                            }
                            Ok(shape)
                        })());
                        let shape = *self.survivor_shape.as_ref().and_then(|shape| shape.as_ref().ok())
                            .ok_or(ResourceReservationErrorV1::Conflict)?;
                        self.survivor_handoff = Some(entry.retain_completed_host_catalog_session_once_v2(
                            opening, root, controller, &self.source, shape));
                        if !matches!(self.survivor_handoff, Some(Ok(()))) {
                            return Err(Box::new(ResourceReservationErrorV1::Conflict));
                        }
                        let mut actual = session.session_mut_v4(opening)?;
                        self.flight.dispose_positive_once_v2(&mut actual, entry, root, controller, &self.source)?;
                    }
                    Phase::Activation => entry.finish_host_activation_after_posts_once_v2(controller)?,
                }
                Ok(())
            })();
            if complete.is_err() { self.window_mut(phase).first = Some(First::Completion); }
            self.window_mut(phase).completion = Some(complete);
            if self.window(phase).first.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        }
        Ok(())
    }

    pub(super) fn failure_v2<'held>(&'held self, entry: &'held AcceptedStartEntryOriginalV1,
        root: &'held RootHostLaunchClientOriginalV1,
        session: &'held StartResourceSessionOpenOriginalV4,
        opening: &'held StartResourceSessionOpeningOriginalV2,
    ) -> Option<&'held (dyn Error + 'static)> {
        for phase in [Phase::Admission, Phase::Catalog, Phase::Activation] {
            let state = self.window(phase);
            let Some(first) = state.first else { continue; };
            return match first {
                First::Predecessor => self.post_shape.as_ref().and_then(|shape| shape.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
                    .or_else(|| self.flight.failure_v2())
                    .or_else(|| state.predecessor.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _)),
                First::Entry | First::Posts => {
                    if entry.host_current_turn_root_failure_is_selected_v2() { root.failure() }
                    else { entry.failure().or_else(|| root.failure()) }
                }
                First::Body => {
                    let original = if phase == Phase::Catalog {
                        if self.source.original_failure_selected_v2() || self.flight.original_failure_selected_v2()
                            || session.native_original_failure_selected_v4() {
                            entry.failure()
                        } else { None }
                    } else { entry.failure() };
                    original.or_else(|| self.source.failure_v2()).or_else(|| self.flight.failure_v2())
                        .or_else(|| session.failure()).or_else(|| opening.failure())
                        .or_else(|| state.body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                },
                First::Completion => self.survivors.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
                    .or_else(|| self.survivor_shape.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn Error + 'static)))
                    .or_else(|| if matches!(self.survivor_handoff, Some(Err(_))) { entry.failure() } else { None })
                    .or_else(|| self.flight.failure_v2())
                    .or_else(|| state.completion.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                    .or_else(|| entry.failure()),
            }.or(Some(&ResourceReservationErrorV1::Conflict));
        }
        None
    }
}
