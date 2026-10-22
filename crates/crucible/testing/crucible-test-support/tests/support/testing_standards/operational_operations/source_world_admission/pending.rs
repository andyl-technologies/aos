//! Binds the same Main Pending, receiver, saved admission and physical cleanup.

use super::super::Companion;

pub(in super::super) const PREPARED_WORLD: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction/prepared.rs",
    required: &[
        (
            r#"fn retain_world(
        &mut self,
        loan: AuthenticatedNativeWorldCleanupLoan,
        controls: AuthenticatedNativeWorldControlLease,
    ) -> Result<(), &'static str> {
        *self.world = Some(loan);
        let returned = match self.reservation.as_ref() {
            Some(reservation) => reservation.attach_controls(controls),
            None => Err(controls),
        };
        match returned {
            Ok(()) => Ok(()),
            Err(controls) => {
                *self.controls = Some(controls);
                self.first_failure
                    .get_or_insert(QemuVmRealizationError::CleanupRetained {
                        operation:                                                   ,
                    });
                Err(                                                  )
            }
        }
    }"#,
            1,
        ),
        (
            r#"metadata_failure: &mut metadata_failure,
};
let selected_checkpoint = self.selected_checkpoint.take();
let result = factory.begin_world(
    admission, process_resources, context.cancellation().clone(), selected_checkpoint,
    consumer_control_bytes, registration.as_ref(), &mut receiver,
);
drop(receiver);
self.history.admission = admission.take_history();"#,
            1,
        ),
        (
            r#"|| self.reservation.as_ref().is_none_or(|reservation| !reservation.is_reserved())
|| self.controls.is_some() || self.construction_custody.is_none() || self.world.is_none()
{ return Err(""); }"#,
            1,
        ),
        (
            r#"let parts = (
            self.returned_guard.take(),
            self.generation_storage.take(),
            self.factory.take(),
            self.reservation.take(),
            self.construction_custody.take(),
            self.world.take(),
            self.target_storage.take(),
        );
        match parts {
            (
                Some(guard),
                Some(storage),
                Some(factory),
                Some(reservation),
                Some(custody),
                Some(world),
                Some(targets),
            ) => {
                self.transferred = true;
                Ok((
                    guard,
                    storage,
                    factory,
                    reservation,
                    custody,
                    world,
                    targets,
                ))
            }
            (guard, storage, factory, reservation, custody, world, targets) => {


                self.returned_guard = guard;
                self.generation_storage = storage;
                self.factory = factory;
                self.reservation = reservation;
                self.construction_custody = custody;
                self.world = world;
                self.target_storage = targets;
                Err(                                                     )
            }
        }
    }"#,
            1,
        ),
        (
            r#".with_cleanup_reservation(reservation).with_construction_custody(custody)
.with_world_cleanup_loan(world).with_target_construction_storage(targets),"#,
            1,
        ),
        (
            r#"self.transferred = false;
self.finish_launcher = Some(finish_retained_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>>,);"#,
            1,
        ),
        (
            r#"if self.construction_started || self.transferred || self.history.first.is_some() { return Err(()); } self.construction_started = true;"#,
            1,
        ),
        (
            r#"let selection = self.service.prepared_selector();
        let admission =
            match factory.prepare_world_admission(selection.clone(), registration.as_ref()) {
                Ok(admission) => admission,
                Err(first) => {
                    self.record_construction_first(
                        crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(first),
                    );
                    self.restore_canonical_selection(context);
                    return Err(());
                }
            };
        self.world_admission = Some(admission);
        let Some(admission) = self.world_admission.as_mut() else {
            self.record_unavailable();
            return Err(());
        };"#,
            1,
        ),
        (
            r#"let mut receiver = PendingWorldBeforeEffects {
            selection,
            not_started: &mut self.not_started,
            generation_storage: &mut self.generation_storage,
            target_nodes: &mut self.target_nodes,
            target_retained_nodes: &mut self.target_retained_nodes,
            target_storage: &mut self.target_storage,
            target_node_selection: &mut self.target_node_selection,
            target_node_storage: &mut self.target_node_storage,
            world: &mut self.world,
            reservation: &self.reservation,
            controls: &mut self.controls,
            first_failure: &mut self.history.native,
            source,
            metadata_failure: &mut metadata_failure,
        };"#,
            1,
        ),
        (
            r#"struct PendingWorldBeforeEffects<'a, G: QemuAttemptResourceGuard> {
    selection: crate::PreparedSourceSelector,
    not_started: &'a mut Option<SourceWorldNotStarted>,"#,
            1,
        ),
        (
            r#"fn source_selection(&self) -> &crate::PreparedSourceSelector { &self.selection }"#,
            1,
        ),
        (
            r#"fn entered_world(&mut self) { drop(self.not_started.take()); }"#,
            1,
        ),
        (
            r#"pub(super) first: Option<SourcePreparationFirst>,
    pub(super) admission: crate::qemu_resource_guard::SourceWorldAdmissionHistory,
    pub(super) native: Option<QemuVmRealizationError>,"#,
            1,
        ),
        (
            r#"admission_first: self.admission.first_failure(), admission_post: self.admission.post(),
    first: self.first.as_ref().map(SourcePreparationFirst::failure_ref), native: self.native.as_ref(),"#,
            1,
        ),
    ],
};

pub(in super::super) const PENDING_LAYOUT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction.rs",
    required: &[
        (
            r#"world_admission: Option<crate::qemu_resource_guard::SourceWorldAdmission>,"#,
            1,
        ),
        (
            r#"let preparation =
            crucible_qemu_host::LinuxQemuNativeWorldPreparation::shared_control_extent()
                .and_then(|bytes| usize::try_from(bytes).ok())
                .ok_or_else(|| launcher_message("World Preparation control extent overflow"))?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(preparation)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<crate::ProductionVmConstructionCustody>())
            })
            // One original reservation/admission report can outlive this call.
            // These alternatives share a phase; price its actual payload before
            // any failure rather than allocate a replacement ownership carrier.
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<crucible_qemu_host::OriginalActorAccountError>()
                        .max(std::mem::size_of::<LifecycleApiError>()),
                )
            })
            .ok_or_else(|| launcher_message("pending Source construction extent overflow"))?;"#,
            1,
        ),
        (r#"world_admission: None,"#, 1),
    ],
};

pub(in super::super) const PENDING_POST_BODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction/post_body.rs",
    required: &[
        (
            r#"if !self.body_disposed { if self.post_body.is_none() {
    self.post_body = Some(self.extract_post_body()?); }"#,
            1,
        ),
        (
            r#"self.generation_storage = None; self.returned_guard = None;
    self.world_admission = None; self.finish_launcher = None;
    self.take_launcher_post_body = None; self.body_disposed = true;"#,
            1,
        ),
    ],
};
