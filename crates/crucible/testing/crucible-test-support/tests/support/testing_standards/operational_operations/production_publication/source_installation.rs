//! Binds Source installation and its native World to the original Main body.
//!
//! Every transfer preserves the same input, factory, reservation and World.
//! Completed body custody alone cannot substitute for native return or the
//! original terminal receipt; these source checks grant no native authority.

use super::Companion;

/// Binds owning callback and postbody types across the control boundary.
pub(super) const CONTROL_API: Companion = Companion {
    path: "crates/crucible/control/crucible-control-api/src/cleanup_owner.rs",
    required: &[
        (
            r#"pub trait ProductionVmCleanupReservation: Send { type Failure: std::error::Error + Send + 'static;"#,
            1,
        ),
        (
            r#"fn retain(
    self: Box<Self>,
    owner: Box<
        dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>,
    >,
) -> Result<
    Box<dyn ProductionVmCleanupHandoff<Failure = Self::Failure, PostBody = Self::PostBody>>,
    (
        Box<
            dyn ProductionVmCleanupReservation<
                Failure = Self::Failure,
                PostBody = Self::PostBody,
                ReturnDestination = Self::ReturnDestination,
            >,
        >,
        Box<dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>>,
    ),
>;"#,
            1,
        ),
        (
            r#"fn prepare_return(
        self: Box<Self>,
    ) -> Result<
        Self::ReturnDestination,
        Box<
            dyn ProductionVmCleanupReservation<
                    Failure = Self::Failure,
                    PostBody = Self::PostBody,
                    ReturnDestination = Self::ReturnDestination,
                >,
        >,
    >;"#,
            1,
        ),
        (
            r#"fn retain_returned(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>,
        >,
    ) -> Result<
        Box<dyn ProductionVmCleanupHandoff<Failure = Self::Failure, PostBody = Self::PostBody>>,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                        Failure = Self::Failure,
                        PostBody = Self::PostBody,
                        ReturnDestination = Self::ReturnDestination,
                    >,
            >,
            Box<dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>>,
        ),
    >;"#,
            1,
        ),
    ],
};

/// Binds Source republication and transfer of the original completed receipt.
pub(super) const RETAINED_SOURCE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle/source_construction/retained.rs",
    required: &[
        (
            r#"Api { owner: crate::ProductionVmConstructionFailure, handoff: Option<SourceCleanupHandoff>, },"#,
            1,
        ),
        (
            r#"Self::Api { owner, handoff } => (handoff, owner.retry_reserved_publication()?),"#,
            1,
        ),
        (
            r#"let Some(receipt) = published else { return Err(""); };
*slot = Some(SourceCleanupHandoff::new(receipt)); Ok(())"#,
            1,
        ),
        (
            r#"if let Some(handoff) = self.handoff_mut()
    && !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete)) { return Err(self); }"#,
            1,
        ),
        (
            r#"if let Some(handoff) = self.handoff_mut() && !handoff.retain_post_body() { return Err(self); }"#,
            1,
        ),
        (
            r#"if let Some(owner) = self.retained_install.as_mut() {
    if owner.handoff_mut().is_none() {
        if owner.retry_publication().is_err() { return Err(owner.report()); }
    }
}"#,
            1,
        ),
        (
            r#"let Some(receipt) = owner.handoff_mut() else { return Err(owner.report()); };
let attempt = receipt.retry(); let stage = receipt.stage();
if !matches!(stage, Ok(ProductionVmCleanupStage::Complete)) {"#,
            1,
        ),
        (
            r#"Self::Api { owner, handoff: Some(handoff), } => match owner.into_published_error() {
    Ok(first) => SourceCleanupHistory {
        first: Some(SourceInstallationFirst::Api(first)),
        cleanup: None, cleanup_post: None, terminal_receipt: Some(handoff),
    },
    Err(owner) => { return Err(Self::Api { owner, handoff: Some(handoff), }); }
},"#,
            1,
        ),
        (
            r#"pub(super) fn require_install_vacancy(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        if self.lifecycle_outstanding {
            return Err(
                QemuAttemptProductionVmLifecycleError::SourceInstallRetained {
                    diagnostic: String::from(                                                  ),
                },
            );
        }


        self.retry_retained_source_installation()
    }"#,
            1,
        ),
    ],
};

/// Binds construction and refused World-control retention.
pub(super) const PENDING_SOURCE: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction.rs",
    required: &[
        (
            r#"factory: Some(factory), world: None, reservation: Some(reservation),"#,
            1,
        ),
        (
            r#"if let Err(controls) = reservation.attach_controls(controls) {
    self.controls = Some(controls);
    return Err(crate::ProductionVmConstructionCleanupError::Retained("",));
}"#,
            1,
        ),
        (
            r#"(Self::new_prepaid(factory, reservation), Some(start))"#,
            2,
        ),
    ],
};

/// Binds input and factory retention before prepared-body publication.
pub(super) const SOURCE_BIRTH: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
    required: &[
        (
            r#"match self.prepare_source_with_input((), PendingSourceConstruction::<R>::new_prepared) {"#,
            1,
        ),
        (
            r#"if let Err(first) = self.refresh_prepared_source() {
            return Err(SourcePreparationFailure { input, first });
        }"#,
            1,
        ),
        (
            r#"if let Err(first) = self.require_install_vacancy() {
            return Err(SourcePreparationFailure { input, first });
        }"#,
            1,
        ),
        (
            r#"let Some(factory) = self.resources.retain_fork_target_factory() else {
            return Err(SourcePreparationFailure {
                input,
                first: QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                    QemuVmRealizationError::CleanupRetained {
                        operation:                                                       ,
                    },
                ),
            });
        }"#,
            1,
        ),
        (
            r#"let Some(producer) = self.resources.source_main_producer() else {
            return Err(SourcePreparationFailure {
                input,
                first: QemuAttemptProductionVmLifecycleError::SourceMainPreparation(
                    SourceMainPreparationRefusal {
                        first: crate::lifecycle_cleanup::ServiceMainPreclaimError::Role(
                                                                         ,
                        ),
                    },
                ),
            });
        }"#,
            1,
        ),
        (
            r#"let installed = match producer.reserve_with_prepared(
            crate::lifecycle_cleanup::PreparedRole::Source,
            (factory, input),
            bytes,
            build,
            crate::lifecycle_cleanup::PreparedSourceProjections {
                first: PendingSourceConstruction::<R>::project_first_error,
                history: PendingSourceConstruction::<R>::project_history,
                terminal_metadata_return: None,
            },
        ) {
            Ok(installed) => installed,
            Err(((_, input), first)) => {
                return Err(SourcePreparationFailure {
                    input,
                    first: QemuAttemptProductionVmLifecycleError::SourceMainPreparation(
                        SourceMainPreparationRefusal { first },
                    ),
                });
            }
        };"#,
            1,
        ),
        (
            r#"let prepared = crate::qemu_lifecycle_launcher::PreparedSourceHandle::from_main(installed);
let service = prepared.service_main_handle(); self.prepared_source = Some(prepared); Ok(service)"#,
            1,
        ),
    ],
};

/// Binds the launched World to its original reservation and selector.
pub(super) const LAUNCHER: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher.rs",
    required: &[
        (
            r#"pub(crate) fn with_cleanup_reservation(
        mut self,
        reservation: crate::WorldLifecycleCleanupReservation,
    ) -> Self {
        self.prepared_source_selector =
            Some(reservation.service_preclaim().handle().prepared_selector());
        self.cleanup_reservation = Some(reservation);
        self
    }"#,
            1,
        ),
        (
            r#"fn take_cleanup_reservation(
        &mut self,
    ) -> Option<
        Box<
            dyn crucible_control_api::ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                    ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                >,
        >,
    > { self.cleanup_reservation.take().map(crate::WorldLifecycleCleanupReservation::into_reservation) }"#,
            1,
        ),
        (
            r#"pub(crate) fn with_world_cleanup_loan(
        mut self,
        world: crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Self { self._world_cleanup_loan = Some(world); self }"#,
            1,
        ),
    ],
};

/// Binds the real factory selector without a fallback Main issuer.
pub(super) const FACTORY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard.rs",
    required: &[
        (
            r#"fn source_main_producer(&self) -> Option<crate::SourceMainProducer> { None }"#,
            1,
        ),
        (
            r#"fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
    self.cleanup.as_ref().map(|cleanup| cleanup.source_main_producer())
}"#,
            1,
        ),
        (
            r#"fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
    self.host.source_main_producer()
}"#,
            1,
        ),
    ],
};

/// Binds authenticated native World delivery before preparation begins.
pub(super) const NATIVE_WORLD: Companion = super::super::source_world_admission::NATIVE_WORLD;

/// Binds custody and first-cause retention at native admission refusals.
pub(super) const NATIVE_REFUSAL: Companion = Companion {
    path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/refusal.rs",
    required: &[
        (
            r#"pub fn take_retained_world(&mut self) -> Option<AuthenticatedNativeWorldClaim> {
    self._retained.as_mut()?._world.take()
}"#,
            1,
        ),
        (r#"retained.delivery.get_or_insert(error);"#, 1),
        (r#"retained.receiver.get_or_insert(operation);"#, 1),
    ],
};

/// Binds all-or-restore World transfers and original no-entry proof consumption.
pub(super) const PREPARED_WORLD: Companion = super::super::source_world_admission::PREPARED_WORLD;
