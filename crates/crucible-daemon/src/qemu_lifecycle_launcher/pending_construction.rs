//! Retains the real factory and exact World across partial Source construction.
//!
//! The containing Box and construction carrier are Main-paid and allocated
//! after exact cell reservation, before logical World admission. Custody
//! delivery allocates nothing. The same Main cell owns ordinary cleanup.
//! Main validates its fixed role before the two existing Boxes are born, then
//! installs the complete owner before publishing work. Neither reports nor
//! missing delivery infer native return or create a replacement Original.

use super::*;
use crate::{QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory};
use crucible_api::{ProductionVmCleanupOwner, ProductionVmCleanupReservation};
use crucible_linux_resource::host_services::process_birth::{
    AuthenticatedNativeWorldCleanupLoan, AuthenticatedNativeWorldControlLease,
};
use crucible_qemu::QemuVmRealizationError;

mod cleanup;
mod hot_fork_capture;
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
mod native_observation;
mod post_body;
mod prepared;
mod target_nodes;
use prepared::SourcePreparationHistory;

/// Proves only that this exact preborn owner has not entered the host World call.
///
/// The sole constructor is the actual Pending producer. Entry consumes the
/// token before the host call, including calls that return no delivered loan.
pub(crate) struct SourceWorldNotStarted {
    _private: (),
}

pub(crate) struct PendingSourceConstruction<F: QemuAttemptResourceGuardFactory> {
    returned_guard: Option<F::Guard>,
    launcher: Option<Box<dyn std::any::Any + Send>>,
    launch_input: Option<Box<dyn ProductionVmNodeLauncher>>,
    checkpoint_input: Option<crate::vm_lifecycle::ProductionVmExactCheckpointSet>,
    carrier_active: bool,
    finish_launcher: Option<
        fn(
            &mut (dyn std::any::Any + Send),
        ) -> Result<(), crate::ProductionVmConstructionCleanupError>,
    >,
    take_launcher_post_body: Option<
        fn(
            &mut (dyn std::any::Any + Send),
        ) -> Result<
            Option<crate::ProductionVmConstructionPostBody>,
            crate::ProductionVmConstructionCleanupError,
        >,
    >,
    post_body: Option<crate::ProductionVmConstructionPostBody>,
    body_disposed: bool,
    post_body_taken: bool,
    service: crate::lifecycle_cleanup::ServiceMainHandle,
    not_started: Option<SourceWorldNotStarted>,
    construction_started: bool,
    admitted_resources: Option<crucible_campaign::AttemptResourceLimits>,
    selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    transferred: bool,
    history: SourcePreparationHistory,
    generation_storage: Option<crate::QemuAttemptGenerationStorage>,
    target_nodes:
        Option<Vec<crate::qemu_hot_fork_reconciliation::TargetNodeConstruction<F::Guard>>>,
    target_retained_nodes:
        Option<Vec<crate::qemu_hot_fork_reconciliation::TargetNodeConstruction<F::Guard>>>,
    target_retained_nodes_lent: bool,
    target_node_selection: Option<crate::qemu_resource_guard::QemuGenerationStorageSelection>,
    // Keeps only the same World-paid immutable roster alive through handback;
    // no native guard, role or process permission lives in this metadata alias.
    target_node_storage: Option<crate::QemuAttemptGenerationStorage>,
    target_nodes_lent: bool,
    target_storage: Option<TargetConstructionStorage>,
    worker_geometry: Option<crucible_qemu::QemuHotForkWorkerGeometry>,
    factory: Option<F>,
    world: Option<AuthenticatedNativeWorldCleanupLoan>,
    reservation: Option<crate::WorldLifecycleCleanupReservation>,
    construction_custody: Option<Box<crate::ProductionVmConstructionCustody>>,
    // Remains here on genuine cell-admission refusal; no charge is discarded.
    controls: Option<AuthenticatedNativeWorldControlLease>,
    members_closed: bool,
    body_cleanup_complete: bool,
}

impl<F: QemuAttemptResourceGuardFactory> PendingSourceConstruction<F> {
    /// Prices the actual Main-preborn Pending body and construction carrier.
    pub(crate) fn control_bytes() -> Result<u64, LifecycleApiError> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<crate::ProductionVmConstructionCustody>())
            // One original reservation/admission report can outlive this call.
            // These alternatives share a phase; price its actual payload before
            // any failure rather than allocate a replacement ownership carrier.
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<crucible_qemu::OriginalActorAccountError>()
                        .max(std::mem::size_of::<LifecycleApiError>()),
                )
            })
            .ok_or_else(|| launcher_message("pending Source construction extent overflow"))?;
        u64::try_from(bytes)
            .map_err(|_| launcher_message("pending Source construction extent overflow"))
    }
}

impl<F> PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    /// Performs only the fixed two-Box birth beneath the reserved Main locks.
    pub(crate) fn new_prepared(
        (factory, ()): (F, ()),
        reservation: crate::WorldLifecycleCleanupReservation,
    ) -> (
        Box<Self>,
        Option<crate::packaged_qemu_executor::RetainedServiceStart>,
    ) {
        let start = crate::packaged_qemu_executor::RetainedServiceStart::new(
            reservation.service_preclaim(),
        );
        (Self::new_prepaid(factory, reservation), Some(start))
    }

    /// Moves the same import input into that fixed preborn Service phase.
    pub(crate) fn new_prepared_with_import(
        (factory, input): (F, crate::imported_checkpoint::RetainedImportedCheckpoint),
        reservation: crate::WorldLifecycleCleanupReservation,
    ) -> (
        Box<Self>,
        Option<crate::packaged_qemu_executor::RetainedServiceStart>,
    ) {
        let start = crate::packaged_qemu_executor::RetainedServiceStart::new_with_import(
            reservation.service_preclaim(),
            input,
        );
        (Self::new_prepaid(factory, reservation), Some(start))
    }

    /// Creates the same Main-paid owner before logical World admission.
    ///
    /// The fixed Main producer has already validated its genuine role and
    /// geometry, and immediately installs this owner before publishing Reserved.
    /// This constructor enters no Original and performs no physical work.
    fn new_prepaid(factory: F, reservation: crate::WorldLifecycleCleanupReservation) -> Box<Self> {
        let service = reservation.service_preclaim().handle();
        Box::new(Self {
            returned_guard: None,
            launcher: None,
            launch_input: None,
            checkpoint_input: None,
            carrier_active: false,
            finish_launcher: None,
            take_launcher_post_body: None,
            post_body: None,
            body_disposed: false,
            post_body_taken: false,
            service,
            not_started: Some(SourceWorldNotStarted { _private: () }),
            construction_started: false,
            admitted_resources: None,
            selected_checkpoint: None,
            transferred: false,
            history: SourcePreparationHistory::default(),
            generation_storage: None,
            target_nodes: None,
            target_retained_nodes: None,
            target_retained_nodes_lent: false,
            target_node_selection: None,
            target_node_storage: None,
            target_nodes_lent: false,
            target_storage: None,
            worker_geometry: None,
            factory: Some(factory),
            world: None,
            reservation: Some(reservation),
            construction_custody: Some(Box::new(crate::ProductionVmConstructionCustody::new())),
            controls: None,
            members_closed: false,
            body_cleanup_complete: false,
        })
    }

    pub(crate) fn record_first(&mut self, source: QemuVmRealizationError) {
        if self.history.native.is_none() {
            self.history.native = Some(source);
        }
    }
}

impl<F> crucible_api::ProductionVmCleanupOwner for PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        self.take_retained_post_body()
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }
}

impl<F> ProductionVmNodeLauncher for PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    fn take_cleanup_reservation(
        &mut self,
    ) -> Option<
        Box<
            dyn ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                    ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                >,
        >,
    > {
        self.reservation
            .take()
            .map(crate::WorldLifecycleCleanupReservation::into_reservation)
    }
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Err(launcher_message(
            "pending Source construction grants no execution",
        ))
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Err(launcher_message(
            "pending Source construction has no active lifecycle",
        ))
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _qemu_executable: &std::path::Path,
        _root_image: &std::path::Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(launcher_message(
            "pending Source construction grants no launch",
        ))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(launcher_message(
            "pending Source construction grants no restore",
        ))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(launcher_message(
            "pending Source construction grants no replay",
        ))
    }

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        self.require_external_body_acceptance()?;
        // The Source World still pays lent row payloads. A destroyed external
        // Loop does not return those bytes while an exact Target owns them.
        self.close_target_nodes()?;
        if self.body_cleanup_complete {
            return Ok(());
        }
        if self.carrier_active {
            let custody = self.construction_custody.as_ref().ok_or(
                crate::ProductionVmConstructionCleanupError::Retained(
                    "same active construction carrier is absent",
                ),
            )?;
            custody.retry_cleanup()?;
            self.body_cleanup_complete = true;
            return Ok(());
        }
        if let Some(launcher) = self.launch_input.as_mut() {
            launcher.finish()?;
            self.body_cleanup_complete = true;
            return Ok(());
        }
        if let Some(launcher) = self.launcher.as_mut() {
            let finish = self.finish_launcher.ok_or(
                crate::ProductionVmConstructionCleanupError::Retained(
                    "same retained launcher cleanup projection is absent",
                ),
            )?;
            finish(launcher.as_mut())?;
            self.body_cleanup_complete = true;
            return Ok(());
        }
        if self.transferred || self.not_started.is_some() {
            // This closes only the Pending body. The exact nominal no-entry
            // proof or external launcher PostBody is still required by Main.
            self.body_cleanup_complete = true;
            return Ok(());
        }
        if self.controls.is_some() {
            let reservation = self.reservation.as_ref().ok_or(
                crate::ProductionVmConstructionCleanupError::Retained(
                    "same World controls have no original Main reservation",
                ),
            )?;
            let Some(controls) = self.controls.take() else {
                return Err(crate::ProductionVmConstructionCleanupError::Retained(
                    "same retained World controls are absent",
                ));
            };
            if let Err(controls) = reservation.attach_controls(controls) {
                self.controls = Some(controls);
                return Err(crate::ProductionVmConstructionCleanupError::Retained(
                    "same World controls remain in Pending custody",
                ));
            }
        }
        self.finish_under_world_cleanup()
    }
}
