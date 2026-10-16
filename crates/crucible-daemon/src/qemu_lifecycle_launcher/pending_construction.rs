//! Retains the real factory and exact World across partial Source construction.
//!
//! The containing Box is allocated inside the authenticated before-effects
//! callback. The queue cell already owns the same World body charge. Failure
//! moves this existing Box into that cell; no fallback launcher, new Original,
//! registry, or failure-time allocation is used.

use super::*;
use crate::{QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory};
use crucible_api::{ProductionVmCleanupOwner, ProductionVmCleanupReservation};
use crucible_linux_resource::host_services::process_birth::{
    AuthenticatedNativeWorldCleanupLoan, AuthenticatedNativeWorldControlLease,
};
use crucible_qemu::QemuVmRealizationError;

pub(crate) struct PendingSourceConstruction<F: QemuAttemptResourceGuardFactory> {
    returned_guard: Option<F::Guard>,
    generation_storage: Option<crate::QemuAttemptGenerationStorage>,
    factory: Option<F>,
    world: AuthenticatedNativeWorldCleanupLoan,
    reservation: Option<Box<dyn ProductionVmCleanupReservation>>,
    construction_custody: Option<Box<crucible_api::ProductionVmConstructionCustody>>,
    // Remains here on genuine cell-admission refusal; no charge is discarded.
    controls: Option<AuthenticatedNativeWorldControlLease>,
    first_failure: Option<QemuVmRealizationError>,
    members_closed: bool,
    physically_closed: bool,
}

impl<F: QemuAttemptResourceGuardFactory> PendingSourceConstruction<F> {
    /// Prices the temporary Box that overlaps successful launcher construction.
    pub(crate) fn control_bytes() -> Result<u64, LifecycleApiError> {
        u64::try_from(std::mem::size_of::<Self>())
            .map_err(|_| launcher_message("pending Source construction extent overflow"))
    }
}

impl<F> PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    /// Creates the paid owner after logical claim and before cell admission.
    ///
    /// Both admission outcomes retain this already allocated same Box.
    pub(crate) fn new_prepaid(
        factory: F,
        world: AuthenticatedNativeWorldCleanupLoan,
        controls: AuthenticatedNativeWorldControlLease,
    ) -> Box<Self> {
        Box::new(Self {
            returned_guard: None,
            generation_storage: None,
            factory: Some(factory),
            world,
            reservation: None,
            construction_custody: Some(Box::new(
                crucible_api::ProductionVmConstructionCustody::new(),
            )),
            controls: Some(controls),
            first_failure: None,
            members_closed: false,
            physically_closed: false,
        })
    }

    /// Moves the exact containing lease into the same permanent Main cell.
    ///
    /// # Errors
    /// Preserves this same Box and lease on genuine reservation refusal. This
    /// method never claims that no node was born or that a debit was returned.
    pub(crate) fn reserve_cleanup(&mut self) -> Result<(), QemuVmRealizationError> {
        let factory = self
            .factory
            .as_ref()
            .ok_or_else(|| missing_pending("actual factory is absent"))?;
        let controls = self
            .controls
            .take()
            .ok_or_else(|| missing_pending("actual body lease is absent"))?;
        match factory.reserve_world_lifecycle_cleanup(controls) {
            Ok(reservation) => {
                self.reservation = Some(reservation);
                Ok(())
            }
            Err((controls, source)) => {
                self.controls = Some(controls);
                Err(source)
            }
        }
    }

    /// Builds exactly the prepaid selected rows before any native Source effects.
    pub(crate) fn prepare_generation_storage<'a>(
        &mut self,
        nodes: impl Clone + Iterator<Item = &'a crucible::NodeId>,
    ) -> Result<(), LifecycleApiError> {
        if self.generation_storage.is_some() {
            return Err(launcher_message("generation storage was already prepared"));
        }
        self.generation_storage = Some(crate::QemuAttemptGenerationStorage::prepare(nodes)?);
        Ok(())
    }

    pub(crate) fn record_first(&mut self, source: QemuVmRealizationError) {
        if self.first_failure.is_none() {
            self.first_failure = Some(source);
        }
    }

    /// Moves the same token and factory into the successful actual launcher.
    ///
    /// The caller retains this Box unchanged if its expected fields are absent.
    pub(crate) fn into_launcher_parts(
        mut self: Box<Self>,
        guard: F::Guard,
    ) -> Result<
        (
            F::Guard,
            crate::QemuAttemptGenerationStorage,
            F,
            Box<dyn ProductionVmCleanupReservation>,
            Box<crucible_api::ProductionVmConstructionCustody>,
        ),
        Box<Self>,
    > {
        self.returned_guard = Some(guard);
        if self.first_failure.is_some()
            || self.generation_storage.is_none()
            || self.factory.is_none()
            || self.reservation.is_none()
            || self.controls.is_some()
            || self.construction_custody.is_none()
        {
            return Err(self);
        }
        // Both fields were checked together before either ownership move.
        let Some(factory) = self.factory.take() else {
            return Err(self);
        };
        let Some(reservation) = self.reservation.take() else {
            self.factory = Some(factory);
            return Err(self);
        };
        let Some(custody) = self.construction_custody.take() else {
            self.factory = Some(factory);
            self.reservation = Some(reservation);
            return Err(self);
        };
        // Dropping this emptied temporary Box closes its World cleanup borrow.
        // The cell's body lease and returned launcher continue to retain Main.
        let Some(guard) = self.returned_guard.take() else {
            self.factory = Some(factory);
            self.reservation = Some(reservation);
            self.construction_custody = Some(custody);
            return Err(self);
        };
        let Some(storage) = self.generation_storage.take() else {
            self.returned_guard = Some(guard);
            self.factory = Some(factory);
            self.reservation = Some(reservation);
            self.construction_custody = Some(custody);
            return Err(self);
        };
        Ok((guard, storage, factory, reservation, custody))
    }

    /// Returns the exact typed begin error after publishing the same owner.
    ///
    /// Invariant refusal returns that same error, token and preexisting owner
    /// together. The inline mutex adds Sync without a failure-time allocation.
    pub(crate) fn retain_after_begin_error(
        mut self: Box<Self>,
        source: QemuVmRealizationError,
    ) -> Result<
        (
            QemuVmRealizationError,
            Box<dyn crucible_api::ProductionVmCleanupHandoff>,
        ),
        SourceConstructionCustodyFailure,
    > {
        let reservation = self.reservation.take();
        retain_source_owner(
            reservation,
            ProductionVmCleanupOwner::Launcher(self),
            source,
        )
    }
}

impl<F> ProductionVmNodeLauncher for PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    fn take_cleanup_reservation(&mut self) -> Option<Box<dyn ProductionVmCleanupReservation>> {
        self.reservation.take()
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

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if self.physically_closed {
            return Ok(());
        }
        if self.controls.is_some() {
            return Err(launcher_message(
                "unreserved World body remains retained; consuming never-born return is required",
            ));
        }
        let factory = self
            .factory
            .as_mut()
            .ok_or_else(|| launcher_message("pending Source lost its actual factory"))?;
        let members = if self.members_closed {
            Ok(())
        } else {
            factory.retry_native_world_construction(&self.world)
        };
        match members {
            Ok(()) => {
                self.members_closed = true;
                if let Some(guard) = self.returned_guard.as_mut() {
                    if let Err(source) = guard.finish() {
                        self.record_first(source);
                        return Err(launcher_message(
                            "same returned Source guard retains cleanup",
                        ));
                    }
                }
                self.returned_guard = None;
                self.generation_storage = None;
                self.physically_closed = true;
                Ok(())
            }
            Err(source) => {
                self.record_first(source);
                Err(launcher_message(format!(
                    "same World construction cleanup remains retained: {}",
                    self.first_failure
                        .as_ref()
                        .map_or("unknown refusal".to_owned(), ToString::to_string),
                )))
            }
        }
    }
}

/// Preserves an exceptional failed publication without erasing its native cause.
///
/// The same typed begin error and preallocated owner remain reachable. This is
/// an owning refusal, never an observation that Cleanup or return succeeded.
#[must_use = "retain the same owner and reservation until custody publication succeeds"]
pub struct SourceConstructionCustodyFailure<C = QemuVmRealizationError> {
    source: C,
    custody: Mutex<
        Option<(
            Option<Box<dyn ProductionVmCleanupReservation>>,
            ProductionVmCleanupOwner,
        )>,
    >,
}

impl<C: std::error::Error + Send + Sync + 'static> SourceConstructionCustodyFailure<C> {
    fn new(
        source: C,
        reservation: Option<Box<dyn ProductionVmCleanupReservation>>,
        owner: ProductionVmCleanupOwner,
    ) -> Self {
        Self {
            source,
            custody: Mutex::new(Some((reservation, owner))),
        }
    }

    /// Retries only custody publication through the exact reserved token.
    ///
    /// # Errors
    /// Keeps both fields on absent-token, poisoned, or exact-cell refusal.
    /// Expiry never manufactures Cleanup authority and is not consulted here.
    pub fn retry_publication(
        &mut self,
    ) -> Result<Option<Box<dyn crucible_api::ProductionVmCleanupHandoff>>, &'static str> {
        let slot = self
            .custody
            .get_mut()
            .map_err(|_| "Source custody is poisoned")?;
        let Some((reservation, owner)) = slot.take() else {
            return Ok(None);
        };
        let Some(reservation) = reservation else {
            *slot = Some((None, owner));
            return Err("Source custody has no authentic reserved token");
        };
        match reservation.retain(owner) {
            Ok(handoff) => Ok(Some(handoff)),
            Err((reservation, owner)) => {
                *slot = Some((Some(reservation), owner));
                Err("same Source custody publication remains refused")
            }
        }
    }
}

impl<C: std::error::Error + Send + Sync + 'static> std::fmt::Debug
    for SourceConstructionCustodyFailure<C>
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceConstructionCustodyFailure")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl<C: std::error::Error + Send + Sync + 'static> std::fmt::Display
    for SourceConstructionCustodyFailure<C>
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; same Source owner and token remain in custody failure",
            self.source
        )
    }
}

impl<C: std::error::Error + Send + Sync + 'static> std::error::Error
    for SourceConstructionCustodyFailure<C>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn missing_pending(message: &'static str) -> QemuVmRealizationError {
    QemuVmRealizationError::ExecutorUnavailable {
        operation: "retain actual Source construction",
        message: String::from(message),
    }
}

/// Publishes custody without executing or renewing any operation.
pub(crate) fn retain_source_owner<C: std::error::Error + Send + Sync + 'static>(
    reservation: Option<Box<dyn ProductionVmCleanupReservation>>,
    owner: ProductionVmCleanupOwner,
    source: C,
) -> Result<
    (C, Box<dyn crucible_api::ProductionVmCleanupHandoff>),
    SourceConstructionCustodyFailure<C>,
> {
    let Some(reservation) = reservation else {
        return Err(SourceConstructionCustodyFailure::new(source, None, owner));
    };
    match reservation.retain(owner) {
        Ok(handoff) => Ok((source, handoff)),
        Err((reservation, owner)) => Err(SourceConstructionCustodyFailure::new(
            source,
            Some(reservation),
            owner,
        )),
    }
}
