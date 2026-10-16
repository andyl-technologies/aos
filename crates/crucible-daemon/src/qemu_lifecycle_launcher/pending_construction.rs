//! Retains the real factory and exact World across partial Source construction.
//!
//! The containing Box is allocated inside the authenticated before-effects
//! callback under the selected World's containing-body charge. An accepted
//! Main cell owns ordinary cleanup. If cell admission refuses, the fixed
//! factory slot keeps this same Box until canonical no-birth proof permits a
//! consuming return. Neither path creates a replacement owner or Original.

use super::*;
use crate::qemu_campaign_lifecycle::SourceCleanupCause;
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
    world: Option<AuthenticatedNativeWorldCleanupLoan>,
    reservation: Option<crate::WorldLifecycleCleanupReservation>,
    construction_custody: Option<Box<crate::ProductionVmConstructionCustody>>,
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
            world: Some(world),
            reservation: None,
            construction_custody: Some(Box::new(crate::ProductionVmConstructionCustody::new())),
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
                let reserved = reservation.is_reserved();
                self.reservation = Some(reservation);
                if reserved {
                    Ok(())
                } else {
                    Err(QemuVmRealizationError::CleanupRetained {
                        operation: "authenticate exact World cleanup reservation",
                    })
                }
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

    /// Moves the same token, factory and World loan into the actual launcher.
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
            crate::WorldLifecycleCleanupReservation,
            Box<crate::ProductionVmConstructionCustody>,
            AuthenticatedNativeWorldCleanupLoan,
        ),
        Box<Self>,
    > {
        self.returned_guard = Some(guard);
        if self.first_failure.is_some()
            || self.generation_storage.is_none()
            || self.factory.is_none()
            || self
                .reservation
                .as_ref()
                .is_none_or(|reservation| !reservation.is_reserved())
            || self.controls.is_some()
            || self.construction_custody.is_none()
            || self.world.is_none()
        {
            return Err(self);
        }
        // Validate every required part before moving any of their ownership.
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
        let Some(world) = self.world.take() else {
            self.returned_guard = Some(guard);
            self.generation_storage = Some(storage);
            self.factory = Some(factory);
            self.reservation = Some(reservation);
            self.construction_custody = Some(custody);
            return Err(self);
        };
        Ok((guard, storage, factory, reservation, custody, world))
    }

    /// Identifies the no-cell branch without asserting absence of Source effects.
    pub(crate) fn has_unreserved_controls(&self) -> bool {
        self.controls.is_some()
    }

    /// Returns the exact typed begin error after publishing the same owner.
    ///
    /// Invariant refusal returns that same error, token and preexisting owner
    /// together. The inline mutex adds Sync without a failure-time allocation.
    pub(crate) fn retain_after_begin_error<C: std::error::Error + Send + Sync + 'static>(
        mut self: Box<Self>,
        source: C,
    ) -> Result<
        (
            C,
            Box<
                dyn crucible_api::ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                    >,
            >,
        ),
        SourceConstructionCustodyFailure<C>,
    > {
        let reservation = self
            .reservation
            .take()
            .map(crate::WorldLifecycleCleanupReservation::into_reservation);
        retain_source_owner(reservation, self, source)
    }
}

/// Retains the no-cell body, then its exact post-destruction World return.
pub(crate) struct UnbornSourceConstruction<
    F: QemuAttemptResourceGuardFactory,
    C = QemuVmRealizationError,
> {
    pending: Option<Box<PendingSourceConstruction<F>>>,
    returning: Option<UnbornWorldReturn<F>>,
    first: C,
    cleanup_failure: Option<SourceCleanupCause>,
    cleanup_post: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    physically_closed: bool,
}

struct UnbornWorldReturn<F> {
    factory: F,
    world: AuthenticatedNativeWorldCleanupLoan,
    controls: AuthenticatedNativeWorldControlLease,
    body_destroyed: bool,
}

impl<F, C> UnbornSourceConstruction<F, C>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
    C: std::error::Error + Send + Sync + 'static,
{
    pub(crate) fn new(pending: Box<PendingSourceConstruction<F>>, first: C) -> Self {
        Self {
            pending: Some(pending),
            returning: None,
            first,
            cleanup_failure: None,
            cleanup_post: None,
            physically_closed: false,
        }
    }

    pub(crate) fn cleanup_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cleanup_failure
            .as_ref()
            .map(SourceCleanupCause::as_error)
    }

    pub(crate) fn first(&self) -> &C {
        &self.first
    }

    /// Moves all actual causes only after the exact World return completed.
    pub(crate) fn into_causes(
        self,
    ) -> Result<
        (
            C,
            Option<SourceCleanupCause>,
            Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
        ),
        Self,
    > {
        if !self.physically_closed {
            return Err(self);
        }
        Ok((self.first, self.cleanup_failure, self.cleanup_post))
    }

    /// Advances only the exact never-born branch under its saved World Cleanup.
    pub(crate) fn retry(&mut self) -> Result<bool, &'static str> {
        if self.physically_closed {
            return Ok(true);
        }
        let world = self
            .pending
            .as_ref()
            .and_then(|pending| pending.world.as_ref())
            .or_else(|| self.returning.as_ref().map(|returning| &returning.world))
            .ok_or("same World cleanup loan is absent")?;
        let cleanup = match world.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                self.cleanup_failure
                    .get_or_insert(SourceCleanupCause::Body(first));
                return Err("same World Cleanup admission remains refused");
            }
        };
        let (result, post) = observe_world_cleanup(&cleanup, || self.retry_under_cleanup(&cleanup));
        if let Err(first) = post {
            self.cleanup_post.get_or_insert(first);
        }
        // Physical return precedes the post-check. A negative post belongs to
        // history and must not replay an abort after its World was removed.
        if self.physically_closed {
            Ok(true)
        } else {
            result
        }
    }

    fn retry_under_cleanup(
        &mut self,
        cleanup: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<bool, &'static str> {
        check_world_cleanup(cleanup, &mut self.cleanup_failure)?;
        if let Some(pending) = self.pending.as_mut() {
            // A returned guard, metadata preparation or accepted cell requires
            // the ordinary retained cleanup path, never a no-birth shortcut.
            if pending.returned_guard.is_some()
                || pending.generation_storage.is_some()
                || pending.reservation.is_some()
                || pending.first_failure.is_some()
            {
                return Err("pending Source requires retained member cleanup");
            }
            let (Some(factory), Some(world), Some(controls)) =
                (&pending.factory, &pending.world, &pending.controls)
            else {
                return Err("pending Source retains incomplete return custody");
            };
            if let Err(first) = factory.verify_unborn_native_world(world, controls) {
                self.cleanup_failure
                    .get_or_insert(SourceCleanupCause::Native(first));
                return Err("same factory cannot prove the Source never began");
            }
            check_world_cleanup(cleanup, &mut self.cleanup_failure)?;
            let Some(mut pending) = self.pending.take() else {
                return Err("same pending Source body is absent");
            };
            let (factory, world, controls) = match (
                pending.factory.take(),
                pending.world.take(),
                pending.controls.take(),
            ) {
                (Some(factory), Some(world), Some(controls)) => (factory, world, controls),
                (factory, world, controls) => {
                    pending.factory = factory;
                    pending.world = world;
                    pending.controls = controls;
                    self.pending = Some(pending);
                    return Err("same pending Source return fields are absent");
                }
            };
            // Retain the return journal before destroying the actual Box and
            // its preborn empty API carrier. A destructor unwind leaves this
            // same journal uncertain and cannot certify body destruction.
            self.returning = Some(UnbornWorldReturn {
                factory,
                world,
                controls,
                body_destroyed: false,
            });
            drop(pending);
            if let Some(returning) = self.returning.as_mut() {
                returning.body_destroyed = true;
            }
        }
        check_world_cleanup(cleanup, &mut self.cleanup_failure)?;
        let Some(returning) = self.returning.as_mut() else {
            return Err("same unborn World return journal is absent");
        };
        if !returning.body_destroyed {
            return Err("pending Source body destruction remains uncertain");
        }
        if let Err(first) = returning.controls.close_after_owner_destruction() {
            self.cleanup_failure
                .get_or_insert(SourceCleanupCause::Body(first));
            return Err("same containing body lease remains retained");
        }
        check_world_cleanup(cleanup, &mut self.cleanup_failure)?;
        if let Err(first) = returning
            .factory
            .abort_unborn_native_world(&returning.world)
        {
            self.cleanup_failure
                .get_or_insert(SourceCleanupCause::Native(first));
            return Err("same unborn World assignment remains retained");
        }
        self.physically_closed = true;
        Ok(true)
    }
}

/// Observes the same entered Cleanup after either attempt result.
fn observe_world_cleanup<T>(
    cleanup: &crucible_linux_resource::host_supervision::HostOperationGuard,
    attempt: impl FnOnce() -> T,
) -> (
    T,
    Result<(), crucible_linux_resource::host_supervision::HostSupervisionError>,
) {
    let result = attempt();
    let post = cleanup.wait_slice().map(|_| ());
    (result, post)
}

fn check_world_cleanup(
    cleanup: &crucible_linux_resource::host_supervision::HostOperationGuard,
    first: &mut Option<SourceCleanupCause>,
) -> Result<(), &'static str> {
    if let Err(source) = cleanup.wait_slice() {
        first.get_or_insert(SourceCleanupCause::Body(source.into()));
        return Err("same World Cleanup no longer permits return effects");
    }
    Ok(())
}

impl<F> crucible_api::ProductionVmCleanupOwner for PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    type Failure = crate::ProductionVmConstructionCleanupError;

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
        if self.physically_closed {
            return Ok(());
        }
        if self.controls.is_some() {
            return Err((launcher_message(
                "unreserved World body remains retained; consuming never-born return is required",
            ))
            .into());
        }
        let factory = self
            .factory
            .as_mut()
            .ok_or_else(|| launcher_message("pending Source lost its actual factory"))?;
        let members = if self.members_closed {
            Ok(())
        } else {
            let world = self
                .world
                .as_ref()
                .ok_or_else(|| launcher_message("same pending World cleanup loan is absent"))?;
            factory.retry_native_world_construction(world)
        };
        match members {
            Ok(()) => {
                self.members_closed = true;
                if let Some(guard) = self.returned_guard.as_mut() {
                    guard.finish()?;
                }
                self.returned_guard = None;
                self.generation_storage = None;
                self.physically_closed = true;
                Ok(())
            }
            Err(source) => {
                self.record_first(source);
                Err((launcher_message(format!(
                    "same World construction cleanup remains retained: {}",
                    self.first_failure
                        .as_ref()
                        .map_or("unknown refusal".to_owned(), ToString::to_string),
                )))
                .into())
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
            Option<
                Box<
                    dyn ProductionVmCleanupReservation<
                        Failure = crate::ProductionVmConstructionCleanupError,
                    >,
                >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>,
            >,
        )>,
    >,
}

impl<C: std::error::Error + Send + Sync + 'static> SourceConstructionCustodyFailure<C> {
    fn new(
        source: C,
        reservation: Option<
            Box<
                dyn ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                >,
            >,
        >,
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>,
        >,
    ) -> Self {
        Self {
            source,
            custody: Mutex::new(Some((reservation, owner))),
        }
    }

    /// Moves the original typed cause from an empty published error shell.
    ///
    /// This extracts history only. Publication and diagnostic extraction never
    /// certify physical cleanup; the exact handoff receipt owns that proof.
    ///
    /// # Errors
    /// Returns the same complete error if it still holds an owner/token or its
    /// publication storage is poisoned. No diagnostic clone or new body is made.
    pub fn into_published_error(mut self) -> Result<C, Self> {
        let Ok(owned) = self.custody.get_mut() else {
            return Err(self);
        };
        if owned.is_some() {
            return Err(self);
        }
        Ok(self.source)
    }

    /// Retries only custody publication through the exact reserved token.
    ///
    /// # Errors
    /// Keeps both fields on absent-token, poisoned, or exact-cell refusal.
    /// Expiry never manufactures Cleanup authority and is not consulted here.
    pub fn retry_publication(
        &mut self,
    ) -> Result<
        Option<
            Box<
                dyn crucible_api::ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                    >,
            >,
        >,
        &'static str,
    > {
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
    reservation: Option<
        Box<
            dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
            >,
        >,
    >,
    owner: Box<dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>>,
    source: C,
) -> Result<
    (
        C,
        Box<
            dyn crucible_api::ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                >,
        >,
    ),
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

#[cfg(test)]
mod published_error_tests {
    use super::*;

    fn first() -> QemuVmRealizationError {
        QemuVmRealizationError::ExecutorUnavailable {
            operation: "component original Source refusal",
            message: String::from("typed cause"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unclosed_return_keeps_both_error_allocations_on_extraction_refusal() {
        type Factory = crate::ComposedQemuAttemptResourceGuardFactory<
            crate::LinuxQemuAttemptHostResourceFactory,
        >;
        // Unissued transport fixture: no Pending Box, World or factory is
        // constructed, and no physical-closure fact is fabricated.
        let first = first();
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &first else {
            panic!("unexpected original variant");
        };
        let first_pointer = message.as_ptr();
        let cleanup_message = String::from("actual body return refusal");
        let cleanup_pointer = cleanup_message.as_ptr();
        let holder = UnbornSourceConstruction::<Factory> {
            pending: None,
            returning: None,
            first,
            cleanup_failure: Some(SourceCleanupCause::Body(
                crucible_linux_resource::host_services::process_birth::ServiceBirthError::Policy(
                    cleanup_message,
                ),
            )),
            cleanup_post: None,
            physically_closed: false,
        };

        let retained = holder.into_causes().unwrap_err();
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = retained.first() else {
            panic!("original cause was replaced");
        };
        assert_eq!(message.as_ptr(), first_pointer);
        let cleanup = retained.cleanup_failure().unwrap()
            .downcast_ref::<crucible_linux_resource::host_services::process_birth::ServiceBirthError>().unwrap();
        let crucible_linux_resource::host_services::process_birth::ServiceBirthError::Policy(
            message,
        ) = cleanup
        else {
            panic!("body cause was replaced");
        };
        assert_eq!(message.as_ptr(), cleanup_pointer);
        assert!(!retained.physically_closed);
    }

    #[test]
    fn same_cleanup_post_is_observed_after_an_initiating_refusal() {
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
            HostSupervisionError,
        };

        // Actual entered Cleanup, without a Main/World/native admission claim.
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let cleanup = original.begin_original_cleanup_control().unwrap();
        let mut primary = None;
        check_world_cleanup(&cleanup, &mut primary).unwrap();
        let initiating = first();
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &initiating else {
            panic!("unexpected initiating variant");
        };
        let initiating_pointer = message.as_ptr();

        let (attempt, post) = observe_world_cleanup(&cleanup, || {
            cleanup.complete().unwrap();
            Err::<(), _>(initiating)
        });

        let initiating = attempt.unwrap_err();
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &initiating else {
            panic!("initiating cause was replaced");
        };
        assert_eq!(message.as_ptr(), initiating_pointer);
        assert_eq!(
            post,
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Completed,
            })
        );
        assert!(primary.is_none());
    }

    #[test]
    fn terminal_saved_cleanup_refuses_effects_and_still_has_independent_post() {
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
        };

        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let cleanup = original.begin_original_cleanup_control().unwrap();
        cleanup.complete().unwrap();
        let mut first = None;
        let mut effects = 0;

        let (attempt, post) = observe_world_cleanup(&cleanup, || {
            check_world_cleanup(&cleanup, &mut first)?;
            effects += 1;
            Ok::<(), &'static str>(())
        });

        assert!(attempt.is_err());
        assert!(post.is_err());
        assert_eq!(effects, 0);
        assert!(matches!(first, Some(SourceCleanupCause::Body(
            crucible_linux_resource::host_services::process_birth::ServiceBirthError::Supervision(_)
        ))));
    }

    #[test]
    fn published_empty_shell_moves_original_native_error() {
        // Diagnostic-only shell; no Main/Source/operation is constructed.
        let shell = SourceConstructionCustodyFailure {
            source: first(),
            custody: Mutex::new(None),
        };
        let moved = shell.into_published_error().unwrap();
        assert!(
            matches!(moved, QemuVmRealizationError::ExecutorUnavailable { operation, message }
            if operation == "component original Source refusal" && message == "typed cause")
        );
    }

    #[test]
    fn unpublished_body_keeps_same_native_error_and_owner() {
        let shell = SourceConstructionCustodyFailure {
            source: first(),
            custody: Mutex::new(Some((
                None,
                Box::new(crate::ProductionVmConstructionCustody::new()),
            ))),
        };
        let mut retained = shell.into_published_error().unwrap_err();
        assert!(retained.custody.get_mut().unwrap().is_some());
        assert!(
            matches!(retained.source, QemuVmRealizationError::ExecutorUnavailable { operation, .. }
            if operation == "component original Source refusal")
        );
    }
}

/// Publishes normal disposal without constructing a speculative first error.
pub(crate) fn publish_source_owner(
    reservation: Option<
        Box<
            dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
            >,
        >,
    >,
    owner: Box<dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>>,
) -> Result<
    Box<
        dyn crucible_api::ProductionVmCleanupHandoff<
                Failure = crate::ProductionVmConstructionCleanupError,
            >,
    >,
    SourceConstructionCustodyFailure,
> {
    let Some(reservation) = reservation else {
        return Err(SourceConstructionCustodyFailure::new(
            missing_pending("same Source observation has no authentic reservation"),
            None,
            owner,
        ));
    };
    match reservation.retain(owner) {
        Ok(handoff) => Ok(handoff),
        Err((reservation, owner)) => Err(SourceConstructionCustodyFailure::new(
            missing_pending("same Source observation publication remains refused"),
            Some(reservation),
            owner,
        )),
    }
}
