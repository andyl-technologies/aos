//! Attempt-owned launch authority and dispatch for production QEMU generations.

use super::*;

/// Attempt-owned authority for every QEMU generation in one production lifecycle.
///
/// Implementations may install cgroup, filesystem-quota, cancellation, and
/// process-reap ownership before delegating to the packaged QEMU launcher. An
/// error return must leave no unowned child process. The lifecycle retains this
/// authority for modeled crash/restart replacements instead of bypassing it
/// after the initial generation. Implementations must also retain or transfer
/// containment authority from their `Drop` path when lifecycle construction,
/// unwinding, or caller abandonment prevents an explicit [`Self::finish`].
pub trait ProductionVmNodeLauncher:
    ProductionVmCleanupOwner<
        Failure = crate::ProductionVmConstructionCleanupError,
        PostBody = crate::ProductionVmConstructionPostBody,
    >
{
    /// Moves the same existing World return loan into durable Source retirement.
    ///
    /// This creates no loan or Original. Source custody must already bar work
    /// and retain the whole body before effects; absence cannot prove return.
    #[cfg(target_os = "linux")]
    fn take_source_world_cleanup_loan(
        &mut self,
    ) -> Option<
        crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    > {
        None
    }

    /// Copies only the original Main selection retained by this actual launcher.
    ///
    /// The selector carries no process, Target or cleanup permission. Absence
    /// cannot prove physical return or authorize an alternate native producer.
    #[cfg(target_os = "linux")]
    fn prepared_source_selector(&self) -> Option<crate::PreparedSourceSelector> {
        None
    }

    /// Moves the exact cleanup reservation without claiming physical return.
    #[cfg(target_os = "linux")]
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
        None
    }

    /// Moves the storage admitted before this launcher's first Source effects.
    ///
    /// The empty carrier supplies custody only. It issues no operation,
    /// original, process or cleanup authority. Missing storage refuses
    /// construction while preserving every incoming owner in the error.
    fn take_construction_custody(&mut self) -> Option<Box<ProductionVmConstructionCustody>> {
        None
    }

    /// Reports retained physical target custody before source cleanup.
    #[cfg(target_os = "linux")]
    fn fork_target_is_owned(&self) -> bool {
        false
    }

    /// Checks that existing Target rows belong to this exact Source registry.
    ///
    /// This observation issues no native role or allocation permission. The
    /// real producer repeats its containing Main and actual permit checks.
    fn matches_target_construction_storage(
        &self,
        _storage: &crate::qemu_lifecycle_launcher::TargetConstructionStorage,
    ) -> bool {
        false
    }

    /// Moves the Source's prepaid selected Target storage into one constructor.
    ///
    /// # Errors
    /// Refuses launchers without the actual Source storage or while it is lent.
    fn take_target_construction_storage(
        &mut self,
    ) -> Result<crate::qemu_lifecycle_launcher::TargetConstructionStorage, LifecycleApiError> {
        Err(loop_factory_error(
            "launcher has no prepaid Target construction storage",
        ))
    }

    /// Moves rows already prepared for return outside the Source mutex.
    ///
    /// # Errors
    /// Preserves rows when exact registry/vacancy or the completed metadata
    /// preparation does not match. This operation performs no cleanup or IO.
    fn return_prepared_target_construction_storage(
        &mut self,
        storage: crate::qemu_lifecycle_launcher::TargetConstructionStorage,
    ) -> Result<(), crate::qemu_lifecycle_launcher::TargetConstructionStorage> {
        Err(storage)
    }

    /// Restores only unused or already-returned storage to its original Source.
    ///
    /// # Errors
    /// Returns the same storage if this launcher cannot accept it or its native
    /// loans still retain physical Target ownership.
    fn return_target_construction_storage(
        &mut self,
        storage: crate::qemu_lifecycle_launcher::TargetConstructionStorage,
    ) -> Result<(), crate::qemu_lifecycle_launcher::TargetConstructionStorage> {
        Err(storage)
    }

    /// Copies actual World coordinates for selected Target routing only.
    ///
    /// # Errors
    /// Refuses a launcher without an actual selected native World.
    #[cfg(target_os = "linux")]
    fn native_world_identity(
        &self,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        crucible_qemu_host::QemuVmRealizationError,
    > {
        Err(
            crucible_qemu_host::QemuVmRealizationError::ExecutorUnavailable {
                operation: "observe retained native Source World identity",
                message: String::from("launcher has no selected native Source World"),
            },
        )
    }

    /// Lends only the selected Source member's genuine Target permit.
    ///
    /// # Errors
    /// Refuses a launcher without matching actual per-node Source ownership.
    #[cfg(target_os = "linux")]
    fn prepare_fork_target_for_node(
        &mut self,
        _node: &NodeId,
    ) -> Result<
        crucible_qemu_host::QemuForkTargetPreparation,
        crate::qemu_lifecycle_launcher::TargetPreparationFailure,
    > {
        Err(loop_factory_error("launcher has no genuine source target issuer").into())
    }

    /// Lends the genuine source owner's single same-family target permit.
    ///
    /// # Errors
    /// Refuses launchers without actual source ownership or a free target slot.
    #[cfg(target_os = "linux")]
    fn prepare_fork_target(
        &mut self,
    ) -> Result<
        crucible_qemu_host::QemuForkTargetPreparation,
        crate::qemu_lifecycle_launcher::TargetPreparationFailure,
    > {
        Err(loop_factory_error("launcher has no genuine source target issuer").into())
    }

    /// Prepares a target generation beneath the source's retained project quota.
    ///
    /// # Errors
    /// Refuses missing source storage, a foreign target contract or preparation.
    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory(
        &mut self,
        _target_contract: &crucible_qemu_host::QemuChildProcessContract,
        _requirements: crucible_qemu_host::QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        Err(loop_factory_error(
            "launcher has no genuine source storage owner",
        ))
    }

    /// Reports exclusion by a retained park owner, without issuing phase authority.
    ///
    /// Complete source-world operations use this negative gate before touching
    /// any installed Node or launcher. Implementations keep it set on refusal.
    fn parent_park_drain_is_owned(&self) -> bool {
        false
    }

    /// Invokes a fixed later phase while the complete lifecycle retains its source.
    ///
    /// # Errors
    /// Refuses an absent authentic factory/host/original route or retained cause.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn parent_park_drain(
        &mut self,
        _source: &mut crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        _request: ProductionVmParentParkDrainRequest<'_>,
    ) -> Result<crucible_qemu_host::QmpParentParkResult, ProductionVmParentParkDrainRefusal> {
        Err(ProductionVmParentParkDrainRefusal::Unavailable(
            "launcher has no original park issuer",
        ))
    }

    /// Transfers the actual containing attempt into its existing quarantine.
    ///
    /// The complete source and phase credit remain retained independently of
    /// cleanup; this does not attest reap, native disposition or resource refund.
    ///
    /// # Errors
    /// Refuses a launcher without the fixed actual-owner containment route.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn contain_parent_park_drain(&mut self) -> Result<(), ProductionVmParentParkDrainRefusal> {
        Err(ProductionVmParentParkDrainRefusal::Unavailable(
            "launcher has no original containment route",
        ))
    }

    /// Borrows the retained typed phase cause without exposing physical authority.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn parent_park_drain_failure(&self) -> Option<ProductionVmParentParkDrainFailure<'_>> {
        None
    }

    /// Admits one scheduler quantum under the retained attempt authority.
    ///
    /// Attempt-scoped launchers use this boundary to check sticky cancellation
    /// and atomically charge the aggregate execution-quantum ceiling before any
    /// scheduler, host-fault, or guest state can advance. The packaged launcher
    /// has no external attempt contract and therefore uses the default no-op.
    /// A failed admission must not consume modeled state or begin guest work.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] after cancellation, resource exhaustion,
    /// or loss of the retained attempt authority.
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError>;

    /// Checks the retained attempt authority after one scheduler quantum.
    ///
    /// This post-boundary check makes cancellation or host-enforcement failure
    /// that raced the final guest operation observable before the lifecycle
    /// returns its modeled outcome. The packaged launcher uses the default
    /// no-op because it has no external attempt contract.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the attempt became canceled or its
    /// resource enforcement can no longer be authenticated.
    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError>;

    /// Launches one freshly provisioned node generation.
    ///
    /// Before spawning any process, the implementation creates the generation
    /// run directory and performs the operation-specific artifact preparation
    /// under the same aggregate storage, cancellation, and cleanup authority.
    /// Success returns the node and a linear containment lease whose identity
    /// exactly matches the request. The lifecycle retains that lease until the
    /// corresponding child has been reaped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when admission, namespace or artifact
    /// preparation, process launch, or post-launch authentication fails. The
    /// implementation must retain or clean every
    /// partial artifact and retain or reap every process it may have spawned
    /// before returning.
    fn launch_fresh(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        qemu_executable: &Path,
        root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError>;

    /// Launches one descriptor-backed exact node generation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when exact artifact materialization,
    /// process launch, restore, or post-launch authentication fails.
    fn launch_restored(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError>;

    /// Imports a freshly captured terminal checkpoint into this attempt's
    /// authenticated repository and returns its one-shot restore admissions.
    ///
    /// The launcher must retain the published root as process-contract
    /// authority for every successor launched from the returned checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] if publication, authentication, or root
    /// ownership cannot be completed under the current attempt.
    fn prepare_terminal_exact_checkpoint(
        &mut self,
        _closure: ProductionExactCheckpointClosure,
    ) -> Result<DecodedProductionExactCheckpoint, LifecycleApiError> {
        Err(loop_factory_error(
            "production launcher has no terminal exact-checkpoint import authority",
        ))
    }

    /// Creates an independent authority for whole-world debugger replay.
    ///
    /// An attempt-scoped implementation may reject this operation when its
    /// resource contract cannot admit a second world. It must never silently
    /// substitute an unguarded launcher.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when replay process authority cannot be
    /// allocated under the same containment policy.
    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError>;

    /// Finalizes process-containment ownership after lifecycle node shutdown.
    ///
    /// The lifecycle calls this method after asking every retained QEMU node to
    /// shut down. Implementations must make it idempotent. Success attests that
    /// no child remains and that attempt resources may be released. An error
    /// must retain or transfer all remaining authority to quarantine. Dropping
    /// the authority without calling this method must provide the same
    /// fail-closed ownership transfer, without claiming resource release.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when reap or containment release cannot be
    /// attested. The caller reports this failure even when node shutdown also
    /// failed.
    fn finish(&mut self) -> Result<(), ProductionVmConstructionCleanupError>;
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PackagedProductionVmNodeLauncher;

#[cfg(any(test, feature = "test-support"))]
impl crucible_control_api::ProductionVmCleanupOwner for PackagedProductionVmNodeLauncher {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        // This component launcher owns no native World or Service return.
        Ok(None)
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ProductionVmNodeLauncher for PackagedProductionVmNodeLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _qemu_executable: &Path,
        _root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production replay authority",
        ))
    }

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        Ok(())
    }
}

pub(super) fn launch_production_node_generation(
    launcher: &mut dyn ProductionVmNodeLauncher,
    basis: ProductionVmNodeLaunchBasis<'_>,
    crash_detector: &str,
    preparation: ProductionVmNodePreparationKind<'_>,
    kind: ProductionVmNodeLaunchKind,
) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
    ProductionVmNodeGeneration::new(basis.node.clone(), basis.generation)?;
    let request = ProductionVmNodeLaunchRequest::new(basis, "crucible-router", crash_detector);
    match (preparation, kind) {
        (
            ProductionVmNodePreparationKind::Fresh {
                qemu_executable,
                root_image,
            },
            ProductionVmNodeLaunchKind::Fresh,
        ) => launcher.launch_fresh(request, qemu_executable, root_image),
        (ProductionVmNodePreparationKind::Exact, ProductionVmNodeLaunchKind::Exact(admission)) => {
            launcher.launch_restored(request, *admission)
        }
        _ => Err(loop_factory_error(
            "production QEMU node preparation does not match its launch operation",
        )),
    }
}
