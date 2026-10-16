//! Attempt-owned guarded launcher for the production VM lifecycle.
//!
//! This adapter is the daemon-side owner of the API lifecycle's linear QEMU
//! generations. It admits and pins fresh generation directories, runs image
//! tools under the attempt contract, streams repository checkpoints, and lends
//! the sealed process contract only after preparation. Any unreaped QEMU or
//! helper child is transferred into the aggregate guard before an error returns.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crucible_api::{
    DecodedProductionExactCheckpoint, LifecycleApiError, ProductionExactCheckpointClosure,
    ProductionVmExactNodeRestoreAdmission, ProductionVmNodeGeneration, ProductionVmNodeLaunch,
    ProductionVmNodeLaunchRequest, ProductionVmNodeLauncher, ProductionVmNodeLease,
};
use crucible_qemu::{
    QemuChildProcessContract, QemuLiveNodeIdentity, QemuNode, QemuPreparedRunDirectory,
    QemuProductionFreshLaunchAdmission,
};

use crate::{
    ExactCheckpointStore, ExecutionCancellation, QemuAttemptGenerationLease,
    QemuAttemptGenerationResourceOwner, QemuAttemptProcessResourceGuard,
};

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
mod parent_park_drain;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub(crate) use parent_park_drain::OriginalParkDrainDisposition;

mod pending_construction;
pub(crate) use pending_construction::retain_source_owner;
mod failed_launch;
use failed_launch::RetainedFailedLaunch;
pub(crate) use pending_construction::PendingSourceConstruction;
pub use pending_construction::SourceConstructionCustodyFailure;

struct TerminalCheckpointImport {
    checkpoints: Arc<ExactCheckpointStore>,
    source: crucible::ScenarioDefForm,
    cancellation: ExecutionCancellation,
    published_root: Option<crucible::ContentHash>,
    _decode_custody: Option<crucible::owned_decode::DecodeCustody>,
}

/// Guarded production lifecycle launcher for one admitted QEMU attempt.
#[must_use = "finish the lifecycle launcher or transfer its aggregate owner to quarantine"]
pub(crate) struct QemuAttemptProductionVmNodeLauncher<G, F = ()>
where
    G: QemuAttemptProcessResourceGuard,
{
    // Retire this issuer alias before the actual containing generation owner.
    pub(crate) park_drain_registration:
        Option<crate::qemu_campaign_lifecycle::ConfiguredParkDrainRegistration>,
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    parent_park_phase: Option<parent_park_drain::OriginalParkDrainPhase>,
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    parent_park_disposition: Option<OriginalParkDrainDisposition>,
    // A real shared factory facade is inline: retaining it clones only its
    // existing host Arc. The field itself exposes no permit or process contract.
    fork_target_factory: Option<F>,
    cleanup_reservation: Option<Box<dyn crucible_api::ProductionVmCleanupReservation>>,
    construction_custody: Option<Box<crucible_api::ProductionVmConstructionCustody>>,
    failed_launch: Option<RetainedFailedLaunch>,
    owner: QemuAttemptGenerationResourceOwner<G>,
    run_directories: Arc<Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>>,
    image_helpers: Arc<Mutex<ImageHelperCleanupDebt>>,
    terminal_checkpoint: Option<TerminalCheckpointImport>,
}

impl<G> QemuAttemptProductionVmNodeLauncher<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Wraps an owner without manufacturing a same-family target consumer.
    pub(crate) fn new(owner: QemuAttemptGenerationResourceOwner<G>) -> Self {
        Self::with_fork_target_factory(owner, None)
    }
}

impl<G, F> QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Retains the factory selected by the actual Source construction path.
    pub(crate) fn with_fork_target_factory(
        owner: QemuAttemptGenerationResourceOwner<G>,
        fork_target_factory: Option<F>,
    ) -> Self {
        Self {
            park_drain_registration: None,
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            parent_park_phase: None,
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            parent_park_disposition: None,
            fork_target_factory,
            cleanup_reservation: None,
            construction_custody: None,
            failed_launch: None,
            owner,
            run_directories: Arc::new(Mutex::new(BTreeMap::new())),
            image_helpers: Arc::new(Mutex::new(ImageHelperCleanupDebt::default())),
            terminal_checkpoint: None,
        }
    }

    /// Binds the same configured family before the launcher enters its lifecycle.
    pub(crate) fn new_registered(
        owner: QemuAttemptGenerationResourceOwner<G>,
        park_drain_registration: crate::qemu_campaign_lifecycle::ConfiguredParkDrainRegistration,
        fork_target_factory: Option<F>,
    ) -> Self {
        let mut launcher = Self::with_fork_target_factory(owner, fork_target_factory);
        launcher.park_drain_registration = Some(park_drain_registration);
        launcher
    }

    /// Returns the actual boxed Source-launcher extent before its allocation.
    ///
    /// The containing Main pool must debit this extent for every simultaneous
    /// Source launcher. The result is a request size, never allocation credit.
    ///
    /// # Errors
    /// Refuses a target whose pointer-sized layout cannot be expressed in bytes.
    pub(crate) fn retained_control_bytes() -> Result<u64, LifecycleApiError> {
        u64::try_from(std::mem::size_of::<Self>())
            .map_err(|_| launcher_message("retained Source launcher extent overflows"))
    }

    /// Measures selected Source construction before any containing allocation.
    ///
    /// Includes the actual launcher Box, inline guard/factory, shared directory
    /// and helper controls, selected generation rows, carrier, and temporary
    /// Pending body. No Target directory is constructed by this Source path;
    /// its later genuine producer must price its own before-birth peak.
    ///
    /// # Errors
    /// Refuses an empty/excessive member set or layout/byte arithmetic overflow.
    pub(crate) fn retained_source_launcher_control_bytes<'a>(
        nodes: impl Clone + Iterator<Item = &'a crucible::NodeId>,
    ) -> Result<u64, LifecycleApiError>
    where
        F: crate::QemuAttemptResourceGuardFactory,
    {
        let generations = crate::QemuAttemptGenerationStorage::control_bytes(nodes.clone())?;
        let directories = launcher_arc_bytes::<
            Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>,
        >()?;
        let helpers = launcher_arc_bytes::<Mutex<ImageHelperCleanupDebt>>()?;
        let pending = pending_construction::PendingSourceConstruction::<F>::control_bytes()?;
        let retained_launcher = Self::retained_control_bytes()?
            .checked_add(directories)
            .and_then(|bytes| bytes.checked_add(helpers))
            .ok_or_else(|| launcher_message("retained Source launcher extent overflow"))?;
        // The emptied Pending Box is destroyed before the concrete launcher
        // Box and shared controls are built. The same carrier and selected
        // generation rows remain live across both phases.
        pending
            .max(retained_launcher)
            .checked_add(generations)
            .and_then(|bytes| {
                bytes.checked_add(crucible_api::ProductionVmConstructionCustody::allocation_bytes())
            })
            .ok_or_else(|| launcher_message("selected Source control extent overflow"))
    }

    /// Moves the exact claimed World's token into the successful launcher.
    pub(crate) fn with_cleanup_reservation(
        mut self,
        reservation: Box<dyn crucible_api::ProductionVmCleanupReservation>,
    ) -> Self {
        self.cleanup_reservation = Some(reservation);
        self
    }

    /// Moves the initialized same construction carrier into the actual launcher.
    pub(crate) fn with_construction_custody(
        mut self,
        custody: Box<crucible_api::ProductionVmConstructionCustody>,
    ) -> Self {
        self.construction_custody = Some(custody);
        self
    }

    /// Installs the selected campaign store for a recoverable terminal restart.
    pub(crate) fn with_terminal_checkpoint_import(
        mut self,
        checkpoints: Arc<ExactCheckpointStore>,
        source: crucible::ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Self {
        self.install_terminal_checkpoint_import(checkpoints, source, cancellation);
        self
    }

    /// Moves already-admitted terminal metadata into the retained boxed owner.
    pub(crate) fn install_terminal_checkpoint_import(
        &mut self,
        checkpoints: Arc<ExactCheckpointStore>,
        source: crucible::ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) {
        self.terminal_checkpoint = Some(TerminalCheckpointImport {
            checkpoints,
            source,
            cancellation,
            published_root: None,
            _decode_custody: crucible::owned_decode::current_custody(),
        });
    }

    #[cfg(target_os = "linux")]
    fn launch_exact_generation(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        admission: ProductionVmExactNodeRestoreAdmission,
        lease: QemuAttemptGenerationLease,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }
        let run_directory = match self.owner.prepare_generation_run_directory_for_node(
            request.node(),
            request.launch().resource_requirements(),
        ) {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let attempt_contract = match self.owner.child_process_contract_for_node(request.node()) {
            Ok(contract) => contract,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let terminal_contract = (|| {
            let Some(terminal) = &self.terminal_checkpoint else {
                return Ok(None);
            };
            let Some(root) = terminal.published_root else {
                return Ok(None);
            };
            if admission.repository_root() != root {
                return Err(launcher_message(
                    "terminal exact restore admission differs from the published campaign root",
                ));
            }
            attempt_contract
                .try_derive_for_exact_checkpoint_root(root)
                .map(Some)
                .map_err(|error| {
                    launcher_message(format!("derive terminal exact process contract: {error}"))
                })
        })();
        let terminal_contract = match terminal_contract {
            Ok(contract) => contract,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let process_contract = terminal_contract.as_ref().unwrap_or(attempt_contract);
        let retained_contract = match process_contract.try_clone_for_attempt_generation() {
            Ok(contract) => contract,
            Err(error) => {
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message(format!("retain exact generation contract: {error}")),
                ));
            }
        };
        let atomic = match admission.into_atomic_restore(request, run_directory, process_contract) {
            Ok(atomic) => atomic,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let (node, run_directory) = match atomic.launch(|restore| {
            self.owner
                .launch_exact_node_for_node(request.node(), restore)
        }) {
            Ok(launched) => launched,
            Err(mut error) => {
                let message = launch_error_chain(&error);
                if let Some(child) = error.take_unreaped_child() {
                    self.owner
                        .retain_failed_launch_child_for_node(request.node(), child);
                    drop(lease);
                    self.owner.quarantine();
                    return Err(launcher_message(format!(
                        "atomic exact restore for `{}` failed and transferred an unreaped child to quarantine: {message}",
                        request.node_name(),
                    )));
                }
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message(format!(
                        "atomic exact restore for `{}` failed after synchronous cleanup: {message}",
                        request.node_name(),
                    )),
                ));
            }
        };
        self.record_launched_generation(
            request,
            lease,
            run_directory,
            node,
            retained_contract,
            run_directories,
        )
    }

    pub(crate) fn with_native_guard<T>(&mut self, apply: impl FnOnce(&mut G) -> T) -> T {
        self.owner.with_guard_mut(apply)
    }

    fn launch_fresh_generation(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        qemu_executable: &std::path::Path,
        root_image: &std::path::Path,
        lease: QemuAttemptGenerationLease,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        if request.launch().qemu_executable() != qemu_executable
            || request.launch().root_image() != Some(root_image)
        {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message(
                    "fresh image-tool inputs do not match the exact QEMU launch profile",
                ),
            ));
        }
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }
        let mut run_directory = match self.owner.prepare_generation_run_directory_for_node(
            request.node(),
            request.launch().resource_requirements(),
        ) {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        let preparation = {
            let process_contract = match self.owner.child_process_contract_for_node(request.node())
            {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            run_directory.prepare_fresh_artifacts_guarded(
                qemu_executable,
                Some(root_image),
                process_contract,
            )
        };
        if let Err(mut error) = preparation {
            let message = launch_error_chain(&error);
            if let Some(child) = error.take_unreaped_child() {
                self.owner
                    .retain_failed_launch_child_for_node(request.node(), child);
                drop(lease);
                self.owner.quarantine();
                return Err(launcher_message(format!(
                    "prepare fresh QEMU node `{}` failed and transferred an unreaped image-tool child to quarantine: {message}",
                    request.node_name(),
                )));
            }
            return Err(abort_unspawned_generation(
                lease,
                launcher_message(format!(
                    "prepare fresh QEMU node `{}` failed after synchronous helper cleanup: {message}",
                    request.node_name(),
                )),
            ));
        }
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }

        let launch = request
            .launch()
            .clone()
            .with_run_directory(run_directory.path());
        let identity = QemuLiveNodeIdentity::new(
            request.node_name(),
            request.router_name(),
            request.crash_detector(),
        );
        let (launched, retained_contract) = {
            let process_contract = match self.owner.child_process_contract_for_node(request.node())
            {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            let retained_contract = match process_contract.try_clone_for_attempt_generation() {
                Ok(contract) => contract,
                Err(error) => {
                    return Err(abort_unspawned_generation(
                        lease,
                        launcher_message(format!("retain fresh generation contract: {error}")),
                    ));
                }
            };
            let launched = QemuProductionFreshLaunchAdmission::admit(
                &launch,
                &run_directory,
                process_contract,
                identity,
            )
            .and_then(|admission| {
                self.owner
                    .launch_fresh_node_for_node(request.node(), &launch, admission)
            });
            (launched, retained_contract)
        };
        let node = match launched {
            Ok(node) => node,
            Err(mut error) => {
                #[cfg(feature = "private-measurement-domain")]
                if let crucible_qemu::QemuLiveNodeStepGateError::OriginalNativeLaunch { source } =
                    error
                {
                    // The original slot already owns this exact prepaid Arc,
                    // including any node created before the independent postcut.
                    // No ordinary error formatting or second shared allocation
                    // may replace that first cause or release its native credit.
                    self.owner.quarantine_original_launch();
                    drop(lease);
                    return Err(LifecycleApiError::BackendConstruction {
                        source: crucible_api::LifecycleBackendConstructionError::from_shared(
                            source,
                        ),
                    });
                }
                let message = launch_error_chain(&error);
                if let Some(child) = error.take_unreaped_child() {
                    self.owner
                        .retain_failed_launch_child_for_node(request.node(), child);
                    drop(lease);
                    self.owner.quarantine();
                    return Err(launcher_message(format!(
                        "launch guarded fresh QEMU node `{}` failed and transferred an unreaped child to quarantine: {message}",
                        request.node_name(),
                    )));
                }
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message(format!(
                        "launch guarded fresh QEMU node `{}` failed after synchronous cleanup: {message}",
                        request.node_name(),
                    )),
                ));
            }
        };

        self.record_launched_generation(
            request,
            lease,
            run_directory,
            node,
            retained_contract,
            run_directories,
        )
    }

    fn record_launched_generation(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        lease: QemuAttemptGenerationLease,
        run_directory: QemuPreparedRunDirectory,
        node: QemuNode,
        process_contract: QemuChildProcessContract,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let generation = lease.identity().clone();
        let run_directory_path = run_directory.path().to_path_buf();
        let prior = run_directories.insert(generation, run_directory);
        debug_assert!(prior.is_none());
        let lease = QemuLifecycleGenerationLease {
            inner: lease,
            run_directories: Arc::clone(&self.run_directories),
            qemu_executable: request.launch().qemu_executable().to_path_buf(),
            process_contract,
            image_helpers: Arc::clone(&self.image_helpers),
            directory_released: false,
        };

        match ProductionVmNodeLaunch::new_in_run_directory(request, run_directory_path, node, lease)
        {
            Ok(launch) => Ok(launch),
            Err((first, launch)) => {
                // Both launch methods exclude an earlier failed pairing before
                // any effects, so this pre-existing slot cannot be overwritten.
                self.failed_launch = Some(RetainedFailedLaunch::new(launch));
                Err(first)
            }
        }
    }

    fn transfer_image_helper_debt(&mut self) {
        let mut debt = self
            .image_helpers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debt.closed = true;

        for (generation, child) in std::mem::take(&mut debt.children) {
            self.owner
                .retain_failed_launch_child_for_node(generation.node(), child);
            debt.transferred.insert(generation);
        }
    }
}

impl<G, F> Drop for QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn drop(&mut self) {
        // Transfer the original wait handles before the aggregate owner's Drop
        // starts quarantine. Its worker keeps retrying reap before quota release.
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if let Some(phase) = self.parent_park_phase.take() {
            // No explicit native disposition exists. Keep both originals,
            // imported descriptors and their credits while the actual owner
            // below enters its existing physical quarantine.
            std::mem::forget(phase);
        }
        self.transfer_image_helper_debt();
    }
}

impl<G, F> ProductionVmNodeLauncher for QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard + Send,
    F: Send,
{
    fn take_construction_custody(
        &mut self,
    ) -> Option<Box<crucible_api::ProductionVmConstructionCustody>> {
        self.construction_custody.take()
    }

    fn take_cleanup_reservation(
        &mut self,
    ) -> Option<Box<dyn crucible_api::ProductionVmCleanupReservation>> {
        self.cleanup_reservation.take()
    }

    #[cfg(target_os = "linux")]
    fn fork_target_is_owned(&self) -> bool {
        self.owner.fork_target_is_owned()
    }

    #[cfg(target_os = "linux")]
    fn lend_fork_target_permit(
        &mut self,
    ) -> Result<crucible_qemu::LinuxQemuForkTargetPermit, LifecycleApiError> {
        self.owner.lend_fork_target_permit()
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: crucible_qemu::QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        self.owner
            .prepare_fork_target_run_directory(target_contract, requirements)
    }

    fn parent_park_drain_is_owned(&self) -> bool {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        {
            self.parent_park_phase.is_some()
        }
        #[cfg(not(all(target_os = "linux", feature = "private-measurement-domain")))]
        {
            false
        }
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn parent_park_drain(
        &mut self,
        source: &mut crucible_qemu::QemuNodeSetPreparedHotForkSource<'_>,
        request: crucible_api::ProductionVmParentParkDrainRequest<'_>,
    ) -> Result<crucible_qemu::QmpParentParkResult, crucible_api::ProductionVmParentParkDrainRefusal>
    {
        self.invoke_parent_park_drain(source, request)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn contain_parent_park_drain(
        &mut self,
    ) -> Result<(), crucible_api::ProductionVmParentParkDrainRefusal> {
        // Use the actual containing guard's existing kill/reap quarantine.
        // Its owner stays inside the complete lifecycle; phase custody below
        // is not refunded by this transfer or by a scalar successful return.
        self.transfer_image_helper_debt();
        self.owner.quarantine_original_launch();
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn parent_park_drain_failure(
        &self,
    ) -> Option<crucible_api::ProductionVmParentParkDrainFailure<'_>> {
        self.parent_park_phase.as_ref().map(|phase| phase.failure())
    }

    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_phase.is_some() {
            return Err(LifecycleApiError::ParentParkHeld);
        }
        self.owner.charge_execution_quantum()
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        self.owner.check_operational_boundary()
    }

    fn prepare_terminal_exact_checkpoint(
        &mut self,
        closure: ProductionExactCheckpointClosure,
    ) -> Result<DecodedProductionExactCheckpoint, LifecycleApiError> {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_phase.is_some() {
            return Err(LifecycleApiError::ParentParkHeld);
        }
        self.owner.check_operational_boundary()?;
        let terminal = self.terminal_checkpoint.as_mut().ok_or_else(|| {
            launcher_message("terminal exact checkpoint has no selected campaign store")
        })?;
        terminal.published_root = None;

        let prepared = terminal
            .checkpoints
            .prepare_terminal_production_closure(closure, &terminal.cancellation)
            .map_err(|error| launcher_message(format!("prepare terminal checkpoint: {error}")))?;
        let publication = terminal
            .checkpoints
            .publish_production_closure(&prepared)
            .map_err(|error| launcher_message(format!("publish terminal checkpoint: {error}")))?;
        let loaded = terminal
            .checkpoints
            .load_production_closure_with_cancellation(publication.root(), &terminal.cancellation)
            .map(Arc::new)
            .map_err(|error| launcher_message(format!("load terminal checkpoint: {error}")))?;
        let decoded = terminal
            .checkpoints
            .decode_semantic_checkpoint(&loaded, &terminal.source, &terminal.cancellation)
            .map_err(|error| launcher_message(format!("decode terminal checkpoint: {error}")))?;
        self.owner.check_operational_boundary()?;
        terminal.published_root = Some(crucible::ContentHash {
            bytes: publication.root().content_id().digest(),
        });
        Ok(decoded)
    }

    fn launch_fresh(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        qemu_executable: &std::path::Path,
        root_image: &std::path::Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        if self.failed_launch.is_some() {
            return Err(launcher_message(
                "a refused QEMU pairing retains generation cleanup",
            ));
        }
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_phase.is_some() {
            return Err(LifecycleApiError::ParentParkHeld);
        }
        let identity =
            ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
        let lease = self.owner.register_generation(identity.clone())?;
        let run_directories = Arc::clone(&self.run_directories);
        let mut run_directories = match run_directories.lock() {
            Ok(run_directories) => run_directories,
            Err(_) => {
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message("QEMU generation run-directory registry is poisoned"),
                ));
            }
        };
        if run_directories.contains_key(&identity) {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message("QEMU generation already retains a run-directory authority"),
            ));
        }

        self.launch_fresh_generation(
            request,
            qemu_executable,
            root_image,
            lease,
            &mut run_directories,
        )
    }

    fn launch_restored(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        if self.failed_launch.is_some() {
            return Err(launcher_message(
                "a refused QEMU pairing retains generation cleanup",
            ));
        }
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_phase.is_some() {
            return Err(LifecycleApiError::ParentParkHeld);
        }
        let identity =
            ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
        let lease = self.owner.register_generation(identity.clone())?;
        let run_directories = Arc::clone(&self.run_directories);
        let mut run_directories = match run_directories.lock() {
            Ok(run_directories) => run_directories,
            Err(_) => {
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message("QEMU generation run-directory registry is poisoned"),
                ));
            }
        };
        if run_directories.contains_key(&identity) {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message("QEMU generation already retains a run-directory authority"),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            self.launch_exact_generation(request, admission, lease, &mut run_directories)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (admission, run_directories);
            Err(abort_unspawned_generation(
                lease,
                launcher_message("exact restore requires descriptor-backed paged state on Linux"),
            ))
        }
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(launcher_message(
            "attempt resource contract does not admit an independent debugger replay world",
        ))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_phase.is_some() {
            return Err(LifecycleApiError::ParentParkHeld);
        }
        if let Some(failed) = self.failed_launch.as_mut() {
            failed.finish()?;
        }
        self.failed_launch = None;
        self.transfer_image_helper_debt();
        self.owner.finish()?;
        self.fork_target_factory = None;
        Ok(())
    }
}

/// Shared wait authority survives generation-lease abandonment.
#[derive(Default)]
struct ImageHelperCleanupDebt {
    closed: bool,
    children: BTreeMap<ProductionVmNodeGeneration, crucible_qemu::QemuNodeChild>,
    // Aggregate quarantine owns the wait handle after transfer. An empty local
    // map must not let a retained lease claim that its helper was reaped.
    transferred: BTreeSet<ProductionVmNodeGeneration>,
}

impl ImageHelperCleanupDebt {
    fn retry_generation(
        &mut self,
        generation: &ProductionVmNodeGeneration,
    ) -> Result<(), LifecycleApiError> {
        if self.transferred.contains(generation) {
            return Err(launcher_message(
                "hot-fork image helper cleanup belongs to aggregate quarantine",
            ));
        }
        if let Some(child) = self.children.get_mut(generation) {
            child
                .force_kill_and_reap_failed_helper(std::time::Duration::from_secs(5))
                .map_err(|error| {
                    launcher_message(format!("retry hot-fork image helper cleanup: {error}"))
                })?;
            self.children.remove(generation);
        }
        Ok(())
    }
}

struct QemuLifecycleGenerationLease {
    inner: QemuAttemptGenerationLease,
    run_directories: Arc<Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>>,
    qemu_executable: std::path::PathBuf,
    process_contract: QemuChildProcessContract,
    image_helpers: Arc<Mutex<ImageHelperCleanupDebt>>,
    directory_released: bool,
}

impl ProductionVmNodeLease for QemuLifecycleGenerationLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        self.inner.identity()
    }

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        let run_directories = self
            .run_directories
            .lock()
            .map_err(|_| launcher_message("QEMU generation run-directory registry is poisoned"))?;
        let directory = run_directories.get(self.inner.identity()).ok_or_else(|| {
            launcher_message("QEMU generation lost its retained run-directory authority")
        })?;
        directory
            .open_root_overlay_for_checkpoint()
            .map_err(|error| launcher_message(format!("open pinned checkpoint overlay: {error}")))
    }

    fn open_hot_fork_vmstate(&self) -> Result<std::fs::File, LifecycleApiError> {
        let run_directories = self
            .run_directories
            .lock()
            .map_err(|_| launcher_message("QEMU generation run-directory registry is poisoned"))?;
        let directory = run_directories.get(self.inner.identity()).ok_or_else(|| {
            launcher_message("QEMU generation lost its retained run-directory authority")
        })?;
        directory
            .open_vmstate_for_hot_fork()
            .map_err(|error| launcher_message(format!("open pinned hot-fork VMState: {error}")))
    }

    fn prepare_hot_fork_detached_root_overlay(
        &mut self,
        graph_generation: u64,
        virtual_size: u64,
    ) -> Result<(std::fs::File, std::path::PathBuf), LifecycleApiError> {
        // Closing the launcher and creating helper debt serialize under this
        // lock, so cleanup cannot miss a helper launched by a retained lease.
        let mut helper_debt = self
            .image_helpers
            .lock()
            .map_err(|_| launcher_message("QEMU image-helper registry is poisoned"))?;
        if helper_debt.closed {
            return Err(launcher_message("QEMU image-helper owner is terminal"));
        }
        if helper_debt.children.contains_key(self.inner.identity()) {
            return Err(launcher_message(
                "prior hot-fork image helper still owes process cleanup",
            ));
        }
        let run_directories = self
            .run_directories
            .lock()
            .map_err(|_| launcher_message("QEMU generation run-directory registry is poisoned"))?;
        let directory = run_directories.get(self.inner.identity()).ok_or_else(|| {
            launcher_message("QEMU generation lost its retained run-directory authority")
        })?;
        match directory.prepare_hot_fork_detached_root_overlay_guarded(
            &self.qemu_executable,
            &self.process_contract,
            graph_generation,
            virtual_size,
        ) {
            Ok(overlay) => Ok(overlay),
            Err(mut error) => {
                let message = error.to_string();
                if let Some(child) = error.take_unreaped_child() {
                    // An unreaped helper is retained with the source generation.
                    // Its lease must reap it before finishing; abandonment
                    // transfers the original handle to aggregate quarantine.
                    helper_debt
                        .children
                        .insert(self.inner.identity().clone(), child);
                }
                Err(launcher_message(format!(
                    "prepare guarded hot-fork detached overlay: {message}"
                )))
            }
        }
    }

    fn authenticate_hot_fork_overlay_name(
        &self,
        source_pid: u32,
        file: &std::fs::File,
        path: &std::path::Path,
    ) -> Result<std::path::PathBuf, LifecycleApiError> {
        let directories = self
            .run_directories
            .lock()
            .map_err(|_| launcher_message("QEMU generation run-directory registry is poisoned"))?;
        let directory = directories.get(self.inner.identity()).ok_or_else(|| {
            launcher_message("QEMU generation lost its retained run-directory authority")
        })?;
        directory
            .authenticate_hot_fork_overlay_name(source_pid, file, path)
            .map_err(|error| {
                launcher_message(format!(
                    "authenticate hot-fork source cwd and overlay: {error}"
                ))
            })
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.image_helpers
            .lock()
            .map_err(|_| launcher_message("QEMU image-helper registry is poisoned"))?
            .retry_generation(self.inner.identity())?;
        if !self.directory_released {
            let mut run_directories = self.run_directories.lock().map_err(|_| {
                launcher_message("QEMU generation run-directory registry is poisoned")
            })?;
            if std::env::var_os("CRUCIBLE_RR_CLAMP_TAIL").is_some() {
                let identity = self.inner.identity();
                let trace = run_directories
                    .get(identity)
                    .ok_or_else(|| {
                        launcher_message(
                            "QEMU generation lost its retained run-directory authority",
                        )
                    })?
                    .summarize_rr_control_boundary_trace_after_reap();
                match trace {
                    Ok(summary) => {
                        for (index, row) in summary.lines().enumerate() {
                            if index == 0 {
                                // crucible-lint: allow direct-diagnostic -- record the authenticated full-file digest and row count.
                                eprintln!(
                                    "CRUCIBLE-RR-CLAMP-TAIL-V2 node={} generation={} authenticated_full=true {row}",
                                    identity.node().name,
                                    identity.generation(),
                                );
                            } else {
                                // crucible-lint: allow direct-diagnostic -- retain only the last 32 parsed control rows per node.
                                eprintln!(
                                    "CRUCIBLE-RR-CLAMP-ROW-V2 node={} {row}",
                                    identity.node().name
                                );
                            }
                        }
                    }
                    Err(error) => {
                        // crucible-lint: allow direct-diagnostic -- a failed trace admission must remain visible.
                        eprintln!(
                            "CRUCIBLE-RR-CLAMP-TAIL-V2 node={} generation={} error={error}",
                            identity.node().name,
                            identity.generation()
                        );
                    }
                }
            }
            if run_directories.remove(self.inner.identity()).is_none() {
                return Err(launcher_message(
                    "QEMU generation lost its retained run-directory authority",
                ));
            }
            self.directory_released = true;
        }
        self.inner.finish()
    }
}

fn abort_unspawned_generation(
    lease: QemuAttemptGenerationLease,
    primary: LifecycleApiError,
) -> LifecycleApiError {
    match lease.abort_without_process() {
        Ok(()) => primary,
        Err(abort) => launcher_message(format!(
            "{primary}; aborting the no-process generation also failed: {abort}"
        )),
    }
}

fn launcher_message(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

/// Preserves typed causes when crossing the lifecycle's string-only boundary.
/// Bounds also contain unexpectedly recursive or verbose backend errors.
// crucible-lint: allow erased-error -- diagnostic formatting follows Error::source without replacing the typed launch error.
fn launch_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = String::new();
    let mut current = Some(error);
    for _ in 0..12 {
        let Some(error) = current else { break };
        if !message.is_empty() {
            message.push_str("; caused by: ");
        }
        message.extend(error.to_string().chars().take(1024));
        current = error.source();
    }
    if current.is_some() {
        message.push_str("; further causes omitted");
    }
    message
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture failures identify the exact ownership transition.
    #![allow(clippy::expect_used)]

    use super::*;

    #[derive(Default)]
    struct HelperGuardReceipts {
        children: Vec<crucible_qemu::QemuNodeChild>,
        quarantined: bool,
    }

    struct HelperGuard {
        receipts: Arc<Mutex<HelperGuardReceipts>>,
        cancellation: ExecutionCancellation,
    }

    impl crate::QemuAttemptOperationalBoundary for HelperGuard {
        fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
            crucible_campaign::AttemptResourceLimits::new(1, 64 * 1024 * 1024, 128 * 1024 * 1024, 8)
                .expect("fixture resource ceilings")
        }

        fn cancellation(&self) -> &ExecutionCancellation {
            &self.cancellation
        }

        fn check_operational_boundary(
            &mut self,
        ) -> Result<(), crucible_qemu::QemuVmRealizationError> {
            Ok(())
        }

        fn charge_execution_quantum(
            &mut self,
        ) -> Result<(), crucible_qemu::QemuVmRealizationError> {
            panic!("fixture cannot advance a guest")
        }
    }

    impl crate::QemuAttemptResourceGuard for HelperGuard {
        fn finish(&mut self) -> Result<(), crucible_qemu::QemuVmRealizationError> {
            panic!("an abandoned generation must enter quarantine")
        }

        fn quarantine(&mut self) {
            self.receipts.lock().expect("fixture receipts").quarantined = true;
        }
    }

    impl QemuAttemptProcessResourceGuard for HelperGuard {
        fn child_process_contract(
            &self,
        ) -> Result<&QemuChildProcessContract, crucible_qemu::QemuVmRealizationError> {
            panic!("fixture cannot mint launch authority")
        }

        fn prepare_generation_run_directory(
            &mut self,
            _requirements: crucible_qemu::QemuLaunchResourceRequirements,
        ) -> Result<QemuPreparedRunDirectory, crucible_qemu::QemuVmRealizationError> {
            panic!("fixture cannot mint storage authority")
        }

        fn retain_failed_launch_child(&mut self, child: crucible_qemu::QemuNodeChild) {
            self.receipts
                .lock()
                .expect("fixture receipts")
                .children
                .push(child);
        }
    }

    #[test]
    fn abandoned_generation_transfers_original_helper_to_attempt_quarantine()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = [crucible::NodeId {
            name: String::from("source"),
        }];
        let storage = crate::QemuAttemptGenerationStorage::prepare(selected.iter())?;
        let receipts = Arc::new(Mutex::new(HelperGuardReceipts::default()));
        let guard = HelperGuard {
            receipts: Arc::clone(&receipts),
            cancellation: ExecutionCancellation::default(),
        };
        let owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
        let mut launcher = QemuAttemptProductionVmNodeLauncher::new(owner);
        let generation = ProductionVmNodeGeneration::new(
            crucible::NodeId {
                name: String::from("source"),
            },
            1,
        )?;
        let lease = launcher.owner.register_generation(generation.clone())?;
        let process = std::process::Command::new("sleep").arg("60").spawn()?;
        let child = crucible_qemu::QemuNodeChild::from_test_process(process);
        let process_id = child.process_id();
        let helper_debt = Arc::clone(&launcher.image_helpers);
        helper_debt
            .lock()
            .expect("helper registry")
            .children
            .insert(generation.clone(), child);

        drop(lease);
        drop(launcher);

        let mut debt = helper_debt.lock().expect("helper registry");
        assert!(debt.closed);
        assert!(debt.children.is_empty());
        assert!(debt.transferred.contains(&generation));
        assert!(debt.retry_generation(&generation).is_err());
        let mut receipts = receipts.lock().expect("fixture receipts");
        assert!(receipts.quarantined);
        assert_eq!(receipts.children.len(), 1);
        assert_eq!(receipts.children[0].process_id(), process_id);
        assert!(!receipts.children[0].reaped());

        receipts.children[0]
            .force_kill_and_reap_failed_helper(std::time::Duration::from_secs(5))?;
        assert!(receipts.children[0].reaped());
        // Reap belongs to the aggregate guard; it does not mint a fresh local
        // generation completion receipt for an abandoned lease.
        assert!(debt.retry_generation(&generation).is_err());
        Ok(())
    }

    #[test]
    fn retained_image_helper_debt_reaps_original_process_before_removal()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = ProductionVmNodeGeneration::new(
            crucible::NodeId {
                name: String::from("source"),
            },
            1,
        )?;
        let process = std::process::Command::new("sleep").arg("60").spawn()?;
        let child = crucible_qemu::QemuNodeChild::from_test_process(process);
        let process_id = child.process_id();
        let mut debt = ImageHelperCleanupDebt::default();
        debt.children.insert(generation.clone(), child);

        assert_eq!(debt.children[&generation].process_id(), process_id);
        debt.retry_generation(&generation)?;

        assert!(debt.children.is_empty());
        debt.retry_generation(&generation)?;
        Ok(())
    }

    fn rendered_launch_error(
        operation: &'static str,
        error: impl std::error::Error + 'static,
    ) -> String {
        launcher_message(format!("{operation}: {}", launch_error_chain(&error))).to_string()
    }

    #[test]
    fn launch_failure_preserves_rejected_asset_detail() {
        let error = crucible_qemu::QemuLiveNodeStepGateError::LaunchCommand {
            source: crucible_qemu::QemuLaunchCommandError::InvalidStorePath {
                field: "root_image",
                path: "/tmp/root.raw".to_owned(),
            },
        };
        let message = rendered_launch_error("launch fresh node", error);
        assert!(message.contains("build QEMU launch command failed"));
        assert!(message.contains("root_image must be an AOS store path, got `/tmp/root.raw`"));
    }

    #[test]
    fn launch_failure_bounds_recursive_and_verbose_causes() {
        // A manually implemented source exercises errors outside our derives.
        #[derive(Debug)]
        struct Recursive;
        impl std::fmt::Display for Recursive {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "recursive backend")
            }
        }
        impl std::error::Error for Recursive {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(self)
            }
        }
        let message = launch_error_chain(&Recursive);
        assert_eq!(message.matches("recursive backend").count(), 12);
        assert!(message.ends_with("further causes omitted"));
        assert_eq!(
            launch_error_chain(&std::io::Error::other("x".repeat(2048))).len(),
            1024
        );
    }
}

fn launcher_arc_bytes<T>() -> Result<u64, LifecycleApiError> {
    let (layout, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<T>())
    .map_err(|_| launcher_message("Source launcher Arc layout overflow"))?;
    u64::try_from(layout.pad_to_align().size())
        .map_err(|_| launcher_message("Source launcher Arc extent overflow"))
}
