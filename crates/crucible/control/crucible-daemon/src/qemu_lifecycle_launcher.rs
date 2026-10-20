//! Attempt-owned guarded launcher for the production VM lifecycle.
//!
//! This adapter is the backend owner of the production lifecycle's linear QEMU
//! generations. It admits and pins fresh generation directories, runs image
//! tools under the attempt contract, streams repository checkpoints, and lends
//! the sealed process contract only after preparation. Any unreaped QEMU or
//! helper child is transferred into the aggregate guard before an error returns.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::{
    DecodedProductionExactCheckpoint, ProductionExactCheckpointClosure,
    ProductionVmExactNodeRestoreAdmission, ProductionVmNodeGeneration, ProductionVmNodeLaunch,
    ProductionVmNodeLaunchRequest, ProductionVmNodeLauncher, ProductionVmNodeLease,
};
use crucible_control_api::LifecycleApiError;
use crucible_qemu_host::{
    QemuChildProcessContract, QemuLiveNodeIdentity, QemuNode, QemuPreparedRunDirectory,
    QemuProductionFreshLaunchAdmission, QemuVmRealizationError,
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
mod prepared_source;
pub(crate) use prepared_source::PreparedSourceHandle;
mod target_construction;
pub use pending_construction::CanonicalContextError;
pub use target_construction::TargetConstructionStorage;
#[cfg(target_os = "linux")]
pub(crate) use target_construction::TargetMemberAdmission;
#[cfg(target_os = "linux")]
pub use target_construction::TargetPreparationFailure;
mod fresh_generation;
mod retained_node;
use retained_node::RetainedNodeLaunch;
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
mod native_observation;
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
pub(crate) use native_observation::ObservedNativeNode;
pub(crate) use pending_construction::{PendingSourceConstruction, SourceWorldNotStarted};

struct TerminalCheckpointImport {
    checkpoints: Arc<ExactCheckpointStore>,
    source: crucible_engine::ScenarioDefForm,
    cancellation: ExecutionCancellation,
    published_root: Option<crucible_engine::ContentHash>,
    _decode_custody: Option<crucible_engine::owned_decode::DecodeCustody>,
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
    cleanup_reservation: Option<crate::WorldLifecycleCleanupReservation>,
    prepared_source_selector: Option<crate::PreparedSourceSelector>,
    cleanup_complete: bool,
    construction_custody: Option<Box<crate::ProductionVmConstructionCustody>>,
    retained_node: Option<RetainedNodeLaunch>,
    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    pub(crate) native_observation_config: Option<crate::ProductionVmLifecycleConfig>,
    target_storage: Option<TargetConstructionStorage>,
    target_return:
        Option<fn(crate::PreparedSourceSelector) -> crate::ProductionVmConstructionPostBody>,
    owner: QemuAttemptGenerationResourceOwner<G>,
    run_directories: Arc<Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>>,
    image_helpers: Arc<Mutex<ImageHelperCleanupDebt>>,
    terminal_checkpoint: Option<TerminalCheckpointImport>,
    // Retains the same World through the other launcher fields' destruction.
    // Holding this loan does not attest physical return.
    _world_cleanup_loan: Option<
        crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    >,
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
            prepared_source_selector: None,
            cleanup_complete: false,
            construction_custody: None,
            retained_node: None,
            #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
            native_observation_config: None,
            target_storage: None,
            target_return: None,
            owner,
            run_directories: Arc::new(Mutex::new(BTreeMap::new())),
            image_helpers: Arc::new(Mutex::new(ImageHelperCleanupDebt::default())),
            terminal_checkpoint: None,
            _world_cleanup_loan: None,
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
    /// and helper controls, selected generation rows, and the overlapping
    /// prepared Source Loop Box. The retained World also pays its shared Source
    /// allocation and overlapping transfer headers. Main separately pays Pending
    /// and its carrier. The same World also prices its selected Target rows and
    /// the overlapping Target launcher, adoption and reconciliation controls.
    ///
    /// # Errors
    /// Refuses an empty/excessive member set or layout/byte arithmetic overflow.
    pub(crate) fn retained_source_launcher_control_bytes<'a>(
        nodes: impl Clone + Iterator<Item = &'a crucible_engine::NodeId>,
        workers: crucible_qemu_host::QemuHotForkWorkerGeometry,
    ) -> Result<u64, LifecycleApiError>
    where
        F: crate::QemuAttemptResourceGuardFactory,
        F::Guard: QemuAttemptProcessResourceGuard,
    {
        let generations = crate::QemuAttemptGenerationStorage::control_bytes(nodes.clone())?;
        let target_runtime =
            Self::retained_target_runtime_control_bytes::<F::Guard>(nodes.clone())?;
        let worker_requests = workers
            .requested_control_bytes(nodes.clone().count())
            .map_err(|first| launcher_message(first.to_string()))?;
        let targets = TargetConstructionStorage::control_bytes(nodes.clone())?;
        let selected = nodes.clone().count();
        let terminal_rows = crate::vm_lifecycle::terminal_replacement_control_bytes(selected)?;
        let target_nodes =
            crate::qemu_hot_fork_reconciliation::TargetNodeConstruction::<F::Guard>::control_bytes(
                nodes,
            )?;
        let directories = launcher_arc_bytes::<
            Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>,
        >()?;
        let helpers = launcher_arc_bytes::<Mutex<ImageHelperCleanupDebt>>()?;
        let source_loop = u64::try_from(std::mem::size_of::<crate::ProductionVmLifecycleLoop>())
            .map_err(|_| launcher_message("prepared Source lifecycle extent overflows"))?;
        #[cfg(target_os = "linux")]
        let shared_source = {
            let headers = std::mem::size_of::<crate::vm_lifecycle::PreparedSharedSource>()
                .checked_add(std::mem::size_of::<crate::vm_lifecycle::MainSharedSource>())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(|| launcher_message("shared Source transfer extent overflows"))?;
            launcher_arc_bytes::<Mutex<crate::vm_lifecycle::ProductionVmHotForkSourceWorld>>()?
                .checked_add(headers)
                .ok_or_else(|| launcher_message("shared Source allocation extent overflows"))?
        };
        #[cfg(not(target_os = "linux"))]
        let shared_source = 0;

        let retained_source = Self::retained_control_bytes()?
            .checked_add(directories)
            .and_then(|bytes| bytes.checked_add(helpers))
            .and_then(|bytes| bytes.checked_add(source_loop))
            .and_then(|bytes| bytes.checked_add(terminal_rows))
            .and_then(|bytes| bytes.checked_add(shared_source))
            .ok_or_else(|| launcher_message("retained Source launcher extent overflow"))?;
        // Main already pays the preborn Pending and construction carrier.
        // This World pays its actual launcher, shared controls, generation rows
        // and the Source Loop/shared allocation overlapping them. Each queried
        // Arc extent includes its actual payload and reference-count header.
        retained_source
            .checked_add(generations)
            .and_then(|bytes| bytes.checked_add(targets))
            .and_then(|bytes| bytes.checked_add(target_runtime))
            .and_then(|bytes| {
                target_nodes
                    .checked_mul(2)
                    .and_then(|rows| bytes.checked_add(rows))
            })
            .and_then(|bytes| bytes.checked_add(worker_requests))
            .ok_or_else(|| launcher_message("selected Source control extent overflow"))
    }

    /// Measures the actual overlapping Target launcher and adoption controls.
    ///
    /// The selected Source World currently retains one such construction. This
    /// request includes the shared directory/helper headers, exact reconciliation
    /// roster, adoption vector and each actual boxed adoption lease.
    ///
    /// # Errors
    /// Refuses invalid selected geometry or checked extent arithmetic overflow.
    fn retained_target_runtime_control_bytes<'a, T: QemuAttemptProcessResourceGuard>(
        nodes: impl Clone + Iterator<Item = &'a crucible_engine::NodeId>,
    ) -> Result<u64, LifecycleApiError> {
        use crate::qemu_hot_fork_reconciliation::LinuxQemuHotForkWorldReconciliationSet;
        use crate::qemu_hot_fork_world_resource::QemuHotForkWorldLifecycleGuard;

        let registry = LinuxQemuHotForkWorldReconciliationSet::<T>::control_bytes(nodes.clone())?;
        let adoptions =
            LinuxQemuHotForkWorldReconciliationSet::<T>::adoption_control_bytes(nodes.count())?;
        let launcher =
            QemuAttemptProductionVmNodeLauncher::<QemuHotForkWorldLifecycleGuard<T>>::retained_control_bytes()?;
        let directories = launcher_arc_bytes::<
            Mutex<BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>>,
        >()?;
        let helpers = launcher_arc_bytes::<Mutex<ImageHelperCleanupDebt>>()?;

        launcher
            .checked_add(directories)
            .and_then(|bytes| bytes.checked_add(helpers))
            .and_then(|bytes| bytes.checked_add(registry))
            .and_then(|bytes| bytes.checked_add(adoptions))
            .ok_or_else(|| launcher_message("Target runtime control extent overflows"))
    }

    /// Binds the actual Target tail selected by this launcher's same Main role.
    ///
    /// This stores only a monomorphized operation and the existing key. It
    /// creates no World loan, Source Service phase or replacement owner.
    pub(crate) fn with_target_return<T: crate::lifecycle_cleanup::TargetConstructionPostBody>(
        mut self,
    ) -> Self {
        self.target_return = Some(crate::ProductionVmConstructionPostBody::target::<T>);
        self
    }

    /// Moves the same preborn selected Target directory into its real Source.
    pub(crate) fn with_target_construction_storage(
        mut self,
        storage: TargetConstructionStorage,
    ) -> Self {
        self.target_storage = Some(storage);
        self
    }

    /// Retains the same admitted World's cleanup loan after construction.
    pub(crate) fn with_world_cleanup_loan(
        mut self,
        world: crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Self {
        self._world_cleanup_loan = Some(world);
        self
    }

    /// Moves the exact claimed World's token into the successful launcher.
    pub(crate) fn with_cleanup_reservation(
        mut self,
        reservation: crate::WorldLifecycleCleanupReservation,
    ) -> Self {
        self.prepared_source_selector =
            Some(reservation.service_preclaim().handle().prepared_selector());
        self.cleanup_reservation = Some(reservation);
        self
    }

    /// Moves the initialized same construction carrier into the actual launcher.
    pub(crate) fn with_construction_custody(
        mut self,
        custody: Box<crate::ProductionVmConstructionCustody>,
    ) -> Self {
        self.construction_custody = Some(custody);
        self
    }

    /// Installs the selected campaign store for a recoverable terminal restart.
    pub(crate) fn with_terminal_checkpoint_import(
        mut self,
        checkpoints: Arc<ExactCheckpointStore>,
        source: crucible_engine::ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Self {
        self.install_terminal_checkpoint_import(checkpoints, source, cancellation);
        self
    }

    /// Moves already-admitted terminal metadata into the retained boxed owner.
    pub(crate) fn install_terminal_checkpoint_import(
        &mut self,
        checkpoints: Arc<ExactCheckpointStore>,
        source: crucible_engine::ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) {
        self.terminal_checkpoint = Some(TerminalCheckpointImport {
            checkpoints,
            source,
            cancellation,
            published_root: None,
            _decode_custody: crucible_engine::owned_decode::current_custody(),
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
                if error.has_retained_owner() {
                    return Err(LifecycleApiError::BackendConstruction {
                        source: crucible_control_api::LifecycleBackendConstructionError::new(error),
                    });
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

    fn record_launched_generation(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        lease: QemuAttemptGenerationLease,
        run_directory: QemuPreparedRunDirectory,
        node: QemuNode,
        process_contract: QemuChildProcessContract,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let (node, lease, run_directory_path) = self.record_launched_parts(
            request.launch().qemu_executable(),
            lease,
            run_directory,
            node,
            process_contract,
            run_directories,
        );
        match ProductionVmNodeLaunch::new_in_run_directory(request, run_directory_path, node, lease)
        {
            Ok(launch) => Ok(launch),
            Err((first, launch)) => {
                // Both launch methods exclude an earlier failed pairing before
                // any effects, so this pre-existing slot cannot be overwritten.
                self.retained_node = Some(RetainedNodeLaunch::new(launch));
                Err(first)
            }
        }
    }

    /// Moves the same born process and its directory into generation custody.
    fn record_launched_parts(
        &mut self,
        qemu_executable: &std::path::Path,
        lease: QemuAttemptGenerationLease,
        run_directory: QemuPreparedRunDirectory,
        node: QemuNode,
        process_contract: QemuChildProcessContract,
        run_directories: &mut BTreeMap<ProductionVmNodeGeneration, QemuPreparedRunDirectory>,
    ) -> (QemuNode, QemuLifecycleGenerationLease, std::path::PathBuf) {
        let generation = lease.identity().clone();
        let run_directory_path = run_directory.path().to_path_buf();
        let prior = run_directories.insert(generation, run_directory);
        debug_assert!(prior.is_none());
        let lease = QemuLifecycleGenerationLease {
            inner: lease,
            run_directories: Arc::clone(&self.run_directories),
            qemu_executable: qemu_executable.to_path_buf(),
            process_contract,
            image_helpers: Arc::clone(&self.image_helpers),
            directory_released: false,
        };

        (node, lease, run_directory_path)
    }

    fn transfer_image_helper_debt(&mut self) {
        let mut debt = self
            .image_helpers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debt.closed = true;

        #[cfg(test)]
        {
            let mut returned = BTreeMap::new();
            for (generation, recipient) in std::mem::take(&mut debt.children) {
                match recipient {
                    ImageHelperRecipient::Component(child) => {
                        self.owner
                            .retain_failed_launch_child_for_node(generation.node(), child);
                        debt.transferred.insert(generation);
                    }
                    issued => {
                        returned.insert(generation, issued);
                    }
                }
            }
            debt.children = returned;
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

impl<G, F> crucible_control_api::ProductionVmCleanupOwner
    for QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard + Send,
    F: Send,
{
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        if !self.cleanup_complete {
            return Err(Self::Failure::Retained(
                "launcher body cleanup is not complete",
            ));
        }
        if let Some(build) = self.target_return {
            if self._world_cleanup_loan.is_some() {
                return Err(Self::Failure::Retained(
                    "Target launcher also retains an unrelated Source World loan",
                ));
            }
            let selector =
                self.prepared_source_selector
                    .as_ref()
                    .ok_or(Self::Failure::Retained(
                        "Target launcher has no original Main selector",
                    ))?;
            let body = build(selector.clone());
            self.target_return = None;
            return Ok(Some(body));
        }
        Ok(self
            ._world_cleanup_loan
            .take()
            .map(|loan| crate::ProductionVmConstructionPostBody::world(loan, None)))
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }
}

impl<G, F> ProductionVmNodeLauncher for QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard + Send,
    F: Send,
{
    #[cfg(target_os = "linux")]
    fn take_source_world_cleanup_loan(
        &mut self,
    ) -> Option<
        crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    > {
        self._world_cleanup_loan.take()
    }

    #[cfg(target_os = "linux")]
    fn prepared_source_selector(&self) -> Option<crate::PreparedSourceSelector> {
        self.prepared_source_selector.clone()
    }

    fn take_construction_custody(&mut self) -> Option<Box<crate::ProductionVmConstructionCustody>> {
        self.construction_custody.take()
    }

    fn take_cleanup_reservation(
        &mut self,
    ) -> Option<
        Box<
            dyn crucible_control_api::ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                    ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                >,
        >,
    > {
        self.cleanup_reservation
            .take()
            .map(crate::WorldLifecycleCleanupReservation::into_reservation)
    }

    #[cfg(target_os = "linux")]
    fn fork_target_is_owned(&self) -> bool {
        self.owner.fork_target_is_owned()
    }

    fn matches_target_construction_storage(&self, storage: &TargetConstructionStorage) -> bool {
        self.target_storage.is_none() && storage.belongs_to(&self.owner)
    }

    fn take_target_construction_storage(
        &mut self,
    ) -> Result<TargetConstructionStorage, LifecycleApiError> {
        self.target_storage.take().ok_or_else(|| {
            launcher_message("Source Target construction storage is already borrowed or absent")
        })
    }

    fn return_prepared_target_construction_storage(
        &mut self,
        storage: TargetConstructionStorage,
    ) -> Result<(), TargetConstructionStorage> {
        if self.target_storage.is_some()
            || !storage.source_return_is_prepared()
            || !storage.belongs_to(&self.owner)
        {
            return Err(storage);
        }
        // Vacancy was checked above. This replaces None and moves existing
        // payloads; it drops no history, loan, alias or physical owner here.
        self.target_storage = Some(storage);
        Ok(())
    }

    fn return_target_construction_storage(
        &mut self,
        mut storage: TargetConstructionStorage,
    ) -> Result<(), TargetConstructionStorage> {
        if self.target_storage.is_some()
            || !storage.belongs_to(&self.owner)
            || !storage.prepare_reuse()
        {
            return Err(storage);
        }
        self.target_storage = Some(storage);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn native_world_identity(
        &self,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        QemuVmRealizationError,
    > {
        self.owner.native_world_identity()
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target_for_node(
        &mut self,
        node: &crucible_engine::NodeId,
    ) -> Result<
        crucible_qemu_host::QemuForkTargetPreparation,
        crate::qemu_lifecycle_launcher::TargetPreparationFailure,
    > {
        self.owner.prepare_fork_target_for_node(node)
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target(
        &mut self,
    ) -> Result<
        crucible_qemu_host::QemuForkTargetPreparation,
        crate::qemu_lifecycle_launcher::TargetPreparationFailure,
    > {
        self.owner.prepare_fork_target()
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: crucible_qemu_host::QemuLaunchResourceRequirements,
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
        source: &mut crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        request: crate::ProductionVmParentParkDrainRequest<'_>,
    ) -> Result<crucible_qemu_host::QmpParentParkResult, crate::ProductionVmParentParkDrainRefusal>
    {
        self.invoke_parent_park_drain(source, request)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn contain_parent_park_drain(
        &mut self,
    ) -> Result<(), crate::ProductionVmParentParkDrainRefusal> {
        // Use the actual containing guard's existing kill/reap quarantine.
        // Its owner stays inside the complete lifecycle; phase custody below
        // is not refunded by this transfer or by a scalar successful return.
        self.transfer_image_helper_debt();
        self.owner.quarantine_original_launch();
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn parent_park_drain_failure(&self) -> Option<crate::ProductionVmParentParkDrainFailure<'_>> {
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
        terminal.published_root = Some(crucible_engine::ContentHash {
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
        if self.retained_node.is_some() {
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
        if self.retained_node.is_some() {
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

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        if self.cleanup_complete {
            return Ok(());
        }
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_phase.is_some() {
            return Err((LifecycleApiError::ParentParkHeld).into());
        }
        if let Some(failed) = self.retained_node.as_mut() {
            failed.finish()?;
        }
        self.retained_node = None;
        // The exact observation registrar/configuration aliases remain until
        // its real node and generation lease have physically closed.
        #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
        {
            if self.native_observation_config.take().is_some() {
                self.park_drain_registration = None;
            }
        }
        self.transfer_image_helper_debt();
        self.owner.finish()?;
        self.fork_target_factory = None;
        self.cleanup_complete = true;
        Ok(())
    }
}

/// Moves the existing fresh-generation owners between two private launch cuts.
struct PreparedFreshGeneration {
    lease: QemuAttemptGenerationLease,
    directory: QemuPreparedRunDirectory,
    node: QemuNode,
    contract: QemuChildProcessContract,
}

/// Shared wait authority survives generation-lease abandonment.
#[derive(Default)]
struct ImageHelperCleanupDebt {
    closed: bool,
    children: BTreeMap<ProductionVmNodeGeneration, ImageHelperRecipient>,
    // Aggregate quarantine owns the wait handle after transfer. An empty local
    // map must not let a retained lease claim that its helper was reaped.
    transferred: BTreeSet<ProductionVmNodeGeneration>,
}

enum ImageHelperRecipient {
    Issued(std::sync::Weak<crucible_qemu_host::OriginalNativeFreshLaunchError>),
    #[cfg(test)]
    Component(crucible_qemu_host::QemuNodeChild),
}

impl ImageHelperRecipient {
    fn retry(&mut self) -> Result<(), LifecycleApiError> {
        match self {
            Self::Issued(receiver) => {
                let receiver = receiver.upgrade().ok_or_else(|| {
                    launcher_message("issued image-helper recipient is unavailable")
                })?;
                if receiver.retry_retained_helper() {
                    Ok(())
                } else {
                    Err(launcher_message(
                        "issued image-helper physical return remains pending",
                    ))
                }
            }
            #[cfg(test)]
            Self::Component(child) => child
                .force_kill_and_reap_failed_helper(std::time::Duration::from_secs(5))
                .map_err(|error| {
                    launcher_message(format!("retry component helper cleanup: {error}"))
                }),
        }
    }

    #[cfg(test)]
    fn process_id(&self) -> Option<u32> {
        match self {
            Self::Component(child) => Some(child.process_id()),
            Self::Issued(_) => None,
        }
    }
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
        if let Some(recipient) = self.children.get_mut(generation) {
            recipient.retry()?;
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
            Err(error) => {
                if let Some(receiver) = error.retained_receiver() {
                    helper_debt.children.insert(
                        self.inner.identity().clone(),
                        ImageHelperRecipient::Issued(Arc::downgrade(&receiver)),
                    );
                }
                Err(launcher_message(format!(
                    "prepare guarded hot-fork detached overlay: {error}"
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
        children: Vec<crucible_qemu_host::QemuNodeChild>,
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
        ) -> Result<(), crucible_qemu_host::QemuVmRealizationError> {
            Ok(())
        }

        fn charge_execution_quantum(
            &mut self,
        ) -> Result<(), crucible_qemu_host::QemuVmRealizationError> {
            panic!("fixture cannot advance a guest")
        }
    }

    impl crate::QemuAttemptResourceGuard for HelperGuard {
        fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
            panic!("an abandoned generation must enter quarantine")
        }

        fn quarantine(&mut self) {
            self.receipts.lock().expect("fixture receipts").quarantined = true;
        }
    }

    impl QemuAttemptProcessResourceGuard for HelperGuard {
        fn child_process_contract(
            &self,
        ) -> Result<&QemuChildProcessContract, crucible_qemu_host::QemuVmRealizationError> {
            panic!("fixture cannot mint launch authority")
        }

        fn prepare_generation_run_directory(
            &mut self,
            _requirements: crucible_qemu_host::QemuLaunchResourceRequirements,
        ) -> Result<QemuPreparedRunDirectory, crucible_qemu_host::QemuVmRealizationError> {
            panic!("fixture cannot mint storage authority")
        }

        fn retain_failed_launch_child(&mut self, child: crucible_qemu_host::QemuNodeChild) {
            self.receipts
                .lock()
                .expect("fixture receipts")
                .children
                .push(child);
        }
    }

    #[test]
    fn target_storage_returns_only_to_its_same_source_registry() -> Result<(), LifecycleApiError> {
        let nodes = [crucible_engine::NodeId {
            name: String::from("source"),
        }];
        let selected = crate::QemuAttemptGenerationStorage::prepare(nodes.iter())?;
        let own_targets = TargetConstructionStorage::prepare(nodes.iter(), &selected)?;
        let foreign = crate::QemuAttemptGenerationStorage::prepare(nodes.iter())?;
        let foreign_targets = TargetConstructionStorage::prepare(nodes.iter(), &foreign)?;
        let receipts = Arc::new(Mutex::new(HelperGuardReceipts::default()));
        let guard = HelperGuard {
            receipts: Arc::clone(&receipts),
            cancellation: ExecutionCancellation::default(),
        };
        let owner = QemuAttemptGenerationResourceOwner::new(guard, selected);
        let mut launcher = QemuAttemptProductionVmNodeLauncher::new(owner)
            .with_target_construction_storage(own_targets);

        let targets = launcher.take_target_construction_storage()?;
        assert!(launcher.matches_target_construction_storage(&targets));
        assert!(!launcher.matches_target_construction_storage(&foreign_targets));
        assert!(launcher.take_target_construction_storage().is_err());
        assert!(
            launcher
                .return_target_construction_storage(foreign_targets)
                .is_err()
        );
        assert!(launcher.return_target_construction_storage(targets).is_ok());
        let targets = launcher.take_target_construction_storage()?;
        assert!(targets.belongs_to(&launcher.owner));
        assert!(targets.can_restore_to_source());
        assert!(launcher.return_target_construction_storage(targets).is_ok());
        assert!(receipts.lock().unwrap().children.is_empty());
        Ok(())
    }

    #[test]
    fn abandoned_generation_transfers_original_helper_to_attempt_quarantine()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = [crucible_engine::NodeId {
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
            crucible_engine::NodeId {
                name: String::from("source"),
            },
            1,
        )?;
        let lease = launcher.owner.register_generation(generation.clone())?;
        let process = std::process::Command::new("sleep").arg("60").spawn()?;
        let child = crucible_qemu_host::QemuNodeChild::from_test_process(process);
        let process_id = child.process_id();
        let helper_debt = Arc::clone(&launcher.image_helpers);
        helper_debt
            .lock()
            .expect("helper registry")
            .children
            .insert(generation.clone(), ImageHelperRecipient::Component(child));

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
            crucible_engine::NodeId {
                name: String::from("source"),
            },
            1,
        )?;
        let process = std::process::Command::new("sleep").arg("60").spawn()?;
        let child = crucible_qemu_host::QemuNodeChild::from_test_process(process);
        let process_id = child.process_id();
        let mut debt = ImageHelperCleanupDebt::default();
        debt.children
            .insert(generation.clone(), ImageHelperRecipient::Component(child));

        assert_eq!(debt.children[&generation].process_id(), Some(process_id));
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
        let error = crucible_qemu_host::QemuLiveNodeStepGateError::LaunchCommand {
            source: crucible_qemu_host::QemuLaunchCommandError::InvalidStorePath {
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
