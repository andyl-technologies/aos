//! Keeps the real Target constructor outside its eventual lifecycle body.
//!
//! Main pays this Box and its same construction carrier. The retained Source
//! World separately pays selected member/generation storage. Main installs the
//! same pending body before physical Target begin and keeps it through the
//! actual Loop body destruction and exact per-member loan return.

use super::*;
use crate::qemu_hot_fork_reconciliation::LinuxQemuHotForkWorldReconciliationSet;
use crate::qemu_hot_fork_reconciliation::TargetNodeConstruction;
use crate::qemu_hot_fork_world::QemuHotForkCompleteWorldAssembly;
use crate::qemu_lifecycle_launcher::TargetConstructionStorage;
use crate::vm_lifecycle::TargetSourceBackends;
use crucible_control_api::LifecycleApiError;

mod installation;
mod transaction;

/// Selects the actual operational owner before Target startup has any effects.
#[derive(Clone, Copy)]
pub(crate) enum TargetService {
    /// Uses the already admitted campaign execution's operational owner.
    Execution,
    /// Admits an independent Service inside this same prepaid Target role.
    Independent,
}

/// Moves existing ownership without allocating on a refused Main preclaim.
pub(crate) struct TargetConstructionInput<F: QemuAttemptResourceGuardFactory> {
    pub(crate) factory: F,
    pub(crate) source: QemuHotForkSourceWorldLease,
    pub(crate) source_selector: crate::PreparedSourceSelector,
    pub(crate) continuation: crate::ProductionVmHotForkWorldContinuation,
}

/// Preserves unchanged inputs when Main refuses before Target occupancy.
///
/// The caller still owns the original checkout and Source-paid storage. This
/// value creates no fallback role and must be restored or kept in the existing
/// containing factory's fixed owning-failure slot if restoration is uncertain.
#[must_use = "retain or restore the unchanged Target construction input"]
pub(crate) struct TargetMainAdmissionFailure<F: QemuAttemptResourceGuardFactory> {
    pub(crate) input: TargetConstructionInput<F>,
    pub(crate) first: TargetMainAdmissionError,
}

impl<F: QemuAttemptResourceGuardFactory> TargetMainAdmissionFailure<F> {
    /// Restores only unchanged pre-occupancy storage, retaining refusal on busy.
    ///
    /// Layout/reset happens outside the Source mutex. The short metadata cut
    /// checks the original checkout and moves the same pristine rows. A refused
    /// restore returns this SAME input and actual first cause without reboxing.
    pub(crate) fn try_restore_source(
        mut self,
    ) -> Result<(QemuHotForkSourceWorldLease, TargetMainAdmissionError), Self> {
        // Main refused before a constructor was installed. No row, native
        // permit or Source backend has left its original owner at this cut.
        let Some(owner) = self.input.source.source_owner() else {
            return Err(self);
        };
        let Ok(source) = owner.try_lock() else {
            return Err(self);
        };
        if !self.input.source.identity().matches(&source)
            || source.fork_target_is_owned()
            || !source
                .prepared_source_selector()
                .is_some_and(|selected| selected.same_role(&self.input.source_selector))
        {
            return Err(self);
        }
        let Self { input, first } = self;
        let TargetConstructionInput {
            factory,
            source: lease,
            source_selector: _,
            continuation: _,
        } = input;
        drop(source);
        drop(owner);
        drop(factory);
        Ok((lease, first))
    }
}

/// Separates pure geometry from the same authentic Main's admission refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TargetMainAdmissionError {
    /// The selected constructor's real layout cannot be represented.
    #[error("selected Target constructor geometry refused: {0}")]
    Geometry(#[source] LifecycleApiError),
    /// The actual Source is absent, closed or belongs to another containing Main.
    #[error("selected Target Source/Main binding refused")]
    Source,
    /// The genuine containing Main refused before constructing another body.
    #[error("selected Target Main preclaim refused: {0}")]
    Main(#[source] crate::lifecycle_cleanup::ServiceMainPreclaimError),
}

/// Installs the actual Pending before any logical Target or physical effect.
///
/// The input was moved from its genuine Source under that Source's checkout.
/// Identity verification and all Main custody locks precede the fixed builder.
/// A refused preclaim returns the SAME input with no Pending or carrier birth.
pub(crate) fn reserve_target_main<F>(
    producer: &crate::SourceMainProducer,
    input: TargetConstructionInput<F>,
    service: TargetService,
) -> Result<
    crate::lifecycle_cleanup::PreparedSourceHandle<PendingTargetConstruction<F>>,
    TargetMainAdmissionFailure<F>,
>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    // Derive the selection only from this input's actual checkout. A caller
    // cannot substitute another same-Main Source role for a foreign checkout.
    let selected = {
        let selected = input
            .source
            .source_owner()
            .and_then(|owner| match owner.try_lock() {
                Ok(source)
                    if input.source.identity().matches(&source)
                        && !source.fork_target_is_owned() =>
                {
                    source.prepared_source_selector()
                }
                Ok(_) | Err(_) => None,
            });
        selected
    };
    let Some(selected) = selected else {
        return Err(TargetMainAdmissionFailure {
            input,
            first: TargetMainAdmissionError::Source,
        });
    };
    if !selected.same_role(&input.source_selector) {
        return Err(TargetMainAdmissionFailure {
            input,
            first: TargetMainAdmissionError::Source,
        });
    }
    if let Err(first) = producer.verify_source_selector(&selected) {
        return Err(TargetMainAdmissionFailure {
            input,
            first: TargetMainAdmissionError::Main(first),
        });
    }
    let bytes = match PendingTargetConstruction::<F>::control_bytes() {
        Ok(bytes) => bytes,
        Err(first) => {
            return Err(TargetMainAdmissionFailure {
                input,
                first: TargetMainAdmissionError::Geometry(first),
            });
        }
    };
    let build = match service {
        TargetService::Execution => build_target::<F>,
        TargetService::Independent => build_service_target::<F>,
    };
    producer
        .reserve_with_prepared(
            crate::lifecycle_cleanup::PreparedRole::Target,
            input,
            bytes,
            build,
            crate::lifecycle_cleanup::PreparedSourceProjections {
                first: project_first::<F>,
                history: project_history::<F>,
                terminal_metadata_return: Some(return_target_terminal_metadata::<F>),
            },
        )
        .map_err(|(input, first)| TargetMainAdmissionFailure {
            input,
            first: TargetMainAdmissionError::Main(first),
        })
}

// The containing producer invokes only this fixed allocation/move operation
// while its custody locks are held. It enters no Original and invokes no IO.
fn build_target<F>(
    input: TargetConstructionInput<F>,
    reservation: crate::WorldLifecycleCleanupReservation,
) -> (
    Box<PendingTargetConstruction<F>>,
    Option<crate::packaged_qemu_executor::RetainedServiceStart>,
)
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    (
        PendingTargetConstruction::new_prepaid(input, reservation),
        None,
    )
}

// The same fixed constructor also retains an independently admitted Service.
// This is still a Target recipe; it creates no Source World or Source grant.
fn build_service_target<F>(
    input: TargetConstructionInput<F>,
    reservation: crate::WorldLifecycleCleanupReservation,
) -> (
    Box<PendingTargetConstruction<F>>,
    Option<crate::packaged_qemu_executor::RetainedServiceStart>,
)
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    let service =
        crate::packaged_qemu_executor::RetainedServiceStart::new(reservation.service_preclaim());
    (
        PendingTargetConstruction::new_prepaid(input, reservation),
        Some(service),
    )
}

fn project_first<F>(
    owner: &(dyn std::any::Any + Send),
) -> Option<&(dyn std::error::Error + 'static)>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    owner
        .downcast_ref::<PendingTargetConstruction<F>>()?
        .first_failure()
}

fn project_history<F>(
    owner: &(dyn std::any::Any + Send),
) -> Option<&(dyn std::error::Error + 'static)>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    let pending = owner.downcast_ref::<PendingTargetConstruction<F>>()?;
    pending
        .has_history()
        .then_some(pending as &dyn std::error::Error)
}

/// Preserves an actual setup refusal beside the still-canonical owners.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TargetSetupFailure {
    /// The original model copy refused its admitted allocation.
    #[error(transparent)]
    ModelCopy(#[from] crucible_engine::EngineError),
    /// Existing assembly/admission status with unchanged diagnostic policy.
    #[error(transparent)]
    Assembly(#[from] LifecycleApiError),
    /// The retained Source refused an actual selected-node observation.
    #[error(transparent)]
    Source(#[from] SchedulerError),
    /// The actual host returned an independent concrete setup failure.
    #[error(transparent)]
    Native(#[from] QemuVmRealizationError),
    /// RAM registration or original supervision refused its admitted ownership.
    #[error(transparent)]
    Ram(#[from] crucible_control_api::host_operational::HostRamAdmissionError),
    /// The execution has no remaining admitted process-driving allowance.
    #[error(transparent)]
    ExecutionBudget(#[from] crate::executor_worker::ExecutionQuantumBudgetError),
    /// The complete native resource geometry cannot form a valid contract.
    #[error(transparent)]
    ResourceLimits(#[from] crucible_campaign::CampaignCodecError),
    /// The existing child refused its actual protocol admission.
    #[error(transparent)]
    Child(
        #[from]
        crate::QemuHotForkAttemptReconciliationError<crate::LinuxQemuHotForkReconciliationError>,
    ),
    /// Scheduler installation returned its original already allocated error.
    #[error(transparent)]
    ChildInstallation(
        #[from]
        Box<
            crate::QemuHotForkAttemptReconciliationError<
                crate::LinuxQemuHotForkReconciliationError,
            >,
        >,
    ),
    /// The assembly returned its unchanged member-admission status.
    #[error(transparent)]
    WorldAdmission(#[from] crate::qemu_hot_fork_world::QemuHotForkWorldChildAdmissionFailure),
    /// Publication refused while the unchanged assembly retains its children.
    #[error(transparent)]
    WorldPublication(#[from] crate::qemu_hot_fork_world::QemuHotForkWorldPublicationFailure),
    /// The already priced adoption payload could not be reserved.
    #[error("reserve Target adoption payload: {0}")]
    Adoptions(#[source] std::collections::TryReserveError),
    /// All started workers joined while the canonical rows retain their state.
    #[error(transparent)]
    Workers(#[from] crucible_qemu_host::QemuHotForkWorkerFailure),
}

type PendingTargetChild<G> =
    QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>;

/// Owns the same paid Target phase before, during and after Loop construction.
///
/// All Target bodies, actual raw history and aliases precede the Source
/// checkout in destruction order. No field creates another family, Original,
/// window, World loan or Service release permission.
#[must_use = "retain this Main-owned Target body through exact retirement"]
pub(crate) struct PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    selector: crate::PreparedSourceSelector,
    source_selector: crate::PreparedSourceSelector,
    nodes: Option<Vec<TargetNodeConstruction<F::Guard>>>,
    spare_rows: Option<Vec<TargetNodeConstruction<F::Guard>>>,
    worker_geometry: Option<crucible_qemu_host::QemuHotForkWorkerGeometry>,
    source_backends: Option<TargetSourceBackends>,
    first_main: Option<TargetMainAdmissionError>,
    first_setup: Option<TargetSetupFailure>,
    adoptions: Vec<crate::ProductionVmHotForkNodeAdoption>,
    continuation: Option<crate::ProductionVmHotForkWorldContinuation>,
    launch_continuation: Option<crate::ProductionVmHotForkWorldContinuation>,
    launch_input: Option<Box<dyn crate::ProductionVmNodeLauncher>>,
    construction: Option<Box<crate::ProductionVmConstructionCustody>>,
    guard: Option<F::Guard>,
    assembly: Option<QemuHotForkWorldAssembly<PendingTargetChild<F::Guard>>>,
    complete: Option<QemuHotForkCompleteWorldAssembly<PendingTargetChild<F::Guard>>>,
    adopting_child: Option<PendingTargetChild<F::Guard>>,
    adopting_identity: Option<ProductionVmNodeGeneration>,
    reconciliations: Option<LinuxQemuHotForkWorldReconciliationSet<F::Guard>>,
    rollback_children: Option<BTreeMap<crucible_engine::NodeId, PendingTargetChild<F::Guard>>>,
    resources: Option<QemuHotForkWorldResourceOwner<F::Guard>>,
    auxiliary: Option<QemuHotForkWorldAuxiliaryResourceBroker<F::Guard>>,
    auxiliary_binding: Option<
        crate::qemu_hot_fork_world_resource::QemuHotForkWorldAuxiliaryResourceBinding<F::Guard>,
    >,
    disposition: Option<AttemptExecutionDisposition>,
    reservation: Option<crate::WorldLifecycleCleanupReservation>,
    first_begin: Option<crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport>,
    first_preparation: Option<crate::qemu_lifecycle_launcher::TargetPreparationFailure>,
    first_reconciliation: Option<LifecycleApiError>,
    first_aggregate: Option<crate::QemuAttemptResourceGuardCleanupFailure>,
    first_readiness:
        Option<crate::qemu_hot_fork_world_resource::QemuHotForkWorldReleaseReadinessError>,
    body_destroyed: bool,
    aggregate_attempted: bool,
    physically_returned: bool,
    history_disposed: bool,
    pre_body_closed: bool,
    post_body_taken: bool,
    post_body: Option<crate::ProductionVmConstructionPostBody>,
    api_prepared: bool,
    exported: bool,
    members: Option<TargetConstructionStorage>,
    factory: F,
    source_world: Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>>,
    source: Option<QemuHotForkSourceWorldLease>,
}

impl<F> PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Borrows timing evidence from the same Main-owned selected rows.
    #[cfg(test)]
    pub(crate) fn node_launch_timing_summary(&self) -> Option<(u64, u64)> {
        TargetNodeConstruction::launch_timing_summary(self.nodes.as_deref()?)
    }

    /// Moves the existing selected payloads only after Main owns this body.
    ///
    /// Each lock protects metadata only. A refused later move leaves earlier
    /// rows in this SAME Pending and keeps the Source unavailable for reuse.
    pub(crate) fn take_source_storage(&mut self) -> bool {
        if self.nodes.is_none() {
            let source = self
                .source_selector
                .typed::<crate::qemu_lifecycle_launcher::PendingSourceConstruction<F>>();
            match source.with_prepared(|pending| pending.take_target_nodes()) {
                Ok(Some((nodes, retained, geometry))) => {
                    self.nodes = Some(nodes);
                    self.spare_rows = Some(retained);
                    self.worker_geometry = Some(geometry);
                }
                Ok(None) => {
                    self.first_main
                        .get_or_insert(TargetMainAdmissionError::Source);
                    return false;
                }
                Err(first) => {
                    self.first_main
                        .get_or_insert(TargetMainAdmissionError::Main(first));
                    return false;
                }
            }
        }
        if self.members.is_some() {
            return true;
        }
        let Some(lease) = self.source.as_ref() else {
            return false;
        };
        let Some(owner) = self.source_world.as_ref() else {
            return false;
        };
        let Ok(mut source) = owner.try_lock() else {
            return false;
        };
        if !lease.identity().matches(&source)
            || !source
                .prepared_source_selector()
                .is_some_and(|selected| selected.same_role(&self.source_selector))
        {
            self.first_main
                .get_or_insert(TargetMainAdmissionError::Source);
            return false;
        }
        match source.take_target_construction_storage() {
            Ok(members) => {
                self.members = Some(members);
                true
            }
            Err(first) => {
                self.first_preparation.get_or_insert(first);
                false
            }
        }
    }

    /// Measures the actual Main constructor, carrier and native report payloads.
    ///
    /// Selected payloads belong to the Source World query. This measurement is
    /// a request; only the actual containing Main producer can fund its birth.
    pub(crate) fn control_bytes() -> Result<u64, LifecycleApiError> {
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<crate::ProductionVmConstructionCustody>())
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<crucible_qemu_host::OriginalActorAccountError>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| LifecycleApiError::LoopFactory {
                message: String::from("pending Target constructor extent overflows"),
            })
    }

    /// Builds only after Main reserved this actual constructor role's payment.
    ///
    /// The producer installs the returned SAME Box before invoking native
    /// begin. A refused preclaim returns unchanged input and never calls this
    /// constructor or allocates replacement ownership on the failure path.
    pub(crate) fn new_prepaid(
        input: TargetConstructionInput<F>,
        reservation: crate::WorldLifecycleCleanupReservation,
    ) -> Box<Self> {
        let source_world = input.source.source_owner();
        let selector = reservation.service_preclaim().handle().prepared_selector();
        Box::new(Self {
            selector,
            source_selector: input.source_selector,
            nodes: None,
            spare_rows: None,
            worker_geometry: None,
            source_backends: None,
            first_main: None,
            first_setup: None,
            adoptions: Vec::new(),
            continuation: None,
            launch_continuation: Some(input.continuation),
            launch_input: None,
            construction: Some(Box::new(crate::ProductionVmConstructionCustody::new())),
            guard: None,
            assembly: None,
            complete: None,
            adopting_child: None,
            adopting_identity: None,
            reconciliations: None,
            rollback_children: None,
            resources: None,
            auxiliary: None,
            auxiliary_binding: None,
            disposition: None,
            reservation: Some(reservation),
            first_begin: None,
            first_preparation: None,
            first_reconciliation: None,
            first_aggregate: None,
            first_readiness: None,
            body_destroyed: false,
            aggregate_attempted: false,
            physically_returned: false,
            history_disposed: false,
            pre_body_closed: false,
            post_body_taken: false,
            post_body: None,
            api_prepared: false,
            exported: false,
            members: None,
            factory: input.factory,
            source_world,
            source: Some(input.source),
        })
    }

    /// Restores only the same backend/token headers after scoped workers joined.
    ///
    /// This method performs no native operation, callback, allocation or Drop
    /// while the Source metadata mutex is held. Contention keeps the complete
    /// original set in this Main owner for the next bounded attempt.
    fn restore_source_backends(&mut self) -> bool {
        if self.source_backends.is_none() {
            return true;
        }
        let (Some(lease), Some(owner), Some(members)) = (
            self.source.as_ref(),
            self.source_world.as_ref(),
            self.members.as_ref(),
        ) else {
            return false;
        };
        let Ok(mut source) = owner.try_lock() else {
            return false;
        };
        if !lease.identity().matches(&source) {
            return false;
        }
        let Some(backends) = self.source_backends.take() else {
            return false;
        };
        let returned = source.return_target_source_backends(members, backends);
        drop(source);
        match returned {
            Ok(empty) => {
                drop(empty);
                true
            }
            Err(backends) => {
                self.source_backends = Some(backends);
                false
            }
        }
    }

    /// Reserves one real Source member while this SAME body owns its checkout.
    ///
    /// The producer calls this only through the installed Main prepared handle.
    /// An occupied native outcome is already stored in the selected row before
    /// this method returns. No first cause is copied, formatted or moved into a
    /// nonowning caller's diagnostic while the actual role remains outstanding.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_member(&mut self, node: &crucible_engine::NodeId) -> bool {
        use crate::qemu_lifecycle_launcher::TargetMemberAdmission;

        let Some(members) = self.members.as_mut() else {
            return false;
        };
        if self.body_destroyed
            || self.first_preparation.is_some()
            || members.first_admission_failure().is_some()
        {
            return false;
        }
        if !members.contains_member(node) {
            self.first_preparation = Some(
                LifecycleApiError::LoopFactory {
                    message: String::from("Target admission has no paid selected member"),
                }
                .into(),
            );
            return false;
        }
        let Some(source_world) = self.source_world.as_ref() else {
            return false;
        };
        let mut source = match source_world.try_lock() {
            Ok(source) => source,
            Err(_) => {
                self.first_preparation = Some(
                    LifecycleApiError::LoopFactory {
                        message: String::from("Target retains its poisoned Source ownership lock"),
                    }
                    .into(),
                );
                return false;
            }
        };
        if members.native_identity().is_none() {
            let identity = match source.native_world_identity() {
                Ok(identity) => identity,
                Err(first) => {
                    self.first_preparation = Some(first);
                    return false;
                }
            };
            if !members.bind_native_identity(identity) {
                self.first_preparation = Some(
                    LifecycleApiError::LoopFactory {
                        message: String::from("Target World coordinates changed"),
                    }
                    .into(),
                );
                return false;
            }
        }
        let outcome = members.prepare_member(node, || source.prepare_fork_target_for_node(node));
        match outcome {
            Ok(TargetMemberAdmission::Ready) => true,
            Ok(TargetMemberAdmission::Retained) => false,
            Err(first) => {
                self.first_preparation = Some(first);
                false
            }
        }
    }

    /// Starts only the selected real members already admitted in this body.
    ///
    /// The guard moves into its canonical Pending field before any post refusal
    /// is exposed. A pre-guard error leaves all returned native hosts in the
    /// same selected storage; neither branch drops or quarantines an owner.
    #[cfg(target_os = "linux")]
    pub(crate) fn begin_world(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: crate::ExecutionCancellation,
    ) -> bool {
        if self.guard.is_some() || self.first_begin.is_some() || self.first_failure().is_some() {
            return false;
        }
        let Some(members) = self.members.as_mut() else {
            return false;
        };
        match self
            .factory
            .begin_fork_target_world(members, resources, cancellation)
        {
            Ok((guard, first_post)) => {
                self.guard = Some(guard);
                self.first_begin = first_post.map(Into::into);
                self.first_begin.is_none()
            }
            Err(first) => {
                self.first_begin = Some(first.into());
                false
            }
        }
    }

    /// Prepares native storage/history outside all parent and Source locks.
    fn prepare_terminal_handback(&mut self) -> bool {
        if !self.physically_returned || !self.body_destroyed || self.source_backends.is_some() {
            return false;
        }
        if !self.history_disposed {
            if let Some(members) = self.members.as_mut()
                && !members.dispose_returned_history_and_reset()
            {
                return false;
            }
            if let Some(rows) = self.nodes.as_mut() {
                let mut all_vacant = true;
                for row in rows {
                    if !row.dispose_returned_history() {
                        all_vacant = false;
                    }
                }
                if !all_vacant {
                    return false;
                }
            }
            // Aggregate and constructor reports stay in this SAME terminal
            // Main body through actual Source restoration and owner disposal.
            // Only the observed, now-returned row payload must be reset before
            // moving its original allocation back into the Source header.
            self.history_disposed = true;
        }
        let Some(members) = self.members.take() else {
            return true;
        };
        match self.source_selector.external_body_destroyed() {
            Ok(true) => {
                // This factual journal, not a missing launcher/header, proves
                // the original Source body destination no longer exists. The
                // returned native backing is disposed under this terminal role
                // while its still-lent row Vec keeps Source controls paid.
                drop(members);
                true
            }
            Ok(false) => {
                let (Some(lease), Some(owner)) = (self.source.as_ref(), self.source_world.as_ref())
                else {
                    self.members = Some(members);
                    return false;
                };
                let Ok(mut source) = owner.try_lock() else {
                    self.members = Some(members);
                    return false;
                };
                if !lease.identity().matches(&source) || source.fork_target_is_owned() {
                    self.members = Some(members);
                    return false;
                }
                let returned = source.return_target_construction_storage(members);
                drop(source);
                match returned {
                    Ok(()) => true,
                    Err(members) => {
                        self.members = Some(members);
                        false
                    }
                }
            }
            Err(first) => {
                self.members = Some(members);
                self.first_main
                    .get_or_insert(TargetMainAdmissionError::Main(first));
                false
            }
        }
    }

    /// Moves only this exact Source's vacant original Vec into its paid header.
    ///
    /// The protected terminal projection already validates the actual parent
    /// role and factual Target return. No IO, Original, Drop or callback occurs
    /// while that Source prepared mutex is held.
    fn return_terminal_rows(
        &mut self,
        source: &mut crate::qemu_lifecycle_launcher::PendingSourceConstruction<F>,
    ) -> bool {
        if !self.history_disposed || self.members.is_some() || self.source_backends.is_some() {
            return false;
        }
        if let Some(rows) = self.spare_rows.take() {
            if let Err(rows) = source.return_target_nodes(rows) {
                self.spare_rows = Some(rows);
                return false;
            }
        }
        let Some(rows) = self.nodes.take() else {
            return true;
        };
        match source.return_target_retained_nodes(rows) {
            Ok(()) => true,
            Err(rows) => {
                self.nodes = Some(rows);
                false
            }
        }
    }

    fn terminal_metadata_returned(&self) -> bool {
        self.physically_returned
            && self.history_disposed
            && self.nodes.is_none()
            && self.spare_rows.is_none()
            && self.members.is_none()
            && self.source_backends.is_none()
    }

    fn take_terminal_checkout(&mut self) -> Option<QemuHotForkSourceWorldLease> {
        if !self.terminal_metadata_returned() {
            return None;
        }
        // Managed providers retain their own Arc/Weak. Drop this redundant
        // alias outside every Source lock before their real restore transaction.
        drop(self.source_world.take());
        self.source.take()
    }

    /// Observes all selected reports, independently of physical return.
    fn has_history(&self) -> bool {
        self.first_failure().is_some()
            || self
                .nodes
                .as_ref()
                .is_some_and(|rows| rows.iter().any(TargetNodeConstruction::has_history))
    }

    /// Borrows actual history retained in this Main-paid constructor body.
    pub(crate) fn first_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(first) = &self.first_main {
            return Some(first);
        }
        if let Some(first) = &self.first_setup {
            return Some(first);
        }
        if let Some(first) = &self.first_preparation {
            return Some(first);
        }
        #[cfg(target_os = "linux")]
        if let Some(first) = self
            .members
            .as_ref()
            .and_then(TargetConstructionStorage::first_admission_failure)
        {
            return Some(first);
        }
        #[cfg(target_os = "linux")]
        if let Some(first) = self
            .members
            .as_ref()
            .and_then(TargetConstructionStorage::first_cleanup_failure)
        {
            return Some(first);
        }
        #[cfg(target_os = "linux")]
        if let Some(first) = self
            .members
            .as_ref()
            .and_then(TargetConstructionStorage::first_reconciliation_failure)
        {
            return Some(first);
        }
        if let Some(first) = self
            .nodes
            .as_ref()
            .and_then(|rows| rows.iter().find_map(TargetNodeConstruction::first_failure))
        {
            return Some(first);
        }
        if let Some(first) = &self.first_begin {
            return Some(first);
        }
        if let Some(first) = &self.first_reconciliation {
            return Some(first);
        }
        if let Some(first) = &self.first_readiness {
            return Some(first);
        }
        self.first_aggregate
            .as_ref()
            .map(|first| first as &dyn std::error::Error)
    }
}

struct TargetLaunchHistory<'a, G: crate::QemuAttemptResourceGuard>(&'a [TargetNodeConstruction<G>]);

impl<G: crate::QemuAttemptResourceGuard> std::fmt::Debug for TargetLaunchHistory<'_, G> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = formatter.debug_list();
        for row in self.0 {
            if row.has_history() {
                list.entry(&row.history());
            }
        }
        list.finish()
    }
}

impl<F> std::fmt::Debug for PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingTargetConstruction")
            .field("first_main", &self.first_main)
            .field("first_setup", &self.first_setup)
            .field(
                "member_history",
                &self
                    .members
                    .as_ref()
                    .map(TargetConstructionStorage::history),
            )
            .field(
                "launch_history",
                &self
                    .nodes
                    .as_ref()
                    .map(|rows| TargetLaunchHistory(rows.as_slice())),
            )
            .field("first_preparation", &self.first_preparation)
            .field("first_begin", &self.first_begin)
            .field("first_reconciliation", &self.first_reconciliation)
            .field("first_aggregate", &self.first_aggregate)
            .field("first_readiness", &self.first_readiness)
            .field("body_destroyed", &self.body_destroyed)
            .field("physically_returned", &self.physically_returned)
            .finish_non_exhaustive()
    }
}

impl<F> std::fmt::Display for PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "retained Target construction: {self:?}")
    }
}

impl<F> std::error::Error for PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first_failure()
    }
}

impl<F> crucible_control_api::ProductionVmCleanupOwner for PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        if self.pre_body_closed {
            return Ok(());
        }
        if !self.restore_source_backends() {
            return Err(Self::Failure::Retained(
                "exact Source backend handback remains pending",
            ));
        }
        // An untransferred carrier may still own a partial API frame. Native
        // member/aggregate/checkout obligations deliberately remain outside the
        // external Loop body and are driven only after its factual destruction.
        if let Some(construction) = self.construction.as_mut() {
            if self.launch_input.is_some() {
                construction.install_hot_fork_inputs(
                    &mut self.launch_input,
                    &mut self.continuation,
                    &mut self.adoptions,
                )?;
            }
            construction.install_adoption_cleanup(&mut self.adoptions)?;
            construction.retry_cleanup()?;
        } else if !self.adoptions.is_empty() {
            return Err(Self::Failure::Retained(
                "partial Target adoptions retain their original carrier",
            ));
        }
        self.pre_body_closed = true;
        Ok(())
    }

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        if !self.pre_body_closed {
            return Err(Self::Failure::Retained(
                "Target pre-body cleanup remains open",
            ));
        }
        if self.post_body_taken {
            return Ok(None);
        }
        if self.exported {
            let service = self.selector.typed::<Self>().service_main_handle();
            match service.external_body_accepted() {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Self::Failure::Retained(
                        "the original external Target body has not entered Main custody",
                    ));
                }
                Err(first) => {
                    self.first_main
                        .get_or_insert(TargetMainAdmissionError::Main(first));
                    return Err(Self::Failure::Retained(
                        "the original external Target acceptance remains unobservable",
                    ));
                }
            }
        }
        if self.launch_input.is_some() || !self.adoptions.is_empty() {
            return Err(Self::Failure::Retained(
                "Target API inputs remain outside their original carrier",
            ));
        }
        if self.post_body.is_none() {
            self.post_body = if self.exported {
                // The actual returned carrier supplies its own Target tail.
                // This retained constructor contributes only protected history.
                Some(Self::PostBody::history_only())
            } else {
                let body = match self.construction.as_mut() {
                    Some(custody) => {
                        crucible_control_api::ProductionVmCleanupOwner::take_post_body(custody.as_mut())?
                    }
                    None => None,
                };
                Some(body.unwrap_or_else(|| Self::PostBody::target::<Self>(self.selector.clone())))
            };
        }
        // Save the exact obligation before actual frame destruction. An unwind
        // poisons and retains this same Main allocation; no body-return journal
        // or native completion follows a destructor that did not finish.
        drop(self.construction.take());
        drop(self.continuation.take());
        drop(self.launch_continuation.take());
        self.post_body_taken = true;
        Ok(self.post_body.take())
    }
}

impl<F> PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Gives each same preborn node row one bounded cleanup opportunity.
    fn retry_node_rows(&mut self) -> bool {
        let Some(nodes) = self.nodes.as_mut() else {
            return self.members.is_none();
        };
        let Some(members) = self.members.as_mut() else {
            return nodes.iter().all(TargetNodeConstruction::is_vacant);
        };
        let mut all_returned = true;
        for row in nodes {
            if !row.retry_owned_cleanup(members) {
                all_returned = false;
            }
        }
        all_returned
    }

    /// Moves already allocated child maps after their actual API aliases close.
    fn prepare_rollback_children(&mut self) -> bool {
        if self.rollback_children.is_some() {
            return true;
        }
        let alternatives =
            usize::from(self.assembly.is_some()) + usize::from(self.complete.is_some());
        if alternatives > 1 {
            return false;
        }
        let children = if let Some(assembly) = self.assembly.take() {
            Some(assembly.into_rollback_children())
        } else if let Some(complete) = self.complete.take() {
            Some(complete.into_rollback_children())
        } else if let Some(reconciliations) = self.reconciliations.as_mut() {
            let Some(rows) = self.nodes.as_ref() else {
                return false;
            };
            let unadopted = rows
                .iter()
                .filter(|row| row.is_live_boundary() && !row.was_world_adopted())
                .map(|row| &row.node);
            match reconciliations.take_construction_post_body_children(unadopted) {
                Ok(children) => {
                    // The map has moved. This destroys only the empty unique
                    // registry, with no Source/native/queue mutex held.
                    drop(self.reconciliations.take());
                    Some(children)
                }
                Err(first) => {
                    self.first_reconciliation.get_or_insert(first);
                    return false;
                }
            }
        } else {
            None
        };
        self.rollback_children = children;
        true
    }

    /// Gives every retained member one bounded saved-Cleanup step per pass.
    fn retry_rollback_children(&mut self) -> bool {
        if let Some(child) = self.adopting_child.as_mut() {
            let (Some(identity), Some(members)) =
                (self.adopting_identity.as_ref(), self.members.as_mut())
            else {
                return false;
            };
            if !members.rollback_child(identity.node(), child) {
                return false;
            }
            drop(self.adopting_child.take());
            drop(self.adopting_identity.take());
        }
        if !self.prepare_rollback_children() {
            return false;
        }
        let Some(children) = self.rollback_children.as_mut() else {
            return true;
        };
        let Some(members) = self.members.as_mut() else {
            return false;
        };
        let disposition = self
            .disposition
            .unwrap_or(AttemptExecutionDisposition::Canceled);
        for retired in children.extract_if(.., |node, child| {
            members.settle_child(node, child, disposition)
        }) {
            // The saved Cleanup and all Source/registry locks were released by
            // rollback_child before actual completed child metadata is dropped.
            drop(retired);
        }
        if !children.is_empty() {
            return false;
        }
        drop(self.rollback_children.take());
        // A partial adoption legitimately leaves two maps: unadopted children
        // in the assembly and returned leases in the registry. Drain them in
        // separate bounded passes before touching the aggregate.
        self.assembly.is_none() && self.complete.is_none() && self.reconciliations.is_none()
    }

    /// Closes only the same aggregate, preserving its actual first raw report.
    fn retry_aggregate(&mut self) -> bool {
        if self.aggregate_attempted {
            return true;
        }
        if let Some(resources) = self.resources.as_mut() {
            use crate::qemu_hot_fork_world_resource::QemuHotForkWorldReleaseReadiness;
            match resources.release_readiness() {
                Ok(QemuHotForkWorldReleaseReadiness::Ready) => {}
                Ok(_) => return false,
                Err(first) => {
                    self.first_readiness.get_or_insert(first);
                    return false;
                }
            }
            self.aggregate_attempted = true;
            if let Err(first) = resources.finish() {
                self.first_aggregate.get_or_insert(first);
            }
        } else if let Some(guard) = self.guard.as_mut() {
            self.aggregate_attempted = true;
            if let Err(first) = guard.finish() {
                self.first_aggregate.get_or_insert(first);
            }
        } else if let Some(members) = self.members.as_mut() {
            // A pre-G composition/birth refusal still owns its actual partial
            // hosts in the original vector. The saved native Cleanups, not a
            // newly admitted guard, drive those same owners here.
            if let Err(first) = members.retry_native_bodies() {
                self.first_aggregate.get_or_insert_with(|| first.into());
            }
        }
        true
    }
}

impl<F> crate::lifecycle_cleanup::TargetConstructionPostBody for PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn retry_after_body(&mut self) -> bool {
        if self.physically_returned {
            return true;
        }
        // The canonical selector invokes this callback only after its exact
        // body_destroyed_epoch. It is not a caller-supplied physical assertion.
        self.body_destroyed = true;
        if !self.restore_source_backends() {
            return false;
        }
        if !self.retry_node_rows() || !self.retry_rollback_children() || !self.retry_aggregate() {
            return false;
        }
        let Some(members) = self.members.as_mut() else {
            // No selected native storage ever left Source, so this private
            // Pending could neither reserve a member nor begin physical Target.
            // Its checkout/row handback still remains terminal work below.
            if self.guard.is_none()
                && self.resources.is_none()
                && self.assembly.is_none()
                && self.complete.is_none()
                && self.adopting_child.is_none()
                && self.adopting_identity.is_none()
                && self.reconciliations.is_none()
                && self.rollback_children.is_none()
                && self.source_backends.is_none()
            {
                self.physically_returned = true;
            }
            return self.physically_returned;
        };
        if !members.retry_native_loans() {
            return false;
        }
        let recovered = if let Some(resources) = self.resources.as_mut() {
            resources.recover_target_construction_storage(members)
        } else if let Some(guard) = self.guard.as_mut() {
            guard.recover_target_construction_storage(members)
        } else {
            members.recover_retained_native_storage()
        };
        if !recovered {
            return false;
        }
        // Genuine loan returns precede storage recovery and every remaining
        // empty guard/control alias drop. Source rows and checkout remain in
        // this same paid Main body through protected terminal observation.
        drop(self.auxiliary.take());
        drop(self.auxiliary_binding.take());
        drop(self.resources.take());
        drop(self.guard.take());
        self.physically_returned = true;
        true
    }

    fn source_selector(&self) -> &crate::PreparedSourceSelector {
        &self.source_selector
    }

    fn is_physically_returned(&self) -> bool {
        self.physically_returned
    }

    fn first_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        PendingTargetConstruction::first_failure(self)
    }
}

/// Returns the original Source checkout only through its terminal Target owner.
///
/// Native returns/body destruction precede history disposal. The only nested
/// parent borrow moves vacant metadata; contention retains the SAME vector and
/// checkout in the SAME paid terminal body for the next bounded retry.
pub(crate) fn finalize_target_terminal<F>(
    body: &mut crate::ProductionVmConstructionPostBody,
) -> Option<QemuHotForkSourceWorldLease>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    if !return_target_terminal_metadata::<F>(body) {
        return None;
    }
    body.with_terminal_prepared::<PendingTargetConstruction<F>, _>(|target| {
        target.take_terminal_checkout()
    })?
}

/// Returns existing metadata before either observed or abandoned terminal disposal.
fn return_target_terminal_metadata<F>(body: &mut crate::ProductionVmConstructionPostBody) -> bool
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    if body.with_terminal_prepared::<PendingTargetConstruction<F>, _>(|target| {
        target.terminal_metadata_returned()
    }) == Some(true)
    {
        return true;
    }
    if body.with_terminal_prepared::<PendingTargetConstruction<F>, _>(|target| {
        target.prepare_terminal_handback()
    }) != Some(true)
    {
        return false;
    }
    body.with_terminal_target_parent_metadata::<
        PendingTargetConstruction<F>,
        crate::qemu_lifecycle_launcher::PendingSourceConstruction<F>,
        _,
    >(|target, source| target.return_terminal_rows(source)) == Some(true)
}
