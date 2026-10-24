//! Owned inactive native staging and one durable whole-world activation barrier.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_format::{CapturedOwner, ContentRef, HashRef, Id, Position, U64};

use crate::node_admission::AdmittedGraph;
use crate::node_contract::{
    ActivationPublisher, ActivationRecord, NativeRuntimeContinuationVerifier, NodeRuntime,
    OwnerIdentity, PreparedRuntimeRestore, PreparedWorldPublication, PublicationStatus,
    QuarantinedRuntime, RuntimeCustodySupervisor, RuntimeError, RuntimeLimits, SimulationNode,
    WorldActivation,
};
use crate::node_scheduling::PreparedSchedulingRestore;

#[path = "transaction/publication.rs"]
mod publication;

use super::validation::{incompatible, incomplete};
use super::{
    PreparedNativeCustody, PreparedRestoreAllocation, StateError, StateErrorCode, StateLimits,
    VerifiedCapture,
};

/// Reports original-world disposition established by the native preservation adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginalWorldDisposition {
    /// Accepted native proof establishes that the original can still resume.
    Resumable,
    /// Original state remains stopped awaiting reconciliation.
    StoppedAwaitingReconciliation,
    /// Accepted native proof establishes that original owners terminated.
    Terminated,
    /// Available evidence cannot establish original-world disposition.
    Unknown,
}

/// Preserves durable publication knowledge independently of restoration success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationKnowledge {
    /// No durable publication was attempted for this generation.
    NotAttempted,
    /// The trusted publisher establishes that the original record did not commit.
    NotCommitted,
    /// The original record may have committed and requires reconciliation.
    Unknown,
    /// The original record committed even if later local installation failed.
    Committed,
}

impl From<PublicationStatus> for PublicationKnowledge {
    fn from(status: PublicationStatus) -> Self {
        match status {
            PublicationStatus::NotCommitted => Self::NotCommitted,
            PublicationStatus::Unknown => Self::Unknown,
            PublicationStatus::Committed => Self::Committed,
        }
    }
}

/// Reports actual complete-world resource reservations made under enforced limits.
#[derive(Clone, Copy, Debug, Default)]
pub struct RestoreReservations {
    /// Gives reserved native memory, including peak inter-boundary requirements.
    pub memory_bytes: u64,
    /// Gives reserved writable storage across all state owners.
    pub writable_bytes: u64,
    /// Gives the complete owned process reservation.
    pub processes: u64,
    /// Gives the complete owned descriptor reservation.
    pub descriptors: u64,
}

/// Reports one restored owner's authentic ready-state projection beneath a closed gate.
#[derive(Clone, Debug)]
pub struct RestoredOwnerAttestation {
    /// Names the exact new authoritative owner incarnation.
    pub identity: OwnerIdentity,
    /// Enumerates all preserved authoritative mutable domains.
    pub state_domain_ids: Vec<Id>,
    /// Binds the complete actual participant compatibility roster.
    pub binding_hashes: Vec<HashRef>,
    /// Gives the unchanged preserved consistent cut.
    pub cut: Position,
    /// Gives the unchanged preserved coordinator event ordinal.
    pub event_ordinal: U64,
    /// Binds complete queues, clock mappings and rebased transfer custody.
    pub state_inventory: ContentRef,
    /// Binds authentic native nonexecuting readiness evidence.
    pub ready_receipt: ContentRef,
}

/// Owns native resources and coordinator state while ordinary execution is withheld.
///
/// Implementations are trusted installed adapters. They must retain authoritative
/// native state and reservation custody through every failure or dropped borrower.
/// Shared owners are restored once; public node views must not create additional
/// mutable replicas. No method may execute guest work, drain modeled events,
/// consume ordinary world inputs or publish outputs during preparation.
/// Lazy restoration must retain authenticated backing leases for every future
/// fetch through the final native use; borrowed admission buffers or a digest
/// alone do not retain an available preservation source.
pub trait NativeRestoreStaging: NativeRuntimeContinuationVerifier {
    /// Observes requested backing of an independently authenticated concrete staging owner.
    ///
    /// This DATA callback is not a general purity promise for arbitrary trait
    /// implementations. The caller must authenticate the closed original
    /// constructor before invoking it; labels or public fields do not suffice.
    /// The enclosing Box layout is charged separately. Unknown families return
    /// `None`; no lifecycle, restoration or execution right is created.
    ///
    /// # Errors
    /// Refuses busy/foreign owners, unsupported fields, overflow or the bound.
    fn retained_requested_storage_precredit_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, RuntimeError> {
        Ok(None)
    }

    /// Names explicit fixed scratch of the authenticated closed DATA walk.
    ///
    /// # Errors
    /// Refuses unsupported families, foreign creator or arithmetic overflow.
    fn retained_requested_storage_precredit_scratch_data(
        &self,
    ) -> Result<Option<usize>, RuntimeError> {
        Ok(None)
    }

    /// Reports the complete actual native resource reservation.
    fn reservations(&self) -> RestoreReservations;

    /// Reports authenticated original-world disposition without claiming rollback.
    fn original_disposition(&self) -> OriginalWorldDisposition;

    /// Restores one original capture into its already admitted fresh native owner.
    ///
    /// # Errors
    /// Rejects unavailable sources, changed schemas, inadequate isolation or failed
    /// native reconstruction while retaining allocated resources under custody.
    fn prepare_owner(
        &mut self,
        capture: &VerifiedCapture,
        owner: &CapturedOwner,
        activation: &ActivationRecord,
    ) -> Result<RestoredOwnerAttestation, StateError>;

    /// Authenticates actual restored domains and closed-gate readiness independently.
    ///
    /// # Errors
    /// Rejects copied or incomplete readiness receipts, original live permissions,
    /// missing pending queues or transport authority not rebound to new incarnations.
    fn verify_prepared_owner(
        &self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        attestation: &RestoredOwnerAttestation,
    ) -> Result<(), StateError>;

    /// Restores complete non-runnable coordinator state and cross-owner custody.
    ///
    /// # Errors
    /// Rejects missing fault/assertion/PRNG/operation-ledger state or inconsistent
    /// pending transfers. Logical exactly-once positions must survive transport rebinding.
    fn prepare_coordinator(
        &mut self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
    ) -> Result<ContentRef, StateError>;

    /// Authenticates the complete restored world and all cross-owner projections.
    ///
    /// # Errors
    /// Rejects incomplete owner/coordinator inventory, inconsistent cut or custody,
    /// unsupported host features or any guest-visible effect performed during staging.
    fn verify_prepared_world(
        &self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        owners: &[RestoredOwnerAttestation],
        coordinator_receipt: &ContentRef,
    ) -> Result<(), StateError>;

    /// Transfers actual public node handles while retaining extra coordinator custody.
    ///
    /// # Errors
    /// Rejects unavailable or already transferred handles. A partial transfer must
    /// remain supervised by this capsule; no resources may disappear on an error.
    fn take_nodes(&mut self) -> Result<Vec<Box<dyn SimulationNode>>, StateError>;

    /// Retains and authenticates closed native gates under uncertain publication.
    ///
    /// # Errors
    /// Rejects unavailable containment. Success preserves staged state and all
    /// resources without releasing execution or input/output publication rights.
    fn contain_uncertain_publication(
        &mut self,
        activation: &ActivationRecord,
    ) -> Result<(), StateError>;

    /// Transfers all remaining native and coordinator obligations to supervision.
    ///
    /// This idempotent hook must retain resources until authentic reclamation;
    /// it must not discard live leases or interpret cancellation as rollback.
    /// Supervision must own the exact activation record and publication knowledge
    /// beyond this capsule's lifetime. An uncertain record permits reconciliation
    /// of that generation only; a committed generation must never be replaced
    /// merely because local restoration failed or its borrower disappeared.
    fn quarantine_resources(
        &mut self,
        activation: &ActivationRecord,
        publication: PublicationKnowledge,
    );

    /// Polls actual reclamation of capsule-owned coordinator and extra native resources.
    ///
    /// # Errors
    /// Returns failed cleanup while retaining custody; pending arranges a wake or
    /// documented bounded supervisory repolling. Success requires native evidence.
    fn poll_reclamation(&mut self, context: &mut Context<'_>) -> Poll<Result<(), StateError>>;
}

/// Creates a complete native staging capsule under authenticated host policy.
pub trait WorldRestoreDriver: RuntimeCustodySupervisor {
    /// Allocates inactive fresh owners under complete resource reservations.
    ///
    /// # Errors
    /// Rejects unsupported native reconstruction or unavailable resources. The
    /// driver installs its empty capsule into `allocation` before allocating
    /// external resources, then allocates exclusively into that owned capsule.
    /// Limits are enforced before allocation. Error and callback unwind retain
    /// the capsule and complete source in their already reserved owning slot.
    fn stage_world(
        &mut self,
        graph: &AdmittedGraph,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        limits: StateLimits,
        allocation: &mut PreparedRestoreAllocation,
    ) -> Result<(), StateError>;
}

/// Retains a failed replacement world's native custody without execution authority.
#[must_use = "retain failed native state until actual reclamation or supervised transfer"]
pub struct RestoreFailure {
    /// Identifies the refused state or transaction obligation.
    pub error: StateError,
    /// Reports what actual evidence establishes about the original world.
    pub original: OriginalWorldDisposition,
    publication: PublicationKnowledge,
    activation: Option<Box<ActivationRecord>>,
    prepared_publication: Option<Rc<PreparedWorldPublication>>,
    staging: Option<Box<PreparedNativeCustody>>,
    runtime: Option<Box<QuarantinedRuntime>>,
    rejected_runtime: Option<Box<crate::node_contract::RuntimePreparationFailure>>,
    panic_payload: Option<Box<dyn std::any::Any + Send>>,
}

impl RestoreFailure {
    /// Retains a native staging failure and its authentic resource capsule.
    pub fn native(
        error: StateError,
        activation: ActivationRecord,
        publication: PublicationKnowledge,
        mut staging: PreparedNativeCustody,
    ) -> Self {
        let original = staging.original_disposition();
        staging.quarantine_resources(&activation, publication);
        Self {
            error,
            original,
            publication,
            activation: Some(Box::new(activation)),
            prepared_publication: None,
            staging: Some(Box::new(staging)),
            runtime: None,
            rejected_runtime: None,
            panic_payload: None,
        }
    }

    /// Reports a no-allocation refusal without asserting source-world preservation.
    pub fn refused(error: StateError) -> Self {
        Self {
            error,
            original: OriginalWorldDisposition::Unknown,
            publication: PublicationKnowledge::NotAttempted,
            activation: None,
            prepared_publication: None,
            staging: None,
            runtime: None,
            rejected_runtime: None,
            panic_payload: None,
        }
    }

    /// Reports an original opaque callback panic retained by an opt-in owner.
    ///
    /// The payload is not serialized, formatted, resumed or reinterpreted as
    /// authority. Its private heap layout is unknown; a complete owning-storage
    /// observer must refuse unsupported accounting rather than count it as zero.
    pub fn has_retained_panic_payload_data(&self) -> bool {
        self.panic_payload.is_some()
    }

    /// Reports durable publication knowledge without implying native rollback.
    pub fn publication_knowledge(&self) -> PublicationKnowledge {
        self.publication
    }

    /// Returns the exact proposed or attempted generation retained by this failure.
    pub fn original_activation(&self) -> Option<&ActivationRecord> {
        self.activation.as_deref()
    }

    /// Reconciles only the original uncertain durable record under retained containment.
    ///
    /// Reconciliation updates publication knowledge; it never recreates an
    /// activation token or releases quarantined native state. A committed result
    /// still requires supervisory recovery of the original generation.
    ///
    /// # Errors
    /// Refuses reconciliation when publication was not uncertain or the original
    /// record is unavailable. These refusals never query a replacement generation.
    pub fn reconcile_publication(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<PublicationKnowledge, StateError> {
        if self.publication != PublicationKnowledge::Unknown {
            return Err(incompatible(
                "failed publication",
                "only the original uncertain record can be reconciled",
            ));
        }
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| incomplete("failed publication", "original durable record absent"))?;
        let status = match &mut self.runtime {
            Some(runtime) => runtime
                .reconcile_publication(activation, publisher)
                .map_err(|error| {
                    StateError::new(
                        StateErrorCode::Restoration,
                        "failed publication reconciliation",
                        error.to_string(),
                    )
                })?,
            None => match &self.prepared_publication {
                Some(prepared) => publisher.reconcile_complete(activation, prepared),
                None => publisher.reconcile(activation),
            },
        };
        self.publication = status.into();
        if let Some(staging) = &mut self.staging {
            staging.quarantine_resources(activation, self.publication);
        }
        Ok(self.publication)
    }

    /// Borrows retained whole-runtime containment for authentic reclamation polling.
    pub fn quarantined_runtime(&mut self) -> Option<&mut QuarantinedRuntime> {
        self.runtime.as_deref_mut()
    }

    /// Polls capsule-owned resource reclamation without losing failed native handles.
    ///
    /// # Errors
    /// Returns cleanup failure while keeping ownership. Success covers only the
    /// capsule; runtime or rejected-node reclamation obligations remain separate.
    pub fn poll_capsule_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), StateError>> {
        match self.staging.as_mut() {
            Some(staging) => staging.poll_reclamation(context),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for RestoreFailure {
    fn drop(&mut self) {
        if let (Some(staging), Some(activation)) = (&mut self.staging, &self.activation) {
            staging.quarantine_resources(activation, self.publication);
        }
    }
}

/// Retains every prepared owner and coordinator while withholding activation authority.
#[must_use = "prepared worlds require complete durable activation or retained containment"]
pub struct PreparedRestore<'a> {
    graph: &'a AdmittedGraph,
    capture: Rc<VerifiedCapture>,
    activation: ActivationRecord,
    publication: PublicationKnowledge,
    prepared_publication: Option<Rc<PreparedWorldPublication>>,
    staging: Option<PreparedNativeCustody>,
    runtime: Option<NodeRuntime>,
    scheduler: Option<PreparedSchedulingRestore>,
    continuation: Option<PreparedRuntimeRestore>,
}

/// Reports complete publication without mistaking uncertainty for rollback.
#[must_use = "uncertain publication retains the original generation and native custody"]
pub enum RestorePublication<'a> {
    /// Owns one completely published replacement world and its fresh authority.
    Committed(Box<RestoredWorld>),
    /// Retains failed replacement resources without exposing a partial world.
    Failed(RestoreFailure),
    /// Retains the exact original generation for reconciliation under closed gates.
    Uncertain(Box<PendingRestorePublication<'a>>),
}

/// Retains the original whole-world publication attempt without execution permission.
#[must_use = "reconcile the original publication; dropping transfers native custody to supervision"]
pub struct PendingRestorePublication<'a> {
    prepared: PreparedRestore<'a>,
}

/// Owns one completely restored world with retained native and coordinator custody.
#[must_use = "retain the restored world while its native resources remain live"]
pub struct RestoredWorld {
    runtime: NodeRuntime,
    activation: WorldActivation,
    staging: PreparedNativeCustody,
    artifact: ContentRef,
    original: OriginalWorldDisposition,
    repeatability: crucible_node_format::Repeatability,
}

impl RestoredWorld {
    /// Observes the original restored runtime and its authenticated closed staging.
    ///
    /// The caller must retain and authenticate the concrete installed factory
    /// before lending its same erased Rc. This data read neither publishes nor
    /// polls native work. The enclosing world Box is charged separately.
    ///
    /// # Errors
    /// Refuses missing original factory correspondence, unknown/busy custody,
    /// unsupported fields or the requested bound.
    pub fn original_closed_requested_storage_precredit_data(
        &self,
        original_factory: &Rc<dyn super::NativeWorldFactory>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
        let Self {
            runtime,
            activation,
            staging,
            artifact,
            original: _,
            repeatability: _,
        } = self;
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(
            runtime.original_retained_requested_storage_precredit_data(counter.remaining())?,
        )?;
        let facts = activation.retained_requested_storage_data(counter.remaining())?;
        counter.views(
            facts.independent_bytes(),
            facts
                .shared_allocations()
                .map(|root| (root.identity(), root.requested_bytes())),
        )?;
        counter.owned(artifact)?;
        counter
            .add(staging.original_closed_storage_data(original_factory, counter.remaining())?)?;
        Ok(counter.bytes())
    }

    /// Names simultaneous counters and the maximum sequential native data scratch.
    ///
    /// # Errors
    /// Refuses missing original factory correspondence or unsupported scratch.
    pub fn original_closed_requested_storage_precredit_scratch_data(
        &self,
        original_factory: &Rc<dyn super::NativeWorldFactory>,
    ) -> Result<usize, RuntimeError> {
        let runtime = self
            .runtime
            .original_retained_requested_storage_precredit_scratch_data()?;
        let staging = self
            .staging
            .original_closed_storage_scratch_data(original_factory)?;
        std::mem::size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>()
            .checked_add(runtime.max(staging))
            .and_then(|bytes| {
                bytes.checked_add(NodeRuntime::capture_opaque_owner_observer_scratch_data())
            })
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Returns fresh authority minted by the runtime's complete publication barrier.
    pub fn activation(&self) -> &WorldActivation {
        &self.activation
    }

    /// Borrows the single authoritative runtime and its retained restored scheduler.
    pub fn runtime_mut(&mut self) -> &mut NodeRuntime {
        &mut self.runtime
    }

    /// Returns the authenticated complete artifact used for this reconstruction.
    pub fn artifact(&self) -> &ContentRef {
        &self.artifact
    }

    /// Reports authenticated source-world disposition after reconstruction.
    pub fn original_disposition(&self) -> OriginalWorldDisposition {
        self.original
    }

    /// Reports preserved graph-wide repeatability independently of exact restoration.
    pub fn world_repeatability(&self) -> crucible_node_format::Repeatability {
        self.repeatability
    }
}

impl Drop for RestoredWorld {
    fn drop(&mut self) {
        self.staging
            .quarantine_resources(self.activation.record(), PublicationKnowledge::Committed);
    }
}

/// Prepares complete state under fresh admitted owners before global publication.
///
/// # Errors
/// Refuses changed world bindings, source identities, incompatible native owners,
/// resource excess, unrepresentable coordinator continuation, incomplete ready
/// domains or failed native proof. Allocated handles remain in the returned failure;
/// no individual owner receives execution permission during preparation.
pub fn stage_restore<'a>(
    graph: &'a AdmittedGraph,
    capture: VerifiedCapture,
    activation: ActivationRecord,
    driver: &mut dyn WorldRestoreDriver,
    limits: StateLimits,
) -> Result<PreparedRestore<'a>, RestoreFailure> {
    let original_activation = activation.clone();
    stage_restore_inner(graph, capture, activation, driver, limits).map_err(|mut failure| {
        // Allocation and native preparation have no publication permission.
        failure.publication = PublicationKnowledge::NotAttempted;
        failure.activation = Some(Box::new(original_activation));
        failure
    })
}

fn stage_restore_inner<'a>(
    graph: &'a AdmittedGraph,
    capture: VerifiedCapture,
    activation: ActivationRecord,
    driver: &mut dyn WorldRestoreDriver,
    limits: StateLimits,
) -> Result<PreparedRestore<'a>, RestoreFailure> {
    let capture = Rc::new(capture);
    validate_fresh_target(graph, &capture, &activation).map_err(RestoreFailure::refused)?;
    let runtime_limits = RuntimeLimits {
        maximum_nodes: graph.node_ids().count(),
        maximum_owners: limits.maximum_owners_or_domains,
        ..RuntimeLimits::default()
    };
    PreparedRuntimeRestore::validate_saved(
        graph,
        &activation,
        &capture.scheduler,
        &capture.runtime,
        runtime_limits,
        limits.maximum_record_bytes,
    )
    .map_err(|error| {
        RestoreFailure::refused(StateError::new(
            StateErrorCode::Restoration,
            "runtime continuation",
            error.to_string(),
        ))
    })?;
    let prepared_slot = driver
        .reserve_world(&activation, runtime_limits)
        .map_err(|error| {
            RestoreFailure::refused(StateError::new(
                StateErrorCode::Restoration,
                "runtime custody reservation",
                error.to_string(),
            ))
        })?;
    let custody_slot = driver
        .reserve_world(&activation, runtime_limits)
        .map_err(|error| {
            RestoreFailure::refused(StateError::new(
                StateErrorCode::Restoration,
                "runtime custody reservation",
                error.to_string(),
            ))
        })?;
    let mut allocation = PreparedRestoreAllocation::new(
        prepared_slot,
        Rc::clone(&capture),
        activation.clone(),
        runtime_limits,
    );
    let staged = driver.stage_world(graph, &capture, &activation, limits, &mut allocation);
    let mut staging = allocation.finish().map_err(RestoreFailure::refused)?;
    if let Err(error) = staged {
        return Err(RestoreFailure::native(
            error,
            activation.clone(),
            PublicationKnowledge::NotAttempted,
            staging,
        ));
    }
    let preparation = prepare_native(staging.as_mut(), &capture, &activation, limits);
    if let Err(error) = preparation {
        return Err(RestoreFailure::native(
            error,
            activation.clone(),
            PublicationKnowledge::NotAttempted,
            staging,
        ));
    }
    let continuation = match PreparedRuntimeRestore::prepare(
        graph,
        &activation,
        &capture.scheduler,
        capture.runtime.clone(),
        staging.as_mut(),
        runtime_limits,
        limits.maximum_record_bytes,
    ) {
        Ok(continuation) => continuation,
        Err(error) => {
            return Err(RestoreFailure::native(
                StateError::new(
                    StateErrorCode::NativeEvidence,
                    "runtime continuation",
                    error.to_string(),
                ),
                activation.clone(),
                PublicationKnowledge::NotAttempted,
                staging,
            ));
        }
    };
    let scheduler = match PreparedSchedulingRestore::prepare_with_native_custody(
        graph,
        &activation,
        capture.scheduler.clone(),
        continuation.native_continuation(),
    ) {
        Ok(scheduler) => scheduler,
        Err(error) => {
            return Err(RestoreFailure::native(
                StateError::new(
                    StateErrorCode::Restoration,
                    "coordinator snapshot",
                    error.to_string(),
                ),
                activation.clone(),
                PublicationKnowledge::NotAttempted,
                staging,
            ));
        }
    };
    let nodes = match staging.take_nodes() {
        Ok(nodes) => nodes,
        Err(error) => {
            return Err(RestoreFailure::native(
                error,
                activation.clone(),
                PublicationKnowledge::NotAttempted,
                staging,
            ));
        }
    };
    let mut runtime = match NodeRuntime::new(
        graph,
        nodes,
        activation.clone(),
        runtime_limits,
        custody_slot,
    ) {
        Ok(runtime) => runtime,
        Err(failure) => {
            let mut retained = RestoreFailure::native(
                StateError::new(
                    StateErrorCode::Restoration,
                    "runtime roster",
                    failure.error.to_string(),
                ),
                activation.clone(),
                PublicationKnowledge::NotAttempted,
                staging,
            );
            retained.rejected_runtime = Some(failure);
            return Err(retained);
        }
    };
    if let Err(error) = runtime.arm_all() {
        let mut failure = RestoreFailure::native(
            StateError::new(
                StateErrorCode::Restoration,
                "all-owner readiness",
                error.to_string(),
            ),
            activation.clone(),
            PublicationKnowledge::NotAttempted,
            staging,
        );
        failure.runtime = Some(Box::new(runtime.into_quarantine()));
        return Err(failure);
    }
    Ok(PreparedRestore {
        graph,
        capture,
        activation,
        publication: PublicationKnowledge::NotAttempted,
        prepared_publication: None,
        staging: Some(staging),
        runtime: Some(runtime),
        scheduler: Some(scheduler),
        continuation: Some(continuation),
    })
}

fn validate_fresh_target(
    graph: &AdmittedGraph,
    capture: &VerifiedCapture,
    activation: &ActivationRecord,
) -> Result<(), StateError> {
    if graph.world_binding_hash() != &capture.manifest.world_binding_hash
        || activation.world_binding_hash != capture.manifest.world_binding_hash
        || activation.boundary != capture.manifest.cut
        || activation.generation.get() <= capture.scheduler.source_generation.get()
        || activation.activation_id == capture.scheduler.source_activation_id
    {
        return Err(incompatible(
            "restore target",
            "actual world, preserved cut or fresh generation differs",
        ));
    }
    let expected: Vec<_> = graph.owners().map(|owner| owner.owner.id.clone()).collect();
    if activation
        .owners
        .iter()
        .map(|owner| owner.owner.clone())
        .collect::<Vec<_>>()
        != expected
    {
        return Err(incomplete(
            "restore target",
            "fresh activation does not contain every authoritative owner",
        ));
    }
    for target in &activation.owners {
        let source = capture
            .source_owners
            .iter()
            .find(|source| source.owner == target.owner)
            .ok_or_else(|| incomplete(target.owner.as_str(), "source owner provenance absent"))?;
        if target.generation.get() <= source.generation.get()
            || capture
                .source_owners
                .iter()
                .any(|source| source.incarnation == target.incarnation)
        {
            return Err(StateError::new(
                StateErrorCode::StaleAuthority,
                target.owner.as_str(),
                "saved live incarnation/generation cannot authorize a replacement",
            ));
        }
    }
    Ok(())
}

fn prepare_native(
    staging: &mut dyn NativeRestoreStaging,
    capture: &VerifiedCapture,
    activation: &ActivationRecord,
    limits: StateLimits,
) -> Result<(), StateError> {
    let reservations = staging.reservations();
    if reservations.memory_bytes > limits.maximum_native_memory_bytes
        || reservations.writable_bytes > limits.maximum_native_writable_bytes
        || reservations.processes > limits.maximum_native_processes
        || reservations.descriptors > limits.maximum_native_descriptors
    {
        return Err(super::closure::limit("complete native reservation"));
    }
    let mut attestations = Vec::with_capacity(capture.manifest.owners.len());
    for owner in &capture.manifest.owners {
        let attestation = staging.prepare_owner(capture, owner, activation)?;
        let identity = activation
            .owners
            .iter()
            .find(|identity| identity.owner == owner.capture_owner_id)
            .ok_or_else(|| incomplete(owner.capture_owner_id.as_str(), "fresh owner absent"))?;
        attestation
            .ready_receipt
            .validate()
            .map_err(super::schema)?;
        attestation
            .state_inventory
            .validate()
            .map_err(super::schema)?;
        if attestation.identity != *identity
            || attestation.state_domain_ids != owner.state_domain_ids
            || attestation.binding_hashes != owner.binding_hashes
            || attestation.cut != capture.manifest.cut
            || attestation.event_ordinal != capture.manifest.event_ordinal
        {
            return Err(incomplete(
                owner.capture_owner_id.as_str(),
                "native restored ready projection differs from preserved state",
            ));
        }
        staging.verify_prepared_owner(capture, activation, &attestation)?;
        attestations.push(attestation);
    }
    let coordinator = staging.prepare_coordinator(capture, activation)?;
    coordinator.validate().map_err(super::schema)?;
    staging.verify_prepared_world(capture, activation, &attestations, &coordinator)
}

use crucible_node_format::Validate;

struct RecordingPublisher<'a> {
    publisher: &'a mut dyn ActivationPublisher,
    status: Option<PublicationStatus>,
    publication: &'a mut PublicationKnowledge,
    prepared: &'a mut Option<Rc<PreparedWorldPublication>>,
    retain_first: bool,
}

impl RecordingPublisher<'_> {
    fn retain_complete_bank(&mut self, prepared: &PreparedWorldPublication) -> bool {
        if self.retain_first
            && let Some(original) = self.prepared.as_ref()
        {
            // The opt-in handoff already owns its complete first body. Equality
            // authenticates all fields without replacing that owning allocation.
            return original.as_ref() == prepared;
        }
        *self.prepared = Some(Rc::new(prepared.clone()));
        true
    }
}

impl ActivationPublisher for RecordingPublisher<'_> {
    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[crate::node_contract::ValidatedNodePreparation],
    ) -> Result<crate::node_scheduling::InputPayload, crate::node_contract::RuntimeError> {
        self.publisher.prepare_coordinator(record, nodes)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &crate::node_contract::PreparedWorldPublication,
    ) -> PublicationStatus {
        if !self.retain_complete_bank(prepared) {
            // A changed complete body cannot reach the actual publisher. Keep
            // the original bank and conservative prior publication uncertainty.
            self.status = Some(PublicationStatus::Unknown);
            *self.publication = PublicationKnowledge::Unknown;
            return PublicationStatus::Unknown;
        }
        self.status = Some(PublicationStatus::Unknown);
        *self.publication = PublicationKnowledge::Unknown;
        let status = self.publisher.publish_complete(record, prepared);
        self.status = Some(status);
        *self.publication = status.into();
        status
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &crate::node_contract::PreparedWorldPublication,
    ) -> PublicationStatus {
        if !self.retain_complete_bank(prepared) {
            // A changed complete body cannot reach the actual publisher. Keep
            // the original bank and conservative prior publication uncertainty.
            self.status = Some(PublicationStatus::Unknown);
            *self.publication = PublicationKnowledge::Unknown;
            return PublicationStatus::Unknown;
        }
        self.status = Some(PublicationStatus::Unknown);
        *self.publication = PublicationKnowledge::Unknown;
        let status = self.publisher.reconcile_complete(record, prepared);
        self.status = Some(status);
        *self.publication = status.into();
        status
    }

    fn publish(&mut self, record: &ActivationRecord) -> PublicationStatus {
        self.status = Some(PublicationStatus::Unknown);
        *self.publication = PublicationKnowledge::Unknown;
        let status = self.publisher.publish(record);
        self.status = Some(status);
        *self.publication = status.into();
        status
    }
    fn reconcile(&mut self, record: &ActivationRecord) -> PublicationStatus {
        self.status = Some(PublicationStatus::Unknown);
        *self.publication = PublicationKnowledge::Unknown;
        let status = self.publisher.reconcile(record);
        self.status = Some(status);
        *self.publication = status.into();
        status
    }
}

impl<'a> PreparedRestore<'a> {
    #[cfg(test)]
    pub(super) fn lose_prepared_scheduler_for_test(&mut self) {
        self.scheduler = None;
    }

    /// Returns the complete proposed generation, which confers no execution authority.
    pub fn proposed_activation(&self) -> &ActivationRecord {
        &self.activation
    }

    /// Publishes the already prepared original generation through the runtime barrier.
    pub fn publish(self, publisher: &mut dyn ActivationPublisher) -> RestorePublication<'a> {
        self.publication(publisher, false)
    }

    fn publication(
        self,
        publisher: &mut dyn ActivationPublisher,
        reconcile: bool,
    ) -> RestorePublication<'a> {
        self.publication_with_unwind_policy(publisher, reconcile, false)
    }

    fn publication_with_unwind_policy(
        mut self,
        publisher: &mut dyn ActivationPublisher,
        reconcile: bool,
        retain_unwind: bool,
    ) -> RestorePublication<'a> {
        if self.runtime.is_none() {
            return RestorePublication::Failed(self.fail(incomplete(
                "restore runtime",
                "prepared runtime custody absent",
            )));
        }
        let mut attempt = || {
            let mut publisher = RecordingPublisher {
                publisher,
                status: None,
                publication: &mut self.publication,
                prepared: &mut self.prepared_publication,
                retain_first: retain_unwind,
            };
            let result = match self.runtime.as_mut() {
                Some(runtime) if reconcile => runtime.reconcile_activation(&mut publisher),
                Some(runtime) => runtime.activate(&mut publisher),
                None => Err(crate::node_contract::RuntimeError::OutstandingObligations),
            };
            (result, publisher.status)
        };
        let (result, publication_status) = if retain_unwind {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(attempt)) {
                Ok(result) => result,
                Err(payload) => {
                    let mut failure = self.fail(incomplete(
                        "restored publication",
                        "original publisher callback unwound",
                    ));
                    failure.panic_payload = Some(payload);
                    return RestorePublication::Failed(failure);
                }
            }
        } else {
            attempt()
        };
        match result {
            Ok(activation) => {
                self.publication = PublicationKnowledge::Committed;
                let finished = if retain_unwind {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.finish_committed_publication(activation)
                    }))
                } else {
                    Ok(self.finish_committed_publication(activation))
                };
                match finished {
                    Ok(Ok(world)) => RestorePublication::Committed(world),
                    Ok(Err(error)) => RestorePublication::Failed(self.fail(error)),
                    Err(payload) => {
                        let mut failure = self.fail(incomplete(
                            "published continuation",
                            "original post-commit callback unwound",
                        ));
                        failure.panic_payload = Some(payload);
                        RestorePublication::Failed(failure)
                    }
                }
            }
            Err(_error) if publication_status == Some(PublicationStatus::Unknown) => {
                let mut contain = || match self.staging.as_mut() {
                    Some(staging) => staging.contain_uncertain_publication(&self.activation),
                    None => Err(incomplete(
                        "restore capsule",
                        "uncertain publication has no native custody",
                    )),
                };
                let containment = if retain_unwind {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(contain))
                } else {
                    Ok(contain())
                };
                match containment {
                    Ok(Ok(())) => {
                        RestorePublication::Uncertain(Box::new(PendingRestorePublication {
                            prepared: self,
                        }))
                    }
                    Ok(Err(error)) => RestorePublication::Failed(self.fail(error)),
                    Err(payload) => {
                        let mut failure = self.fail(incomplete(
                            "uncertain publication containment",
                            "original callback unwound",
                        ));
                        failure.panic_payload = Some(payload);
                        RestorePublication::Failed(failure)
                    }
                }
            }
            Err(error) => RestorePublication::Failed(self.fail(StateError::new(
                StateErrorCode::Restoration,
                "world publication",
                error.to_string(),
            ))),
        }
    }

    fn finish_committed_publication(
        &mut self,
        activation: WorldActivation,
    ) -> Result<Box<RestoredWorld>, StateError> {
        let scheduler = self
            .scheduler
            .take()
            .ok_or_else(|| incomplete("restored scheduler", "prepared continuation absent"))?;
        let scheduler = scheduler
            .activate(self.graph, &activation)
            .map_err(|error| {
                StateError::new(
                    StateErrorCode::Restoration,
                    "published scheduler",
                    error.to_string(),
                )
            })?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| incomplete("restore runtime", "published runtime custody absent"))?;
        runtime
            .install_restored_scheduler(&activation, scheduler)
            .map_err(|error| {
                StateError::new(
                    StateErrorCode::Restoration,
                    "published scheduler installation",
                    error.to_string(),
                )
            })?;
        let continuation = self.continuation.take().ok_or_else(|| {
            incomplete(
                "runtime continuation",
                "prepared original operation custody absent",
            )
        })?;
        continuation
            .install(runtime, &activation)
            .map_err(|error| {
                StateError::new(
                    StateErrorCode::Restoration,
                    "published runtime continuation",
                    error.to_string(),
                )
            })?;
        // Keep both native owners in self across every callback and fallible
        // clone. The opt-in caller can then return the actual original failure
        // even after durable publication, without implying rollback.
        let original = self
            .staging
            .as_ref()
            .ok_or_else(|| incomplete("restore capsule", "native coordinator custody absent"))?
            .original_disposition();
        let artifact = self.capture.artifact.clone();
        let repeatability = self.capture.repeatability;
        let runtime = self
            .runtime
            .take()
            .ok_or_else(|| incomplete("restore runtime", "published runtime custody absent"))?;
        let staging = self
            .staging
            .take()
            .ok_or_else(|| incomplete("restore capsule", "native coordinator custody absent"))?;
        Ok(Box::new(RestoredWorld {
            runtime,
            activation,
            staging,
            artifact,
            original,
            repeatability,
        }))
    }

    fn fail(mut self, error: StateError) -> RestoreFailure {
        let mut failure = match self.staging.take() {
            Some(staging) => {
                RestoreFailure::native(error, self.activation.clone(), self.publication, staging)
            }
            None => RestoreFailure::refused(error),
        };
        failure.publication = self.publication;
        failure.activation = Some(Box::new(self.activation.clone()));
        failure.prepared_publication = self.prepared_publication.take();
        failure.runtime = self
            .runtime
            .take()
            .map(NodeRuntime::into_quarantine)
            .map(Box::new);
        failure
    }
}

impl<'a> PendingRestorePublication<'a> {
    /// Returns the original generation retained through uncertain publication.
    pub fn original_activation(&self) -> &ActivationRecord {
        &self.prepared.activation
    }

    /// Reconciles the original durable record without creating another generation.
    pub fn reconcile(self, publisher: &mut dyn ActivationPublisher) -> RestorePublication<'a> {
        self.prepared.publication(publisher, true)
    }
}

impl Drop for PreparedRestore<'_> {
    fn drop(&mut self) {
        if let Some(staging) = &mut self.staging {
            staging.quarantine_resources(&self.activation, self.publication);
        }
        if let Some(runtime) = self.runtime.take() {
            drop(runtime.into_quarantine());
        }
    }
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod publication_tests;
