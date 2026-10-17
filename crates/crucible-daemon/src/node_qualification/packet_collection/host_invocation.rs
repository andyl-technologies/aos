//! Owns one public packet peer-to-collector invocation and its durable publishers.
//!
//! The caller supplies independently installed source policy and all supervisor
//! reservations before Child. This capsule joins the real launch, realization,
//! opaque collecting graph, actual initial publication and original pre/post-ACK
//! observations. It never returns a graph, runtime, mutable publisher or accepted
//! certificate. Failed or unwound preparation cannot start a replacement peer.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use crucible::{
    node_adapters::cnp::{CnpSemanticLaunchGuard, CnpSemanticRegistry},
    node_admission::{AdmissionLimits, InstalledConformancePlan, ScenarioRequirements},
    node_contract::{ActivationRecord, RuntimeCustodySlot, RuntimeLimits},
};
use crucible_cas::content_store::{ImmutableBlobBackend, MutableRefBackend, RefName};
use crucible_node_contract::{Id, U64};
use crucible_node_provider::handshake::TrustedHandshakeVerifier;

use super::{
    InstalledPacketCollectionAuthority, PacketCollectionFailure, PacketCollectionPhase,
    PacketOriginalRuntimeFailure, PacketOriginalRuntimeRequest, PacketPeerLaunchFailure,
    PacketTemplateExecution, PacketTemplateInstallationFailure, PreparedPacketCollectionPeer,
    QualificationError, StoredPacketResultPublisher,
};
use crate::{
    node_observed_executor::StoredWorldActivationPublisher,
    node_qualification::{CollectedConformance, QualificationLimits},
};

type Execution<'a> =
    PacketTemplateExecution<'a, StoredWorldActivationPublisher, StoredPacketResultPublisher>;

/// Supplies one already prepared peer and the complete original host invocation.
///
/// The peer capsule contains its native and returned-journal reservations. The
/// separate runtime slot must already be allocated in the same independently
/// installed supervisor. Ref names belong to a retained fixture namespace, not
/// ordinary daemon GC; their owner retains all bytes through cleanup and audit.
pub struct PacketHostCollectionRequest<'a, V> {
    /// Retains the actual pre-Child capsule prepared by this same authority.
    pub peer: Box<PreparedPacketCollectionPeer<'a, V>>,
    /// Retains the same opaque complete Refused plan used by the source registry.
    pub plan: InstalledConformancePlan,
    /// Retains complete original scenario requirements without inferred defaults.
    pub requirements: ScenarioRequirements,
    /// Retains the original activation proposal without predicted Ready bodies.
    pub activation: ActivationRecord,
    /// Retains the source registry used by this original realization.
    pub registry: CnpSemanticRegistry,
    /// Retains the independently preallocated whole-runtime supervisor slot.
    pub runtime_custody: Box<dyn RuntimeCustodySlot>,
    /// Bounds unchanged ordinary structural and schema admission.
    pub admission_limits: AdmissionLimits,
    /// Bounds original native/runtime ledger capacity before Arm.
    pub runtime_limits: RuntimeLimits,
    /// Bounds complete collector attempts and retained evidence.
    pub qualification_limits: QualificationLimits,
    /// Names the exact selected logical participant.
    pub node: Id,
    /// Names the fixed source-authored original operation.
    pub operation: Id,
    /// Names the source-authenticated exclusive operation horizon.
    pub horizon: U64,
    /// Names the immutable source template for the before-ACK observation.
    pub before_case: String,
    /// Names a distinct immutable source template for the after-ACK observation.
    pub after_case: String,
    /// Retains the actual durable immutable store through publication and audit.
    pub blobs: Arc<dyn ImmutableBlobBackend>,
    /// Retains the actual durable write-once mutable reference store.
    pub refs: Arc<dyn MutableRefBackend>,
    /// Names this original activation's separate write-once placement.
    pub activation_reference: RefName,
    /// Names this original result's separate write-once placement.
    pub result_reference: RefName,
    /// Bounds the authentic post-Arm initial coordinator to at most 65,536 bytes.
    pub maximum_coordinator_bytes: usize,
    /// Bounds prospective result construction and placement to at most 64 MiB.
    pub maximum_result_bytes: usize,
}

/// Reports data-only progress while preserving the same original owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketHostPhase {
    /// Retains complete publishers and peer/runtime reservations before Child.
    Prepared,
    /// Retains one actual collecting runtime and its original operation attempts.
    Running,
    /// Retains refused or uncertain original custody without redispatch.
    Held,
    /// Retains collected observations with all unknown requirements still explicit.
    Complete,
}

/// Describes a host invocation refusal without claiming native reclamation.
pub enum PacketHostFailure {
    /// Refuses an invalid phase or a second original launch attempt.
    Phase,
    /// Preserves an original launch, realization or installation failure.
    Preparation,
    /// Preserves the exact native/runtime lifecycle failure.
    Lifecycle(PacketCollectionFailure),
    /// Preserves the original capsule after a callback unwinds.
    Unwind,
}

/// Retains the complete pre-Child capsule when host preparation refuses.
pub struct PacketHostPreparationFailure<'a, V> {
    /// Describes the original scope, storage or credit refusal.
    pub error: QualificationError,
    /// Retains the same prepared peer, source metadata and supervisor reservations.
    pub original: Box<PacketHostCollection<'a, V>>,
}

/// Owns one actual peer, collector and both original durable publishers.
///
/// This object remains outside its internal unwind guards. During native owner
/// transfer, the guard or runtime's original Drop contract transfers that same
/// owner and journals to its preallocated supervisor. The capsule retains source
/// settings and any returned failure. It never reconstructs a guard from a PID.
/// A failed supervisor retain contract or allocator exhaustion is outside this
/// bounded callback contract. Collector finalization retains its documented
/// consuming-finalizer limitation; independently owned native/report bodies stay
/// retained by their original stores and supervisors.
#[must_use = "retain the original host invocation until genuine supervised reclamation"]
pub struct PacketHostCollection<'a, V> {
    authority: &'a Rc<InstalledPacketCollectionAuthority>,
    peer: Option<Box<PreparedPacketCollectionPeer<'a, V>>>,
    launch_failure: Option<PacketPeerLaunchFailure<'a, V>>,
    guard: Option<CnpSemanticLaunchGuard>,
    runtime_failure: Option<PacketOriginalRuntimeFailure>,
    installation_failure: Option<
        Box<
            PacketTemplateInstallationFailure<
                'a,
                StoredWorldActivationPublisher,
                StoredPacketResultPublisher,
            >,
        >,
    >,
    runtime_custody: Option<Box<dyn RuntimeCustodySlot>>,
    activation_proposal: Option<ActivationRecord>,
    activation_publisher: Option<StoredWorldActivationPublisher>,
    result_publisher: Option<StoredPacketResultPublisher>,
    execution: Option<Execution<'a>>,
    settings: Settings,
    phase: PacketHostPhase,
}

struct Settings {
    plan: Rc<InstalledConformancePlan>,
    requirements: ScenarioRequirements,
    registry: CnpSemanticRegistry,
    admission_limits: AdmissionLimits,
    runtime_limits: RuntimeLimits,
    qualification_limits: QualificationLimits,
    node: Id,
    operation: Option<Id>,
    horizon: U64,
    before_case: String,
    after_case: String,
    maximum_coordinator_bytes: usize,
}

impl InstalledPacketCollectionAuthority {
    /// Prepares the owning public caller and both publishers without Child effects.
    ///
    /// # Errors
    /// Returns the same capsule on foreign peer/plan, changed case/world/source,
    /// inadequate complete-body credit or refused durable publisher preparation.
    /// It creates neither an accepted class nor a native readiness certificate.
    pub fn prepare_host_collection<'a, V: TrustedHandshakeVerifier>(
        self: &'a Rc<Self>,
        request: PacketHostCollectionRequest<'a, V>,
    ) -> Result<Box<PacketHostCollection<'a, V>>, PacketHostPreparationFailure<'a, V>> {
        let PacketHostCollectionRequest {
            peer,
            plan,
            requirements,
            activation,
            registry,
            runtime_custody,
            admission_limits,
            runtime_limits,
            qualification_limits,
            node,
            operation,
            horizon,
            before_case,
            after_case,
            blobs,
            refs,
            activation_reference,
            result_reference,
            maximum_coordinator_bytes,
            maximum_result_bytes,
        } = request;
        let mut original = Box::new(PacketHostCollection {
            authority: self,
            peer: Some(peer),
            launch_failure: None,
            guard: None,
            runtime_failure: None,
            installation_failure: None,
            runtime_custody: Some(runtime_custody),
            activation_proposal: Some(activation),
            activation_publisher: None,
            result_publisher: None,
            execution: None,
            settings: Settings {
                plan: Rc::new(plan),
                requirements,
                registry,
                admission_limits,
                runtime_limits,
                qualification_limits,
                node,
                operation: Some(operation),
                horizon,
                before_case,
                after_case,
                maximum_coordinator_bytes,
            },
            phase: PacketHostPhase::Prepared,
        });
        let checked = catch_unwind(AssertUnwindSafe(|| {
            if maximum_coordinator_bytes == 0
                || maximum_coordinator_bytes > 65_536
                || maximum_result_bytes == 0
                || maximum_result_bytes > 64 * 1024 * 1024
                || original
                    .settings
                    .plan
                    .authenticate_authority(self.as_ref())
                    .is_err()
                || !original
                    .peer
                    .as_ref()
                    .is_some_and(|peer| peer.has_authority(self.as_ref()))
            {
                return Err(QualificationError::Refused(
                    "packet host original tuple or credit",
                ));
            }
            let activation =
                original
                    .activation_proposal
                    .as_ref()
                    .ok_or(QualificationError::Refused(
                        "packet host original activation absent",
                    ))?;
            let operation =
                original
                    .settings
                    .operation
                    .as_ref()
                    .ok_or(QualificationError::Refused(
                        "packet host original operation absent",
                    ))?;
            // Count the complete borrowed tuple before any scenario/case clone.
            // Existing source/plan bodies and Rc-held native data remain shared.
            super::scope::encoded_size(
                &(
                    &original.settings.requirements,
                    super::scope::activation_view(activation),
                    &original.settings.node,
                    operation,
                    horizon,
                    &original.settings.before_case,
                    &original.settings.after_case,
                    activation_reference.as_str(),
                    result_reference.as_str(),
                ),
                maximum_result_bytes / 4,
            )?;
            self.oracle.authenticate_case_pair(
                &original.settings.node,
                operation,
                horizon,
                &original.settings.before_case,
                &original.settings.after_case,
            )?;
            self.current()?;
            original
                .settings
                .plan
                .reauthenticate()
                .map_err(|_| QualificationError::Refused("packet host original plan revoked"))?;
            original.activation_publisher = Some(
                StoredWorldActivationPublisher::new(
                    blobs.clone(),
                    refs.clone(),
                    activation_reference,
                )
                .map_err(|_| QualificationError::Refused("packet host activation store refused"))?,
            );
            original.result_publisher = Some(
                StoredPacketResultPublisher::with_shared_plan(
                    self.clone(),
                    original.settings.plan.clone(),
                    original.settings.requirements.clone(),
                    original.settings.before_case.clone(),
                    blobs,
                    refs,
                    result_reference,
                    maximum_result_bytes,
                )
                .map_err(|_| QualificationError::Refused("packet host result store refused"))?,
            );
            // Publisher capability callbacks cannot survive into Child with a
            // revoked installation. The peer repeats its direct launch read.
            self.current()?;
            original.settings.plan.reauthenticate().map_err(|_| {
                QualificationError::Refused("packet host publisher callbacks revoked original plan")
            })
        }));
        let error = match checked {
            Ok(Ok(())) => return Ok(original),
            Ok(Err(error)) => error,
            Err(_) => QualificationError::Refused("packet host prelaunch callback unwound"),
        };
        original.phase = PacketHostPhase::Held;
        Err(PacketHostPreparationFailure { error, original })
    }
}

impl<'a, V: TrustedHandshakeVerifier> PacketHostCollection<'a, V> {
    /// Starts the one original peer and transfers it into the collecting executor.
    ///
    /// # Errors
    /// Retains the original failure or supervised owner on launch, realization,
    /// graph/admission, runtime transfer, case-ticket or callback failure. The
    /// phase becomes Held before the first native attempt and cannot be retried.
    pub fn start(&mut self) -> Result<(), PacketHostFailure> {
        if self.phase != PacketHostPhase::Prepared {
            return Err(PacketHostFailure::Phase);
        }
        self.phase = PacketHostPhase::Held;
        match catch_unwind(AssertUnwindSafe(|| self.start_original())) {
            Ok(result) => result,
            Err(_) => Err(PacketHostFailure::Unwind),
        }
    }

    fn start_original(&mut self) -> Result<(), PacketHostFailure> {
        let peer = self.peer.take().ok_or(PacketHostFailure::Phase)?;
        match peer.start() {
            Ok(guard) => self.guard = Some(guard),
            Err(failure) => {
                self.launch_failure = Some(failure);
                return Err(PacketHostFailure::Preparation);
            }
        }
        let guard = self.guard.take().ok_or(PacketHostFailure::Phase)?;
        let activation = self
            .activation_proposal
            .take()
            .ok_or(PacketHostFailure::Phase)?;
        let runtime_custody = self
            .runtime_custody
            .take()
            .ok_or(PacketHostFailure::Phase)?;
        let runtime = match self.authority.prepare_original_runtime(
            guard,
            &mut self.settings.registry,
            PacketOriginalRuntimeRequest {
                plan: &self.settings.plan,
                requirements: &self.settings.requirements,
                activation,
                admission_limits: self.settings.admission_limits,
                runtime_limits: self.settings.runtime_limits,
                runtime_custody,
            },
        ) {
            Ok(runtime) => runtime,
            Err(failure) => {
                self.runtime_failure = Some(failure);
                return Err(PacketHostFailure::Preparation);
            }
        };
        let operation = self
            .settings
            .operation
            .take()
            .ok_or(PacketHostFailure::Phase)?;
        let activation = self
            .activation_publisher
            .take()
            .ok_or(PacketHostFailure::Phase)?;
        let result = self
            .result_publisher
            .take()
            .ok_or(PacketHostFailure::Phase)?;
        match self.authority.template_execution_shared(
            runtime,
            self.settings.plan.clone(),
            self.settings.node.clone(),
            operation,
            self.settings.horizon,
            self.settings.before_case.clone(),
            self.settings.after_case.clone(),
            activation,
            result,
            self.settings.qualification_limits,
            self.settings.maximum_coordinator_bytes,
        ) {
            Ok(execution) => self.execution = Some(execution),
            Err(failure) => {
                self.installation_failure = Some(failure);
                return Err(PacketHostFailure::Preparation);
            }
        }
        self.phase = PacketHostPhase::Running;
        Ok(())
    }

    /// Polls one phase of the same runtime without another launch or Begin.
    ///
    /// # Errors
    /// Retains the execution and both publishers on refusal, uncertainty or
    /// unwind. A normal Publishing phase reconciles its exact original root;
    /// a Held execution or unwind has no redispatch path.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), PacketHostFailure>> {
        if self.phase == PacketHostPhase::Complete {
            return Poll::Ready(Ok(()));
        }
        if self.phase != PacketHostPhase::Running {
            return Poll::Ready(Err(PacketHostFailure::Phase));
        }
        let Some(execution) = self.execution.as_mut() else {
            self.phase = PacketHostPhase::Held;
            return Poll::Ready(Err(PacketHostFailure::Phase));
        };
        match catch_unwind(AssertUnwindSafe(|| execution.poll(context))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(Ok(()))) => {
                self.phase = PacketHostPhase::Complete;
                Poll::Ready(Ok(()))
            }
            Ok(Poll::Ready(Err(error))) => {
                if execution.phase() == PacketCollectionPhase::Held {
                    self.phase = PacketHostPhase::Held;
                }
                Poll::Ready(Err(PacketHostFailure::Lifecycle(error)))
            }
            Err(_) => {
                self.phase = PacketHostPhase::Held;
                Poll::Ready(Err(PacketHostFailure::Unwind))
            }
        }
    }

    /// Reports progress without granting runtime or qualification authority.
    pub fn phase(&self) -> PacketHostPhase {
        self.phase
    }

    /// Borrows collected observations while unexecuted normative cases remain explicit.
    pub fn collected(&self) -> Option<&CollectedConformance> {
        self.execution
            .as_ref()
            .and_then(|execution| execution.collected())
    }
}
