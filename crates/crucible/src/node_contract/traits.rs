//! Object-safe node and explicitly acquired role-independent facet interfaces.

use std::task::{Context, Poll};

use crucible_node_contract::{NodeBinding, NodeDescriptor, Position, PreparedOwner};

use super::{
    ActivationRecord, CancelStatus, FacetKind, NativeReclamationReceipt, NodeRoute, NodeStatus,
    OperationAdmission, OperationFailure, OperationOutcome, OperationToken, OwnerIdentity, Refusal,
    Submission,
};

/// Reports an owner's prepared domains without authorizing execution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ReadyAttestation {
    /// Exact owner incarnations validated and armed by the provider.
    pub owners: Vec<OwnerIdentity>,
    /// Original initial or preserved cut; no later convenient boundary.
    pub boundary: Position,
    /// Complete preserved domains, queues and reference-custody inventory.
    pub state_inventory: crucible_node_contract::ContentRef,
    /// Authentic original nonexecuting native readiness receipt.
    pub ready_receipt: crucible_node_contract::ContentRef,
}

/// Defines heterogeneous process-local participant behavior without downcasts.
///
/// Common mutations receive opaque coordinator admissions. Role and facet
/// descriptions do not provide alternate mutation paths. Implementations need
/// not be `Send` or `Sync`; a worker requires explicit custody transfer.
pub trait SimulationNode {
    /// Returns the immutable admitted public descriptor.
    fn descriptor(&self) -> &NodeDescriptor;

    /// Returns the immutable realized configuration and capability binding.
    fn binding(&self) -> &NodeBinding;

    /// Returns the complete route used by all component aliases.
    fn route(&self) -> &NodeRoute;

    /// Declares native callback thread custody or an explicit owning actor.
    fn thread_affinity(&self) -> super::ThreadAffinity;

    /// Returns the explicitly supported optional facets.
    fn facets(&self) -> &[FacetKind];

    /// Reads the next immutable authored fault decision without applying it.
    ///
    /// The selected native controller owns the complete program and cursor.
    /// This observation creates no mutation permission. The default refuses.
    ///
    /// # Errors
    /// Refuses unsupported controllers, foreign activation or changed custody.
    fn next_fault_mutation(
        &self,
        _activation: &super::WorldActivation,
    ) -> Result<Option<super::FaultMutationRequest>, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "admitted authored native fault controller is unsupported".into(),
        })
    }

    /// Reports lifecycle separately from physical suspension.
    ///
    /// # Errors
    /// Returns a native observation failure; missing evidence remains unknown.
    fn status(&mut self) -> Result<NodeStatus, OperationFailure>;

    /// Observes authentic complete native output bounds without modeled effects.
    ///
    /// The default explicitly refuses. Empty queues, counters and descriptor
    /// resolution never establish a positive native producer bound.
    ///
    /// # Errors
    /// Returns unsupported observation or unavailable complete native evidence.
    fn observe_scheduling(
        &mut self,
        _activation: &super::WorldActivation,
    ) -> Result<crate::node_scheduling::NativeSchedulingObservation, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "complete native scheduling observation is unsupported".into(),
        })
    }

    /// Authenticates a complete native scheduling observation for this activation.
    ///
    /// # Errors
    /// Returns unsupported validation, incomplete scope or invalid native custody.
    fn validate_scheduling_observation(
        &self,
        _activation: &super::WorldActivation,
        _observation: &crate::node_scheduling::NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "complete native scheduling evidence validation is unsupported".into(),
        })
    }

    /// Reads a genuine original event-condition hit without asserting a world stop.
    ///
    /// # Errors
    /// The default refuses; selected adapters authenticate the actual evaluator,
    /// original input and immutable program under this activation.
    fn observe_condition_hit(
        &self,
        _activation: &super::WorldActivation,
    ) -> Result<Option<crate::node_adapters::ConditionHitCandidate>, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original event-condition observation is unsupported".into(),
        })
    }

    /// Authenticates the exact original hit against current native ownership.
    ///
    /// # Errors
    /// The default refuses unknown, substituted or unavailable native evidence.
    fn validate_condition_hit(
        &self,
        _activation: &super::WorldActivation,
        _hit: &crate::node_adapters::ConditionHitCandidate,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original event-condition authentication is unsupported".into(),
        })
    }

    /// Reads complete physical stop custody while retaining future native work.
    ///
    /// # Errors
    /// The default refuses. Selected providers must own an effective physical
    /// stop and cover native timers, pending buffers and original operation ledgers.
    fn observe_condition_stop(
        &self,
        _activation: &super::WorldActivation,
        _maximum_bytes: usize,
    ) -> Result<super::NativeConditionStopInventory, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "complete condition stop inventory is unsupported".into(),
        })
    }

    /// Authenticates complete unchanged local custody at the original stop cut.
    ///
    /// # Errors
    /// The default refuses rather than inferring a live fence from saved bytes.
    fn validate_condition_stop(
        &self,
        _activation: &super::WorldActivation,
        _inventory: &super::NativeConditionStopInventory,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "condition stop custody authentication is unsupported".into(),
        })
    }

    /// Reads the complete next autonomous native event frontier without progress.
    ///
    /// # Errors
    /// The default refuses. Missing events do not imply EOF or absent input.
    fn observe_condition_frontier(
        &self,
        _activation: &super::WorldActivation,
        _maximum_bytes: usize,
    ) -> Result<super::NativeConditionEventFrontier, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "complete condition event frontier is unsupported".into(),
        })
    }

    /// Authenticates a frontier against the actual unchanged original native state.
    ///
    /// # Errors
    /// The default refuses incomplete, foreign or regenerated native evidence.
    fn validate_condition_frontier(
        &self,
        _activation: &super::WorldActivation,
        _frontier: &super::NativeConditionEventFrontier,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "condition event frontier authentication is unsupported".into(),
        })
    }

    /// Reads complete native terminal inventory without advancing or draining.
    ///
    /// The selected codec must establish physical suspension, no outstanding
    /// native events/inputs/outputs, and either unconditional future closure or
    /// input-dependent closure. The default explicitly refuses.
    ///
    /// # Errors
    /// Refuses unsupported or incomplete terminal scope and exhausted bytes.
    fn observe_terminal(
        &mut self,
        _activation: &super::WorldActivation,
        _maximum_bytes: usize,
    ) -> Result<super::NativeTerminalInventory, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "complete native terminal inventory is unsupported".into(),
        })
    }

    /// Authenticates original terminal inventory against live native custody.
    ///
    /// An accepted disposition covers all autonomous native work and future
    /// timers, retained publications and non-coordinator ingress. Its native
    /// fence remains effective through original report publication and ACK.
    /// Paused execution, an empty queue or a finite output bound is insufficient.
    ///
    /// # Errors
    /// Refuses unsupported validation, foreign scope or changed native state.
    fn validate_terminal(
        &self,
        _activation: &super::WorldActivation,
        _inventory: &super::NativeTerminalInventory,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "native terminal inventory authentication is unsupported".into(),
        })
    }

    /// Reads immutable native proof bodies for original boundary observations.
    ///
    /// Records must belong to this actual activation and retained native owner
    /// scope. Reading does not regenerate a receipt, advance time or transfer
    /// publication custody. The owner-thread restriction still applies. The
    /// default explicitly refuses rather than substituting hashes for raw data.
    ///
    /// # Errors
    /// Refuses unsupported retrieval, foreign or missing original evidence,
    /// changed native custody and a total byte count exceeding `maximum_bytes`.
    fn read_boundary_evidence(
        &self,
        _activation: &super::WorldActivation,
        _references: &[crucible_node_contract::ContentRef],
        _maximum_bytes: usize,
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original native boundary evidence retrieval is unsupported".into(),
        })
    }

    /// Authenticates retained raw bodies against original native boundary custody.
    ///
    /// Syntax and content integrity are checked separately. This hook must verify
    /// the actual owning adapter's original activation, native receipt registry
    /// and complete requested inventory without deriving proof from public claims.
    ///
    /// # Errors
    /// Refuses unsupported validation, mismatched scope, unavailable bodies or
    /// evidence that was regenerated after original acknowledgement or retirement.
    fn validate_boundary_evidence(
        &self,
        _activation: &super::WorldActivation,
        _references: &[crucible_node_contract::ContentRef],
        _objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original native boundary evidence authentication is unsupported".into(),
        })
    }

    /// Lists complete codec-selected dependencies of an authentic producer proof.
    ///
    /// The returned inventory excludes the root itself. Implementations must
    /// authenticate the root against this world's retained producer custody and
    /// apply both finite limits before materializing dependent objects. Empty
    /// dependencies establish a qualified leaf codec, not unknown provenance.
    ///
    /// # Errors
    /// Refuses unsupported codecs, foreign roots, incomplete original custody,
    /// changed dependencies or exhausted object and byte limits.
    fn input_provenance_dependencies(
        &self,
        _activation: &super::WorldActivation,
        _root: &crucible_node_contract::ContentRef,
        _limits: super::InputProvenanceLimits,
    ) -> Result<Vec<crucible_node_contract::ContentRef>, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original producer provenance closure is unsupported".into(),
        })
    }

    /// Authenticates complete original dependencies against the producer codec.
    ///
    /// # Errors
    /// Refuses unsupported verification, omitted dependency objects or a root
    /// belonging to a different native world, owner or receipt registry.
    fn validate_input_provenance_dependencies(
        &self,
        _activation: &super::WorldActivation,
        _root: &crucible_node_contract::ContentRef,
        _dependencies: &[crucible_node_contract::ContentRef],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original producer provenance closure validation is unsupported".into(),
        })
    }

    /// Rebinds authenticated original native custody to genuine fresh local handles.
    ///
    /// The runtime invokes this hook only after complete world publication and
    /// trusted unchanged-cut continuation verification. Entries belong to this
    /// logical node and retain their original operation and input identities.
    /// The adapter must match its prepared native lineage, then reattach cached
    /// results and buffers without rerunning an operation or restaging an input.
    /// The default refuses; native restore support must implement this hook.
    ///
    /// # Errors
    /// Returns unsupported rebinding, changed prepared lineage or incomplete
    /// native custody. Failure quarantines the complete published world.
    fn install_restored_custody(
        &mut self,
        _activation: &super::WorldActivation,
        _source: &super::RuntimeSnapshot,
        _operations: &[OperationAdmission],
        _inputs: &[std::rc::Rc<crate::node_scheduling::RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "native restored custody rebinding is unsupported".into(),
        })
    }

    /// Reads complete unchanged local host state using its installed native codec.
    ///
    /// The coordinator supplies authentic live authority and its complete saved
    /// ledger. This read must preserve the original cut, pending buffers, original
    /// operation results and native acknowledgement knowledge without modeled
    /// execution or draining. The host-specific capability cannot be constructed
    /// by external providers; unsupported implementations explicitly refuse.
    ///
    /// # Errors
    /// Returns unsupported native capture, changed live custody, incomplete state
    /// or a serialization exceeding the supplied preallocation ceiling.
    fn capture_host_continuation(
        &self,
        _activation: &super::WorldActivation,
        _source: &super::RuntimeSnapshot,
        _maximum_bytes: usize,
    ) -> Result<super::HostNativeCapture, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "complete installed host native capture is unsupported".into(),
        })
    }

    /// Captures complete installed native custody at the authentic unchanged cut.
    ///
    /// Mechanical preservation work may checkpoint a stopped process, but must
    /// not run a modeled event, drain a queue, consume input or publish output.
    /// The result covers the entire authoritative capture owner and participant
    /// roster. The host-specific seal cannot qualify another backend.
    ///
    /// # Errors
    /// Refuses unsupported native codecs, changed original runtime custody,
    /// unavailable image closure or an exceeded finite capture reservation.
    fn capture_native_continuation(
        &mut self,
        _activation: &super::WorldActivation,
        _source: &super::RuntimeSnapshot,
        _limits: super::NativeCaptureLimits,
    ) -> Result<super::InstalledNativeCapture, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "complete installed native capture is unsupported".into(),
        })
    }

    /// Stages an immutable complete input cut without modeled execution.
    ///
    /// Staging transfers buffer custody only. It must not deliver an input,
    /// advance a guest clock, execute a reaction, or resample the original cut.
    /// The default refuses; input support requires separate authentic evidence.
    ///
    /// # Errors
    /// Returns unsupported staging or native failure with explicit effect knowledge.
    fn stage_inputs(
        &mut self,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<crate::node_scheduling::NativeInputAcknowledgement, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "native input staging is unsupported".into(),
        })
    }

    /// Reports whether this installed consumer requires authentic producer proofs.
    ///
    /// This preference conveys no proof authority. Supporting consumers still
    /// validate the opaque complete closure before any native staging effects.
    fn requires_input_provenance(
        &self,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> bool {
        false
    }

    /// Stages an original input batch with its runtime-authenticated provenance.
    ///
    /// Implementations must validate the original activation, consumer, staging
    /// operation, batch and complete inventory before touching native buffers.
    /// Proof objects are evidence and must never become modeled payload bytes.
    ///
    /// # Errors
    /// Refuses unsupported staging, mismatched proof scope, incomplete original
    /// evidence or native failures with explicit effect knowledge.
    fn stage_inputs_with_provenance(
        &mut self,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
        _provenance: &super::InputProvenanceClosure,
    ) -> Result<crate::node_scheduling::NativeInputAcknowledgement, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "native staging with producer provenance is unsupported".into(),
        })
    }

    /// Authenticates native custody of the unchanged complete staged input batch.
    ///
    /// # Errors
    /// Returns unsupported validation, changed original scope or incomplete native
    /// buffer evidence. A content hash by itself does not prove native readiness.
    fn validate_input_acknowledgement(
        &self,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
        _acknowledgement: &crate::node_scheduling::NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "native input custody validation is unsupported".into(),
        })
    }

    /// Arms validated owner readiness while withholding semantic execution.
    ///
    /// # Errors
    /// Returns refusal or failed staging while retaining native resource custody.
    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure>;

    /// Verifies complete initial or restored state readiness against this world.
    ///
    /// # Errors
    /// Rejects unauthenticated readiness, incomplete domains or references,
    /// mismatched pending custody, or a moved capture boundary.
    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure>;

    /// Reads original public owner preparation beneath the still-closed gate.
    ///
    /// `None` explicitly declares unsupported public mapping. A supported mapping
    /// must retain actual preparation tokens and admitted complete binding hashes;
    /// scalar owner IDs and content hashes cannot manufacture native readiness.
    ///
    /// # Errors
    /// Returns unavailable or inconsistent original native preparation custody.
    fn prepared_owners(
        &self,
        _world: &ActivationRecord,
        _readiness: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        Ok(None)
    }

    /// Authenticates original public preparation against this native realization.
    ///
    /// # Errors
    /// Refuses unsupported validation, changed preparation tokens or foreign
    /// readiness, binding, owner generation or incarnation evidence.
    fn validate_prepared_owners(
        &self,
        _world: &ActivationRecord,
        _readiness: &ReadyAttestation,
        _owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "public owner preparation validation is unsupported".into(),
        })
    }

    /// Authenticates fresh initial native state before encoding an initial coordinator.
    ///
    /// Empty represented host ledgers do not establish native initial state. A
    /// restored owner may retain original operations outside those ledgers until
    /// continuation installation. The default refuses this distinct assertion.
    ///
    /// # Errors
    /// Refuses unsupported initial-state authentication or any restored, used,
    /// foreign or incompletely observed native preparation.
    fn validate_initial_preparation(
        &self,
        _world: &ActivationRecord,
        _readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "fresh initial native preparation validation is unsupported".into(),
        })
    }

    /// Begins the original admitted operation without fabricating completion.
    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission;

    /// Polls the original operation under retained provider custody.
    ///
    /// A pending result must arrange a wake or provide bounded explicit repolling.
    ///
    /// # Errors
    /// Returns failure with classified effects while retaining native resources.
    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>>;

    /// Authenticates complete profile-specific native receipt evidence.
    ///
    /// Structural equality and content-reference syntax do not establish stop,
    /// clock, inventory or unchanged-state evidence. The trusted adapter must
    /// verify original operation custody, referenced evidence and its qualified
    /// native profile before the runtime can publish a result.
    ///
    /// # Errors
    /// Returns failed or unavailable evidence while retaining native custody.
    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure>;

    /// Reads retained immutable evidence belonging to the original operation.
    ///
    /// Supporting adapters retain these original objects after native output
    /// acknowledgement and include their registry in complete capture custody.
    /// Reading must not regenerate a receipt, stage an input or advance time.
    /// The default refuses; a hash alone establishes no readable provenance.
    ///
    /// # Errors
    /// Returns unsupported evidence retrieval, missing original object custody
    /// or a failure to read the exact bounded requested evidence inventory.
    fn read_operation_evidence(
        &self,
        _original: &OperationAdmission,
        _references: &[crucible_node_contract::ContentRef],
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original native operation evidence retrieval is unsupported".into(),
        })
    }

    /// Authenticates evidence objects against unchanged original native custody.
    ///
    /// Content integrity is checked independently by the runtime. This hook
    /// must also establish that the original operation owns the requested
    /// records and that their bytes came from its retained native receipt registry.
    ///
    /// # Errors
    /// Returns unsupported native authentication, foreign object custody or
    /// changed evidence, including objects regenerated after acknowledgement.
    fn validate_operation_evidence(
        &self,
        _original: &OperationAdmission,
        _references: &[crucible_node_contract::ContentRef],
        _objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: super::EffectKnowledge::None,
            reason: "original native operation evidence authentication is unsupported".into(),
        })
    }

    /// Requests cancellation without claiming rollback, closure or suspension.
    ///
    /// # Errors
    /// Returns a failed cancellation request; original operation remains retained.
    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure>;

    /// Requests closure of the original quantized operation without a second run.
    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission;

    /// Acknowledges retained original output custody after validated publication.
    ///
    /// # Errors
    /// Returns failure while preserving the original publication obligation.
    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[crucible_node_contract::Id],
    ) -> Result<(), OperationFailure>;

    /// Acquires an advertised facet without synthetic fallback support.
    ///
    /// # Errors
    /// Returns a no-effect refusal when the selected facet is unsupported.
    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal>;

    /// Transfers unfinished native custody to the provider's authentic supervisor.
    ///
    /// This idempotent hook must retain processes, device authority, pending
    /// effects and resource reservations until actual reclamation. It must not
    /// discard obligations when a caller or runtime is dropped. Implementations
    /// integrate their native resource guards and quarantine registry here.
    fn quarantine_resources(&mut self);

    /// Polls actual reclamation of one original native owner under supervision.
    ///
    /// # Errors
    /// Returns cleanup failure while retaining all native obligations. Pending
    /// must arrange a wake or a documented bounded supervisory repoll path.
    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>>;

    /// Authenticates native reclamation rather than trusting receipt syntax.
    ///
    /// # Errors
    /// Returns invalid or unavailable evidence without discharging resource custody.
    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure>;
}

/// Describes a facet without granting an alternate operation dispatch path.
pub trait FacetDescription {
    /// Returns the facet's nonempty immutable admitted profile identity.
    fn profile(&self) -> &crucible_node_contract::Id;
}

/// Represents explicitly acquired optional behavior through runtime dispatch.
pub enum NodeFacet<'a> {
    /// Exact ceiling semantics, independent of repeatability.
    ExactExecution(&'a dyn FacetDescription),
    /// Quantized visibility semantics, independent of physical suspension.
    QuantizedExecution(&'a dyn FacetDescription),
    /// Authentic physical-pause semantics.
    PhysicalPause(&'a dyn FacetDescription),
    /// Declared state-fidelity and closure semantics.
    Preservation(&'a dyn FacetDescription),
    /// Explicit repeatability or transcript semantics.
    Replay(&'a dyn FacetDescription),
    /// Explicit fault surfaces and application semantics.
    FaultInjection(&'a dyn FacetDescription),
    /// Declared coverage observation semantics.
    Coverage(&'a dyn FacetDescription),
    /// Declared architectural observation semantics.
    Introspection(&'a dyn FacetDescription),
    /// Whole-world-fenced terminal assertion semantics.
    TerminalAssertions(&'a dyn FacetDescription),
    /// Explicit noncanonical debugging semantics.
    Debugging(&'a dyn FacetDescription),
}

impl NodeFacet<'_> {
    /// Returns the immutable selected facet profile identity.
    pub fn profile(&self) -> &crucible_node_contract::Id {
        match self {
            Self::ExactExecution(facet)
            | Self::QuantizedExecution(facet)
            | Self::PhysicalPause(facet)
            | Self::Preservation(facet)
            | Self::Replay(facet)
            | Self::FaultInjection(facet)
            | Self::Coverage(facet)
            | Self::Introspection(facet)
            | Self::Debugging(facet)
            | Self::TerminalAssertions(facet) => facet.profile(),
        }
    }

    /// Returns the selected facet kind for acquisition validation.
    pub fn kind(&self) -> FacetKind {
        match self {
            Self::ExactExecution(_) => FacetKind::ExactExecution,
            Self::QuantizedExecution(_) => FacetKind::QuantizedExecution,
            Self::PhysicalPause(_) => FacetKind::PhysicalPause,
            Self::Preservation(_) => FacetKind::Preservation,
            Self::Replay(_) => FacetKind::Replay,
            Self::FaultInjection(_) => FacetKind::FaultInjection,
            Self::Coverage(_) => FacetKind::Coverage,
            Self::Introspection(_) => FacetKind::Introspection,
            Self::Debugging(_) => FacetKind::Debugging,
            Self::TerminalAssertions(_) => FacetKind::TerminalAssertions,
        }
    }
}

/// Describes role semantics without exposing an alternate mutation path.
pub trait RoleDescription {
    /// Returns an immutable canonical role profile identity.
    fn role_profile(&self) -> &crucible_node_contract::Id;
}

/// Exposes compute semantics through the common admitted-operation contract.
pub trait ComputeNode: SimulationNode {
    /// Returns the architecture, processors, clocks and observation profile.
    fn compute_description(&self) -> &dyn RoleDescription;
}

/// Exposes block semantics through the common admitted-operation contract.
pub trait BlockNode: SimulationNode {
    /// Returns request, ordering, durability and storage-ownership semantics.
    fn block_description(&self) -> &dyn RoleDescription;
}

/// Exposes filesystem semantics through the common admitted-operation contract.
pub trait FilesystemNode: SimulationNode {
    /// Returns namespace, permission, handle-lifetime and visibility semantics.
    fn filesystem_description(&self) -> &dyn RoleDescription;
}

/// Exposes link semantics through the common admitted-operation contract.
pub trait NetworkLinkNode: SimulationNode {
    /// Returns endpoint, latency, ordering and retained-frame semantics.
    fn link_description(&self) -> &dyn RoleDescription;
}

/// Exposes clock semantics without establishing a second coordinator authority.
pub trait ClockNode: SimulationNode {
    /// Returns coordinate, epoch, transform, wrap and timer semantics.
    fn clock_description(&self) -> &dyn RoleDescription;
}

/// Exposes external-device semantics without inferring physical pause support.
pub trait ExternalDeviceNode: SimulationNode {
    /// Returns input capture, quantization, containment and restore limitations.
    fn external_description(&self) -> &dyn RoleDescription;
}
