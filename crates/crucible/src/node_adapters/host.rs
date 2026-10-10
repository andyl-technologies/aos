//! Exact event execution, inactive readiness and complete custody of owned host models.

use std::{
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible_device::{clock::VirtualClock, netlink::NetLink};
use crucible_node_contract::{
    ContentRef, Direction, Endpoint, HashRef, Id, NodeBinding, NodeDescriptor, Phase, Position,
    canonical,
};

use crate::{device_subnode::ScheduledIoNode, node_admission::AdmittedGraph, node_contract::*};

pub use condition_state::reopen::reopen_condition_model;
pub use owned_preparation::HOST_PUBLIC_OWNED_MODEL_PREPARATION_SPECIFICATION;
pub use preparation::{
    HOST_PUBLIC_CLOCK_PREPARATION_SPECIFICATION, host_public_clock_preparation_schema,
};
use preparation::{HostPreparationOrigin, HostPublicPreparation};
pub use public_continuation::{
    HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE, HOST_PUBLIC_CLOCK_CONTINUATION_SPECIFICATION,
    HOST_PUBLIC_CLOCK_EPOCH_CONTINUATION_PROFILE, host_public_clock_continuation_schema,
    host_public_clock_epoch_continuation_schema, validate_public_clock_continuation,
};
pub use state::archive::{HostContinuationInventory, validate_host_continuation};

/// Identifies the complete host-model preservation facet.
pub const HOST_PRESERVATION_PROFILE: &str = "host/preservation-v1";
/// Identifies genuine suspension of a locally owned nonautonomous host model.
pub const HOST_PHYSICAL_PAUSE_PROFILE: &str = "host/physical-pause-v1";
/// Identifies bounded exact host-model event execution and boundary settlement.
pub const HOST_EXACT_PROFILE: &str = "host/exact-v1";
/// Identifies explicit whole-world-fenced assertion finalization.
pub const HOST_TERMINAL_ASSERTIONS_PROFILE: &str = "host/terminal-assertions-v1";
/// Identifies complete stopped host-model future-work inventory.
pub const HOST_TERMINAL_INVENTORY_PROFILE: &str = "host/terminal-inventory-v1";
/// Identifies admitted immutable coefficient transitions with original custody.
pub const HOST_FAULT_INJECTION_PROFILE: &str = "host/fault-injection-v1";
/// Identifies selected original canonical condition stop and resume control.
pub const HOST_CONDITION_DEBUG_PROFILE: &str = "host/condition-debug-v1";
/// Identifies complete local stopped custody with permitted future native work.
pub const HOST_CONDITION_INVENTORY_PROFILE: &str = "host/condition-inventory-v1";

/// Encodes the complete integer clock continuation without guest timer state.
pub fn host_clock_initial_bytes(time_ps: u64) -> Vec<u8> {
    let mut bytes = b"crucible.host-clock.v1\0".to_vec();
    bytes.extend_from_slice(&time_ps.to_le_bytes());
    bytes
}

/// Contains an actual deterministic model with exclusive local custody.
pub enum HostModel {
    /// Owns the complete block or filesystem device and scheduler bridge.
    Io(Box<ScheduledIoNode>),
    /// Owns the directed link's full pending deliveries, faults and RNG cursor.
    Link(Box<NetLink>),
    /// Owns the selected seeded transport definition and full native fault/RNG queue.
    SeededLink {
        /// Owns the unchanged native NetLink state.
        link: Box<NetLink>,
        /// Binds original seed, stream and bounded static fault policy.
        definition: super::SeededLinkDefinition,
    },
    /// Owns a separately selected adverse transport and original input decisions.
    FaultedLink {
        /// Owns complete actual native timing, queue, fault table and random cursor.
        link: Box<NetLink>,
        /// Binds the independently selected static adverse program.
        definition: super::FaultedLinkDefinition,
        /// Retains original inputs, raw draws and zero/one/two output decisions.
        decisions: Vec<super::FaultDecision>,
    },
    /// Owns an opaque packet receiver with original history and delayed echo custody.
    PacketReceiver(Box<super::PacketReceiver>),
    /// Owns a separately selected recorded coefficient controller and native link.
    ControlledFaultLink(Box<super::ControlledFaultLink>),
    /// Owns an exact integer coordinator-clock model, without guest timers.
    Clock(VirtualClock),
    /// Owns a distinct rational visible counter and original causal alarm queue.
    RateAlarmClock(Box<super::RateAlarmClock>),
    /// Owns a finite immutable public request script and its exact native cursor.
    ScriptedSource(Box<super::ScriptedSource>),
    /// Owns the complete original assertion evaluator and checked input prefix.
    Semantics(Box<super::semantic_model::HostSemanticModel>),
    /// Owns a separately selected event-condition evaluator and original control journal.
    ConditionObserver(Box<super::ConditionDebugModel>),
}

impl HostModel {
    /// Encodes the complete native initialization state using its existing codec.
    ///
    /// # Errors
    /// Rejects codec failures or state exceeding the requested retention ceiling.
    pub fn initialization_bytes(&self, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
        self.capture(maximum)
    }
    fn role(&self) -> &'static str {
        match self {
            Self::Io(node) if node.block_device().is_some() => "block",
            Self::Io(_) => "filesystem",
            Self::Link(_) => "network_link",
            Self::SeededLink { .. } => "seeded_byte_transport",
            Self::FaultedLink { .. } => "adverse_byte_transport",
            Self::ControlledFaultLink(_) => "controlled_fault_transport",
            Self::PacketReceiver(_) => "packet_receiver",
            Self::Clock(_) => "clock",
            Self::RateAlarmClock(_) => "rate_alarm_clock",
            Self::ScriptedSource(_) => "scripted_source",
            Self::Semantics(_) => "host_assertions",
            Self::ConditionObserver(_) => "condition_observer",
        }
    }

    fn time_ps(&self) -> Result<u64, OperationFailure> {
        match self {
            Self::Io(node) => node
                .block_device()
                .map(|d| d.core().current_icount())
                .or_else(|| node.ninep_device().map(|d| d.core().current_icount()))
                .ok_or_else(|| failure("unknown concrete host I/O device")),
            Self::Link(link) | Self::SeededLink { link, .. } | Self::FaultedLink { link, .. } => {
                Ok(link.current_icount())
            }
            Self::PacketReceiver(receiver) => Ok(receiver.time_ps()),
            Self::ControlledFaultLink(controller) => Ok(controller.native().current_icount()),
            Self::Clock(clock) => Ok(clock.current_icount()),
            Self::RateAlarmClock(clock) => Ok(clock.time_ps()),
            Self::ScriptedSource(source) => Ok(source.time_ps()),
            Self::Semantics(model) => Ok(model.position().time_ps.get()),
            Self::ConditionObserver(model) => Ok(model.position().time_ps.get()),
        }
    }

    fn capture(&self, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
        let bytes = match self {
            Self::Io(node) => node
                .checkpoint()
                .canonical_bytes()
                .map_err(|e| failure(&e.to_string()))?,
            Self::Link(link) => link
                .snapshot()
                .canonical_bytes_with_limit(maximum as u64)
                .map_err(|e| failure(&e.to_string()))?,
            Self::SeededLink { link, definition } => definition.capture(link, maximum)?,
            Self::FaultedLink {
                link,
                definition,
                decisions,
            } => definition.capture(link, decisions, maximum)?,
            Self::PacketReceiver(receiver) => receiver.capture()?,
            Self::ControlledFaultLink(controller) => controller.capture(maximum)?,
            Self::Clock(clock) => host_clock_initial_bytes(clock.current_icount()),
            Self::RateAlarmClock(clock) => clock.capture()?,
            Self::ScriptedSource(source) => source.capture()?,
            Self::Semantics(model) => model.capture()?,
            Self::ConditionObserver(model) => model.capture()?,
        };
        if bytes.len() > maximum {
            return Err(failure(
                "host model continuation exceeds admitted byte ceiling",
            ));
        }
        Ok(bytes)
    }
}

/// Authenticates installed host code and complete immutable model inputs.
///
/// This trusted host boundary must inspect the actual supplied model, its
/// immutable block base or served filesystem tree, installed implementation
/// artifacts and selected profile. Matching a label, hash syntax, or mutable
/// checkpoint alone is insufficient. Implementations must not accept a vendor
/// self-issued qualification claim.
pub trait HostModelQualification {
    /// Qualifies the actual owned model and realized contract without effects.
    ///
    /// # Errors
    /// Rejects missing installed-code evidence, immutable artifact mismatches,
    /// unsupported model semantics or incomplete future-affecting inventory.
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure>;

    /// Qualifies original public preparation of an independently owned finite model.
    ///
    /// # Errors
    /// Refuses by default. An installed policy must regenerate the complete
    /// graph, immutable model inputs and original single-owner scope. This
    /// permission supplies no continuation or capture qualification.
    fn authenticate_initial_owned_model(
        &self,
        _model: &HostModel,
        _graph: &AdmittedGraph,
        _descriptor: &NodeDescriptor,
        _binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        Err(failure("original owned-model preparation is not qualified"))
    }

    /// Authenticates the independently installed complete recorded-input source.
    ///
    /// # Errors
    /// The default refuses; source syntax or matching hashes do not qualify arrivals.
    fn authenticate_recorded_ingress(
        &self,
        _definition: &super::RecordedIngressDefinition,
        _descriptor: &NodeDescriptor,
        _binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        Err(failure(
            "installed recorded-input qualification unavailable",
        ))
    }

    /// Qualifies the separate complete recorded cursor preservation policy.
    ///
    /// # Errors
    /// Refuses by default until the installed source owns this native codec.
    fn authenticate_recorded_preservation(
        &self,
        _definition: &super::RecordedIngressDefinition,
        _descriptor: &NodeDescriptor,
        _binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        Err(failure(
            "recorded cursor preservation policy is not qualified",
        ))
    }

    /// Qualifies the separately selected stopped-condition native continuation.
    ///
    /// # Errors
    /// Refuses by default. Implementations must regenerate the installed whole
    /// condition world, model artifacts, finite limits and native-six grammar.
    fn authenticate_condition_preservation(
        &self,
        _model: &HostModel,
        _descriptor: &NodeDescriptor,
        _binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        Err(failure(
            "condition continuation preservation is not qualified",
        ))
    }

    /// Authenticates complete native capture and isolated original custody lineage.
    ///
    /// # Errors
    /// The default refuses restoration. Installed implementations must verify
    /// the actual complete capture, immutable native inputs, original host
    /// runtime inventory and fresh destination owner generations.
    fn authenticate_continuation(
        &self,
        _model: &HostModel,
        _descriptor: &NodeDescriptor,
        _binding: &NodeBinding,
        _native: &[u8],
        _source: &RuntimeSnapshot,
        _target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        Err(failure(
            "installed host continuation qualification unavailable",
        ))
    }
}

/// Bounds host continuation and original-operation evidence custody.
#[derive(Clone, Copy, Debug)]
pub struct HostModelResources {
    /// Bounds each native continuation retained by the administrative adapter.
    pub maximum_capture_bytes: usize,
    /// Bounds original operation tombstones, which are never recycled.
    pub maximum_operations: usize,
}

impl Default for HostModelResources {
    fn default() -> Self {
        Self {
            maximum_capture_bytes: 16 * 1024 * 1024,
            maximum_operations: 65_536,
        }
    }
}

struct Completed {
    original: OperationAdmission,
    outcome: OperationOutcome,
    capture: Option<Rc<Vec<u8>>>,
    acknowledged: bool,
    evidence: Vec<crate::node_scheduling::InputPayload>,
}

/// Exposes a genuinely owned host model through common node operations.
///
/// The qualified exact facet settles authentic staged requests and pending
/// device or link events within half-open grants. Administrative profiles also
/// support inactive readiness, physical suspension, complete preservation and
/// supervised destruction. Legacy model codecs remain unchanged.
pub struct HostModelNode {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    model: Option<HostModel>,
    initial: Rc<Vec<u8>>,
    boundary: Position,
    thread: std::thread::ThreadId,
    facets: Vec<FacetKind>,
    preservation: HostFacet,
    fault_injection: HostFacet,
    condition_debug: HostFacet,
    pause: HostFacet,
    world_hash: HashRef,
    limits: HostModelResources,
    readiness: Option<(ActivationRecord, ReadyAttestation)>,
    completed: BTreeMap<Id, Completed>,
    condition_objects: BTreeMap<ContentRef, crate::node_scheduling::InputPayload>,
    condition_operation_objects: BTreeMap<Id, Vec<ContentRef>>,
    failed: BTreeMap<Id, (OperationAdmission, OperationFailure)>,
    reclamations: BTreeMap<OwnerIdentity, NativeReclamationReceipt>,
    quarantined: bool,
    activation_authority: Option<Rc<()>>,
    execution: HostFacet,
    terminal: HostFacet,
    terminal_inventory: HostFacet,
    input_endpoint: Option<Endpoint>,
    output_endpoint: Option<Endpoint>,
    maximum_microsteps: crucible_node_contract::U64,
    staged: Option<execution::Staged>,
    input_history: BTreeMap<Id, execution::Staged>,
    pending_causes: BTreeMap<(u64, u32, u32), Vec<Position>>,
    native_sequence: u64,
    scheduling_observation: Option<(
        WorldActivation,
        crate::node_scheduling::NativeSchedulingObservation,
    )>,
    prepared_continuation: Option<state::PreparedHostContinuation>,
    readiness_inventory: ContentRef,
    original_model_session: Rc<()>,
    preparation_origin: HostPreparationOrigin,
    public_preparation: Option<HostPublicPreparation>,
    public_model_preparation: Option<owned_preparation::OriginalOwnedModelPreparation>,
    public_continuation: bool,
    recorded_ingress: Option<super::host_ingress::RecordedIngressCustody>,
    condition_preservation: bool,
    producer_observations: Vec<rate_alarm_evidence::OriginalReceipt>,
}

impl HostModelNode {
    /// Takes exclusive custody of a qualified inactive model from a sealed graph.
    ///
    /// Initialization bytes must be the model's actual existing continuation
    /// codec. The clock edition uses its documented little-endian integer tick.
    /// Distinct execution/capture owners require a shared owning actor and are
    /// refused by this single-owner adapter.
    ///
    /// # Errors
    /// Rejects absent graph membership, unsupported selected facets, incomplete
    /// installed-model qualification, owner aliasing, initialization mismatch,
    /// or exceeded native continuation/resource ceilings.
    pub fn new(
        graph: &AdmittedGraph,
        node: &Id,
        model: HostModel,
        qualification: &dyn HostModelQualification,
        limits: HostModelResources,
    ) -> Result<Self, OperationFailure> {
        let descriptor = graph
            .descriptor(node)
            .ok_or_else(|| failure("host node absent from sealed graph"))?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| failure("host binding absent from sealed graph"))?;
        if limits.maximum_capture_bytes == 0
            || limits.maximum_operations == 0
            || descriptor.roles.len() != 1
            || descriptor.roles[0].as_str() != model.role()
            || binding.compatibility.execution_owner != binding.compatibility.capture_owner
            || binding
                .compatibility
                .execution_owner
                .participant_ids
                .as_slice()
                != std::slice::from_ref(node)
        {
            return Err(failure(
                "host model role, single-owner custody or resource contract mismatch",
            ));
        }
        if matches!(&model, HostModel::RateAlarmClock(_))
            != super::rate_alarm_clock::selected(binding)
        {
            return Err(failure(
                "rational clock requires its distinct installed native schema",
            ));
        }
        if rate_alarm_evidence::selected(binding)
            && !matches!(&model, HostModel::RateAlarmClock(_))
            && !matches!(&model, HostModel::ScriptedSource(source) if source.kind() == super::ScriptedRequestKind::RateAlarmClock)
        {
            return Err(failure(
                "selected producer receipt codec requires RateClock/kind4 Script",
            ));
        }
        qualification.authenticate_model(&model, descriptor, binding)?;
        let mut facets = Vec::new();
        let public_preservation = matches!(model, HostModel::Clock(_))
            && binding
                .compatibility
                .implementation
                .formats
                .contains(&public_continuation::host_public_clock_continuation_schema()?);
        let epoch_preservation = binding
            .compatibility
            .implementation
            .formats
            .contains(&public_continuation::host_public_clock_epoch_continuation_schema()?);
        let preservation = Id::new(if state::condition::selected(binding) {
            state::condition::PRESERVATION_PROFILE
        } else if epoch_preservation {
            public_continuation::HOST_PUBLIC_CLOCK_EPOCH_CONTINUATION_PROFILE
        } else if public_preservation {
            public_continuation::HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE
        } else {
            HOST_PRESERVATION_PROFILE
        })
        .map_err(|e| failure(&e.to_string()))?;
        let pause = Id::new("host/physical-pause-v1").map_err(|e| failure(&e.to_string()))?;
        let execution = Id::new(HOST_EXACT_PROFILE).map_err(|e| failure(&e.to_string()))?;
        let terminal =
            Id::new(HOST_TERMINAL_ASSERTIONS_PROFILE).map_err(|e| failure(&e.to_string()))?;
        let condition_inventory_selected = binding
            .compatibility
            .operating_contract
            .facets
            .iter()
            .any(|facet| {
                facet.id.as_str() == HOST_CONDITION_INVENTORY_PROFILE && facet.version == 1
            });
        let terminal_inventory = Id::new(if condition_inventory_selected {
            HOST_CONDITION_INVENTORY_PROFILE
        } else {
            HOST_TERMINAL_INVENTORY_PROFILE
        })
        .map_err(|e| failure(&e.to_string()))?;
        let condition_debug =
            Id::new(HOST_CONDITION_DEBUG_PROFILE).map_err(|e| failure(&e.to_string()))?;
        let fault_injection =
            Id::new(HOST_FAULT_INJECTION_PROFILE).map_err(|e| failure(&e.to_string()))?;
        for selected in &binding.compatibility.operating_contract.facets {
            if selected.id == preservation {
                facets.push(FacetKind::Preservation);
            } else if selected.id == pause {
                facets.push(FacetKind::PhysicalPause);
            } else if selected.id == execution && selected.version == 1 {
                facets.push(FacetKind::ExactExecution);
            } else if selected.id == terminal
                && selected.version == 1
                && matches!(&model, HostModel::Semantics(model) if model.definition().version == 2)
            {
                facets.push(FacetKind::TerminalAssertions);
            } else if selected.id == terminal_inventory && selected.version == 1 {
                facets.push(FacetKind::Introspection);
            } else if selected.id == condition_debug
                && selected.version == 1
                && matches!(&model, HostModel::ConditionObserver(_))
            {
                facets.push(FacetKind::Debugging);
            } else if selected.id == fault_injection
                && selected.version == 1
                && matches!(&model, HostModel::ControlledFaultLink(_))
            {
                facets.push(FacetKind::FaultInjection);
            } else {
                return Err(failure(
                    "host selected facet lacks an installed execution adapter",
                ));
            }
        }
        facets.sort();
        let (input_endpoint, output_endpoint) =
            execution::validate_inventory(graph, node, &model, &facets)?;
        let initial = model.capture(limits.maximum_capture_bytes)?;
        let reference = canonical::content_ref(&initial, &descriptor.initialization_ref.media_type)
            .map_err(|e| failure(&e.to_string()))?;
        if reference != descriptor.initialization_ref {
            return Err(failure(
                "actual host continuation differs from admitted initialization",
            ));
        }
        let boundary = Position::new(model.time_ps()?.into(), 0.into(), Phase::BoundaryControl);
        let owner = OwnerIdentity {
            owner: binding.compatibility.execution_owner.id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        Ok(Self {
            descriptor: descriptor.clone(),
            binding: binding.clone(),
            route: NodeRoute {
                node: node.clone(),
                owners: vec![owner],
            },
            model: Some(model),
            initial: Rc::new(initial),
            boundary,
            thread: std::thread::current().id(),
            facets,
            preservation: HostFacet(preservation),
            fault_injection: HostFacet(fault_injection),
            condition_debug: HostFacet(condition_debug),
            pause: HostFacet(pause),
            world_hash: graph.world_binding_hash().clone(),
            limits,
            readiness: None,
            completed: BTreeMap::new(),
            condition_objects: BTreeMap::new(),
            condition_operation_objects: BTreeMap::new(),
            failed: BTreeMap::new(),
            reclamations: BTreeMap::new(),
            quarantined: false,
            activation_authority: None,
            execution: HostFacet(execution),
            terminal: HostFacet(terminal),
            terminal_inventory: HostFacet(terminal_inventory),
            input_endpoint,
            output_endpoint,
            maximum_microsteps: graph.coordinator_policy().maximum_microsteps_per_instant,
            staged: None,
            input_history: BTreeMap::new(),
            pending_causes: BTreeMap::new(),
            native_sequence: 0,
            scheduling_observation: None,
            producer_observations: Vec::new(),
            prepared_continuation: None,
            readiness_inventory: descriptor.initialization_ref.clone(),
            original_model_session: Rc::new(()),
            preparation_origin: HostPreparationOrigin::Original,
            public_preparation: None,
            public_model_preparation: None,
            public_continuation: false,
            recorded_ingress: None,
            condition_preservation: false,
        })
    }

    /// Selects independently qualified original stopped-condition preservation.
    ///
    /// This attachment is accepted only while the actual model remains fresh.
    /// Live condition inventory edition four remains unchanged; complete signed
    /// capture uses the distinct native-six wrapper and source-qualified factory.
    ///
    /// # Errors
    /// Refuses late attachment, unsupported model/format, mixed recorded custody,
    /// absent preservation facets or default-refusing installed qualification.
    pub fn with_preservable_condition(
        mut self,
        qualification: &dyn HostModelQualification,
    ) -> Result<Self, OperationFailure> {
        if self.condition_preservation
            || self.readiness.is_some()
            || self.preparation_origin != HostPreparationOrigin::Original
            || !self.completed.is_empty()
            || !self.failed.is_empty()
            || self.recorded_ingress.is_some()
            || !self.facets.contains(&FacetKind::Preservation)
            || !condition_state::selected(&self)
            || !state::condition::selected(&self.binding)
        {
            return Err(failure(
                "condition preservation requires original inactive custody",
            ));
        }
        let model = self
            .model
            .as_ref()
            .ok_or_else(|| failure("condition model missing"))?;
        qualification.authenticate_condition_preservation(
            model,
            &self.descriptor,
            &self.binding,
        )?;
        self.condition_preservation = true;
        Ok(self)
    }

    /// Takes the complete qualified recorded-input FIFO before arming this owner.
    ///
    /// Capture and restoration remain refused until their codecs preserve the
    /// original source cursor and pending FIFO alongside the native device.
    ///
    /// # Errors
    /// Refuses late attachment, unsupported model/lane, incomplete graph inventory,
    /// selected capture facets, or absent installed source authentication.
    pub fn with_recorded_ingress(
        self,
        graph: &AdmittedGraph,
        definition: super::RecordedIngressDefinition,
        qualification: &dyn HostModelQualification,
    ) -> Result<Self, OperationFailure> {
        self.install_recorded_ingress(graph, definition, qualification, false)
    }

    /// Installs independently qualified recorded Block custody with its distinct cursor codec.
    ///
    /// # Errors
    /// Refuses another native format, unsupported source policy or nonfresh custody.
    pub fn with_preservable_recorded_ingress(
        self,
        graph: &AdmittedGraph,
        definition: super::RecordedIngressDefinition,
        qualification: &dyn HostModelQualification,
    ) -> Result<Self, OperationFailure> {
        self.install_recorded_ingress(graph, definition, qualification, true)
    }

    fn install_recorded_ingress(
        mut self,
        graph: &AdmittedGraph,
        definition: super::RecordedIngressDefinition,
        qualification: &dyn HostModelQualification,
        preserved: bool,
    ) -> Result<Self, OperationFailure> {
        let endpoint = &definition.source().endpoint;
        if self.readiness.is_some()
            || self.recorded_ingress.is_some()
            || !self.completed.is_empty()
            || !self.failed.is_empty()
            || !matches!(self.model.as_ref(), Some(HostModel::Io(io)) if io.block_device().is_some())
            || self.input_endpoint.as_ref() != Some(endpoint)
            || graph.coordinator_policy().external_inputs.as_slice()
                != std::slice::from_ref(endpoint)
            || self.facets.contains(&FacetKind::Preservation) != preserved
            || (preserved && !state::recorded::selected(&self.binding))
        {
            return Err(failure(
                "recorded input lacks unique original inactive Block custody and selected codec",
            ));
        }
        qualification.authenticate_recorded_ingress(
            &definition,
            &self.descriptor,
            &self.binding,
        )?;
        if preserved {
            qualification.authenticate_recorded_preservation(
                &definition,
                &self.descriptor,
                &self.binding,
            )?;
        }
        self.readiness_inventory = definition.root().clone();
        let mut ingress = super::host_ingress::RecordedIngressCustody::new(definition);
        ingress.preserved = preserved;
        self.recorded_ingress = Some(ingress);
        Ok(self)
    }

    /// Returns the actual retained continuation for an original completed capture.
    ///
    /// # Errors
    /// Rejects foreign token custody or an operation that did not capture state.
    pub fn captured_bytes(&self, original: &OperationToken) -> Result<&[u8], OperationFailure> {
        self.original(original)?
            .capture
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .ok_or_else(|| failure("original operation did not capture state"))
    }

    fn original(&self, token: &OperationToken) -> Result<&Completed, OperationFailure> {
        let completed = self
            .completed
            .get(token.operation())
            .ok_or_else(|| failure("unknown original host operation"))?;
        if !Rc::ptr_eq(&completed.original.token.authority, &token.authority)
            || token.route() != &self.route
        {
            return Err(failure("foreign host operation authority"));
        }
        self.validate_original_fault_result(completed)?;
        Ok(completed)
    }

    fn capture(&self) -> Result<Vec<u8>, OperationFailure> {
        self.model
            .as_ref()
            .ok_or_else(|| failure("host model released"))?
            .capture(self.limits.maximum_capture_bytes)
    }

    fn receipt(&self, label: &str) -> Result<ContentRef, OperationFailure> {
        canonical::content_ref(&self.receipt_bytes(label), "application/octet-stream")
            .map_err(|e| failure(&e.to_string()))
    }

    fn receipt_bytes(&self, label: &str) -> Vec<u8> {
        let mut bytes = label.as_bytes().to_vec();
        bytes.extend_from_slice(&self.boundary.time_ps.get().to_le_bytes());
        for owner in &self.route.owners {
            bytes.extend_from_slice(owner.owner.as_str().as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(owner.incarnation.as_str().as_bytes());
            bytes.extend_from_slice(&owner.generation.get().to_le_bytes());
        }
        bytes
    }
}

impl FacetDescription for HostModelNode {
    fn profile(&self) -> &Id {
        &self.preservation.0
    }
}

struct HostFacet(Id);
impl FacetDescription for HostFacet {
    fn profile(&self) -> &Id {
        &self.0
    }
}

#[path = "host_rate_alarm_evidence.rs"]
pub(super) mod rate_alarm_evidence;

#[path = "host_runtime.rs"]
mod runtime;

#[path = "host_execution.rs"]
mod execution;

#[path = "host_fault.rs"]
mod fault;

#[path = "host_state.rs"]
pub(super) mod state;

#[path = "host_terminal.rs"]
mod terminal;

#[path = "host_preparation.rs"]
mod preparation;

#[path = "host_owned_preparation.rs"]
mod owned_preparation;
#[path = "host_public_continuation.rs"]
mod public_continuation;

pub(super) fn failure(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;

#[path = "host_condition_debug.rs"]
mod condition_debug;
#[path = "host_ingress_execution.rs"]
mod ingress_execution;

#[path = "host_condition_provenance.rs"]
pub(super) mod condition_provenance;

#[path = "host_condition_state.rs"]
pub(super) mod condition_state;

#[path = "host_clock_evidence.rs"]
mod clock_evidence;
#[path = "host_condition_objects.rs"]
mod condition_objects;
