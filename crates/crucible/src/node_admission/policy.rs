//! Closed host-admission policy schemas bound by portable content references.
//!
//! Core descriptors deliberately place detailed semantic contracts in referenced
//! content. These records provide one explicit host-supported policy edition;
//! unsupported editions or extensions are refused rather than guessed.

use crucible_node_contract::{ContentRef, Endpoint, Id, U64};
use serde::{Deserialize, Serialize};

/// Selects lane visibility without confusing publication with physical execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LaneVisibility {
    /// Exact superdense coordinates preserve native causal ordering.
    Exact,
    /// Inputs and outputs use an explicitly bound quantized window contract.
    Quantized {
        /// Gives the positive quantum duration in picoseconds.
        quantum_ps: U64,
        /// Gives the grid phase, strictly smaller than the quantum.
        phase_ps: U64,
        /// Binds complete ingress, egress, uncertainty, and lateness semantics.
        contract_ref: ContentRef,
    },
}

/// Defines admitted finite capacity exhaustion semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowControl {
    /// Retains owned operations while bounded credits are exhausted.
    Credit,
    /// Refuses a new operation without performing its effect.
    Refusal,
    /// Applies an explicitly qualified bounded-loss contract.
    BoundedLoss,
}

/// Defines the full selected semantics of one directed lane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanePolicy {
    /// Names the lane in its immutable port descriptor.
    pub lane_id: Id,
    /// Binds sequence, arbitration, barrier, and retry semantics.
    pub ordering_ref: ContentRef,
    /// Binds correlation, completion multiplicity, and cancellation semantics.
    pub correlation_ref: ContentRef,
    /// Selects finite exhaustion behavior.
    pub flow_control: FlowControl,
    /// Bounds outstanding payload bytes, including partial operations.
    pub maximum_pending_bytes: U64,
    /// Gives the exact selected publication contract.
    pub visibility: LaneVisibility,
    /// Enumerates permitted baseline effect phases in increasing order.
    pub effect_phases: Vec<u16>,
    /// Gives a qualified lower bound covering every output path.
    pub minimum_lookahead_ps: U64,
}

/// Defines a port's finite multi-client and mutable-state contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortPolicy {
    /// Selects this closed policy edition; currently one.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Enumerates every immutable descriptor lane, sorted by lane identity.
    pub lanes: Vec<LanePolicy>,
    /// Bounds input connections across the port.
    pub maximum_producers: U64,
    /// Bounds output connections across the port.
    pub maximum_consumers: U64,
    /// Binds serialization, broadcast, or shared-access arbitration.
    pub arbitration_ref: ContentRef,
    /// Names the unique owner advancing mutable port effects.
    pub execution_owner_id: Id,
    /// Enumerates all mutable domains represented by the port.
    pub state_domain_ids: Vec<Id>,
    /// Marks a causal port mediated inside the indivisible composite owner.
    pub internal: bool,
}

/// Selects direct visibility or a separately admitted explicit conversion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VisibilityConversion {
    /// Preserves identical lane visibility on both endpoints.
    Direct,
    /// Preserves original public coordinates across accepted visibility modes.
    ///
    /// This conversion retains every original publication coordinate and byte,
    /// adds only the selected fixed transport latency, and invents no internal
    /// evaluation time. Its use requires explicit scenario acceptance.
    PublicationPreserving {
        /// Binds lossless original-coordinate delivery and its weaker semantics.
        contract_ref: ContentRef,
    },
    /// Samples each original publication at the first destination quantum boundary.
    BoundarySampling {
        /// Binds lossless ordered sampling with retained original causal provenance.
        contract_ref: ContentRef,
    },
    /// Applies a qualified conversion whose omissions are explicitly accepted.
    Adapter {
        /// Binds the complete conversion semantics and guarantee scope.
        contract_ref: ContentRef,
    },
}

/// Selects the actual temporal transfer rule independently of causal lookahead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectionDelivery {
    /// Applies an explicitly selected fixed delivery interval.
    Fixed {
        /// Gives the actual interval added to the producer's publication instant.
        latency_ps: U64,
    },
}

/// Defines a selected connection's bounds, visibility, and transfer custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPolicy {
    /// Selects this closed policy edition; currently one.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Bounds each message for this connection.
    pub maximum_payload_bytes: U64,
    /// Bounds outstanding operations for this connection.
    pub maximum_pending_events: U64,
    /// Bounds total outstanding payload bytes for this connection.
    pub maximum_pending_bytes: U64,
    /// Selects exact direct delivery or an explicit conversion.
    pub visibility: VisibilityConversion,
    /// Selects actual delivery timing; minimum lookahead is not a delay rule.
    pub delivery: ConnectionDelivery,
    /// Binds all-path latency proof, including failures and cancellation.
    pub causal_proof_ref: ContentRef,
    /// Enumerates mutable transfer/credit/custody domains captured by its owner.
    pub state_domain_ids: Vec<Id>,
}

/// Enumerates a uniquely owned mutable state domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDomain {
    /// Names the domain globally within the world.
    pub id: Id,
    /// Names its sole authoritative capture owner.
    pub capture_owner_id: Id,
    /// Names all serialized execution owners allowed to mutate this domain.
    pub execution_owner_ids: Vec<Id>,
    /// States whether the domain can affect modeled continuation or timing.
    pub future_affecting: bool,
}

/// Classifies a realized object without inferring completeness from serializers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectState {
    /// Names the authoritative mutable domain containing the object's state.
    Mutable {
        /// Gives a declared mutable domain identity.
        domain_id: Id,
    },
    /// Binds immutable state required to reconstruct the modeled object.
    Immutable {
        /// Commits to the complete immutable object content.
        content_ref: ContentRef,
    },
    /// Declares an omission instead of claiming exact model closure.
    OutsideScope,
}

/// Identifies every realized object in an accepted coverage inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateObject {
    /// Names the object within the admitted world.
    pub id: Id,
    /// Names the logical public-node views exposing this object.
    pub node_ids: Vec<Id>,
    /// States whether it can affect future modeled execution or timing.
    pub future_affecting: bool,
    /// Classifies its state preservation obligation.
    pub state: ObjectState,
}

/// Declares a causal path not represented by a public transport connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalDependency {
    /// Identifies the causal path in the coverage inventory.
    pub id: Id,
    /// Names the producer public-node view.
    pub producer_node_id: Id,
    /// Names the consumer public-node view.
    pub consumer_node_id: Id,
    /// Gives an accepted minimum latency over every admitted path.
    pub minimum_latency_ps: U64,
    /// Binds complete path enumeration, semantics, and causal qualification.
    pub proof_ref: ContentRef,
}

/// Declares a capture owner's complete boundary and reconstruction contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCapturePolicy {
    /// Names an admitted authoritative capture owner.
    pub owner_id: Id,
    /// States whether all owned future-affecting model state is preserved.
    pub complete_model: bool,
    /// States whether capture preserves the reached cut without model mutation.
    pub unchanged_cut: bool,
    /// States whether the captured state admits exact suffix continuation.
    pub exact_continuation: bool,
    /// States whether reconstruction works after all source owners have exited.
    pub durable_restart: bool,
    /// States whether live child branches have independent mutable resources.
    pub isolated_fork: bool,
    /// Enumerates other capture owners participating in the consistent cut.
    pub dependencies: Vec<Id>,
    /// Binds the qualified closure/custody procedure for this owner and its peers.
    pub cut_procedure_ref: ContentRef,
}

/// Describes complete realized object, causal-path, and ownership coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipPolicy {
    /// Selects this closed policy edition; currently one.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Enumerates unique mutable domains sorted by identity.
    pub domains: Vec<StateDomain>,
    /// Enumerates every realized stateful/immutable object sorted by identity.
    pub objects: Vec<StateObject>,
    /// Enumerates all internal and side-channel paths sorted by identity.
    pub internal_dependencies: Vec<InternalDependency>,
    /// Enumerates every capture owner's contract sorted by owner identity.
    pub capture_owners: Vec<OwnerCapturePolicy>,
    /// Binds accepted evidence that the inventory includes all effective paths.
    pub inventory_proof_ref: ContentRef,
}

/// Defines a bounded qualified same-time closure procedure for one owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SameTimeClosure {
    /// Names the execution owner whose complete microstep closure is supported.
    pub execution_owner_id: Id,
    /// Binds accepted evidence for phase-complete same-time participation.
    pub proof_ref: ContentRef,
}

/// Defines the selected coordinator progress and operational containment policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorPolicy {
    /// Selects this closed policy edition; currently one.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Binds complete coordinator future-affecting state and consistent-cut logic.
    pub state_closure_ref: ContentRef,
    /// Caps superdense microsteps per physical instant; zero disallows cycles.
    pub maximum_microsteps_per_instant: U64,
    /// Enumerates execution owners with accepted complete same-time closure.
    pub same_time_closure: Vec<SameTimeClosure>,
    /// Binds finite host resource limits, watchdogs, and containment semantics.
    pub operational_policy_ref: ContentRef,
    /// Enumerates admitted external root-input lanes with explicit provenance.
    pub external_inputs: Vec<Endpoint>,
}

/// Specifies scenario guarantees and explicit acceptance of weaker contracts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRequirements {
    /// Requires qualified deterministic forward execution of the entire world.
    pub deterministic: bool,
    /// Requires complete model state captured without advancing or draining.
    pub exact_capture: bool,
    /// Requires exact suffix continuation from the captured world cut.
    pub exact_continuation: bool,
    /// Requires fresh durable reconstruction after all original owners exit.
    pub durable_restart: bool,
    /// Requires isolated live children, independently of durable restart.
    pub isolated_fork: bool,
    /// Explicitly accepts named nodes' complete selected quantized contracts.
    pub accepted_quantized_nodes: Vec<Id>,
    /// Explicitly accepts named nodes' nondeterministic/unqualified execution.
    pub accepted_nondeterministic_nodes: Vec<Id>,
    /// Explicitly accepts named nodes' capture and replay limitations.
    pub accepted_limited_state_nodes: Vec<Id>,
    /// Explicitly accepts named connections' complete visibility conversions.
    pub accepted_visibility_conversions: Vec<Id>,
}
