//! Closed, scenario-owned policy data consumed by network fault effects.
//!
//! Network effects refer to these declarations by [`FaultObjectId`].  The ID is
//! only an address: all executable behavior is carried by the declaration and
//! included in the [`World`](super::World) identity.  This prevents a live
//! adapter from assigning host-local meaning to an otherwise opaque string.

use super::world_faults::{invalid, require};
use super::*;

/// Maximum declarations in one world.
pub const HARD_NETWORK_POLICY_ARTIFACTS: usize = 65_536;
/// Maximum entries in one policy declaration.
pub const HARD_NETWORK_POLICY_ENTRIES: usize = 65_536;
/// Maximum inline bytes in one typed network result or transform.
pub const HARD_NETWORK_POLICY_BYTES: usize = 16 * 1024 * 1024;

/// Exact interpolation between adjacent integer lookup points.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyInterpolation {
    /// Uses the value at the greatest key no larger than the input.
    Step,
    /// Uses checked rational linear interpolation with ties to even.
    LinearTiesToEven,
}

/// Behavior outside an integer lookup table's admitted domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyOutsideRange {
    /// Uses the nearest endpoint value.
    Clamp,
    /// Fails the opportunity with a typed range error.
    TypedError,
}

/// One strictly ordered point in an integer transfer table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyIntegerPoint {
    /// Input in the declaration's named fixed-point unit.
    pub input: i64,
    /// Output in the declaration's named fixed-point unit.
    pub output: i64,
}

/// A canonical integer transfer function.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyIntegerTable {
    /// Stable input-unit identity.
    pub input_unit: FaultObjectId,
    /// Stable output-unit identity.
    pub output_unit: FaultObjectId,
    /// In-domain interpolation rule.
    pub interpolation: NetworkPolicyInterpolation,
    /// Outside-domain behavior.
    pub outside: NetworkPolicyOutsideRange,
    /// Strictly increasing table points.
    pub points: Vec<NetworkPolicyIntegerPoint>,
}

/// Per-state correlated frame-error behavior.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyErrorState {
    /// Stable state identity.
    pub state: FaultObjectId,
    /// Loss probability while in this state.
    pub loss: ProbabilityMillionths,
    /// Undetected-corruption probability while in this state.
    pub corruption: ProbabilityMillionths,
    /// Registered XOR template used when undetected corruption fires.
    pub corruption_transform: Option<FaultObjectId>,
}

/// One traffic class used by queue scheduling.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyQueueClass {
    /// Stable class identity.
    pub class: FaultObjectId,
    /// Packet selector assigning a matching frame to this class.
    pub selector: FaultObjectId,
    /// Lower values run first under strict priority.
    pub priority: u16,
    /// Positive round-robin weight.
    pub weight: PositiveU64,
    /// Positive deficit quantum in bytes.
    pub quantum_bytes: PositiveU64,
}

/// Complete optional parameters for bounded queue disciplines.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyQueueDiscipline {
    /// Canonically class-ID-ordered class definitions.
    pub classes: Vec<NetworkPolicyQueueClass>,
    /// RED minimum byte threshold, when RED is used.
    pub red_minimum_bytes: Option<u64>,
    /// RED maximum byte threshold, when RED is used.
    pub red_maximum_bytes: Option<u64>,
    /// RED maximum keyed drop probability, when RED is used.
    pub red_maximum_probability: Option<ProbabilityMillionths>,
    /// RED EWMA weight numerator.
    pub red_weight_numerator: Option<PositiveU64>,
    /// RED EWMA weight denominator.
    pub red_weight_denominator: Option<PositiveU64>,
}

/// One byte predicate used by a typed packet or forwarding selector.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyByteMatch {
    /// First selected byte.
    pub offset_bytes: u64,
    /// Bytes compared after applying the corresponding mask.
    pub value: Vec<u8>,
    /// Per-byte comparison mask with the same length as `value`.
    pub mask: Vec<u8>,
}

/// One deterministic state-machine edge.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyTransition {
    /// Source state.
    pub from: FaultObjectId,
    /// Typed request or event.
    pub event: FaultObjectId,
    /// Destination state.
    pub to: FaultObjectId,
    /// Delay before the destination state commits.
    pub delay_nanos: u64,
    /// Explicit traffic treatment during the transition.
    pub traffic_policy: NetworkInFlightPolicy,
}

/// Arbitration rule for one shared medium.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyArbitration {
    /// Oldest canonical transmission wins.
    Fifo,
    /// Lowest numeric priority encoded by the selector wins.
    StrictPriority,
    /// CAN-style dominant-bit arbitration.
    CanDominantBit,
    /// Fixed time slots are assigned in declared resource order.
    FixedSlots,
    /// Simultaneous transmitters contend and may collide.
    Contention,
}

/// Receiver disposition for overlapping medium transmissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyCollision {
    /// Every overlapping transmission is lost.
    DropAll,
    /// A transmission wins when its received power exceeds the runner-up by the threshold.
    Capture,
    /// A collision is delivered only through the declared undetected transform.
    UndetectedTransform,
}

/// Complete shared-medium access parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyMediumAccess {
    /// Arbitration rule.
    pub arbitration: NetworkPolicyArbitration,
    /// Collision/capture behavior.
    pub collision: NetworkPolicyCollision,
    /// Capture threshold in the declared integer power-ratio unit.
    pub capture_threshold: i64,
    /// Positive base backoff slot duration.
    pub backoff_slot_nanos: PositiveU64,
    /// Maximum binary-backoff exponent.
    pub maximum_backoff_exponent: u8,
    /// Maximum retry count.
    pub maximum_retries: u16,
    /// Duty-cycle numerator.
    pub duty_cycle_numerator: PositiveU64,
    /// Duty-cycle denominator.
    pub duty_cycle_denominator: PositiveU64,
}

/// One SINR transfer-table result.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyRfProfile {
    /// Inclusive lower SINR bound in the declared fixed-point unit.
    pub minimum_sinr: i64,
    /// Positive resulting bit rate.
    pub rate_bps: PositiveU64,
    /// Resulting loss probability.
    pub loss: ProbabilityMillionths,
    /// Resulting corruption probability.
    pub corruption: ProbabilityMillionths,
    /// Resulting retry delay.
    pub retry_delay_nanos: u64,
}

/// Integer-only RF propagation and transfer policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyRfChannel {
    /// Distance-to-path-gain table.
    pub path_gain: NetworkPolicyIntegerTable,
    /// Orientation-to-antenna-gain table.
    pub antenna_gain: NetworkPolicyIntegerTable,
    /// Ordered SINR-to-link-profile table.
    pub profiles: Vec<NetworkPolicyRfProfile>,
    /// Spatial quantization cell in millimetres.
    pub spatial_cell_mm: PositiveU64,
    /// Fading time bucket in virtual nanoseconds.
    pub fading_bucket_nanos: PositiveU64,
}

/// Closed association and handoff timing policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyAssociation {
    /// Minimum candidate advantage before handoff.
    pub hysteresis: i64,
    /// Residence above hysteresis before handoff.
    pub time_to_trigger_nanos: u64,
    /// Scan interval.
    pub scan_interval_nanos: PositiveU64,
    /// Authentication duration.
    pub authentication_nanos: u64,
    /// Handoff interruption duration.
    pub interruption_nanos: u64,
    /// Whether queued traffic survives a successful handoff.
    pub preserve_queued: bool,
    /// Whether addressing survives a successful handoff.
    pub preserve_address: bool,
    /// Candidate-specific deterministic score functions.
    pub candidates: Vec<NetworkPolicyAssociationCandidate>,
}

/// One association candidate and its signal-to-score transfer function.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyAssociationCandidate {
    /// Attachment identity present in the effect's candidate set.
    pub candidate: FaultObjectId,
    /// Integer transfer function from the binding input to candidate score.
    pub score: NetworkPolicyIntegerTable,
}

/// One half-open period during which a contact can carry traffic.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyContactInterval {
    /// Inclusive contact start in virtual nanoseconds.
    pub start_nanos: u64,
    /// Exclusive contact end in virtual nanoseconds.
    pub end_nanos: u64,
    /// Beam used during this interval.
    pub beam: FaultObjectId,
    /// Gateway used during this interval.
    pub gateway: FaultObjectId,
}

/// Disposition when a bounded control or custody queue overflows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyOverflow {
    /// Drops the arriving item.
    DropNewest,
    /// Drops the oldest queued item.
    DropOldest,
    /// Completes the arriving item with a typed error.
    TypedError,
    /// Retains the item until its modeled timeout.
    Timeout,
}

/// Coarse artifact class used to validate effect references before execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetworkPolicyArtifactClass {
    /// Integer transfer or distribution table.
    IntegerLookup,
    /// Correlated frame-error state table.
    ErrorStateTable,
    /// Queue discipline configuration.
    QueueDiscipline,
    /// Canonical bytes used by a transform.
    ByteTemplate,
    /// Typed packet selector.
    PacketSelector,
    /// Exhaustive state machine.
    StateMachine,
    /// Piecewise service curve.
    ServiceCurve,
    /// Shared-medium access configuration.
    MediumAccess,
    /// RF channel configuration.
    RfChannel,
    /// Association/handoff configuration.
    Association,
    /// Typed control result.
    ControlResult,
    /// Overflow/expiry configuration.
    Overflow,
    /// Ordered intermittent-contact plan.
    ContactPlan,
}

impl NetworkPolicyArtifactClass {
    /// Returns the stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntegerLookup => "integer_lookup",
            Self::ErrorStateTable => "error_state_table",
            Self::QueueDiscipline => "queue_discipline",
            Self::ByteTemplate => "byte_template",
            Self::PacketSelector => "packet_selector",
            Self::StateMachine => "state_machine",
            Self::ServiceCurve => "service_curve",
            Self::MediumAccess => "medium_access",
            Self::RfChannel => "rf_channel",
            Self::Association => "association",
            Self::ControlResult => "control_result",
            Self::Overflow => "overflow",
            Self::ContactPlan => "contact_plan",
        }
    }
}

/// One closed, self-contained artifact referenced by a network effect.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NetworkPolicyArtifactKind {
    /// Integer transfer or quantile table.
    IntegerLookup(NetworkPolicyIntegerTable),
    /// Good/bad correlated error-state outputs.
    ErrorStateTable {
        /// State interpreted as the good condition.
        good: FaultObjectId,
        /// State interpreted as the bad condition.
        bad: FaultObjectId,
        /// Initial state.
        initial: FaultObjectId,
        /// Canonical state definitions.
        states: Vec<NetworkPolicyErrorState>,
    },
    /// Queue discipline parameters.
    QueueDiscipline(NetworkPolicyQueueDiscipline),
    /// Replacement bytes or an undetected-corruption template.
    ByteTemplate {
        /// Complete bounded byte payload.
        bytes: Vec<u8>,
    },
    /// Typed byte-level packet selector.
    PacketSelector {
        /// All predicates must match.
        matches: Vec<NetworkPolicyByteMatch>,
    },
    /// Exhaustive deterministic state machine.
    StateMachine {
        /// Initial state.
        initial: FaultObjectId,
        /// Complete finite state set.
        states: Vec<FaultObjectId>,
        /// Complete allowed transition set.
        transitions: Vec<NetworkPolicyTransition>,
    },
    /// Piecewise service curve shared by queues or control work.
    ServiceCurve {
        /// Ordered segments beginning at offset zero.
        segments: NetworkServiceSegments,
    },
    /// Shared-medium arbitration, collision, backoff, and duty-cycle policy.
    MediumAccess(NetworkPolicyMediumAccess),
    /// Integer RF propagation and transfer tables.
    RfChannel(NetworkPolicyRfChannel),
    /// Association, authentication, and handoff policy.
    Association(NetworkPolicyAssociation),
    /// Typed operation-result replacement.
    ControlResult {
        /// Stable result schema identity.
        schema: FaultObjectId,
        /// Canonical encoded result bytes.
        bytes: Vec<u8>,
    },
    /// Queue-overflow or expiry policy.
    Overflow {
        /// Overflow disposition.
        disposition: NetworkPolicyOverflow,
        /// Optional modeled timeout.
        timeout_nanos: Option<PositiveU64>,
    },
    /// Ordered intermittent-contact intervals.
    ContactPlan {
        /// Strictly ordered, non-overlapping contact intervals.
        intervals: Vec<NetworkPolicyContactInterval>,
    },
}

impl NetworkPolicyArtifactKind {
    /// Returns the closed admission class for this policy payload.
    #[must_use]
    pub const fn class(&self) -> NetworkPolicyArtifactClass {
        match self {
            Self::IntegerLookup(_) => NetworkPolicyArtifactClass::IntegerLookup,
            Self::ErrorStateTable { .. } => NetworkPolicyArtifactClass::ErrorStateTable,
            Self::QueueDiscipline(_) => NetworkPolicyArtifactClass::QueueDiscipline,
            Self::ByteTemplate { .. } => NetworkPolicyArtifactClass::ByteTemplate,
            Self::PacketSelector { .. } => NetworkPolicyArtifactClass::PacketSelector,
            Self::StateMachine { .. } => NetworkPolicyArtifactClass::StateMachine,
            Self::ServiceCurve { .. } => NetworkPolicyArtifactClass::ServiceCurve,
            Self::MediumAccess(_) => NetworkPolicyArtifactClass::MediumAccess,
            Self::RfChannel(_) => NetworkPolicyArtifactClass::RfChannel,
            Self::Association(_) => NetworkPolicyArtifactClass::Association,
            Self::ControlResult { .. } => NetworkPolicyArtifactClass::ControlResult,
            Self::Overflow { .. } => NetworkPolicyArtifactClass::Overflow,
            Self::ContactPlan { .. } => NetworkPolicyArtifactClass::ContactPlan,
        }
    }
}

/// One versioned scenario-owned network policy declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkPolicyArtifact {
    /// Stable declaration identity referenced by effects.
    pub id: FaultObjectId,
    /// Exact policy semantic version.
    pub semantic_version: u16,
    /// Closed typed policy payload.
    pub artifact: NetworkPolicyArtifactKind,
}

impl WorldNetworkPolicyArtifact {
    pub(super) fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        if self.semantic_version != 1 {
            return Err(invalid("network policy semantic version"));
        }
        match &self.artifact {
            NetworkPolicyArtifactKind::IntegerLookup(table) => validate_integer_table(table),
            NetworkPolicyArtifactKind::ErrorStateTable {
                good,
                bad,
                initial,
                states,
            } => {
                hard_policy_count(states.len(), "network error states")?;
                require(states.len() == 2, "network error states")?;
                require(good != bad, "network error good/bad states")?;
                require(
                    states.iter().any(|state| &state.state == initial),
                    "network error initial state",
                )?;
                require(
                    states.iter().any(|state| &state.state == good)
                        && states.iter().any(|state| &state.state == bad),
                    "network error good/bad states",
                )?;
                require_unique(
                    states.iter().map(|state| &state.state),
                    "network error state",
                )?;
                require(
                    states.iter().all(|state| {
                        (state.corruption.get() == 0) == state.corruption_transform.is_none()
                    }),
                    "network error-state corruption transform",
                )
            }
            NetworkPolicyArtifactKind::QueueDiscipline(parameters) => {
                hard_policy_count(parameters.classes.len(), "network queue classes")?;
                require_unique(
                    parameters.classes.iter().map(|class| &class.class),
                    "network queue class",
                )?;
                let red_all = parameters.red_minimum_bytes.is_some()
                    && parameters.red_maximum_bytes.is_some()
                    && parameters.red_maximum_probability.is_some()
                    && parameters.red_weight_numerator.is_some()
                    && parameters.red_weight_denominator.is_some();
                let red_none = parameters.red_minimum_bytes.is_none()
                    && parameters.red_maximum_bytes.is_none()
                    && parameters.red_maximum_probability.is_none()
                    && parameters.red_weight_numerator.is_none()
                    && parameters.red_weight_denominator.is_none();
                require(red_all || red_none, "network RED parameters")?;
                if let (Some(minimum), Some(maximum)) =
                    (parameters.red_minimum_bytes, parameters.red_maximum_bytes)
                {
                    require(minimum < maximum, "network RED thresholds")?;
                }
                if let (Some(numerator), Some(denominator)) = (
                    parameters.red_weight_numerator,
                    parameters.red_weight_denominator,
                ) {
                    require(
                        numerator.get() <= denominator.get(),
                        "network RED EWMA weight",
                    )?;
                }
                Ok(())
            }
            NetworkPolicyArtifactKind::ByteTemplate { bytes }
            | NetworkPolicyArtifactKind::ControlResult { bytes, .. } => require(
                bytes.len() <= HARD_NETWORK_POLICY_BYTES,
                "network policy bytes",
            ),
            NetworkPolicyArtifactKind::PacketSelector { matches } => {
                hard_policy_count(matches.len(), "network packet selector")?;
                require(!matches.is_empty(), "network packet selector")?;
                for predicate in matches {
                    require(
                        !predicate.value.is_empty()
                            && predicate.value.len() == predicate.mask.len()
                            && predicate.value.len() <= HARD_NETWORK_POLICY_BYTES,
                        "network packet selector predicate",
                    )?;
                }
                Ok(())
            }
            NetworkPolicyArtifactKind::StateMachine {
                initial,
                states,
                transitions,
            } => {
                hard_policy_count(states.len(), "network policy states")?;
                hard_policy_count(transitions.len(), "network policy transitions")?;
                require(!states.is_empty(), "network policy states")?;
                require_unique(states.iter(), "network policy state")?;
                require(states.contains(initial), "network policy initial state")?;
                for transition in transitions {
                    require(
                        states.contains(&transition.from) && states.contains(&transition.to),
                        "network policy transition state",
                    )?;
                }
                let mut keys = transitions
                    .iter()
                    .map(|transition| (&transition.from, &transition.event))
                    .collect::<Vec<_>>();
                keys.sort();
                require(
                    !keys.windows(2).any(|pair| pair[0] == pair[1]),
                    "network policy transition key",
                )
            }
            NetworkPolicyArtifactKind::ServiceCurve { segments } => {
                hard_policy_count(segments.as_slice().len(), "network service curve")
            }
            NetworkPolicyArtifactKind::MediumAccess(policy) => require(
                policy.maximum_backoff_exponent <= 63
                    && policy.duty_cycle_numerator.get() <= policy.duty_cycle_denominator.get(),
                "network medium access policy",
            ),
            NetworkPolicyArtifactKind::RfChannel(channel) => {
                validate_integer_table(&channel.path_gain)?;
                validate_integer_table(&channel.antenna_gain)?;
                hard_policy_count(channel.profiles.len(), "network RF profiles")?;
                require(!channel.profiles.is_empty(), "network RF profiles")?;
                require(
                    channel
                        .profiles
                        .windows(2)
                        .all(|pair| pair[0].minimum_sinr < pair[1].minimum_sinr),
                    "network RF profile order",
                )
            }
            NetworkPolicyArtifactKind::Association(policy) => {
                hard_policy_count(policy.candidates.len(), "network association candidates")?;
                require(
                    !policy.candidates.is_empty(),
                    "network association candidates",
                )?;
                require_unique(
                    policy
                        .candidates
                        .iter()
                        .map(|candidate| &candidate.candidate),
                    "network association candidate",
                )?;
                for candidate in &policy.candidates {
                    validate_integer_table(&candidate.score)?;
                }
                Ok(())
            }
            NetworkPolicyArtifactKind::Overflow {
                disposition,
                timeout_nanos,
            } => require(
                matches!(disposition, NetworkPolicyOverflow::Timeout) == timeout_nanos.is_some(),
                "network overflow timeout",
            ),
            NetworkPolicyArtifactKind::ContactPlan { intervals } => {
                hard_policy_count(intervals.len(), "network contact intervals")?;
                require(!intervals.is_empty(), "network contact intervals")?;
                require(
                    intervals
                        .iter()
                        .all(|interval| interval.start_nanos < interval.end_nanos)
                        && intervals
                            .windows(2)
                            .all(|pair| pair[0].end_nanos <= pair[1].start_nanos),
                    "network contact interval order",
                )
            }
        }
    }
}

fn validate_integer_table(
    table: &NetworkPolicyIntegerTable,
) -> Result<(), WorldFaultTopologyError> {
    hard_policy_count(table.points.len(), "network integer lookup")?;
    require(!table.points.is_empty(), "network integer lookup")?;
    require(
        table
            .points
            .windows(2)
            .all(|pair| pair[0].input < pair[1].input),
        "network integer lookup order",
    )
}

fn hard_policy_count(actual: usize, field: &'static str) -> Result<(), WorldFaultTopologyError> {
    require(actual <= HARD_NETWORK_POLICY_ENTRIES, field)
}

fn require_unique<'a, T: Ord + 'a>(
    values: impl IntoIterator<Item = &'a T>,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    require(!values.windows(2).any(|pair| pair[0] == pair[1]), field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test policy ID must be valid: {error}"))
    }

    fn positive(value: u64) -> PositiveU64 {
        PositiveU64::new("test", value)
            .unwrap_or_else(|error| panic!("test positive integer must be valid: {error}"))
    }

    #[test]
    fn integer_tables_reject_unsorted_and_duplicate_inputs() {
        let declaration = WorldNetworkPolicyArtifact {
            id: id("delay-table"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::IntegerLookup(NetworkPolicyIntegerTable {
                input_unit: id("distance-mm"),
                output_unit: id("delay-nanos"),
                interpolation: NetworkPolicyInterpolation::Step,
                outside: NetworkPolicyOutsideRange::Clamp,
                points: vec![
                    NetworkPolicyIntegerPoint {
                        input: 10,
                        output: 100,
                    },
                    NetworkPolicyIntegerPoint {
                        input: 10,
                        output: 101,
                    },
                ],
            }),
        };
        assert!(declaration.validate().is_err());
    }

    #[test]
    fn state_machines_reject_ambiguous_event_edges() {
        let edge = NetworkPolicyTransition {
            from: id("down"),
            event: id("recover"),
            to: id("up"),
            delay_nanos: 10,
            traffic_policy: NetworkInFlightPolicy::Drop,
        };
        let declaration = WorldNetworkPolicyArtifact {
            id: id("link-machine"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::StateMachine {
                initial: id("down"),
                states: vec![id("down"), id("up")],
                transitions: vec![edge.clone(), edge],
            },
        };
        assert!(declaration.validate().is_err());
    }

    #[test]
    fn medium_policy_requires_a_real_duty_cycle() {
        let declaration = WorldNetworkPolicyArtifact {
            id: id("radio-access"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::MediumAccess(NetworkPolicyMediumAccess {
                arbitration: NetworkPolicyArbitration::Contention,
                collision: NetworkPolicyCollision::Capture,
                capture_threshold: 6,
                backoff_slot_nanos: positive(1_000),
                maximum_backoff_exponent: 10,
                maximum_retries: 8,
                duty_cycle_numerator: positive(2),
                duty_cycle_denominator: positive(1),
            }),
        };
        assert!(declaration.validate().is_err());
    }
}
