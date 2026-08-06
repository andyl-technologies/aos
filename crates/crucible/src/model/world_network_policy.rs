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
    /// The strongest canonical transmission wins when it meets the capture ratio.
    Capture,
    /// A collision is delivered only through the declared undetected transform.
    UndetectedTransform,
}

/// Complete contention, collision, retry, and capture parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyContention {
    /// Terminal receiver behavior when the retry budget is exhausted.
    pub collision: NetworkPolicyCollision,
    /// Positive capture ratio in millionths, present only for capture.
    pub capture_threshold_millionths: Option<PositiveU64>,
    /// Nonempty XOR template used only for undetected collision delivery.
    pub undetected_transform: Option<FaultObjectId>,
    /// Positive base backoff slot duration.
    pub backoff_slot_nanos: PositiveU64,
    /// Maximum binary-backoff exponent.
    pub maximum_backoff_exponent: u8,
    /// Maximum retry count.
    pub maximum_retries: u16,
}

/// Complete shared-medium access parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyMediumAccess {
    /// Arbitration rule.
    pub arbitration: NetworkPolicyArbitration,
    /// Packet-key artifact used by strict-priority or CAN arbitration.
    pub arbitration_key: Option<FaultObjectId>,
    /// Positive slot width used only by fixed-slot arbitration.
    pub fixed_slot_nanos: Option<PositiveU64>,
    /// Contention parameters, present only for contention arbitration.
    pub contention: Option<NetworkPolicyContention>,
    /// Duty-cycle numerator.
    pub duty_cycle_numerator: PositiveU64,
    /// Duty-cycle denominator.
    pub duty_cycle_denominator: PositiveU64,
}

/// Receiver treatment when an RF transfer profile samples corruption.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NetworkPolicyRfCorruption {
    /// Corrects the frame without a retry or payload change.
    Corrected,
    /// Detects the error and retries or drops at retry exhaustion.
    Detected,
    /// Delivers an undetected XOR corruption from a byte-template artifact.
    Undetected {
        /// Nonempty byte-template artifact repeated across the frame.
        transform: FaultObjectId,
    },
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
    /// Receiver treatment when corruption fires.
    pub corruption_action: NetworkPolicyRfCorruption,
    /// Maximum retries after the first transmission, in `0..=256`.
    pub maximum_retries: u16,
    /// Delay for every consumed retry.
    pub retry_delay_nanos: u64,
}

/// Integer-only RF propagation policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyRfPropagation {
    /// Distance-to-path-gain ratio in millionths.
    pub path_gain_ratio: NetworkPolicyIntegerTable,
    /// Orientation-to-antenna-gain ratio in millionths.
    pub antenna_gain_ratio: NetworkPolicyIntegerTable,
    /// Spatial quantization cell in millimetres.
    pub spatial_cell_mm: PositiveU64,
    /// Fading time bucket in virtual nanoseconds.
    pub fading_bucket_nanos: PositiveU64,
}

/// Integer-only SINR transfer policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyRfTransfer {
    /// Ordered SINR-millionths-to-link-profile table.
    pub profiles: Vec<NetworkPolicyRfProfile>,
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
    /// Source endpoint for the directed contact.
    pub source: FaultObjectId,
    /// Destination endpoint for the directed contact.
    pub destination: FaultObjectId,
    /// Beam used during this interval.
    pub beam: FaultObjectId,
    /// Gateway used during this interval.
    pub gateway: FaultObjectId,
    /// Minimum modeled range in millimetres during the interval.
    pub minimum_range_mm: u64,
    /// Maximum modeled range in millimetres during the interval.
    pub maximum_range_mm: u64,
    /// Piecewise service curve available during the contact.
    pub capacity_profile: FaultObjectId,
    /// Acquisition duration beginning at `start_nanos`.
    pub acquisition_nanos: u64,
    /// Teardown duration ending at `end_nanos`.
    pub teardown_nanos: u64,
    /// Confidence assigned to this normalized contact record.
    pub confidence: ProbabilityMillionths,
    /// Stable provenance identity for the imported or authored record.
    pub provenance: FaultObjectId,
}

/// One recipient in a versioned broadcast or multicast membership.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyRecipient {
    /// Stable recipient identity.
    pub member: FaultObjectId,
    /// Membership-owned monotone join sequence used by oldest/newest selection.
    pub joined_sequence: u64,
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

/// Header fields and modeled delay for one generated reverse-path response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyResponseHeaders {
    /// Optional source MAC; absence uses the rejected frame's destination MAC.
    pub source_mac: Option<[u8; 6]>,
    /// Optional IPv4 source; absence uses the rejected packet's destination.
    pub source_ipv4: Option<[u8; 4]>,
    /// Optional IPv6 source; absence uses the rejected packet's destination.
    pub source_ipv6: Option<[u8; 16]>,
    /// Positive IPv4 TTL or IPv6 hop limit.
    pub hop_limit: u8,
    /// Deterministic identification used by generated IPv4 packets.
    pub ipv4_identification: u16,
    /// Additional virtual delay before the response enters its reverse route.
    pub delay_nanos: Option<PositiveU64>,
}

/// Closed protocol response generated for a modeled network rejection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NetworkPolicyTypedResponseKind {
    /// ICMPv4 Destination Unreachable, excluding Packet Too Big code 4.
    Icmpv4DestinationUnreachable {
        /// ICMP code in `0..=15`, other than 4.
        code: u8,
        /// Maximum request payload bytes quoted after its complete IPv4 header.
        quote_payload_bytes: u16,
    },
    /// ICMPv4 Packet Too Big.
    Icmpv4PacketTooBig {
        /// Maximum request payload bytes quoted after its complete IPv4 header.
        quote_payload_bytes: u16,
        /// Next-hop IPv4 MTU placed in the ICMP header.
        next_hop_mtu: u16,
    },
    /// ICMPv4 Time Exceeded.
    Icmpv4TimeExceeded {
        /// ICMP code, 0 for TTL or 1 for fragment reassembly.
        code: u8,
        /// Maximum request payload bytes quoted after its complete IPv4 header.
        quote_payload_bytes: u16,
    },
    /// ICMPv6 Destination Unreachable.
    Icmpv6DestinationUnreachable {
        /// ICMPv6 code in `0..=7`.
        code: u8,
        /// Maximum request payload bytes quoted after its base IPv6 header.
        quote_payload_bytes: u16,
    },
    /// ICMPv6 Packet Too Big.
    Icmpv6PacketTooBig {
        /// Maximum request payload bytes quoted after its base IPv6 header.
        quote_payload_bytes: u16,
        /// Next-hop IPv6 MTU, at least 1280 bytes.
        next_hop_mtu: u32,
    },
    /// TCP reset for an unfragmented IPv4 or IPv6 TCP segment.
    TcpReset,
    /// Exact complete Ethernet response frame.
    OpaqueEthernet {
        /// Complete frame bytes bounded at world admission.
        bytes: Vec<u8>,
    },
}

/// Complete response artifact referenced by MTU, firewall, or queue effects.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyTypedResponse {
    /// Packet family and family-specific parameters.
    pub response: NetworkPolicyTypedResponseKind,
    /// Source addressing, IP header values, and virtual delay.
    pub headers: NetworkPolicyResponseHeaders,
}

/// Disposition when no response variant matches the rejected frame protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyUnmatchedResponse {
    /// Suppresses the response while preserving the modeled forward rejection.
    Suppress,
    /// Fails the scheduler closed with a typed boundary error.
    FailClosed,
}

/// Ordered dual-stack response alternatives with explicit unmatched behavior.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyTypedResponseSet {
    /// Nonempty alternatives evaluated in declaration order.
    pub responses: Vec<NetworkPolicyTypedResponse>,
    /// Disposition when every alternative reports a protocol mismatch.
    pub unmatched: NetworkPolicyUnmatchedResponse,
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
    /// Ordered byte ranges forming a stable packet/flow key.
    PacketKey,
    /// Exhaustive state machine.
    StateMachine,
    /// Piecewise service curve.
    ServiceCurve,
    /// Shared-medium access configuration.
    MediumAccess,
    /// RF propagation and antenna-gain configuration.
    RfPropagation,
    /// RF SINR transfer configuration.
    RfTransfer,
    /// Association/handoff configuration.
    Association,
    /// Typed control result.
    ControlResult,
    /// Generated reverse-path packet response.
    TypedResponse,
    /// Overflow/expiry configuration.
    Overflow,
    /// Ordered intermittent-contact plan.
    ContactPlan,
    /// Versioned broadcast or multicast recipient membership.
    RecipientMembership,
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
            Self::PacketKey => "packet_key",
            Self::StateMachine => "state_machine",
            Self::ServiceCurve => "service_curve",
            Self::MediumAccess => "medium_access",
            Self::RfPropagation => "rf_propagation",
            Self::RfTransfer => "rf_transfer",
            Self::Association => "association",
            Self::ControlResult => "control_result",
            Self::TypedResponse => "typed_response",
            Self::Overflow => "overflow",
            Self::ContactPlan => "contact_plan",
            Self::RecipientMembership => "recipient_membership",
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
    /// Ordered non-overlapping byte ranges concatenated into a packet key.
    PacketKey {
        /// Canonical ranges in strictly increasing offset order.
        ranges: Vec<ByteRange>,
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
    /// Integer RF propagation and antenna-gain tables.
    RfPropagation(NetworkPolicyRfPropagation),
    /// Integer RF SINR transfer table.
    RfTransfer(NetworkPolicyRfTransfer),
    /// Association, authentication, and handoff policy.
    Association(NetworkPolicyAssociation),
    /// Typed operation-result replacement.
    ControlResult {
        /// Stable result schema identity.
        schema: FaultObjectId,
        /// Canonical encoded result bytes.
        bytes: Vec<u8>,
    },
    /// Generated reverse-path packet response.
    TypedResponse(NetworkPolicyTypedResponseSet),
    /// Queue-overflow or expiry policy.
    Overflow {
        /// Overflow disposition.
        disposition: NetworkPolicyOverflow,
        /// Optional modeled timeout.
        timeout_nanos: Option<PositiveU64>,
        /// Typed control result returned only by `typed_error`.
        typed_error: Option<FaultObjectId>,
    },
    /// Ordered intermittent-contact intervals.
    ContactPlan {
        /// Strictly ordered, non-overlapping contact intervals.
        intervals: Vec<NetworkPolicyContactInterval>,
    },
    /// Canonical candidate set for one broadcast or multicast membership version.
    RecipientMembership {
        /// Nonempty records in canonical recipient-identity order.
        members: Vec<NetworkPolicyRecipient>,
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
            Self::PacketKey { .. } => NetworkPolicyArtifactClass::PacketKey,
            Self::StateMachine { .. } => NetworkPolicyArtifactClass::StateMachine,
            Self::ServiceCurve { .. } => NetworkPolicyArtifactClass::ServiceCurve,
            Self::MediumAccess(_) => NetworkPolicyArtifactClass::MediumAccess,
            Self::RfPropagation(_) => NetworkPolicyArtifactClass::RfPropagation,
            Self::RfTransfer(_) => NetworkPolicyArtifactClass::RfTransfer,
            Self::Association(_) => NetworkPolicyArtifactClass::Association,
            Self::ControlResult { .. } => NetworkPolicyArtifactClass::ControlResult,
            Self::TypedResponse(_) => NetworkPolicyArtifactClass::TypedResponse,
            Self::Overflow { .. } => NetworkPolicyArtifactClass::Overflow,
            Self::ContactPlan { .. } => NetworkPolicyArtifactClass::ContactPlan,
            Self::RecipientMembership { .. } => NetworkPolicyArtifactClass::RecipientMembership,
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
            NetworkPolicyArtifactKind::TypedResponse(responses) => {
                hard_policy_count(responses.responses.len(), "typed network responses")?;
                require(!responses.responses.is_empty(), "typed network responses")?;
                for (index, response) in responses.responses.iter().enumerate() {
                    validate_typed_response(response)?;
                    if matches!(
                        response.response,
                        NetworkPolicyTypedResponseKind::OpaqueEthernet { .. }
                    ) {
                        require(
                            index + 1 == responses.responses.len(),
                            "opaque network response ordering",
                        )?;
                    }
                }
                Ok(())
            }
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
            NetworkPolicyArtifactKind::PacketKey { ranges } => {
                hard_policy_count(ranges.len(), "network packet key ranges")?;
                require(!ranges.is_empty(), "network packet key ranges")?;
                let mut prior_end = 0_u64;
                let mut total = 0_u64;
                for (index, range) in ranges.iter().copied().enumerate() {
                    require(
                        index == 0 || range.start() >= prior_end,
                        "network packet key order",
                    )?;
                    prior_end = range.end();
                    total = total
                        .checked_add(range.length())
                        .ok_or_else(|| invalid("network packet key bytes"))?;
                }
                require(
                    total <= u64::try_from(HARD_NETWORK_POLICY_BYTES).unwrap_or(u64::MAX),
                    "network packet key bytes",
                )
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
                policy.arbitration_key.is_some()
                    == matches!(
                        policy.arbitration,
                        NetworkPolicyArbitration::StrictPriority
                            | NetworkPolicyArbitration::CanDominantBit
                    )
                    && policy.fixed_slot_nanos.is_some()
                        == matches!(policy.arbitration, NetworkPolicyArbitration::FixedSlots)
                    && policy.contention.is_some()
                        == matches!(policy.arbitration, NetworkPolicyArbitration::Contention)
                    && policy.contention.as_ref().is_none_or(|contention| {
                        contention.maximum_backoff_exponent <= 63
                            && contention.maximum_retries <= 256
                            && contention.capture_threshold_millionths.is_some()
                                == matches!(contention.collision, NetworkPolicyCollision::Capture)
                            && contention.undetected_transform.is_some()
                                == matches!(
                                    contention.collision,
                                    NetworkPolicyCollision::UndetectedTransform
                                )
                    })
                    && policy.duty_cycle_numerator.get() <= policy.duty_cycle_denominator.get(),
                "network medium access policy",
            ),
            NetworkPolicyArtifactKind::RfPropagation(channel) => {
                validate_integer_table(&channel.path_gain_ratio)?;
                validate_integer_table(&channel.antenna_gain_ratio)?;
                require(
                    channel.path_gain_ratio.input_unit.as_str() == "millimetres"
                        && channel.antenna_gain_ratio.input_unit.as_str() == "millidegrees"
                        && channel.path_gain_ratio.output_unit.as_str() == "ratio-millionths"
                        && channel.antenna_gain_ratio.output_unit.as_str() == "ratio-millionths"
                        && channel
                            .path_gain_ratio
                            .points
                            .iter()
                            .all(|point| point.output >= 0)
                        && channel
                            .antenna_gain_ratio
                            .points
                            .iter()
                            .all(|point| point.output >= 0),
                    "network RF propagation units and ratios",
                )
            }
            NetworkPolicyArtifactKind::RfTransfer(transfer) => {
                hard_policy_count(transfer.profiles.len(), "network RF profiles")?;
                require(!transfer.profiles.is_empty(), "network RF profiles")?;
                require(
                    transfer
                        .profiles
                        .windows(2)
                        .all(|pair| pair[0].minimum_sinr < pair[1].minimum_sinr),
                    "network RF profile order",
                )?;
                require(
                    transfer
                        .profiles
                        .iter()
                        .all(|profile| profile.maximum_retries <= 256),
                    "network RF retry limit",
                )
            }
            NetworkPolicyArtifactKind::Association(policy) => {
                hard_policy_count(policy.candidates.len(), "network association candidates")?;
                require(
                    !policy.candidates.is_empty(),
                    "network association candidates",
                )?;
                require(
                    policy
                        .candidates
                        .windows(2)
                        .all(|pair| pair[0].candidate < pair[1].candidate),
                    "network association candidate order",
                )?;
                for candidate in &policy.candidates {
                    validate_integer_table(&candidate.score)?;
                }
                Ok(())
            }
            NetworkPolicyArtifactKind::Overflow {
                disposition,
                timeout_nanos,
                typed_error,
            } => {
                require(
                    matches!(disposition, NetworkPolicyOverflow::Timeout)
                        == timeout_nanos.is_some(),
                    "network overflow timeout",
                )?;
                require(
                    matches!(disposition, NetworkPolicyOverflow::TypedError)
                        == typed_error.is_some(),
                    "network overflow typed error",
                )
            }
            NetworkPolicyArtifactKind::ContactPlan { intervals } => {
                hard_policy_count(intervals.len(), "network contact intervals")?;
                require(!intervals.is_empty(), "network contact intervals")?;
                require(
                    intervals.iter().all(|interval| {
                        interval.start_nanos < interval.end_nanos
                            && interval.source != interval.destination
                            && interval.minimum_range_mm <= interval.maximum_range_mm
                            && interval
                                .acquisition_nanos
                                .checked_add(interval.teardown_nanos)
                                .is_some_and(|transition| {
                                    transition <= interval.end_nanos - interval.start_nanos
                                })
                    }) && intervals
                        .windows(2)
                        .all(|pair| pair[0].end_nanos <= pair[1].start_nanos),
                    "network contact interval order",
                )
            }
            NetworkPolicyArtifactKind::RecipientMembership { members } => {
                hard_policy_count(members.len(), "network recipient membership")?;
                require(!members.is_empty(), "network recipient membership")?;
                require(
                    members
                        .windows(2)
                        .all(|pair| pair[0].member < pair[1].member),
                    "network recipient membership order",
                )
            }
        }
    }
}

fn validate_typed_response(
    response: &NetworkPolicyTypedResponse,
) -> Result<(), WorldFaultTopologyError> {
    let headers = &response.headers;
    match &response.response {
        NetworkPolicyTypedResponseKind::Icmpv4DestinationUnreachable { code, .. } => {
            require(headers.hop_limit > 0, "network response hop limit")?;
            require(headers.source_ipv6.is_none(), "IPv4 response IPv6 source")?;
            require(*code <= 15 && *code != 4, "ICMPv4 unreachable code")
        }
        NetworkPolicyTypedResponseKind::Icmpv4PacketTooBig { next_hop_mtu, .. } => {
            require(headers.hop_limit > 0, "network response hop limit")?;
            require(headers.source_ipv6.is_none(), "IPv4 response IPv6 source")?;
            require(*next_hop_mtu >= 68, "ICMPv4 next-hop MTU")
        }
        NetworkPolicyTypedResponseKind::Icmpv4TimeExceeded { code, .. } => {
            require(headers.hop_limit > 0, "network response hop limit")?;
            require(headers.source_ipv6.is_none(), "IPv4 response IPv6 source")?;
            require(*code <= 1, "ICMPv4 time-exceeded code")
        }
        NetworkPolicyTypedResponseKind::Icmpv6DestinationUnreachable { code, .. } => {
            require(headers.hop_limit > 0, "network response hop limit")?;
            require(headers.source_ipv4.is_none(), "IPv6 response IPv4 source")?;
            require(
                headers.ipv4_identification == 0,
                "IPv6 response IPv4 identification",
            )?;
            require(*code <= 7, "ICMPv6 unreachable code")
        }
        NetworkPolicyTypedResponseKind::Icmpv6PacketTooBig { next_hop_mtu, .. } => {
            require(headers.hop_limit > 0, "network response hop limit")?;
            require(headers.source_ipv4.is_none(), "IPv6 response IPv4 source")?;
            require(
                headers.ipv4_identification == 0,
                "IPv6 response IPv4 identification",
            )?;
            require(*next_hop_mtu >= 1_280, "ICMPv6 next-hop MTU")
        }
        NetworkPolicyTypedResponseKind::TcpReset => {
            require(headers.hop_limit > 0, "network response hop limit")
        }
        NetworkPolicyTypedResponseKind::OpaqueEthernet { bytes } => {
            require(
                (14..=HARD_NETWORK_POLICY_BYTES).contains(&bytes.len()),
                "opaque network response bytes",
            )?;
            require(
                headers.source_mac.is_none()
                    && headers.source_ipv4.is_none()
                    && headers.source_ipv6.is_none()
                    && headers.hop_limit == 0
                    && headers.ipv4_identification == 0,
                "opaque network response unused headers",
            )
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
    fn overflow_policies_require_exact_timeout_and_typed_error_fields() {
        let declaration = |disposition, timeout_nanos, typed_error| WorldNetworkPolicyArtifact {
            id: id("overflow"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::Overflow {
                disposition,
                timeout_nanos,
                typed_error,
            },
        };
        declaration(NetworkPolicyOverflow::DropNewest, None, None)
            .validate()
            .unwrap_or_else(|error| panic!("drop-newest overflow policy: {error}"));
        declaration(NetworkPolicyOverflow::Timeout, Some(positive(10)), None)
            .validate()
            .unwrap_or_else(|error| panic!("timeout overflow policy: {error}"));
        declaration(
            NetworkPolicyOverflow::TypedError,
            None,
            Some(id("control-error")),
        )
        .validate()
        .unwrap_or_else(|error| panic!("typed overflow policy: {error}"));
        assert!(
            declaration(NetworkPolicyOverflow::Timeout, None, None)
                .validate()
                .is_err()
        );
        assert!(
            declaration(NetworkPolicyOverflow::TypedError, None, None,)
                .validate()
                .is_err()
        );
        assert!(
            declaration(
                NetworkPolicyOverflow::DropOldest,
                None,
                Some(id("unexpected-error")),
            )
            .validate()
            .is_err()
        );
    }

    #[test]
    fn medium_policy_requires_exact_conditional_fields_and_bounds() {
        let base = NetworkPolicyMediumAccess {
            arbitration: NetworkPolicyArbitration::Contention,
            arbitration_key: None,
            fixed_slot_nanos: None,
            contention: Some(NetworkPolicyContention {
                collision: NetworkPolicyCollision::Capture,
                capture_threshold_millionths: Some(positive(1_000_000)),
                undetected_transform: None,
                backoff_slot_nanos: positive(1_000),
                maximum_backoff_exponent: 10,
                maximum_retries: 8,
            }),
            duty_cycle_numerator: positive(1),
            duty_cycle_denominator: positive(1),
        };
        let declaration = |policy| WorldNetworkPolicyArtifact {
            id: id("radio-access"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::MediumAccess(policy),
        };
        declaration(base.clone())
            .validate()
            .unwrap_or_else(|error| panic!("complete medium policy: {error}"));

        let mut invalid = base.clone();
        invalid.duty_cycle_numerator = positive(2);
        assert!(declaration(invalid).validate().is_err());
        let mut invalid = base.clone();
        invalid
            .contention
            .as_mut()
            .unwrap_or_else(|| panic!("test contention must exist"))
            .maximum_retries = 257;
        assert!(declaration(invalid).validate().is_err());
        let mut invalid = base.clone();
        invalid.arbitration = NetworkPolicyArbitration::StrictPriority;
        assert!(declaration(invalid).validate().is_err());
        let mut invalid = base.clone();
        invalid.fixed_slot_nanos = Some(positive(10));
        assert!(declaration(invalid).validate().is_err());
        let mut invalid = base;
        let contention = invalid
            .contention
            .as_mut()
            .unwrap_or_else(|| panic!("test contention must exist"));
        contention.collision = NetworkPolicyCollision::UndetectedTransform;
        contention.capture_threshold_millionths = None;
        assert!(declaration(invalid).validate().is_err());
    }

    #[test]
    fn rf_propagation_requires_canonical_linear_ratio_units() {
        let table = |input_unit: &str, output: i64| NetworkPolicyIntegerTable {
            input_unit: id(input_unit),
            output_unit: id("ratio-millionths"),
            interpolation: NetworkPolicyInterpolation::Step,
            outside: NetworkPolicyOutsideRange::Clamp,
            points: vec![NetworkPolicyIntegerPoint { input: 0, output }],
        };
        let valid = WorldNetworkPolicyArtifact {
            id: id("rf-propagation"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::RfPropagation(NetworkPolicyRfPropagation {
                path_gain_ratio: table("millimetres", 500_000),
                antenna_gain_ratio: table("millidegrees", 1_000_000),
                spatial_cell_mm: positive(1),
                fading_bucket_nanos: positive(1),
            }),
        };
        valid
            .validate()
            .unwrap_or_else(|error| panic!("canonical RF propagation: {error}"));

        let invalid = WorldNetworkPolicyArtifact {
            id: id("rf-logarithmic-propagation"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::RfPropagation(NetworkPolicyRfPropagation {
                path_gain_ratio: table("millimetres", -3_000),
                antenna_gain_ratio: table("millidegrees", 1_000_000),
                spatial_cell_mm: positive(1),
                fading_bucket_nanos: positive(1),
            }),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rf_transfer_requires_strictly_ordered_sinr_thresholds() {
        let probability = ProbabilityMillionths::new(0)
            .unwrap_or_else(|error| panic!("zero probability: {error}"));
        let profile = |minimum_sinr| NetworkPolicyRfProfile {
            minimum_sinr,
            rate_bps: positive(1),
            loss: probability,
            corruption: probability,
            corruption_action: NetworkPolicyRfCorruption::Corrected,
            maximum_retries: 0,
            retry_delay_nanos: 0,
        };
        let declaration = WorldNetworkPolicyArtifact {
            id: id("rf-transfer"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::RfTransfer(NetworkPolicyRfTransfer {
                profiles: vec![profile(10), profile(10)],
            }),
        };
        assert!(declaration.validate().is_err());
    }

    #[test]
    fn contact_intervals_validate_complete_directed_records() {
        let interval = NetworkPolicyContactInterval {
            start_nanos: 100,
            end_nanos: 200,
            source: id("satellite"),
            destination: id("ground-station"),
            beam: id("beam-a"),
            gateway: id("gateway-a"),
            minimum_range_mm: 10_000,
            maximum_range_mm: 20_000,
            capacity_profile: id("contact-capacity"),
            acquisition_nanos: 10,
            teardown_nanos: 20,
            confidence: ProbabilityMillionths::new(900_000)
                .unwrap_or_else(|error| panic!("test confidence should be valid: {error}")),
            provenance: id("normalized-contact-trace"),
        };
        let valid = WorldNetworkPolicyArtifact {
            id: id("contact-plan"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::ContactPlan {
                intervals: vec![interval.clone()],
            },
        };
        assert!(valid.validate().is_ok());

        let mut invalid_interval = interval;
        invalid_interval.acquisition_nanos = 90;
        invalid_interval.teardown_nanos = 20;
        let invalid = WorldNetworkPolicyArtifact {
            id: id("invalid-contact-plan"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::ContactPlan {
                intervals: vec![invalid_interval],
            },
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn recipient_membership_requires_canonical_unique_identity_order() {
        let mut declaration = WorldNetworkPolicyArtifact {
            id: id("multicast-members-v1"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::RecipientMembership {
                members: vec![
                    NetworkPolicyRecipient {
                        member: id("receiver-a"),
                        joined_sequence: 2,
                    },
                    NetworkPolicyRecipient {
                        member: id("receiver-b"),
                        joined_sequence: 1,
                    },
                ],
            },
        };
        declaration
            .validate()
            .unwrap_or_else(|error| panic!("canonical membership: {error}"));

        if let NetworkPolicyArtifactKind::RecipientMembership { members } =
            &mut declaration.artifact
        {
            members.swap(0, 1);
        }
        assert!(declaration.validate().is_err());
    }

    #[test]
    fn typed_responses_admit_dual_stack_and_reject_ambiguous_fallbacks() {
        let headers = |ipv4| NetworkPolicyResponseHeaders {
            source_mac: None,
            source_ipv4: None,
            source_ipv6: None,
            hop_limit: 64,
            ipv4_identification: if ipv4 { 7 } else { 0 },
            delay_nanos: Some(positive(10)),
        };
        let ipv4 = NetworkPolicyTypedResponse {
            response: NetworkPolicyTypedResponseKind::Icmpv4PacketTooBig {
                quote_payload_bytes: 64,
                next_hop_mtu: 1_400,
            },
            headers: headers(true),
        };
        let ipv6 = NetworkPolicyTypedResponse {
            response: NetworkPolicyTypedResponseKind::Icmpv6PacketTooBig {
                quote_payload_bytes: 64,
                next_hop_mtu: 1_280,
            },
            headers: headers(false),
        };
        let mut declaration = WorldNetworkPolicyArtifact {
            id: id("dual-stack-too-big"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::TypedResponse(NetworkPolicyTypedResponseSet {
                responses: vec![ipv4.clone(), ipv6],
                unmatched: NetworkPolicyUnmatchedResponse::Suppress,
            }),
        };
        declaration
            .validate()
            .unwrap_or_else(|error| panic!("dual-stack response: {error}"));

        let opaque = NetworkPolicyTypedResponse {
            response: NetworkPolicyTypedResponseKind::OpaqueEthernet { bytes: vec![0; 14] },
            headers: NetworkPolicyResponseHeaders {
                source_mac: None,
                source_ipv4: None,
                source_ipv6: None,
                hop_limit: 0,
                ipv4_identification: 0,
                delay_nanos: None,
            },
        };
        declaration.artifact =
            NetworkPolicyArtifactKind::TypedResponse(NetworkPolicyTypedResponseSet {
                responses: vec![opaque, ipv4],
                unmatched: NetworkPolicyUnmatchedResponse::FailClosed,
            });
        assert!(declaration.validate().is_err());
    }

    #[test]
    fn packet_keys_require_canonical_nonoverlapping_ranges() {
        let range = |start, length| {
            ByteRange::new(start, length)
                .unwrap_or_else(|error| panic!("test packet-key range: {error}"))
        };
        let mut declaration = WorldNetworkPolicyArtifact {
            id: id("five-tuple"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::PacketKey {
                ranges: vec![range(12, 8), range(20, 4)],
            },
        };
        declaration
            .validate()
            .unwrap_or_else(|error| panic!("canonical packet key: {error}"));
        declaration.artifact = NetworkPolicyArtifactKind::PacketKey {
            ranges: vec![range(12, 8), range(19, 4)],
        };
        assert!(declaration.validate().is_err());
    }
}
