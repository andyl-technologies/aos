//! Closed parameter schemas for every executable network effect.
//!
//! Complex technology behavior is referenced through validated world-object or
//! lookup-artifact identities. Such references do not permit arbitrary runtime
//! code: their schemas and semantic versions are admitted separately by the
//! network world registry.

use super::{
    BoundedCount, EffectKind, FaultContractError, FaultObjectId, ObjectIdSet, OperationSet,
    PositiveU64, ProbabilityMillionths,
};

/// Availability visible in one or both network directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAvailabilityState {
    /// Both directions accept traffic.
    Up,
    /// Neither direction accepts traffic.
    Down,
    /// Only receive traffic is accepted.
    ReceiveOnly,
    /// Only transmit traffic is accepted.
    TransmitOnly,
}

/// Treatment of operations already admitted when network state changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkInFlightPolicy {
    /// Complete under the profile captured at admission.
    Preserve,
    /// Re-resolve at the next declared adapter phase.
    Reevaluate,
    /// Drop at the state transition.
    Drop,
    /// Return the effect-specific typed error.
    TypedError,
}

/// Negotiated duplex mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDuplex {
    /// Only one direction may transmit at a time.
    Half,
    /// Both directions may transmit concurrently.
    Full,
}

/// Negotiated forward-error-correction mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFecMode {
    /// Forward error correction is disabled.
    None,
    /// Reed-Solomon forward error correction is enabled.
    ReedSolomon,
    /// Low-density parity-check correction is enabled.
    Ldpc,
    /// Convolutional correction is enabled.
    Convolutional,
}

/// Integer-only distribution used for keyed jitter and selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDistribution {
    /// Every integer value in the range is equiprobable.
    Uniform,
    /// A committed integer lookup artifact supplies a normal-like distribution.
    NormalLookup,
    /// A committed integer lookup artifact supplies an exponential distribution.
    ExponentialLookup,
}

/// One time-varying service-curve segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkServiceSegment {
    /// Segment start relative to effect activation.
    pub at_nanos: u64,
    /// Positive service rate in bits per virtual second.
    pub rate_bps: PositiveU64,
}

/// A canonical piecewise-constant service curve.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct NetworkServiceSegments(Vec<NetworkServiceSegment>);

impl NetworkServiceSegments {
    /// Validates an ordered curve beginning at time zero.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::EmptyCollection`] for no segments or
    /// [`FaultContractError::InvalidServiceCurve`] for a nonzero first point or
    /// non-increasing coordinates.
    pub fn new(segments: Vec<NetworkServiceSegment>) -> Result<Self, FaultContractError> {
        if segments.is_empty() {
            return Err(FaultContractError::EmptyCollection { field: "segments" });
        }
        if segments[0].at_nanos != 0
            || segments
                .windows(2)
                .any(|pair| pair[0].at_nanos >= pair[1].at_nanos)
        {
            return Err(FaultContractError::InvalidServiceCurve);
        }
        Ok(Self(segments))
    }

    /// Returns segments in semantic time order.
    #[must_use]
    pub fn as_slice(&self) -> &[NetworkServiceSegment] {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for NetworkServiceSegments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let segments =
            <Vec<NetworkServiceSegment> as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(segments).map_err(serde::de::Error::custom)
    }
}

/// A queue service discipline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkQueueDiscipline {
    /// First-in, first-out service.
    Fifo,
    /// Strict class priority with lowest numeric class first.
    StrictPriority,
    /// Weighted round-robin service.
    WeightedRoundRobin,
    /// Deficit round-robin service.
    DeficitRoundRobin,
    /// Random early detection using keyed occupancy decisions.
    Red,
}

/// A queue overflow disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkQueueOverflow {
    /// Reject the newly arriving frame.
    TailDrop,
    /// Remove the oldest queued frame.
    HeadDrop,
    /// Select a victim through a keyed canonical candidate set.
    KeyedDrop,
    /// Return a typed admission error.
    TypedError,
}

/// A deterministic bounded selection rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSelection {
    /// Select with a keyed uniform draw.
    KeyedUniform,
    /// Select the oldest eligible item.
    Oldest,
    /// Select the newest eligible item.
    Newest,
    /// Select by stable identity order.
    CanonicalOrder,
}

/// An explicit frame-loss decision when no probability is sampled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkLossDecision {
    /// Preserve the frame.
    Preserve,
    /// Drop the frame.
    Drop,
}

/// A frame payload mutation with a fully typed selector.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NetworkPayloadMutation {
    /// XORs the selected byte range with a repeated nonzero mask.
    BitFlip {
        /// First selected payload byte.
        offset_bytes: u64,
        /// Positive selected payload length.
        length_bytes: PositiveU64,
        /// Nonzero XOR mask byte.
        mask: u8,
    },
    /// Replaces one protocol field through a registered typed field schema.
    FieldMutation {
        /// Protocol field identity.
        field: FaultObjectId,
        /// Typed replacement-value artifact.
        replacement: FaultObjectId,
    },
    /// Truncates the payload to a declared length.
    Truncate {
        /// Resulting frame length.
        length_bytes: u64,
    },
    /// Applies a corruption transform while preserving detection fields.
    UndetectedCorruption {
        /// Registered typed corruption transform.
        transform: FaultObjectId,
    },
}

/// A receiver-detected frame error class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum DetectedFrameErrorKind {
    /// Cyclic-redundancy-check failure.
    Crc,
    /// Frame-check-sequence failure.
    Fcs,
    /// Framing failure.
    Framing,
    /// Uncorrectable forward-error-correction result.
    FecUncorrectable,
}

/// Receiver action for a detected frame error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum DetectedFrameErrorAction {
    /// Deliver corrected data and evidence.
    Corrected,
    /// Request a technology-valid retry.
    Retry,
    /// Drop the frame.
    Drop,
    /// Reset or retrain the link.
    LinkReset,
}

/// Disposition of a frame exceeding the effective MTU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkOversizeDisposition {
    /// Drop the frame.
    Drop,
    /// Fragment only when the declared technology permits fragmentation.
    Fragment,
    /// Return a typed oversize error.
    TypedError,
}

/// Protocol-aware fragmentation performed for an oversized Ethernet frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFragmentationProtocol {
    /// Fragments an Ethernet-carried IPv4 datagram and repairs its header checksum.
    EthernetIpv4,
}

/// A forwarder lifecycle transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkForwarderTransition {
    /// Restart software while retaining declared hardware state.
    Restart,
    /// Reset the complete forwarding device.
    Reset,
    /// Remove power and volatile state.
    PowerLoss,
}

/// State retention at a lifecycle or association transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkStatePolicy {
    /// Retain the named state.
    Preserve,
    /// Clear the named state.
    Clear,
    /// Drain queued state before transition completion.
    Drain,
}

/// A forwarding-state mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NetworkForwardingMutationKind {
    /// Replaces the selected output port.
    WrongPort {
        /// Replacement port identity.
        replacement_port: FaultObjectId,
    },
    /// Floods to the declared recipient set.
    Flood {
        /// Replacement recipient set.
        recipients: ObjectIdSet,
    },
    /// Produces no next hop.
    Blackhole,
    /// Routes to a declared prior hop while preserving the hop budget.
    Loop {
        /// Replacement prior-hop identity.
        next_hop: FaultObjectId,
    },
    /// Changes the entry age to a declared value.
    StaleAge {
        /// Replacement age in virtual nanoseconds.
        age_nanos: u64,
    },
}

/// Firewall disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFirewallAction {
    /// Accept the operation.
    Accept,
    /// Return a typed rejection.
    Reject,
    /// Silently drop the operation.
    Drop,
}

/// Stateful logical network-function family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkConnectionKind {
    /// Network address translation.
    Nat,
    /// Stateful connection tracking.
    Conntrack,
    /// Stateful load balancing.
    LoadBalancer,
    /// Tunnel/session state.
    Tunnel,
    /// DNS query/cache state.
    Dns,
}

/// Mutation applied to a typed control-operation result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NetworkControlResultKind {
    /// Suppress the result.
    Drop,
    /// Return a prior version.
    Stale,
    /// Add a signed typed bias.
    Bias,
    /// Replace with a typed result artifact.
    Replace,
    /// Return a typed technology error.
    Error,
}

/// Typed parameters for every executable network effect kind.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NetworkEffectSpecification {
    /// Directional network availability.
    Availability {
        /// Requested availability state.
        state: NetworkAvailabilityState,
        /// Treatment of queued operations.
        queued_policy: NetworkInFlightPolicy,
        /// Treatment of in-flight operations.
        in_flight_policy: NetworkInFlightPolicy,
    },
    /// Link-down, training, and recovery timing.
    Flap {
        /// Time spent down.
        down_nanos: PositiveU64,
        /// Time spent training.
        training_nanos: PositiveU64,
        /// Time spent recovering after training.
        recovery_nanos: PositiveU64,
    },
    /// Negotiated link mode.
    NegotiatedMode {
        /// Positive negotiated bit rate.
        rate_bps: PositiveU64,
        /// Negotiated duplex mode.
        duplex: NetworkDuplex,
        /// Positive negotiated lane count.
        lanes: BoundedCount,
        /// Negotiated FEC mode.
        fec: NetworkFecMode,
        /// Training duration.
        training_nanos: PositiveU64,
    },
    /// Multi-component technology profile change.
    ProfileDelta {
        /// Signed latency component in virtual nanoseconds.
        latency_nanos: Option<i64>,
        /// Optional positive bit-rate cap.
        rate_cap_bps: Option<PositiveU64>,
        /// Optional registered loss-hazard signal identity.
        loss_hazard: Option<FaultObjectId>,
        /// Optional registered corruption-hazard signal identity.
        corruption_hazard: Option<FaultObjectId>,
        /// Registered technology-metric bundle, when present.
        technology_metrics: Option<FaultObjectId>,
    },
    /// Added propagation delay.
    PropagationDelay {
        /// Fixed delay, mutually exclusive with `distance_velocity_lookup`.
        delay_nanos: Option<PositiveU64>,
        /// Registered distance/velocity lookup, mutually exclusive with delay.
        distance_velocity_lookup: Option<FaultObjectId>,
    },
    /// Added access delay.
    AccessDelay {
        /// Arbitration or retry delay.
        delay_nanos: PositiveU64,
        /// Typed cause identity.
        cause: FaultObjectId,
    },
    /// Keyed jitter.
    Jitter {
        /// Maximum added jitter.
        maximum_nanos: PositiveU64,
        /// Integer-only distribution.
        distribution: NetworkDistribution,
        /// Required lookup for non-uniform distributions.
        distribution_lookup: Option<FaultObjectId>,
    },
    /// Piecewise network service curve.
    ServiceCurve {
        /// Ordered service segments.
        segments: NetworkServiceSegments,
    },
    /// Token-bucket service constraint.
    TokenBucket {
        /// Refill rate in bits per virtual second.
        rate_bps: PositiveU64,
        /// Positive bucket capacity in bits.
        burst_bits: PositiveU64,
        /// Initial tokens, no greater than the burst capacity.
        initial_bits: u64,
    },
    /// Bounded queue policy.
    QueuePolicy {
        /// Positive byte capacity.
        capacity_bytes: PositiveU64,
        /// Positive frame capacity.
        capacity_frames: BoundedCount,
        /// Service discipline.
        discipline: NetworkQueueDiscipline,
        /// Registered closed discipline parameters.
        discipline_parameters: Option<FaultObjectId>,
        /// Overflow disposition.
        overflow: NetworkQueueOverflow,
    },
    /// Per-frame loss decision.
    FrameLoss {
        /// Keyed probability, mutually exclusive with `outcome`.
        probability: Option<ProbabilityMillionths>,
        /// Explicit result, mutually exclusive with `probability`.
        outcome: Option<NetworkLossDecision>,
    },
    /// Correlated good/bad error-state process.
    BurstErrorState {
        /// Good-to-bad transition probability.
        good_to_bad: ProbabilityMillionths,
        /// Bad-to-good transition probability.
        bad_to_good: ProbabilityMillionths,
        /// Registered per-state loss/corruption table.
        state_parameters: FaultObjectId,
    },
    /// Bounded frame duplication.
    Duplicate {
        /// Keyed duplication probability.
        probability: ProbabilityMillionths,
        /// Delay between copies.
        gap_nanos: u64,
        /// Number of additional copies.
        copies: BoundedCount,
    },
    /// Bounded delivery reordering.
    Reorder {
        /// Maximum shift window.
        window_nanos: PositiveU64,
        /// Deterministic selection rule.
        selection: NetworkSelection,
    },
    /// Ordered frame payload mutation.
    PayloadTransform {
        /// Typed mutation and selector.
        mutation: NetworkPayloadMutation,
    },
    /// Receiver-detected frame error.
    DetectedFrameError {
        /// Detected error class.
        kind: DetectedFrameErrorKind,
        /// Receiver action.
        receiver_action: DetectedFrameErrorAction,
        /// Retry delay, present only for `retry`.
        retry_delay_nanos: Option<PositiveU64>,
        /// Maximum retries, present only for `retry`.
        retry_limit: Option<BoundedCount>,
        /// Retries actually consumed, present only for `retry`.
        retry_attempts: Option<BoundedCount>,
        /// Whether the last declared retry succeeds, present only for `retry`.
        retry_succeeds: Option<bool>,
        /// Link-reset/retraining duration, present only for `link_reset`.
        reset_nanos: Option<PositiveU64>,
    },
    /// Effective MTU.
    Mtu {
        /// Positive MTU in bytes.
        mtu_bytes: PositiveU64,
        /// Oversize disposition.
        oversize: NetworkOversizeDisposition,
        /// Protocol parser/encoder used only for `fragment`.
        fragmentation_protocol: Option<NetworkFragmentationProtocol>,
        /// Typed reverse-path response artifact used only for `typed_error`.
        typed_error: Option<FaultObjectId>,
    },
    /// Class-scoped pause or resume.
    PauseBackpressure {
        /// Traffic-class identity.
        class: FaultObjectId,
        /// Pause duration, or absent to pause until the contribution is removed.
        pause_nanos: Option<PositiveU64>,
    },
    /// Broadcast or multicast recipient subset.
    RecipientSubset {
        /// Membership version sampled for this opportunity.
        membership_version: FaultObjectId,
        /// Explicit dropped members, mutually exclusive with selection.
        drop_members: Option<ObjectIdSet>,
        /// Keyed selection rule, mutually exclusive with explicit members.
        selection: Option<NetworkSelection>,
        /// Number of recipients retained by a keyed selection.
        retain_count: Option<BoundedCount>,
    },
    /// Forwarder restart, reset, or power loss.
    ForwarderLifecycle {
        /// Requested transition.
        transition: NetworkForwarderTransition,
        /// Downtime before transition completion.
        downtime_nanos: PositiveU64,
        /// Queue retention policy.
        queue_policy: NetworkStatePolicy,
        /// Forwarding-table retention policy.
        table_policy: NetworkStatePolicy,
    },
    /// Forwarding-state mutation.
    ForwardingMutation {
        /// Typed lookup selector.
        selector: FaultObjectId,
        /// Typed mutation.
        mutation: NetworkForwardingMutationKind,
    },
    /// Versioned route transition.
    RouteTransition {
        /// Prior route version.
        old_route: FaultObjectId,
        /// New route version.
        new_route: FaultObjectId,
        /// Registered convergence event sequence.
        convergence_events: FaultObjectId,
        /// In-flight traffic policy.
        in_flight_policy: NetworkInFlightPolicy,
    },
    /// Shared control-plane service.
    ControlPlaneService {
        /// Service-curve identity.
        service_curve: FaultObjectId,
        /// Positive queue bound.
        queue_bound: BoundedCount,
        /// Drop or timeout policy identity.
        overflow_policy: FaultObjectId,
    },
    /// Firewall disposition and state transition.
    FirewallDisposition {
        /// Firewall action.
        action: NetworkFirewallAction,
        /// Optional typed rejection identity.
        typed_reject: Option<FaultObjectId>,
        /// Matched rule identity.
        rule: FaultObjectId,
        /// Stateful firewall table identity.
        state: FaultObjectId,
    },
    /// Stateful logical network-function transition.
    ConnectionState {
        /// Function family.
        kind: NetworkConnectionKind,
        /// Positive table bound.
        table_bound: BoundedCount,
        /// Registered transition event.
        transition: FaultObjectId,
    },
    /// Shared-medium arbitration and collision state.
    SharedMedium {
        /// Canonical participating resource set.
        resources: ObjectIdSet,
        /// Registered arbitration policy.
        arbitration: FaultObjectId,
        /// Registered collision and capture policy.
        collision_capture: FaultObjectId,
        /// Registered backoff and duty-cycle policy.
        backoff_duty_cycle: FaultObjectId,
    },
    /// RF channel calculation.
    RfChannel {
        /// Carrier frequency in hertz.
        carrier_hz: PositiveU64,
        /// Channel bandwidth in hertz.
        bandwidth_hz: PositiveU64,
        /// Transmit power in canonical integer femtowatts.
        transmit_power_femtowatts: u64,
        /// Receiver noise power in canonical integer femtowatts.
        receiver_noise_femtowatts: u64,
        /// Registered path and antenna gain-ratio bundle.
        propagation_fields: FaultObjectId,
        /// Registered SINR-to-profile transfer table.
        sinr_transfer: FaultObjectId,
    },
    /// Authentication, association, and handoff machine.
    Association {
        /// Technology contract identity.
        technology: FaultObjectId,
        /// Candidate attachment set.
        candidates: ObjectIdSet,
        /// Registered selection and hysteresis policy.
        selection_policy: FaultObjectId,
        /// Registered timer policy.
        timer_policy: FaultObjectId,
        /// Registered authentication policy.
        authentication_policy: FaultObjectId,
        /// Buffering and address-continuity policy.
        traffic_policy: FaultObjectId,
    },
    /// Typed network-control result transform.
    ControlResultTransform {
        /// Technology contract identity.
        technology: FaultObjectId,
        /// Filtered operations.
        operations: OperationSet,
        /// Transform kind.
        kind: NetworkControlResultKind,
        /// Registered typed transform fields.
        result: FaultObjectId,
    },
    /// Contact acquisition and availability machine.
    Contact {
        /// Ordered contact-interval artifact.
        intervals: FaultObjectId,
        /// Range-to-delay lookup.
        range_delay_lookup: FaultObjectId,
        /// Candidate beam identities.
        beams: ObjectIdSet,
        /// Candidate gateway identities.
        gateways: ObjectIdSet,
    },
    /// Bounded custody queue.
    CustodyQueue {
        /// Positive byte capacity.
        capacity_bytes: PositiveU64,
        /// Positive bundle capacity.
        capacity_bundles: BoundedCount,
        /// Positive expiry duration.
        expiry_nanos: PositiveU64,
        /// Registered custody policy.
        custody_policy: FaultObjectId,
        /// Registered route/contact plan.
        route_contact_plan: FaultObjectId,
    },
}

impl NetworkEffectSpecification {
    /// Returns the exact closed registry kind for these parameters.
    #[must_use]
    pub const fn kind(&self) -> EffectKind {
        match self {
            Self::Availability { .. } => EffectKind::NetworkAvailability,
            Self::Flap { .. } => EffectKind::NetworkFlap,
            Self::NegotiatedMode { .. } => EffectKind::NetworkNegotiatedMode,
            Self::ProfileDelta { .. } => EffectKind::NetworkProfileDelta,
            Self::PropagationDelay { .. } => EffectKind::NetworkPropagationDelay,
            Self::AccessDelay { .. } => EffectKind::NetworkAccessDelay,
            Self::Jitter { .. } => EffectKind::NetworkJitter,
            Self::ServiceCurve { .. } => EffectKind::NetworkServiceCurve,
            Self::TokenBucket { .. } => EffectKind::NetworkTokenBucket,
            Self::QueuePolicy { .. } => EffectKind::NetworkQueuePolicy,
            Self::FrameLoss { .. } => EffectKind::NetworkFrameLoss,
            Self::BurstErrorState { .. } => EffectKind::NetworkBurstErrorState,
            Self::Duplicate { .. } => EffectKind::NetworkDuplicate,
            Self::Reorder { .. } => EffectKind::NetworkReorder,
            Self::PayloadTransform { .. } => EffectKind::NetworkPayloadTransform,
            Self::DetectedFrameError { .. } => EffectKind::NetworkDetectedFrameError,
            Self::Mtu { .. } => EffectKind::NetworkMtu,
            Self::PauseBackpressure { .. } => EffectKind::NetworkPauseBackpressure,
            Self::RecipientSubset { .. } => EffectKind::NetworkRecipientSubset,
            Self::ForwarderLifecycle { .. } => EffectKind::NetworkForwarderLifecycle,
            Self::ForwardingMutation { .. } => EffectKind::NetworkForwardingMutation,
            Self::RouteTransition { .. } => EffectKind::NetworkRouteTransition,
            Self::ControlPlaneService { .. } => EffectKind::NetworkControlPlaneService,
            Self::FirewallDisposition { .. } => EffectKind::NetworkFirewallDisposition,
            Self::ConnectionState { .. } => EffectKind::NetworkConnectionState,
            Self::SharedMedium { .. } => EffectKind::NetworkSharedMedium,
            Self::RfChannel { .. } => EffectKind::NetworkRfChannel,
            Self::Association { .. } => EffectKind::NetworkAssociation,
            Self::ControlResultTransform { .. } => EffectKind::NetworkControlResultTransform,
            Self::Contact { .. } => EffectKind::NetworkContact,
            Self::CustodyQueue { .. } => EffectKind::NetworkCustodyQueue,
        }
    }

    /// Validates cross-field invariants not encoded by parameter types.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::MutuallyExclusiveFields`] for alternatives
    /// that are both present or both absent, or
    /// [`FaultContractError::InvalidEffectParameters`] for invalid dependent
    /// values such as excess initial tokens or a zero bit-flip mask.
    pub fn validate(&self) -> Result<(), FaultContractError> {
        match self {
            Self::PropagationDelay {
                delay_nanos,
                distance_velocity_lookup,
            } => exactly_one(
                delay_nanos.is_some(),
                distance_velocity_lookup.is_some(),
                "delay_nanos",
                "distance_velocity_lookup",
            ),
            Self::Jitter {
                distribution,
                distribution_lookup,
                ..
            } => {
                let needs_lookup = !matches!(distribution, NetworkDistribution::Uniform);
                if needs_lookup == distribution_lookup.is_some() {
                    Ok(())
                } else {
                    Err(FaultContractError::InvalidEffectParameters {
                        effect: self.kind(),
                    })
                }
            }
            Self::TokenBucket {
                burst_bits,
                initial_bits,
                ..
            } if *initial_bits > burst_bits.get() => {
                Err(FaultContractError::InvalidEffectParameters {
                    effect: self.kind(),
                })
            }
            Self::QueuePolicy {
                discipline,
                discipline_parameters,
                ..
            } => {
                let valid = match discipline {
                    NetworkQueueDiscipline::Fifo => discipline_parameters.is_none(),
                    NetworkQueueDiscipline::StrictPriority
                    | NetworkQueueDiscipline::WeightedRoundRobin
                    | NetworkQueueDiscipline::DeficitRoundRobin
                    | NetworkQueueDiscipline::Red => discipline_parameters.is_some(),
                };
                if valid {
                    Ok(())
                } else {
                    Err(FaultContractError::InvalidEffectParameters {
                        effect: self.kind(),
                    })
                }
            }
            Self::FrameLoss {
                probability,
                outcome,
            } => exactly_one(
                probability.is_some(),
                outcome.is_some(),
                "probability_millionths",
                "outcome",
            ),
            Self::PayloadTransform {
                mutation: NetworkPayloadMutation::BitFlip { mask: 0, .. },
            } => Err(FaultContractError::InvalidEffectParameters {
                effect: self.kind(),
            }),
            Self::RecipientSubset {
                drop_members,
                selection,
                retain_count,
                ..
            } => {
                exactly_one(
                    drop_members.is_some(),
                    selection.is_some(),
                    "drop_members",
                    "selection",
                )?;
                if selection.is_some() == retain_count.is_some() {
                    Ok(())
                } else {
                    Err(FaultContractError::InvalidEffectParameters {
                        effect: self.kind(),
                    })
                }
            }
            Self::DetectedFrameError {
                receiver_action,
                retry_delay_nanos,
                retry_limit,
                retry_attempts,
                retry_succeeds,
                reset_nanos,
                ..
            } => {
                let valid = match receiver_action {
                    DetectedFrameErrorAction::Retry => {
                        match (
                            retry_delay_nanos,
                            retry_limit,
                            retry_attempts,
                            retry_succeeds,
                        ) {
                            (Some(_delay), Some(limit), Some(attempts), Some(succeeds)) => {
                                attempts.get() > 0
                                    && attempts.get() <= limit.get()
                                    && (*succeeds || attempts.get() == limit.get())
                                    && reset_nanos.is_none()
                            }
                            _ => false,
                        }
                    }
                    DetectedFrameErrorAction::LinkReset => {
                        retry_delay_nanos.is_none()
                            && retry_limit.is_none()
                            && retry_attempts.is_none()
                            && retry_succeeds.is_none()
                            && reset_nanos.is_some()
                    }
                    DetectedFrameErrorAction::Corrected | DetectedFrameErrorAction::Drop => {
                        retry_delay_nanos.is_none()
                            && retry_limit.is_none()
                            && retry_attempts.is_none()
                            && retry_succeeds.is_none()
                            && reset_nanos.is_none()
                    }
                };
                if valid {
                    Ok(())
                } else {
                    Err(FaultContractError::InvalidEffectParameters {
                        effect: self.kind(),
                    })
                }
            }
            Self::Mtu {
                oversize,
                fragmentation_protocol,
                typed_error,
                ..
            } => {
                let valid = match oversize {
                    NetworkOversizeDisposition::Drop => {
                        fragmentation_protocol.is_none() && typed_error.is_none()
                    }
                    NetworkOversizeDisposition::Fragment => {
                        fragmentation_protocol.is_some() && typed_error.is_none()
                    }
                    NetworkOversizeDisposition::TypedError => {
                        fragmentation_protocol.is_none() && typed_error.is_some()
                    }
                };
                if valid {
                    Ok(())
                } else {
                    Err(FaultContractError::InvalidEffectParameters {
                        effect: self.kind(),
                    })
                }
            }
            Self::RfChannel {
                transmit_power_femtowatts,
                receiver_noise_femtowatts,
                ..
            } if *transmit_power_femtowatts == 0 || *receiver_noise_femtowatts == 0 => {
                Err(FaultContractError::InvalidEffectParameters {
                    effect: self.kind(),
                })
            }
            _ => Ok(()),
        }
    }
}

fn exactly_one(
    left_present: bool,
    right_present: bool,
    left: &'static str,
    right: &'static str,
) -> Result<(), FaultContractError> {
    if left_present == right_present {
        return Err(FaultContractError::MutuallyExclusiveFields { left, right });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CountLimit;

    #[test]
    fn every_network_variant_maps_to_a_network_registry_key() {
        let probability = match ProbabilityMillionths::new(10) {
            Ok(value) => value,
            Err(error) => panic!("test probability must be valid: {error}"),
        };
        let effect = NetworkEffectSpecification::FrameLoss {
            probability: Some(probability),
            outcome: None,
        };
        assert_eq!(effect.kind(), EffectKind::NetworkFrameLoss);
        assert!(effect.validate().is_ok());
    }

    #[test]
    fn mutually_exclusive_network_fields_fail_closed() {
        let effect = NetworkEffectSpecification::FrameLoss {
            probability: None,
            outcome: None,
        };
        assert_eq!(
            effect.validate(),
            Err(FaultContractError::MutuallyExclusiveFields {
                left: "probability_millionths",
                right: "outcome",
            })
        );
    }

    #[test]
    fn detected_retry_declares_exact_attempts_and_final_outcome() {
        let count = |value| {
            BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, value)
                .unwrap_or_else(|error| panic!("test retry count: {error}"))
        };
        let delay = PositiveU64::new("retry_delay_nanos", 10)
            .unwrap_or_else(|error| panic!("test retry delay: {error}"));
        let retry = |attempts, succeeds| NetworkEffectSpecification::DetectedFrameError {
            kind: DetectedFrameErrorKind::Crc,
            receiver_action: DetectedFrameErrorAction::Retry,
            retry_delay_nanos: Some(delay),
            retry_limit: Some(count(3)),
            retry_attempts: Some(count(attempts)),
            retry_succeeds: Some(succeeds),
            reset_nanos: None,
        };

        assert!(retry(2, true).validate().is_ok());
        assert!(retry(3, false).validate().is_ok());
        assert!(retry(2, false).validate().is_err());
        assert!(retry(4, true).validate().is_err());
    }
}
