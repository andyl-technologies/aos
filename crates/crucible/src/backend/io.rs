//! Backend input and guest-originated network-output values.

use super::*;
use crate::LinkId;
use crate::model::{EffectKind, ResolvedFaultTarget};

/// One scheduler-validated directed route for a guest-originated frame.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendNetworkRoute {
    /// Canonical World link identity.
    pub link: LinkId,
    /// Direction through the canonical link.
    pub direction: crate::device::NetworkLinkDirection,
    /// Destination VM endpoint selected on the directed route.
    pub destination: NodeId,
}

/// One availability contribution captured before a queued frame's transition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendNetworkPreservedAvailability {
    /// Binding whose later availability state must not affect this frame.
    pub binding: FaultObjectId,
    /// Concrete route target whose captured behavior is preserved.
    pub target: ResolvedFaultTarget,
    /// Adapter phase at which the prior contribution was captured.
    pub phase: FaultPhase,
    /// Exact binding transition version whose behavior was captured.
    pub transition_sequence: u64,
}

/// Resumable signal-adapter position for one routed network frame.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendNetworkFaultCursor {
    /// Canonically ordered target/phase pairs already resolved for this frame.
    completed_phases: Vec<BackendNetworkCompletedFaultPhase>,
    /// Earliest virtual coordinate at which evaluation may resume.
    not_before_nanos: u64,
    /// Latest release from an adapter phase that has already resumed.
    completed_release_nanos: u64,
    /// Queue opportunity that owns the current reservation, when deferred.
    queue_opportunity: Option<ContentHash>,
    /// Sole effect kind allowed to repeat an intentionally incomplete phase.
    repeated_phase_effect: Option<EffectKind>,
    /// Queue service rank used to order equal-coordinate resumptions.
    queue_priority: Option<u8>,
    /// Path version locked for preserve semantics across deferred phases.
    route_path_version: Option<FaultObjectId>,
}

/// One exact route target/phase pair already resolved for a frame.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendNetworkCompletedFaultPhase {
    /// Concrete route target that owned the opportunity.
    pub target: ResolvedFaultTarget,
    /// Exact adapter phase already applied at that target.
    pub phase: FaultPhase,
}

/// Failure to record a bounded network fault continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackendNetworkFaultCursorError {
    /// The frame crossed more target/phase pairs than the hard continuation bound.
    #[error("network fault completed-phase count exceeds 65,536")]
    CompletedPhaseLimit,
    /// A queue attempted to reschedule a frame owned by another reservation.
    #[error("network fault queue reservation does not own the continuation")]
    QueueReservationMismatch,
}

impl BackendNetworkFaultCursor {
    /// Returns completed route target/phase pairs in canonical order.
    #[must_use]
    pub fn completed_phases(&self) -> &[BackendNetworkCompletedFaultPhase] {
        &self.completed_phases
    }

    /// Returns whether this exact target/phase opportunity has already resolved.
    #[must_use]
    pub fn is_complete(&self, target: &ResolvedFaultTarget, phase: FaultPhase) -> bool {
        self.completed_phases
            .binary_search(&BackendNetworkCompletedFaultPhase {
                target: target.clone(),
                phase,
            })
            .is_ok()
    }

    /// Returns the earliest virtual coordinate at which the frame may resume.
    #[must_use]
    pub const fn not_before_nanos(&self) -> u64 {
        self.not_before_nanos
    }

    /// Returns the latest committed adapter release coordinate.
    #[must_use]
    pub const fn release_nanos(&self) -> u64 {
        if self.not_before_nanos > self.completed_release_nanos {
            self.not_before_nanos
        } else {
            self.completed_release_nanos
        }
    }

    /// Returns the active queue-reservation opportunity, when present.
    #[must_use]
    pub const fn queue_opportunity(&self) -> Option<ContentHash> {
        self.queue_opportunity
    }

    /// Returns the effect that exclusively owns a repeated phase, when any.
    #[must_use]
    pub const fn repeated_phase_effect(&self) -> Option<EffectKind> {
        self.repeated_phase_effect
    }

    /// Returns the queue service rank for an equal-coordinate resume.
    #[must_use]
    pub const fn queue_priority(&self) -> Option<u8> {
        self.queue_priority
    }

    /// Returns the route path version locked for this frame, when one exists.
    #[must_use]
    pub const fn route_path_version(&self) -> Option<&FaultObjectId> {
        self.route_path_version.as_ref()
    }

    /// Locks the route path selected at first admission.
    pub fn lock_route_path(&mut self, path_version: FaultObjectId) {
        self.route_path_version = Some(path_version);
    }

    /// Clears the path lock so the next declared phase re-resolves routing.
    pub fn reevaluate_route_path(&mut self) {
        self.route_path_version = None;
    }

    /// Records one exact route target/phase pair as resolved.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkFaultCursorError::CompletedPhaseLimit`] when a
    /// frame would exceed the hard route-complexity bound.
    pub fn complete(
        &mut self,
        target: ResolvedFaultTarget,
        phase: FaultPhase,
    ) -> Result<(), BackendNetworkFaultCursorError> {
        let completed = BackendNetworkCompletedFaultPhase { target, phase };
        match self.completed_phases.binary_search(&completed) {
            Ok(_index) => return Ok(()),
            Err(index) => {
                if self.completed_phases.len() == 65_536 {
                    return Err(BackendNetworkFaultCursorError::CompletedPhaseLimit);
                }
                self.completed_phases.insert(index, completed);
            }
        }
        self.completed_release_nanos = if self.not_before_nanos > self.completed_release_nanos {
            self.not_before_nanos
        } else {
            self.completed_release_nanos
        };
        self.not_before_nanos = 0;
        self.queue_opportunity = None;
        self.repeated_phase_effect = None;
        self.queue_priority = None;
        Ok(())
    }

    /// Defers the already-resolved phase until an exact future coordinate.
    pub fn defer_until(&mut self, not_before_nanos: u64, opportunity: ContentHash) {
        self.not_before_nanos = not_before_nanos;
        self.queue_opportunity = Some(opportunity);
        self.repeated_phase_effect = None;
        self.queue_priority = None;
    }

    /// Defers a phase while allowing only its owning effect to run on resume.
    pub fn defer_repeated_effect_until(
        &mut self,
        not_before_nanos: u64,
        opportunity: ContentHash,
        effect: EffectKind,
        queue_priority: Option<u8>,
    ) {
        self.not_before_nanos = not_before_nanos;
        self.queue_opportunity = Some(opportunity);
        self.repeated_phase_effect = Some(effect);
        self.queue_priority = queue_priority;
    }

    /// Replaces the current queue reservation's release coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkFaultCursorError::QueueReservationMismatch`]
    /// when another opportunity owns the active reservation.
    pub fn reschedule_queue_until(
        &mut self,
        opportunity: ContentHash,
        not_before_nanos: u64,
    ) -> Result<(), BackendNetworkFaultCursorError> {
        if self.queue_opportunity != Some(opportunity) {
            return Err(BackendNetworkFaultCursorError::QueueReservationMismatch);
        }
        self.not_before_nanos = not_before_nanos;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ResolvedFaultTarget {
        ResolvedFaultTarget::NetworkForwarder {
            forwarder: FaultObjectId::parse("forwarder-a")
                .unwrap_or_else(|error| panic!("test target should be valid: {error}")),
        }
    }

    #[test]
    fn network_fault_cursor_retains_release_after_resuming() {
        let mut cursor = BackendNetworkFaultCursor::default();
        cursor.defer_until(41, ContentHash::from_bytes(b"queue"));
        assert_eq!(cursor.not_before_nanos(), 41);
        assert_eq!(cursor.release_nanos(), 41);
        cursor
            .complete(target(), FaultPhase::Resolve)
            .unwrap_or_else(|error| panic!("cursor should advance: {error}"));
        assert_eq!(cursor.not_before_nanos(), 0);
        assert_eq!(cursor.release_nanos(), 41);
        assert!(cursor.is_complete(&target(), FaultPhase::Resolve));
    }

    #[test]
    fn network_fault_cursor_completion_is_idempotent_across_path_reevaluation() {
        let mut cursor = BackendNetworkFaultCursor::default();
        cursor
            .complete(target(), FaultPhase::Resolve)
            .unwrap_or_else(|error| panic!("cursor should complete: {error}"));
        cursor.lock_route_path(
            FaultObjectId::parse("old-path")
                .unwrap_or_else(|error| panic!("test path should be valid: {error}")),
        );
        cursor.reevaluate_route_path();
        cursor
            .complete(target(), FaultPhase::Resolve)
            .unwrap_or_else(|error| panic!("duplicate completion should succeed: {error}"));
        assert_eq!(cursor.completed_phases().len(), 1);
        assert!(cursor.route_path_version().is_none());
    }

    #[test]
    fn protocol_expansion_path_orders_nested_child_frames() {
        let mut first = BackendNetworkFaultContinuation::default();
        first.append_protocol_expansion_ordinal(0);
        first.append_protocol_expansion_ordinal(7);
        let mut second = BackendNetworkFaultContinuation::default();
        second.append_protocol_expansion_ordinal(1);
        assert!(first < second);
        assert_eq!(first.protocol_expansion_path(), &[0, 7]);
    }

    #[test]
    fn generated_response_resets_forward_state_and_enforces_depth() {
        let cause = ContentHash::from_bytes(b"reject");
        let mut parent = BackendNetworkFaultContinuation::default();
        parent.append_protocol_expansion_ordinal(3);
        parent
            .cursor_mut()
            .complete(target(), FaultPhase::Resolve)
            .unwrap_or_else(|error| panic!("parent cursor: {error}"));
        let mut child = parent
            .generated_response(cause)
            .unwrap_or_else(|| panic!("first response must fit"));
        assert_eq!(child.generated_response_depth(), 1);
        assert_eq!(child.generated_response_cause(), Some(cause));
        assert!(child.protocol_expansion_path().is_empty());
        assert!(child.cursor().completed_phases().is_empty());
        for ordinal in 1..crate::model::HARD_NETWORK_RESPONSE_DEPTH {
            child = child
                .generated_response(ContentHash::from_bytes(&[ordinal]))
                .unwrap_or_else(|| panic!("bounded response {ordinal} must fit"));
        }
        assert!(child.generated_response(cause).is_none());
    }

    #[test]
    fn forwarding_mutation_preserves_wire_state_and_records_forced_recipient() {
        let cause = ContentHash::from_bytes(b"wrong-port");
        let destination = NodeId {
            name: String::from("receiver-b"),
        };
        let mut parent = BackendNetworkFaultContinuation::default();
        parent.append_protocol_expansion_ordinal(2);
        parent.cursor_mut().lock_route_path(
            FaultObjectId::parse("old-path").unwrap_or_else(|error| panic!("test path: {error}")),
        );
        let child = parent
            .forwarding_mutation(cause, destination.clone())
            .unwrap_or_else(|| panic!("first forwarding mutation must fit"));
        assert_eq!(child.protocol_expansion_path(), &[2]);
        assert_eq!(child.forwarding_mutation_path(), &[cause]);
        assert_eq!(child.forced_route_destination(), Some(&destination));
        assert!(child.cursor().route_path_version().is_none());
    }

    #[test]
    fn pending_network_output_codec_round_trips_complete_fault_continuation() {
        let mut continuation = BackendNetworkFaultContinuation::default();
        continuation.preserve_availability(
            FaultObjectId::parse("binding-a")
                .unwrap_or_else(|error| panic!("test binding: {error}")),
            target(),
            FaultPhase::Admit,
            7,
        );
        let mut effects = crucible_device::ResolvedNetworkFrameEffects::default();
        effects
            .add_latency_delta(-11)
            .unwrap_or_else(|error| panic!("latency delta: {error}"));
        effects
            .add_delay(29)
            .unwrap_or_else(|error| panic!("delay: {error}"));
        effects
            .constrain_rate(1_000_000)
            .unwrap_or_else(|error| panic!("rate: {error}"));
        effects
            .mark_contact_service_accounted([3; 32])
            .unwrap_or_else(|error| panic!("contact: {error}"));
        effects.mark_drop();
        effects
            .add_duplicate_gap(31)
            .unwrap_or_else(|error| panic!("duplicate: {error}"));
        continuation.set_resolved_frame_effects(effects);
        continuation.append_protocol_expansion_ordinal(2);
        continuation.append_protocol_expansion_ordinal(9);
        assert!(continuation.begin_generated_response(ContentHash::from_bytes(b"response")));
        continuation = continuation
            .forwarding_mutation(
                ContentHash::from_bytes(b"reroute"),
                NodeId {
                    name: String::from("receiver-b"),
                },
            )
            .unwrap_or_else(|| panic!("forwarding mutation should fit"));
        continuation
            .cursor_mut()
            .complete(target(), FaultPhase::Resolve)
            .unwrap_or_else(|error| panic!("complete cursor: {error}"));
        continuation.cursor_mut().defer_repeated_effect_until(
            73,
            ContentHash::from_bytes(b"queue"),
            EffectKind::NetworkQueuePolicy,
            Some(4),
        );
        continuation.cursor_mut().lock_route_path(
            FaultObjectId::parse("path-v1").unwrap_or_else(|error| panic!("test path: {error}")),
        );
        let output = BackendNetworkOutput {
            source: NodeId {
                name: String::from("sender-a"),
            },
            destination: NodeId {
                name: String::from("receiver-b"),
            },
            emit_icount: Icount { retired: 41 },
            sequence: 43,
            payload: vec![1, 2, 3, 4],
            route: Some(BackendNetworkRoute {
                link: LinkId::from_name("link-a-b"),
                direction: crate::device::NetworkLinkDirection::EndpointAToEndpointB,
                destination: NodeId {
                    name: String::from("receiver-b"),
                },
            }),
            fault_continuation: continuation,
        };

        let bytes = output
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("pending frame encodes: {error}"));
        let restored = BackendNetworkOutput::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("pending frame decodes: {error}"));
        assert_eq!(restored, output);
        assert_eq!(
            restored
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("restored frame encodes: {error}")),
            bytes
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            BackendNetworkOutput::from_canonical_bytes(&trailing),
            Err(BackendNetworkOutputCodecError::Noncanonical)
        );
    }
}

/// Fault-policy continuation retained with one scheduler-queued frame.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendNetworkFaultContinuation {
    /// Canonical contributions whose pre-transition profile is preserved.
    preserved_availability: Vec<BackendNetworkPreservedAvailability>,
    /// Exact signal-adapter outcomes resolved before link scheduling.
    resolved_frame_effects: crucible_device::ResolvedNetworkFrameEffects,
    /// Nested protocol-expansion ordinals from the guest frame to this child.
    protocol_expansion_path: Vec<u16>,
    /// Number of scheduler-generated responses in this frame's ancestry.
    generated_response_depth: u8,
    /// Opportunity that generated this frame, absent for guest frames.
    generated_response_cause: Option<ContentHash>,
    /// Ordered opportunities that changed this frame's World route.
    forwarding_mutation_path: Vec<ContentHash>,
    /// Policy-authorized recipient used without rewriting Ethernet bytes.
    forced_route_destination: Option<NodeId>,
    /// Resumable ordered route/phase position.
    cursor: BackendNetworkFaultCursor,
}

impl BackendNetworkFaultContinuation {
    /// Preserves one exact pre-transition contribution identity.
    pub fn preserve_availability(
        &mut self,
        binding: FaultObjectId,
        target: ResolvedFaultTarget,
        phase: FaultPhase,
        transition_sequence: u64,
    ) {
        let preserved = BackendNetworkPreservedAvailability {
            binding,
            target,
            phase,
            transition_sequence,
        };
        match self.preserved_availability.binary_search(&preserved) {
            Ok(_index) => {}
            Err(index) => self.preserved_availability.insert(index, preserved),
        }
    }

    /// Returns whether a later contribution must be ignored for this frame.
    #[must_use]
    pub fn preserves_availability(
        &self,
        binding: &FaultObjectId,
        target: &ResolvedFaultTarget,
        phase: FaultPhase,
        transition_sequence: u64,
    ) -> bool {
        self.preserved_availability
            .binary_search(&BackendNetworkPreservedAvailability {
                binding: binding.clone(),
                target: target.clone(),
                phase,
                transition_sequence,
            })
            .is_ok()
    }

    /// Returns captured contributions in canonical identity order.
    #[must_use]
    pub fn preserved_availability(&self) -> &[BackendNetworkPreservedAvailability] {
        &self.preserved_availability
    }

    /// Replaces the exact signal-adapter outcomes for this frame.
    pub fn set_resolved_frame_effects(
        &mut self,
        effects: crucible_device::ResolvedNetworkFrameEffects,
    ) {
        self.resolved_frame_effects = effects;
    }

    /// Returns the exact signal-adapter outcomes for this frame.
    #[must_use]
    pub const fn resolved_frame_effects(&self) -> &crucible_device::ResolvedNetworkFrameEffects {
        &self.resolved_frame_effects
    }

    /// Appends one protocol-expansion ordinal to this child frame's identity.
    pub fn append_protocol_expansion_ordinal(&mut self, ordinal: u16) {
        self.protocol_expansion_path.push(ordinal);
    }

    /// Returns the nested protocol-expansion path in parent-to-child order.
    #[must_use]
    pub fn protocol_expansion_path(&self) -> &[u16] {
        &self.protocol_expansion_path
    }

    /// Records one scheduler-generated response and its exact cause.
    ///
    /// Returns `false` without mutation when the hard response-depth bound has
    /// already been reached.
    pub fn begin_generated_response(&mut self, cause: ContentHash) -> bool {
        if self.generated_response_depth >= crate::model::HARD_NETWORK_RESPONSE_DEPTH {
            return false;
        }
        self.generated_response_depth += 1;
        self.generated_response_cause = Some(cause);
        true
    }

    /// Creates a fresh route continuation for a generated child response.
    ///
    /// The child retains only bounded response ancestry. Route cursor state,
    /// resolved frame effects, availability preservation, and protocol
    /// expansion belong to the rejected forward frame and are reset.
    #[must_use]
    pub fn generated_response(&self, cause: ContentHash) -> Option<Self> {
        let depth = self.generated_response_depth.checked_add(1)?;
        if depth > crate::model::HARD_NETWORK_RESPONSE_DEPTH {
            return None;
        }
        Some(Self {
            generated_response_depth: depth,
            generated_response_cause: Some(cause),
            ..Self::default()
        })
    }

    /// Returns the number of generated responses in this frame's ancestry.
    #[must_use]
    pub const fn generated_response_depth(&self) -> u8 {
        self.generated_response_depth
    }

    /// Returns the opportunity that generated this frame, when applicable.
    #[must_use]
    pub const fn generated_response_cause(&self) -> Option<ContentHash> {
        self.generated_response_cause
    }

    /// Creates a rerouted child while preserving already-resolved frame state.
    #[must_use]
    pub fn forwarding_mutation(&self, cause: ContentHash, destination: NodeId) -> Option<Self> {
        if self.forwarding_mutation_path.len()
            >= usize::from(crate::model::HARD_NETWORK_FORWARDING_MUTATION_DEPTH)
        {
            return None;
        }
        let mut child = self.clone();
        child.forwarding_mutation_path.push(cause);
        child.forced_route_destination = Some(destination);
        child.cursor.reevaluate_route_path();
        Some(child)
    }

    /// Returns the ordered forwarding-mutation ancestry.
    #[must_use]
    pub fn forwarding_mutation_path(&self) -> &[ContentHash] {
        &self.forwarding_mutation_path
    }

    /// Returns the policy-authorized route recipient, when present.
    #[must_use]
    pub const fn forced_route_destination(&self) -> Option<&NodeId> {
        self.forced_route_destination.as_ref()
    }

    /// Returns the resumable ordered route/phase position.
    #[must_use]
    pub const fn cursor(&self) -> &BackendNetworkFaultCursor {
        &self.cursor
    }

    /// Returns mutable access to the adapter-owned route/phase position.
    #[must_use]
    pub const fn cursor_mut(&mut self) -> &mut BackendNetworkFaultCursor {
        &mut self.cursor
    }
}

/// Deterministic input delivered to a backend.
///
/// This payload represents backend delivery for model-controlled inputs, not a
/// host-side workload generator. Application workload traffic must originate
/// from guest execution and cross modeled devices as ordinary guest/device I/O.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BackendInput {
    /// The target node.
    pub node: NodeId,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

/// A guest-originated network frame awaiting scheduler-owned routing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendNetworkOutput {
    /// The VM that emitted the frame.
    pub source: NodeId,
    /// The logical router endpoint that received the guest TX frame.
    ///
    /// The scheduler resolves the Ethernet destination against the World and
    /// does not trust the backend to select a peer VM.
    pub destination: NodeId,
    /// The source VM icount at which the guest emitted the frame.
    pub emit_icount: Icount,
    /// The per-source deterministic frame sequence.
    pub sequence: u64,
    /// The opaque guest Ethernet frame bytes.
    pub payload: Vec<u8>,
    /// Scheduler-validated route selected by a pre-routing interceptor.
    ///
    /// Live backends always publish `None`. The authoritative scheduler or an
    /// in-loop interceptor may expand one multicast frame into route-locked
    /// copies before modeled link mutation. A supplied route is revalidated
    /// against the World and frame destination before use.
    pub route: Option<BackendNetworkRoute>,
    /// Policy continuation for frames retained across availability transitions.
    pub fault_continuation: BackendNetworkFaultContinuation,
}

impl BackendNetworkOutput {
    /// Encodes a pending routed frame and its complete fault continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkOutputCodecError`] when an identity or payload
    /// exceeds its hard bound, a continuation collection is not canonical, a
    /// target is invalid, or deterministic CBOR encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BackendNetworkOutputCodecError> {
        let wire = BackendNetworkOutputWire::try_from(self)?;
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&wire, &mut bytes)
            .map_err(|_| BackendNetworkOutputCodecError::Encoding)?;
        if bytes.len() > HARD_BACKEND_NETWORK_CHECKPOINT_BYTES {
            return Err(BackendNetworkOutputCodecError::Limit {
                field: "encoded frame",
                hard: HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes and validates a pending routed frame and fault continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BackendNetworkOutputCodecError`] for malformed, over-limit,
    /// noncanonical, semantically invalid, or trailing state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BackendNetworkOutputCodecError> {
        if bytes.len() > HARD_BACKEND_NETWORK_CHECKPOINT_BYTES {
            return Err(BackendNetworkOutputCodecError::Limit {
                field: "encoded frame",
                hard: HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            });
        }
        let wire: BackendNetworkOutputWire = ciborium::de::from_reader(bytes)
            .map_err(|_| BackendNetworkOutputCodecError::Encoding)?;
        let output = Self::try_from(wire)?;
        if output.canonical_bytes()?.as_slice() != bytes {
            return Err(BackendNetworkOutputCodecError::Noncanonical);
        }
        Ok(output)
    }
}

const BACKEND_NETWORK_OUTPUT_VERSION: u16 = 1;
const HARD_BACKEND_NETWORK_CHECKPOINT_BYTES: usize = 16_777_216;
const HARD_BACKEND_NETWORK_ID_BYTES: usize = 4_096;
const HARD_BACKEND_NETWORK_CURSOR_PHASES: usize = 65_536;

/// Failure to encode or decode a pending routed network frame.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackendNetworkOutputCodecError {
    /// The durable record version is unsupported.
    #[error("unsupported pending network frame checkpoint version")]
    Version,
    /// Deterministic CBOR encoding or decoding failed.
    #[error("malformed pending network frame checkpoint encoding")]
    Encoding,
    /// A bounded field exceeds its compiled hard ceiling.
    #[error("pending network frame checkpoint `{field}` exceeds hard limit {hard}")]
    Limit {
        /// Field whose bound was exceeded.
        field: &'static str,
        /// Compiled hard ceiling.
        hard: usize,
    },
    /// The record is well-formed but violates a runtime continuation invariant.
    #[error("invalid pending network frame checkpoint: {0}")]
    Invalid(&'static str),
    /// The record has an alternate or noncanonical representation.
    #[error("noncanonical pending network frame checkpoint")]
    Noncanonical,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkOutputWire {
    version: u16,
    source: String,
    destination: String,
    emit_icount: u64,
    sequence: u64,
    payload: Vec<u8>,
    route: Option<BackendNetworkRouteWire>,
    fault: BackendNetworkFaultContinuationWire,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkRouteWire {
    link: String,
    direction: u8,
    destination: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkFaultContinuationWire {
    preserved_availability: Vec<BackendNetworkPreservedAvailabilityWire>,
    resolved_frame_effects: ResolvedNetworkFrameEffectsWire,
    protocol_expansion_path: Vec<u16>,
    generated_response_depth: u8,
    generated_response_cause: Option<ContentHash>,
    forwarding_mutation_path: Vec<ContentHash>,
    forced_route_destination: Option<String>,
    cursor: BackendNetworkFaultCursorWire,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkPreservedAvailabilityWire {
    binding: FaultObjectId,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkCompletedFaultPhaseWire {
    target: ResolvedFaultTarget,
    phase: FaultPhase,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendNetworkFaultCursorWire {
    completed_phases: Vec<BackendNetworkCompletedFaultPhaseWire>,
    not_before_nanos: u64,
    completed_release_nanos: u64,
    queue_opportunity: Option<ContentHash>,
    repeated_phase_effect: Option<EffectKind>,
    queue_priority: Option<u8>,
    route_path_version: Option<FaultObjectId>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedNetworkFrameEffectsWire {
    latency_delta_nanos: i64,
    additional_delay_nanos: u64,
    serialization_rate_cap_bps: Option<u64>,
    serialization_accounted: bool,
    contact_services_accounted: Vec<[u8; 32]>,
    drop: bool,
    duplicate_gaps_nanos: Vec<u64>,
}

impl TryFrom<&BackendNetworkOutput> for BackendNetworkOutputWire {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(output: &BackendNetworkOutput) -> Result<Self, Self::Error> {
        validate_network_checkpoint_name(&output.source.name, "source")?;
        validate_network_checkpoint_name(&output.destination.name, "destination")?;
        if output.payload.len() > HARD_BACKEND_NETWORK_CHECKPOINT_BYTES {
            return Err(BackendNetworkOutputCodecError::Limit {
                field: "frame payload",
                hard: HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            });
        }
        let route = output
            .route
            .as_ref()
            .map(|route| {
                validate_network_checkpoint_name(&route.link.name, "route link")?;
                validate_network_checkpoint_name(&route.destination.name, "route destination")?;
                Ok(BackendNetworkRouteWire {
                    link: route.link.name.clone(),
                    direction: match route.direction {
                        crate::device::NetworkLinkDirection::EndpointAToEndpointB => 1,
                        crate::device::NetworkLinkDirection::EndpointBToEndpointA => 2,
                    },
                    destination: route.destination.name.clone(),
                })
            })
            .transpose()?;
        Ok(Self {
            version: BACKEND_NETWORK_OUTPUT_VERSION,
            source: output.source.name.clone(),
            destination: output.destination.name.clone(),
            emit_icount: output.emit_icount.retired,
            sequence: output.sequence,
            payload: output.payload.clone(),
            route,
            fault: BackendNetworkFaultContinuationWire::try_from(&output.fault_continuation)?,
        })
    }
}

impl TryFrom<BackendNetworkOutputWire> for BackendNetworkOutput {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: BackendNetworkOutputWire) -> Result<Self, Self::Error> {
        if wire.version != BACKEND_NETWORK_OUTPUT_VERSION {
            return Err(BackendNetworkOutputCodecError::Version);
        }
        validate_network_checkpoint_name(&wire.source, "source")?;
        validate_network_checkpoint_name(&wire.destination, "destination")?;
        if wire.payload.len() > HARD_BACKEND_NETWORK_CHECKPOINT_BYTES {
            return Err(BackendNetworkOutputCodecError::Limit {
                field: "frame payload",
                hard: HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            });
        }
        let route = wire
            .route
            .map(|route| {
                validate_network_checkpoint_name(&route.link, "route link")?;
                validate_network_checkpoint_name(&route.destination, "route destination")?;
                let direction = match route.direction {
                    1 => crate::device::NetworkLinkDirection::EndpointAToEndpointB,
                    2 => crate::device::NetworkLinkDirection::EndpointBToEndpointA,
                    _ => return Err(BackendNetworkOutputCodecError::Invalid("route direction")),
                };
                Ok(BackendNetworkRoute {
                    link: LinkId::from_name(route.link),
                    direction,
                    destination: NodeId {
                        name: route.destination,
                    },
                })
            })
            .transpose()?;
        Ok(Self {
            source: NodeId { name: wire.source },
            destination: NodeId {
                name: wire.destination,
            },
            emit_icount: Icount {
                retired: wire.emit_icount,
            },
            sequence: wire.sequence,
            payload: wire.payload,
            route,
            fault_continuation: BackendNetworkFaultContinuation::try_from(wire.fault)?,
        })
    }
}

impl TryFrom<&BackendNetworkFaultContinuation> for BackendNetworkFaultContinuationWire {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(value: &BackendNetworkFaultContinuation) -> Result<Self, Self::Error> {
        validate_network_fault_continuation(value)?;
        Ok(Self {
            preserved_availability: value
                .preserved_availability
                .iter()
                .map(|entry| BackendNetworkPreservedAvailabilityWire {
                    binding: entry.binding.clone(),
                    target: entry.target.clone(),
                    phase: entry.phase,
                    transition_sequence: entry.transition_sequence,
                })
                .collect(),
            resolved_frame_effects: ResolvedNetworkFrameEffectsWire::from(
                &value.resolved_frame_effects,
            ),
            protocol_expansion_path: value.protocol_expansion_path.clone(),
            generated_response_depth: value.generated_response_depth,
            generated_response_cause: value.generated_response_cause,
            forwarding_mutation_path: value.forwarding_mutation_path.clone(),
            forced_route_destination: value
                .forced_route_destination
                .as_ref()
                .map(|node| node.name.clone()),
            cursor: BackendNetworkFaultCursorWire::from(&value.cursor),
        })
    }
}

impl TryFrom<BackendNetworkFaultContinuationWire> for BackendNetworkFaultContinuation {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: BackendNetworkFaultContinuationWire) -> Result<Self, Self::Error> {
        let preserved_availability = wire
            .preserved_availability
            .into_iter()
            .map(|entry| {
                entry
                    .target
                    .validate()
                    .map_err(|_| BackendNetworkOutputCodecError::Invalid("preserved target"))?;
                Ok(BackendNetworkPreservedAvailability {
                    binding: entry.binding,
                    target: entry.target,
                    phase: entry.phase,
                    transition_sequence: entry.transition_sequence,
                })
            })
            .collect::<Result<Vec<_>, BackendNetworkOutputCodecError>>()?;
        let forced_route_destination = wire
            .forced_route_destination
            .map(|name| {
                validate_network_checkpoint_name(&name, "forced route destination")?;
                Ok(NodeId { name })
            })
            .transpose()?;
        let value = Self {
            preserved_availability,
            resolved_frame_effects: crucible_device::ResolvedNetworkFrameEffects::try_from(
                wire.resolved_frame_effects,
            )?,
            protocol_expansion_path: wire.protocol_expansion_path,
            generated_response_depth: wire.generated_response_depth,
            generated_response_cause: wire.generated_response_cause,
            forwarding_mutation_path: wire.forwarding_mutation_path,
            forced_route_destination,
            cursor: BackendNetworkFaultCursor::try_from(wire.cursor)?,
        };
        validate_network_fault_continuation(&value)?;
        Ok(value)
    }
}

impl From<&BackendNetworkFaultCursor> for BackendNetworkFaultCursorWire {
    fn from(value: &BackendNetworkFaultCursor) -> Self {
        Self {
            completed_phases: value
                .completed_phases
                .iter()
                .map(|entry| BackendNetworkCompletedFaultPhaseWire {
                    target: entry.target.clone(),
                    phase: entry.phase,
                })
                .collect(),
            not_before_nanos: value.not_before_nanos,
            completed_release_nanos: value.completed_release_nanos,
            queue_opportunity: value.queue_opportunity,
            repeated_phase_effect: value.repeated_phase_effect,
            queue_priority: value.queue_priority,
            route_path_version: value.route_path_version.clone(),
        }
    }
}

impl TryFrom<BackendNetworkFaultCursorWire> for BackendNetworkFaultCursor {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: BackendNetworkFaultCursorWire) -> Result<Self, Self::Error> {
        if wire.completed_phases.len() > HARD_BACKEND_NETWORK_CURSOR_PHASES {
            return Err(BackendNetworkOutputCodecError::Limit {
                field: "completed phases",
                hard: HARD_BACKEND_NETWORK_CURSOR_PHASES,
            });
        }
        let completed_phases = wire
            .completed_phases
            .into_iter()
            .map(|entry| {
                entry
                    .target
                    .validate()
                    .map_err(|_| BackendNetworkOutputCodecError::Invalid("completed target"))?;
                Ok(BackendNetworkCompletedFaultPhase {
                    target: entry.target,
                    phase: entry.phase,
                })
            })
            .collect::<Result<Vec<_>, BackendNetworkOutputCodecError>>()?;
        if completed_phases.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BackendNetworkOutputCodecError::Noncanonical);
        }
        let deferred = wire.queue_opportunity.is_some();
        if wire.repeated_phase_effect.is_some() && !deferred
            || wire.queue_priority.is_some() && wire.repeated_phase_effect.is_none()
        {
            return Err(BackendNetworkOutputCodecError::Invalid(
                "fault cursor deferral state",
            ));
        }
        Ok(Self {
            completed_phases,
            not_before_nanos: wire.not_before_nanos,
            completed_release_nanos: wire.completed_release_nanos,
            queue_opportunity: wire.queue_opportunity,
            repeated_phase_effect: wire.repeated_phase_effect,
            queue_priority: wire.queue_priority,
            route_path_version: wire.route_path_version,
        })
    }
}

impl From<&crucible_device::ResolvedNetworkFrameEffects> for ResolvedNetworkFrameEffectsWire {
    fn from(value: &crucible_device::ResolvedNetworkFrameEffects) -> Self {
        Self {
            latency_delta_nanos: value.latency_delta_nanos(),
            additional_delay_nanos: value.additional_delay_nanos(),
            serialization_rate_cap_bps: value.serialization_rate_cap_bps(),
            serialization_accounted: value.serialization_is_accounted(),
            contact_services_accounted: value.accounted_contact_services().to_vec(),
            drop: value.is_dropped(),
            duplicate_gaps_nanos: value.duplicate_gaps_nanos().to_vec(),
        }
    }
}

impl TryFrom<ResolvedNetworkFrameEffectsWire> for crucible_device::ResolvedNetworkFrameEffects {
    type Error = BackendNetworkOutputCodecError;

    fn try_from(wire: ResolvedNetworkFrameEffectsWire) -> Result<Self, Self::Error> {
        if wire.contact_services_accounted.len() > 256 || wire.duplicate_gaps_nanos.len() > 256 {
            return Err(BackendNetworkOutputCodecError::Limit {
                field: "resolved frame effects",
                hard: 256,
            });
        }
        if wire
            .contact_services_accounted
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || wire
                .duplicate_gaps_nanos
                .windows(2)
                .any(|pair| pair[0] > pair[1])
            || !wire.contact_services_accounted.is_empty() && !wire.serialization_accounted
        {
            return Err(BackendNetworkOutputCodecError::Noncanonical);
        }
        let mut effects = Self::default();
        effects
            .add_latency_delta(wire.latency_delta_nanos)
            .map_err(|_| BackendNetworkOutputCodecError::Invalid("latency delta"))?;
        effects
            .add_delay(wire.additional_delay_nanos)
            .map_err(|_| BackendNetworkOutputCodecError::Invalid("additional delay"))?;
        if let Some(rate) = wire.serialization_rate_cap_bps {
            effects
                .constrain_rate(rate)
                .map_err(|_| BackendNetworkOutputCodecError::Invalid("rate cap"))?;
        }
        for service in wire.contact_services_accounted {
            effects
                .mark_contact_service_accounted(service)
                .map_err(|_| BackendNetworkOutputCodecError::Invalid("contact service"))?;
        }
        if wire.serialization_accounted && effects.accounted_contact_services().is_empty() {
            effects.mark_serialization_accounted();
        }
        if wire.drop {
            effects.mark_drop();
        }
        for gap in wire.duplicate_gaps_nanos {
            effects
                .add_duplicate_gap(gap)
                .map_err(|_| BackendNetworkOutputCodecError::Invalid("duplicate gap"))?;
        }
        Ok(effects)
    }
}

fn validate_network_fault_continuation(
    value: &BackendNetworkFaultContinuation,
) -> Result<(), BackendNetworkOutputCodecError> {
    if value.preserved_availability.len() > HARD_BACKEND_NETWORK_CURSOR_PHASES {
        return Err(BackendNetworkOutputCodecError::Limit {
            field: "preserved availability",
            hard: HARD_BACKEND_NETWORK_CURSOR_PHASES,
        });
    }
    for entry in &value.preserved_availability {
        entry
            .target
            .validate()
            .map_err(|_| BackendNetworkOutputCodecError::Invalid("preserved target"))?;
    }
    if value
        .preserved_availability
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || value.protocol_expansion_path.len() > crate::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
        || value.generated_response_depth > crate::model::HARD_NETWORK_RESPONSE_DEPTH
        || value.forwarding_mutation_path.len()
            > usize::from(crate::model::HARD_NETWORK_FORWARDING_MUTATION_DEPTH)
        || (value.generated_response_depth == 0) != value.generated_response_cause.is_none()
        || value.forwarding_mutation_path.is_empty() != value.forced_route_destination.is_none()
    {
        return Err(BackendNetworkOutputCodecError::Noncanonical);
    }
    if let Some(node) = &value.forced_route_destination {
        validate_network_checkpoint_name(&node.name, "forced route destination")?;
    }
    let _ =
        BackendNetworkFaultCursor::try_from(BackendNetworkFaultCursorWire::from(&value.cursor))?;
    let wire = ResolvedNetworkFrameEffectsWire::from(&value.resolved_frame_effects);
    let restored = crucible_device::ResolvedNetworkFrameEffects::try_from(wire)?;
    if restored != value.resolved_frame_effects {
        return Err(BackendNetworkOutputCodecError::Noncanonical);
    }
    Ok(())
}

fn validate_network_checkpoint_name(
    value: &str,
    field: &'static str,
) -> Result<(), BackendNetworkOutputCodecError> {
    if value.is_empty() || value.len() > HARD_BACKEND_NETWORK_ID_BYTES {
        return Err(BackendNetworkOutputCodecError::Limit {
            field,
            hard: HARD_BACKEND_NETWORK_ID_BYTES,
        });
    }
    Ok(())
}

/// Derives the stable locally administered unicast MAC for a World VM.
///
/// The mapping depends only on the canonical node identity, so launch order and
/// backend slot allocation cannot perturb guest-visible addressing.
#[must_use]
pub fn deterministic_node_mac(node: &NodeId) -> [u8; 6] {
    let hash = ContentHash::from_canonical_material(
        "crucible.world-node-mac.v1",
        &format!("node_name_len={}\nnode_name={}", node.name.len(), node.name),
    );
    let mut mac = [0_u8; 6];
    mac.copy_from_slice(&hash.bytes[..6]);
    mac[0] = (mac[0] | 0x02) & 0xfe;
    mac
}

/// Renders [`deterministic_node_mac`] in canonical QEMU option syntax.
#[must_use]
pub fn deterministic_node_mac_string(node: &NodeId) -> String {
    let mac = deterministic_node_mac(node);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
