//! Backend input and guest-originated network-output values.

use super::*;
use crate::LinkId;
use crate::model::ResolvedFaultTarget;

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
        Ok(())
    }

    /// Defers the already-resolved phase until an exact future coordinate.
    pub fn defer_until(&mut self, not_before_nanos: u64, opportunity: ContentHash) {
        self.not_before_nanos = not_before_nanos;
        self.queue_opportunity = Some(opportunity);
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
