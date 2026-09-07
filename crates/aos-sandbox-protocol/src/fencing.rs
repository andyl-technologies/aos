//! Simulates assignment and ownership-lease fencing without Linux effects.
//!
//! The state machines in this module model the durable comparisons that a
//! node and every mutable shared endpoint perform before admitting effects.
//! [`EndpointSet`] applies ownership changes transactionally so a destination
//! cannot become active after updating only a subset of its shared endpoints.
//! This entire module is a protocol simulation, not a production authority
//! boundary. Its constructors accept modeled facts and perform no cryptography;
//! production brokers use `aos-sandbox-core` verified leases and durable local
//! records instead.

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDigest, SandboxId,
};

/// Describes whether a durable comparison applied new state or replayed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    /// Newer state was durably accepted.
    Applied,
    /// The exact previously accepted bytes were presented again.
    Replay,
}

/// Identifies the semantic assignment authorized to mutate node-local state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignmentClaim {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    node: NodeId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
}

impl AssignmentClaim {
    /// Constructs an assignment claim from its complete fencing tuple.
    #[must_use]
    pub const fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        node: NodeId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
    ) -> Self {
        Self {
            sandbox,
            incarnation,
            node,
            epoch,
            desired_generation,
            assignment_digest,
        }
    }

    /// Returns the logical sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the runtime incarnation.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the assigned node.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the assignment epoch.
    #[must_use]
    pub const fn epoch(self) -> AssignmentEpoch {
        self.epoch
    }

    /// Returns the desired-state generation within the assignment.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the digest of immutable assignment semantics.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    fn lease_identity_matches(self, other: Self) -> bool {
        self.sandbox == other.sandbox
            && self.incarnation == other.incarnation
            && self.node == other.node
            && self.epoch.get() == other.epoch.get()
            && self.assignment_digest == other.assignment_digest
    }
}

/// Carries a simulated ownership lease with caller-asserted verification facts.
///
/// This value is test/model input only and must never be treated as proof that
/// a signature or durable broker fence was verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipLease {
    assignment: AssignmentClaim,
    generation: u64,
    authority_issued_nanoseconds: u64,
    authority_expires_nanoseconds: u64,
    maximum_clock_skew_nanoseconds: u64,
    renewal_nonce: [u8; 16],
    lease_digest: ObjectDigest,
}

impl OwnershipLease {
    /// Constructs a simulated lease from caller-asserted verified fields.
    ///
    /// The assignment digest excludes lease timing and generation, while the
    /// lease digest commits to the exact signed lease bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FencingError::InvalidLease`] for generation zero, an empty or
    /// reversed authority interval, or an all-zero renewal nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn new_verified(
        assignment: AssignmentClaim,
        generation: u64,
        authority_issued_nanoseconds: u64,
        authority_expires_nanoseconds: u64,
        maximum_clock_skew_nanoseconds: u64,
        renewal_nonce: [u8; 16],
        lease_digest: ObjectDigest,
    ) -> Result<Self, FencingError> {
        if generation == 0
            || authority_expires_nanoseconds <= authority_issued_nanoseconds
            || renewal_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(FencingError::InvalidLease);
        }

        Ok(Self {
            assignment,
            generation,
            authority_issued_nanoseconds,
            authority_expires_nanoseconds,
            maximum_clock_skew_nanoseconds,
            renewal_nonce,
            lease_digest,
        })
    }

    /// Returns the assignment authorized by this lease.
    #[must_use]
    pub const fn assignment(self) -> AssignmentClaim {
        self.assignment
    }

    /// Returns the monotonically increasing renewal generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the authority issue time.
    #[must_use]
    pub const fn authority_issued_nanoseconds(self) -> u64 {
        self.authority_issued_nanoseconds
    }

    /// Returns the authority expiry time.
    #[must_use]
    pub const fn authority_expires_nanoseconds(self) -> u64 {
        self.authority_expires_nanoseconds
    }

    /// Returns the maximum admitted authority-clock skew.
    #[must_use]
    pub const fn maximum_clock_skew_nanoseconds(self) -> u64 {
        self.maximum_clock_skew_nanoseconds
    }

    /// Returns the authority-provided renewal nonce.
    #[must_use]
    pub const fn renewal_nonce(&self) -> &[u8; 16] {
        &self.renewal_nonce
    }

    /// Returns the digest of the exact signed lease.
    #[must_use]
    pub const fn lease_digest(self) -> ObjectDigest {
        self.lease_digest
    }

    fn conservatively_live_at(self, authority_now_nanoseconds: u64) -> bool {
        let earliest_admissible =
            authority_now_nanoseconds.saturating_add(self.maximum_clock_skew_nanoseconds);
        let latest_admissible =
            authority_now_nanoseconds.saturating_sub(self.maximum_clock_skew_nanoseconds);
        latest_admissible >= self.authority_issued_nanoseconds
            && earliest_admissible < self.authority_expires_nanoseconds
    }

    fn supersession_time(self) -> Option<u64> {
        self.authority_expires_nanoseconds
            .checked_add(self.maximum_clock_skew_nanoseconds)
    }
}

/// Models caller-asserted evidence that a prior owner was stopped.
///
/// This simulation value is not a production stop-proof verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopProof {
    prior_assignment: AssignmentClaim,
    prior_lease_digest: ObjectDigest,
}

impl StopProof {
    /// Constructs simulated evidence bound to a prior assignment and lease.
    #[must_use]
    pub const fn new(prior_assignment: AssignmentClaim, prior_lease_digest: ObjectDigest) -> Self {
        Self {
            prior_assignment,
            prior_lease_digest,
        }
    }

    fn matches(self, assignment: AssignmentClaim, lease_digest: ObjectDigest) -> bool {
        self.prior_assignment.lease_identity_matches(assignment)
            && self.prior_lease_digest == lease_digest
    }
}

/// Reports a rejected assignment, lease, or shared-endpoint operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FencingError {
    /// A lease has an invalid generation, interval, or nonce.
    #[error("ownership lease is structurally invalid")]
    InvalidLease,
    /// State names a different logical sandbox than the durable fence.
    #[error("fencing state belongs to another sandbox")]
    WrongSandbox,
    /// An assignment was delivered to a node other than its named owner.
    #[error("assignment names another node")]
    WrongNode,
    /// An older epoch, generation, or lease generation was presented.
    #[error("assignment or lease is stale")]
    Stale,
    /// Equal ordering counters carried different semantic bytes.
    #[error("equal fencing counters carry conflicting semantics")]
    Equivocation,
    /// A lease does not bind the exact accepted semantic assignment.
    #[error("ownership lease does not match the accepted assignment")]
    LeaseAssignmentMismatch,
    /// Authority time or the conservative skew window makes a lease inactive.
    #[error("ownership lease is not conservatively live")]
    LeaseNotLive,
    /// Local fail-stop deadline conversion overflowed.
    #[error("local fail-stop deadline overflowed")]
    DeadlineOverflow,
    /// A reboot invalidated a previously armed local deadline.
    #[error("host boot identity does not match the armed lease")]
    HostBootChanged,
    /// The local fail-stop deadline has expired.
    #[error("local fail-stop deadline has expired")]
    FailStopExpired,
    /// A newer owner lacks expiry or exact authoritative-stop evidence.
    #[error("prior owner has not been authoritatively fenced")]
    PriorOwnerNotFenced,
    /// A mutation token is not the endpoint's current owner and lease.
    #[error("shared endpoint rejected a stale ownership token")]
    EndpointTokenMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArmedLease {
    lease: OwnershipLease,
    host_boot_id: [u8; 16],
    fail_stop_boottime_nanoseconds: u64,
}

/// Models one node's durable assignment and guardian admission fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeFence {
    local_node: NodeId,
    accepted: Option<AssignmentClaim>,
    armed: Option<ArmedLease>,
}

impl NodeFence {
    /// Constructs an empty durable fence for one node identity.
    #[must_use]
    pub const fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            accepted: None,
            armed: None,
        }
    }

    /// Durably accepts a monotone assignment tuple before effects.
    ///
    /// # Errors
    ///
    /// Returns [`FencingError`] for a wrong node, wrong sandbox, stale tuple,
    /// or equal epoch/generation with different semantic bytes.
    pub fn accept_assignment(
        &mut self,
        proposed: AssignmentClaim,
    ) -> Result<ApplyOutcome, FencingError> {
        if proposed.node != self.local_node {
            return Err(FencingError::WrongNode);
        }
        let Some(current) = self.accepted else {
            self.accepted = Some(proposed);
            return Ok(ApplyOutcome::Applied);
        };
        if proposed.sandbox != current.sandbox {
            return Err(FencingError::WrongSandbox);
        }
        if proposed.epoch < current.epoch {
            return Err(FencingError::Stale);
        }
        if proposed.epoch == current.epoch {
            if proposed.incarnation != current.incarnation || proposed.node != current.node {
                return Err(FencingError::Equivocation);
            }
            if proposed.desired_generation < current.desired_generation {
                return Err(FencingError::Stale);
            }
            if proposed.desired_generation == current.desired_generation {
                return if proposed.assignment_digest == current.assignment_digest {
                    Ok(ApplyOutcome::Replay)
                } else {
                    Err(FencingError::Equivocation)
                };
            }
        }

        self.accepted = Some(proposed);
        self.armed = None;
        Ok(ApplyOutcome::Applied)
    }

    /// Arms or renews a boot-bound local fail-stop deadline.
    ///
    /// # Errors
    ///
    /// Returns [`FencingError`] when no exact assignment is accepted, the
    /// lease is stale, conflicting, or not conservatively live, the boot ID is
    /// zero, or deadline arithmetic overflows.
    pub fn arm_lease(
        &mut self,
        lease: OwnershipLease,
        authority_now_nanoseconds: u64,
        boottime_now_nanoseconds: u64,
        safety_margin_nanoseconds: u64,
        host_boot_id: [u8; 16],
    ) -> Result<ApplyOutcome, FencingError> {
        let accepted = self.accepted.ok_or(FencingError::LeaseAssignmentMismatch)?;
        if !accepted.lease_identity_matches(lease.assignment) {
            return Err(FencingError::LeaseAssignmentMismatch);
        }
        if host_boot_id.iter().all(|byte| *byte == 0)
            || !lease.conservatively_live_at(authority_now_nanoseconds)
        {
            return Err(FencingError::LeaseNotLive);
        }
        if let Some(armed) = self.armed {
            if lease.generation < armed.lease.generation {
                return Err(FencingError::Stale);
            }
            if lease.generation == armed.lease.generation {
                return if lease == armed.lease && host_boot_id == armed.host_boot_id {
                    Ok(ApplyOutcome::Replay)
                } else {
                    Err(FencingError::Equivocation)
                };
            }
        }

        let authority_deadline = lease
            .authority_expires_nanoseconds
            .checked_sub(lease.maximum_clock_skew_nanoseconds)
            .and_then(|deadline| deadline.checked_sub(safety_margin_nanoseconds))
            .ok_or(FencingError::LeaseNotLive)?;
        let remaining = authority_deadline
            .checked_sub(authority_now_nanoseconds)
            .ok_or(FencingError::LeaseNotLive)?;
        let fail_stop_boottime_nanoseconds = boottime_now_nanoseconds
            .checked_add(remaining)
            .ok_or(FencingError::DeadlineOverflow)?;
        self.armed = Some(ArmedLease {
            lease,
            host_boot_id,
            fail_stop_boottime_nanoseconds,
        });
        Ok(ApplyOutcome::Applied)
    }

    /// Checks whether the guardian may admit one assignment-scoped effect.
    ///
    /// # Errors
    ///
    /// Returns [`FencingError`] after reboot or deadline expiry, or when the
    /// presented assignment and lease token are not the exact armed values.
    pub fn admit_effect(
        &self,
        assignment: AssignmentClaim,
        lease_generation: u64,
        lease_digest: ObjectDigest,
        host_boot_id: [u8; 16],
        boottime_now_nanoseconds: u64,
    ) -> Result<(), FencingError> {
        let armed = self.armed.ok_or(FencingError::EndpointTokenMismatch)?;
        if host_boot_id != armed.host_boot_id {
            return Err(FencingError::HostBootChanged);
        }
        if boottime_now_nanoseconds >= armed.fail_stop_boottime_nanoseconds {
            return Err(FencingError::FailStopExpired);
        }
        if !armed.lease.assignment.lease_identity_matches(assignment)
            || armed.lease.generation != lease_generation
            || armed.lease.lease_digest != lease_digest
        {
            return Err(FencingError::EndpointTokenMismatch);
        }
        Ok(())
    }
}

/// Models the current fencing token at one mutable shared endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedEndpointFence {
    owner: Option<OwnershipLease>,
}

impl SharedEndpointFence {
    /// Returns the endpoint's current ownership lease, if assigned.
    #[must_use]
    pub const fn owner(self) -> Option<OwnershipLease> {
        self.owner
    }

    fn accept(
        &mut self,
        proposed: OwnershipLease,
        authority_now_nanoseconds: u64,
        stop_proof: Option<StopProof>,
    ) -> Result<ApplyOutcome, FencingError> {
        if !proposed.conservatively_live_at(authority_now_nanoseconds) {
            return Err(FencingError::LeaseNotLive);
        }
        let Some(current) = self.owner else {
            self.owner = Some(proposed);
            return Ok(ApplyOutcome::Applied);
        };
        if proposed.assignment.sandbox != current.assignment.sandbox {
            return Err(FencingError::WrongSandbox);
        }
        if proposed.assignment.epoch < current.assignment.epoch {
            return Err(FencingError::Stale);
        }
        if proposed.assignment.epoch == current.assignment.epoch {
            if !proposed
                .assignment
                .lease_identity_matches(current.assignment)
            {
                return Err(FencingError::Equivocation);
            }
            if proposed.generation < current.generation {
                return Err(FencingError::Stale);
            }
            if proposed.generation == current.generation {
                return if proposed == current {
                    Ok(ApplyOutcome::Replay)
                } else {
                    Err(FencingError::Equivocation)
                };
            }
            self.owner = Some(proposed);
            return Ok(ApplyOutcome::Applied);
        }

        let expired = current
            .supersession_time()
            .is_some_and(|deadline| authority_now_nanoseconds >= deadline);
        let stopped =
            stop_proof.is_some_and(|proof| proof.matches(current.assignment, current.lease_digest));
        if !expired && !stopped {
            return Err(FencingError::PriorOwnerNotFenced);
        }

        self.owner = Some(proposed);
        Ok(ApplyOutcome::Applied)
    }

    /// Checks an exact lease token before one shared mutation.
    ///
    /// # Errors
    ///
    /// Returns [`FencingError`] if the token is stale or the current lease is
    /// outside its conservative authority-time window.
    pub fn admit_mutation(
        &self,
        assignment: AssignmentClaim,
        lease_generation: u64,
        lease_digest: ObjectDigest,
        authority_now_nanoseconds: u64,
    ) -> Result<(), FencingError> {
        let owner = self.owner.ok_or(FencingError::EndpointTokenMismatch)?;
        if !owner.conservatively_live_at(authority_now_nanoseconds) {
            return Err(FencingError::LeaseNotLive);
        }
        if !owner.assignment.lease_identity_matches(assignment)
            || owner.generation != lease_generation
            || owner.lease_digest != lease_digest
        {
            return Err(FencingError::EndpointTokenMismatch);
        }
        Ok(())
    }
}

/// Applies ownership changes atomically across every shared endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSet {
    endpoints: Vec<SharedEndpointFence>,
}

impl EndpointSet {
    /// Constructs an unowned set with a fixed endpoint count.
    #[must_use]
    pub fn new(endpoint_count: usize) -> Self {
        Self {
            endpoints: vec![SharedEndpointFence::default(); endpoint_count],
        }
    }

    /// Returns the individual endpoint fences for inventory and assertions.
    #[must_use]
    pub fn endpoints(&self) -> &[SharedEndpointFence] {
        &self.endpoints
    }

    /// Atomically transfers all endpoint fences to an ownership lease.
    ///
    /// Validation runs on a private copy and commits only if every endpoint
    /// accepts, preventing partial publication from granting ownership.
    ///
    /// # Errors
    ///
    /// Returns the first endpoint's [`FencingError`] without modifying any
    /// endpoint in the set.
    pub fn transfer(
        &mut self,
        proposed: OwnershipLease,
        authority_now_nanoseconds: u64,
        stop_proof: Option<StopProof>,
    ) -> Result<ApplyOutcome, FencingError> {
        let mut proposed_endpoints = self.endpoints.clone();
        let mut outcome = ApplyOutcome::Replay;
        for endpoint in &mut proposed_endpoints {
            if endpoint.accept(proposed, authority_now_nanoseconds, stop_proof)?
                == ApplyOutcome::Applied
            {
                outcome = ApplyOutcome::Applied;
            }
        }
        self.endpoints = proposed_endpoints;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_A: [u8; 16] = [0xa1; 16];
    const BOOT_B: [u8; 16] = [0xb1; 16];

    fn id<const N: usize>(byte: u8) -> [u8; N] {
        [byte; N]
    }

    fn claim(node: u8, epoch: u64, generation: u64, digest: u8) -> AssignmentClaim {
        AssignmentClaim::new(
            SandboxId::from_bytes(id(1)),
            IncarnationId::from_bytes(id(node)),
            NodeId::from_bytes(id(node)),
            AssignmentEpoch::new(epoch),
            DesiredGeneration::new(generation),
            ObjectDigest::from_bytes(id(digest)),
        )
    }

    fn lease(
        assignment: AssignmentClaim,
        generation: u64,
        issued: u64,
        expires: u64,
        skew: u64,
        digest: u8,
    ) -> OwnershipLease {
        OwnershipLease::new_verified(
            assignment,
            generation,
            issued,
            expires,
            skew,
            id(digest),
            ObjectDigest::from_bytes(id(digest)),
        )
        .unwrap_or_else(|error| panic!("test lease failed: {error}"))
    }

    #[test]
    fn stale_coordinator_and_equal_counter_equivocation_fail_closed() {
        let local = NodeId::from_bytes(id(2));
        let mut fence = NodeFence::new(local);
        let current = claim(2, 8, 4, 0x84);
        assert_eq!(fence.accept_assignment(current), Ok(ApplyOutcome::Applied));
        assert_eq!(fence.accept_assignment(current), Ok(ApplyOutcome::Replay));
        assert_eq!(
            fence.accept_assignment(claim(2, 7, 99, 0x79)),
            Err(FencingError::Stale)
        );
        assert_eq!(
            fence.accept_assignment(claim(2, 8, 4, 0x85)),
            Err(FencingError::Equivocation)
        );
        assert_eq!(
            fence.accept_assignment(claim(3, 9, 1, 0x91)),
            Err(FencingError::WrongNode)
        );
    }

    #[test]
    fn guardian_deadline_is_conservative_and_invalid_after_reboot() {
        let assignment = claim(2, 1, 1, 0x11);
        let ownership = lease(assignment, 1, 1_000, 2_000, 100, 0x21);
        let mut fence = NodeFence::new(assignment.node());
        assert_eq!(
            fence.accept_assignment(assignment),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            fence.arm_lease(ownership, 1_200, 5_000, 50, BOOT_A),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            fence.admit_effect(assignment, 1, ownership.lease_digest(), BOOT_A, 5_649),
            Ok(())
        );
        assert_eq!(
            fence.admit_effect(assignment, 1, ownership.lease_digest(), BOOT_A, 5_650),
            Err(FencingError::FailStopExpired)
        );
        assert_eq!(
            fence.admit_effect(assignment, 1, ownership.lease_digest(), BOOT_B, 5_100),
            Err(FencingError::HostBootChanged)
        );
    }

    #[test]
    fn partition_cannot_create_two_shared_mutation_owners() {
        let old_assignment = claim(2, 1, 1, 0x11);
        let old_lease = lease(old_assignment, 1, 1_000, 2_000, 100, 0x21);
        let new_assignment = claim(3, 2, 1, 0x31);
        let new_lease = lease(new_assignment, 1, 1_500, 3_000, 100, 0x41);
        let mut endpoints = EndpointSet::new(4);

        assert_eq!(
            endpoints.transfer(old_lease, 1_200, None),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            endpoints.transfer(new_lease, 1_600, None),
            Err(FencingError::PriorOwnerNotFenced)
        );
        for endpoint in endpoints.endpoints() {
            assert_eq!(
                endpoint.admit_mutation(
                    old_assignment,
                    old_lease.generation(),
                    old_lease.lease_digest(),
                    1_600,
                ),
                Ok(())
            );
        }

        assert_eq!(
            endpoints.transfer(new_lease, 2_100, None),
            Ok(ApplyOutcome::Applied)
        );
        for endpoint in endpoints.endpoints() {
            assert_eq!(
                endpoint.admit_mutation(
                    old_assignment,
                    old_lease.generation(),
                    old_lease.lease_digest(),
                    1_900,
                ),
                Err(FencingError::EndpointTokenMismatch)
            );
            assert_eq!(
                endpoint.admit_mutation(
                    new_assignment,
                    new_lease.generation(),
                    new_lease.lease_digest(),
                    2_100,
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn exact_stop_proof_allows_early_transfer_but_stale_proof_does_not() {
        let old_assignment = claim(2, 1, 1, 0x11);
        let old_lease = lease(old_assignment, 1, 1_000, 2_000, 100, 0x21);
        let new_assignment = claim(3, 2, 1, 0x31);
        let new_lease = lease(new_assignment, 1, 1_500, 3_000, 100, 0x41);
        let mut endpoints = EndpointSet::new(2);
        assert!(endpoints.transfer(old_lease, 1_200, None).is_ok());

        let stale = StopProof::new(old_assignment, ObjectDigest::from_bytes(id(0x22)));
        assert_eq!(
            endpoints.transfer(new_lease, 1_600, Some(stale)),
            Err(FencingError::PriorOwnerNotFenced)
        );
        let exact = StopProof::new(old_assignment, old_lease.lease_digest());
        assert_eq!(
            endpoints.transfer(new_lease, 1_600, Some(exact)),
            Ok(ApplyOutcome::Applied)
        );
    }

    #[test]
    fn endpoint_transfer_rolls_back_when_any_endpoint_rejects() {
        let old_assignment = claim(2, 1, 1, 0x11);
        let old_lease = lease(old_assignment, 1, 1_000, 2_000, 100, 0x21);
        let future_assignment = claim(3, 3, 1, 0x31);
        let future_lease = lease(future_assignment, 1, 3_000, 4_000, 100, 0x41);
        let proposed_assignment = claim(4, 2, 1, 0x51);
        let proposed_lease = lease(proposed_assignment, 1, 2_100, 3_500, 100, 0x61);
        let mut endpoints = EndpointSet::new(2);
        assert!(endpoints.transfer(old_lease, 1_200, None).is_ok());
        endpoints.endpoints[1]
            .accept(
                future_lease,
                3_100,
                Some(StopProof::new(old_assignment, old_lease.lease_digest())),
            )
            .unwrap_or_else(|error| panic!("fixture transfer failed: {error}"));
        let before = endpoints.clone();

        assert_eq!(
            endpoints.transfer(
                proposed_lease,
                2_200,
                Some(StopProof::new(old_assignment, old_lease.lease_digest()))
            ),
            Err(FencingError::Stale)
        );
        assert_eq!(endpoints, before);
    }
}
