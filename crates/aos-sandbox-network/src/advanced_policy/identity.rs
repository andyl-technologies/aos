//! Immutable physical allocation and replaceable policy revision identity.
//!
//! Opaque witnesses are minted only from a protected owner's journal head.
//! Recovery bytes never mint them: decoding rebinds every serialized witness
//! to an exact handle in a bounded protected-owner authority set whose current
//! checkpoint is an exact journal successor. Public policy callers can retain
//! witnesses but cannot construct them or inspect their scalar coordinates.

use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, NodeId, ObjectDigest,
    ProjectId, SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::allocation::{NetworkIpAddressV1, NetworkNamespacePlanV1};
use crate::policy::NetworkIpPrefixV1;

use super::{AdvancedNetworkPolicyError, nonzero_digest};

const PHYSICAL_DOMAIN: &[u8] = b"aos.sandbox.network.physical-allocation.v1\0";
const REVISION_DOMAIN: &[u8] = b"aos.sandbox.network.policy-revision.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.network.advanced-identity.v2\0";
const WITNESS_HEAD_DOMAIN: &[u8] = b"aos.sandbox.network.protected-head.v1\0";
const MAXIMUM_RECOVERY_AUTHORITY_HANDLES: usize = 8_192;

/// Separates protected heads that are not interchangeable authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProtectedWitnessPurposeV1 {
    Assignment,
    Discovery,
    Capabilities,
    IngressPool,
    IngressRegistry,
    Quota,
    KernelObservation,
    CombinedTransaction,
    RecoveryAuthority,
    RecoveryCheckpoint,
}

/// Carries a protected owner's opaque journal coordinate inside this crate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ProtectedJournalIdentityV1 {
    owner: ObjectDigest,
    namespace: ObjectDigest,
    journal: ObjectDigest,
}

impl ProtectedJournalIdentityV1 {
    pub(crate) fn seal(
        owner: ObjectDigest,
        namespace: ObjectDigest,
        journal: ObjectDigest,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !nonzero_digest(owner) || !nonzero_digest(namespace) || !nonzero_digest(journal) {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        Ok(Self {
            owner,
            namespace,
            journal,
        })
    }
}

impl core::fmt::Debug for ProtectedJournalIdentityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedJournalIdentityV1(..)")
    }
}

/// Commits one current protected record without exposing its journal key.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtectedCurrentnessWitnessV1 {
    purpose: ProtectedWitnessPurposeV1,
    owner: ObjectDigest,
    namespace: ObjectDigest,
    journal: ObjectDigest,
    sequence: u64,
    predecessor_head: ObjectDigest,
    current_head: ObjectDigest,
    record_digest: ObjectDigest,
}

/// Retains opaque protected-owner handles admitted for one recovery decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRecoveryAuthoritiesV1 {
    checkpoint: ProtectedCurrentnessWitnessV1,
    checkpoint_predecessor: ProtectedCurrentnessWitnessV1,
    witnesses: Vec<ProtectedCurrentnessWitnessV1>,
}

impl core::fmt::Debug for ProtectedCurrentnessWitnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedCurrentnessWitnessV1(..)")
    }
}

impl ProtectedCurrentnessWitnessV1 {
    pub(crate) fn mint(
        purpose: ProtectedWitnessPurposeV1,
        identity: ProtectedJournalIdentityV1,
        sequence: u64,
        predecessor_head: ObjectDigest,
        record_digest: ObjectDigest,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if sequence == 0
            || !nonzero_digest(record_digest)
            || (sequence == 1) != !nonzero_digest(predecessor_head)
        {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        let ProtectedJournalIdentityV1 {
            owner,
            namespace,
            journal,
        } = identity;
        let current_head = witness_head(
            purpose,
            owner,
            namespace,
            journal,
            sequence,
            predecessor_head,
            record_digest,
        );
        Ok(Self {
            purpose,
            owner,
            namespace,
            journal,
            sequence,
            predecessor_head,
            current_head,
            record_digest,
        })
    }

    pub(crate) const fn sequence(self) -> u64 {
        self.sequence
    }

    pub(crate) const fn record_digest(self) -> ObjectDigest {
        self.record_digest
    }

    pub(crate) const fn current_head(self) -> ObjectDigest {
        self.current_head
    }

    pub(crate) const fn purpose(self) -> ProtectedWitnessPurposeV1 {
        self.purpose
    }

    pub(crate) const fn namespace(self) -> ObjectDigest {
        self.namespace
    }

    pub(crate) fn protected_source_key(self) -> [u8; 33] {
        protected_source_key(self.purpose, self.namespace)
    }

    pub(crate) fn is_exact_successor_of(self, prior: Self) -> bool {
        self.purpose == prior.purpose
            && self.owner == prior.owner
            && self.namespace == prior.namespace
            && self.journal == prior.journal
            && prior.sequence.checked_add(1) == Some(self.sequence)
            && self.predecessor_head == prior.current_head
    }

    pub(crate) fn is_exact_journal_successor_of(self, prior: Self) -> bool {
        self.owner == prior.owner
            && self.namespace == prior.namespace
            && self.journal == prior.journal
            && prior.sequence.checked_add(1) == Some(self.sequence)
            && self.predecessor_head == prior.current_head
    }

    pub(crate) fn is_later_in_same_journal(self, prior: Self) -> bool {
        self.owner == prior.owner
            && self.namespace == prior.namespace
            && self.journal == prior.journal
            && self.sequence > prior.sequence
    }

    pub(crate) const fn belongs_to(self, identity: ProtectedJournalIdentityV1) -> bool {
        self.owner == identity.owner
            && self.namespace == identity.namespace
            && self.journal == identity.journal
    }

    pub(crate) fn encode_recovery(self) -> [u8; 201] {
        let mut bytes = [0; 201];
        bytes[0] = witness_purpose_code(self.purpose);
        bytes[1..33].copy_from_slice(self.owner.as_bytes());
        bytes[33..65].copy_from_slice(self.namespace.as_bytes());
        bytes[65..97].copy_from_slice(self.journal.as_bytes());
        bytes[97..105].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[105..137].copy_from_slice(self.predecessor_head.as_bytes());
        bytes[137..169].copy_from_slice(self.current_head.as_bytes());
        bytes[169..201].copy_from_slice(self.record_digest.as_bytes());
        bytes
    }

    pub(crate) fn rebind_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() != 201 {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        authorities.rebind(bytes)
    }

    pub(crate) fn decode_protected_record(
        bytes: &[u8],
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() != 201 {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let purpose =
            protected_witness_purpose(bytes[0]).ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let identity = ProtectedJournalIdentityV1::seal(
            ObjectDigest::from_bytes(copy_array(&bytes[1..33])?),
            ObjectDigest::from_bytes(copy_array(&bytes[33..65])?),
            ObjectDigest::from_bytes(copy_array(&bytes[65..97])?),
        )?;
        let sequence = u64::from_be_bytes(copy_array(&bytes[97..105])?);
        let predecessor_head = ObjectDigest::from_bytes(copy_array(&bytes[105..137])?);
        let record_digest = ObjectDigest::from_bytes(copy_array(&bytes[169..201])?);
        let witness = Self::mint(purpose, identity, sequence, predecessor_head, record_digest)?;
        if witness.current_head.as_bytes() != &bytes[137..169] {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(witness)
    }
}

pub(crate) fn protected_source_key(
    purpose: ProtectedWitnessPurposeV1,
    namespace: ObjectDigest,
) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = witness_purpose_code(purpose);
    key[1..].copy_from_slice(namespace.as_bytes());
    key
}

impl ProtectedRecoveryAuthoritiesV1 {
    pub(crate) fn from_protected_owner(
        checkpoint: ProtectedCurrentnessWitnessV1,
        checkpoint_predecessor: ProtectedCurrentnessWitnessV1,
        mut witnesses: Vec<ProtectedCurrentnessWitnessV1>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if checkpoint.purpose != ProtectedWitnessPurposeV1::RecoveryCheckpoint
            || !matches!(
                checkpoint_predecessor.purpose,
                ProtectedWitnessPurposeV1::CombinedTransaction
                    | ProtectedWitnessPurposeV1::RecoveryCheckpoint
            )
            || !checkpoint.is_exact_journal_successor_of(checkpoint_predecessor)
            || witnesses.len() > MAXIMUM_RECOVERY_AUTHORITY_HANDLES
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        witnesses.sort_unstable_by_key(|witness| witness.encode_recovery());
        if witnesses
            .windows(2)
            .any(|pair| pair[0].encode_recovery() == pair[1].encode_recovery())
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Self {
            checkpoint,
            checkpoint_predecessor,
            witnesses,
        })
    }

    fn rebind(
        &self,
        bytes: &[u8],
    ) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError> {
        self.witnesses
            .binary_search_by(|witness| witness.encode_recovery().as_slice().cmp(bytes))
            .ok()
            .and_then(|index| self.witnesses.get(index).copied())
            .ok_or(AdvancedNetworkPolicyError::StaleAuthority)
    }

    pub(crate) const fn checkpoint(&self) -> ProtectedCurrentnessWitnessV1 {
        self.checkpoint
    }

    pub(crate) const fn checkpoint_predecessor(&self) -> ProtectedCurrentnessWitnessV1 {
        self.checkpoint_predecessor
    }
}

/// Identifies one immutable physical namespace allocation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkAllocationIdentityV1 {
    generation: u64,
    network_handle: [u8; 32],
    physical_shape_digest: ObjectDigest,
    host_mac: Option<[u8; 6]>,
    sandbox_mac: Option<[u8; 6]>,
    digest: ObjectDigest,
}

impl NetworkAllocationIdentityV1 {
    /// Reconstructs physical identity from an existing namespace plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::Unspecified`] for a sentinel
    /// plan field.
    pub fn from_namespace_plan(
        plan: &NetworkNamespacePlanV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if plan.allocation_generation() == 0 || plan.network_handle() == &[0; 32] {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        let physical_shape_digest = physical_shape_digest(plan);
        let digest = physical_digest(
            plan.allocation_generation(),
            *plan.network_handle(),
            physical_shape_digest,
        );
        Ok(Self {
            generation: plan.allocation_generation(),
            network_handle: *plan.network_handle(),
            physical_shape_digest,
            host_mac: plan.host_mac().map(|value| value.octets()),
            sandbox_mac: plan.sandbox_mac().map(|value| value.octets()),
            digest,
        })
    }

    /// Returns the never-reused protected allocation generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the opaque allocation handle.
    #[must_use]
    pub const fn network_handle(self) -> [u8; 32] {
        self.network_handle
    }

    /// Returns the immutable namespace/link/address shape commitment.
    #[must_use]
    pub const fn physical_shape_digest(self) -> ObjectDigest {
        self.physical_shape_digest
    }

    /// Returns the immutable host-side link MAC, when a veth exists.
    #[must_use]
    pub const fn host_mac(self) -> Option<[u8; 6]> {
        self.host_mac
    }

    /// Returns the immutable sandbox-side link MAC, when a veth exists.
    #[must_use]
    pub const fn sandbox_mac(self) -> Option<[u8; 6]> {
        self.sandbox_mac
    }

    /// Returns the physical identity commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }

    /// Checks exact agreement with a freshly supplied namespace plan.
    #[must_use]
    pub fn matches_namespace_plan(self, plan: &NetworkNamespacePlanV1) -> bool {
        self.generation == plan.allocation_generation()
            && self.network_handle == *plan.network_handle()
            && self.physical_shape_digest == physical_shape_digest(plan)
    }
}

/// Names one replaceable assignment-bound policy revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkPolicyRevisionV1 {
    assignment: BrokerAssignment,
    revision: u64,
    currentness: ProtectedCurrentnessWitnessV1,
    digest: ObjectDigest,
}

impl NetworkPolicyRevisionV1 {
    /// Constructs a revision under exact protected assignment state.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::StaleAuthority`] unless the
    /// witness commits the assignment, or when the revision is zero.
    pub(crate) fn new(
        assignment: BrokerAssignment,
        revision: u64,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if revision == 0
            || currentness.purpose != ProtectedWitnessPurposeV1::Assignment
            || currentness.namespace != assignment_namespace(assignment)
            || currentness.record_digest != assignment.digest()
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let digest = revision_digest(assignment, revision, currentness);
        Ok(Self {
            assignment,
            revision,
            currentness,
            digest,
        })
    }

    /// Returns the exact broker assignment.
    #[must_use]
    pub const fn assignment(self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the allocation-local policy revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns protected assignment-currentness evidence.
    #[must_use]
    pub const fn currentness(self) -> ProtectedCurrentnessWitnessV1 {
        self.currentness
    }

    /// Returns the revision commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Binds a policy revision to project and immutable physical allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvancedNetworkIdentityV1 {
    project: ProjectId,
    physical: NetworkAllocationIdentityV1,
    revision: NetworkPolicyRevisionV1,
    digest: ObjectDigest,
}

impl AdvancedNetworkIdentityV1 {
    /// Constructs one complete advanced Network identity.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::Unspecified`] for a sentinel
    /// project identity.
    pub fn new(
        project: ProjectId,
        physical: NetworkAllocationIdentityV1,
        revision: NetworkPolicyRevisionV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if project.as_bytes() == &[0; 16] {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        let digest = identity_digest(project, physical, revision);
        Ok(Self {
            project,
            physical,
            revision,
            digest,
        })
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns immutable physical allocation identity.
    #[must_use]
    pub const fn physical(&self) -> NetworkAllocationIdentityV1 {
        self.physical
    }

    /// Returns the replaceable policy revision.
    #[must_use]
    pub const fn revision(&self) -> NetworkPolicyRevisionV1 {
        self.revision
    }

    /// Returns the exact broker assignment.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.revision.assignment
    }

    /// Returns the complete identity commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Reports whether another revision names the same physical allocation.
    #[must_use]
    pub fn has_same_allocation_scope(&self, other: &Self) -> bool {
        self.project == other.project
            && self.assignment().sandbox() == other.assignment().sandbox()
            && self.assignment().incarnation() == other.assignment().incarnation()
            && self.physical == other.physical
    }

    /// Reports whether `candidate` is a strictly newer fenced revision.
    #[must_use]
    pub fn admits_successor(&self, candidate: &Self) -> bool {
        if !self.has_same_allocation_scope(candidate)
            || self.revision.revision.checked_add(1) != Some(candidate.revision.revision)
            || !candidate
                .revision
                .currentness
                .is_later_in_same_journal(self.revision.currentness)
            || self.assignment().digest() == candidate.assignment().digest()
        {
            return false;
        }
        let old_epoch = self.assignment().epoch();
        let new_epoch = candidate.assignment().epoch();
        new_epoch > old_epoch
            || (new_epoch == old_epoch
                && candidate.assignment().desired_generation()
                    > self.assignment().desired_generation())
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(398);
        bytes.extend_from_slice(b"AOSANI01");
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.physical.generation.to_be_bytes());
        bytes.extend_from_slice(&self.physical.network_handle);
        bytes.extend_from_slice(self.physical.physical_shape_digest.as_bytes());
        let macs_present = self.physical.host_mac.is_some() && self.physical.sandbox_mac.is_some();
        bytes.push(u8::from(macs_present));
        bytes.extend_from_slice(&self.physical.host_mac.unwrap_or([0; 6]));
        bytes.extend_from_slice(&self.physical.sandbox_mac.unwrap_or([0; 6]));
        let assignment = self.revision.assignment;
        bytes.extend_from_slice(assignment.sandbox().as_bytes());
        bytes.extend_from_slice(assignment.incarnation().as_bytes());
        bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
        bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
        bytes.extend_from_slice(assignment.digest().as_bytes());
        bytes.extend_from_slice(&self.revision.revision.to_be_bytes());
        bytes.extend_from_slice(&self.revision.currentness.encode_recovery());
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() != 398 || bytes.get(..8) != Some(b"AOSANI01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let project = ProjectId::from_bytes(copy_array(&bytes[8..24])?);
        let generation = u64::from_be_bytes(copy_array(&bytes[24..32])?);
        let handle = copy_array(&bytes[32..64])?;
        let shape = ObjectDigest::from_bytes(copy_array(&bytes[64..96])?);
        let macs_present = match bytes[96] {
            0 => false,
            1 => true,
            _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
        };
        let host_mac = copy_array(&bytes[97..103])?;
        let sandbox_mac = copy_array(&bytes[103..109])?;
        if !macs_present && (host_mac != [0; 6] || sandbox_mac != [0; 6]) {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        if generation == 0
            || handle == [0; 32]
            || !nonzero_digest(shape)
            || (macs_present
                && (host_mac == [0; 6]
                    || sandbox_mac == [0; 6]
                    || host_mac == sandbox_mac
                    || host_mac[0] & 0x03 != 0x02
                    || sandbox_mac[0] & 0x03 != 0x02))
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let physical_digest = physical_digest(generation, handle, shape);
        let physical = NetworkAllocationIdentityV1 {
            generation,
            network_handle: handle,
            physical_shape_digest: shape,
            host_mac: macs_present.then_some(host_mac),
            sandbox_mac: macs_present.then_some(sandbox_mac),
            digest: physical_digest,
        };
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes(copy_array(&bytes[109..125])?),
            IncarnationId::from_bytes(copy_array(&bytes[125..141])?),
            AssignmentEpoch::new(u64::from_be_bytes(copy_array(&bytes[141..149])?)),
            DesiredGeneration::new(u64::from_be_bytes(copy_array(&bytes[149..157])?)),
            ObjectDigest::from_bytes(copy_array(&bytes[157..189])?),
        )
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        let revision_number = u64::from_be_bytes(copy_array(&bytes[189..197])?);
        let witness =
            ProtectedCurrentnessWitnessV1::rebind_recovery(&bytes[197..398], authorities)?;
        let revision = NetworkPolicyRevisionV1::new(assignment, revision_number, witness)?;
        let identity = Self::new(project, physical, revision)?;
        if identity.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(identity)
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AdvancedNetworkPolicyError> {
    bytes
        .try_into()
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
}

fn physical_digest(
    generation: u64,
    handle: [u8; 32],
    physical_shape: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(PHYSICAL_DOMAIN);
    digest.update(generation.to_be_bytes());
    digest.update(handle);
    digest.update(physical_shape.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn physical_shape_digest(plan: &NetworkNamespacePlanV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.physical-shape.v1\0");
    digest.update([u8::from(plan.mtu().is_some())]);
    digest.update(plan.mtu().map_or(0, |value| value).to_be_bytes());
    digest.update(plan.host_mac().map_or([0; 6], |value| value.octets()));
    digest.update(plan.sandbox_mac().map_or([0; 6], |value| value.octets()));
    digest.update((plan.address_pairs().len() as u16).to_be_bytes());
    for pair in plan.address_pairs() {
        digest.update(encode_address(pair.host()));
        digest.update(encode_address(pair.sandbox()));
        digest.update([pair.prefix_length()]);
    }
    digest.update((plan.routes().len() as u16).to_be_bytes());
    for route in plan.routes() {
        digest.update(encode_prefix(route.destination()));
        digest.update(encode_address(route.gateway()));
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_address(value: NetworkIpAddressV1) -> [u8; 17] {
    let mut bytes = [0; 17];
    match value {
        NetworkIpAddressV1::Ipv4(address) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&address);
        }
        NetworkIpAddressV1::Ipv6(address) => {
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&address);
        }
    }
    bytes
}

fn encode_prefix(value: NetworkIpPrefixV1) -> [u8; 18] {
    let mut bytes = [0; 18];
    match value {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => {
            bytes[0] = 4;
            bytes[1] = prefix_length;
            bytes[2..6].copy_from_slice(&network);
        }
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => {
            bytes[0] = 6;
            bytes[1] = prefix_length;
            bytes[2..18].copy_from_slice(&network);
        }
    }
    bytes
}

fn revision_digest(
    assignment: BrokerAssignment,
    revision: u64,
    witness: ProtectedCurrentnessWitnessV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(REVISION_DOMAIN);
    digest.update(assignment.sandbox().as_bytes());
    digest.update(assignment.incarnation().as_bytes());
    digest.update(assignment.epoch().get().to_be_bytes());
    digest.update(assignment.desired_generation().get().to_be_bytes());
    digest.update(assignment.digest().as_bytes());
    digest.update(revision.to_be_bytes());
    digest.update(witness.current_head.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(crate) fn assignment_namespace(assignment: BrokerAssignment) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.assignment-namespace.v1\0");
    digest.update(assignment.sandbox().as_bytes());
    digest.update(assignment.incarnation().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(crate) fn project_namespace(project: ProjectId) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.project-namespace.v1\0");
    digest.update(project.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(crate) fn node_namespace(node: NodeId) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.node-namespace.v1\0");
    digest.update(node.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn witness_head(
    purpose: ProtectedWitnessPurposeV1,
    owner: ObjectDigest,
    namespace: ObjectDigest,
    journal: ObjectDigest,
    sequence: u64,
    predecessor_head: ObjectDigest,
    record: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(WITNESS_HEAD_DOMAIN);
    digest.update([witness_purpose_code(purpose)]);
    digest.update(owner.as_bytes());
    digest.update(namespace.as_bytes());
    digest.update(journal.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(predecessor_head.as_bytes());
    digest.update(record.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

const fn witness_purpose_code(value: ProtectedWitnessPurposeV1) -> u8 {
    match value {
        ProtectedWitnessPurposeV1::Assignment => 1,
        ProtectedWitnessPurposeV1::Discovery => 2,
        ProtectedWitnessPurposeV1::Capabilities => 3,
        ProtectedWitnessPurposeV1::IngressPool => 4,
        ProtectedWitnessPurposeV1::IngressRegistry => 5,
        ProtectedWitnessPurposeV1::Quota => 6,
        ProtectedWitnessPurposeV1::KernelObservation => 7,
        ProtectedWitnessPurposeV1::CombinedTransaction => 8,
        ProtectedWitnessPurposeV1::RecoveryAuthority => 9,
        ProtectedWitnessPurposeV1::RecoveryCheckpoint => 10,
    }
}

const fn protected_witness_purpose(value: u8) -> Option<ProtectedWitnessPurposeV1> {
    match value {
        1 => Some(ProtectedWitnessPurposeV1::Assignment),
        2 => Some(ProtectedWitnessPurposeV1::Discovery),
        3 => Some(ProtectedWitnessPurposeV1::Capabilities),
        4 => Some(ProtectedWitnessPurposeV1::IngressPool),
        5 => Some(ProtectedWitnessPurposeV1::IngressRegistry),
        6 => Some(ProtectedWitnessPurposeV1::Quota),
        7 => Some(ProtectedWitnessPurposeV1::KernelObservation),
        8 => Some(ProtectedWitnessPurposeV1::CombinedTransaction),
        9 => Some(ProtectedWitnessPurposeV1::RecoveryAuthority),
        10 => Some(ProtectedWitnessPurposeV1::RecoveryCheckpoint),
        _ => None,
    }
}

fn identity_digest(
    project: ProjectId,
    physical: NetworkAllocationIdentityV1,
    revision: NetworkPolicyRevisionV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(IDENTITY_DOMAIN);
    digest.update(project.as_bytes());
    digest.update(physical.digest.as_bytes());
    digest.update(revision.digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}
