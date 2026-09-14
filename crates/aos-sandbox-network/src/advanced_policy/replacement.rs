//! Crash-recoverable atomic replacement and durable recovery summaries.
//!
//! Preparation reserves protected node/project quota and the node-global
//! ingress registry before effects can be released. `EffectReleased` is an
//! irreversible ambiguity boundary: only a complete typed observation may
//! advance it, and mixed or absent state remains nonauthorizing until a later
//! observation proves an exact predecessor or candidate. Bare digests never
//! represent kernel success.
//!
//! The phase types, reducer, observation schema, and recovery codec remain
//! colocated so changes to an ambiguity transition cannot drift from the exact
//! durable phase and typed-observation representation used after restart.
//!
//! Durable indices use this fixed 376-byte canonical format:
//!
//! ```text
//! AOSANR01 | version:u16be | phase:u8 | flags:u8 | length:u32be
//! generation:u64be | operation-id[16] | active[32] | candidate[32]
//! registry[32] | quota[32] | combined-transaction[32]
//! baseline-observation[32] | outcome-observation[32]
//! pool[32] | capabilities[32] | recovery-attempt[32] | reserved-zero[16]
//! ```
//!
//! `flags` bit 0 announces the baseline and bit 1 announces the outcome; all
//! other bits and every absent commitment are zero. A separately protected
//! [`AdvancedNetworkRecoveryCompanionsV1`] retains the bounded typed objects;
//! rehydration requires byte-exact agreement with this index.
//!
//! Companion records use a bounded canonical envelope:
//!
//! ```text
//! AOSANC01 | version:u16be | reserved-zero:u16 | length:u32be
//! AOSANR01-index[376] | payload-length:u32be | payload-sha256[32] | payload[]
//! ```
//!
//! The payload codec reconstructs every retained typed object. Decode always
//! performs payload decode-reencode before accepting reconstructed state and
//! requires every serialized currentness value to match an opaque protected
//! owner handle. A distinct, nonserialized recovery-checkpoint handle binds the
//! complete companion bytes and an exact protected-journal predecessor.
//! Its payload begins with `AOSRPS01 | version:u16be | phase:u8 |
//! reserved-zero:u8`; the selected closed phase then contains length-prefixed
//! canonical component records. Required records reject zero lengths, optional
//! records use zero length for absence, and the 16 MiB envelope ceiling is
//! checked before any component allocation.

use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_core::{FeatureRef, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use crate::allocation::{NetworkAddressPairV1, NetworkIpAddressV1, NetworkRouteV1};
use crate::policy::NetworkPolicyProgramV1;

use super::compiler::CompiledAdvancedNetworkPolicyV1;
use super::identity::{
    ProtectedCurrentnessWitnessV1, ProtectedRecoveryAuthoritiesV1, ProtectedWitnessPurposeV1,
    node_namespace,
};
use super::ingress::{
    ExternalIngressRegistryV1, IngressPoolAuthorityV1, IngressRegistryCasV1,
    IngressTranslationPlanV1,
};
use super::quota::{ProtectedNetworkQuotaV1, ProtectedNetworkTransactionV1};
use super::{AdvancedNetworkPolicyError, nonzero_digest, strictly_increasing};

const CAPABILITY_DOMAIN: &[u8] = b"aos.sandbox.network.replacement-capabilities.v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.network.replacement-observation.v1\0";
const RECOVERY_AUTHORIZATION_DOMAIN: &[u8] = b"aos.sandbox.network.recovery-authorization.v1\0";
const RECOVERY_ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.network.recovery-attempt.v1\0";
const RECOVERY_CHECKPOINT_DOMAIN: &[u8] = b"aos.sandbox.network.recovery-checkpoint.v1\0";
const RECOVERY_MAGIC: &[u8; 8] = b"AOSANR01";
const RECOVERY_VERSION: u16 = 1;
const RECOVERY_BYTES: usize = 376;
const COMPANION_MAGIC: &[u8; 8] = b"AOSANC01";
const COMPANION_VERSION: u16 = 1;
const COMPANION_HEADER_BYTES: usize = 428;
const MAXIMUM_COMPANION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const RECOVERY_BYTES_U32: u32 = 376;
const MAXIMUM_FEATURES: usize = 64;
const MAXIMUM_OBSERVED_ADDRESSES: usize = 256;
const MAXIMUM_OBSERVED_ROUTES: usize = 256;
const MAXIMUM_ANTI_SPOOF_BINDINGS: usize = 512;

/// Carries exact protected feature availability for one replacement attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementCapabilitiesV1 {
    features: Vec<FeatureRef>,
    digest: ObjectDigest,
    currentness: ProtectedCurrentnessWitnessV1,
}

impl ReplacementCapabilitiesV1 {
    /// Computes the exact capability commitment to witness.
    #[must_use]
    pub fn commitment(features: &[FeatureRef]) -> ObjectDigest {
        capability_digest(features)
    }

    /// Constructs one canonical protected capability snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for excess or unordered features,
    /// or a witness that does not commit the exact capability set.
    pub fn new(
        features: Vec<FeatureRef>,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if features.len() > MAXIMUM_FEATURES || !strictly_increasing(&features) {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let content_digest = capability_digest(&features);
        if currentness.purpose() != ProtectedWitnessPurposeV1::Capabilities
            || currentness.record_digest() != content_digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let digest = protected_capability_digest(content_digest, currentness);
        Ok(Self {
            features,
            digest,
            currentness,
        })
    }

    /// Returns exact available features in canonical order.
    #[must_use]
    pub fn features(&self) -> &[FeatureRef] {
        &self.features
    }

    /// Returns the capability commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns protected capability-currentness evidence.
    #[must_use]
    pub const fn currentness(&self) -> ProtectedCurrentnessWitnessV1 {
        self.currentness
    }
}

/// Classifies the complete policy effect observed after ambiguity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedNetworkPolicyV1 {
    /// The exact predecessor remains installed.
    Predecessor,
    /// The exact candidate and translation are installed.
    Candidate,
    /// All expected policy effects are absent.
    Absent,
    /// Facts from different revisions coexist or required facts disagree.
    Mixed,
}

/// Names which peer owns one concrete anti-spoof binding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AntiSpoofPeerV1 {
    Host,
    Sandbox,
}

/// Carries one concrete address-to-MAC anti-spoof fact from the kernel observer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ObservedAntiSpoofBindingV1 {
    peer: AntiSpoofPeerV1,
    address: NetworkIpAddressV1,
    mac: [u8; 6],
}

/// Carries concrete installed effects for one revision side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedRevisionEffectsV1 {
    assignment_digest: ObjectDigest,
    namespace_plan_digest: ObjectDigest,
    program: NetworkPolicyProgramV1,
    translation: IngressTranslationPlanV1,
}

/// Carries one typed projection from the existing kernel/listener observer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetworkObserverProjectionV1 {
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    host_ifindex: u32,
    sandbox_ifindex: u32,
    host_peer_ifindex: u32,
    sandbox_peer_ifindex: u32,
    host_mac: [u8; 6],
    sandbox_mac: [u8; 6],
    network_handle: [u8; 32],
    allocation_generation: u64,
    address_pairs: Vec<NetworkAddressPairV1>,
    routes: Vec<NetworkRouteV1>,
    anti_spoof: Vec<ObservedAntiSpoofBindingV1>,
    predecessor: Option<ObservedRevisionEffectsV1>,
    candidate: Option<ObservedRevisionEffectsV1>,
}

impl ObservedAntiSpoofBindingV1 {
    pub(crate) const fn new(
        peer: AntiSpoofPeerV1,
        address: NetworkIpAddressV1,
        mac: [u8; 6],
    ) -> Self {
        Self { peer, address, mac }
    }
}

impl ObservedRevisionEffectsV1 {
    pub(crate) fn new(
        assignment_digest: ObjectDigest,
        namespace_plan_digest: ObjectDigest,
        program: NetworkPolicyProgramV1,
        translation: IngressTranslationPlanV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !nonzero_digest(assignment_digest)
            || !nonzero_digest(namespace_plan_digest)
            || program.digest().as_bytes() == &[0; 32]
            || translation.digest().as_bytes() == &[0; 32]
        {
            return Err(AdvancedNetworkPolicyError::InvalidObservation);
        }
        Ok(Self {
            assignment_digest,
            namespace_plan_digest,
            program,
            translation,
        })
    }
}

impl NetworkObserverProjectionV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kernel_boot_id: [u8; 16],
        namespace_device: u64,
        namespace_inode: u64,
        host_ifindex: u32,
        sandbox_ifindex: u32,
        host_peer_ifindex: u32,
        sandbox_peer_ifindex: u32,
        host_mac: [u8; 6],
        sandbox_mac: [u8; 6],
        network_handle: [u8; 32],
        allocation_generation: u64,
        address_pairs: Vec<NetworkAddressPairV1>,
        routes: Vec<NetworkRouteV1>,
        anti_spoof: Vec<ObservedAntiSpoofBindingV1>,
        predecessor: Option<ObservedRevisionEffectsV1>,
        candidate: Option<ObservedRevisionEffectsV1>,
    ) -> Self {
        Self {
            kernel_boot_id,
            namespace_device,
            namespace_inode,
            host_ifindex,
            sandbox_ifindex,
            host_peer_ifindex,
            sandbox_peer_ifindex,
            host_mac,
            sandbox_mac,
            network_handle,
            allocation_generation,
            address_pairs,
            routes,
            anti_spoof,
            predecessor,
            candidate,
        }
    }
}

/// Carries complete typed physical and policy observation evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct NetworkReplacementObservationV1 {
    observed: ObservedNetworkPolicyV1,
    kernel_boot_id: [u8; 16],
    boot_currentness: ProtectedCurrentnessWitnessV1,
    namespace_device: u64,
    namespace_inode: u64,
    host_ifindex: u32,
    sandbox_ifindex: u32,
    host_peer_ifindex: u32,
    sandbox_peer_ifindex: u32,
    host_mac: [u8; 6],
    sandbox_mac: [u8; 6],
    network_handle: [u8; 32],
    allocation_generation: u64,
    address_pairs: Vec<NetworkAddressPairV1>,
    routes: Vec<NetworkRouteV1>,
    anti_spoof: Vec<ObservedAntiSpoofBindingV1>,
    predecessor: Option<ObservedRevisionEffectsV1>,
    candidate: Option<ObservedRevisionEffectsV1>,
    digest: ObjectDigest,
}

impl core::fmt::Debug for NetworkReplacementObservationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NetworkReplacementObservationV1(..)")
    }
}

impl NetworkReplacementObservationV1 {
    pub(crate) fn seal_observer_projection(
        observed: ObservedNetworkPolicyV1,
        boot_currentness: ProtectedCurrentnessWitnessV1,
        projection: NetworkObserverProjectionV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let NetworkObserverProjectionV1 {
            kernel_boot_id,
            namespace_device,
            namespace_inode,
            host_ifindex,
            sandbox_ifindex,
            host_peer_ifindex,
            sandbox_peer_ifindex,
            host_mac,
            sandbox_mac,
            network_handle,
            allocation_generation,
            address_pairs,
            routes,
            anti_spoof,
            predecessor,
            candidate,
        } = projection;
        let namespace_shape_is_valid = match observed {
            ObservedNetworkPolicyV1::Absent => {
                namespace_device == 0
                    && namespace_inode == 0
                    && host_ifindex == 0
                    && valid_link_shape(
                        host_ifindex,
                        sandbox_ifindex,
                        host_peer_ifindex,
                        sandbox_peer_ifindex,
                        host_mac,
                        sandbox_mac,
                    )
            }
            _ => {
                namespace_device != 0
                    && namespace_inode != 0
                    && valid_link_shape(
                        host_ifindex,
                        sandbox_ifindex,
                        host_peer_ifindex,
                        sandbox_peer_ifindex,
                        host_mac,
                        sandbox_mac,
                    )
            }
        };
        let effect_shape_is_valid = match observed {
            ObservedNetworkPolicyV1::Predecessor => predecessor.is_some() && candidate.is_none(),
            ObservedNetworkPolicyV1::Candidate => predecessor.is_none() && candidate.is_some(),
            ObservedNetworkPolicyV1::Absent => predecessor.is_none() && candidate.is_none(),
            ObservedNetworkPolicyV1::Mixed => predecessor.is_some() && candidate.is_some(),
        };
        let inventories_are_canonical = address_pairs.len() <= MAXIMUM_OBSERVED_ADDRESSES
            && routes.len() <= MAXIMUM_OBSERVED_ROUTES
            && anti_spoof.len() <= MAXIMUM_ANTI_SPOOF_BINDINGS
            && strictly_increasing(&address_pairs)
            && strictly_increasing(&routes)
            && strictly_increasing(&anti_spoof);
        let projection_digest = observer_projection_digest(
            observed,
            kernel_boot_id,
            namespace_device,
            namespace_inode,
            host_ifindex,
            sandbox_ifindex,
            host_peer_ifindex,
            sandbox_peer_ifindex,
            host_mac,
            sandbox_mac,
            network_handle,
            allocation_generation,
            &address_pairs,
            &routes,
            &anti_spoof,
            predecessor.as_ref(),
            candidate.as_ref(),
        );
        if kernel_boot_id == [0; 16]
            || boot_currentness.purpose() != ProtectedWitnessPurposeV1::KernelObservation
            || boot_currentness.namespace()
                != observer_namespace(network_handle, allocation_generation)
            || boot_currentness.record_digest() != projection_digest
            || !namespace_shape_is_valid
            || !effect_shape_is_valid
            || !inventories_are_canonical
            || network_handle == [0; 32]
            || allocation_generation == 0
            || (observed == ObservedNetworkPolicyV1::Absent
                && (!address_pairs.is_empty() || !routes.is_empty() || !anti_spoof.is_empty()))
        {
            return Err(AdvancedNetworkPolicyError::InvalidObservation);
        }
        let digest = observation_digest(observed, boot_currentness, projection_digest);
        if !nonzero_digest(digest) {
            return Err(AdvancedNetworkPolicyError::InvalidObservation);
        }
        Ok(Self {
            observed,
            kernel_boot_id,
            boot_currentness,
            namespace_device,
            namespace_inode,
            host_ifindex,
            sandbox_ifindex,
            host_peer_ifindex,
            sandbox_peer_ifindex,
            host_mac,
            sandbox_mac,
            network_handle,
            allocation_generation,
            address_pairs,
            routes,
            anti_spoof,
            predecessor,
            candidate,
            digest,
        })
    }

    pub(crate) const fn observed(&self) -> ObservedNetworkPolicyV1 {
        self.observed
    }

    pub(crate) const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn matches_policy(
        &self,
        policy: &CompiledAdvancedNetworkPolicyV1,
        expected: ObservedNetworkPolicyV1,
    ) -> bool {
        let physical = policy.source().identity().physical();
        let link_matches = match policy.source().kind() {
            NetworkKind::Isolated => self.host_ifindex == 0 && self.sandbox_ifindex == 0,
            NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => {
                self.host_mac == physical.host_mac().map_or([0; 6], |value| value)
                    && self.sandbox_mac == physical.sandbox_mac().map_or([0; 6], |value| value)
                    && self.host_ifindex != 0
                    && self.sandbox_ifindex != 0
            }
            NetworkKind::Host => false,
        };
        self.observed == expected
            && link_matches
            && self.network_handle == physical.network_handle()
            && self.allocation_generation == physical.generation()
            && self.address_pairs == policy.namespace_plan().address_pairs()
            && self.routes == policy.namespace_plan().routes()
            && self.anti_spoof == expected_anti_spoof(policy)
            && match expected {
                ObservedNetworkPolicyV1::Predecessor => self
                    .predecessor
                    .as_ref()
                    .is_some_and(|effects| effects_match(effects, policy)),
                ObservedNetworkPolicyV1::Candidate => self
                    .candidate
                    .as_ref()
                    .is_some_and(|effects| effects_match(effects, policy)),
                ObservedNetworkPolicyV1::Absent | ObservedNetworkPolicyV1::Mixed => false,
            }
    }

    pub(crate) fn matches_attempt_scope(
        &self,
        predecessor: &CompiledAdvancedNetworkPolicyV1,
        candidate: &CompiledAdvancedNetworkPolicyV1,
    ) -> bool {
        let physical = predecessor.source().identity().physical();
        self.network_handle == physical.network_handle()
            && self.allocation_generation == physical.generation()
            && match self.observed {
                ObservedNetworkPolicyV1::Absent => {
                    self.predecessor.is_none() && self.candidate.is_none()
                }
                ObservedNetworkPolicyV1::Mixed => {
                    self.predecessor
                        .as_ref()
                        .is_some_and(|effects| effects_match(effects, predecessor))
                        && self
                            .candidate
                            .as_ref()
                            .is_some_and(|effects| effects_match(effects, candidate))
                }
                ObservedNetworkPolicyV1::Predecessor => {
                    self.matches_policy(predecessor, ObservedNetworkPolicyV1::Predecessor)
                }
                ObservedNetworkPolicyV1::Candidate => {
                    self.matches_policy(candidate, ObservedNetworkPolicyV1::Candidate)
                }
            }
    }

    fn matches_exact_effect(&self, policy: &CompiledAdvancedNetworkPolicyV1) -> bool {
        (self.matches_policy(policy, ObservedNetworkPolicyV1::Predecessor)
            || self.matches_policy(policy, ObservedNetworkPolicyV1::Candidate))
            && !matches!(
                self.observed,
                ObservedNetworkPolicyV1::Absent | ObservedNetworkPolicyV1::Mixed
            )
    }

    fn same_physical_resource(&self, other: &Self) -> bool {
        self.kernel_boot_id == other.kernel_boot_id
            && self.namespace_device == other.namespace_device
            && self.namespace_inode == other.namespace_inode
            && self.host_ifindex == other.host_ifindex
            && self.sandbox_ifindex == other.sandbox_ifindex
            && self.host_peer_ifindex == other.host_peer_ifindex
            && self.sandbox_peer_ifindex == other.sandbox_peer_ifindex
            && self.host_mac == other.host_mac
            && self.sandbox_mac == other.sandbox_mac
            && self.network_handle == other.network_handle
            && self.allocation_generation == other.allocation_generation
            && self.address_pairs == other.address_pairs
            && self.routes == other.routes
            && self.anti_spoof == other.anti_spoof
    }

    fn same_kernel_boot(&self, other: &Self) -> bool {
        self.kernel_boot_id == other.kernel_boot_id
    }

    fn is_exact_successor_of(&self, prior: &Self) -> bool {
        self.boot_currentness
            .is_exact_successor_of(prior.boot_currentness)
    }
}

/// Identifies the closed durable replacement phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPolicyReplacementPhaseV1 {
    /// One policy is active and no replacement evidence remains.
    Stable,
    /// Protected quota and global ingress are reserved; no effect was released.
    Reserved,
    /// Effect authority was released and exact outcome is not yet known.
    EffectReleased,
    /// An absent or mixed observation requires continued read-only recovery.
    RecoveryRequired,
    /// Protected authority admits one predecessor-only recovery attempt.
    RecoveryAuthorized,
    /// Exact absence proves the old mixed effects have been fenced.
    RecoveryFenced,
    /// Restore inputs have been revalidated before effect release.
    RecoveryApplyPrepared,
    /// Restore effect authority escaped and outcome is again ambiguous.
    RecoveryEffectReleased,
    /// The exact candidate was observed and committed.
    Committed,
    /// The exact predecessor was observed after a replacement attempt.
    RolledBack,
    /// Reservation was aborted before any effect authority was released.
    Aborted,
}

/// Retains one fully protected stable policy state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableStateV1 {
    generation: u64,
    active: CompiledAdvancedNetworkPolicyV1,
    registry: ExternalIngressRegistryV1,
    registry_currentness: ProtectedCurrentnessWitnessV1,
    aggregate_quota: ProtectedNetworkQuotaV1,
    transaction: ProtectedNetworkTransactionV1,
    advisory_degradations: Vec<FeatureRef>,
    active_observation: NetworkReplacementObservationV1,
}

/// Retains both revisions and all reservations before outcome certainty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedStateV1 {
    generation: u64,
    replacement_id: OperationId,
    predecessor: CompiledAdvancedNetworkPolicyV1,
    candidate: CompiledAdvancedNetworkPolicyV1,
    reserved_registry: ExternalIngressRegistryV1,
    reserved_ingress_currentness: ProtectedCurrentnessWitnessV1,
    reserved_quota: ProtectedNetworkQuotaV1,
    reserved_transaction: ProtectedNetworkTransactionV1,
    pool: IngressPoolAuthorityV1,
    capabilities: ReplacementCapabilitiesV1,
    predecessor_degradations: Vec<FeatureRef>,
    candidate_degradations: Vec<FeatureRef>,
    predecessor_observation: NetworkReplacementObservationV1,
}

/// Retains an irreversible effect-release boundary and latest observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbiguousStateV1 {
    reservation: ReservedStateV1,
    observation: Option<NetworkReplacementObservationV1>,
    recovery: Option<RecoveryAttemptV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryAttemptV1 {
    recovery_id: OperationId,
    authority: ProtectedCurrentnessWitnessV1,
    authorization_observation: NetworkReplacementObservationV1,
    fenced_observation: Option<NetworkReplacementObservationV1>,
}

/// Retains one exact terminal outcome until explicit settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalStateV1 {
    generation: u64,
    replacement_id: OperationId,
    predecessor: CompiledAdvancedNetworkPolicyV1,
    candidate: CompiledAdvancedNetworkPolicyV1,
    active: CompiledAdvancedNetworkPolicyV1,
    registry: ExternalIngressRegistryV1,
    registry_currentness: ProtectedCurrentnessWitnessV1,
    aggregate_quota: ProtectedNetworkQuotaV1,
    transaction: ProtectedNetworkTransactionV1,
    advisory_degradations: Vec<FeatureRef>,
    baseline_observation: NetworkReplacementObservationV1,
    observation: Option<NetworkReplacementObservationV1>,
}

/// Stores every closed crash-recoverable replacement state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkPolicyReplacementStateV1 {
    /// Stable active state.
    Stable(StableStateV1),
    /// Fully protected reservation before effect release.
    Reserved(ReservedStateV1),
    /// Irreversible ambiguity boundary after effect release.
    EffectReleased(AmbiguousStateV1),
    /// Mixed or absent effect requiring repeated observation.
    RecoveryRequired(AmbiguousStateV1),
    /// Recovery authority is durable but old effects are not yet fenced.
    RecoveryAuthorized(AmbiguousStateV1),
    /// Old effects are absent and a restore may be prepared.
    RecoveryFenced(AmbiguousStateV1),
    /// Restore inputs are revalidated but effect authority remains contained.
    RecoveryApplyPrepared(AmbiguousStateV1),
    /// Restore effect authority escaped and exact outcome is pending.
    RecoveryEffectReleased(AmbiguousStateV1),
    /// Exact candidate terminal state.
    Committed(TerminalStateV1),
    /// Exact predecessor terminal state.
    RolledBack(TerminalStateV1),
    /// Pre-effect abort terminal state.
    Aborted(TerminalStateV1),
}

impl NetworkPolicyReplacementStateV1 {
    /// Constructs initial stable state from protected owner snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for zero generation, incomplete
    /// active ingress, absent aggregate usage, or invalid degradation evidence.
    pub fn stable(
        generation: u64,
        active: CompiledAdvancedNetworkPolicyV1,
        registry: ExternalIngressRegistryV1,
        registry_currentness: ProtectedCurrentnessWitnessV1,
        aggregate_quota: ProtectedNetworkQuotaV1,
        transaction: ProtectedNetworkTransactionV1,
        advisory_degradations: Vec<FeatureRef>,
        active_observation: NetworkReplacementObservationV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if generation == 0
            || !registry.contains_policy(active.source().ingress())
            || registry.has_in_flight_lineage()
            || registry_currentness.purpose() != ProtectedWitnessPurposeV1::IngressRegistry
            || registry_currentness.namespace() != node_namespace(registry.node())
            || registry_currentness.record_digest() != registry.digest()
            || aggregate_quota.has_reservation()
            || !aggregate_quota.covers_active(active.source().identity().project(), active.usage())
            || !transaction.covers(&registry, registry_currentness, &aggregate_quota)
            || !valid_degradations(&active, &advisory_degradations)
            || !active_observation.matches_exact_effect(&active)
        {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        Ok(Self::Stable(StableStateV1 {
            generation,
            active,
            registry,
            registry_currentness,
            aggregate_quota,
            transaction,
            advisory_degradations,
            active_observation,
        }))
    }

    /// Returns the closed durable phase.
    #[must_use]
    pub const fn phase(&self) -> NetworkPolicyReplacementPhaseV1 {
        match self {
            Self::Stable(_) => NetworkPolicyReplacementPhaseV1::Stable,
            Self::Reserved(_) => NetworkPolicyReplacementPhaseV1::Reserved,
            Self::EffectReleased(_) => NetworkPolicyReplacementPhaseV1::EffectReleased,
            Self::RecoveryRequired(_) => NetworkPolicyReplacementPhaseV1::RecoveryRequired,
            Self::RecoveryAuthorized(_) => NetworkPolicyReplacementPhaseV1::RecoveryAuthorized,
            Self::RecoveryFenced(_) => NetworkPolicyReplacementPhaseV1::RecoveryFenced,
            Self::RecoveryApplyPrepared(_) => {
                NetworkPolicyReplacementPhaseV1::RecoveryApplyPrepared
            }
            Self::RecoveryEffectReleased(_) => {
                NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased
            }
            Self::Committed(_) => NetworkPolicyReplacementPhaseV1::Committed,
            Self::RolledBack(_) => NetworkPolicyReplacementPhaseV1::RolledBack,
            Self::Aborted(_) => NetworkPolicyReplacementPhaseV1::Aborted,
        }
    }

    /// Returns the reducer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        match self {
            Self::Stable(value) => value.generation,
            Self::Reserved(value) => value.generation,
            Self::EffectReleased(value)
            | Self::RecoveryRequired(value)
            | Self::RecoveryAuthorized(value)
            | Self::RecoveryFenced(value)
            | Self::RecoveryApplyPrepared(value)
            | Self::RecoveryEffectReleased(value) => value.reservation.generation,
            Self::Committed(value) | Self::RolledBack(value) | Self::Aborted(value) => {
                value.generation
            }
        }
    }

    /// Returns the currently authoritative policy.
    #[must_use]
    pub const fn active(&self) -> &CompiledAdvancedNetworkPolicyV1 {
        match self {
            Self::Stable(value) => &value.active,
            Self::Reserved(value) => &value.predecessor,
            Self::EffectReleased(value)
            | Self::RecoveryRequired(value)
            | Self::RecoveryAuthorized(value)
            | Self::RecoveryFenced(value)
            | Self::RecoveryApplyPrepared(value)
            | Self::RecoveryEffectReleased(value) => &value.reservation.predecessor,
            Self::Committed(value) | Self::RolledBack(value) | Self::Aborted(value) => {
                &value.active
            }
        }
    }

    /// Returns the retained candidate while an outcome remains unresolved.
    #[must_use]
    pub const fn candidate(&self) -> Option<&CompiledAdvancedNetworkPolicyV1> {
        match self {
            Self::Reserved(value) => Some(&value.candidate),
            Self::EffectReleased(value)
            | Self::RecoveryRequired(value)
            | Self::RecoveryAuthorized(value)
            | Self::RecoveryFenced(value)
            | Self::RecoveryApplyPrepared(value)
            | Self::RecoveryEffectReleased(value) => Some(&value.reservation.candidate),
            _ => None,
        }
    }

    /// Returns the protected registry image appropriate to this phase.
    #[must_use]
    pub const fn protected_registry(&self) -> &ExternalIngressRegistryV1 {
        match self {
            Self::Stable(value) => &value.registry,
            Self::Reserved(value) => &value.reserved_registry,
            Self::EffectReleased(value)
            | Self::RecoveryRequired(value)
            | Self::RecoveryAuthorized(value)
            | Self::RecoveryFenced(value)
            | Self::RecoveryApplyPrepared(value)
            | Self::RecoveryEffectReleased(value) => &value.reservation.reserved_registry,
            Self::Committed(value) | Self::RolledBack(value) | Self::Aborted(value) => {
                &value.registry
            }
        }
    }

    /// Returns the protected aggregate quota image appropriate to this phase.
    #[must_use]
    pub const fn protected_quota(&self) -> &ProtectedNetworkQuotaV1 {
        match self {
            Self::Stable(value) => &value.aggregate_quota,
            Self::Reserved(value) => &value.reserved_quota,
            Self::EffectReleased(value)
            | Self::RecoveryRequired(value)
            | Self::RecoveryAuthorized(value)
            | Self::RecoveryFenced(value)
            | Self::RecoveryApplyPrepared(value)
            | Self::RecoveryEffectReleased(value) => &value.reservation.reserved_quota,
            Self::Committed(value) | Self::RolledBack(value) | Self::Aborted(value) => {
                &value.aggregate_quota
            }
        }
    }

    /// Returns the combined protected registry/quota transaction head.
    #[must_use]
    pub const fn protected_transaction(&self) -> ProtectedNetworkTransactionV1 {
        match self {
            Self::Stable(value) => value.transaction,
            Self::Reserved(value) => value.reserved_transaction,
            Self::EffectReleased(value)
            | Self::RecoveryRequired(value)
            | Self::RecoveryAuthorized(value)
            | Self::RecoveryFenced(value)
            | Self::RecoveryApplyPrepared(value)
            | Self::RecoveryEffectReleased(value) => value.reservation.reserved_transaction,
            Self::Committed(value) | Self::RolledBack(value) | Self::Aborted(value) => {
                value.transaction
            }
        }
    }

    /// Returns the latest complete typed observation, when one is retained.
    #[must_use]
    pub const fn observation(&self) -> Option<&NetworkReplacementObservationV1> {
        match self {
            Self::Stable(value) => Some(&value.active_observation),
            Self::Reserved(_) => None,
            Self::EffectReleased(value)
            | Self::RecoveryRequired(value)
            | Self::RecoveryAuthorized(value)
            | Self::RecoveryFenced(value)
            | Self::RecoveryApplyPrepared(value)
            | Self::RecoveryEffectReleased(value) => value.observation.as_ref(),
            Self::Committed(value) | Self::RolledBack(value) | Self::Aborted(value) => {
                value.observation.as_ref()
            }
        }
    }
}

/// Supplies one compare-and-swap-fenced replacement transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkPolicyReplacementEventV1 {
    /// Atomically reserves protected quota and global ingress.
    Prepare {
        /// Exact current reducer generation.
        expected_generation: u64,
        /// Unique replacement operation identity.
        replacement_id: OperationId,
        /// Fully compiled exact candidate.
        candidate: CompiledAdvancedNetworkPolicyV1,
        /// Protected current capability snapshot.
        capabilities: ReplacementCapabilitiesV1,
        /// Node-global ingress CAS.
        ingress_cas: IngressRegistryCasV1,
        /// Protected current node-global ingress head used by the CAS.
        ingress_currentness: ProtectedCurrentnessWitnessV1,
        /// Protected successor witness atomically published with reservation.
        reserved_ingress_currentness: ProtectedCurrentnessWitnessV1,
        /// Protected ingress pool authority.
        pool: IngressPoolAuthorityV1,
        /// Already atomically reserved project/node aggregate quota.
        reserved_quota: ProtectedNetworkQuotaV1,
        /// Exact combined successor published with both protected reservations.
        reserved_transaction: ProtectedNetworkTransactionV1,
    },
    /// Records that effect authority may now escape to a worker.
    ReleaseEffects {
        /// Exact reserved generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
        /// Fresh protected assignment-head witness.
        assignment_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh protected discovery-head witness, when egress uses discovery.
        discovery_currentness: Option<ProtectedCurrentnessWitnessV1>,
        /// Fresh protected capability-head witness.
        capabilities_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh protected ingress-pool-head witness.
        pool_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh protected node-global reserved-registry head witness.
        ingress_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh protected aggregate-quota-head witness.
        quota_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh combined registry/quota transaction-head witness.
        transaction_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh exact predecessor namespace, link, and policy observation.
        predecessor_observation: NetworkReplacementObservationV1,
    },
    /// Supplies a complete typed post-crash or post-effect observation.
    Observe {
        /// Exact ambiguous generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
        /// Complete typed physical and policy observation.
        observation: NetworkReplacementObservationV1,
        /// Next protected quota witness, present only for a terminal transition.
        result_quota_currentness: Option<ProtectedCurrentnessWitnessV1>,
        /// Next protected registry witness, present only for a terminal transition.
        result_ingress_currentness: Option<ProtectedCurrentnessWitnessV1>,
        /// Combined successor transaction, present only for a terminal transition.
        result_transaction: Option<ProtectedNetworkTransactionV1>,
    },
    /// Authorizes a predecessor-only recovery after mixed or absent effects.
    AuthorizeRecovery {
        /// Exact recovery-required generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
        /// Unique recovery attempt identity.
        recovery_id: OperationId,
        /// Protected purpose-bound recovery authorization.
        authority: ProtectedCurrentnessWitnessV1,
    },
    /// Records exact absence after fencing every mixed effect.
    FenceRecovery {
        /// Exact authorized-recovery generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
        /// Exact recovery attempt identity.
        recovery_id: OperationId,
        /// Fresh typed observer result after the fencing attempt.
        observation: NetworkReplacementObservationV1,
    },
    /// Revalidates retained protected inputs before preparing predecessor restore.
    PrepareRecoveryApply {
        /// Exact fenced-recovery generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
        /// Exact recovery attempt identity.
        recovery_id: OperationId,
        /// Fresh predecessor assignment head.
        assignment_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh predecessor discovery head, when used.
        discovery_currentness: Option<ProtectedCurrentnessWitnessV1>,
        /// Fresh retained capability head.
        capabilities_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh retained pool head.
        pool_currentness: ProtectedCurrentnessWitnessV1,
        /// Fresh retained combined registry/quota transaction head.
        transaction_currentness: ProtectedCurrentnessWitnessV1,
    },
    /// Persists the ambiguity boundary before predecessor restore effects escape.
    ReleaseRecoveryEffects {
        /// Exact prepared-recovery generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
        /// Exact recovery attempt identity.
        recovery_id: OperationId,
    },
    /// Aborts only while effect release remains impossible.
    AbortReserved {
        /// Exact reserved generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
        /// Protected witness for the registry after reservation rollback.
        result_ingress_currentness: ProtectedCurrentnessWitnessV1,
        /// Protected witness for aggregate quota after reservation rollback.
        result_quota_currentness: ProtectedCurrentnessWitnessV1,
        /// Combined protected successor for the rollback.
        result_transaction: ProtectedNetworkTransactionV1,
    },
    /// Acknowledges an exact terminal outcome.
    Settle {
        /// Exact terminal generation.
        expected_generation: u64,
        /// Exact replacement operation identity.
        replacement_id: OperationId,
    },
}

/// Applies one pure fail-closed replacement transition.
///
/// # Errors
///
/// Returns [`AdvancedNetworkPolicyError`] for stale CAS/currentness, illegal
/// phase, unsupported hard features, collision/exhaustion, observation mismatch,
/// or arithmetic failure.
pub fn reduce_network_policy_replacement_v1(
    state: &NetworkPolicyReplacementStateV1,
    event: NetworkPolicyReplacementEventV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    match (state, event) {
        (
            NetworkPolicyReplacementStateV1::Stable(current),
            NetworkPolicyReplacementEventV1::Prepare {
                expected_generation,
                replacement_id,
                candidate,
                capabilities,
                ingress_cas,
                ingress_currentness,
                reserved_ingress_currentness,
                pool,
                reserved_quota,
                reserved_transaction,
            },
        ) => prepare(
            current,
            expected_generation,
            replacement_id,
            candidate,
            capabilities,
            ingress_cas,
            ingress_currentness,
            reserved_ingress_currentness,
            pool,
            reserved_quota,
            reserved_transaction,
        ),
        (
            NetworkPolicyReplacementStateV1::Reserved(current),
            NetworkPolicyReplacementEventV1::ReleaseEffects {
                expected_generation,
                replacement_id,
                assignment_currentness,
                discovery_currentness,
                capabilities_currentness,
                pool_currentness,
                ingress_currentness,
                quota_currentness,
                transaction_currentness,
                predecessor_observation,
            },
        ) => {
            require_attempt(
                current.generation,
                current.replacement_id,
                expected_generation,
                replacement_id,
            )?;
            if assignment_currentness
                != current
                    .candidate
                    .source()
                    .identity()
                    .revision()
                    .currentness()
                || discovery_currentness != current.candidate.discovery_currentness()
                || capabilities_currentness != current.capabilities.currentness()
                || pool_currentness != current.pool.currentness()
                || quota_currentness != current.reserved_quota.currentness()
                || ingress_currentness != current.reserved_ingress_currentness
                || transaction_currentness != current.reserved_transaction.currentness()
                || !predecessor_observation.is_exact_successor_of(&current.predecessor_observation)
                || !predecessor_observation
                    .matches_policy(&current.predecessor, ObservedNetworkPolicyV1::Predecessor)
            {
                return Err(AdvancedNetworkPolicyError::StaleAuthority);
            }
            let mut reservation = current.clone();
            reservation.generation = next_generation(current.generation)?;
            reservation.predecessor_observation = predecessor_observation;
            Ok(NetworkPolicyReplacementStateV1::EffectReleased(
                AmbiguousStateV1 {
                    reservation,
                    observation: None,
                    recovery: None,
                },
            ))
        }
        (
            NetworkPolicyReplacementStateV1::EffectReleased(current)
            | NetworkPolicyReplacementStateV1::RecoveryRequired(current),
            NetworkPolicyReplacementEventV1::Observe {
                expected_generation,
                replacement_id,
                observation,
                result_quota_currentness,
                result_ingress_currentness,
                result_transaction,
            },
        ) => observe(
            current,
            expected_generation,
            replacement_id,
            observation,
            result_quota_currentness,
            result_ingress_currentness,
            result_transaction,
            true,
        ),
        (
            NetworkPolicyReplacementStateV1::RecoveryEffectReleased(current),
            NetworkPolicyReplacementEventV1::Observe {
                expected_generation,
                replacement_id,
                observation,
                result_quota_currentness,
                result_ingress_currentness,
                result_transaction,
            },
        ) => observe(
            current,
            expected_generation,
            replacement_id,
            observation,
            result_quota_currentness,
            result_ingress_currentness,
            result_transaction,
            false,
        ),
        (
            NetworkPolicyReplacementStateV1::RecoveryFenced(current)
            | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(current),
            NetworkPolicyReplacementEventV1::Observe {
                expected_generation,
                replacement_id,
                observation,
                result_quota_currentness: None,
                result_ingress_currentness: None,
                result_transaction: None,
            },
        ) => restart_recovery(current, expected_generation, replacement_id, observation),
        (
            NetworkPolicyReplacementStateV1::RecoveryRequired(current),
            NetworkPolicyReplacementEventV1::AuthorizeRecovery {
                expected_generation,
                replacement_id,
                recovery_id,
                authority,
            },
        ) => authorize_recovery(
            current,
            expected_generation,
            replacement_id,
            recovery_id,
            authority,
        ),
        (
            NetworkPolicyReplacementStateV1::RecoveryAuthorized(current),
            NetworkPolicyReplacementEventV1::FenceRecovery {
                expected_generation,
                replacement_id,
                recovery_id,
                observation,
            },
        ) => fence_recovery(
            current,
            expected_generation,
            replacement_id,
            recovery_id,
            observation,
        ),
        (
            NetworkPolicyReplacementStateV1::RecoveryFenced(current),
            NetworkPolicyReplacementEventV1::PrepareRecoveryApply {
                expected_generation,
                replacement_id,
                recovery_id,
                assignment_currentness,
                discovery_currentness,
                capabilities_currentness,
                pool_currentness,
                transaction_currentness,
            },
        ) => prepare_recovery_apply(
            current,
            expected_generation,
            replacement_id,
            recovery_id,
            assignment_currentness,
            discovery_currentness,
            capabilities_currentness,
            pool_currentness,
            transaction_currentness,
        ),
        (
            NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(current),
            NetworkPolicyReplacementEventV1::ReleaseRecoveryEffects {
                expected_generation,
                replacement_id,
                recovery_id,
            },
        ) => release_recovery_effects(current, expected_generation, replacement_id, recovery_id),
        (
            NetworkPolicyReplacementStateV1::Reserved(current),
            NetworkPolicyReplacementEventV1::AbortReserved {
                expected_generation,
                replacement_id,
                result_ingress_currentness,
                result_quota_currentness,
                result_transaction,
            },
        ) => abort_reserved(
            current,
            expected_generation,
            replacement_id,
            result_ingress_currentness,
            result_quota_currentness,
            result_transaction,
        ),
        (
            NetworkPolicyReplacementStateV1::Committed(current)
            | NetworkPolicyReplacementStateV1::RolledBack(current)
            | NetworkPolicyReplacementStateV1::Aborted(current),
            NetworkPolicyReplacementEventV1::Settle {
                expected_generation,
                replacement_id,
            },
        ) => {
            require_attempt(
                current.generation,
                current.replacement_id,
                expected_generation,
                replacement_id,
            )?;
            NetworkPolicyReplacementStateV1::stable(
                next_generation(current.generation)?,
                current.active.clone(),
                current.registry.clone(),
                current.registry_currentness,
                current.aggregate_quota.clone(),
                current.transaction,
                current.advisory_degradations.clone(),
                current
                    .observation
                    .clone()
                    .ok_or(AdvancedNetworkPolicyError::InvalidObservation)?,
            )
        }
        _ => Err(AdvancedNetworkPolicyError::InvalidTransition),
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    current: &StableStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    candidate: CompiledAdvancedNetworkPolicyV1,
    capabilities: ReplacementCapabilitiesV1,
    ingress_cas: IngressRegistryCasV1,
    ingress_currentness: ProtectedCurrentnessWitnessV1,
    reserved_ingress_currentness: ProtectedCurrentnessWitnessV1,
    pool: IngressPoolAuthorityV1,
    reserved_quota: ProtectedNetworkQuotaV1,
    reserved_transaction: ProtectedNetworkTransactionV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    if current.generation != expected_generation
        || replacement_id.as_bytes() == &[0; 16]
        || !current
            .active
            .source()
            .identity()
            .admits_successor(candidate.source().identity())
        || !reserved_quota.is_reservation_successor_of(
            &current.aggregate_quota,
            candidate.source().identity().project(),
            candidate.usage(),
        )
        || capabilities.currentness().namespace() != node_namespace(pool.node())
        || ingress_currentness != current.registry_currentness
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    if [current.active.source(), candidate.source()]
        .into_iter()
        .flat_map(|policy| policy.hard_features())
        .any(|required| capabilities.features.binary_search(required).is_err())
    {
        return Err(AdvancedNetworkPolicyError::UnsupportedHardFeature);
    }
    if current
        .active
        .source()
        .ingress()
        .allocations()
        .iter()
        .any(|allocation| !pool.admits(allocation.external()))
    {
        return Err(AdvancedNetworkPolicyError::IngressConflict);
    }
    let candidate_degradations = candidate
        .source()
        .advisory_features()
        .iter()
        .filter(|feature| capabilities.features.binary_search(feature).is_err())
        .cloned()
        .collect::<Vec<_>>();
    let reserved_registry = current.registry.reserve_replacement(
        ingress_cas,
        ingress_currentness,
        current.active.source().ingress(),
        candidate.source().ingress(),
        &pool,
    )?;
    if reserved_ingress_currentness.record_digest() != reserved_registry.digest()
        || !reserved_ingress_currentness.is_exact_successor_of(ingress_currentness)
        || !reserved_transaction.covers(
            &reserved_registry,
            reserved_ingress_currentness,
            &reserved_quota,
        )
        || !reserved_transaction.is_exact_successor_of(current.transaction)
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    Ok(NetworkPolicyReplacementStateV1::Reserved(ReservedStateV1 {
        generation: next_generation(current.generation)?,
        replacement_id,
        predecessor: current.active.clone(),
        candidate,
        reserved_registry,
        reserved_ingress_currentness,
        reserved_quota,
        reserved_transaction,
        pool,
        capabilities,
        predecessor_degradations: current.advisory_degradations.clone(),
        candidate_degradations,
        predecessor_observation: current.active_observation.clone(),
    }))
}

fn observe(
    current: &AmbiguousStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    observation: NetworkReplacementObservationV1,
    quota_currentness: Option<ProtectedCurrentnessWitnessV1>,
    result_ingress_currentness: Option<ProtectedCurrentnessWitnessV1>,
    result_transaction: Option<ProtectedNetworkTransactionV1>,
    allow_candidate: bool,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    let reservation = &current.reservation;
    require_attempt(
        reservation.generation,
        reservation.replacement_id,
        expected_generation,
        replacement_id,
    )?;
    let generation = next_generation(reservation.generation)?;
    let preceding_observation = current
        .observation
        .as_ref()
        .or_else(|| {
            current
                .recovery
                .as_ref()
                .and_then(|attempt| attempt.fenced_observation.as_ref())
        })
        .unwrap_or(&reservation.predecessor_observation);
    if !observation.is_exact_successor_of(preceding_observation) {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    if allow_candidate
        && observation.same_physical_resource(&reservation.predecessor_observation)
        && observation.matches_policy(&reservation.candidate, ObservedNetworkPolicyV1::Candidate)
    {
        let quota_currentness =
            quota_currentness.ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let result_ingress_currentness =
            result_ingress_currentness.ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let result_transaction =
            result_transaction.ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let registry = reservation.reserved_registry.commit_replacement(
            reservation.candidate.source().ingress(),
            reservation.pool.reuse_delay_generations(),
            reservation.reserved_ingress_currentness.sequence(),
        )?;
        if result_ingress_currentness.record_digest() != registry.digest()
            || !result_ingress_currentness
                .is_exact_successor_of(reservation.reserved_ingress_currentness)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let quota = reservation.reserved_quota.commit_replacement(
            reservation.candidate.source().identity().project(),
            reservation.predecessor.usage(),
            reservation.candidate.usage(),
            quota_currentness,
        )?;
        if !result_transaction.covers(&registry, result_ingress_currentness, &quota)
            || !result_transaction.is_exact_successor_of(reservation.reserved_transaction)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        return Ok(NetworkPolicyReplacementStateV1::Committed(
            TerminalStateV1 {
                generation,
                replacement_id,
                predecessor: reservation.predecessor.clone(),
                candidate: reservation.candidate.clone(),
                active: reservation.candidate.clone(),
                registry,
                registry_currentness: result_ingress_currentness,
                aggregate_quota: quota,
                transaction: result_transaction,
                advisory_degradations: reservation.candidate_degradations.clone(),
                baseline_observation: reservation.predecessor_observation.clone(),
                observation: Some(observation),
            },
        ));
    }
    // A protected boot change destroys the old kernel objects. Only the
    // already-authoritative predecessor may resolve on a reconstituted object.
    if (observation.same_physical_resource(&reservation.predecessor_observation)
        || !observation.same_kernel_boot(&reservation.predecessor_observation))
        && observation.matches_policy(
            &reservation.predecessor,
            ObservedNetworkPolicyV1::Predecessor,
        )
    {
        let quota_currentness =
            quota_currentness.ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let result_ingress_currentness =
            result_ingress_currentness.ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let result_transaction =
            result_transaction.ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let registry = reservation.reserved_registry.rollback_reservation(
            reservation.predecessor.source().ingress(),
            reservation.candidate.source().ingress(),
        )?;
        if result_ingress_currentness.record_digest() != registry.digest()
            || !result_ingress_currentness
                .is_exact_successor_of(reservation.reserved_ingress_currentness)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let quota = reservation.reserved_quota.rollback_reservation(
            reservation.candidate.source().identity().project(),
            reservation.candidate.usage(),
            quota_currentness,
        )?;
        if !result_transaction.covers(&registry, result_ingress_currentness, &quota)
            || !result_transaction.is_exact_successor_of(reservation.reserved_transaction)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        return Ok(NetworkPolicyReplacementStateV1::RolledBack(
            TerminalStateV1 {
                generation,
                replacement_id,
                predecessor: reservation.predecessor.clone(),
                candidate: reservation.candidate.clone(),
                active: reservation.predecessor.clone(),
                registry,
                registry_currentness: result_ingress_currentness,
                aggregate_quota: quota,
                transaction: result_transaction,
                advisory_degradations: reservation.predecessor_degradations.clone(),
                baseline_observation: reservation.predecessor_observation.clone(),
                observation: Some(observation),
            },
        ));
    }
    let recoverable_shape = match observation.observed {
        ObservedNetworkPolicyV1::Absent => true,
        ObservedNetworkPolicyV1::Mixed => {
            observation.same_physical_resource(&reservation.predecessor_observation)
        }
        _ => false,
    };
    if quota_currentness.is_none()
        && result_ingress_currentness.is_none()
        && result_transaction.is_none()
        && recoverable_shape
        && observation.matches_attempt_scope(&reservation.predecessor, &reservation.candidate)
    {
        let mut retained = current.clone();
        retained.reservation.generation = generation;
        retained.observation = Some(observation);
        retained.recovery = None;
        return Ok(NetworkPolicyReplacementStateV1::RecoveryRequired(retained));
    }
    Err(AdvancedNetworkPolicyError::InvalidObservation)
}

fn authorize_recovery(
    current: &AmbiguousStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    recovery_id: OperationId,
    authority: ProtectedCurrentnessWitnessV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    require_attempt(
        current.reservation.generation,
        current.reservation.replacement_id,
        expected_generation,
        replacement_id,
    )?;
    let observation = current
        .observation
        .as_ref()
        .ok_or(AdvancedNetworkPolicyError::InvalidObservation)?;
    if recovery_id.as_bytes() == &[0; 16]
        || current.recovery.is_some()
        || !matches!(
            observation.observed,
            ObservedNetworkPolicyV1::Absent | ObservedNetworkPolicyV1::Mixed
        )
        || authority.purpose() != ProtectedWitnessPurposeV1::RecoveryAuthority
        || !authority.is_exact_journal_successor_of(observation.boot_currentness)
        || authority.namespace()
            != observer_namespace(
                current
                    .reservation
                    .predecessor
                    .source()
                    .identity()
                    .physical()
                    .network_handle(),
                current
                    .reservation
                    .predecessor
                    .source()
                    .identity()
                    .physical()
                    .generation(),
            )
        || authority.record_digest()
            != recovery_authorization_digest(&current.reservation, observation, recovery_id)
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    let mut next = current.clone();
    next.reservation.generation = next_generation(current.reservation.generation)?;
    next.recovery = Some(RecoveryAttemptV1 {
        recovery_id,
        authority,
        authorization_observation: observation.clone(),
        fenced_observation: None,
    });
    Ok(NetworkPolicyReplacementStateV1::RecoveryAuthorized(next))
}

fn restart_recovery(
    current: &AmbiguousStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    observation: NetworkReplacementObservationV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    require_attempt(
        current.reservation.generation,
        current.reservation.replacement_id,
        expected_generation,
        replacement_id,
    )?;
    let preceding = current
        .observation
        .as_ref()
        .ok_or(AdvancedNetworkPolicyError::InvalidObservation)?;
    if !matches!(
        observation.observed,
        ObservedNetworkPolicyV1::Absent | ObservedNetworkPolicyV1::Mixed
    ) || !observation.is_exact_successor_of(preceding)
        || !observation.matches_attempt_scope(
            &current.reservation.predecessor,
            &current.reservation.candidate,
        )
    {
        return Err(AdvancedNetworkPolicyError::InvalidObservation);
    }

    let mut next = current.clone();
    next.reservation.generation = next_generation(current.reservation.generation)?;
    next.observation = Some(observation);
    next.recovery = None;
    Ok(NetworkPolicyReplacementStateV1::RecoveryRequired(next))
}

fn fence_recovery(
    current: &AmbiguousStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    recovery_id: OperationId,
    observation: NetworkReplacementObservationV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    require_recovery_attempt(current, expected_generation, replacement_id, recovery_id)?;
    let authority = current
        .recovery
        .as_ref()
        .ok_or(AdvancedNetworkPolicyError::InvalidTransition)?
        .authority;
    if !matches!(
        observation.observed,
        ObservedNetworkPolicyV1::Absent | ObservedNetworkPolicyV1::Mixed
    ) || !observation
        .boot_currentness
        .is_exact_journal_successor_of(authority)
        || !observation.matches_attempt_scope(
            &current.reservation.predecessor,
            &current.reservation.candidate,
        )
    {
        return Err(AdvancedNetworkPolicyError::InvalidObservation);
    }
    let mut next = current.clone();
    next.reservation.generation = next_generation(current.reservation.generation)?;
    next.observation = Some(observation.clone());
    if observation.observed == ObservedNetworkPolicyV1::Mixed {
        next.recovery = None;
        return Ok(NetworkPolicyReplacementStateV1::RecoveryRequired(next));
    }
    next.recovery
        .as_mut()
        .ok_or(AdvancedNetworkPolicyError::InvalidTransition)?
        .fenced_observation = Some(observation);
    Ok(NetworkPolicyReplacementStateV1::RecoveryFenced(next))
}

#[allow(clippy::too_many_arguments)]
fn prepare_recovery_apply(
    current: &AmbiguousStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    recovery_id: OperationId,
    assignment_currentness: ProtectedCurrentnessWitnessV1,
    discovery_currentness: Option<ProtectedCurrentnessWitnessV1>,
    capabilities_currentness: ProtectedCurrentnessWitnessV1,
    pool_currentness: ProtectedCurrentnessWitnessV1,
    transaction_currentness: ProtectedCurrentnessWitnessV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    require_recovery_attempt(current, expected_generation, replacement_id, recovery_id)?;
    if current
        .recovery
        .as_ref()
        .and_then(|attempt| attempt.fenced_observation.as_ref())
        .is_none()
        || assignment_currentness
            != current
                .reservation
                .predecessor
                .source()
                .identity()
                .revision()
                .currentness()
        || discovery_currentness != current.reservation.predecessor.discovery_currentness()
        || capabilities_currentness != current.reservation.capabilities.currentness()
        || pool_currentness != current.reservation.pool.currentness()
        || transaction_currentness != current.reservation.reserved_transaction.currentness()
        || current
            .reservation
            .predecessor
            .source()
            .hard_features()
            .iter()
            .any(|required| {
                current
                    .reservation
                    .capabilities
                    .features
                    .binary_search(required)
                    .is_err()
            })
        || !current
            .reservation
            .reserved_registry
            .retains_policy(current.reservation.predecessor.source().ingress())
        || current
            .reservation
            .predecessor
            .source()
            .ingress()
            .allocations()
            .iter()
            .any(|allocation| !current.reservation.pool.admits(allocation.external()))
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    let mut next = current.clone();
    next.reservation.generation = next_generation(current.reservation.generation)?;
    Ok(NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(next))
}

fn release_recovery_effects(
    current: &AmbiguousStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    recovery_id: OperationId,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    require_recovery_attempt(current, expected_generation, replacement_id, recovery_id)?;
    let mut next = current.clone();
    next.reservation.generation = next_generation(current.reservation.generation)?;
    next.observation = None;
    Ok(NetworkPolicyReplacementStateV1::RecoveryEffectReleased(
        next,
    ))
}

fn require_recovery_attempt(
    current: &AmbiguousStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    recovery_id: OperationId,
) -> Result<(), AdvancedNetworkPolicyError> {
    require_attempt(
        current.reservation.generation,
        current.reservation.replacement_id,
        expected_generation,
        replacement_id,
    )?;
    if current
        .recovery
        .as_ref()
        .map_or(true, |attempt| attempt.recovery_id != recovery_id)
    {
        return Err(AdvancedNetworkPolicyError::InvalidTransition);
    }
    Ok(())
}

fn abort_reserved(
    current: &ReservedStateV1,
    expected_generation: u64,
    replacement_id: OperationId,
    result_ingress_currentness: ProtectedCurrentnessWitnessV1,
    result_quota_currentness: ProtectedCurrentnessWitnessV1,
    result_transaction: ProtectedNetworkTransactionV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    require_attempt(
        current.generation,
        current.replacement_id,
        expected_generation,
        replacement_id,
    )?;
    let registry = current.reserved_registry.rollback_reservation(
        current.predecessor.source().ingress(),
        current.candidate.source().ingress(),
    )?;
    if result_ingress_currentness.record_digest() != registry.digest()
        || !result_ingress_currentness.is_exact_successor_of(current.reserved_ingress_currentness)
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    let quota = current.reserved_quota.rollback_reservation(
        current.candidate.source().identity().project(),
        current.candidate.usage(),
        result_quota_currentness,
    )?;
    if !result_transaction.covers(&registry, result_ingress_currentness, &quota)
        || !result_transaction.is_exact_successor_of(current.reserved_transaction)
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    Ok(NetworkPolicyReplacementStateV1::Aborted(TerminalStateV1 {
        generation: next_generation(current.generation)?,
        replacement_id,
        predecessor: current.predecessor.clone(),
        candidate: current.candidate.clone(),
        active: current.predecessor.clone(),
        registry,
        registry_currentness: result_ingress_currentness,
        aggregate_quota: quota,
        transaction: result_transaction,
        advisory_degradations: current.predecessor_degradations.clone(),
        baseline_observation: current.predecessor_observation.clone(),
        observation: Some(current.predecessor_observation.clone()),
    }))
}

fn require_attempt(
    generation: u64,
    current_id: OperationId,
    expected_generation: u64,
    supplied_id: OperationId,
) -> Result<(), AdvancedNetworkPolicyError> {
    if generation != expected_generation || current_id != supplied_id {
        return Err(AdvancedNetworkPolicyError::InvalidTransition);
    }
    Ok(())
}

fn valid_degradations(policy: &CompiledAdvancedNetworkPolicyV1, values: &[FeatureRef]) -> bool {
    values.len() <= MAXIMUM_FEATURES
        && strictly_increasing(values)
        && values.iter().all(|feature| {
            policy
                .source()
                .advisory_features()
                .binary_search(feature)
                .is_ok()
        })
}

fn next_generation(value: u64) -> Result<u64, AdvancedNetworkPolicyError> {
    value
        .checked_add(1)
        .ok_or(AdvancedNetworkPolicyError::InvalidTransition)
}

fn capability_digest(features: &[FeatureRef]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(CAPABILITY_DOMAIN);
    digest.update((features.len() as u16).to_be_bytes());
    for feature in features {
        digest.update([feature.namespace().len() as u8]);
        digest.update(feature.namespace().as_bytes());
        digest.update(feature.major().to_be_bytes());
        digest.update(feature.minor().to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn protected_capability_digest(
    content: ObjectDigest,
    witness: ProtectedCurrentnessWitnessV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.protected-capabilities.v1\0");
    digest.update(content.as_bytes());
    digest.update(witness.current_head().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn observer_namespace(handle: [u8; 32], allocation: u64) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.observer-namespace.v1\0");
    digest.update(handle);
    digest.update(allocation.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn recovery_checkpoint_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RECOVERY_CHECKPOINT_DOMAIN);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn observation_digest(
    observed: ObservedNetworkPolicyV1,
    boot_currentness: ProtectedCurrentnessWitnessV1,
    projection: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(OBSERVATION_DOMAIN);
    digest.update([observed_code(observed)]);
    digest.update(boot_currentness.current_head().as_bytes());
    digest.update(projection.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn recovery_authorization_digest(
    reservation: &ReservedStateV1,
    observation: &NetworkReplacementObservationV1,
    recovery_id: OperationId,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RECOVERY_AUTHORIZATION_DOMAIN);
    digest.update(reservation.replacement_id.as_bytes());
    digest.update(recovery_id.as_bytes());
    digest.update(reservation.predecessor.digest().as_bytes());
    digest.update(reservation.candidate.digest().as_bytes());
    digest.update(reservation.reserved_transaction.digest().as_bytes());
    digest.update(observation.digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn observer_projection_digest(
    observed: ObservedNetworkPolicyV1,
    boot: [u8; 16],
    device: u64,
    inode: u64,
    host_ifindex: u32,
    sandbox_ifindex: u32,
    host_peer_ifindex: u32,
    sandbox_peer_ifindex: u32,
    host_mac: [u8; 6],
    sandbox_mac: [u8; 6],
    handle: [u8; 32],
    allocation: u64,
    addresses: &[NetworkAddressPairV1],
    routes: &[NetworkRouteV1],
    anti_spoof: &[ObservedAntiSpoofBindingV1],
    predecessor: Option<&ObservedRevisionEffectsV1>,
    candidate: Option<&ObservedRevisionEffectsV1>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.observer-projection.v1\0");
    digest.update([observed_code(observed)]);
    digest.update(boot);
    digest.update(device.to_be_bytes());
    digest.update(inode.to_be_bytes());
    for value in [
        host_ifindex,
        sandbox_ifindex,
        host_peer_ifindex,
        sandbox_peer_ifindex,
    ] {
        digest.update(value.to_be_bytes());
    }
    digest.update(host_mac);
    digest.update(sandbox_mac);
    digest.update(handle);
    digest.update(allocation.to_be_bytes());
    digest.update((addresses.len() as u16).to_be_bytes());
    for pair in addresses {
        digest.update(encode_ip(pair.host()));
        digest.update(encode_ip(pair.sandbox()));
        digest.update([pair.prefix_length()]);
    }
    digest.update((routes.len() as u16).to_be_bytes());
    for route in routes {
        digest.update(encode_prefix(route.destination()));
        digest.update(encode_ip(route.gateway()));
    }
    digest.update((anti_spoof.len() as u16).to_be_bytes());
    for binding in anti_spoof {
        digest.update([match binding.peer {
            AntiSpoofPeerV1::Host => 1,
            AntiSpoofPeerV1::Sandbox => 2,
        }]);
        digest.update(encode_ip(binding.address));
        digest.update(binding.mac);
    }
    for effects in [predecessor, candidate] {
        match effects {
            Some(value) => {
                digest.update([1]);
                digest.update(value.assignment_digest.as_bytes());
                digest.update(value.namespace_plan_digest.as_bytes());
                digest.update(value.program.digest().as_bytes());
                digest.update(value.translation.digest().as_bytes());
            }
            None => digest.update([0]),
        }
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn effects_match(
    observed: &ObservedRevisionEffectsV1,
    expected: &CompiledAdvancedNetworkPolicyV1,
) -> bool {
    observed.assignment_digest == expected.source().identity().assignment().digest()
        && observed.namespace_plan_digest == expected.namespace_plan_digest()
        && observed.program == *expected.program()
        && observed.translation == *expected.translation()
}

fn expected_anti_spoof(
    policy: &CompiledAdvancedNetworkPolicyV1,
) -> Vec<ObservedAntiSpoofBindingV1> {
    let physical = policy.source().identity().physical();
    let (Some(host_mac), Some(sandbox_mac)) = (physical.host_mac(), physical.sandbox_mac()) else {
        return Vec::new();
    };
    let mut bindings = Vec::with_capacity(policy.namespace_plan().address_pairs().len() * 2);
    for pair in policy.namespace_plan().address_pairs() {
        bindings.push(ObservedAntiSpoofBindingV1::new(
            AntiSpoofPeerV1::Host,
            pair.host(),
            host_mac,
        ));
        bindings.push(ObservedAntiSpoofBindingV1::new(
            AntiSpoofPeerV1::Sandbox,
            pair.sandbox(),
            sandbox_mac,
        ));
    }
    bindings.sort_unstable();
    bindings
}

fn encode_ip(value: NetworkIpAddressV1) -> [u8; 17] {
    let mut bytes = [0; 17];
    match value {
        NetworkIpAddressV1::Ipv4(address) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&address);
        }
        NetworkIpAddressV1::Ipv6(address) => {
            bytes[0] = 6;
            bytes[1..].copy_from_slice(&address);
        }
    }
    bytes
}

fn encode_prefix(value: crate::policy::NetworkIpPrefixV1) -> [u8; 18] {
    let mut bytes = [0; 18];
    match value {
        crate::policy::NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => {
            bytes[0] = 4;
            bytes[1] = prefix_length;
            bytes[2..6].copy_from_slice(&network);
        }
        crate::policy::NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => {
            bytes[0] = 6;
            bytes[1] = prefix_length;
            bytes[2..].copy_from_slice(&network);
        }
    }
    bytes
}

fn valid_link_shape(
    host: u32,
    sandbox: u32,
    host_peer: u32,
    sandbox_peer: u32,
    host_mac: [u8; 6],
    sandbox_mac: [u8; 6],
) -> bool {
    let isolated = host == 0
        && sandbox == 0
        && host_peer == 0
        && sandbox_peer == 0
        && host_mac == [0; 6]
        && sandbox_mac == [0; 6];
    let veth = host != 0
        && sandbox != 0
        && host != sandbox
        && host_peer == sandbox
        && sandbox_peer == host
        && host_mac != [0; 6]
        && sandbox_mac != [0; 6]
        && host_mac[0] & 0x03 == 0x02
        && sandbox_mac[0] & 0x03 == 0x02;
    isolated || veth
}

const fn observed_code(value: ObservedNetworkPolicyV1) -> u8 {
    match value {
        ObservedNetworkPolicyV1::Predecessor => 1,
        ObservedNetworkPolicyV1::Candidate => 2,
        ObservedNetworkPolicyV1::Absent => 3,
        ObservedNetworkPolicyV1::Mixed => 4,
    }
}

struct RecoveryReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> RecoveryReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], AdvancedNetworkPolicyError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AdvancedNetworkPolicyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
    }
    fn byte(&mut self) -> Result<u8, AdvancedNetworkPolicyError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, AdvancedNetworkPolicyError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, AdvancedNetworkPolicyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, AdvancedNetworkPolicyError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn blob(&mut self, maximum: usize) -> Result<Option<&'a [u8]>, AdvancedNetworkPolicyError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        if length == 0 {
            return Ok(None);
        }
        if length > maximum {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Some(self.take(length)?))
    }
    fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

fn recovery_blob(
    bytes: &mut Vec<u8>,
    value: Option<&[u8]>,
) -> Result<(), AdvancedNetworkPolicyError> {
    match value {
        Some(value) => {
            let length =
                u32::try_from(value.len()).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(value);
        }
        None => bytes.extend_from_slice(&0_u32.to_be_bytes()),
    }
    Ok(())
}

fn encode_recovery_features(
    bytes: &mut Vec<u8>,
    values: &[FeatureRef],
) -> Result<(), AdvancedNetworkPolicyError> {
    let count = u8::try_from(values.len()).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    bytes.push(count);
    for value in values {
        let length = u8::try_from(value.namespace().len())
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        bytes.push(length);
        bytes.extend_from_slice(value.namespace().as_bytes());
        bytes.extend_from_slice(&value.major().to_be_bytes());
        bytes.extend_from_slice(&value.minor().to_be_bytes());
    }
    Ok(())
}
fn decode_recovery_features(
    reader: &mut RecoveryReader<'_>,
    maximum: usize,
) -> Result<Vec<FeatureRef>, AdvancedNetworkPolicyError> {
    let count = usize::from(reader.byte()?);
    if count > maximum {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(reader.byte()?);
        let namespace = core::str::from_utf8(reader.take(length)?)
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?
            .to_owned();
        let major = reader.u32()?;
        let minor = reader.u32()?;
        values.push(
            FeatureRef::new(namespace, major, minor)
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
    }
    if !strictly_increasing(&values) {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(values)
}

fn encode_capabilities(
    value: &ReplacementCapabilitiesV1,
) -> Result<Vec<u8>, AdvancedNetworkPolicyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AOSRCP01");
    bytes.extend_from_slice(&value.currentness.encode_recovery());
    encode_recovery_features(&mut bytes, &value.features)?;
    Ok(bytes)
}
fn decode_capabilities(
    bytes: &[u8],
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<ReplacementCapabilitiesV1, AdvancedNetworkPolicyError> {
    if bytes.len() > 32 * 1024 || bytes.get(..8) != Some(b"AOSRCP01") {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut reader = RecoveryReader::new(&bytes[8..]);
    let witness = ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
    let features = decode_recovery_features(&mut reader, MAXIMUM_FEATURES)?;
    if !reader.finished() {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let value = ReplacementCapabilitiesV1::new(features, witness)?;
    if encode_capabilities(&value)? != bytes {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(value)
}

fn encode_observation(
    value: &NetworkReplacementObservationV1,
) -> Result<Vec<u8>, AdvancedNetworkPolicyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AOSOBS02");
    bytes.push(observed_code(value.observed));
    bytes.extend_from_slice(&value.kernel_boot_id);
    bytes.extend_from_slice(&value.boot_currentness.encode_recovery());
    bytes.extend_from_slice(&value.namespace_device.to_be_bytes());
    bytes.extend_from_slice(&value.namespace_inode.to_be_bytes());
    for item in [
        value.host_ifindex,
        value.sandbox_ifindex,
        value.host_peer_ifindex,
        value.sandbox_peer_ifindex,
    ] {
        bytes.extend_from_slice(&item.to_be_bytes());
    }
    bytes.extend_from_slice(&value.host_mac);
    bytes.extend_from_slice(&value.sandbox_mac);
    bytes.extend_from_slice(&value.network_handle);
    bytes.extend_from_slice(&value.allocation_generation.to_be_bytes());
    bytes.extend_from_slice(&(value.address_pairs.len() as u16).to_be_bytes());
    for pair in &value.address_pairs {
        bytes.extend_from_slice(&encode_ip(pair.host()));
        bytes.extend_from_slice(&encode_ip(pair.sandbox()));
        bytes.push(pair.prefix_length());
    }
    bytes.extend_from_slice(&(value.routes.len() as u16).to_be_bytes());
    for route in &value.routes {
        bytes.extend_from_slice(&encode_prefix(route.destination()));
        bytes.extend_from_slice(&encode_ip(route.gateway()));
    }
    bytes.extend_from_slice(&(value.anti_spoof.len() as u16).to_be_bytes());
    for binding in &value.anti_spoof {
        bytes.push(match binding.peer {
            AntiSpoofPeerV1::Host => 1,
            AntiSpoofPeerV1::Sandbox => 2,
        });
        bytes.extend_from_slice(&encode_ip(binding.address));
        bytes.extend_from_slice(&binding.mac);
    }
    Ok(bytes)
}

fn decode_observation(
    bytes: &[u8],
    predecessor: &CompiledAdvancedNetworkPolicyV1,
    candidate: Option<&CompiledAdvancedNetworkPolicyV1>,
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<NetworkReplacementObservationV1, AdvancedNetworkPolicyError> {
    if bytes.len() > 256 * 1024 || bytes.get(..8) != Some(b"AOSOBS02") {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut reader = RecoveryReader::new(&bytes[8..]);
    let observed = match reader.byte()? {
        1 => ObservedNetworkPolicyV1::Predecessor,
        2 => ObservedNetworkPolicyV1::Candidate,
        3 => ObservedNetworkPolicyV1::Absent,
        4 => ObservedNetworkPolicyV1::Mixed,
        _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
    };
    let boot = reader.array()?;
    let witness = ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
    let device = reader.u64()?;
    let inode = reader.u64()?;
    let host_ifindex = reader.u32()?;
    let sandbox_ifindex = reader.u32()?;
    let host_peer = reader.u32()?;
    let sandbox_peer = reader.u32()?;
    let host_mac = reader.array()?;
    let sandbox_mac = reader.array()?;
    let handle = reader.array()?;
    let allocation = reader.u64()?;
    let address_count = usize::from(reader.u16()?);
    if address_count > MAXIMUM_OBSERVED_ADDRESSES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut addresses = Vec::with_capacity(address_count);
    for _ in 0..address_count {
        let host = decode_observed_ip(&mut reader)?;
        let sandbox = decode_observed_ip(&mut reader)?;
        let prefix = reader.byte()?;
        addresses.push(
            NetworkAddressPairV1::recover(host, sandbox, prefix)
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
    }
    let route_count = usize::from(reader.u16()?);
    if route_count > MAXIMUM_OBSERVED_ROUTES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut routes = Vec::with_capacity(route_count);
    for _ in 0..route_count {
        let destination = decode_observed_prefix(&mut reader)?;
        let gateway = decode_observed_ip(&mut reader)?;
        routes.push(
            NetworkRouteV1::recover(destination, gateway)
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
    }
    let binding_count = usize::from(reader.u16()?);
    if binding_count > MAXIMUM_ANTI_SPOOF_BINDINGS {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut anti_spoof = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let peer = match reader.byte()? {
            1 => AntiSpoofPeerV1::Host,
            2 => AntiSpoofPeerV1::Sandbox,
            _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
        };
        let address = decode_observed_ip(&mut reader)?;
        let mac = reader.array()?;
        anti_spoof.push(ObservedAntiSpoofBindingV1::new(peer, address, mac));
    }
    if !reader.finished() {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let effects = |policy: &CompiledAdvancedNetworkPolicyV1| {
        ObservedRevisionEffectsV1::new(
            policy.source().identity().assignment().digest(),
            policy.namespace_plan_digest(),
            policy.program().clone(),
            policy.translation().clone(),
        )
    };
    let predecessor_effects = matches!(
        observed,
        ObservedNetworkPolicyV1::Predecessor | ObservedNetworkPolicyV1::Mixed
    )
    .then(|| effects(predecessor))
    .transpose()?;
    let candidate_policy = candidate.unwrap_or(predecessor);
    let candidate_effects = matches!(
        observed,
        ObservedNetworkPolicyV1::Candidate | ObservedNetworkPolicyV1::Mixed
    )
    .then(|| effects(candidate_policy))
    .transpose()?;
    if observed == ObservedNetworkPolicyV1::Mixed && candidate.is_none() {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let projection = NetworkObserverProjectionV1::new(
        boot,
        device,
        inode,
        host_ifindex,
        sandbox_ifindex,
        host_peer,
        sandbox_peer,
        host_mac,
        sandbox_mac,
        handle,
        allocation,
        addresses,
        routes,
        anti_spoof,
        predecessor_effects,
        candidate_effects,
    );
    let value =
        NetworkReplacementObservationV1::seal_observer_projection(observed, witness, projection)?;
    if encode_observation(&value)? != bytes {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(value)
}

fn decode_observed_ip(
    reader: &mut RecoveryReader<'_>,
) -> Result<NetworkIpAddressV1, AdvancedNetworkPolicyError> {
    match reader.byte()? {
        4 => {
            let raw = reader.array::<16>()?;
            if raw[4..].iter().any(|byte| *byte != 0) {
                Err(AdvancedNetworkPolicyError::NonCanonical)
            } else {
                Ok(NetworkIpAddressV1::Ipv4(
                    raw[..4]
                        .try_into()
                        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
                ))
            }
        }
        6 => Ok(NetworkIpAddressV1::Ipv6(reader.array()?)),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}
fn decode_observed_prefix(
    reader: &mut RecoveryReader<'_>,
) -> Result<crate::policy::NetworkIpPrefixV1, AdvancedNetworkPolicyError> {
    let family = reader.byte()?;
    let length = reader.byte()?;
    match family {
        4 => {
            let raw = reader.array::<16>()?;
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            crate::policy::NetworkIpPrefixV1::ipv4(
                raw[..4]
                    .try_into()
                    .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
                length,
            )
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
        }
        6 => crate::policy::NetworkIpPrefixV1::ipv6(reader.array()?, length)
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}

fn encode_recovery_payload(
    state: &NetworkPolicyReplacementStateV1,
) -> Result<Vec<u8>, AdvancedNetworkPolicyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AOSRPS01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(phase_code(state.phase()));
    bytes.push(0);

    match state {
        NetworkPolicyReplacementStateV1::Stable(value) => {
            encode_stable_state(&mut bytes, value)?;
        }
        NetworkPolicyReplacementStateV1::Reserved(value) => {
            encode_reserved_state(&mut bytes, value)?;
        }
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            encode_ambiguous_state(&mut bytes, value)?;
        }
        NetworkPolicyReplacementStateV1::Committed(value)
        | NetworkPolicyReplacementStateV1::RolledBack(value)
        | NetworkPolicyReplacementStateV1::Aborted(value) => {
            encode_terminal_state(&mut bytes, value)?;
        }
    }
    if bytes.len() > MAXIMUM_COMPANION_PAYLOAD_BYTES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(bytes)
}

fn decode_recovery_payload(
    bytes: &[u8],
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    if bytes.len() < 12
        || bytes.len() > MAXIMUM_COMPANION_PAYLOAD_BYTES
        || bytes.get(..8) != Some(b"AOSRPS01")
        || u16::from_be_bytes([bytes[8], bytes[9]]) != 1
        || bytes[11] != 0
    {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let phase = decode_phase(bytes[10]).ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
    let mut reader = RecoveryReader::new(&bytes[12..]);
    let state = match phase {
        NetworkPolicyReplacementPhaseV1::Stable => decode_stable_state(&mut reader, authorities)?,
        NetworkPolicyReplacementPhaseV1::Reserved => NetworkPolicyReplacementStateV1::Reserved(
            decode_reserved_state(&mut reader, authorities)?,
        ),
        NetworkPolicyReplacementPhaseV1::EffectReleased
        | NetworkPolicyReplacementPhaseV1::RecoveryRequired
        | NetworkPolicyReplacementPhaseV1::RecoveryAuthorized
        | NetworkPolicyReplacementPhaseV1::RecoveryFenced
        | NetworkPolicyReplacementPhaseV1::RecoveryApplyPrepared
        | NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased => {
            decode_ambiguous_state(&mut reader, phase, authorities)?
        }
        NetworkPolicyReplacementPhaseV1::Committed
        | NetworkPolicyReplacementPhaseV1::RolledBack
        | NetworkPolicyReplacementPhaseV1::Aborted => {
            decode_terminal_state(&mut reader, phase, authorities)?
        }
    };
    if !reader.finished() || encode_recovery_payload(&state)? != bytes {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(state)
}

fn encode_stable_state(
    bytes: &mut Vec<u8>,
    state: &StableStateV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    bytes.extend_from_slice(&state.generation.to_be_bytes());
    recovery_blob(bytes, Some(&state.active.encode_recovery()))?;
    bytes.extend_from_slice(&state.registry_currentness.encode_recovery());
    recovery_blob(bytes, Some(&state.registry.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.aggregate_quota.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.transaction.encode_recovery()))?;
    encode_recovery_features(bytes, &state.advisory_degradations)?;
    recovery_blob(bytes, Some(&encode_observation(&state.active_observation)?))?;
    Ok(())
}

fn decode_stable_state(
    reader: &mut RecoveryReader<'_>,
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    let generation = reader.u64()?;
    let active = CompiledAdvancedNetworkPolicyV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        authorities,
    )?;
    let registry_currentness =
        ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
    let registry = ExternalIngressRegistryV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        registry_currentness,
        authorities,
    )?;
    let quota =
        ProtectedNetworkQuotaV1::decode_recovery(required_blob(reader, 32 * 1024)?, authorities)?;
    let transaction = ProtectedNetworkTransactionV1::decode_recovery(
        required_blob(reader, 675)?,
        &registry,
        registry_currentness,
        &quota,
        authorities,
    )?;
    let degradations = decode_recovery_features(reader, MAXIMUM_FEATURES)?;
    let observation = decode_observation(
        required_blob(reader, 256 * 1024)?,
        &active,
        None,
        authorities,
    )?;
    NetworkPolicyReplacementStateV1::stable(
        generation,
        active,
        registry,
        registry_currentness,
        quota,
        transaction,
        degradations,
        observation,
    )
}

fn encode_reserved_state(
    bytes: &mut Vec<u8>,
    state: &ReservedStateV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    bytes.extend_from_slice(&state.generation.to_be_bytes());
    bytes.extend_from_slice(state.replacement_id.as_bytes());
    recovery_blob(bytes, Some(&state.predecessor.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.candidate.encode_recovery()))?;
    bytes.extend_from_slice(&state.reserved_ingress_currentness.encode_recovery());
    recovery_blob(bytes, Some(&state.reserved_registry.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.reserved_quota.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.reserved_transaction.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.pool.encode_recovery()))?;
    recovery_blob(bytes, Some(&encode_capabilities(&state.capabilities)?))?;
    encode_recovery_features(bytes, &state.predecessor_degradations)?;
    encode_recovery_features(bytes, &state.candidate_degradations)?;
    recovery_blob(
        bytes,
        Some(&encode_observation(&state.predecessor_observation)?),
    )?;
    Ok(())
}

fn decode_reserved_state(
    reader: &mut RecoveryReader<'_>,
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<ReservedStateV1, AdvancedNetworkPolicyError> {
    let generation = reader.u64()?;
    let replacement_id = OperationId::from_bytes(reader.array()?);
    let predecessor = CompiledAdvancedNetworkPolicyV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        authorities,
    )?;
    let candidate = CompiledAdvancedNetworkPolicyV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        authorities,
    )?;
    let registry_currentness =
        ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
    let registry = ExternalIngressRegistryV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        registry_currentness,
        authorities,
    )?;
    let quota =
        ProtectedNetworkQuotaV1::decode_recovery(required_blob(reader, 32 * 1024)?, authorities)?;
    let transaction = ProtectedNetworkTransactionV1::decode_recovery(
        required_blob(reader, 675)?,
        &registry,
        registry_currentness,
        &quota,
        authorities,
    )?;
    let pool = IngressPoolAuthorityV1::decode_recovery(required_blob(reader, 4096)?, authorities)?;
    let capabilities = decode_capabilities(required_blob(reader, 32 * 1024)?, authorities)?;
    let predecessor_degradations = decode_recovery_features(reader, MAXIMUM_FEATURES)?;
    let candidate_degradations = decode_recovery_features(reader, MAXIMUM_FEATURES)?;
    let predecessor_observation = decode_observation(
        required_blob(reader, 256 * 1024)?,
        &predecessor,
        Some(&candidate),
        authorities,
    )?;
    let state = ReservedStateV1 {
        generation,
        replacement_id,
        predecessor,
        candidate,
        reserved_registry: registry,
        reserved_ingress_currentness: registry_currentness,
        reserved_quota: quota,
        reserved_transaction: transaction,
        pool,
        capabilities,
        predecessor_degradations,
        candidate_degradations,
        predecessor_observation,
    };
    validate_reserved_state(&state)?;
    Ok(state)
}

fn encode_ambiguous_state(
    bytes: &mut Vec<u8>,
    state: &AmbiguousStateV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    encode_reserved_state(bytes, &state.reservation)?;
    let observation = state
        .observation
        .as_ref()
        .map(encode_observation)
        .transpose()?;
    recovery_blob(bytes, observation.as_deref())?;
    match &state.recovery {
        Some(recovery) => {
            bytes.push(1);
            bytes.extend_from_slice(recovery.recovery_id.as_bytes());
            bytes.extend_from_slice(&recovery.authority.encode_recovery());
            recovery_blob(
                bytes,
                Some(&encode_observation(&recovery.authorization_observation)?),
            )?;
            let fenced = recovery
                .fenced_observation
                .as_ref()
                .map(encode_observation)
                .transpose()?;
            recovery_blob(bytes, fenced.as_deref())?;
        }
        None => bytes.push(0),
    }
    Ok(())
}

fn decode_ambiguous_state(
    reader: &mut RecoveryReader<'_>,
    phase: NetworkPolicyReplacementPhaseV1,
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    let reservation = decode_reserved_state(reader, authorities)?;
    let observation = reader
        .blob(256 * 1024)?
        .map(|bytes| {
            decode_observation(
                bytes,
                &reservation.predecessor,
                Some(&reservation.candidate),
                authorities,
            )
        })
        .transpose()?;
    let recovery = match reader.byte()? {
        0 => None,
        1 => {
            let recovery_id = OperationId::from_bytes(reader.array()?);
            let authority =
                ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
            let authorization_observation = decode_observation(
                required_blob(reader, 256 * 1024)?,
                &reservation.predecessor,
                Some(&reservation.candidate),
                authorities,
            )?;
            let fenced_observation = reader
                .blob(256 * 1024)?
                .map(|bytes| {
                    decode_observation(
                        bytes,
                        &reservation.predecessor,
                        Some(&reservation.candidate),
                        authorities,
                    )
                })
                .transpose()?;
            Some(RecoveryAttemptV1 {
                recovery_id,
                authority,
                authorization_observation,
                fenced_observation,
            })
        }
        _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
    };
    let ambiguous = AmbiguousStateV1 {
        reservation,
        observation,
        recovery,
    };
    validate_ambiguous_state(&ambiguous, phase)?;
    Ok(match phase {
        NetworkPolicyReplacementPhaseV1::EffectReleased => {
            NetworkPolicyReplacementStateV1::EffectReleased(ambiguous)
        }
        NetworkPolicyReplacementPhaseV1::RecoveryRequired => {
            NetworkPolicyReplacementStateV1::RecoveryRequired(ambiguous)
        }
        NetworkPolicyReplacementPhaseV1::RecoveryAuthorized => {
            NetworkPolicyReplacementStateV1::RecoveryAuthorized(ambiguous)
        }
        NetworkPolicyReplacementPhaseV1::RecoveryFenced => {
            NetworkPolicyReplacementStateV1::RecoveryFenced(ambiguous)
        }
        NetworkPolicyReplacementPhaseV1::RecoveryApplyPrepared => {
            NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(ambiguous)
        }
        NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased => {
            NetworkPolicyReplacementStateV1::RecoveryEffectReleased(ambiguous)
        }
        _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
    })
}

fn encode_terminal_state(
    bytes: &mut Vec<u8>,
    state: &TerminalStateV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    bytes.extend_from_slice(&state.generation.to_be_bytes());
    bytes.extend_from_slice(state.replacement_id.as_bytes());
    recovery_blob(bytes, Some(&state.predecessor.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.candidate.encode_recovery()))?;
    bytes.extend_from_slice(&state.registry_currentness.encode_recovery());
    recovery_blob(bytes, Some(&state.registry.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.aggregate_quota.encode_recovery()))?;
    recovery_blob(bytes, Some(&state.transaction.encode_recovery()))?;
    encode_recovery_features(bytes, &state.advisory_degradations)?;
    recovery_blob(
        bytes,
        Some(&encode_observation(&state.baseline_observation)?),
    )?;
    let observation = state
        .observation
        .as_ref()
        .map(encode_observation)
        .transpose()?;
    recovery_blob(bytes, observation.as_deref())?;
    Ok(())
}

fn decode_terminal_state(
    reader: &mut RecoveryReader<'_>,
    phase: NetworkPolicyReplacementPhaseV1,
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
    let generation = reader.u64()?;
    let replacement_id = OperationId::from_bytes(reader.array()?);
    let predecessor = CompiledAdvancedNetworkPolicyV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        authorities,
    )?;
    let candidate = CompiledAdvancedNetworkPolicyV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        authorities,
    )?;
    let active = match phase {
        NetworkPolicyReplacementPhaseV1::Committed => candidate.clone(),
        NetworkPolicyReplacementPhaseV1::RolledBack | NetworkPolicyReplacementPhaseV1::Aborted => {
            predecessor.clone()
        }
        _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
    };
    let registry_currentness =
        ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
    let registry = ExternalIngressRegistryV1::decode_recovery(
        required_blob(reader, 4 * 1024 * 1024)?,
        registry_currentness,
        authorities,
    )?;
    let quota =
        ProtectedNetworkQuotaV1::decode_recovery(required_blob(reader, 32 * 1024)?, authorities)?;
    let transaction = ProtectedNetworkTransactionV1::decode_recovery(
        required_blob(reader, 675)?,
        &registry,
        registry_currentness,
        &quota,
        authorities,
    )?;
    let degradations = decode_recovery_features(reader, MAXIMUM_FEATURES)?;
    let baseline_observation = decode_observation(
        required_blob(reader, 256 * 1024)?,
        &predecessor,
        Some(&candidate),
        authorities,
    )?;
    let observation = reader
        .blob(256 * 1024)?
        .map(|bytes| decode_observation(bytes, &predecessor, Some(&candidate), authorities))
        .transpose()?;
    let terminal = TerminalStateV1 {
        generation,
        replacement_id,
        predecessor,
        candidate,
        active,
        registry,
        registry_currentness,
        aggregate_quota: quota,
        transaction,
        advisory_degradations: degradations,
        baseline_observation,
        observation,
    };
    validate_terminal_state(&terminal, phase)?;
    Ok(match phase {
        NetworkPolicyReplacementPhaseV1::Committed => {
            NetworkPolicyReplacementStateV1::Committed(terminal)
        }
        NetworkPolicyReplacementPhaseV1::RolledBack => {
            NetworkPolicyReplacementStateV1::RolledBack(terminal)
        }
        NetworkPolicyReplacementPhaseV1::Aborted => {
            NetworkPolicyReplacementStateV1::Aborted(terminal)
        }
        _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
    })
}

fn validate_reserved_state(state: &ReservedStateV1) -> Result<(), AdvancedNetworkPolicyError> {
    let predecessor_ingress = state.predecessor.source().ingress();
    let candidate_ingress = state.candidate.source().ingress();
    let supports_policy = |policy: &CompiledAdvancedNetworkPolicyV1| {
        policy
            .source()
            .hard_features()
            .iter()
            .all(|feature| state.capabilities.features.binary_search(feature).is_ok())
    };
    let pool_admits = |policy: &CompiledAdvancedNetworkPolicyV1| {
        policy
            .source()
            .ingress()
            .allocations()
            .iter()
            .all(|allocation| state.pool.admits(allocation.external()))
    };
    let expected_candidate_degradations = state
        .candidate
        .source()
        .advisory_features()
        .iter()
        .filter(|feature| state.capabilities.features.binary_search(feature).is_err())
        .cloned()
        .collect::<Vec<_>>();
    if state.generation == 0
        || state.replacement_id.as_bytes() == &[0; 16]
        || !state
            .predecessor
            .source()
            .identity()
            .admits_successor(state.candidate.source().identity())
        || state.reserved_registry.node() != state.pool.node()
        || state.reserved_ingress_currentness.purpose()
            != ProtectedWitnessPurposeV1::IngressRegistry
        || state.reserved_ingress_currentness.namespace()
            != node_namespace(state.reserved_registry.node())
        || state.reserved_ingress_currentness.record_digest() != state.reserved_registry.digest()
        || !state.reserved_registry.retains_policy(predecessor_ingress)
        || !registry_retains_candidate(&state.reserved_registry, candidate_ingress)
        || !state.reserved_registry.has_in_flight_lineage()
        || !state.reserved_quota.covers_active(
            state.predecessor.source().identity().project(),
            state.predecessor.usage(),
        )
        || !state.reserved_quota.contains_reservation(
            state.candidate.source().identity().project(),
            state.candidate.usage(),
        )
        || !state.reserved_transaction.covers(
            &state.reserved_registry,
            state.reserved_ingress_currentness,
            &state.reserved_quota,
        )
        || state.capabilities.currentness().namespace() != node_namespace(state.pool.node())
        || !supports_policy(&state.predecessor)
        || !supports_policy(&state.candidate)
        || !pool_admits(&state.predecessor)
        || !pool_admits(&state.candidate)
        || !valid_degradations(&state.predecessor, &state.predecessor_degradations)
        || !valid_degradations(&state.candidate, &state.candidate_degradations)
        || state.candidate_degradations != expected_candidate_degradations
        || !state
            .predecessor_observation
            .matches_policy(&state.predecessor, ObservedNetworkPolicyV1::Predecessor)
    {
        return Err(AdvancedNetworkPolicyError::InvalidTransition);
    }
    Ok(())
}

fn validate_ambiguous_state(
    state: &AmbiguousStateV1,
    phase: NetworkPolicyReplacementPhaseV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    validate_reserved_state(&state.reservation)?;
    let recoverable = |observation: &NetworkReplacementObservationV1| {
        matches!(
            observation.observed,
            ObservedNetworkPolicyV1::Absent | ObservedNetworkPolicyV1::Mixed
        ) && observation
            .matches_attempt_scope(&state.reservation.predecessor, &state.reservation.candidate)
            && observation.boot_currentness.is_later_in_same_journal(
                state.reservation.predecessor_observation.boot_currentness,
            )
    };
    let recovery_is_valid = |attempt: &RecoveryAttemptV1| {
        attempt.recovery_id.as_bytes() != &[0; 16]
            && recoverable(&attempt.authorization_observation)
            && attempt.authority.purpose() == ProtectedWitnessPurposeV1::RecoveryAuthority
            && attempt
                .authority
                .is_exact_journal_successor_of(attempt.authorization_observation.boot_currentness)
            && attempt.authority.namespace()
                == observer_namespace(
                    state
                        .reservation
                        .predecessor
                        .source()
                        .identity()
                        .physical()
                        .network_handle(),
                    state
                        .reservation
                        .predecessor
                        .source()
                        .identity()
                        .physical()
                        .generation(),
                )
            && attempt.authority.record_digest()
                == recovery_authorization_digest(
                    &state.reservation,
                    &attempt.authorization_observation,
                    attempt.recovery_id,
                )
    };
    let valid = match phase {
        NetworkPolicyReplacementPhaseV1::EffectReleased => {
            state.observation.is_none() && state.recovery.is_none()
        }
        NetworkPolicyReplacementPhaseV1::RecoveryRequired => {
            state.observation.as_ref().is_some_and(recoverable) && state.recovery.is_none()
        }
        NetworkPolicyReplacementPhaseV1::RecoveryAuthorized => {
            state.recovery.as_ref().is_some_and(|attempt| {
                recovery_is_valid(attempt)
                    && attempt.fenced_observation.is_none()
                    && state.observation.as_ref() == Some(&attempt.authorization_observation)
            })
        }
        NetworkPolicyReplacementPhaseV1::RecoveryFenced
        | NetworkPolicyReplacementPhaseV1::RecoveryApplyPrepared => {
            state.recovery.as_ref().is_some_and(|attempt| {
                recovery_is_valid(attempt)
                    && attempt
                        .fenced_observation
                        .as_ref()
                        .is_some_and(|observation| {
                            observation.observed == ObservedNetworkPolicyV1::Absent
                                && recoverable(observation)
                                && observation
                                    .boot_currentness
                                    .is_exact_journal_successor_of(attempt.authority)
                                && state.observation.as_ref() == Some(observation)
                        })
            })
        }
        NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased => {
            state.recovery.as_ref().is_some_and(|attempt| {
                recovery_is_valid(attempt)
                    && attempt
                        .fenced_observation
                        .as_ref()
                        .is_some_and(|observation| {
                            observation.observed == ObservedNetworkPolicyV1::Absent
                                && recoverable(observation)
                                && observation
                                    .boot_currentness
                                    .is_exact_journal_successor_of(attempt.authority)
                        })
                    && state.observation.is_none()
            })
        }
        _ => false,
    };
    if !valid {
        return Err(AdvancedNetworkPolicyError::InvalidTransition);
    }
    Ok(())
}

fn validate_terminal_state(
    state: &TerminalStateV1,
    phase: NetworkPolicyReplacementPhaseV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    let active_is_expected = match phase {
        NetworkPolicyReplacementPhaseV1::Committed => {
            state.active == state.candidate
                && state.observation.as_ref().is_some_and(|observation| {
                    observation.matches_policy(&state.candidate, ObservedNetworkPolicyV1::Candidate)
                        && observation
                            .boot_currentness
                            .is_later_in_same_journal(state.baseline_observation.boot_currentness)
                })
        }
        NetworkPolicyReplacementPhaseV1::RolledBack => {
            state.active == state.predecessor
                && state.observation.as_ref().is_some_and(|observation| {
                    observation
                        .matches_policy(&state.predecessor, ObservedNetworkPolicyV1::Predecessor)
                        && observation
                            .boot_currentness
                            .is_later_in_same_journal(state.baseline_observation.boot_currentness)
                })
        }
        NetworkPolicyReplacementPhaseV1::Aborted => {
            state.active == state.predecessor
                && state.observation.as_ref() == Some(&state.baseline_observation)
        }
        _ => false,
    };
    if state.generation == 0
        || state.replacement_id.as_bytes() == &[0; 16]
        || !state
            .predecessor
            .source()
            .identity()
            .admits_successor(state.candidate.source().identity())
        || !state
            .baseline_observation
            .matches_policy(&state.predecessor, ObservedNetworkPolicyV1::Predecessor)
        || !active_is_expected
        || state.registry_currentness.purpose() != ProtectedWitnessPurposeV1::IngressRegistry
        || state.registry_currentness.namespace() != node_namespace(state.registry.node())
        || state.registry_currentness.record_digest() != state.registry.digest()
        || !state
            .registry
            .contains_policy(state.active.source().ingress())
        || state.registry.has_in_flight_lineage()
        || state.aggregate_quota.has_reservation()
        || !state.aggregate_quota.covers_active(
            state.active.source().identity().project(),
            state.active.usage(),
        )
        || !state.transaction.covers(
            &state.registry,
            state.registry_currentness,
            &state.aggregate_quota,
        )
        || !valid_degradations(&state.active, &state.advisory_degradations)
    {
        return Err(AdvancedNetworkPolicyError::InvalidTransition);
    }
    Ok(())
}

fn registry_retains_candidate(
    registry: &ExternalIngressRegistryV1,
    candidate: &super::ingress::IngressAllocationSetV1,
) -> bool {
    let retained = registry
        .rows()
        .iter()
        .filter_map(|row| row.successor())
        .filter(|allocation| {
            allocation
                .owner()
                .has_same_allocation_scope(candidate.owner())
        })
        .collect::<Vec<_>>();
    retained.len() == candidate.allocations().len()
        && candidate
            .allocations()
            .iter()
            .all(|expected| retained.contains(&expected))
}

fn required_blob<'a>(
    reader: &mut RecoveryReader<'a>,
    maximum: usize,
) -> Result<&'a [u8], AdvancedNetworkPolicyError> {
    reader
        .blob(maximum)?
        .ok_or(AdvancedNetworkPolicyError::NonCanonical)
}

/// Stores a fixed canonical durable index for separately retained reducer state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvancedNetworkRecoveryRecordV1 {
    bytes: [u8; RECOVERY_BYTES],
}

/// Retains the bounded typed objects referenced by one durable recovery index.
///
/// Only protected owner integration in this crate can seal a companion. The
/// public rehydration path never accepts reconstructed scalar fields. Durable
/// decode additionally requires opaque live protected-owner authority handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvancedNetworkRecoveryCompanionsV1 {
    bytes: Vec<u8>,
    state: NetworkPolicyReplacementStateV1,
}

impl AdvancedNetworkRecoveryCompanionsV1 {
    pub(crate) fn checkpoint_commitment(bytes: &[u8]) -> ObjectDigest {
        // This digest is only a record preimage. Authority comes exclusively
        // from the protected checkpoint handle supplied during decode.
        recovery_checkpoint_digest(bytes)
    }

    pub(crate) fn seal(
        state: NetworkPolicyReplacementStateV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let payload = encode_recovery_payload(&state)?;
        if payload.len() > MAXIMUM_COMPANION_PAYLOAD_BYTES {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Self::from_payload(state, payload)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() < COMPANION_HEADER_BYTES
            || &bytes[..8] != COMPANION_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != COMPANION_VERSION
            || bytes[10..12].iter().any(|byte| *byte != 0)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let encoded_length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let payload_length = usize::try_from(u32::from_be_bytes([
            bytes[392], bytes[393], bytes[394], bytes[395],
        ]))
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        let expected_length = COMPANION_HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        if payload_length > MAXIMUM_COMPANION_PAYLOAD_BYTES
            || usize::try_from(encoded_length).ok() != Some(expected_length)
            || bytes.len() != expected_length
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        let index = AdvancedNetworkRecoveryRecordV1::decode(&bytes[16..392])?;
        let payload = &bytes[COMPANION_HEADER_BYTES..];
        let payload_digest = Sha256::digest(payload);
        if payload_digest[..] != bytes[396..428] {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let state = decode_recovery_payload(payload, authorities)?;
        let checkpoint = authorities.checkpoint();
        let checkpoint_predecessor = authorities.checkpoint_predecessor();
        let checkpoint_anchor_is_valid = match checkpoint_predecessor.purpose() {
            ProtectedWitnessPurposeV1::CombinedTransaction => {
                checkpoint_predecessor == state.protected_transaction().currentness()
            }
            ProtectedWitnessPurposeV1::RecoveryCheckpoint => true,
            _ => false,
        };
        if checkpoint.purpose() != ProtectedWitnessPurposeV1::RecoveryCheckpoint
            || !checkpoint_anchor_is_valid
            || !checkpoint.is_exact_journal_successor_of(checkpoint_predecessor)
            || checkpoint.record_digest() != Self::checkpoint_commitment(bytes)
            || encode_recovery_payload(&state)?.as_slice() != payload
            || !index.matches_state(&state)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            state,
        })
    }

    fn from_payload(
        state: NetworkPolicyReplacementStateV1,
        payload: Vec<u8>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if payload.len() > MAXIMUM_COMPANION_PAYLOAD_BYTES {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let total_length = COMPANION_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let length =
            u32::try_from(total_length).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        let index = AdvancedNetworkRecoveryRecordV1::encode(&state);
        let payload_digest = Sha256::digest(&payload);

        let mut bytes = Vec::with_capacity(total_length);
        bytes.extend_from_slice(COMPANION_MAGIC);
        bytes.extend_from_slice(&COMPANION_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(index.as_bytes());
        bytes.extend_from_slice(&payload_length.to_be_bytes());
        bytes.extend_from_slice(&payload_digest);
        bytes.extend_from_slice(&payload);
        Ok(Self { bytes, state })
    }

    /// Returns the canonical bounded companion-record bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Rehydrates complete reducer state after exact index verification.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::NonCanonical`] unless every typed
    /// companion object reproduces the supplied canonical index exactly.
    pub fn rehydrate(
        &self,
        index: &AdvancedNetworkRecoveryRecordV1,
    ) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
        if !index.matches_state(&self.state) {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(self.state.clone())
    }
}

impl AdvancedNetworkRecoveryRecordV1 {
    /// Gives the exact canonical encoded length.
    pub const ENCODED_LEN: usize = RECOVERY_BYTES;

    /// Encodes complete state commitments and typed baseline/outcome summaries.
    #[must_use]
    pub fn encode(state: &NetworkPolicyReplacementStateV1) -> Self {
        let mut bytes = [0; RECOVERY_BYTES];
        bytes[..8].copy_from_slice(RECOVERY_MAGIC);
        bytes[8..10].copy_from_slice(&RECOVERY_VERSION.to_be_bytes());
        bytes[10] = phase_code(state.phase());
        bytes[12..16].copy_from_slice(&RECOVERY_BYTES_U32.to_be_bytes());
        bytes[16..24].copy_from_slice(&state.generation().to_be_bytes());
        bytes[40..72].copy_from_slice(state.active().digest().as_bytes());
        bytes[72..104].copy_from_slice(candidate_digest(state).as_bytes());
        bytes[104..136].copy_from_slice(registry_digest(state).as_bytes());
        bytes[136..168].copy_from_slice(quota_digest(state).as_bytes());
        bytes[168..200].copy_from_slice(state.protected_transaction().digest().as_bytes());
        bytes[264..296].copy_from_slice(pool_digest(state).as_bytes());
        bytes[296..328].copy_from_slice(capabilities_digest(state).as_bytes());
        bytes[328..360].copy_from_slice(recovery_attempt_digest(state).as_bytes());
        if let Some(id) = replacement_id(state) {
            bytes[24..40].copy_from_slice(id.as_bytes());
        }
        if let Some(observation) = baseline_observation(state) {
            bytes[11] |= 1;
            bytes[200..232].copy_from_slice(observation.digest.as_bytes());
        }
        if let Some(observation) = state.observation() {
            bytes[11] |= 2;
            bytes[232..264].copy_from_slice(observation.digest.as_bytes());
        }
        Self { bytes }
    }

    /// Decodes one exact fixed-width canonical recovery index.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::NonCanonical`] for bad magic,
    /// version, length, phase, flags, reserved bytes, or typed observation.
    pub fn decode(bytes: &[u8]) -> Result<Self, AdvancedNetworkPolicyError> {
        let phase = bytes.get(10).copied().and_then(decode_phase);
        if bytes.len() != RECOVERY_BYTES
            || &bytes[..8] != RECOVERY_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != RECOVERY_VERSION
            || phase.is_none()
            || bytes[11] & !0x03 != 0
            || u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]])
                != RECOVERY_BYTES_U32
            || bytes[360..].iter().any(|byte| *byte != 0)
            || (bytes[11] & 1 == 0 && bytes[200..232].iter().any(|byte| *byte != 0))
            || (bytes[11] & 1 != 0 && bytes[200..232].iter().all(|byte| *byte == 0))
            || (bytes[11] & 2 == 0 && bytes[232..264].iter().any(|byte| *byte != 0))
            || (bytes[11] & 2 != 0 && bytes[232..264].iter().all(|byte| *byte == 0))
            || bytes[16..24].iter().all(|byte| *byte == 0)
            || bytes[40..72].iter().all(|byte| *byte == 0)
            || bytes[104..200]
                .chunks_exact(32)
                .any(|value| value.iter().all(|byte| *byte == 0))
            || !valid_recovery_phase(phase, bytes)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut exact = [0; RECOVERY_BYTES];
        exact.copy_from_slice(bytes);
        Ok(Self { bytes: exact })
    }

    /// Returns the exact canonical durable bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Verifies exact agreement with the separately retained reducer state.
    #[must_use]
    pub fn matches_state(&self, state: &NetworkPolicyReplacementStateV1) -> bool {
        *self == Self::encode(state)
    }

    /// Rehydrates complete state from an exact protected companion.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::NonCanonical`] for any companion
    /// mismatch.
    pub fn rehydrate(
        &self,
        companion: &AdvancedNetworkRecoveryCompanionsV1,
    ) -> Result<NetworkPolicyReplacementStateV1, AdvancedNetworkPolicyError> {
        companion.rehydrate(self)
    }
}

fn valid_recovery_phase(phase: Option<NetworkPolicyReplacementPhaseV1>, bytes: &[u8]) -> bool {
    let operation_is_zero = bytes[24..40].iter().all(|byte| *byte == 0);
    let candidate_is_zero = bytes[72..104].iter().all(|byte| *byte == 0);
    let attempt_witnesses_present = bytes[264..328]
        .chunks_exact(32)
        .all(|digest| digest.iter().any(|byte| *byte != 0));
    let attempt_witnesses_zero = bytes[264..328].iter().all(|byte| *byte == 0);
    let recovery_present = bytes[328..360].iter().any(|byte| *byte != 0);
    let baseline_present = bytes[11] & 1 != 0;
    let outcome_present = bytes[11] & 2 != 0;
    match phase {
        Some(NetworkPolicyReplacementPhaseV1::Stable) => {
            operation_is_zero
                && candidate_is_zero
                && !baseline_present
                && outcome_present
                && attempt_witnesses_zero
                && !recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::Reserved) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && !outcome_present
                && attempt_witnesses_present
                && !recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::EffectReleased) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && !outcome_present
                && attempt_witnesses_present
                && !recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::RecoveryRequired) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && outcome_present
                && attempt_witnesses_present
                && !recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::RecoveryAuthorized)
        | Some(NetworkPolicyReplacementPhaseV1::RecoveryFenced)
        | Some(NetworkPolicyReplacementPhaseV1::RecoveryApplyPrepared) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && outcome_present
                && attempt_witnesses_present
                && recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && !outcome_present
                && attempt_witnesses_present
                && recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::Committed) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && outcome_present
                && attempt_witnesses_zero
                && !recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::RolledBack) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && outcome_present
                && attempt_witnesses_zero
                && !recovery_present
        }
        Some(NetworkPolicyReplacementPhaseV1::Aborted) => {
            !operation_is_zero
                && !candidate_is_zero
                && baseline_present
                && outcome_present
                && attempt_witnesses_zero
                && !recovery_present
        }
        None => false,
    }
}

fn baseline_observation(
    state: &NetworkPolicyReplacementStateV1,
) -> Option<&NetworkReplacementObservationV1> {
    match state {
        NetworkPolicyReplacementStateV1::Reserved(value) => Some(&value.predecessor_observation),
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            Some(&value.reservation.predecessor_observation)
        }
        NetworkPolicyReplacementStateV1::Committed(value)
        | NetworkPolicyReplacementStateV1::RolledBack(value)
        | NetworkPolicyReplacementStateV1::Aborted(value) => Some(&value.baseline_observation),
        _ => None,
    }
}

fn candidate_digest(state: &NetworkPolicyReplacementStateV1) -> ObjectDigest {
    match state {
        NetworkPolicyReplacementStateV1::Reserved(value) => value.candidate.digest(),
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            value.reservation.candidate.digest()
        }
        NetworkPolicyReplacementStateV1::Committed(value)
        | NetworkPolicyReplacementStateV1::RolledBack(value)
        | NetworkPolicyReplacementStateV1::Aborted(value) => value.candidate.digest(),
        _ => ObjectDigest::from_bytes([0; 32]),
    }
}

fn registry_digest(state: &NetworkPolicyReplacementStateV1) -> ObjectDigest {
    match state {
        NetworkPolicyReplacementStateV1::Stable(value) => {
            protected_registry_digest(value.registry.digest(), value.registry_currentness)
        }
        NetworkPolicyReplacementStateV1::Reserved(value) => protected_registry_digest(
            value.reserved_registry.digest(),
            value.reserved_ingress_currentness,
        ),
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            protected_registry_digest(
                value.reservation.reserved_registry.digest(),
                value.reservation.reserved_ingress_currentness,
            )
        }
        NetworkPolicyReplacementStateV1::Committed(value)
        | NetworkPolicyReplacementStateV1::RolledBack(value)
        | NetworkPolicyReplacementStateV1::Aborted(value) => {
            protected_registry_digest(value.registry.digest(), value.registry_currentness)
        }
    }
}

fn protected_registry_digest(
    registry: ObjectDigest,
    witness: ProtectedCurrentnessWitnessV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.protected-ingress-registry.v1\0");
    digest.update(registry.as_bytes());
    digest.update(witness.current_head().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn quota_digest(state: &NetworkPolicyReplacementStateV1) -> ObjectDigest {
    match state {
        NetworkPolicyReplacementStateV1::Stable(value) => value.aggregate_quota.digest(),
        NetworkPolicyReplacementStateV1::Reserved(value) => value.reserved_quota.digest(),
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            value.reservation.reserved_quota.digest()
        }
        NetworkPolicyReplacementStateV1::Committed(value)
        | NetworkPolicyReplacementStateV1::RolledBack(value)
        | NetworkPolicyReplacementStateV1::Aborted(value) => value.aggregate_quota.digest(),
    }
}

fn pool_digest(state: &NetworkPolicyReplacementStateV1) -> ObjectDigest {
    match state {
        NetworkPolicyReplacementStateV1::Reserved(value) => value.pool.digest(),
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            value.reservation.pool.digest()
        }
        _ => ObjectDigest::from_bytes([0; 32]),
    }
}

fn capabilities_digest(state: &NetworkPolicyReplacementStateV1) -> ObjectDigest {
    match state {
        NetworkPolicyReplacementStateV1::Reserved(value) => value.capabilities.digest(),
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            value.reservation.capabilities.digest()
        }
        _ => ObjectDigest::from_bytes([0; 32]),
    }
}

fn replacement_id(state: &NetworkPolicyReplacementStateV1) -> Option<OperationId> {
    match state {
        NetworkPolicyReplacementStateV1::Stable(_) => None,
        NetworkPolicyReplacementStateV1::Reserved(value) => Some(value.replacement_id),
        NetworkPolicyReplacementStateV1::EffectReleased(value)
        | NetworkPolicyReplacementStateV1::RecoveryRequired(value)
        | NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => {
            Some(value.reservation.replacement_id)
        }
        NetworkPolicyReplacementStateV1::Committed(value)
        | NetworkPolicyReplacementStateV1::RolledBack(value)
        | NetworkPolicyReplacementStateV1::Aborted(value) => Some(value.replacement_id),
    }
}

fn recovery_attempt_digest(state: &NetworkPolicyReplacementStateV1) -> ObjectDigest {
    let attempt = match state {
        NetworkPolicyReplacementStateV1::RecoveryAuthorized(value)
        | NetworkPolicyReplacementStateV1::RecoveryFenced(value)
        | NetworkPolicyReplacementStateV1::RecoveryApplyPrepared(value)
        | NetworkPolicyReplacementStateV1::RecoveryEffectReleased(value) => value.recovery.as_ref(),
        _ => None,
    };
    let Some(attempt) = attempt else {
        return ObjectDigest::from_bytes([0; 32]);
    };

    let mut digest = Sha256::new();
    digest.update(RECOVERY_ATTEMPT_DOMAIN);
    digest.update(attempt.recovery_id.as_bytes());
    digest.update(attempt.authority.current_head().as_bytes());
    digest.update(attempt.authorization_observation.digest.as_bytes());
    if let Some(observation) = &attempt.fenced_observation {
        digest.update([1]);
        digest.update(observation.digest.as_bytes());
    } else {
        digest.update([0]);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

const fn phase_code(value: NetworkPolicyReplacementPhaseV1) -> u8 {
    match value {
        NetworkPolicyReplacementPhaseV1::Stable => 1,
        NetworkPolicyReplacementPhaseV1::Reserved => 2,
        NetworkPolicyReplacementPhaseV1::EffectReleased => 3,
        NetworkPolicyReplacementPhaseV1::RecoveryRequired => 4,
        NetworkPolicyReplacementPhaseV1::RecoveryAuthorized => 5,
        NetworkPolicyReplacementPhaseV1::RecoveryFenced => 6,
        NetworkPolicyReplacementPhaseV1::RecoveryApplyPrepared => 7,
        NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased => 8,
        NetworkPolicyReplacementPhaseV1::Committed => 9,
        NetworkPolicyReplacementPhaseV1::RolledBack => 10,
        NetworkPolicyReplacementPhaseV1::Aborted => 11,
    }
}

const fn decode_phase(value: u8) -> Option<NetworkPolicyReplacementPhaseV1> {
    match value {
        1 => Some(NetworkPolicyReplacementPhaseV1::Stable),
        2 => Some(NetworkPolicyReplacementPhaseV1::Reserved),
        3 => Some(NetworkPolicyReplacementPhaseV1::EffectReleased),
        4 => Some(NetworkPolicyReplacementPhaseV1::RecoveryRequired),
        5 => Some(NetworkPolicyReplacementPhaseV1::RecoveryAuthorized),
        6 => Some(NetworkPolicyReplacementPhaseV1::RecoveryFenced),
        7 => Some(NetworkPolicyReplacementPhaseV1::RecoveryApplyPrepared),
        8 => Some(NetworkPolicyReplacementPhaseV1::RecoveryEffectReleased),
        9 => Some(NetworkPolicyReplacementPhaseV1::Committed),
        10 => Some(NetworkPolicyReplacementPhaseV1::RolledBack),
        11 => Some(NetworkPolicyReplacementPhaseV1::Aborted),
        _ => None,
    }
}
