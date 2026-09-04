//! Signed, audience-specific authorization for privileged local brokers.
//!
//! Plans are immutable authority objects. They bind one assignment to exactly
//! one broker protocol and audience, a closed set of numeric semantic verbs,
//! opaque broker-owned handles, request ceilings, policy and revocation
//! commitments, and an exclusive expiry. [`VerifiedBrokerPlan`] proves only
//! plan authenticity; it is deliberately not an effect authorization because
//! ownership-lease verification and durable fence admission remain required.
//! This v1 registry covers the Host, Mount, Storage, and Network protocols
//! already present on the local wire. The per-assignment guardian consumes its
//! signed ownership lease directly and is not a broker-plan audience.

use crate::format::{
    CanonicalCborError, DecodeLimits, decode_broker_authorization_plan, decode_trust_policy,
    descriptor_for_bytes,
};
use crate::model::{KeyReference, Signature, SignaturePurpose};
use crate::{
    AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NodeId, ObjectDigest,
    ProtocolId, ProtocolVersion, RegistryError, RevocationScopeId, SandboxId,
    SignatureVerificationError, verify_signature,
};

const ARGUMENT_COMMITMENT_DOMAIN: &[u8] = b"aos-sandbox-broker-arguments-v1\0";

/// Maximum grants carried by one authorization plan.
pub const MAX_BROKER_PLAN_GRANTS: usize = 1_024;

/// Commits canonical typed request/catalog semantics without type confusion.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BrokerArgumentCommitment(ObjectDigest);

impl BrokerArgumentCommitment {
    /// Computes the domain-separated commitment for canonical semantic bytes.
    #[must_use]
    pub fn for_canonical_bytes(bytes: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(ARGUMENT_COMMITMENT_DOMAIN);
        hasher.update(bytes);
        Self(ObjectDigest::from_bytes(hasher.finalize().into()))
    }

    /// Constructs a commitment from an already verified nonzero digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBrokerAuthorizationPlan::UnspecifiedArgumentCommitment`]
    /// for the reserved all-zero digest.
    pub fn from_digest(digest: ObjectDigest) -> Result<Self, InvalidBrokerAuthorizationPlan> {
        if digest.as_bytes() == &[0; 32] {
            Err(InvalidBrokerAuthorizationPlan::UnspecifiedArgumentCommitment)
        } else {
            Ok(Self(digest))
        }
    }

    /// Returns the exact portable SHA-256 digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Names the sole privileged broker permitted to consume a plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BrokerAudience {
    /// Root host lifecycle broker.
    Host,
    /// Root detached-mount broker.
    Mount,
    /// Root storage broker.
    Storage,
    /// Root network broker.
    Network,
}

impl BrokerAudience {
    /// Returns the only protocol domain valid for this audience.
    #[must_use]
    pub const fn protocol(self) -> ProtocolId {
        match self {
            Self::Host => ProtocolId::HostBroker,
            Self::Mount => ProtocolId::MountBroker,
            Self::Storage => ProtocolId::StorageBroker,
            Self::Network => ProtocolId::NetworkBroker,
        }
    }
}

/// Identifies one exact semantic verb independently of coarse RPC methods.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BrokerVerb {
    /// Launches a host runtime from its typed catalog entry.
    HostLaunch,
    /// Stops a host runtime.
    HostStop,
    /// Freezes a host runtime.
    HostFreeze,
    /// Thaws a host runtime.
    HostThaw,
    /// Kills a host runtime.
    HostKill,
    /// Observes a host runtime.
    HostObserve,
    /// Inventories host runtimes for an assignment.
    HostInventory,
    /// Creates a detached mount and mints its handle.
    MountCreate,
    /// Installs an existing detached mount.
    MountInstall,
    /// Atomically replaces an installed mount.
    MountReplace,
    /// Detaches an installed mount.
    MountDetach,
    /// Releases a retained detached mount.
    MountRelease,
    /// Inventories assignment mount summaries.
    MountInventorySummary,
    /// Inventories retained mount resources.
    MountInventoryResources,
    /// Creates an assignment workspace and mints its storage handle.
    StorageCreateWorkspace,
    /// Snapshots an existing workspace.
    StorageSnapshot,
    /// Holds an existing immutable storage version.
    StorageHoldSnapshot,
    /// Releases a hold on an immutable storage version.
    StorageReleaseHold,
    /// Clones an immutable storage version into a workspace.
    StorageClone,
    /// Changes the quota on an existing workspace.
    StorageSetQuota,
    /// Destroys an existing broker-owned storage object.
    StorageDestroy,
    /// Inventories storage resources for an assignment.
    StorageInventory,
    /// Prepares assignment networking and mints its network handle.
    NetworkPrepare,
    /// Arms the ownership-lease gate for an existing network.
    NetworkArmLease,
    /// Renews the ownership-lease gate for an existing network.
    NetworkRenewLease,
    /// Applies default-drop and disarms an existing network.
    NetworkDisarm,
    /// Destroys an existing broker-owned network.
    NetworkDestroy,
    /// Inventories network resources for an assignment.
    NetworkInventory,
}

impl BrokerVerb {
    /// Resolves one exact verb from the shared local protocol registry.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBrokerAuthorizationPlan::UnknownVerb`] for reserved
    /// zero and every verb not implemented by this protocol generation.
    pub(crate) const fn from_code(value: u32) -> Result<Self, InvalidBrokerAuthorizationPlan> {
        match value {
            1 => Ok(Self::HostLaunch),
            2 => Ok(Self::HostStop),
            3 => Ok(Self::HostFreeze),
            4 => Ok(Self::HostThaw),
            5 => Ok(Self::HostKill),
            6 => Ok(Self::HostObserve),
            7 => Ok(Self::HostInventory),
            8 => Ok(Self::MountCreate),
            9 => Ok(Self::MountInstall),
            10 => Ok(Self::MountReplace),
            11 => Ok(Self::MountDetach),
            12 => Ok(Self::MountRelease),
            13 => Ok(Self::MountInventorySummary),
            14 => Ok(Self::MountInventoryResources),
            15 => Ok(Self::StorageCreateWorkspace),
            16 => Ok(Self::StorageSnapshot),
            17 => Ok(Self::StorageHoldSnapshot),
            18 => Ok(Self::StorageReleaseHold),
            19 => Ok(Self::StorageClone),
            20 => Ok(Self::StorageSetQuota),
            21 => Ok(Self::StorageDestroy),
            22 => Ok(Self::StorageInventory),
            23 => Ok(Self::NetworkPrepare),
            24 => Ok(Self::NetworkArmLease),
            25 => Ok(Self::NetworkRenewLease),
            26 => Ok(Self::NetworkDisarm),
            27 => Ok(Self::NetworkDestroy),
            28 => Ok(Self::NetworkInventory),
            _ => Err(InvalidBrokerAuthorizationPlan::UnknownVerb),
        }
    }

    /// Returns the protocol's numeric semantic-verb identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        match self {
            Self::HostLaunch => 1,
            Self::HostStop => 2,
            Self::HostFreeze => 3,
            Self::HostThaw => 4,
            Self::HostKill => 5,
            Self::HostObserve => 6,
            Self::HostInventory => 7,
            Self::MountCreate => 8,
            Self::MountInstall => 9,
            Self::MountReplace => 10,
            Self::MountDetach => 11,
            Self::MountRelease => 12,
            Self::MountInventorySummary => 13,
            Self::MountInventoryResources => 14,
            Self::StorageCreateWorkspace => 15,
            Self::StorageSnapshot => 16,
            Self::StorageHoldSnapshot => 17,
            Self::StorageReleaseHold => 18,
            Self::StorageClone => 19,
            Self::StorageSetQuota => 20,
            Self::StorageDestroy => 21,
            Self::StorageInventory => 22,
            Self::NetworkPrepare => 23,
            Self::NetworkArmLease => 24,
            Self::NetworkRenewLease => 25,
            Self::NetworkDisarm => 26,
            Self::NetworkDestroy => 27,
            Self::NetworkInventory => 28,
        }
    }

    /// Returns the sole broker audience that implements this verb.
    #[must_use]
    pub const fn audience(self) -> BrokerAudience {
        match self {
            Self::HostLaunch
            | Self::HostStop
            | Self::HostFreeze
            | Self::HostThaw
            | Self::HostKill
            | Self::HostObserve
            | Self::HostInventory => BrokerAudience::Host,
            Self::MountCreate
            | Self::MountInstall
            | Self::MountReplace
            | Self::MountDetach
            | Self::MountRelease
            | Self::MountInventorySummary
            | Self::MountInventoryResources => BrokerAudience::Mount,
            Self::StorageCreateWorkspace
            | Self::StorageSnapshot
            | Self::StorageHoldSnapshot
            | Self::StorageReleaseHold
            | Self::StorageClone
            | Self::StorageSetQuota
            | Self::StorageDestroy
            | Self::StorageInventory => BrokerAudience::Storage,
            Self::NetworkPrepare
            | Self::NetworkArmLease
            | Self::NetworkRenewLease
            | Self::NetworkDisarm
            | Self::NetworkDestroy
            | Self::NetworkInventory => BrokerAudience::Network,
        }
    }

    const fn target_shape(self) -> BrokerGrantTargetShape {
        match self {
            Self::HostLaunch
            | Self::HostInventory
            | Self::MountCreate
            | Self::MountInventorySummary
            | Self::MountInventoryResources
            | Self::StorageCreateWorkspace
            | Self::StorageInventory
            | Self::NetworkPrepare
            | Self::NetworkInventory => BrokerGrantTargetShape::Assignment,
            Self::HostStop
            | Self::HostFreeze
            | Self::HostThaw
            | Self::HostKill
            | Self::HostObserve
            | Self::MountInstall
            | Self::MountDetach
            | Self::MountRelease
            | Self::StorageSnapshot
            | Self::StorageHoldSnapshot
            | Self::StorageReleaseHold
            | Self::StorageClone
            | Self::StorageSetQuota
            | Self::StorageDestroy
            | Self::NetworkArmLease
            | Self::NetworkRenewLease
            | Self::NetworkDisarm
            | Self::NetworkDestroy => BrokerGrantTargetShape::Resource,
            Self::MountReplace => BrokerGrantTargetShape::ResourcePair,
        }
    }
}

/// Names one broker-owned resource without disclosing a host path or command.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BrokerResourceHandle([u8; 32]);

impl BrokerResourceHandle {
    /// Constructs an opaque handle from its exact portable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBrokerAuthorizationPlan::UnspecifiedResource`] for the
    /// all-zero sentinel.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidBrokerAuthorizationPlan> {
        if bytes == [0; 32] {
            Err(InvalidBrokerAuthorizationPlan::UnspecifiedResource)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Borrows the exact portable bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Selects whether a grant is assignment-wide or bound to an existing handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BrokerGrantTarget {
    /// Authorizes assignment-scoped creation, observation, or inventory.
    ///
    /// This does not authorize caller-selected paths or backend expressions:
    /// the broker must still resolve the request through its plan-digest-bound
    /// typed catalog before consuming this token.
    Assignment,
    /// Authorizes an operation on one pre-existing broker-owned resource.
    Resource(BrokerResourceHandle),
    /// Authorizes replacement from the first handle to the second handle.
    ResourcePair {
        /// Existing installed resource being replaced.
        previous: BrokerResourceHandle,
        /// Prepared successor resource being installed.
        successor: BrokerResourceHandle,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerGrantTargetShape {
    Assignment,
    Resource,
    ResourcePair,
}

impl BrokerGrantTarget {
    const fn shape(self) -> BrokerGrantTargetShape {
        match self {
            Self::Assignment => BrokerGrantTargetShape::Assignment,
            Self::Resource(_) => BrokerGrantTargetShape::Resource,
            Self::ResourcePair { .. } => BrokerGrantTargetShape::ResourcePair,
        }
    }
}

/// Commits one verb/target pair and its fixed allocation ceilings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerGrant {
    verb: BrokerVerb,
    target: BrokerGrantTarget,
    argument_commitment: BrokerArgumentCommitment,
    maximum_request_bytes: u32,
    maximum_descriptors: u16,
}

impl BrokerGrant {
    /// Constructs one exact semantic grant.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBrokerAuthorizationPlan`] for a zero body ceiling or
    /// an invalid target or zero request-body ceiling.
    pub fn new(
        verb: BrokerVerb,
        target: BrokerGrantTarget,
        argument_commitment: BrokerArgumentCommitment,
        maximum_request_bytes: u32,
        maximum_descriptors: u16,
    ) -> Result<Self, InvalidBrokerAuthorizationPlan> {
        if maximum_request_bytes == 0
            || maximum_request_bytes > 16 * 1024 * 1024
            || maximum_descriptors > 16
        {
            return Err(InvalidBrokerAuthorizationPlan::InvalidRequestBound);
        }
        if verb.target_shape() != target.shape() {
            return Err(InvalidBrokerAuthorizationPlan::TargetShapeMismatch);
        }
        if matches!(
            target,
            BrokerGrantTarget::ResourcePair { previous, successor } if previous == successor
        ) {
            return Err(InvalidBrokerAuthorizationPlan::TargetShapeMismatch);
        }
        Ok(Self {
            verb,
            target,
            argument_commitment,
            maximum_request_bytes,
            maximum_descriptors,
        })
    }

    /// Returns the committed semantic verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the assignment-wide or resource-specific target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the digest of the exact typed request/catalog semantics.
    #[must_use]
    pub const fn argument_commitment(&self) -> BrokerArgumentCommitment {
        self.argument_commitment
    }

    /// Returns the maximum request body accepted for this grant.
    #[must_use]
    pub const fn maximum_request_bytes(&self) -> u32 {
        self.maximum_request_bytes
    }

    /// Returns the maximum descriptor count accepted for this grant.
    #[must_use]
    pub const fn maximum_descriptors(&self) -> u16 {
        self.maximum_descriptors
    }
}

/// Binds broker authority to one immutable assignment decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAssignment {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    digest: ObjectDigest,
}

impl BrokerAssignment {
    /// Constructs an exact assignment binding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBrokerAuthorizationPlan::UnspecifiedAssignmentDigest`]
    /// for the all-zero digest sentinel.
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        digest: ObjectDigest,
    ) -> Result<Self, InvalidBrokerAuthorizationPlan> {
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || desired_generation.get() == 0
            || digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidBrokerAuthorizationPlan::UnspecifiedAssignmentDigest);
        }
        Ok(Self {
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            digest,
        })
    }

    /// Returns the durable sandbox identity.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }
    /// Returns the assigned sandbox incarnation.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }
    /// Returns the coordinator assignment epoch.
    #[must_use]
    pub const fn epoch(self) -> AssignmentEpoch {
        self.epoch
    }
    /// Returns the desired-state generation.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }
    /// Returns the complete assignment digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Stores one canonical controller-issued broker authorization plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerAuthorizationPlan {
    audience: BrokerAudience,
    protocol: ProtocolId,
    protocol_version: ProtocolVersion,
    assignment: BrokerAssignment,
    node: NodeId,
    ownership_authority: KeyReference,
    grants: Vec<BrokerGrant>,
    policy_commitment: ObjectDigest,
    revocation_scope: RevocationScopeId,
    issued_seconds: i64,
    expires_seconds: i64,
    required_features: Vec<FeatureRef>,
}

/// Reports a malformed or semantically noncanonical plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidBrokerAuthorizationPlan {
    /// Method is reserved or absent from the closed local registry.
    #[error("unknown broker semantic verb")]
    UnknownVerb,
    /// Resource handle zero is a reserved sentinel.
    #[error("broker resource handle must not be zero")]
    UnspecifiedResource,
    /// An assignment field uses a reserved zero sentinel.
    #[error("broker assignment identities, generations, and digest must not be zero")]
    UnspecifiedAssignmentDigest,
    /// A request byte ceiling must permit at least one byte.
    #[error("broker maximum request bytes must be nonzero")]
    InvalidRequestBound,
    /// Verb and target have incompatible semantic shapes.
    #[error("broker verb has an incompatible target shape")]
    TargetShapeMismatch,
    /// Argument commitment uses the reserved zero digest.
    #[error("broker argument commitment must not be zero")]
    UnspecifiedArgumentCommitment,
    /// Policy or revocation commitment uses a reserved zero sentinel.
    #[error("broker policy and revocation commitments must not be zero")]
    UnspecifiedAuthorityCommitment,
    /// Node or ownership-authority commitment uses a reserved sentinel.
    #[error("broker node and ownership authority must be fully specified")]
    UnspecifiedOwnershipAuthority,
    /// Grant count exceeds the hard limit or grants are not strictly ordered.
    #[error("broker grants must be a nonempty canonical set of at most 1024 entries")]
    GrantsNotCanonical,
    /// Required features are not strictly ordered.
    #[error("broker required features must be a canonical set")]
    FeaturesNotCanonical,
    /// Expiry is not strictly later than issue time.
    #[error("broker plan expiry must be later than issue time")]
    InvalidValidityInterval,
    /// Protocol is not the fixed local protocol for the selected audience.
    #[error("broker protocol does not match its audience")]
    ProtocolAudienceMismatch,
}

impl BrokerAuthorizationPlan {
    /// Constructs a bounded canonical broker plan.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBrokerAuthorizationPlan`] for invalid time bounds or
    /// unordered, duplicate, empty, or oversized authority sets.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        audience: BrokerAudience,
        protocol: ProtocolId,
        protocol_version: ProtocolVersion,
        assignment: BrokerAssignment,
        node: NodeId,
        ownership_authority: KeyReference,
        grants: Vec<BrokerGrant>,
        policy_commitment: ObjectDigest,
        revocation_scope: RevocationScopeId,
        issued_seconds: i64,
        expires_seconds: i64,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidBrokerAuthorizationPlan> {
        if grants.is_empty()
            || grants.len() > MAX_BROKER_PLAN_GRANTS
            || !grants
                .windows(2)
                .all(|pair| grant_key(&pair[0]) < grant_key(&pair[1]))
        {
            return Err(InvalidBrokerAuthorizationPlan::GrantsNotCanonical);
        }
        if grants
            .iter()
            .any(|grant| grant.verb().audience() != audience)
        {
            return Err(InvalidBrokerAuthorizationPlan::ProtocolAudienceMismatch);
        }
        if required_features.len() > 64
            || !required_features.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(InvalidBrokerAuthorizationPlan::FeaturesNotCanonical);
        }
        if expires_seconds <= issued_seconds {
            return Err(InvalidBrokerAuthorizationPlan::InvalidValidityInterval);
        }
        if protocol != audience.protocol() {
            return Err(InvalidBrokerAuthorizationPlan::ProtocolAudienceMismatch);
        }
        if crate::negotiate_protocol(protocol, protocol_version).is_err() {
            return Err(InvalidBrokerAuthorizationPlan::ProtocolAudienceMismatch);
        }
        if node.as_bytes() == &[0; 16]
            || ownership_authority.generation() == 0
            || ownership_authority.public_key_sha256().as_bytes() == &[0; 32]
            || ownership_authority.usage() != crate::model::KeyUsage::OwnershipLease
        {
            return Err(InvalidBrokerAuthorizationPlan::UnspecifiedOwnershipAuthority);
        }
        if policy_commitment.as_bytes() == &[0; 32] || revocation_scope.as_bytes() == &[0; 16] {
            return Err(InvalidBrokerAuthorizationPlan::UnspecifiedAuthorityCommitment);
        }
        Ok(Self {
            audience,
            protocol,
            protocol_version,
            assignment,
            node,
            ownership_authority,
            grants,
            policy_commitment,
            revocation_scope,
            issued_seconds,
            expires_seconds,
            required_features,
        })
    }

    /// Returns the sole receiving broker audience.
    #[must_use]
    pub const fn audience(&self) -> BrokerAudience {
        self.audience
    }
    /// Returns the independently versioned broker protocol domain.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolId {
        self.protocol
    }
    /// Returns the exact broker protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
    /// Returns the immutable assignment binding.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }
    /// Returns the sole assigned node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }
    /// Returns the immutable authority generation whose leases may intersect this plan.
    #[must_use]
    pub const fn ownership_authority(&self) -> &KeyReference {
        &self.ownership_authority
    }
    /// Returns the canonical verb/target grants.
    #[must_use]
    pub fn grants(&self) -> &[BrokerGrant] {
        &self.grants
    }
    /// Returns the normalized policy commitment.
    #[must_use]
    pub const fn policy_commitment(&self) -> ObjectDigest {
        self.policy_commitment
    }
    /// Returns the revocation scope subordinate authority must match.
    #[must_use]
    pub const fn revocation_scope(&self) -> RevocationScopeId {
        self.revocation_scope
    }
    /// Returns the inclusive issue time.
    #[must_use]
    pub const fn issued_seconds(&self) -> i64 {
        self.issued_seconds
    }
    /// Returns the exclusive expiry time.
    #[must_use]
    pub const fn expires_seconds(&self) -> i64 {
        self.expires_seconds
    }
    /// Returns required semantics the receiving implementation must know.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

/// Pins the controller trust generation accepted for broker plans.
#[derive(Debug)]
pub struct BrokerPlanTrustAnchor {
    canonical_policy: Vec<u8>,
    policy_descriptor: crate::ObjectDescriptor,
    trust_scope: crate::TrustScopeId,
    signer: KeyReference,
    public_key: [u8; 32],
    revocation_scope: RevocationScopeId,
}

impl BrokerPlanTrustAnchor {
    /// Constructs one explicit trusted controller-plan anchor from local configuration.
    ///
    /// Broker code must call this only for protected local configuration. Trust
    /// policy bytes, keys, and scopes received in a request are never anchors.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerPlanVerificationError`] unless policy bytes, descriptor,
    /// scope, purpose, current signer generation, fingerprint, and revocation
    /// scope are exact and non-sentinel.
    #[allow(clippy::too_many_arguments)]
    pub fn from_trusted_configuration(
        canonical_policy: Vec<u8>,
        policy_descriptor: crate::ObjectDescriptor,
        trust_scope: crate::TrustScopeId,
        signer: KeyReference,
        public_key: [u8; 32],
        revocation_scope: RevocationScopeId,
        limits: DecodeLimits,
    ) -> Result<Self, BrokerPlanVerificationError> {
        use sha2::{Digest as _, Sha256};

        let policy = decode_trust_policy(&canonical_policy, limits)?;
        crate::validate_required_features(policy.required_features())?;
        crate::validate_descriptor_role(
            crate::DescriptorRole::SignatureVerificationPolicy,
            &policy_descriptor,
        )?;
        let computed =
            descriptor_for_bytes(policy_descriptor.media_type().clone(), &canonical_policy);
        if computed != policy_descriptor
            || policy.trust_scope() != trust_scope
            || policy.purpose() != SignaturePurpose::BrokerAuthorization
            || !policy.allowed_keys().contains(&signer)
            || signer.generation() == 0
            || signer.public_key_sha256()
                != ObjectDigest::from_bytes(Sha256::digest(public_key).into())
            || revocation_scope.as_bytes() == &[0; 16]
        {
            return Err(BrokerPlanVerificationError::InvalidTrustAnchor);
        }
        Ok(Self {
            canonical_policy,
            policy_descriptor,
            trust_scope,
            signer,
            public_key,
            revocation_scope,
        })
    }
}

/// Supplies local facts that an authentic plan must exactly match.
#[derive(Clone, Copy, Debug)]
pub struct BrokerPlanExpectation {
    /// Expected receiving broker.
    pub audience: BrokerAudience,
    /// Independently versioned protocol selected by the local session.
    pub protocol: ProtocolId,
    /// Negotiated local protocol version.
    pub protocol_version: ProtocolVersion,
    /// Assignment carried by the request envelope.
    pub assignment: BrokerAssignment,
    /// Node on which the broker runs.
    pub node: NodeId,
    /// Verification clock as a Unix second.
    pub now_seconds: i64,
}

/// Reports failed cryptographic or semantic broker authorization.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerPlanVerificationError {
    /// Canonical plan decoding or its closed registries failed.
    #[error("invalid canonical broker authorization plan: {0}")]
    Plan(#[from] CanonicalCborError),
    /// Detached signature verification failed.
    #[error("broker authorization signature verification failed: {0}")]
    Signature(#[from] SignatureVerificationError),
    /// The signature does not authenticate a broker authorization plan.
    #[error("signature subject does not match the broker authorization plan")]
    SubjectMismatch,
    /// The controller used another immutable key generation.
    #[error("broker authorization signer generation mismatch")]
    SignerGenerationMismatch,
    /// Signature statement and plan time bounds differ.
    #[error("signature and broker authorization plan validity differ")]
    ValidityMismatch,
    /// The plan targets another broker audience.
    #[error("broker authorization audience mismatch")]
    AudienceMismatch,
    /// The plan targets another protocol or version.
    #[error("broker authorization protocol mismatch")]
    ProtocolMismatch,
    /// The plan is bound to another assignment.
    #[error("broker authorization assignment mismatch")]
    AssignmentMismatch,
    /// The plan is expired or not yet valid.
    #[error("broker authorization plan is outside its validity interval")]
    InvalidTime,
    /// A required semantic feature is unknown locally.
    #[error("broker plan registry validation failed: {0}")]
    Registry(#[from] RegistryError),
    /// The configured trust anchor is internally inconsistent.
    #[error("invalid broker plan trust anchor")]
    InvalidTrustAnchor,
    /// Plan revocation scope differs from the pinned anchor.
    #[error("broker plan revocation scope mismatch")]
    RevocationScopeMismatch,
    /// Plan is bound to another node.
    #[error("broker plan node mismatch")]
    NodeMismatch,
    /// No exact verb, target, or argument commitment is present in the plan.
    #[error("broker request semantics are not committed by the verified plan")]
    RequestNotCommitted,
    /// Request body or descriptor count exceeds the signed grant ceiling.
    #[error("broker request exceeds the verified plan bounds")]
    RequestBoundsExceeded,
}

/// Proves plan authenticity without authorizing any broker effect.
///
/// Brokers must additionally verify and intersect a current ownership lease,
/// bind an exact request semantic digest, and durably admit all fences before
/// treating the plan as authority. This type is intentionally not `Clone`.
#[derive(Debug)]
pub struct VerifiedBrokerPlan {
    plan: BrokerAuthorizationPlan,
    plan_digest: ObjectDigest,
}

/// Supplies the exact request semantics to match against an authentic plan.
#[derive(Clone, Copy, Debug)]
pub struct BrokerPlanRequest {
    /// Closed semantic verb selected after request decoding.
    pub verb: BrokerVerb,
    /// Assignment or broker-owned resource target.
    pub target: BrokerGrantTarget,
    /// Domain-separated digest of canonical typed request/catalog semantics.
    pub argument_commitment: BrokerArgumentCommitment,
    /// Bounded encoded request body size.
    pub request_bytes: u32,
    /// Exact ancillary descriptor count.
    pub descriptor_count: u16,
}

/// Proves an exact request match but still does not authorize an effect.
///
/// This borrowed, non-`Clone` proof must be intersected with a verified current
/// ownership lease and durably admitted fences before use.
#[derive(Debug)]
pub struct MatchedBrokerRequest<'a> {
    verified_plan: &'a VerifiedBrokerPlan,
    grant: &'a BrokerGrant,
}

impl MatchedBrokerRequest<'_> {
    /// Returns the authentic plan borrowed by this request proof.
    #[must_use]
    pub(crate) const fn verified_plan(&self) -> &VerifiedBrokerPlan {
        self.verified_plan
    }
    /// Returns the authentic plan digest to persist with later fence admission.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.verified_plan.plan_digest
    }

    /// Returns the exact matched semantic grant.
    #[must_use]
    pub const fn grant(&self) -> &BrokerGrant {
        self.grant
    }
}

impl VerifiedBrokerPlan {
    /// Returns the fully decoded and validated immutable plan.
    #[must_use]
    pub const fn plan(&self) -> &BrokerAuthorizationPlan {
        &self.plan
    }
    /// Returns the canonical plan object digest suitable for durable fencing.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Matches one exact request without granting effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerPlanVerificationError`] unless verb, target, canonical
    /// argument commitment, body size, and descriptor count are covered by one
    /// exact signed grant.
    pub fn match_request(
        &self,
        request: BrokerPlanRequest,
    ) -> Result<MatchedBrokerRequest<'_>, BrokerPlanVerificationError> {
        let index = self
            .plan
            .grants()
            .binary_search_by_key(
                &(request.verb, request.target, request.argument_commitment),
                grant_key,
            )
            .map_err(|_| BrokerPlanVerificationError::RequestNotCommitted)?;
        let grant = &self.plan.grants()[index];
        if request.request_bytes > grant.maximum_request_bytes()
            || request.descriptor_count > grant.maximum_descriptors()
        {
            return Err(BrokerPlanVerificationError::RequestBoundsExceeded);
        }
        Ok(MatchedBrokerRequest {
            verified_plan: self,
            grant,
        })
    }
}

fn grant_key(grant: &BrokerGrant) -> (BrokerVerb, BrokerGrantTarget, BrokerArgumentCommitment) {
    (grant.verb(), grant.target(), grant.argument_commitment())
}

#[cfg(test)]
impl VerifiedBrokerPlan {
    pub(crate) fn from_test_plan(plan: BrokerAuthorizationPlan) -> Self {
        let bytes = crate::format::encode_broker_authorization_plan(&plan);
        let descriptor = crate::format::descriptor_for_bytes(
            crate::MediaType::new(
                crate::PortableMediaType::BrokerAuthorizationPlan
                    .as_str()
                    .to_owned(),
            )
            .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &bytes,
        );
        Self {
            plan,
            plan_digest: descriptor.digest(),
        }
    }
}

/// Verifies canonical plan bytes and a detached controller signature.
///
/// # Errors
///
/// Returns [`BrokerPlanVerificationError`] unless the canonical plan, explicit
/// trusted anchor, signer generation, audience, protocol, assignment, node,
/// revocation scope, and validity all match exactly. Success does not authorize
/// an effect without a separately verified current ownership lease.
pub fn verify_broker_plan(
    canonical_plan: &[u8],
    signature: &Signature,
    anchor: &BrokerPlanTrustAnchor,
    expectation: BrokerPlanExpectation,
    limits: DecodeLimits,
) -> Result<VerifiedBrokerPlan, BrokerPlanVerificationError> {
    let plan = decode_broker_authorization_plan(canonical_plan, limits)?;
    crate::validate_required_features(plan.required_features())?;

    let descriptor = descriptor_for_bytes(
        crate::MediaType::new(
            crate::PortableMediaType::BrokerAuthorizationPlan
                .as_str()
                .to_owned(),
        )
        .map_err(|error| CanonicalCborError::InvalidSemantics {
            object: "broker authorization plan media type",
            message: error.to_string(),
        })?,
        canonical_plan,
    );
    if signature.statement().subject() != &descriptor
        || signature.statement().purpose() != SignaturePurpose::BrokerAuthorization
    {
        return Err(BrokerPlanVerificationError::SubjectMismatch);
    }
    if signature.statement().signer() != &anchor.signer
        || signature.statement().verification_policy() != &anchor.policy_descriptor
        || signature.statement().trust_scope() != anchor.trust_scope
    {
        return Err(BrokerPlanVerificationError::SignerGenerationMismatch);
    }
    if signature.statement().issued_seconds() != plan.issued_seconds()
        || signature.statement().expires_seconds() != Some(plan.expires_seconds())
    {
        return Err(BrokerPlanVerificationError::ValidityMismatch);
    }
    verify_signature(
        signature,
        &anchor.canonical_policy,
        &anchor.public_key,
        expectation.now_seconds,
        limits,
    )?;

    if plan.audience() != expectation.audience {
        return Err(BrokerPlanVerificationError::AudienceMismatch);
    }
    if plan.protocol() != expectation.protocol
        || plan.protocol_version() != expectation.protocol_version
    {
        return Err(BrokerPlanVerificationError::ProtocolMismatch);
    }
    if plan.assignment() != expectation.assignment {
        return Err(BrokerPlanVerificationError::AssignmentMismatch);
    }
    if plan.node() != expectation.node {
        return Err(BrokerPlanVerificationError::NodeMismatch);
    }
    if plan.revocation_scope() != anchor.revocation_scope {
        return Err(BrokerPlanVerificationError::RevocationScopeMismatch);
    }
    if expectation.now_seconds < plan.issued_seconds()
        || expectation.now_seconds >= plan.expires_seconds()
    {
        return Err(BrokerPlanVerificationError::InvalidTime);
    }
    Ok(VerifiedBrokerPlan {
        plan,
        plan_digest: descriptor.digest(),
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::format::{encode_broker_authorization_plan, encode_trust_policy};
    use crate::model::{KeyUsage, SignatureBytes, SignatureStatement, StableKeyId, TrustPolicy};
    use crate::{MediaType, PortableMediaType, TrustScopeId, sign_statement};

    struct Fixture {
        plan_bytes: Vec<u8>,
        signature: Signature,
        anchor: BrokerPlanTrustAnchor,
        context_assignment: BrokerAssignment,
        node: NodeId,
        ownership_authority: KeyReference,
    }

    fn fixture() -> Fixture {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let signer = KeyReference::new(
            StableKeyId::new("broker-controller".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            7,
            ObjectDigest::from_bytes(Sha256::digest(signing_key.verifying_key().as_bytes()).into()),
            KeyUsage::BrokerAuthorization,
        );
        let scope = TrustScopeId::from_bytes([10; 16]);
        let trust_policy = TrustPolicy::new(
            scope,
            SignaturePurpose::BrokerAuthorization,
            vec![signer.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test trust policy failed: {error}"));
        let trust_policy_bytes = encode_trust_policy(&trust_policy);
        let trust_policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &trust_policy_bytes,
        );
        let context_assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        let node = NodeId::from_bytes([6; 16]);
        let ownership_authority = KeyReference::new(
            StableKeyId::new("ownership-authority".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            3,
            ObjectDigest::from_bytes([12; 32]),
            KeyUsage::OwnershipLease,
        );
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(1, 0),
            context_assignment,
            node,
            ownership_authority.clone(),
            vec![
                BrokerGrant::new(
                    BrokerVerb::MountCreate,
                    BrokerGrantTarget::Assignment,
                    BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes([13; 32]))
                        .unwrap_or_else(|error| panic!("test commitment failed: {error}")),
                    4_096,
                    0,
                )
                .unwrap_or_else(|error| panic!("test grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([7; 32]),
            RevocationScopeId::from_bytes([8; 16]),
            100,
            200,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"));
        let plan_bytes = encode_broker_authorization_plan(&plan);
        let plan_descriptor = descriptor_for_bytes(
            MediaType::new(
                PortableMediaType::BrokerAuthorizationPlan
                    .as_str()
                    .to_owned(),
            )
            .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &plan_bytes,
        );
        let statement = SignatureStatement::new(
            plan_descriptor,
            scope,
            signer.clone(),
            SignaturePurpose::BrokerAuthorization,
            100,
            Some(200),
            trust_policy_descriptor.clone(),
        )
        .unwrap_or_else(|error| panic!("test statement failed: {error}"));
        let signature = sign_statement(statement, &signing_key)
            .unwrap_or_else(|error| panic!("test signature failed: {error}"));
        let anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            trust_policy_bytes,
            trust_policy_descriptor,
            scope,
            signer,
            *signing_key.verifying_key().as_bytes(),
            RevocationScopeId::from_bytes([8; 16]),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));

        Fixture {
            plan_bytes,
            signature,
            anchor,
            context_assignment,
            node,
            ownership_authority,
        }
    }

    fn context(fixture: &Fixture) -> BrokerPlanExpectation {
        BrokerPlanExpectation {
            audience: BrokerAudience::Mount,
            protocol: ProtocolId::MountBroker,
            protocol_version: ProtocolVersion::new(1, 0),
            assignment: fixture.context_assignment,
            node: fixture.node,
            now_seconds: 150,
        }
    }

    fn verify(
        fixture: &Fixture,
        context: BrokerPlanExpectation,
    ) -> Result<VerifiedBrokerPlan, BrokerPlanVerificationError> {
        verify_broker_plan(
            &fixture.plan_bytes,
            &fixture.signature,
            &fixture.anchor,
            context,
            DecodeLimits::default(),
        )
    }

    #[test]
    fn valid_plan_returns_non_authorizing_proof() {
        let fixture = fixture();
        let token = verify(&fixture, context(&fixture))
            .unwrap_or_else(|error| panic!("valid authorization failed: {error}"));
        assert_eq!(token.plan().audience(), BrokerAudience::Mount);
        assert_eq!(
            token.plan_digest(),
            fixture.signature.statement().subject().digest()
        );
        let commitment = BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes([13; 32]))
            .unwrap_or_else(|error| panic!("test commitment failed: {error}"));
        let request = BrokerPlanRequest {
            verb: BrokerVerb::MountCreate,
            target: BrokerGrantTarget::Assignment,
            argument_commitment: commitment,
            request_bytes: 4_096,
            descriptor_count: 0,
        };
        let matched = token
            .match_request(request)
            .unwrap_or_else(|error| panic!("request match failed: {error}"));
        assert_eq!(matched.plan_digest(), token.plan_digest());
        assert_eq!(matched.grant().verb(), BrokerVerb::MountCreate);

        let wrong_verb = BrokerPlanRequest {
            verb: BrokerVerb::MountInventorySummary,
            ..request
        };
        assert!(matches!(
            token.match_request(wrong_verb),
            Err(BrokerPlanVerificationError::RequestNotCommitted)
        ));
        let wrong_target = BrokerPlanRequest {
            target: BrokerGrantTarget::Resource(
                BrokerResourceHandle::from_bytes([14; 32])
                    .unwrap_or_else(|error| panic!("test handle failed: {error}")),
            ),
            ..request
        };
        assert!(matches!(
            token.match_request(wrong_target),
            Err(BrokerPlanVerificationError::RequestNotCommitted)
        ));
        let wrong_arguments = BrokerPlanRequest {
            argument_commitment: BrokerArgumentCommitment::for_canonical_bytes(b"substitution"),
            ..request
        };
        assert!(matches!(
            token.match_request(wrong_arguments),
            Err(BrokerPlanVerificationError::RequestNotCommitted)
        ));
        let oversized = BrokerPlanRequest {
            request_bytes: 4_097,
            ..request
        };
        assert!(matches!(
            token.match_request(oversized),
            Err(BrokerPlanVerificationError::RequestBoundsExceeded)
        ));
    }

    #[test]
    fn one_plan_can_commit_distinct_semantics_for_the_same_verb_and_target() {
        let fixture = fixture();
        let grant = |byte| {
            BrokerGrant::new(
                BrokerVerb::MountCreate,
                BrokerGrantTarget::Assignment,
                BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes([byte; 32]))
                    .unwrap_or_else(|error| panic!("test commitment failed: {error}")),
                4_096,
                0,
            )
            .unwrap_or_else(|error| panic!("test grant failed: {error}"))
        };
        let construct = |grants| {
            BrokerAuthorizationPlan::new(
                BrokerAudience::Mount,
                ProtocolId::MountBroker,
                ProtocolVersion::new(1, 0),
                fixture.context_assignment,
                fixture.node,
                fixture.ownership_authority.clone(),
                grants,
                ObjectDigest::from_bytes([7; 32]),
                RevocationScopeId::from_bytes([8; 16]),
                100,
                200,
                Vec::new(),
            )
        };

        assert!(construct(vec![grant(13), grant(14)]).is_ok());
        assert_eq!(
            construct(vec![grant(14), grant(13)]),
            Err(InvalidBrokerAuthorizationPlan::GrantsNotCanonical)
        );
    }

    #[test]
    fn audience_protocol_and_assignment_replay_fail() {
        let fixture = fixture();

        let mut cross_audience = context(&fixture);
        cross_audience.audience = BrokerAudience::Host;
        assert!(matches!(
            verify(&fixture, cross_audience),
            Err(BrokerPlanVerificationError::AudienceMismatch)
        ));

        let mut cross_protocol = context(&fixture);
        cross_protocol.protocol = ProtocolId::HostBroker;
        assert!(matches!(
            verify(&fixture, cross_protocol),
            Err(BrokerPlanVerificationError::ProtocolMismatch)
        ));

        let mut cross_assignment = context(&fixture);
        cross_assignment.assignment = BrokerAssignment::new(
            fixture.context_assignment.sandbox(),
            fixture.context_assignment.incarnation(),
            AssignmentEpoch::new(4),
            fixture.context_assignment.desired_generation(),
            fixture.context_assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        assert!(matches!(
            verify(&fixture, cross_assignment),
            Err(BrokerPlanVerificationError::AssignmentMismatch)
        ));

        let mut cross_node = context(&fixture);
        cross_node.node = NodeId::from_bytes([7; 16]);
        assert!(matches!(
            verify(&fixture, cross_node),
            Err(BrokerPlanVerificationError::NodeMismatch)
        ));
    }

    #[test]
    fn expiry_and_tamper_fail() {
        let fixture = fixture();

        let mut expired = context(&fixture);
        expired.now_seconds = 200;
        assert!(matches!(
            verify(&fixture, expired),
            Err(BrokerPlanVerificationError::Signature(
                SignatureVerificationError::Expired
            ))
        ));

        let mut tampered = fixture.plan_bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            verify_broker_plan(
                &tampered,
                &fixture.signature,
                &fixture.anchor,
                context(&fixture),
                DecodeLimits::default(),
            )
            .is_err()
        );

        let bad_signature = Signature::new(
            fixture.signature.statement().clone(),
            SignatureBytes::new([0; 64]),
        );
        assert!(matches!(
            verify_broker_plan(
                &fixture.plan_bytes,
                &bad_signature,
                &fixture.anchor,
                context(&fixture),
                DecodeLimits::default(),
            ),
            Err(BrokerPlanVerificationError::Signature(
                SignatureVerificationError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn unknown_verbs_wrong_audiences_and_zero_sentinels_fail_closed() {
        let stable_codes = [
            (1, BrokerVerb::HostLaunch),
            (2, BrokerVerb::HostStop),
            (3, BrokerVerb::HostFreeze),
            (4, BrokerVerb::HostThaw),
            (5, BrokerVerb::HostKill),
            (6, BrokerVerb::HostObserve),
            (7, BrokerVerb::HostInventory),
            (8, BrokerVerb::MountCreate),
            (9, BrokerVerb::MountInstall),
            (10, BrokerVerb::MountReplace),
            (11, BrokerVerb::MountDetach),
            (12, BrokerVerb::MountRelease),
            (13, BrokerVerb::MountInventorySummary),
            (14, BrokerVerb::MountInventoryResources),
            (15, BrokerVerb::StorageCreateWorkspace),
            (16, BrokerVerb::StorageSnapshot),
            (17, BrokerVerb::StorageHoldSnapshot),
            (18, BrokerVerb::StorageReleaseHold),
            (19, BrokerVerb::StorageClone),
            (20, BrokerVerb::StorageSetQuota),
            (21, BrokerVerb::StorageDestroy),
            (22, BrokerVerb::StorageInventory),
            (23, BrokerVerb::NetworkPrepare),
            (24, BrokerVerb::NetworkArmLease),
            (25, BrokerVerb::NetworkRenewLease),
            (26, BrokerVerb::NetworkDisarm),
            (27, BrokerVerb::NetworkDestroy),
            (28, BrokerVerb::NetworkInventory),
        ];
        for (code, expected) in stable_codes {
            let verb = BrokerVerb::from_code(code)
                .unwrap_or_else(|error| panic!("registered verb failed: {error}"));
            assert_eq!(verb, expected);
            assert_eq!(verb.get(), code);
        }
        assert_eq!(
            BrokerVerb::from_code(29),
            Err(InvalidBrokerAuthorizationPlan::UnknownVerb)
        );
        assert_eq!(
            BrokerResourceHandle::from_bytes([0; 32]),
            Err(InvalidBrokerAuthorizationPlan::UnspecifiedResource)
        );
        assert_eq!(
            BrokerAssignment::new(
                SandboxId::from_bytes([0; 16]),
                IncarnationId::from_bytes([2; 16]),
                AssignmentEpoch::new(1),
                DesiredGeneration::new(1),
                ObjectDigest::from_bytes([1; 32]),
            ),
            Err(InvalidBrokerAuthorizationPlan::UnspecifiedAssignmentDigest)
        );

        let fixture = fixture();
        let host_grant = BrokerGrant::new(
            BrokerVerb::HostLaunch,
            BrokerGrantTarget::Assignment,
            BrokerArgumentCommitment::for_canonical_bytes(b"host launch"),
            1,
            0,
        )
        .unwrap_or_else(|error| panic!("test grant failed: {error}"));
        assert!(matches!(
            BrokerAuthorizationPlan::new(
                BrokerAudience::Mount,
                ProtocolId::MountBroker,
                ProtocolVersion::new(1, 0),
                fixture.context_assignment,
                fixture.node,
                fixture.ownership_authority.clone(),
                vec![host_grant],
                ObjectDigest::from_bytes([1; 32]),
                RevocationScopeId::from_bytes([1; 16]),
                1,
                2,
                Vec::new(),
            ),
            Err(InvalidBrokerAuthorizationPlan::ProtocolAudienceMismatch)
        ));

        let grant = BrokerGrant::new(
            BrokerVerb::MountCreate,
            BrokerGrantTarget::Assignment,
            BrokerArgumentCommitment::for_canonical_bytes(b"mount create"),
            1,
            0,
        )
        .unwrap_or_else(|error| panic!("test grant failed: {error}"));
        assert!(matches!(
            BrokerAuthorizationPlan::new(
                BrokerAudience::Mount,
                ProtocolId::MountBroker,
                ProtocolVersion::new(1, 0),
                fixture.context_assignment,
                fixture.node,
                fixture.ownership_authority.clone(),
                vec![grant],
                ObjectDigest::from_bytes([0; 32]),
                RevocationScopeId::from_bytes([1; 16]),
                1,
                2,
                Vec::new(),
            ),
            Err(InvalidBrokerAuthorizationPlan::UnspecifiedAuthorityCommitment)
        ));

        assert_eq!(
            BrokerGrant::new(
                BrokerVerb::MountReplace,
                BrokerGrantTarget::Assignment,
                BrokerArgumentCommitment::for_canonical_bytes(b"replace"),
                1,
                0,
            ),
            Err(InvalidBrokerAuthorizationPlan::TargetShapeMismatch)
        );
        assert_eq!(
            BrokerGrant::new(
                BrokerVerb::MountCreate,
                BrokerGrantTarget::Assignment,
                BrokerArgumentCommitment::for_canonical_bytes(b"oversized"),
                16 * 1024 * 1024 + 1,
                0,
            ),
            Err(InvalidBrokerAuthorizationPlan::InvalidRequestBound)
        );
        assert_eq!(
            BrokerGrant::new(
                BrokerVerb::MountCreate,
                BrokerGrantTarget::Assignment,
                BrokerArgumentCommitment::for_canonical_bytes(b"too many descriptors"),
                1,
                17,
            ),
            Err(InvalidBrokerAuthorizationPlan::InvalidRequestBound)
        );
    }

    #[test]
    fn privileged_broker_registry_has_stable_audiences_and_target_shapes() {
        let assignment_verbs = [
            BrokerVerb::HostLaunch,
            BrokerVerb::HostInventory,
            BrokerVerb::MountCreate,
            BrokerVerb::MountInventorySummary,
            BrokerVerb::MountInventoryResources,
            BrokerVerb::StorageCreateWorkspace,
            BrokerVerb::StorageInventory,
            BrokerVerb::NetworkPrepare,
            BrokerVerb::NetworkInventory,
        ];
        let resource_verbs = [
            BrokerVerb::HostStop,
            BrokerVerb::HostFreeze,
            BrokerVerb::HostThaw,
            BrokerVerb::HostKill,
            BrokerVerb::HostObserve,
            BrokerVerb::MountInstall,
            BrokerVerb::MountDetach,
            BrokerVerb::MountRelease,
            BrokerVerb::StorageSnapshot,
            BrokerVerb::StorageHoldSnapshot,
            BrokerVerb::StorageReleaseHold,
            BrokerVerb::StorageClone,
            BrokerVerb::StorageSetQuota,
            BrokerVerb::StorageDestroy,
            BrokerVerb::NetworkArmLease,
            BrokerVerb::NetworkRenewLease,
            BrokerVerb::NetworkDisarm,
            BrokerVerb::NetworkDestroy,
        ];

        for verb in assignment_verbs {
            assert_eq!(verb.target_shape(), BrokerGrantTargetShape::Assignment);
        }
        for verb in resource_verbs {
            assert_eq!(verb.target_shape(), BrokerGrantTargetShape::Resource);
        }
        assert_eq!(
            BrokerVerb::MountReplace.target_shape(),
            BrokerGrantTargetShape::ResourcePair
        );

        for code in 15..=22 {
            assert_eq!(
                BrokerVerb::from_code(code)
                    .unwrap_or_else(|error| panic!("storage verb {code}: {error}"))
                    .audience(),
                BrokerAudience::Storage
            );
        }
        for code in 23..=28 {
            assert_eq!(
                BrokerVerb::from_code(code)
                    .unwrap_or_else(|error| panic!("network verb {code}: {error}"))
                    .audience(),
                BrokerAudience::Network
            );
        }
        assert_eq!(
            BrokerAudience::Storage.protocol(),
            ProtocolId::StorageBroker
        );
        assert_eq!(
            BrokerAudience::Network.protocol(),
            ProtocolId::NetworkBroker
        );
    }

    #[test]
    fn trust_anchor_rejects_unpinned_key_generation() {
        let fixture = fixture();
        let wrong_signer = KeyReference::new(
            fixture.anchor.signer.stable_key_id().clone(),
            fixture.anchor.signer.generation() + 1,
            fixture.anchor.signer.public_key_sha256(),
            KeyUsage::BrokerAuthorization,
        );
        assert!(matches!(
            BrokerPlanTrustAnchor::from_trusted_configuration(
                fixture.anchor.canonical_policy.clone(),
                fixture.anchor.policy_descriptor.clone(),
                fixture.anchor.trust_scope,
                wrong_signer,
                fixture.anchor.public_key,
                fixture.anchor.revocation_scope,
                DecodeLimits::default(),
            ),
            Err(BrokerPlanVerificationError::InvalidTrustAnchor)
        ));

        let other_scope_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            fixture.anchor.canonical_policy.clone(),
            fixture.anchor.policy_descriptor.clone(),
            fixture.anchor.trust_scope,
            fixture.anchor.signer.clone(),
            fixture.anchor.public_key,
            RevocationScopeId::from_bytes([9; 16]),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));
        assert!(matches!(
            verify_broker_plan(
                &fixture.plan_bytes,
                &fixture.signature,
                &other_scope_anchor,
                context(&fixture),
                DecodeLimits::default(),
            ),
            Err(BrokerPlanVerificationError::RevocationScopeMismatch)
        ));
    }
}
