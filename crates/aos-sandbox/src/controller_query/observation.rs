//! Checked additive observation metadata for the public protobuf.
//!
//! The models correlate portable status fields before a service or CLI may
//! return them. Backend-local diagnostics remain outside this schema.

use aos_proto::aos::sandbox::v1::{ConditionState, SandboxPhase};

use super::resource::{
    CheckedConditionV1, CheckedOperationResourceV1, CheckedPlacementV1, CheckedResourceReferenceV1,
    CheckedSandboxResourceV1, PublicConditionCodeV1, PublicResourceTypeV1,
};

/// Maximum pinned public resource references in one sandbox status.
pub const MAXIMUM_PINNED_REFERENCES: usize = 128;
/// Maximum active executions or attachment rows in one sandbox status.
pub const MAXIMUM_STATUS_REFERENCES: usize = 128;
/// Maximum opaque bytes in one public audit-event cursor.
pub const MAXIMUM_AUDIT_CURSOR_BYTES: usize = 4 * 1024;

/// States the mandatory integration constraint for these additive models.
pub const PUBLIC_PROTO_INTEGRATION_REQUIRED: &str =
    "register the dormant checked adapters before exposing this observation";

/// Identifies a closed portable condition reason family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConditionReasonV1 {
    /// Required state is verified.
    Verified,
    /// Reconciliation has not yet completed.
    Pending,
    /// A named dependency is unavailable.
    DependencyUnavailable,
    /// A bounded resource is unavailable.
    CapacityUnavailable,
    /// Policy prevents progress.
    PolicyRejected,
    /// Ownership authority is not active.
    AuthorityPending,
    /// Lost authority was contained.
    AuthorityFenced,
    /// Logical completion left residual cleanup.
    ResidualCleanup,
}

/// Classifies freshness without using incomparable client wall clocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionFreshnessV1 {
    /// The producer attests this observation is current for its sequence.
    Current,
    /// The producer explicitly marks the observation stale.
    Stale,
}

/// Reports inconsistent additive condition metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidObservationMetadata {
    /// A generation or observation sequence uses zero.
    #[error("condition observation metadata is unspecified")]
    Unspecified,
    /// Metadata does not exactly cover the resource's canonical conditions.
    #[error("condition observation metadata does not match the resource")]
    ConditionMismatch,
    /// A typed status has invalid bounds or contradicts another status.
    #[error("controller observation status is inconsistent")]
    InvalidStatus,
}

/// Stores a bounded protobuf-domain timestamp without accepting local clocks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicTimestampV1 {
    seconds: i64,
    nanoseconds: u32,
}

impl PublicTimestampV1 {
    /// Checks a timestamp in the established protobuf timestamp domain.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::InvalidStatus`] outside the
    /// protobuf timestamp range or for one billion nanoseconds or more.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, InvalidObservationMetadata> {
        if seconds < -62_135_596_800 || seconds > 253_402_300_799 || nanoseconds >= 1_000_000_000 {
            Err(InvalidObservationMetadata::InvalidStatus)
        } else {
            Ok(Self {
                seconds,
                nanoseconds,
            })
        }
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns fractional nanoseconds.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Stores a lease exactly correlated to one placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipLeaseStatusV1 {
    placement: CheckedPlacementV1,
    lease_generation: u64,
    expires_at: PublicTimestampV1,
}

impl OwnershipLeaseStatusV1 {
    /// Checks a current or retained ownership lease status.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::Unspecified`] for generation zero.
    pub const fn new(
        placement: CheckedPlacementV1,
        lease_generation: u64,
        expires_at: PublicTimestampV1,
    ) -> Result<Self, InvalidObservationMetadata> {
        if lease_generation == 0 {
            Err(InvalidObservationMetadata::Unspecified)
        } else {
            Ok(Self {
                placement,
                lease_generation,
                expires_at,
            })
        }
    }

    /// Returns the exact leased placement.
    #[must_use]
    pub const fn placement(&self) -> &CheckedPlacementV1 {
        &self.placement
    }

    /// Returns the monotone lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the controller-authenticated lease expiry.
    #[must_use]
    pub const fn expires_at(&self) -> PublicTimestampV1 {
        self.expires_at
    }
}

/// Identifies current ownership evidence for a placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipEvidenceV1 {
    /// No assignment exists.
    Unassigned,
    /// Assignment exists but ownership is not active.
    AwaitingOwnership(CheckedPlacementV1),
    /// A current ownership lease is proven.
    Owned(OwnershipLeaseStatusV1),
    /// The retained assignment's lease expired or was revoked.
    Expired(OwnershipLeaseStatusV1),
}

/// Stores guardian evidence correlated to a placement and lease generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardianStatusV1 {
    placement: CheckedPlacementV1,
    guardian_generation: u64,
    lease_generation: u64,
}

impl GuardianStatusV1 {
    /// Checks a placement guardian status.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::Unspecified`] for generation zero.
    pub const fn new(
        placement: CheckedPlacementV1,
        guardian_generation: u64,
        lease_generation: u64,
    ) -> Result<Self, InvalidObservationMetadata> {
        if guardian_generation == 0 || lease_generation == 0 {
            Err(InvalidObservationMetadata::Unspecified)
        } else {
            Ok(Self {
                placement,
                guardian_generation,
                lease_generation,
            })
        }
    }

    /// Returns the guarded placement.
    #[must_use]
    pub const fn placement(&self) -> &CheckedPlacementV1 {
        &self.placement
    }

    /// Returns the monotone guardian generation.
    #[must_use]
    pub const fn guardian_generation(&self) -> u64 {
        self.guardian_generation
    }

    /// Returns the lease generation enforced by the guardian.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }
}

/// Identifies current fail-stop guardian evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianEvidenceV1 {
    /// No placement guardian is required.
    Disarmed,
    /// Guardian activation is not yet proven.
    Arming(GuardianStatusV1),
    /// The guardian is armed for the owned assignment.
    Armed(GuardianStatusV1),
    /// The guardian proves containment after authority loss.
    Contained(GuardianStatusV1),
}

/// Correlates one condition with generation, sequence, reason, and freshness.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedConditionObservationV1 {
    condition: CheckedConditionV1,
    desired_generation: u64,
    observation_sequence: u64,
    reason: ConditionReasonV1,
    freshness: ConditionFreshnessV1,
}

impl CheckedConditionObservationV1 {
    /// Constructs metadata for one already checked public condition.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::Unspecified`] for zero counters.
    pub fn new(
        condition: CheckedConditionV1,
        desired_generation: u64,
        observation_sequence: u64,
        reason: ConditionReasonV1,
        freshness: ConditionFreshnessV1,
    ) -> Result<Self, InvalidObservationMetadata> {
        if desired_generation == 0 || observation_sequence == 0 {
            return Err(InvalidObservationMetadata::Unspecified);
        }
        if !reason_matches_condition(&condition, reason) {
            return Err(InvalidObservationMetadata::ConditionMismatch);
        }
        Ok(Self {
            condition,
            desired_generation,
            observation_sequence,
            reason,
            freshness,
        })
    }

    /// Returns the correlated checked condition.
    #[must_use]
    pub const fn condition(&self) -> &CheckedConditionV1 {
        &self.condition
    }

    /// Returns the desired generation observed with this condition.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the producer-local monotone observation sequence.
    #[must_use]
    pub const fn observation_sequence(&self) -> u64 {
        self.observation_sequence
    }

    /// Returns the closed portable reason.
    #[must_use]
    pub const fn reason(&self) -> ConditionReasonV1 {
        self.reason
    }

    /// Returns the producer freshness classification.
    #[must_use]
    pub const fn freshness(&self) -> ConditionFreshnessV1 {
        self.freshness
    }

    /// Reports true only for a current true condition at the requested generation.
    #[must_use]
    pub fn is_current_true_for(&self, desired_generation: u64) -> bool {
        self.desired_generation == desired_generation
            && self.freshness == ConditionFreshnessV1::Current
            && self.condition.as_proto().state.as_known()
                == Some(ConditionState::CONDITION_STATE_TRUE)
    }
}

fn reason_matches_condition(condition: &CheckedConditionV1, reason: ConditionReasonV1) -> bool {
    use ConditionReasonV1 as R;
    use PublicConditionCodeV1 as C;

    let state = condition.as_proto().state.as_known();
    match (condition.code(), state, reason) {
        (C::OwnershipPending, Some(ConditionState::CONDITION_STATE_TRUE), R::AuthorityPending)
        | (C::Fenced, Some(ConditionState::CONDITION_STATE_TRUE), R::AuthorityFenced)
        | (C::ResidualState, Some(ConditionState::CONDITION_STATE_TRUE), R::ResidualCleanup)
        | (
            C::Ready
            | C::EnforcementReady
            | C::ViewsReady
            | C::EnvironmentReady
            | C::Quiesced
            | C::Frozen,
            Some(ConditionState::CONDITION_STATE_TRUE),
            R::Verified,
        ) => true,
        (C::Blocked | C::Degraded, Some(ConditionState::CONDITION_STATE_TRUE), reason) => matches!(
            reason,
            R::Pending | R::DependencyUnavailable | R::CapacityUnavailable | R::PolicyRejected
        ),
        (
            _,
            Some(ConditionState::CONDITION_STATE_FALSE | ConditionState::CONDITION_STATE_UNKNOWN),
            reason,
        ) => !matches!(reason, R::Verified),
        _ => false,
    }
}

/// Couples a sandbox status resource to additive current-condition metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedSandboxObservationV1 {
    resource: CheckedSandboxResourceV1,
    conditions: Vec<CheckedConditionObservationV1>,
    additive: AdditiveControllerObservationV1,
}

impl CheckedSandboxObservationV1 {
    /// Checks complete canonical status metadata against the resource sequence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::ConditionMismatch`] unless every
    /// resource condition has matching current-generation metadata with a
    /// sequence no newer than the resource observation.
    pub fn new(
        resource: CheckedSandboxResourceV1,
        conditions: Vec<CheckedConditionObservationV1>,
        additive: AdditiveControllerObservationV1,
    ) -> Result<Self, InvalidObservationMetadata> {
        let matches = resource.conditions().len() == conditions.len()
            && resource
                .conditions()
                .iter()
                .zip(&conditions)
                .all(|(condition, observed)| {
                    condition == observed.condition()
                        && observed.desired_generation() == resource.desired_generation()
                        && observed.observation_sequence() <= resource.observation_sequence()
                });
        if !matches {
            return Err(InvalidObservationMetadata::ConditionMismatch);
        }
        if !additive.correlates_to_placement(resource.placement()) {
            return Err(InvalidObservationMetadata::InvalidStatus);
        }
        if !additive.is_legal_for_phase(resource.phase()) {
            return Err(InvalidObservationMetadata::InvalidStatus);
        }
        Ok(Self {
            resource,
            conditions,
            additive,
        })
    }

    /// Returns the established sandbox status resource.
    #[must_use]
    pub const fn resource(&self) -> &CheckedSandboxResourceV1 {
        &self.resource
    }

    /// Reports a true, fresh condition for the current desired generation.
    #[must_use]
    pub fn has_current_true_condition(&self, code: PublicConditionCodeV1) -> bool {
        self.conditions.iter().any(|condition| {
            condition.condition().code() == code
                && condition.is_current_true_for(self.resource.desired_generation())
        })
    }

    /// Returns additive controller evidence pending public proto integration.
    #[must_use]
    pub const fn additive(&self) -> &AdditiveControllerObservationV1 {
        &self.additive
    }
}

/// Couples an operation resource to complete additive condition metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedOperationObservationV1 {
    resource: CheckedOperationResourceV1,
    observation_sequence: u64,
    conditions: Vec<CheckedConditionObservationV1>,
}

impl CheckedOperationObservationV1 {
    /// Checks exact canonical condition coverage for an operation observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata`] for missing, reordered, or
    /// generation-mismatched condition metadata.
    pub fn new(
        resource: CheckedOperationResourceV1,
        observation_sequence: u64,
        conditions: Vec<CheckedConditionObservationV1>,
    ) -> Result<Self, InvalidObservationMetadata> {
        if observation_sequence == 0 {
            return Err(InvalidObservationMetadata::Unspecified);
        }
        let matches = resource.conditions().len() == conditions.len()
            && resource
                .conditions()
                .iter()
                .zip(&conditions)
                .all(|(condition, observed)| {
                    condition == observed.condition()
                        && observed.desired_generation() == resource.as_proto().accepted_generation
                        && observed.observation_sequence() <= observation_sequence
                });
        if !matches {
            return Err(InvalidObservationMetadata::ConditionMismatch);
        }
        Ok(Self {
            resource,
            observation_sequence,
            conditions,
        })
    }

    /// Returns the established checked operation resource.
    #[must_use]
    pub const fn resource(&self) -> &CheckedOperationResourceV1 {
        &self.resource
    }

    /// Returns the producer-local current observation sequence.
    #[must_use]
    pub const fn observation_sequence(&self) -> u64 {
        self.observation_sequence
    }

    /// Returns complete canonical condition observations.
    #[must_use]
    pub fn conditions(&self) -> &[CheckedConditionObservationV1] {
        &self.conditions
    }

    /// Consumes the observation and returns its checked resource.
    #[must_use]
    pub fn into_resource(self) -> CheckedOperationResourceV1 {
        self.resource
    }
}

/// Identifies the durable ownership transaction state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipTransactionStateV1 {
    /// No ownership transaction is active.
    Absent,
    /// A transaction is prepared but not committed.
    Prepared,
    /// The transaction committed ownership authority.
    Committed,
    /// The transaction was rolled back.
    RolledBack,
}

/// Stores typed ownership transaction status.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OwnershipTransactionStatusV1 {
    state: OwnershipTransactionStateV1,
    generation: u64,
    transaction_id: Option<[u8; 16]>,
}

impl OwnershipTransactionStatusV1 {
    /// Checks a transaction state and its identity requirements.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::InvalidStatus`] unless `Absent`
    /// uses zero/no identity and every active state uses nonzero values.
    pub const fn new(
        state: OwnershipTransactionStateV1,
        generation: u64,
        transaction_id: Option<[u8; 16]>,
    ) -> Result<Self, InvalidObservationMetadata> {
        let valid = match (state, generation, transaction_id) {
            (OwnershipTransactionStateV1::Absent, 0, None) => true,
            (OwnershipTransactionStateV1::Absent, _, _) => false,
            (_, 0, _) | (_, _, None) => false,
            (_, _, Some(identifier)) => identifier != [0; 16],
        };
        if valid {
            Ok(Self {
                state,
                generation,
                transaction_id,
            })
        } else {
            Err(InvalidObservationMetadata::InvalidStatus)
        }
    }

    /// Returns the closed durable transaction state.
    #[must_use]
    pub const fn state(&self) -> OwnershipTransactionStateV1 {
        self.state
    }

    /// Returns the transaction generation, or zero for [`OwnershipTransactionStateV1::Absent`].
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the protected transaction identity to the future proto adapter.
    #[must_use]
    pub(crate) const fn transaction_id(&self) -> Option<[u8; 16]> {
        self.transaction_id
    }
}

impl std::fmt::Debug for OwnershipTransactionStatusV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnershipTransactionStatusV1")
            .field("state", &self.state)
            .field("generation", &self.generation)
            .field("transaction_id", &self.transaction_id.map(|_| "<redacted>"))
            .finish()
    }
}

/// Stores one generation and its checked public descriptor.
#[derive(Clone, Debug, PartialEq)]
pub struct RealizedRootStatusV1 {
    generation: u64,
    descriptor: super::portable::CheckedObjectDescriptorV1,
}

impl RealizedRootStatusV1 {
    /// Checks a realized-root generation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::Unspecified`] for generation zero.
    pub fn new(
        generation: u64,
        descriptor: super::portable::CheckedObjectDescriptorV1,
    ) -> Result<Self, InvalidObservationMetadata> {
        if generation == 0 {
            Err(InvalidObservationMetadata::Unspecified)
        } else {
            Ok(Self {
                generation,
                descriptor,
            })
        }
    }

    /// Returns the realized-root generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the deeply checked root descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &super::portable::CheckedObjectDescriptorV1 {
        &self.descriptor
    }
}

macro_rules! status_domain_identity {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Checks a nonzero public domain identity.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidObservationMetadata::Unspecified`] for zero.
            pub const fn new(value: [u8; 16]) -> Result<Self, InvalidObservationMetadata> {
                if value == [0; 16] {
                    Err(InvalidObservationMetadata::Unspecified)
                } else {
                    Ok(Self(value))
                }
            }

            /// Returns identity bytes to the future established-proto adapter.
            #[must_use]
            pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

status_domain_identity!(
    CacheDomainIdentityV1,
    "Stores the logical cache-accounting domain identity."
);
status_domain_identity!(
    DisclosureDomainIdentityV1,
    "Stores the authorization disclosure-accounting domain identity."
);

/// Identifies portable attachment health without backend diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttachmentHealthV1 {
    /// The attachment is realized and verified.
    Ready,
    /// The attachment remains usable with an advisory limitation.
    Degraded,
    /// The attachment cannot currently be realized.
    Blocked,
}

/// Stores one attachment generation and health observation.
#[derive(Clone, Debug, PartialEq)]
pub struct AttachmentGenerationStatusV1 {
    attachment: CheckedResourceReferenceV1,
    generation: u64,
    health: AttachmentHealthV1,
}

impl AttachmentGenerationStatusV1 {
    /// Checks an attachment reference and nonzero generation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::InvalidStatus`] for another
    /// resource type or generation zero.
    pub fn new(
        attachment: CheckedResourceReferenceV1,
        generation: u64,
        health: AttachmentHealthV1,
    ) -> Result<Self, InvalidObservationMetadata> {
        if attachment.resource_type() != PublicResourceTypeV1::Attachment || generation == 0 {
            Err(InvalidObservationMetadata::InvalidStatus)
        } else {
            Ok(Self {
                attachment,
                generation,
                health,
            })
        }
    }

    /// Returns the checked attachment reference.
    #[must_use]
    pub const fn attachment(&self) -> &CheckedResourceReferenceV1 {
        &self.attachment
    }

    /// Returns the attachment generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns portable attachment health.
    #[must_use]
    pub const fn health(&self) -> AttachmentHealthV1 {
        self.health
    }
}

/// Stores a bounded canonical attachment generation set.
#[derive(Clone, Debug, PartialEq)]
pub struct AttachmentGenerationSetV1(Vec<AttachmentGenerationStatusV1>);

impl AttachmentGenerationSetV1 {
    /// Checks canonical attachment identity order and count.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::InvalidStatus`] for oversized,
    /// duplicated, or unordered rows.
    pub fn new(
        value: Vec<AttachmentGenerationStatusV1>,
    ) -> Result<Self, InvalidObservationMetadata> {
        if value.len() > MAXIMUM_STATUS_REFERENCES
            || !value
                .windows(2)
                .all(|pair| pair[0].attachment.resource_id() < pair[1].attachment.resource_id())
        {
            Err(InvalidObservationMetadata::InvalidStatus)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns canonical attachment generation rows.
    #[must_use]
    pub fn as_slice(&self) -> &[AttachmentGenerationStatusV1] {
        &self.0
    }
}

/// Stores bounded canonical active-execution references.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveExecutionSetV1(Vec<CheckedResourceReferenceV1>);

impl ActiveExecutionSetV1 {
    /// Checks active execution resource types, order, and count.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::InvalidStatus`] for a nonexecution
    /// reference, oversized set, duplicate, or unordered identity.
    pub fn new(value: Vec<CheckedResourceReferenceV1>) -> Result<Self, InvalidObservationMetadata> {
        if value.len() > MAXIMUM_STATUS_REFERENCES
            || value
                .iter()
                .any(|reference| reference.resource_type() != PublicResourceTypeV1::Execution)
            || !value
                .windows(2)
                .all(|pair| pair[0].resource_id() < pair[1].resource_id())
        {
            Err(InvalidObservationMetadata::InvalidStatus)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns canonical active execution references.
    #[must_use]
    pub fn as_slice(&self) -> &[CheckedResourceReferenceV1] {
        &self.0
    }
}

/// Stores current cache admission and pin usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheStatusV1 {
    domain: CacheDomainIdentityV1,
    admitted_bytes: u64,
    pinned_bytes: u64,
    pinned_objects: u32,
}

impl CacheStatusV1 {
    /// Checks cache usage relationships.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::InvalidStatus`] when pinned bytes
    /// exceed admitted bytes or an object count exists without pinned bytes.
    pub const fn new(
        domain: CacheDomainIdentityV1,
        admitted_bytes: u64,
        pinned_bytes: u64,
        pinned_objects: u32,
    ) -> Result<Self, InvalidObservationMetadata> {
        if pinned_bytes > admitted_bytes || (pinned_objects != 0 && pinned_bytes == 0) {
            Err(InvalidObservationMetadata::InvalidStatus)
        } else {
            Ok(Self {
                domain,
                admitted_bytes,
                pinned_bytes,
                pinned_objects,
            })
        }
    }

    /// Returns the public cache-accounting domain identity.
    #[must_use]
    pub const fn domain(self) -> CacheDomainIdentityV1 {
        self.domain
    }

    /// Returns admitted logical bytes.
    #[must_use]
    pub const fn admitted_bytes(self) -> u64 {
        self.admitted_bytes
    }

    /// Returns pinned logical bytes.
    #[must_use]
    pub const fn pinned_bytes(self) -> u64 {
        self.pinned_bytes
    }

    /// Returns the pinned object count.
    #[must_use]
    pub const fn pinned_objects(self) -> u32 {
        self.pinned_objects
    }
}

/// Stores public disclosure accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisclosureStatusV1 {
    /// Names the disclosure-accounting domain.
    pub domain: DisclosureDomainIdentityV1,
    /// Counts resources visible to the bound principal.
    pub visible_resources: u32,
    /// Counts resources concealed by policy.
    pub redacted_resources: u32,
}

impl DisclosureStatusV1 {
    /// Constructs disclosure counters.
    #[must_use]
    pub const fn new(
        domain: DisclosureDomainIdentityV1,
        visible_resources: u32,
        redacted_resources: u32,
    ) -> Self {
        Self {
            domain,
            visible_resources,
            redacted_resources,
        }
    }
}

/// Stores logical usage counters, never host-local physical accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalUsageStatusV1 {
    /// Counts cumulative logical CPU nanoseconds.
    pub cpu_nanoseconds: u64,
    /// Counts logical memory bytes.
    pub memory_bytes: u64,
    /// Counts logical storage bytes.
    pub storage_bytes: u64,
    /// Counts logical processes.
    pub process_count: u32,
}

impl LogicalUsageStatusV1 {
    /// Constructs logical usage counters.
    #[must_use]
    pub const fn new(
        cpu_nanoseconds: u64,
        memory_bytes: u64,
        storage_bytes: u64,
        process_count: u32,
    ) -> Self {
        Self {
            cpu_nanoseconds,
            memory_bytes,
            storage_bytes,
            process_count,
        }
    }
}

/// Stores one bounded opaque audit-event cursor.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditEventCursorV1(Vec<u8>);

impl AuditEventCursorV1 {
    /// Checks a nonempty bounded audit cursor returned by an authenticated API.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata::InvalidStatus`] for empty or
    /// oversized bytes.
    pub(crate) fn from_authenticated(value: Vec<u8>) -> Result<Self, InvalidObservationMetadata> {
        if value.is_empty() || value.len() > MAXIMUM_AUDIT_CURSOR_BYTES {
            Err(InvalidObservationMetadata::InvalidStatus)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns cursor bytes only to the future authenticated watch adapter.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for AuditEventCursorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditEventCursorV1(<redacted>)")
    }
}

/// Carries typed portable controller status required by RFC-0021.
#[derive(Clone, PartialEq)]
pub struct AdditiveControllerObservationV1 {
    ownership: OwnershipEvidenceV1,
    guardian: GuardianEvidenceV1,
    capability_generation: Option<u64>,
    realized_root: Option<RealizedRootStatusV1>,
    transaction: OwnershipTransactionStatusV1,
    environment_generation: Option<u64>,
    attachments: Option<AttachmentGenerationSetV1>,
    active_executions: ActiveExecutionSetV1,
    pinned_references: Vec<CheckedResourceReferenceV1>,
    cache: Option<CacheStatusV1>,
    disclosure: Option<DisclosureStatusV1>,
    logical_usage: Option<LogicalUsageStatusV1>,
    audit_event_cursor: Option<AuditEventCursorV1>,
    last_successful_reconciliation_time: PublicTimestampV1,
}

impl AdditiveControllerObservationV1 {
    /// Checks bounded typed public status before dormant proto integration.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationMetadata`] for zero generations, oversized
    /// or noncanonical pinned references, or internally inconsistent authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ownership: OwnershipEvidenceV1,
        guardian: GuardianEvidenceV1,
        capability_generation: Option<u64>,
        realized_root: Option<RealizedRootStatusV1>,
        transaction: OwnershipTransactionStatusV1,
        environment_generation: Option<u64>,
        attachments: Option<AttachmentGenerationSetV1>,
        active_executions: ActiveExecutionSetV1,
        pinned_references: Vec<CheckedResourceReferenceV1>,
        cache: Option<CacheStatusV1>,
        disclosure: Option<DisclosureStatusV1>,
        logical_usage: Option<LogicalUsageStatusV1>,
        audit_event_cursor: Option<AuditEventCursorV1>,
        last_successful_reconciliation_time: PublicTimestampV1,
    ) -> Result<Self, InvalidObservationMetadata> {
        let core_is_consistent = capability_generation.is_none_or(|value| value != 0)
            && environment_generation.is_none_or(|value| value != 0)
            && attachments.as_ref().is_none_or(|_| {
                capability_generation.is_some()
                    && realized_root.is_some()
                    && environment_generation.is_some()
            });
        let accounting_is_consistent = (cache.is_none() || disclosure.is_some())
            && (pinned_references.is_empty() || cache.is_some())
            && match (cache, disclosure) {
                (Some(cache), Some(disclosure)) => {
                    cache.domain().as_bytes() == disclosure.domain.as_bytes()
                }
                _ => true,
            };
        let execution_is_consistent = active_executions.as_slice().is_empty()
            || (matches!(ownership, OwnershipEvidenceV1::Owned(_))
                && capability_generation.is_some()
                && realized_root.is_some()
                && environment_generation.is_some()
                && attachments.is_some());
        if !core_is_consistent
            || !accounting_is_consistent
            || !execution_is_consistent
            || pinned_references.len() > MAXIMUM_PINNED_REFERENCES
            || !pinned_references.windows(2).all(|pair| {
                (pair[0].resource_type(), pair[0].resource_id())
                    < (pair[1].resource_type(), pair[1].resource_id())
            })
            || !authority_evidence_is_internally_consistent(ownership, guardian)
            || !transaction_matches_ownership(transaction.state(), ownership)
        {
            return Err(InvalidObservationMetadata::InvalidStatus);
        }
        Ok(Self {
            ownership,
            guardian,
            capability_generation,
            realized_root,
            transaction,
            environment_generation,
            attachments,
            active_executions,
            pinned_references,
            cache,
            disclosure,
            logical_usage,
            audit_event_cursor,
            last_successful_reconciliation_time,
        })
    }

    /// Returns current ownership evidence.
    #[must_use]
    pub const fn ownership(&self) -> OwnershipEvidenceV1 {
        self.ownership
    }

    /// Returns current guardian evidence.
    #[must_use]
    pub const fn guardian(&self) -> GuardianEvidenceV1 {
        self.guardian
    }

    /// Returns the current capability generation.
    #[must_use]
    pub const fn capability_generation(&self) -> Option<u64> {
        self.capability_generation
    }

    /// Returns realized root status.
    #[must_use]
    pub const fn realized_root(&self) -> Option<&RealizedRootStatusV1> {
        self.realized_root.as_ref()
    }

    /// Returns ownership transaction status.
    #[must_use]
    pub const fn transaction(&self) -> &OwnershipTransactionStatusV1 {
        &self.transaction
    }

    /// Returns the environment generation.
    #[must_use]
    pub const fn environment_generation(&self) -> Option<u64> {
        self.environment_generation
    }

    /// Returns the typed attachment generation and health set, if realized.
    #[must_use]
    pub const fn attachments(&self) -> Option<&AttachmentGenerationSetV1> {
        self.attachments.as_ref()
    }

    /// Returns typed active execution references.
    #[must_use]
    pub const fn active_executions(&self) -> &ActiveExecutionSetV1 {
        &self.active_executions
    }

    /// Returns canonical pinned public references.
    #[must_use]
    pub fn pinned_references(&self) -> &[CheckedResourceReferenceV1] {
        &self.pinned_references
    }

    /// Returns cache accounting.
    #[must_use]
    pub const fn cache(&self) -> Option<CacheStatusV1> {
        self.cache
    }

    /// Returns public disclosure accounting.
    #[must_use]
    pub const fn disclosure(&self) -> Option<DisclosureStatusV1> {
        self.disclosure
    }

    /// Returns logical usage accounting.
    #[must_use]
    pub const fn logical_usage(&self) -> Option<LogicalUsageStatusV1> {
        self.logical_usage
    }

    /// Returns the audit-event cursor to the future proto adapter.
    #[must_use]
    pub(crate) const fn audit_event_cursor(&self) -> Option<&AuditEventCursorV1> {
        self.audit_event_cursor.as_ref()
    }

    /// Returns the last successful reconciliation timestamp.
    #[must_use]
    pub const fn last_successful_reconciliation_time(&self) -> PublicTimestampV1 {
        self.last_successful_reconciliation_time
    }

    /// Reports exact correlation with the public placement tuple.
    #[must_use]
    pub fn correlates_to_placement(&self, placement: Option<&CheckedPlacementV1>) -> bool {
        authority_evidence_matches_placement(self.ownership, self.guardian, placement)
    }

    /// Reports whether optional status is complete and legal for one phase.
    #[must_use]
    pub fn is_legal_for_phase(&self, phase: SandboxPhase) -> bool {
        use SandboxPhase as P;

        let core_complete = self.capability_generation.is_some()
            && self.realized_root.is_some()
            && self.environment_generation.is_some()
            && self.attachments.is_some()
            && self.cache.is_some()
            && self.disclosure.is_some()
            && self.logical_usage.is_some()
            && self.audit_event_cursor.is_some();
        let no_active_executions = self.active_executions.as_slice().is_empty();
        let authority_legal = match phase {
            P::SANDBOX_PHASE_REQUESTED
            | P::SANDBOX_PHASE_STOPPED
            | P::SANDBOX_PHASE_HIBERNATED
            | P::SANDBOX_PHASE_DELETING
            | P::SANDBOX_PHASE_DELETED => matches!(
                (self.ownership, self.guardian),
                (
                    OwnershipEvidenceV1::Unassigned,
                    GuardianEvidenceV1::Disarmed
                )
            ),
            P::SANDBOX_PHASE_STARTING
            | P::SANDBOX_PHASE_READY
            | P::SANDBOX_PHASE_FREEZING
            | P::SANDBOX_PHASE_FROZEN
            | P::SANDBOX_PHASE_STOPPING => matches!(
                (self.ownership, self.guardian),
                (OwnershipEvidenceV1::Owned(_), GuardianEvidenceV1::Armed(_))
            ),
            P::SANDBOX_PHASE_LOST => matches!(
                (self.ownership, self.guardian),
                (
                    OwnershipEvidenceV1::Expired(_),
                    GuardianEvidenceV1::Contained(_)
                )
            ),
            P::SANDBOX_PHASE_PREPARING | P::SANDBOX_PHASE_ERROR => true,
            P::SANDBOX_PHASE_UNSPECIFIED => false,
        };
        if !authority_legal {
            return false;
        }

        match phase {
            P::SANDBOX_PHASE_REQUESTED => no_active_executions,
            P::SANDBOX_PHASE_PREPARING | P::SANDBOX_PHASE_ERROR => true,
            P::SANDBOX_PHASE_STARTING
            | P::SANDBOX_PHASE_READY
            | P::SANDBOX_PHASE_FREEZING
            | P::SANDBOX_PHASE_FROZEN
            | P::SANDBOX_PHASE_STOPPING
            | P::SANDBOX_PHASE_LOST => core_complete,
            P::SANDBOX_PHASE_STOPPED | P::SANDBOX_PHASE_HIBERNATED => {
                core_complete && no_active_executions
            }
            P::SANDBOX_PHASE_DELETING => no_active_executions && self.audit_event_cursor.is_some(),
            P::SANDBOX_PHASE_DELETED => {
                no_active_executions
                    && self.capability_generation.is_none()
                    && self.realized_root.is_none()
                    && self.environment_generation.is_none()
                    && self.attachments.is_none()
                    && self.pinned_references.is_empty()
                    && self.cache.is_none()
                    && self.logical_usage.is_none()
                    && self.disclosure.is_some()
                    && self.audit_event_cursor.is_some()
            }
            P::SANDBOX_PHASE_UNSPECIFIED => false,
        }
    }
}

fn authority_evidence_is_internally_consistent(
    ownership: OwnershipEvidenceV1,
    guardian: GuardianEvidenceV1,
) -> bool {
    match (ownership, guardian) {
        (OwnershipEvidenceV1::Unassigned, GuardianEvidenceV1::Disarmed) => true,
        (OwnershipEvidenceV1::AwaitingOwnership(placement), GuardianEvidenceV1::Arming(status)) => {
            status.placement() == &placement
        }
        (OwnershipEvidenceV1::Owned(lease), GuardianEvidenceV1::Armed(status))
        | (OwnershipEvidenceV1::Expired(lease), GuardianEvidenceV1::Contained(status)) => {
            status.placement() == lease.placement()
                && status.lease_generation() == lease.lease_generation()
        }
        _ => false,
    }
}

fn transaction_matches_ownership(
    transaction: OwnershipTransactionStateV1,
    ownership: OwnershipEvidenceV1,
) -> bool {
    matches!(
        (transaction, ownership),
        (
            OwnershipTransactionStateV1::Absent | OwnershipTransactionStateV1::RolledBack,
            OwnershipEvidenceV1::Unassigned
        ) | (
            OwnershipTransactionStateV1::Absent | OwnershipTransactionStateV1::Prepared,
            OwnershipEvidenceV1::AwaitingOwnership(_)
        ) | (
            OwnershipTransactionStateV1::Committed,
            OwnershipEvidenceV1::Owned(_)
        ) | (
            OwnershipTransactionStateV1::Committed | OwnershipTransactionStateV1::RolledBack,
            OwnershipEvidenceV1::Expired(_)
        )
    )
}

fn authority_evidence_matches_placement(
    ownership: OwnershipEvidenceV1,
    guardian: GuardianEvidenceV1,
    placement: Option<&CheckedPlacementV1>,
) -> bool {
    if !authority_evidence_is_internally_consistent(ownership, guardian) {
        return false;
    }
    match ownership {
        OwnershipEvidenceV1::Unassigned => placement.is_none(),
        OwnershipEvidenceV1::AwaitingOwnership(evidence) => placement == Some(&evidence),
        OwnershipEvidenceV1::Owned(lease) | OwnershipEvidenceV1::Expired(lease) => {
            placement == Some(lease.placement())
        }
    }
}

impl std::fmt::Debug for AdditiveControllerObservationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdditiveControllerObservationV1")
            .field("ownership", &self.ownership)
            .field("guardian", &self.guardian)
            .field("capability_generation", &self.capability_generation)
            .field("status", &"<redacted>")
            .finish_non_exhaustive()
    }
}
