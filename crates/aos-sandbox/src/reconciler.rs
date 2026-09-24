//! Single-node desired-state reconciliation and durable effect ledger.
//!
//! Admission stores the desired value, operation, idempotency decision, and
//! ordered effect plans in one journal transaction. Reconciliation writes an
//! `Applying` intent before invoking an effect executor. After restart, an
//! ambiguous `Applying` effect is observed by its stable operation/step key;
//! an absent effect is retried with the exact request bytes, while an applied
//! effect is completed from its durable executor receipt. This requires every
//! executor implementation to make one effect key idempotent. Ownership-gated
//! effects additionally retain the exact selected publication and broker
//! packet before `Applying` becomes externally visible.
//!
//! Runtime-holder admission additionally commits an exact intent digest in the
//! operation record. Activation commits its binding and current head in the
//! same transaction as the ownership publication and gate release. The durable
//! operation formats are closed schemas:
//!
//! ```text
//! V1 = version:u8 || state:u8 || flags:u8 || reserved:u8
//!      || effect_count:u32le || runtime_intent_digest_or_zero:32bytes
//! V2 = V1-header-with-version-2-and-public-flag || public_metadata:64bytes
//! ```
//!
//! The zero digest slot denotes an operation without a holder intent. Runtime
//! authority records require and cross-check the exact nonzero digest. V1
//! remains the canonical encoding for internal operations; V2 adds immutable
//! public identity and restart-stable observation metadata.

use aos_sandbox_core::model::{KeyReference, KeyUsage, StableKeyId};
use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use aos_sandbox_ownership_protocol::{CLAIM_BYTES, OwnershipClaimV1};

use crate::{GuardianPlanRequestV1, SignedBrokerPlan};

use crate::journal::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalRecord, JournalTransaction,
    RecordNamespace,
};
use crate::publication::{
    AuthorityPublicationActivationPartsV1, AuthorityPublicationActivationV1,
    AuthorityPublicationDraftV1, AuthorityPublicationStore, validate_durable_effect_attempt,
    validate_durable_gate_publication, validate_publication_namespace,
};

mod effect;
mod observe_reservation;
mod public_operation;
mod runtime_authority;

use crate::runtime_authority::{
    RuntimeAuthorityIntentV1, RuntimeAuthorityLimits, RuntimeAuthorityStateV1,
    RuntimeAuthorityStore,
};
pub(crate) use runtime_authority::{
    runtime_authority_claim, validate_runtime_authority_binding,
    validate_runtime_authority_operations, validate_runtime_authority_pending,
};

pub use effect::{
    AuthorityBoundEffectPlanV1, AuthorityEffectAttemptTimingV1, AuthorityEffectObservationV1,
    EffectDomain, EffectPlan, PreparedAuthorityBrokerRequestV1, PreparedAuthorityEffectV1,
    PublicMutationEffectV1, ValidatedAuthorityEffectReceiptV1, ValidatedHostEffectReceiptV1,
};
use effect::{
    EffectLedgerRecord, EffectState, MAXIMUM_DIAGNOSTIC_BYTES, decode_effect, encode_effect,
};
use public_operation::{DurablePublicOperationV1, PUBLIC_OPERATION_RECORD_BYTES};
pub use public_operation::{PublicOperationAdmissionV1, PublicOperationAuthorizationV1};

const RECORD_VERSION_V1: u8 = 1;
const RECORD_VERSION_V2: u8 = 2;
const OPERATION_FLAG_OWNERSHIP_GATED: u8 = 1;
const OPERATION_FLAG_PUBLIC: u8 = 2;
const OPERATION_RUNTIME_INTENT_DIGEST_BYTES: usize = 32;
const OPERATION_RECORD_V1_BYTES: usize = 8 + OPERATION_RUNTIME_INTENT_DIGEST_BYTES;
const OPERATION_RECORD_V2_BYTES: usize = OPERATION_RECORD_V1_BYTES + PUBLIC_OPERATION_RECORD_BYTES;
const OPERATION_KEY_BYTES: usize = 16;
const EFFECT_KEY_BYTES: usize = 20;
// The default journal transaction bound is 4096 records. Admission also
// carries desired-state, operation, and idempotency records atomically.
const MAXIMUM_EFFECTS: usize = 4093;
const MAXIMUM_GATED_EFFECTS: usize = 4092;
const MAXIMUM_RECEIPT_BYTES: usize = 64 * 1024;
const MAXIMUM_OWNERSHIP_DRAFT_BYTES: usize = 15 * 1024 * 1024;
const OWNERSHIP_GATE_MAGIC: &[u8; 8] = b"AOSOGT01";
const OWNERSHIP_GATE_VERSION: u16 = 1;

/// Defines one atomically admitted desired mutation and its ordered effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPlan {
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    request_digest: [u8; 32],
    desired_key: Vec<u8>,
    desired_value: Vec<u8>,
    effects: Vec<EffectPlan>,
    ownership_gate: Option<OwnershipGatePlanV1>,
    runtime_authority: Option<RuntimeAuthorityIntentV1>,
    public_operation: Option<PublicOperationAdmissionV1>,
    local_records: Vec<JournalRecord>,
}

impl OperationPlan {
    /// Constructs a complete operation admission plan.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for an all-zero operation ID,
    /// empty desired key/value, no effects, or more than 4093 effects.
    pub fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        effects: Vec<EffectPlan>,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || effects.is_empty()
            || effects.len() > MAXIMUM_EFFECTS
            || effects.iter().any(|effect| effect.authority().is_some())
        {
            return Err(ReconcilerError::InvalidPlan("invalid operation plan"));
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects,
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            local_records: Vec::new(),
        })
    }

    /// Constructs an atomically completed controller-local mutation.
    ///
    /// This path is intentionally crate-private. It exists for state owned by
    /// the controller journal itself, such as publisher capability authority,
    /// and cannot be used to represent a privileged or externally observed
    /// effect. The supplied records commit in the same transaction as desired
    /// state, idempotency, and public operation metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the operation identity,
    /// desired state, authority records, or atomic transaction bounds are
    /// invalid.
    pub(crate) fn completed_local(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        local_records: Vec<JournalRecord>,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || local_records.is_empty()
            || local_records.len() > MAXIMUM_EFFECTS
            || local_records.iter().any(|record| {
                (record.namespace() != RecordNamespace::PublisherAuthority
                    && !crate::controller_service::public_projection::is_public_projection_deletion_record_v1(record))
                    || record.key().is_empty()
                    || (record.namespace() == RecordNamespace::PublisherAuthority
                        && record.value().is_none())
                    || (record.namespace() == RecordNamespace::DesiredState
                        && record.key() == desired_key)
            })
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid completed local operation plan",
            ));
        }
        for (index, record) in local_records.iter().enumerate() {
            if local_records[..index]
                .iter()
                .any(|prior| prior.namespace() == record.namespace() && prior.key() == record.key())
            {
                return Err(ReconcilerError::InvalidPlan(
                    "completed local operation contains duplicate records",
                ));
            }
        }

        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects: Vec::new(),
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            local_records,
        })
    }

    /// Constructs an atomically completed public attach without an agent effect.
    ///
    /// # Errors
    ///
    /// Rejects invalid desired state or an endpoint record for another operation.
    pub(crate) fn completed_public_attach(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        route_record: JournalRecord,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || route_record.namespace() != RecordNamespace::PublicAttachRoute
            || route_record.key() != operation_id.as_bytes()
            || route_record.value().is_none()
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid completed public attach plan",
            ));
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects: Vec::new(),
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            local_records: vec![route_record],
        })
    }

    /// Constructs a completed acknowledgment of an already blocked operation.
    ///
    /// The caller must have checked the protected target's terminal phase and
    /// public resource-version fence. This plan atomically retains only the
    /// acknowledgment; it neither changes the target nor dispatches cleanup.
    ///
    /// # Errors
    ///
    /// Rejects mismatched operation identities or a malformed protected
    /// acknowledgment record.
    pub(crate) fn completed_operator_abandon(
        operation_id: OperationId,
        target: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        acknowledgment: JournalRecord,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || target.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || !crate::operator_abandon_ack::validates_record_v1(
                &acknowledgment,
                operation_id,
                target,
                idempotency_key.as_bytes(),
                request_digest,
            )
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid completed operator abandonment",
            ));
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects: Vec::new(),
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            local_records: vec![acknowledgment],
        })
    }

    /// Adds protected controller-local records to a still-active operation.
    ///
    /// These records are committed atomically with the operation and its
    /// effects, but do not make the operation complete. This is intentionally
    /// restricted to operator-recovery state: recovery admission must retain
    /// its checked current head before its effect becomes eligible.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the plan has no effect,
    /// a record is outside the operator-recovery namespace, records collide,
    /// or the atomic transaction bound would be exceeded.
    pub(crate) fn with_operator_recovery_records(
        mut self,
        local_records: Vec<JournalRecord>,
    ) -> Result<Self, ReconcilerError> {
        let atomic_records = self.effects.len().checked_add(local_records.len()).ok_or(
            ReconcilerError::InvalidPlan("operator-recovery records exceed admission bounds"),
        )?;
        if self.effects.is_empty()
            || !self.local_records.is_empty()
            || local_records.is_empty()
            || atomic_records > MAXIMUM_EFFECTS
            || local_records.iter().any(|record| {
                record.namespace() != RecordNamespace::OperatorRecovery
                    || record.key().is_empty()
                    || record.value().is_none()
            })
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid operator-recovery admission records",
            ));
        }
        for (index, record) in local_records.iter().enumerate() {
            if local_records[..index]
                .iter()
                .any(|prior| prior.key() == record.key())
            {
                return Err(ReconcilerError::InvalidPlan(
                    "operator-recovery admission contains duplicate records",
                ));
            }
        }

        self.local_records = local_records;
        Ok(self)
    }

    /// Constructs an operation held behind an atomically admitted ownership gate.
    ///
    /// The claim and validated publication draft remain non-authorizing durable
    /// inputs. Only [`crate::NodeController::resume_ownership`] may supply
    /// verified activation facts through the crate-private opaque bridge. The
    /// draft determines the expected authority; callers cannot provide that
    /// security-sensitive reference separately.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for the ordinary operation
    /// invariants, more than 4092 effects, an effect not derived from the exact
    /// publication draft, or an invalid or mismatched gate.
    #[allow(clippy::too_many_arguments)]
    pub fn ownership_gated(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        effects: Vec<AuthorityBoundEffectPlanV1>,
        claim: OwnershipClaimV1,
        publication_draft: AuthorityPublicationDraftV1,
    ) -> Result<Self, ReconcilerError> {
        if effects.len() > MAXIMUM_GATED_EFFECTS {
            return Err(ReconcilerError::InvalidPlan(
                "ownership-gated operation has too many effects",
            ));
        }
        if effects.iter().any(|effect| {
            !effect.is_supported_authority_apply()
                || effect.source_draft_digest() != publication_draft.digest()
        }) {
            return Err(ReconcilerError::InvalidPlan(
                "ownership-gated effects must be descriptor-free broker Apply templates",
            ));
        }
        let effects: Vec<EffectPlan> = effects
            .into_iter()
            .enumerate()
            .map(|(step, effect)| {
                effect.into_inner(operation_id, u32::try_from(step).unwrap_or(u32::MAX))
            })
            .collect::<Result<_, _>>()?;
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || effects.is_empty()
            || effects.iter().any(|effect| {
                effect
                    .authority()
                    .is_none_or(|binding| binding.source_draft_digest != publication_draft.digest())
            })
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid ownership-gated operation plan",
            ));
        }
        let mut plan = Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects,
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            local_records: Vec::new(),
        };
        plan.ownership_gate = Some(OwnershipGatePlanV1::new(
            operation_id,
            plan.idempotency_key.clone(),
            request_digest,
            claim,
            publication_draft,
        )?);
        Ok(plan)
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Binds a holder intent to this ownership-gated operation's atomic admission.
    ///
    /// The compiler must authenticate and authorize the holder before constructing
    /// the intent. This method does not establish live runtime authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an ungated plan, an admission that exceeds the
    /// journal transaction bound, or revocation not bound to exactly one
    /// canonical Host Stop effect for this assignment.
    pub fn with_runtime_authority(
        mut self,
        intent: RuntimeAuthorityIntentV1,
    ) -> Result<Self, ReconcilerError> {
        let maximum_effects =
            MAXIMUM_GATED_EFFECTS - 1 - usize::from(self.public_operation.is_some());
        if self.ownership_gate.is_none() || self.effects.len() > maximum_effects {
            return Err(ReconcilerError::InvalidPlan(
                "runtime authority intent requires a bounded ownership-gated Host Apply plan",
            ));
        }
        let gate = self
            .ownership_gate
            .as_ref()
            .ok_or(ReconcilerError::InvalidPlan(
                "runtime intent requires an ownership gate",
            ))?;
        runtime_authority::validate_intent_effects(
            intent.state(),
            self.operation_id,
            gate.publication_draft(),
            &self.effects,
        )?;
        self.runtime_authority = Some(intent);
        Ok(self)
    }

    /// Adds immutable public observation metadata to this admission.
    ///
    /// Direct desired-state plans begin at their semantic commit boundary.
    /// A single controller-orchestration effect may instead advertise
    /// cancellation while it remains accepted and has not begun execution.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when metadata was already
    /// attached or its extra atomic record would exceed admission bounds.
    pub fn with_public_operation(
        mut self,
        public_operation: PublicOperationAdmissionV1,
    ) -> Result<Self, ReconcilerError> {
        let maximum_effects = if self.ownership_gate.is_some() {
            MAXIMUM_GATED_EFFECTS - 1 - usize::from(self.runtime_authority.is_some())
        } else {
            MAXIMUM_EFFECTS - 1
        };
        let atomic_records = self
            .effects
            .len()
            .checked_add(self.local_records.len())
            .ok_or(ReconcilerError::InvalidPlan(
                "public operation metadata exceeds admission bounds",
            ))?;
        if self.public_operation.is_some() || atomic_records > maximum_effects {
            return Err(ReconcilerError::InvalidPlan(
                "public operation metadata is duplicate or exceeds admission bounds",
            ));
        }
        self.public_operation = Some(public_operation);
        Ok(self)
    }

    /// Returns the digest of the normalized request admitted by this plan.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}

/// Carries the bounded non-authorizing inputs durably held before ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipGatePlanV1 {
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    request_digest: [u8; 32],
    claim: OwnershipClaimV1,
    publication_draft: AuthorityPublicationDraftV1,
}

impl OwnershipGatePlanV1 {
    fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        claim: OwnershipClaimV1,
        publication_draft: AuthorityPublicationDraftV1,
    ) -> Result<Self, ReconcilerError> {
        let expected_authority = publication_draft.ownership_authority();
        if operation_id.as_bytes() == &[0; 16]
            || request_digest == [0; 32]
            || expected_authority.generation() == 0
            || expected_authority.public_key_sha256().as_bytes() == &[0; 32]
            || expected_authority.usage() != KeyUsage::OwnershipLease
            || publication_draft.canonical_bytes().len() > MAXIMUM_OWNERSHIP_DRAFT_BYTES
        {
            return Err(ReconcilerError::InvalidPlan("invalid ownership gate plan"));
        }
        validate_claim_draft_context(&claim, &publication_draft)?;
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            claim,
            publication_draft,
        })
    }

    /// Returns the operation whose effects remain gated.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the original normalized request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Returns the exact original idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the exact pinned ownership-authority key reference.
    #[must_use]
    pub const fn expected_authority(&self) -> &KeyReference {
        self.publication_draft.ownership_authority()
    }

    /// Returns the exact canonical ownership claim.
    #[must_use]
    pub const fn claim(&self) -> &OwnershipClaimV1 {
        &self.claim
    }

    /// Returns the validated typed authority-publication draft.
    #[must_use]
    pub const fn publication_draft(&self) -> &AuthorityPublicationDraftV1 {
        &self.publication_draft
    }

    /// Returns the domain-separated digest of the exact draft bytes.
    #[must_use]
    pub const fn publication_draft_digest(&self) -> ObjectDigest {
        self.publication_draft.digest()
    }
}

/// Reports the durable state of an operation's ownership gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnershipGateStatusV1 {
    /// The operation remains unavailable to ordinary reconciliation.
    Pending(OwnershipGatePlanV1),
    /// Exact authority was published and the operation gate was released.
    Activated {
        /// The immutable admitted gate inputs.
        plan: OwnershipGatePlanV1,
        /// The exact activated authority-publication digest.
        publication_digest: ObjectDigest,
        /// The activated ownership-lease generation.
        lease_generation: u64,
        /// The exact activated ownership-lease digest.
        lease_digest: ObjectDigest,
    },
}

/// Reports the result of operation admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptOutcome {
    /// This plan was atomically committed as a new operation.
    Accepted(OperationId),
    /// The exact request was already admitted as this operation.
    Replay(OperationId),
}

/// Carries bounded executor evidence for one applied effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectReceipt(Vec<u8>);

const CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC: &[u8; 8] = b"AOSCXL01";
const CANCELED_BEFORE_COMMIT_RECEIPT_BYTES: usize = 40;

impl EffectReceipt {
    /// Constructs a bounded, nonempty executor receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] for an empty receipt
    /// or one exceeding 64 KiB.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ReconcilerError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid effect receipt length",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact executor receipt bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constructs controller evidence that an operation was canceled before
    /// its semantic commit point.
    #[must_use]
    pub fn canceled_before_commit(evidence: ObjectDigest) -> Self {
        let mut bytes = Vec::with_capacity(CANCELED_BEFORE_COMMIT_RECEIPT_BYTES);
        bytes.extend_from_slice(CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC);
        bytes.extend_from_slice(evidence.as_bytes());
        Self(bytes)
    }

    fn canceled_before_commit_evidence(&self) -> Result<Option<ObjectDigest>, ()> {
        if !self.0.starts_with(CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC) {
            return Ok(None);
        }
        if self.0.len() != CANCELED_BEFORE_COMMIT_RECEIPT_BYTES {
            return Err(());
        }

        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&self.0[CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC.len()..]);
        if digest == [0; 32] {
            return Err(());
        }
        Ok(Some(ObjectDigest::from_bytes(digest)))
    }
}

/// Reports the executor's observation of an ambiguous in-flight effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectObservation {
    /// No effect with this stable key is externally visible.
    Absent,
    /// The effect is externally complete with this verified receipt.
    Applied(EffectReceipt),
}

/// Classifies an effect failure without exposing an executor error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectFailure {
    /// The same exact effect may be retried later.
    Retryable(String),
    /// Reconciliation cannot proceed without a new desired mutation or repair.
    Permanent(String),
}

impl EffectFailure {
    fn diagnostic(&self) -> &str {
        match self {
            Self::Retryable(value) | Self::Permanent(value) => value,
        }
    }

    fn validate(&self) -> Result<(), ReconcilerError> {
        if self.diagnostic().is_empty() || self.diagnostic().len() > MAXIMUM_DIAGNOSTIC_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid effect failure diagnostic length",
            ));
        }
        Ok(())
    }
}

/// Executes idempotent single-node effects through fixed local boundaries.
pub trait SingleNodeEffectExecutor {
    /// Supplies advisory timing for one authority-bound attempt preparation.
    ///
    /// Returning `None` explicitly leaves authority-bound execution disabled.
    /// This hook must not perform external effects; the resulting attempt has
    /// not yet been made durable.
    fn authority_effect_timing(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
    ) -> Option<AuthorityEffectAttemptTimingV1> {
        None
    }

    /// Signs the exact post-lease Guardian arm plan requested for a Host launch.
    ///
    /// The request already commits the selected current lease and host boot.
    /// Returning `None` leaves Guardian-gated Host launches disabled. This hook
    /// must not start Guardian or payload units; the resulting plan is inserted
    /// into an exact packet and made durable first.
    fn prepare_guardian_plan(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _request: &GuardianPlanRequestV1,
    ) -> Option<SignedBrokerPlan> {
        None
    }

    /// Observes whether one stable effect key is already applied.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure when observation is temporarily unavailable
    /// or a permanent failure when the stable effect identity is contradictory.
    fn observe(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure>;

    /// Applies one exact idempotent effect request.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure for transient boundary errors or a
    /// permanent failure for a rejected or contradictory fixed request.
    fn apply(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure>;

    /// Observes one controller-orchestration effect with journal custody.
    ///
    /// The default preserves ordinary executor behavior. Production
    /// orchestration may override this hook to reconcile controller-owned
    /// projections and separately protected source-domain state. It must not
    /// change this operation's operation or effect-ledger records.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure while exact orchestration remains pending,
    /// or a permanent failure for contradictory protected state.
    fn observe_controller(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        _journal: &mut Journal,
    ) -> Result<EffectObservation, EffectFailure> {
        self.observe(operation_id, step, plan)
    }

    /// Applies one controller-orchestration effect with journal custody.
    ///
    /// The default preserves ordinary executor behavior. An override may
    /// commit method-specific controller records, but completion evidence must
    /// still cover every external effect and authenticated readback required
    /// by the public mutation.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure for recoverable pending work, or a permanent
    /// failure when protected state rejects the exact admitted request.
    fn apply_controller(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        _journal: &mut Journal,
    ) -> Result<EffectReceipt, EffectFailure> {
        self.apply(operation_id, step, plan)
    }

    /// Observes one exact durably recorded authority-bound broker attempt.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure when authenticated observation is
    /// temporarily unavailable or a permanent failure for contradictory
    /// durable broker state.
    fn observe_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _prepared: &PreparedAuthorityEffectV1,
    ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
        Err(EffectFailure::Permanent(
            "authority-bound effect execution is unsupported".to_owned(),
        ))
    }

    /// Applies one exact durably recorded authority-bound broker attempt.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure for transient transport or broker errors,
    /// or a permanent failure when the exact request is rejected.
    fn apply_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _prepared: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        Err(EffectFailure::Permanent(
            "authority-bound effect execution is unsupported".to_owned(),
        ))
    }
}

/// Reports one bounded reconciliation pass outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    /// Ownership is pending and no effect was made eligible or invoked.
    OwnershipPending,
    /// Durable state advanced without invoking an external effect.
    Progressed,
    /// An effect was applied or recovered and its receipt became durable.
    EffectApplied,
    /// A transient executor failure left the durable effect intent in flight.
    RetryPending,
    /// Every planned effect and the terminal operation success are durable.
    Succeeded,
    /// Protected orchestration canceled the operation before semantic commit.
    CanceledBeforeCommit,
    /// A permanent executor failure durably blocked the operation.
    PermanentlyBlocked,
}

/// Identifies a durable operation state that still requires mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnfinishedOperationStateV1 {
    /// The operation is admitted but has not issued its first effect.
    Accepted,
    /// At least one exact effect intent is durably in flight.
    Applying,
    /// The operation is waiting for separately authorized ownership activation.
    OwnershipPending,
}

/// Identifies one validated durable operation that is not terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedUnfinishedOperationV1 {
    operation_id: OperationId,
    state: UnfinishedOperationStateV1,
}

impl ValidatedUnfinishedOperationV1 {
    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the validated nonterminal state.
    #[must_use]
    pub const fn state(self) -> UnfinishedOperationStateV1 {
        self.state
    }
}

/// Reports admission, ledger, journal, or executor-contract failures.
#[derive(Debug, thiserror::Error)]
pub enum ReconcilerError {
    /// Protected portable sandbox-specification history could not be validated.
    #[error("sandbox-specification state failed: {0}")]
    SandboxSpec(#[source] Box<crate::SandboxSpecStateError>),
    /// Protected destination-slot history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment-slot state failed: {0}")]
    AttachmentSlot(#[source] Box<crate::AttachmentSlotStateError>),
    /// Protected filesystem-view revision history could not be validated.
    #[error("filesystem-view revision state failed: {0}")]
    FilesystemViewRevision(#[source] Box<crate::FilesystemViewRevisionStateError>),
    /// Protected attachment desired-state history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment desired state failed: {0}")]
    AttachmentDesired(#[source] Box<crate::AttachmentDesiredStateError>),
    /// Protected attachment verification history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment verification failed: {0}")]
    AttachmentVerification(#[source] Box<crate::AttachmentVerificationError>),
    /// Protected attachment-source custody history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment source custody failed: {0}")]
    AttachmentSource(#[source] Box<crate::AttachmentSourceError>),
    /// Protected Mount-attempt history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("mount attempt failed: {0}")]
    MountAttempt(#[source] Box<crate::mount_attempt::MountAttemptError>),
    /// Protected Mount source-acquisition inventory could not be validated.
    #[cfg(target_os = "linux")]
    #[error("Mount source-acquisition inventory failed: {0}")]
    MountSourceAcquisitionInventory(#[source] Box<crate::MountSourceAcquisitionInventoryError>),
    /// Protected destination-slot inventory could not be validated.
    #[cfg(target_os = "linux")]
    #[error("destination-slot inventory failed: {0}")]
    DestinationSlotInventory(#[source] Box<crate::mount_attempt::MountAttemptError>),
    /// Protected Storage or Network resource inventory could not be validated.
    #[cfg(target_os = "linux")]
    #[error("broker resource inventory failed: {0}")]
    ResourceInventory(#[source] Box<crate::ResourceInventoryError>),
    /// Durable Host catalog projection or publication state could not be validated.
    #[cfg(target_os = "linux")]
    #[error("Host catalog reconciliation failed: {0}")]
    HostCatalogReconciliation(#[source] Box<crate::HostCatalogReconciliationError>),
    /// Protected destination-slot effect history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("destination-slot effect failed: {0}")]
    DestinationSlotEffect(#[source] Box<crate::DestinationSlotEffectError>),
    /// Protected namespace-target allocation history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("namespace target failed: {0}")]
    NamespaceTarget(#[source] Box<crate::runtime_scope::NamespaceTargetError>),
    /// Protected runtime-generation history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("runtime generation failed: {0}")]
    RuntimeGeneration(#[source] Box<crate::runtime_scope::RuntimeGenerationError>),
    /// Protected runtime-authority validation or mutation preparation failed.
    #[error("runtime authority failed: {0}")]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    /// Durable journal operation failed.
    #[error("sandbox journal failed: {0}")]
    Journal(#[from] JournalError),
    /// An operation plan violates local bounds or required fields.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// A client reused an idempotency key for different semantic bytes.
    #[error("idempotency key is already bound to another request")]
    IdempotencyConflict,
    /// The requested operation does not exist in the durable ledger.
    #[error("operation is absent from the durable ledger")]
    OperationNotFound,
    /// A fresh idempotency key attempted to reuse a durable operation ID.
    #[error("operation identity already exists in the durable ledger")]
    OperationAlreadyExists,
    /// The configured durable nonterminal-operation capacity is exhausted.
    #[error("controller admission is backpressured by pending durable work")]
    AdmissionBackpressure,
    /// The requested operation has no ownership gate.
    #[error("operation has no durable ownership gate")]
    OwnershipGateNotFound,
    /// A released ownership gate was replayed with different activation facts.
    #[error("ownership gate activation conflicts with its durable result")]
    OwnershipActivationConflict,
    /// A new activation would replace current authority with older state.
    #[error("ownership publication is not a valid current successor")]
    OwnershipPublicationNotSuccessor,
    /// Durable operation or effect bytes violate the closed versioned schema.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
    /// An executor returned unbounded or empty evidence.
    #[error("effect executor violated its output contract: {0}")]
    InvalidExecutorOutput(&'static str),
    /// A public operation transition lacks a valid monotone wall-clock sample.
    #[error("public operation clock observation is missing or invalid")]
    PublicOperationClock,
    /// A public operation exhausted its monotone observation sequence.
    #[error("public operation observation sequence is exhausted")]
    PublicOperationSequenceExhausted,
    /// Current publication selection or attempt attenuation failed.
    #[error("authority-bound effect preparation failed: {0}")]
    AuthorityPublication(#[from] crate::AuthorityPublicationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum OperationState {
    Accepted = 1,
    Applying = 2,
    Succeeded = 3,
    PermanentlyBlocked = 4,
    OwnershipPending = 5,
    CanceledBeforeCommit = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationRecord {
    state: OperationState,
    effect_count: u32,
    ownership_gated: bool,
    runtime_intent_digest: Option<ObjectDigest>,
    public_operation: Option<DurablePublicOperationV1>,
}

impl OperationState {
    fn from_byte(value: u8) -> Result<Self, ReconcilerError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Applying),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::PermanentlyBlocked),
            5 => Ok(Self::OwnershipPending),
            6 => Ok(Self::CanceledBeforeCommit),
            _ => Err(ReconcilerError::CorruptLedger("unknown operation state")),
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::PermanentlyBlocked | Self::CanceledBeforeCommit
        )
    }
}

/// Reports whether exact ownership-gate activation committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipGateActivationOutcome {
    /// Publication records and gate release committed atomically.
    Activated,
    /// The exact activation facts were already durable.
    Replay,
}

/// Reconciles one exclusively owned single-node journal.
///
/// A poisoned journal rejects admission, gate resolution, and reconciliation
/// before replay or executor interaction, even if structural validation was
/// previously cached. Recovery requires reopening the journal.
pub struct Reconciler<E> {
    journal: Journal,
    executor: E,
    scheduling_cursor: Option<OperationId>,
    ledger_validated: bool,
}

impl<E> Reconciler<E>
where
    E: SingleNodeEffectExecutor,
{
    /// Constructs a reconciler over an exclusively opened journal.
    #[must_use]
    pub const fn new(journal: Journal, executor: E) -> Self {
        Self {
            journal,
            executor,
            scheduling_cursor: None,
            ledger_validated: false,
        }
    }

    /// Borrows the sole journal writer for a short composed controller action.
    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        self.ledger_validated = false;
        &mut self.journal
    }

    /// Loads and validates an operation's durable ownership gate, when present.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the operation is absent or the gate,
    /// operation state, or original idempotency decision is inconsistent.
    pub fn ownership_gate(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let operation = self.load_operation(operation_id)?;
        self.load_and_validate_ownership_gate(operation_id, operation)
    }

    /// Atomically releases one pending gate with a validated publication bridge.
    ///
    /// The opaque bridge owns exactly the prepared/current publication records
    /// and their structural summary facts. This composition point performs no
    /// ownership service call and grants no authority by itself.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] for an absent or corrupt gate, mismatched
    /// publication context, conflicting replay, stale publication, duplicate
    /// records, or durability failure.
    pub(crate) fn activate_ownership_gate(
        &mut self,
        operation_id: OperationId,
        activation: AuthorityPublicationActivationV1,
    ) -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        self.activate_ownership_gate_inner(operation_id, activation, None)
    }

    pub(crate) fn activate_ownership_gate_at(
        &mut self,
        operation_id: OperationId,
        activation: AuthorityPublicationActivationV1,
        wall_seconds: i64,
    ) -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        self.activate_ownership_gate_inner(operation_id, activation, Some(wall_seconds))
    }

    fn activate_ownership_gate_inner(
        &mut self,
        operation_id: OperationId,
        activation: AuthorityPublicationActivationV1,
        wall_seconds: Option<i64>,
    ) -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let AuthorityPublicationActivationPartsV1 {
            records: publication_records,
            sandbox,
            assignment_digest,
            source_draft_digest,
            ownership_authority,
            publication_digest,
            lease_generation,
            lease_digest,
            receipt_action,
            receipt_request_id,
            receipt_claim_digest,
            prepared,
        } = activation.into_parts();
        let operation = self.load_operation(operation_id)?;
        let gate = self
            .load_and_validate_ownership_gate(operation_id, operation)?
            .ok_or(ReconcilerError::OwnershipGateNotFound)?;
        let durable_plan = match &gate {
            OwnershipGateStatusV1::Pending(plan)
            | OwnershipGateStatusV1::Activated { plan, .. } => plan,
        };
        let claim_assignment = durable_plan.claim.assignment();
        if sandbox != claim_assignment.sandbox()
            || assignment_digest != claim_assignment.digest()
            || source_draft_digest != durable_plan.publication_draft_digest()
            || &ownership_authority != durable_plan.expected_authority()
            || receipt_action != durable_plan.claim.action()
            || receipt_request_id != *durable_plan.claim.request_id()
            || receipt_claim_digest != durable_plan.claim.digest()
        {
            return Err(ReconcilerError::OwnershipActivationConflict);
        }
        let plan = match gate {
            OwnershipGateStatusV1::Pending(plan) => plan,
            OwnershipGateStatusV1::Activated {
                publication_digest: prior_publication,
                lease_generation: prior_generation,
                lease_digest: prior_lease,
                ..
            } if prior_publication == publication_digest
                && prior_generation == lease_generation
                && prior_lease == lease_digest =>
            {
                return Ok(OwnershipGateActivationOutcome::Replay);
            }
            OwnershipGateStatusV1::Activated { .. } => {
                return Err(ReconcilerError::OwnershipActivationConflict);
            }
        };
        AuthorityPublicationStore::new(&mut self.journal)
            .validate_gate_successor(&prepared)
            .map_err(|_| ReconcilerError::OwnershipPublicationNotSuccessor)?;
        self.validate_gated_effects_for_activation(operation_id, operation.effect_count)?;
        let runtime_records = if operation.runtime_intent_digest.is_some()
            || self
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .next()
                .is_some()
        {
            let store =
                RuntimeAuthorityStore::load(&mut self.journal, RuntimeAuthorityLimits::default())?;
            if operation.runtime_intent_digest.is_none() && store.current(sandbox)?.is_some() {
                return Err(ReconcilerError::InvalidPlan(
                    "a current runtime holder requires an explicit successor intent",
                ));
            }
            store.prepare_activation(
                operation_id,
                plan.request_digest,
                plan.publication_draft(),
                &prepared,
            )?
        } else {
            Vec::new()
        };
        let activated = OwnershipGateStatusV1::Activated {
            plan,
            publication_digest,
            lease_generation,
            lease_digest,
        };
        let mut records = Vec::from(publication_records);
        records.extend(runtime_records);
        let operation = transition_operation(operation, OperationState::Accepted, wall_seconds)?;
        records.push(JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.into_bytes().to_vec(),
            encode_operation_record(operation),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::OwnershipGate,
            operation_id.into_bytes().to_vec(),
            encode_ownership_gate(&activated)?,
        ));
        let transaction = JournalTransaction::new(OperationId::new().into_bytes(), records)?;
        self.journal.commit(&transaction)?;
        Ok(OwnershipGateActivationOutcome::Activated)
    }

    /// Atomically admits desired state, an operation, and its effect ledger.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] for an idempotency conflict, record bound
    /// violation, or journal durability failure.
    pub fn accept(&mut self, plan: &OperationPlan) -> Result<AcceptOutcome, ReconcilerError> {
        self.accept_inner(plan, None)
    }

    /// Atomically admits a plan while bounding nonterminal durable work.
    ///
    /// Exact idempotent replay remains available while the bound is reached.
    /// This method is crate-private because admission policy belongs to the
    /// activated controller service rather than the general ledger API.
    pub(crate) fn accept_bounded(
        &mut self,
        plan: &OperationPlan,
        maximum_pending_operations: usize,
    ) -> Result<AcceptOutcome, ReconcilerError> {
        if maximum_pending_operations == 0 {
            return Err(ReconcilerError::InvalidPlan(
                "pending operation bound is zero",
            ));
        }
        self.accept_inner(plan, Some(maximum_pending_operations))
    }

    fn accept_inner(
        &mut self,
        plan: &OperationPlan,
        maximum_pending_operations: Option<usize>,
    ) -> Result<AcceptOutcome, ReconcilerError> {
        self.ensure_ledger_validated()?;
        match self
            .journal
            .check_idempotency(&plan.idempotency_key, plan.request_digest)
        {
            IdempotencyOutcome::Replay(operation_id) => {
                self.validate_operation_gate_relation(operation_id)?;
                let recorded = self.load_operation(operation_id)?;
                let recorded_authorization = self
                    .journal
                    .get(
                        RecordNamespace::PublicOperationAuthorization,
                        operation_id.as_bytes(),
                    )
                    .map(PublicOperationAuthorizationV1::decode)
                    .transpose()?;
                let planned_public_operation = plan.public_operation.as_ref().map(|public| {
                    if plan.effects.is_empty() {
                        public.durable_completed()
                    } else {
                        public.durable()
                    }
                });
                if recorded.runtime_intent_digest
                    != plan
                        .runtime_authority
                        .as_ref()
                        .map(RuntimeAuthorityIntentV1::digest)
                    || recorded.public_operation != planned_public_operation
                    || recorded_authorization.as_ref()
                        != plan
                            .public_operation
                            .as_ref()
                            .map(PublicOperationAdmissionV1::authorization)
                {
                    return Err(ReconcilerError::IdempotencyConflict);
                }
                let recorded_local_completion = recorded.effect_count == 0
                    && recorded.state == OperationState::Succeeded
                    && !recorded.ownership_gated
                    && recorded.runtime_intent_digest.is_none();
                let planned_local_completion =
                    plan.effects.is_empty() && !plan.local_records.is_empty();
                if recorded_local_completion != planned_local_completion {
                    return Err(ReconcilerError::IdempotencyConflict);
                }
                if recorded_local_completion
                    && self
                        .journal
                        .get(RecordNamespace::DesiredState, &plan.desired_key)
                        != Some(plan.desired_value.as_slice())
                {
                    return Err(ReconcilerError::IdempotencyConflict);
                }
                for local in &plan.local_records {
                    if self.journal.get(local.namespace(), local.key()) != local.value() {
                        return Err(ReconcilerError::IdempotencyConflict);
                    }
                }
                return Ok(AcceptOutcome::Replay(operation_id));
            }
            IdempotencyOutcome::Conflict => return Err(ReconcilerError::IdempotencyConflict),
            IdempotencyOutcome::Vacant => {}
        }
        if self
            .journal
            .get(RecordNamespace::Operation, plan.operation_id.as_bytes())
            .is_some()
        {
            return Err(ReconcilerError::OperationAlreadyExists);
        }
        if observe_reservation::claims_operation(&self.journal, plan.operation_id)? {
            return Err(ReconcilerError::OperationAlreadyExists);
        }
        // A second admission cannot replace another operator's terminal
        // acknowledgment, even if a previously compiled plan is retained.
        if plan.local_records.iter().any(|record| {
            crate::operator_abandon_ack::is_acknowledgment_record_v1(record)
                && self.journal.get(record.namespace(), record.key()).is_some()
        }) {
            return Err(ReconcilerError::IdempotencyConflict);
        }
        if let Some(maximum) = maximum_pending_operations {
            // Corrupt operation state must never be treated as spare capacity.
            if self.pending_operation_count()? >= maximum {
                return Err(ReconcilerError::AdmissionBackpressure);
            }
        }

        let effect_count = u32::try_from(plan.effects.len())
            .map_err(|_| ReconcilerError::InvalidPlan("too many effects"))?;
        let mut records = Vec::with_capacity(
            plan.effects.len()
                + plan.local_records.len()
                + 3
                + usize::from(plan.ownership_gate.is_some())
                + usize::from(plan.public_operation.is_some()),
        );
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            plan.desired_key.clone(),
            plan.desired_value.clone(),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::Operation,
            plan.operation_id.into_bytes().to_vec(),
            encode_operation_record(OperationRecord {
                state: if plan.effects.is_empty() && !plan.local_records.is_empty() {
                    OperationState::Succeeded
                } else if plan.ownership_gate.is_some() {
                    OperationState::OwnershipPending
                } else {
                    OperationState::Accepted
                },
                effect_count,
                ownership_gated: plan.ownership_gate.is_some(),
                runtime_intent_digest: plan
                    .runtime_authority
                    .as_ref()
                    .map(RuntimeAuthorityIntentV1::digest),
                public_operation: plan.public_operation.as_ref().map(|public| {
                    if plan.effects.is_empty() {
                        public.durable_completed()
                    } else {
                        public.durable()
                    }
                }),
            }),
        ));
        records.push(JournalRecord::idempotency(
            &plan.idempotency_key,
            plan.request_digest,
            plan.operation_id,
        ));
        if let Some(public) = &plan.public_operation {
            records.push(JournalRecord::put(
                RecordNamespace::PublicOperationAuthorization,
                plan.operation_id.into_bytes().to_vec(),
                public.authorization().encode()?,
            ));
        }
        if let Some(gate) = &plan.ownership_gate {
            if plan.runtime_authority.is_none()
                && self
                    .journal
                    .records(RecordNamespace::RuntimeAuthority)
                    .next()
                    .is_some()
                && RuntimeAuthorityStore::load(
                    &mut self.journal,
                    RuntimeAuthorityLimits::default(),
                )?
                .current(gate.publication_draft().manifest().manifest().sandbox())?
                .is_some()
            {
                return Err(ReconcilerError::InvalidPlan(
                    "a current runtime holder requires an explicit successor intent",
                ));
            }
            records.push(JournalRecord::put(
                RecordNamespace::OwnershipGate,
                plan.operation_id.into_bytes().to_vec(),
                encode_ownership_gate(&OwnershipGateStatusV1::Pending(gate.clone()))?,
            ));
            if let Some(intent) = &plan.runtime_authority {
                records.extend(
                    RuntimeAuthorityStore::load(
                        &mut self.journal,
                        RuntimeAuthorityLimits::default(),
                    )?
                    .prepare_pending(
                        plan.operation_id,
                        plan.request_digest,
                        gate.publication_draft(),
                        intent,
                    )?,
                );
            }
        }
        records.extend(plan.local_records.iter().cloned());
        for (index, effect) in plan.effects.iter().enumerate() {
            let step = u32::try_from(index)
                .map_err(|_| ReconcilerError::InvalidPlan("too many effects"))?;
            records.push(JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(plan.operation_id, step).to_vec(),
                encode_effect(&EffectLedgerRecord {
                    plan: effect.clone(),
                    state: EffectState::Planned,
                    dispatch: None,
                })?,
            ));
        }
        let transaction = JournalTransaction::new(OperationId::new().into_bytes(), records)?;
        self.journal.commit(&transaction)?;
        Ok(AcceptOutcome::Accepted(plan.operation_id))
    }

    fn pending_operation_count(&self) -> Result<usize, ReconcilerError> {
        let mut pending = 0_usize;
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let _operation_id = decode_operation_key(key)?;
            let operation = decode_operation(value)?;
            if !matches!(
                operation.state,
                OperationState::Succeeded
                    | OperationState::CanceledBeforeCommit
                    | OperationState::PermanentlyBlocked
            ) {
                pending = pending
                    .checked_add(1)
                    .ok_or(ReconcilerError::CorruptLedger(
                        "pending operation count overflow",
                    ))?;
            }
        }
        Ok(pending)
    }

    /// Returns the first validated operation that still requires active work.
    ///
    /// The query performs no journal mutation and never invokes the executor.
    /// It validates the complete recovered ledger, scans the journal-bounded
    /// Operation namespace, and retains at most one result.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when journal health, an operation record, or
    /// any cross-referenced durable ledger namespace fails validation.
    pub fn validated_unfinished_operation(
        &mut self,
    ) -> Result<Option<ValidatedUnfinishedOperationV1>, ReconcilerError> {
        self.ensure_ledger_validated_read_only()?;

        let mut first = None;
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let operation_id = decode_operation_key(key)?;
            let operation = decode_operation(value)?;
            let state = match operation.state {
                OperationState::Accepted => UnfinishedOperationStateV1::Accepted,
                OperationState::Applying => UnfinishedOperationStateV1::Applying,
                OperationState::OwnershipPending => UnfinishedOperationStateV1::OwnershipPending,
                OperationState::Succeeded
                | OperationState::CanceledBeforeCommit
                | OperationState::PermanentlyBlocked => continue,
            };
            first.get_or_insert(ValidatedUnfinishedOperationV1 {
                operation_id,
                state,
            });
        }

        Ok(first)
    }

    /// Loads one restart-stable established public operation resource.
    ///
    /// Internal V1 operations deliberately return `None`; their ledger lacks
    /// the public method, generation, audit identity, and timestamps required
    /// to construct a truthful established resource.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the recovered ledger or any referenced
    /// effect record is corrupt.
    pub fn public_operation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<aos_proto::aos::sandbox::v1::Operation>, ReconcilerError> {
        self.ensure_ledger_validated_read_only()?;
        recovered_public_operation_resource_v1(&self.journal, operation_id)
    }

    /// Loads the immutable current-authorization scope for a public operation.
    ///
    /// V2 observations recovered from before this scope was introduced return
    /// `None` and remain available only through protected diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the ledger or authorization binding is
    /// malformed or refers to a non-public operation.
    pub fn public_operation_authorization(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<PublicOperationAuthorizationV1>, ReconcilerError> {
        self.ensure_ledger_validated_read_only()?;
        self.journal
            .get(
                RecordNamespace::PublicOperationAuthorization,
                operation_id.as_bytes(),
            )
            .map(PublicOperationAuthorizationV1::decode)
            .transpose()
    }

    /// Advances one operation by at most one durable transition or effect.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the operation is absent, ledger bytes
    /// are corrupt, executor output violates bounds, or a journal commit fails.
    pub fn reconcile_once(
        &mut self,
        operation_id: OperationId,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        self.reconcile_once_inner(operation_id, None)
    }

    /// Advances one operation using its caller's wall-clock observation.
    ///
    /// Public operations require this entry point so every durable observation
    /// transition receives an atomic, monotone reconciliation timestamp. This
    /// low-level value grants no authority; activated controllers must source
    /// it through their protected clock boundary.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::reconcile_once`], plus
    /// [`ReconcilerError::PublicOperationClock`] if the supplied wall time
    /// moves backward or is outside the protobuf timestamp range.
    pub fn reconcile_once_at(
        &mut self,
        operation_id: OperationId,
        wall_seconds: i64,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        self.reconcile_once_inner(operation_id, Some(wall_seconds))
    }

    fn reconcile_once_inner(
        &mut self,
        operation_id: OperationId,
        wall_seconds: Option<i64>,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let operation = self.load_operation(operation_id)?;
        let gate = self.load_and_validate_ownership_gate(operation_id, operation)?;
        match operation.state {
            OperationState::OwnershipPending => return Ok(ReconcileOutcome::OwnershipPending),
            OperationState::Succeeded => return Ok(ReconcileOutcome::Succeeded),
            OperationState::CanceledBeforeCommit => {
                return Ok(ReconcileOutcome::CanceledBeforeCommit);
            }
            OperationState::PermanentlyBlocked => {
                return Ok(ReconcileOutcome::PermanentlyBlocked);
            }
            OperationState::Accepted | OperationState::Applying => {}
        }

        let mut canceled_before_commit = false;
        for step in 0..operation.effect_count {
            let key = effect_key(operation_id, step);
            let bytes = self
                .journal
                .get(RecordNamespace::Effect, &key)
                .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
            let record = decode_effect(bytes)?;
            match record.state {
                EffectState::Applied { receipt, .. } => {
                    if receipt
                        .canceled_before_commit_evidence()
                        .map_err(|()| {
                            ReconcilerError::CorruptLedger(
                                "invalid canceled-before-commit effect receipt",
                            )
                        })?
                        .is_some()
                    {
                        if operation.effect_count != 1
                            || step != 0
                            || record.plan.public_mutation_method().is_none()
                        {
                            return Err(ReconcilerError::CorruptLedger(
                                "invalid canceled-before-commit effect receipt",
                            ));
                        }
                        canceled_before_commit = true;
                    }
                    continue;
                }
                EffectState::PermanentlyBlocked { .. } => {
                    self.store_operation(
                        operation_id,
                        OperationState::PermanentlyBlocked,
                        operation.effect_count,
                        wall_seconds,
                    )?;
                    return Ok(ReconcileOutcome::PermanentlyBlocked);
                }
                EffectState::Planned => {
                    let dispatch = if let Some(binding) = record.plan.authority() {
                        let OwnershipGateStatusV1::Activated {
                            plan: gate_plan,
                            publication_digest,
                            ..
                        } = gate.as_ref().ok_or(ReconcilerError::CorruptLedger(
                            "authority effect has no activated ownership gate",
                        ))?
                        else {
                            return Err(ReconcilerError::CorruptLedger(
                                "authority effect advanced while ownership is pending",
                            ));
                        };
                        let timing = self
                            .executor
                            .authority_effect_timing(operation_id, step)
                            .ok_or(ReconcilerError::InvalidExecutorOutput(
                                "authority-bound effect execution is unsupported",
                            ))?;
                        let sandbox = gate_plan.claim().assignment().sandbox();
                        let (selected_publication, attempt) = self.prepare_bound_current_attempt(
                            operation_id,
                            step,
                            sandbox,
                            *publication_digest,
                            binding.source_draft_digest,
                            binding.audience,
                            binding.template_digest,
                            timing,
                        )?;
                        Some(PreparedAuthorityEffectV1::new(
                            binding.digest,
                            selected_publication,
                            timing.clock(),
                            attempt,
                        ))
                    } else {
                        None
                    };
                    let applying = EffectLedgerRecord {
                        plan: record.plan,
                        state: EffectState::Applying {
                            attempt: 1,
                            diagnostic: String::new(),
                        },
                        dispatch,
                    };
                    self.store_effect(
                        operation_id,
                        step,
                        &applying,
                        Some(operation.effect_count),
                        wall_seconds,
                    )?;
                    return Ok(ReconcileOutcome::Progressed);
                }
                EffectState::Applying { attempt, .. } => {
                    return self.reconcile_applying(
                        operation_id,
                        step,
                        operation.effect_count,
                        attempt,
                        record.plan,
                        record.dispatch,
                        match gate.as_ref() {
                            Some(OwnershipGateStatusV1::Activated {
                                plan,
                                publication_digest,
                                ..
                            }) => Some((plan.claim().assignment().sandbox(), *publication_digest)),
                            _ => None,
                        },
                        wall_seconds,
                    );
                }
            }
        }

        let (state, outcome) = if canceled_before_commit {
            (
                OperationState::CanceledBeforeCommit,
                ReconcileOutcome::CanceledBeforeCommit,
            )
        } else {
            (OperationState::Succeeded, ReconcileOutcome::Succeeded)
        };
        self.store_operation(operation_id, state, operation.effect_count, wall_seconds)?;
        Ok(outcome)
    }

    /// Advances one fairly selected nonterminal operation by one step.
    ///
    /// Returns `Ok(None)` when no admitted operation needs reconciliation.
    /// The cursor is scheduling state only; durable correctness and effect
    /// ordering do not depend on preserving it across process restart.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] for corrupt operation records or the same
    /// journal and executor failures as [`Self::reconcile_once`].
    pub fn reconcile_next(
        &mut self,
    ) -> Result<Option<(OperationId, ReconcileOutcome)>, ReconcilerError> {
        self.reconcile_next_inner(None)
    }

    /// Advances one fairly selected operation at a caller-supplied wall time.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::reconcile_next`] and rejects a
    /// nonmonotone public-operation timestamp.
    pub fn reconcile_next_at(
        &mut self,
        wall_seconds: i64,
    ) -> Result<Option<(OperationId, ReconcileOutcome)>, ReconcilerError> {
        self.reconcile_next_inner(Some(wall_seconds))
    }

    fn reconcile_next_inner(
        &mut self,
        wall_seconds: Option<i64>,
    ) -> Result<Option<(OperationId, ReconcileOutcome)>, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let mut first = None;
        let mut after_cursor = None;
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let operation_id = decode_operation_key(key)?;
            let operation = decode_operation(value)?;
            if matches!(
                operation.state,
                OperationState::Succeeded
                    | OperationState::CanceledBeforeCommit
                    | OperationState::PermanentlyBlocked
                    | OperationState::OwnershipPending
            ) {
                continue;
            }
            first.get_or_insert(operation_id);
            if self
                .scheduling_cursor
                .is_some_and(|cursor| operation_id > cursor)
            {
                after_cursor = Some(operation_id);
                break;
            }
        }
        let Some(operation_id) = after_cursor.or(first) else {
            return Ok(None);
        };
        self.scheduling_cursor = Some(operation_id);
        let outcome = self.reconcile_once_inner(operation_id, wall_seconds)?;
        Ok(Some((operation_id, outcome)))
    }

    fn validate_all_ownership_gates(
        &mut self,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        let gated_operations = self
            .journal
            .records(RecordNamespace::OwnershipGate)
            .map(|(key, _)| decode_operation_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        for operation_id in gated_operations {
            let operation = self.load_operation(operation_id).map_err(|error| {
                if matches!(error, ReconcilerError::OperationNotFound) {
                    ReconcilerError::CorruptLedger("orphan ownership gate")
                } else {
                    error
                }
            })?;
            self.load_and_validate_ownership_gate_for(
                operation_id,
                operation,
                validate_current_boot,
            )?;
        }

        let operations = self
            .journal
            .records(RecordNamespace::Operation)
            .map(|(key, _)| decode_operation_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        for operation_id in operations {
            let operation = self.load_operation(operation_id)?;
            self.load_and_validate_ownership_gate_for(
                operation_id,
                operation,
                validate_current_boot,
            )?;
        }
        Ok(())
    }

    fn validate_public_operation_authorizations(&self) -> Result<(), ReconcilerError> {
        for (key, value) in self
            .journal
            .records(RecordNamespace::PublicOperationAuthorization)
        {
            let operation_id = decode_operation_key(key)?;
            let operation = self.load_operation(operation_id).map_err(|error| {
                if matches!(error, ReconcilerError::OperationNotFound) {
                    ReconcilerError::CorruptLedger("orphan public operation authorization binding")
                } else {
                    error
                }
            })?;
            if operation.public_operation.is_none() {
                return Err(ReconcilerError::CorruptLedger(
                    "authorization binding refers to a non-public operation",
                ));
            }
            PublicOperationAuthorizationV1::decode(value)?;
        }
        Ok(())
    }

    fn ensure_ledger_validated(&mut self) -> Result<(), ReconcilerError> {
        self.ensure_ledger_validated_for(true)
    }

    fn ensure_ledger_validated_read_only(&mut self) -> Result<(), ReconcilerError> {
        self.ensure_ledger_validated_for(false)
    }

    fn ensure_ledger_validated_for(
        &mut self,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        // Cached structural validity says nothing about a later failed commit.
        // Check on every entry before replay or any executor/session interaction.
        self.journal.ensure_healthy()?;
        if !self.ledger_validated {
            // Scan the publication namespace once after recovery or an exposed
            // raw journal mutation. Individual gated operations still verify
            // their direct prepared/current references on every selection.
            validate_publication_namespace(&self.journal).map_err(|_| {
                ReconcilerError::CorruptLedger("authority publication namespace is corrupt")
            })?;
            self.validate_all_ownership_gates(validate_current_boot)?;
            self.validate_public_operation_authorizations()?;
            validate_runtime_authority_operations(&self.journal)?;
            if self
                .journal
                .records(RecordNamespace::SandboxSpec)
                .next()
                .is_some()
            {
                crate::sandbox_spec_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::SandboxSpec(Box::new(error)))?;
            }
            if self
                .journal
                .records(RecordNamespace::FilesystemViewRevision)
                .next()
                .is_some()
            {
                crate::filesystem_view_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::FilesystemViewRevision(Box::new(error)))?;
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentSlot)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::attachment_slot_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::AttachmentSlot(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment slots require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .next()
                .is_some()
            {
                RuntimeAuthorityStore::load(&mut self.journal, RuntimeAuthorityLimits::default())?;
            }
            if self
                .journal
                .records(RecordNamespace::RuntimeGeneration)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::runtime_scope::validate_generation_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::RuntimeGeneration(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "runtime generations require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::NamespaceTarget)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::runtime_scope::validate_namespace_target_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::NamespaceTarget(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "namespace targets require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentDesired)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::attachment_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::AttachmentDesired(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment desired state requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountAttempt)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_attempt::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::MountAttempt(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "mount attempts require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountCompletion)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_attempt::validate_completion_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::MountAttempt(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "mount completions require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountInventory)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_attempt::validate_inventory_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::MountAttempt(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "mount inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountSourceAcquisitionInventory)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_source_acquisition_inventory::validate_namespace(&mut self.journal)
                    .map_err(|error| {
                        ReconcilerError::MountSourceAcquisitionInventory(Box::new(error))
                    })?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "Mount source-acquisition inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentSourceAttempt)
                .next()
                .is_some()
                || self
                    .journal
                    .records(RecordNamespace::AttachmentSourceCompletion)
                    .next()
                    .is_some()
                || self
                    .journal
                    .records(RecordNamespace::AttachmentSourceDispatch)
                    .next()
                    .is_some()
            {
                #[cfg(target_os = "linux")]
                {
                    crate::attachment_source::validate_attempt_namespace(&mut self.journal)
                        .map_err(|error| ReconcilerError::AttachmentSource(Box::new(error)))?;
                    crate::attachment_source::validate_completion_namespace(&mut self.journal)
                        .map_err(|error| ReconcilerError::AttachmentSource(Box::new(error)))?;
                    crate::attachment_source::validate_dispatch_namespace(&mut self.journal)
                        .map_err(|error| ReconcilerError::AttachmentSource(Box::new(error)))?;
                }
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment source custody requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::DestinationSlotAttempt)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::destination_slot_effect::validate_attempt_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::DestinationSlotEffect(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "destination-slot attempts require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::DestinationSlotCompletion)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::destination_slot_effect::validate_completion_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::DestinationSlotEffect(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "destination-slot completions require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::DestinationSlotInventory)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::destination_slot_inventory::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::DestinationSlotInventory(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "destination-slot inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::StorageResourceInventory)
                .next()
                .is_some()
                || self
                    .journal
                    .records(RecordNamespace::NetworkResourceInventory)
                    .next()
                    .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::resource_inventory::validate_namespaces(&mut self.journal)
                    .map_err(|error| ReconcilerError::ResourceInventory(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "broker resource inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentVerification)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::attachment_verification::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::AttachmentVerification(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment verification requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::HostCatalogReconciliation)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::host_catalog_reconciliation::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::HostCatalogReconciliation(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "Host catalog reconciliation requires Linux validation",
                ));
            }
            // Executor-free validation must not satisfy the stronger cache
            // used immediately before effect recovery and dispatch.
            self.ledger_validated = validate_current_boot;
        }
        Ok(())
    }

    fn validate_gated_effects_for_activation(
        &self,
        operation_id: OperationId,
        effect_count: u32,
    ) -> Result<(), ReconcilerError> {
        for step in 0..effect_count {
            let bytes = self
                .journal
                .get(RecordNamespace::Effect, &effect_key(operation_id, step))
                .ok_or(ReconcilerError::CorruptLedger(
                    "ownership-gated operation is missing an effect",
                ))?;
            if !matches!(decode_effect(bytes)?.state, EffectState::Planned) {
                return Err(ReconcilerError::CorruptLedger(
                    "ownership-gated effect advanced before activation",
                ));
            }
        }
        for (key, _) in self.journal.records(RecordNamespace::Effect) {
            if key.len() >= OPERATION_KEY_BYTES
                && &key[..OPERATION_KEY_BYTES] == operation_id.as_bytes()
            {
                let step_bytes: [u8; 4] = key
                    .get(OPERATION_KEY_BYTES..)
                    .ok_or(ReconcilerError::CorruptLedger(
                        "invalid ownership-gated effect key",
                    ))?
                    .try_into()
                    .map_err(|_| {
                        ReconcilerError::CorruptLedger("invalid ownership-gated effect key")
                    })?;
                if u32::from_be_bytes(step_bytes) >= effect_count {
                    return Err(ReconcilerError::CorruptLedger(
                        "ownership-gated operation has an extra effect",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_operation_gate_relation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), ReconcilerError> {
        let operation = self.load_operation(operation_id)?;
        self.load_and_validate_ownership_gate(operation_id, operation)?;
        Ok(())
    }

    fn load_and_validate_ownership_gate(
        &mut self,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        self.load_and_validate_ownership_gate_for(operation_id, operation, true)
    }

    fn load_and_validate_ownership_gate_for(
        &mut self,
        operation_id: OperationId,
        operation: OperationRecord,
        validate_current_boot: bool,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        self.validate_canceled_operation(operation_id, operation)?;
        let gate = self
            .journal
            .get(RecordNamespace::OwnershipGate, operation_id.as_bytes())
            .map(decode_ownership_gate)
            .transpose()?;
        let Some(gate) = gate else {
            return if operation.ownership_gated {
                Err(ReconcilerError::CorruptLedger(
                    "ownership-gated operation has no gate",
                ))
            } else {
                self.validate_effect_authority_bindings(
                    operation_id,
                    operation.effect_count,
                    None,
                    None,
                    validate_current_boot,
                )?;
                Ok(None)
            };
        };
        let plan = match &gate {
            OwnershipGateStatusV1::Pending(plan)
            | OwnershipGateStatusV1::Activated { plan, .. } => plan,
        };
        if plan.operation_id != operation_id
            || self
                .journal
                .check_idempotency(&plan.idempotency_key, plan.request_digest)
                != IdempotencyOutcome::Replay(operation_id)
        {
            return Err(ReconcilerError::CorruptLedger(
                "ownership gate does not match its operation",
            ));
        }
        if !operation.ownership_gated {
            return Err(ReconcilerError::CorruptLedger(
                "ungated operation has an ownership gate",
            ));
        }
        self.validate_effect_authority_bindings(
            operation_id,
            operation.effect_count,
            Some(plan.publication_draft()),
            match &gate {
                OwnershipGateStatusV1::Activated {
                    publication_digest, ..
                } => Some(*publication_digest),
                OwnershipGateStatusV1::Pending(_) => None,
            },
            validate_current_boot,
        )?;
        match (&gate, operation.state) {
            (OwnershipGateStatusV1::Pending(_), OperationState::OwnershipPending) => Ok(Some(gate)),
            (
                OwnershipGateStatusV1::Activated {
                    plan,
                    publication_digest,
                    lease_generation,
                    lease_digest,
                },
                OperationState::Accepted
                | OperationState::Applying
                | OperationState::Succeeded
                | OperationState::PermanentlyBlocked,
            ) => {
                validate_durable_gate_publication(
                    &self.journal,
                    *publication_digest,
                    plan.publication_draft(),
                    plan.claim(),
                    *lease_generation,
                    *lease_digest,
                )
                .map_err(|_| {
                    ReconcilerError::CorruptLedger(
                        "activated ownership gate publication is missing or corrupt",
                    )
                })?;
                Ok(Some(gate))
            }
            _ => Err(ReconcilerError::CorruptLedger(
                "ownership gate state does not match its operation",
            )),
        }
    }

    fn validate_canceled_operation(
        &self,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<(), ReconcilerError> {
        if operation.state != OperationState::CanceledBeforeCommit {
            return Ok(());
        }
        if operation.effect_count != 1
            || operation.ownership_gated
            || operation.public_operation.is_none()
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid canceled-before-commit operation",
            ));
        }

        let bytes = self
            .journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
            .ok_or(ReconcilerError::CorruptLedger(
                "canceled operation is missing its effect",
            ))?;
        let effect = decode_effect(bytes)?;
        let EffectState::Applied { receipt, .. } = effect.state else {
            return Err(ReconcilerError::CorruptLedger(
                "canceled operation effect is not applied",
            ));
        };
        if effect.plan.public_mutation_method().is_none()
            || receipt
                .canceled_before_commit_evidence()
                .map_err(|()| {
                    ReconcilerError::CorruptLedger("invalid canceled-before-commit effect receipt")
                })?
                .is_none()
        {
            return Err(ReconcilerError::CorruptLedger(
                "canceled operation lacks cancellation evidence",
            ));
        }
        Ok(())
    }

    fn validate_effect_authority_bindings(
        &mut self,
        operation_id: OperationId,
        effect_count: u32,
        draft: Option<&AuthorityPublicationDraftV1>,
        activated_publication: Option<ObjectDigest>,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        for step in 0..effect_count {
            let bytes = self
                .journal
                .get(RecordNamespace::Effect, &effect_key(operation_id, step))
                .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
            let effect = decode_effect(bytes)?;
            match (draft, effect.plan.authority()) {
                (None, None) => {}
                (Some(draft), Some(binding)) => {
                    let template = draft
                        .templates()
                        .iter()
                        .find(|template| template.digest() == binding.template_digest)
                        .ok_or(ReconcilerError::CorruptLedger(
                            "authority effect template is absent from gate draft",
                        ))?;
                    if binding.source_draft_digest != draft.digest()
                        || binding.operation_id != operation_id
                        || binding.step != step
                        || binding.audience != template.audience()
                        || binding.method != template.method()
                        || binding.body_digest
                            != effect::effect_body_digest(template.body_without_deadline())
                        || binding.semantic_digest
                            != crate::dispatch::semantic_identity_digest(template.semantics())
                        || !binding.descriptor_free
                        || !template.descriptor_roles().is_empty()
                        || effect.plan.request() != template.body_without_deadline()
                    {
                        return Err(ReconcilerError::CorruptLedger(
                            "authority effect does not match gate draft template",
                        ));
                    }
                    if let Some(dispatch) = &effect.dispatch {
                        let current_host_boot_id = if validate_current_boot
                            && matches!(&effect.state, EffectState::Applying { .. })
                        {
                            Some(
                                self.executor
                                    .authority_effect_timing(operation_id, step)
                                    .ok_or(ReconcilerError::InvalidExecutorOutput(
                                        "authority-bound effect execution is unsupported",
                                    ))?
                                    .clock()
                                    .host_boot_id(),
                            )
                        } else {
                            None
                        };
                        validate_durable_effect_attempt(
                            &self.journal,
                            draft.manifest().manifest().sandbox(),
                            activated_publication.ok_or(ReconcilerError::CorruptLedger(
                                "authority dispatch exists before gate activation",
                            ))?,
                            binding.digest,
                            binding.source_draft_digest,
                            binding.audience,
                            binding.template_digest,
                            effect.plan.request(),
                            dispatch,
                            current_host_boot_id,
                        )
                        .map_err(|_| {
                            ReconcilerError::CorruptLedger(
                                "authority effect dispatch is missing or corrupt",
                            )
                        })?;
                        if let EffectState::Applied { receipt, .. } = &effect.state {
                            dispatch
                                .validate_durable_receipt(receipt.as_bytes())
                                .map_err(|_| {
                                    ReconcilerError::CorruptLedger(
                                        "authority effect receipt is malformed or substituted",
                                    )
                                })?;
                        }
                    }
                }
                (Some(_), None) => {
                    return Err(ReconcilerError::CorruptLedger(
                        "effect record authority flag does not match operation provenance",
                    ));
                }
                (None, Some(_)) => {
                    return Err(ReconcilerError::CorruptLedger(
                        "effect record authority flag does not match operation provenance",
                    ));
                }
            }
        }
        for (key, _) in self.journal.records(RecordNamespace::Effect) {
            if key.len() >= OPERATION_KEY_BYTES
                && &key[..OPERATION_KEY_BYTES] == operation_id.as_bytes()
            {
                let step: [u8; 4] = key
                    .get(OPERATION_KEY_BYTES..)
                    .ok_or(ReconcilerError::CorruptLedger("invalid effect key"))?
                    .try_into()
                    .map_err(|_| ReconcilerError::CorruptLedger("invalid effect key"))?;
                if u32::from_be_bytes(step) >= effect_count {
                    return Err(ReconcilerError::CorruptLedger(
                        "operation has an extra effect",
                    ));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_bound_current_attempt(
        &mut self,
        operation_id: OperationId,
        step: u32,
        sandbox: SandboxId,
        activated_publication: ObjectDigest,
        source_draft_digest: ObjectDigest,
        audience: aos_sandbox_core::BrokerAudience,
        template_digest: ObjectDigest,
        timing: AuthorityEffectAttemptTimingV1,
    ) -> Result<(ObjectDigest, crate::BrokerDispatchAttemptV1), ReconcilerError> {
        let guardian_request = AuthorityPublicationStore::new(&mut self.journal)
            .select_bound_guardian_plan_request(
                sandbox,
                activated_publication,
                source_draft_digest,
                audience,
                template_digest,
                timing.clock().host_boot_id(),
            )?;
        let guardian_plan = guardian_request
            .as_ref()
            .map(|request| {
                self.executor
                    .prepare_guardian_plan(operation_id, step, request)
                    .ok_or(ReconcilerError::InvalidExecutorOutput(
                        "Guardian plan signing is unavailable for Host launch",
                    ))
            })
            .transpose()?;
        AuthorityPublicationStore::new(&mut self.journal)
            .select_bound_current_attempt(
                sandbox,
                activated_publication,
                source_draft_digest,
                audience,
                template_digest,
                guardian_plan.as_ref(),
                timing.deadline(),
                timing.clock(),
            )
            .map_err(ReconcilerError::AuthorityPublication)
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_applying(
        &mut self,
        operation_id: OperationId,
        step: u32,
        effect_count: u32,
        attempt: u32,
        plan: EffectPlan,
        dispatch: Option<PreparedAuthorityEffectV1>,
        authority_gate: Option<(SandboxId, ObjectDigest)>,
        wall_seconds: Option<i64>,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        let receipt = if let Some(prepared) = dispatch.as_ref() {
            let observed = match self
                .executor
                .observe_authority(operation_id, step, prepared)
            {
                Ok(value) => value,
                Err(failure) => {
                    return self.handle_failure(
                        operation_id,
                        step,
                        effect_count,
                        attempt,
                        plan,
                        dispatch.clone(),
                        failure,
                        wall_seconds,
                    );
                }
            };
            match observed {
                AuthorityEffectObservationV1::Applied(receipt) => {
                    receipt.into_effect_receipt_for(prepared)?
                }
                AuthorityEffectObservationV1::Pending => return Ok(ReconcileOutcome::RetryPending),
                AuthorityEffectObservationV1::Absent => {
                    let binding = plan.authority().ok_or(ReconcilerError::CorruptLedger(
                        "authority dispatch has no binding",
                    ))?;
                    let (sandbox, activated_publication) = authority_gate.ok_or(
                        ReconcilerError::CorruptLedger("authority dispatch has no activated gate"),
                    )?;
                    let timing = self
                        .executor
                        .authority_effect_timing(operation_id, step)
                        .ok_or(ReconcilerError::InvalidExecutorOutput(
                            "authority-bound effect execution is unsupported",
                        ))?;
                    let (publication_digest, fresh_attempt) = self.prepare_bound_current_attempt(
                        operation_id,
                        step,
                        sandbox,
                        activated_publication,
                        binding.source_draft_digest,
                        binding.audience,
                        binding.template_digest,
                        timing,
                    )?;
                    let fresh = PreparedAuthorityEffectV1::new(
                        binding.digest,
                        publication_digest,
                        timing.clock(),
                        fresh_attempt,
                    );
                    let next_attempt =
                        attempt
                            .checked_add(1)
                            .ok_or(ReconcilerError::InvalidExecutorOutput(
                                "effect retry counter exhausted",
                            ))?;
                    let refreshed = EffectLedgerRecord {
                        plan: plan.clone(),
                        state: EffectState::Applying {
                            attempt: next_attempt,
                            diagnostic: String::new(),
                        },
                        dispatch: Some(fresh.clone()),
                    };
                    // This commit is the crash boundary: no Apply may use the
                    // fresh packet until its exact replacement is durable.
                    self.store_effect(operation_id, step, &refreshed, None, wall_seconds)?;
                    match self.executor.apply_authority(operation_id, step, &fresh) {
                        Ok(receipt) => {
                            let receipt = receipt.into_effect_receipt_for(&fresh)?;
                            let applied = EffectLedgerRecord {
                                plan,
                                state: EffectState::Applied {
                                    attempt: next_attempt,
                                    receipt,
                                },
                                dispatch: Some(fresh),
                            };
                            self.store_effect(operation_id, step, &applied, None, wall_seconds)?;
                            return Ok(ReconcileOutcome::EffectApplied);
                        }
                        Err(failure) => {
                            return self.handle_failure(
                                operation_id,
                                step,
                                effect_count,
                                next_attempt,
                                plan,
                                Some(fresh),
                                failure,
                                wall_seconds,
                            );
                        }
                    }
                }
            }
        } else {
            if plan.method().is_none() && plan.public_mutation_method().is_none() {
                return self.handle_failure(
                    operation_id,
                    step,
                    effect_count,
                    attempt,
                    plan,
                    None,
                    EffectFailure::Permanent("effect has no closed dispatch method".to_owned()),
                    wall_seconds,
                );
            }
            let controller_effect = plan.public_mutation_method().is_some();
            let observed = if controller_effect {
                self.executor
                    .observe_controller(operation_id, step, &plan, &mut self.journal)
            } else {
                self.executor.observe(operation_id, step, &plan)
            };
            if controller_effect {
                self.ledger_validated = false;
                self.ensure_ledger_validated()?;
            }
            let observed = match observed {
                Ok(value) => value,
                Err(failure) => {
                    return self.handle_failure(
                        operation_id,
                        step,
                        effect_count,
                        attempt,
                        plan,
                        None,
                        failure,
                        wall_seconds,
                    );
                }
            };
            match observed {
                EffectObservation::Applied(receipt) => receipt,
                EffectObservation::Absent => {
                    let applied = if controller_effect {
                        self.executor
                            .apply_controller(operation_id, step, &plan, &mut self.journal)
                    } else {
                        self.executor.apply(operation_id, step, &plan)
                    };
                    if controller_effect {
                        self.ledger_validated = false;
                        self.ensure_ledger_validated()?;
                    }
                    match applied {
                        Ok(receipt) => receipt,
                        Err(failure) => {
                            return self.handle_failure(
                                operation_id,
                                step,
                                effect_count,
                                attempt,
                                plan,
                                None,
                                failure,
                                wall_seconds,
                            );
                        }
                    }
                }
            }
        };
        if receipt
            .canceled_before_commit_evidence()
            .map_err(|()| {
                ReconcilerError::InvalidExecutorOutput(
                    "invalid canceled-before-commit effect receipt",
                )
            })?
            .is_some()
            && (effect_count != 1 || step != 0 || plan.public_mutation_method().is_none())
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid canceled-before-commit effect receipt",
            ));
        }
        let applied = EffectLedgerRecord {
            plan,
            state: EffectState::Applied { attempt, receipt },
            dispatch,
        };
        self.store_effect(operation_id, step, &applied, None, wall_seconds)?;
        Ok(ReconcileOutcome::EffectApplied)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_failure(
        &mut self,
        operation_id: OperationId,
        step: u32,
        effect_count: u32,
        attempt: u32,
        plan: EffectPlan,
        dispatch: Option<PreparedAuthorityEffectV1>,
        failure: EffectFailure,
        wall_seconds: Option<i64>,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        failure.validate()?;
        match failure {
            EffectFailure::Retryable(diagnostic) => {
                let next_attempt =
                    attempt
                        .checked_add(1)
                        .ok_or(ReconcilerError::InvalidExecutorOutput(
                            "effect retry counter exhausted",
                        ))?;
                let applying = EffectLedgerRecord {
                    plan,
                    state: EffectState::Applying {
                        attempt: next_attempt,
                        diagnostic,
                    },
                    dispatch,
                };
                self.store_effect(operation_id, step, &applying, None, wall_seconds)?;
                Ok(ReconcileOutcome::RetryPending)
            }
            EffectFailure::Permanent(diagnostic) => {
                let blocked = EffectLedgerRecord {
                    plan,
                    state: EffectState::PermanentlyBlocked {
                        attempt,
                        diagnostic,
                    },
                    dispatch,
                };
                self.store_effect(
                    operation_id,
                    step,
                    &blocked,
                    Some(effect_count),
                    wall_seconds,
                )?;
                Ok(ReconcileOutcome::PermanentlyBlocked)
            }
        }
    }

    fn load_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationRecord, ReconcilerError> {
        let bytes = self
            .journal
            .get(RecordNamespace::Operation, operation_id.as_bytes())
            .ok_or(ReconcilerError::OperationNotFound)?;
        decode_operation(bytes)
    }

    fn store_operation(
        &mut self,
        operation_id: OperationId,
        state: OperationState,
        effect_count: u32,
        wall_seconds: Option<i64>,
    ) -> Result<(), ReconcilerError> {
        let operation = self.load_operation(operation_id)?;
        if operation.effect_count != effect_count {
            return Err(ReconcilerError::CorruptLedger(
                "operation effect count changed during transition",
            ));
        }
        let operation = transition_operation(operation, state, wall_seconds)?;
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.into_bytes().to_vec(),
            encode_operation_record(operation),
        );
        self.commit_records(vec![record])
    }

    fn store_effect(
        &mut self,
        operation_id: OperationId,
        step: u32,
        record: &EffectLedgerRecord,
        operation_effect_count: Option<u32>,
        wall_seconds: Option<i64>,
    ) -> Result<(), ReconcilerError> {
        let mut records = vec![JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(operation_id, step).to_vec(),
            encode_effect(record)?,
        )];
        let operation = self.load_operation(operation_id)?;
        if let Some(effect_count) = operation_effect_count {
            if operation.effect_count != effect_count {
                return Err(ReconcilerError::CorruptLedger(
                    "operation effect count changed during transition",
                ));
            }
            let state = match record.state {
                EffectState::Applying { .. } => OperationState::Applying,
                EffectState::PermanentlyBlocked { .. } => OperationState::PermanentlyBlocked,
                EffectState::Planned | EffectState::Applied { .. } => {
                    return Err(ReconcilerError::CorruptLedger(
                        "invalid coupled operation transition",
                    ));
                }
            };
            let operation = transition_operation(operation, state, wall_seconds)?;
            records.push(JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_operation_record(operation),
            ));
        } else if operation.public_operation.is_some() {
            let operation = transition_operation(operation, operation.state, wall_seconds)?;
            records.push(JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_operation_record(operation),
            ));
        }
        self.commit_records(records)
    }

    fn commit_records(&mut self, records: Vec<JournalRecord>) -> Result<(), ReconcilerError> {
        let transaction = JournalTransaction::new(OperationId::new().into_bytes(), records)?;
        self.journal.commit(&transaction)?;
        Ok(())
    }
}

pub(crate) fn recovered_public_operation_admission_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<PublicOperationAdmissionV1>, ReconcilerError> {
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation else {
        return Ok(None);
    };
    let authorization = journal
        .get(
            RecordNamespace::PublicOperationAuthorization,
            operation_id.as_bytes(),
        )
        .map(PublicOperationAuthorizationV1::decode)
        .transpose()?
        .ok_or(ReconcilerError::CorruptLedger(
            "public operation has no authorization scope",
        ))?;

    Ok(Some(public.into_admission(authorization)))
}

pub(crate) fn recovered_public_operation_authorization_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<PublicOperationAuthorizationV1>, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    if decode_operation(operation_bytes)?
        .public_operation
        .is_none()
    {
        return Ok(None);
    }
    journal
        .get(
            RecordNamespace::PublicOperationAuthorization,
            operation_id.as_bytes(),
        )
        .map(PublicOperationAuthorizationV1::decode)
        .transpose()
}

pub(crate) fn recovered_public_operation_resource_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<aos_proto::aos::sandbox::v1::Operation>, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation else {
        return Ok(None);
    };

    let mut applied_effects = 0_u32;
    let mut applying_effects = 0_u32;
    let mut blocked_effects = 0_u32;
    let mut canceled_effects = 0_u32;
    let mut controller_method = None;
    let mut effect_records = Vec::with_capacity(operation.effect_count as usize);
    for step in 0..operation.effect_count {
        let bytes = journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, step))
            .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
        let effect = decode_effect(bytes)?;
        if operation.effect_count == 1 {
            controller_method = effect.plan.public_mutation_method();
        }
        match effect.state {
            EffectState::Applied { ref receipt, .. } => {
                increment_effect_count(&mut applied_effects)?;
                if receipt
                    .canceled_before_commit_evidence()
                    .map_err(|()| {
                        ReconcilerError::CorruptLedger(
                            "invalid canceled-before-commit effect receipt",
                        )
                    })?
                    .is_some()
                {
                    if operation.effect_count != 1
                        || step != 0
                        || effect.plan.public_mutation_method().is_none()
                    {
                        return Err(ReconcilerError::CorruptLedger(
                            "invalid canceled-before-commit effect receipt",
                        ));
                    }
                    increment_effect_count(&mut canceled_effects)?;
                }
            }
            EffectState::Applying { .. } => increment_effect_count(&mut applying_effects)?,
            EffectState::PermanentlyBlocked { .. } => {
                increment_effect_count(&mut blocked_effects)?;
            }
            EffectState::Planned => {}
        }
        effect_records.push(bytes);
    }
    let state_matches_effects = match operation.state {
        OperationState::OwnershipPending | OperationState::Accepted => {
            applied_effects == 0 && applying_effects == 0 && blocked_effects == 0
        }
        OperationState::Applying => applying_effects + applied_effects != 0 && blocked_effects == 0,
        OperationState::Succeeded => {
            applied_effects == operation.effect_count && canceled_effects == 0
        }
        OperationState::CanceledBeforeCommit => {
            applied_effects == operation.effect_count && canceled_effects == 1
        }
        OperationState::PermanentlyBlocked => blocked_effects != 0,
    };
    if !state_matches_effects {
        return Err(ReconcilerError::CorruptLedger(
            "public operation state contradicts its effects",
        ));
    }

    Ok(Some(public.project(
        operation_id,
        operation.state,
        operation.effect_count,
        applied_effects,
        controller_method.is_some(),
        operation.state == OperationState::Accepted
            && controller_method.is_some_and(|method| {
                !matches!(
                    method,
                    crate::controller_query::PublicOperationMethodV1::CancelOperation
                        | crate::controller_query::PublicOperationMethodV1::OperatorRecover
                )
            }),
        operation_bytes,
        &effect_records,
    )))
}

/// Reads one established public operation directly from protected journal state.
///
/// This read-only entry point is intended for a production effect executor that
/// already holds the controller journal through [`SingleNodeEffectExecutor`]'s
/// journal-custody hook. It grants no mutation or effect authority.
///
/// # Errors
///
/// Returns [`ReconcilerError`] when protected authority is absent or the
/// operation or any referenced effect record is corrupt.
pub fn public_operation_resource_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<aos_proto::aos::sandbox::v1::Operation>, ReconcilerError> {
    recovered_public_operation_resource_v1(journal, operation_id)
}

/// Carries one retained public Repair admission into a separately proved terminal CAS.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(crate) struct PendingOperatorRepairLedgerV1 {
    operation_id: OperationId,
    operation: OperationRecord,
    effect: EffectLedgerRecord,
    request: crate::cli_model::OperatorRecoveryRequestV1,
    context: PublicMutationEffectV1,
}

#[allow(dead_code, reason = "public operator Repair route remains closed")]
impl PendingOperatorRepairLedgerV1 {
    pub(crate) const fn request(&self) -> &crate::cli_model::OperatorRecoveryRequestV1 {
        &self.request
    }

    pub(crate) const fn context(&self) -> &PublicMutationEffectV1 {
        &self.context
    }

    /// Prepares the exact completed Effect and Operation records.
    ///
    /// The caller retains them with the physical proof and protected successor
    /// in one transaction. The receipt has already been independently checked.
    ///
    /// # Errors
    ///
    /// Rejects an invalid completion clock, effect receipt, or durable codec.
    pub(crate) fn complete(
        self,
        receipt: EffectReceipt,
        completion_wall_seconds: i64,
    ) -> Result<[JournalRecord; 2], ReconcilerError> {
        let attempt = match &self.effect.state {
            EffectState::Planned => 1,
            EffectState::Applying { attempt, .. } => *attempt,
            _ => {
                return Err(ReconcilerError::InvalidPlan(
                    "Repair effect is already terminal",
                ));
            }
        };
        let effect = encode_effect(&EffectLedgerRecord {
            state: EffectState::Applied { attempt, receipt },
            ..self.effect
        })?;
        decode_effect(&effect)?;
        let public = self
            .operation
            .public_operation
            .ok_or(ReconcilerError::InvalidPlan(
                "Repair operation is not public",
            ))?
            .advance(OperationState::Succeeded, completion_wall_seconds)?;
        let operation = encode_operation_record(OperationRecord {
            state: OperationState::Succeeded,
            public_operation: Some(public),
            ..self.operation
        });
        decode_operation(&operation)?;
        Ok([
            JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(self.operation_id, 0).to_vec(),
                effect,
            ),
            JournalRecord::put(
                RecordNamespace::Operation,
                self.operation_id.as_bytes().to_vec(),
                operation,
            ),
        ])
    }
}

/// Loads the exact pending public Repair operation and its authenticated effect.
///
/// # Errors
///
/// Rejects absent, terminal, corrupt, or mismatched Operation, Effect,
/// authorization, and idempotency rows.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(crate) fn pending_operator_repair_ledger_v1(
    journal: &Journal,
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    request_digest: [u8; 32],
) -> Result<PendingOperatorRepairLedgerV1, ReconcilerError> {
    use aos_proto::aos::sandbox::v1::OperatorRecoveryAction;
    use aos_sandbox_core::{ResourceKind, Selector};

    journal.ensure_protected_authority()?;
    let operation_bytes = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::OperationNotFound)?;
    let operation = decode_operation(operation_bytes)?;
    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger("Repair effect is absent"))?;
    let effect = decode_effect(effect_bytes)?;
    let context = effect
        .plan
        .public_mutation_context()?
        .ok_or(ReconcilerError::CorruptLedger(
            "Repair effect has no admission context",
        ))?;
    let crate::cli_model::DormantSandboxRequestKindV1::OperatorRecover(request) =
        context.validated_request()?
    else {
        return Err(ReconcilerError::CorruptLedger(
            "Repair effect names another method",
        ));
    };
    let request = crate::cli_model::OperatorRecoveryRequestV1::try_from(request)
        .map_err(|_| ReconcilerError::CorruptLedger("invalid public Repair request"))?;
    let public = recovered_public_operation_admission_v1(journal, operation_id)?.ok_or(
        ReconcilerError::CorruptLedger("Repair has no public operation"),
    )?;
    let selector_matches = matches!(
        public.authorization().selector(),
        Selector::Resource { resource } if resource.as_bytes() == &sandbox_id
    );
    let idempotency = IdempotencyKey::new(request.idempotency_key().to_vec())?;
    if operation_id.as_bytes() == &[0; 16]
        || sandbox_id == [0; 16]
        || request_digest == [0; 32]
        || !matches!(
            operation.state,
            OperationState::Accepted | OperationState::Applying
        )
        || operation.effect_count != 1
        || operation.ownership_gated
        || operation.runtime_intent_digest.is_some()
        || !matches!(
            &effect.state,
            EffectState::Planned | EffectState::Applying { .. }
        )
        || effect.plan.public_mutation_method()
            != Some(crate::controller_query::PublicOperationMethodV1::OperatorRecover)
        || request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        || request.resource_id() != sandbox_id
        || public.method() != crate::controller_query::PublicOperationMethodV1::OperatorRecover
        || public.authorization().resource_kind() != ResourceKind::Sandbox
        || !selector_matches
        || public.project() != context.project()
        || public.accepted_wall_seconds() != context.accepted_wall_seconds()
        || journal.check_idempotency(&idempotency, request_digest)
            != IdempotencyOutcome::Replay(operation_id)
    {
        return Err(ReconcilerError::InvalidPlan(
            "pending public Repair ledger disagrees",
        ));
    }
    recovered_public_operation_resource_v1(journal, operation_id)?.ok_or(
        ReconcilerError::CorruptLedger("Repair public operation is absent"),
    )?;

    Ok(PendingOperatorRepairLedgerV1 {
        operation_id,
        operation,
        effect,
        request,
        context,
    })
}

/// Reads the exact accepted CreateExecution effect from protected operation custody.
///
/// A canceled or permanently blocked operation cannot produce a specification.
/// This readback is nonauthorizing after the journal borrow ends.
///
/// # Errors
///
/// Returns an error if the protected operation/effect graph is corrupt or its
/// public method and retained request disagree.
pub(crate) fn accepted_create_execution_effect_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<PublicMutationEffectV1>, ReconcilerError> {
    if recovered_public_operation_resource_v1(journal, operation_id)?.is_none() {
        return Ok(None);
    }
    let bytes = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::CorruptLedger(
            "accepted Create operation is absent",
        ))?;
    let operation = decode_operation(bytes)?;
    if operation.effect_count != 1
        || !matches!(
            operation.state,
            OperationState::Accepted | OperationState::Applying | OperationState::Succeeded
        )
    {
        return Ok(None);
    }
    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger(
            "accepted Create effect is absent",
        ))?;
    let effect = decode_effect(effect_bytes)?;
    if effect.plan.public_mutation_method()
        != Some(crate::controller_query::PublicOperationMethodV1::CreateExecution)
    {
        return Ok(None);
    }
    let context = effect
        .plan
        .public_mutation_context()?
        .ok_or(ReconcilerError::CorruptLedger(
            "accepted Create context is absent",
        ))?;
    if !matches!(
        context.validated_request()?,
        crate::cli_model::DormantSandboxRequestKindV1::Exec(_)
    ) {
        return Err(ReconcilerError::CorruptLedger(
            "accepted Create request has another method",
        ));
    }
    Ok(Some(context))
}

/// Reads the validated publication digest of one activated ownership gate.
///
/// The caller already holds the reconciler's journal through its executor
/// hook. A pending or ungated operation returns `None`; an activated gate is
/// not evidence until its immutable publication has been checked against the
/// exact admitted draft and lease artifacts.
///
/// # Errors
///
/// Returns [`ReconcilerError`] for absent protected authority, inconsistent
/// operation/gate state, or corrupt publication evidence.
pub fn activated_ownership_gate_digest_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<ObjectDigest>, ReconcilerError> {
    match validated_ownership_gate_from_journal_v1(journal, operation_id)? {
        Some(OwnershipGateStatusV1::Activated {
            publication_digest, ..
        }) => Ok(Some(publication_digest)),
        Some(OwnershipGateStatusV1::Pending(_)) | None => Ok(None),
    }
}

pub(crate) fn validated_ownership_gate_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let operation = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .map(decode_operation)
        .transpose()?;
    let gate = journal
        .get(RecordNamespace::OwnershipGate, operation_id.as_bytes())
        .map(decode_ownership_gate)
        .transpose()?;
    let (operation, gate) = match (operation, gate) {
        (None, None)
        | (
            Some(OperationRecord {
                ownership_gated: false,
                ..
            }),
            None,
        ) => {
            return Ok(None);
        }
        (Some(operation), Some(gate)) => (operation, gate),
        _ => {
            return Err(ReconcilerError::CorruptLedger(
                "ownership gate does not match its operation",
            ));
        }
    };
    let plan = match &gate {
        OwnershipGateStatusV1::Pending(plan) | OwnershipGateStatusV1::Activated { plan, .. } => {
            plan
        }
    };
    if !operation.ownership_gated
        || plan.operation_id() != operation_id
        || journal.check_idempotency(plan.idempotency_key(), plan.request_digest())
            != IdempotencyOutcome::Replay(operation_id)
    {
        return Err(ReconcilerError::CorruptLedger(
            "ownership gate does not match its operation",
        ));
    }
    match &gate {
        OwnershipGateStatusV1::Pending(_)
            if operation.state == OperationState::OwnershipPending =>
        {
            Ok(Some(gate))
        }
        OwnershipGateStatusV1::Activated {
            plan,
            publication_digest,
            lease_generation,
            lease_digest,
        } if matches!(
            operation.state,
            OperationState::Accepted
                | OperationState::Applying
                | OperationState::Succeeded
                | OperationState::PermanentlyBlocked
        ) =>
        {
            validate_durable_gate_publication(
                journal,
                *publication_digest,
                plan.publication_draft(),
                plan.claim(),
                *lease_generation,
                *lease_digest,
            )
            .map_err(|_| {
                ReconcilerError::CorruptLedger("activated ownership publication is corrupt")
            })?;
            Ok(Some(gate))
        }
        _ => Err(ReconcilerError::CorruptLedger(
            "ownership gate state does not match its operation",
        )),
    }
}

fn transition_operation(
    operation: OperationRecord,
    state: OperationState,
    wall_seconds: Option<i64>,
) -> Result<OperationRecord, ReconcilerError> {
    let public_operation = operation
        .public_operation
        .map(|public| {
            let wall_seconds = wall_seconds.ok_or(ReconcilerError::PublicOperationClock)?;
            public.advance(state, wall_seconds)
        })
        .transpose()?;

    Ok(OperationRecord {
        state,
        public_operation,
        ..operation
    })
}

fn increment_effect_count(count: &mut u32) -> Result<(), ReconcilerError> {
    *count = count
        .checked_add(1)
        .ok_or(ReconcilerError::CorruptLedger("effect count overflow"))?;
    Ok(())
}

fn effect_key(operation_id: OperationId, step: u32) -> [u8; EFFECT_KEY_BYTES] {
    let mut key = [0_u8; EFFECT_KEY_BYTES];
    key[..OPERATION_KEY_BYTES].copy_from_slice(operation_id.as_bytes());
    key[OPERATION_KEY_BYTES..].copy_from_slice(&step.to_be_bytes());
    key
}

fn decode_operation_key(bytes: &[u8]) -> Result<OperationId, ReconcilerError> {
    let value: [u8; OPERATION_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("invalid operation key length"))?;
    if value == [0; OPERATION_KEY_BYTES] {
        return Err(ReconcilerError::CorruptLedger("zero operation identity"));
    }
    Ok(OperationId::from_bytes(value))
}

fn encode_operation(
    state: OperationState,
    effect_count: u32,
    ownership_gated: bool,
    runtime_intent_digest: Option<ObjectDigest>,
) -> Vec<u8> {
    encode_operation_record(OperationRecord {
        state,
        effect_count,
        ownership_gated,
        runtime_intent_digest,
        public_operation: None,
    })
}

fn encode_operation_record(operation: OperationRecord) -> Vec<u8> {
    let public = operation.public_operation;
    let mut bytes = Vec::with_capacity(if public.is_some() {
        OPERATION_RECORD_V2_BYTES
    } else {
        OPERATION_RECORD_V1_BYTES
    });
    bytes.push(if public.is_some() {
        RECORD_VERSION_V2
    } else {
        RECORD_VERSION_V1
    });
    bytes.push(operation.state as u8);
    bytes.push(
        u8::from(operation.ownership_gated) * OPERATION_FLAG_OWNERSHIP_GATED
            | u8::from(public.is_some()) * OPERATION_FLAG_PUBLIC,
    );
    bytes.push(0);
    bytes.extend_from_slice(&operation.effect_count.to_le_bytes());
    match operation.runtime_intent_digest {
        Some(digest) => bytes.extend_from_slice(digest.as_bytes()),
        None => bytes.extend_from_slice(&[0; OPERATION_RUNTIME_INTENT_DIGEST_BYTES]),
    }
    if let Some(public) = public {
        public.encode(&mut bytes);
    }
    bytes
}

fn decode_operation(bytes: &[u8]) -> Result<OperationRecord, ReconcilerError> {
    if bytes.len() != OPERATION_RECORD_V1_BYTES && bytes.len() != OPERATION_RECORD_V2_BYTES {
        return Err(ReconcilerError::CorruptLedger(
            "invalid operation record version, flags, or length",
        ));
    }
    let version = bytes[0];
    let state = OperationState::from_byte(bytes[1])?;
    let flags = bytes[2];
    let public = flags & OPERATION_FLAG_PUBLIC != 0;
    if bytes[3] != 0
        || flags & !(OPERATION_FLAG_OWNERSHIP_GATED | OPERATION_FLAG_PUBLIC) != 0
        || (version == RECORD_VERSION_V1 && (bytes.len() != OPERATION_RECORD_V1_BYTES || public))
        || (version == RECORD_VERSION_V2 && (bytes.len() != OPERATION_RECORD_V2_BYTES || !public))
        || !matches!(version, RECORD_VERSION_V1 | RECORD_VERSION_V2)
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid operation record version, flags, or length",
        ));
    }
    let effect_count = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid effect count"))?,
    );
    let ownership_gated = flags & OPERATION_FLAG_OWNERSHIP_GATED != 0;
    if effect_count as usize > MAXIMUM_EFFECTS
        || (effect_count == 0 && (state != OperationState::Succeeded || ownership_gated))
    {
        return Err(ReconcilerError::CorruptLedger("invalid effect count"));
    }
    if ownership_gated && effect_count as usize > MAXIMUM_GATED_EFFECTS {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership-gated effect count",
        ));
    }
    if state == OperationState::OwnershipPending && !ownership_gated {
        return Err(ReconcilerError::CorruptLedger(
            "ownership-pending operation lacks gated provenance",
        ));
    }
    let digest: [u8; OPERATION_RUNTIME_INTENT_DIGEST_BYTES] = bytes[8..40]
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("invalid runtime intent digest"))?;
    let runtime_intent_digest = (digest != [0; OPERATION_RUNTIME_INTENT_DIGEST_BYTES])
        .then(|| ObjectDigest::from_bytes(digest));
    if effect_count == 0 && runtime_intent_digest.is_some() {
        return Err(ReconcilerError::CorruptLedger(
            "completed local operation has runtime authority",
        ));
    }
    if runtime_intent_digest.is_some()
        && (!ownership_gated || effect_count as usize > MAXIMUM_GATED_EFFECTS - 1)
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid runtime operation provenance",
        ));
    }
    let public_operation = public
        .then(|| DurablePublicOperationV1::decode(&bytes[40..], state))
        .transpose()?;
    Ok(OperationRecord {
        state,
        effect_count,
        ownership_gated,
        runtime_intent_digest,
        public_operation,
    })
}

fn validate_claim_draft_context(
    claim: &OwnershipClaimV1,
    draft: &AuthorityPublicationDraftV1,
) -> Result<(), ReconcilerError> {
    let assignment = claim.assignment();
    let manifest = draft.manifest();
    let semantics = manifest.manifest();
    if assignment.sandbox() != semantics.sandbox()
        || assignment.incarnation() != semantics.incarnation()
        || assignment.epoch() != semantics.epoch()
        || assignment.digest() != manifest.digest()
        || claim.node() != semantics.node()
        || claim.desired_generation() != semantics.desired_generation()
    {
        return Err(ReconcilerError::InvalidPlan(
            "ownership claim does not match authority publication draft",
        ));
    }
    Ok(())
}

fn encode_ownership_gate(gate: &OwnershipGateStatusV1) -> Result<Vec<u8>, ReconcilerError> {
    let (state, plan, publication_digest, lease_generation, lease_digest) = match gate {
        OwnershipGateStatusV1::Pending(plan) => (1_u8, plan, [0; 32], 0, [0; 32]),
        OwnershipGateStatusV1::Activated {
            plan,
            publication_digest,
            lease_generation,
            lease_digest,
        } => (
            2,
            plan,
            *publication_digest.as_bytes(),
            *lease_generation,
            *lease_digest.as_bytes(),
        ),
    };
    let idempotency_length = u16::try_from(plan.idempotency_key.as_bytes().len())
        .map_err(|_| ReconcilerError::InvalidPlan("ownership idempotency key is too large"))?;
    let expected_authority = plan.expected_authority();
    let key_id = expected_authority.stable_key_id().as_str().as_bytes();
    let key_id_length = u16::try_from(key_id.len())
        .map_err(|_| ReconcilerError::InvalidPlan("ownership authority key ID is too large"))?;
    let draft_length = u32::try_from(plan.publication_draft.canonical_bytes().len())
        .map_err(|_| ReconcilerError::InvalidPlan("ownership publication draft is too large"))?;
    let capacity = 252_usize
        .checked_add(plan.idempotency_key.as_bytes().len())
        .and_then(|value| value.checked_add(key_id.len()))
        .and_then(|value| value.checked_add(CLAIM_BYTES))
        .and_then(|value| value.checked_add(plan.publication_draft.canonical_bytes().len()))
        .ok_or(ReconcilerError::InvalidPlan(
            "ownership gate length overflow",
        ))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(OWNERSHIP_GATE_MAGIC);
    bytes.extend_from_slice(&OWNERSHIP_GATE_VERSION.to_be_bytes());
    bytes.push(state);
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(plan.operation_id.as_bytes());
    bytes.extend_from_slice(&plan.request_digest);
    bytes.extend_from_slice(&idempotency_length.to_be_bytes());
    bytes.extend_from_slice(&key_id_length.to_be_bytes());
    bytes.extend_from_slice(&expected_authority.generation().to_be_bytes());
    bytes.extend_from_slice(expected_authority.public_key_sha256().as_bytes());
    bytes.extend_from_slice(&(CLAIM_BYTES as u32).to_be_bytes());
    bytes.extend_from_slice(&draft_length.to_be_bytes());
    bytes.extend_from_slice(plan.claim.digest().as_bytes());
    bytes.extend_from_slice(plan.publication_draft.digest().as_bytes());
    bytes.extend_from_slice(&publication_digest);
    bytes.extend_from_slice(&lease_generation.to_be_bytes());
    bytes.extend_from_slice(&lease_digest);
    bytes.extend_from_slice(plan.idempotency_key.as_bytes());
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(plan.claim.canonical_bytes());
    bytes.extend_from_slice(plan.publication_draft.canonical_bytes());
    Ok(bytes)
}

fn decode_ownership_gate(bytes: &[u8]) -> Result<OwnershipGateStatusV1, ReconcilerError> {
    let mut cursor = 0;
    if gate_take::<8>(bytes, &mut cursor)? != *OWNERSHIP_GATE_MAGIC
        || u16::from_be_bytes(gate_take::<2>(bytes, &mut cursor)?) != OWNERSHIP_GATE_VERSION
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate version",
        ));
    }
    let state = gate_take::<1>(bytes, &mut cursor)?[0];
    if gate_take::<5>(bytes, &mut cursor)? != [0; 5] {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate reserved bytes",
        ));
    }
    let operation_bytes = gate_take::<16>(bytes, &mut cursor)?;
    let request_digest = gate_take::<32>(bytes, &mut cursor)?;
    let idempotency_length = usize::from(u16::from_be_bytes(gate_take::<2>(bytes, &mut cursor)?));
    let key_id_length = usize::from(u16::from_be_bytes(gate_take::<2>(bytes, &mut cursor)?));
    let authority_generation = u64::from_be_bytes(gate_take::<8>(bytes, &mut cursor)?);
    let authority_fingerprint = gate_take::<32>(bytes, &mut cursor)?;
    let claim_length = usize::try_from(u32::from_be_bytes(gate_take::<4>(bytes, &mut cursor)?))
        .map_err(|_| ReconcilerError::CorruptLedger("ownership claim length overflow"))?;
    let draft_length = usize::try_from(u32::from_be_bytes(gate_take::<4>(bytes, &mut cursor)?))
        .map_err(|_| ReconcilerError::CorruptLedger("ownership draft length overflow"))?;
    let claim_digest = ObjectDigest::from_bytes(gate_take::<32>(bytes, &mut cursor)?);
    let draft_digest = ObjectDigest::from_bytes(gate_take::<32>(bytes, &mut cursor)?);
    let publication_digest = ObjectDigest::from_bytes(gate_take::<32>(bytes, &mut cursor)?);
    let lease_generation = u64::from_be_bytes(gate_take::<8>(bytes, &mut cursor)?);
    let lease_digest = ObjectDigest::from_bytes(gate_take::<32>(bytes, &mut cursor)?);
    if operation_bytes == [0; 16]
        || request_digest == [0; 32]
        || idempotency_length == 0
        || idempotency_length > 128
        || key_id_length == 0
        || key_id_length > 255
        || authority_generation == 0
        || authority_fingerprint == [0; 32]
        || claim_length != CLAIM_BYTES
        || draft_length == 0
        || draft_length > MAXIMUM_OWNERSHIP_DRAFT_BYTES
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate fields",
        ));
    }
    let expected_length = cursor
        .checked_add(idempotency_length)
        .and_then(|value| value.checked_add(key_id_length))
        .and_then(|value| value.checked_add(claim_length))
        .and_then(|value| value.checked_add(draft_length))
        .ok_or(ReconcilerError::CorruptLedger(
            "ownership gate length overflow",
        ))?;
    if expected_length != bytes.len() {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate length",
        ));
    }
    let idempotency = gate_slice(bytes, &mut cursor, idempotency_length)?;
    let key_id = std::str::from_utf8(gate_slice(bytes, &mut cursor, key_id_length)?)
        .map_err(|_| ReconcilerError::CorruptLedger("ownership key ID is not UTF-8"))?;
    let claim_bytes = gate_slice(bytes, &mut cursor, claim_length)?;
    let publication_draft_bytes = gate_slice(bytes, &mut cursor, draft_length)?;
    if cursor != bytes.len() {
        return Err(ReconcilerError::CorruptLedger(
            "trailing ownership gate bytes",
        ));
    }
    let claim = OwnershipClaimV1::from_canonical_bytes(claim_bytes)
        .map_err(|_| ReconcilerError::CorruptLedger("invalid canonical ownership claim"))?;
    if claim.canonical_bytes().as_slice() != claim_bytes || claim.digest() != claim_digest {
        return Err(ReconcilerError::CorruptLedger(
            "ownership claim digest mismatch",
        ));
    }
    let encoded_authority = KeyReference::new(
        StableKeyId::new(key_id.to_owned())
            .map_err(|_| ReconcilerError::CorruptLedger("invalid ownership authority key ID"))?,
        authority_generation,
        ObjectDigest::from_bytes(authority_fingerprint),
        KeyUsage::OwnershipLease,
    );
    let publication_draft =
        AuthorityPublicationDraftV1::from_canonical_bytes(publication_draft_bytes)
            .map_err(|_| ReconcilerError::CorruptLedger("invalid authority publication draft"))?;
    if publication_draft.canonical_bytes() != publication_draft_bytes
        || publication_draft.digest() != draft_digest
        || publication_draft.ownership_authority() != &encoded_authority
    {
        return Err(ReconcilerError::CorruptLedger(
            "ownership publication draft does not match gate metadata",
        ));
    }
    let plan = OwnershipGatePlanV1::new(
        OperationId::from_bytes(operation_bytes),
        IdempotencyKey::new(idempotency.to_vec())
            .map_err(|_| ReconcilerError::CorruptLedger("invalid ownership idempotency key"))?,
        request_digest,
        claim,
        publication_draft,
    )
    .map_err(|_| ReconcilerError::CorruptLedger("invalid ownership gate plan"))?;
    match state {
        1 if publication_digest.as_bytes() == &[0; 32]
            && lease_generation == 0
            && lease_digest.as_bytes() == &[0; 32] =>
        {
            Ok(OwnershipGateStatusV1::Pending(plan))
        }
        2 if publication_digest.as_bytes() != &[0; 32]
            && lease_generation != 0
            && lease_digest.as_bytes() != &[0; 32] =>
        {
            Ok(OwnershipGateStatusV1::Activated {
                plan,
                publication_digest,
                lease_generation,
                lease_digest,
            })
        }
        _ => Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate activation state",
        )),
    }
}

fn gate_take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], ReconcilerError> {
    gate_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("truncated ownership gate"))
}

fn gate_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], ReconcilerError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ReconcilerError::CorruptLedger(
            "ownership gate length overflow",
        ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ReconcilerError::CorruptLedger("truncated ownership gate"))?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::PathBuf;

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, BrokerMethod, RuntimeObservation, RuntimeState,
    };
    use aos_sandbox_core::{
        LeaseAssignment, NodeId, PrincipalId, ProjectId, RawClockProvenance, RawPairedClockSample,
        ResourceId, ResourceKind, Selector,
    };
    use buffa::Message as _;

    use super::*;
    use crate::BrokerDispatchAttemptV1;
    use crate::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1;
    use crate::journal::JournalLimits;
    use crate::publication::tests::{
        activation_claim, alternate_descriptor_free_activation_fixture,
        descriptor_free_activation_fixture, descriptor_free_launch_activation_fixture,
        descriptor_free_mount_activation_fixture, descriptor_host_activation_fixture,
        signed_guardian_plan,
    };
    use crate::publication::{
        AuthorityPublicationDraftV1, AuthorityPublicationError, AuthorityPublicationStore,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-reconciler-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("state.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct Executor {
        applied: BTreeMap<(OperationId, u32), EffectReceipt>,
        failures: VecDeque<EffectFailure>,
        apply_calls: usize,
        observe_calls: usize,
        timing_calls: usize,
        authority_pending: bool,
        authority_receipt_override: Option<ValidatedHostEffectReceiptV1>,
        guardian_plan_requests: Vec<GuardianPlanRequestV1>,
        guardian_plan_override: Option<SignedBrokerPlan>,
        host_boot_id: Option<[u8; 16]>,
    }

    fn host_receipt_bytes(prepared: &PreparedAuthorityEffectV1) -> Vec<u8> {
        let request = ApplyRuntimeRequest::decode_from_slice(prepared.attempt().body()).unwrap();
        let fence = request.fence.as_option().unwrap();
        let incarnation: [u8; 16] = fence.incarnation_id.as_slice().try_into().unwrap();
        let assignment_digest: [u8; 32] = fence.assignment_digest.as_slice().try_into().unwrap();
        let observation = RuntimeObservation {
            runtime_handle: aos_sandbox_protocol::semantics::host::runtime_handle_v1(
                &incarnation,
                fence.assignment_epoch,
                &assignment_digest,
            )
            .to_vec(),
            state: RuntimeState::RUNTIME_STATE_READY.into(),
            observation_sequence: 1,
            fence: Some(fence.clone()).into(),
            ..Default::default()
        };
        observation.encode_to_vec()
    }

    fn host_receipt(prepared: &PreparedAuthorityEffectV1) -> ValidatedHostEffectReceiptV1 {
        prepared
            .validate_host_receipt(host_receipt_bytes(prepared))
            .unwrap()
    }

    impl SingleNodeEffectExecutor for Executor {
        fn authority_effect_timing(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
        ) -> Option<AuthorityEffectAttemptTimingV1> {
            self.timing_calls += 1;
            let provenance = RawClockProvenance::new_untrusted([0x91; 16]).unwrap();
            let clock = RawPairedClockSample::new_untrusted(
                provenance,
                self.host_boot_id.unwrap_or([0x92; 16]),
                150,
                1_000,
            )
            .unwrap();
            Some(AuthorityEffectAttemptTimingV1::new(clock, 2_000))
        }

        fn prepare_guardian_plan(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            request: &GuardianPlanRequestV1,
        ) -> Option<SignedBrokerPlan> {
            self.guardian_plan_requests.push(request.clone());
            self.guardian_plan_override
                .clone()
                .or_else(|| Some(signed_guardian_plan(request)))
        }

        fn observe(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            self.observe_calls += 1;
            Ok(self
                .applied
                .get(&(operation_id, step))
                .cloned()
                .map_or(EffectObservation::Absent, EffectObservation::Applied))
        }

        fn apply(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            self.apply_calls += 1;
            if let Some(failure) = self.failures.pop_front() {
                return Err(failure);
            }
            let receipt = EffectReceipt::new(vec![step as u8 + 1]).unwrap();
            self.applied.insert((operation_id, step), receipt.clone());
            Ok(receipt)
        }

        fn observe_authority(
            &mut self,
            operation_id: OperationId,
            step: u32,
            prepared: &PreparedAuthorityEffectV1,
        ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
            self.observe_calls += 1;
            Ok(if self.authority_pending {
                AuthorityEffectObservationV1::Pending
            } else if self.applied.contains_key(&(operation_id, step)) {
                AuthorityEffectObservationV1::Applied(
                    self.authority_receipt_override
                        .take()
                        .unwrap_or_else(|| host_receipt(prepared)),
                )
            } else {
                AuthorityEffectObservationV1::Absent
            })
        }

        fn apply_authority(
            &mut self,
            operation_id: OperationId,
            step: u32,
            prepared: &PreparedAuthorityEffectV1,
        ) -> Result<ValidatedHostEffectReceiptV1, EffectFailure> {
            self.apply_calls += 1;
            if let Some(failure) = self.failures.pop_front() {
                return Err(failure);
            }
            let receipt = EffectReceipt::new(vec![step as u8 + 1]).unwrap();
            self.applied.insert((operation_id, step), receipt);
            Ok(self
                .authority_receipt_override
                .take()
                .unwrap_or_else(|| host_receipt(prepared)))
        }
    }

    struct CanceledControllerExecutor;

    impl SingleNodeEffectExecutor for CanceledControllerExecutor {
        fn observe(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            Err(EffectFailure::Permanent(
                "controller effect used the broker hook".to_owned(),
            ))
        }

        fn apply(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            Err(EffectFailure::Permanent(
                "controller effect used the broker hook".to_owned(),
            ))
        }

        fn observe_controller(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
            _journal: &mut Journal,
        ) -> Result<EffectObservation, EffectFailure> {
            Ok(EffectObservation::Absent)
        }

        fn apply_controller(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
            _journal: &mut Journal,
        ) -> Result<EffectReceipt, EffectFailure> {
            Ok(EffectReceipt::canceled_before_commit(
                ObjectDigest::from_bytes([0xc7; 32]),
            ))
        }
    }

    fn operation() -> OperationPlan {
        OperationPlan::new(
            OperationId::from_bytes([0x44; 16]),
            IdempotencyKey::new(b"request".to_vec()).unwrap(),
            [0x55; 32],
            b"sandbox".to_vec(),
            b"running".to_vec(),
            vec![
                EffectPlan::new(
                    EffectDomain::Storage,
                    BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
                    b"create".to_vec(),
                )
                .unwrap(),
                EffectPlan::new(
                    EffectDomain::Host,
                    BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                    b"start".to_vec(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn public_operation_authorization() -> PublicOperationAuthorizationV1 {
        PublicOperationAuthorizationV1::new(
            ProjectId::from_bytes([0x91; 16]),
            ResourceKind::Sandbox,
            Selector::Resource {
                resource: ResourceId::from_bytes([0x92; 16]),
            },
        )
        .unwrap()
    }

    fn cancelable_controller_operation() -> OperationPlan {
        use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
        use crate::controller_query::PublicOperationMethodV1;
        use aos_proto::aos::sandbox::v1::{MutationContext, SandboxLifecycleRequest};

        let request = SandboxLifecycleRequest {
            sandbox_id: vec![0x92; 16],
            mutation: Some(MutationContext {
                idempotency_key: b"cancelable-controller-operation".to_vec(),
                expected_resource_version: vec![0x94],
                operation_timeout: Some(aos_proto::aos::sandbox::v1::Duration {
                    nanoseconds: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let envelope = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::StartSandbox,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode();
        let effect = EffectPlan::authorized_public_mutation(
            PublicOperationMethodV1::StartSandbox,
            PublicMutationEffectV1::new(
                PrincipalId::from_bytes([0x93; 16]),
                ProjectId::from_bytes([0x91; 16]),
                100,
                envelope,
            )
            .unwrap(),
        )
        .unwrap();

        OperationPlan::new(
            OperationId::from_bytes([0xc1; 16]),
            IdempotencyKey::new(b"cancelable-controller-operation".to_vec()).unwrap(),
            [0xc2; 32],
            b"controller-operation".to_vec(),
            b"accepted".to_vec(),
            vec![effect],
        )
        .unwrap()
        .with_public_operation(
            PublicOperationAdmissionV1::new(
                PublicOperationMethodV1::StartSandbox,
                7,
                [0xc3; 16],
                100,
                public_operation_authorization(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn gated_operation_with_publication(
        lease_generation: u64,
    ) -> (
        OperationPlan,
        AuthorityPublicationDraftV1,
        crate::publication::PreparedAuthorityPublicationV1,
    ) {
        let (draft, prepared) = descriptor_free_activation_fixture(lease_generation);
        let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
        let plan = OperationPlan::ownership_gated(
            OperationId::from_bytes([0x31; 16]),
            IdempotencyKey::new(b"gated-request".to_vec()).unwrap(),
            [0x32; 32],
            b"gated-sandbox".to_vec(),
            b"pending-ownership".to_vec(),
            vec![effect],
            activation_claim(&draft, lease_generation),
            draft.clone(),
        )
        .unwrap();
        (plan, draft, prepared)
    }

    fn gated_operation() -> OperationPlan {
        gated_operation_with_publication(1).0
    }

    fn gated_launch_operation_with_publication(
        lease_generation: u64,
    ) -> (
        OperationPlan,
        AuthorityPublicationDraftV1,
        crate::publication::PreparedAuthorityPublicationV1,
    ) {
        let (draft, prepared) = descriptor_free_launch_activation_fixture(lease_generation);
        let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
        let plan = OperationPlan::ownership_gated(
            OperationId::from_bytes([0x35; 16]),
            IdempotencyKey::new(b"guardian-gated-launch".to_vec()).unwrap(),
            [0x36; 32],
            b"guardian-gated-sandbox".to_vec(),
            b"pending-launch".to_vec(),
            vec![effect],
            activation_claim(&draft, lease_generation),
            draft.clone(),
        )
        .unwrap();
        (plan, draft, prepared)
    }

    fn gate_activation(
        reconciler: &mut Reconciler<Executor>,
        draft: &AuthorityPublicationDraftV1,
        prepared: &crate::publication::PreparedAuthorityPublicationV1,
    ) -> AuthorityPublicationActivationV1 {
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .prepare_gate_activation(draft, prepared)
            .unwrap()
    }

    fn protected_runtime_journal(directory: &TestDirectory) -> Journal {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            &directory.0,
            "state.journal",
            JournalLimits::default(),
            fs::metadata(&directory.0).unwrap().uid(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn opaque_legacy_effect_is_blocked_before_executor_io() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let operation = operation();
        reconciler.accept(&operation).unwrap();

        let legacy = EffectLedgerRecord {
            plan: EffectPlan {
                domain: EffectDomain::Storage,
                method: None,
                controller_method: None,
                request: b"legacy".to_vec(),
                authority: None,
            },
            state: EffectState::Planned,
            dispatch: None,
        };
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xa7; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Effect,
                        effect_key(operation.operation_id(), 0).to_vec(),
                        encode_effect(&legacy).unwrap(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            reconciler.reconcile_once(operation.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reconciler.reconcile_once(operation.operation_id()).unwrap(),
            ReconcileOutcome::PermanentlyBlocked
        );
        assert_eq!(reconciler.executor.observe_calls, 0);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn runtime_holder_admission_activation_and_reopen_retain_exact_intent() {
        use aos_sandbox_core::PrincipalId;
        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let holder = PrincipalId::from_bytes([0x91; 16]);
        let intent = RuntimeAuthorityIntentV1::bind_holder(holder, None).unwrap();
        let plan = plan.with_runtime_authority(intent).unwrap();
        let sandbox = draft.manifest().manifest().sandbox();
        reconciler.accept(&plan).unwrap();
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .count(),
            1
        );
        assert_eq!(
            reconciler
                .load_operation(plan.operation_id())
                .unwrap()
                .runtime_intent_digest,
            Some(intent.digest())
        );
        assert!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .is_none()
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::OwnershipPending
        );

        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        let binding = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(binding.holder(), Some(holder));
        assert_eq!(binding.manifest(), draft.manifest());
        assert_eq!(binding.publication_digest(), prepared.digest());
        assert_eq!(binding.revision(), 1);
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .count(),
            3
        );
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        assert_eq!(
            reconciler
                .load_operation(plan.operation_id())
                .unwrap()
                .runtime_intent_digest,
            Some(intent.digest())
        );
        drop(reconciler);

        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Replay(plan.operation_id())
        );
        let recovered = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(recovered, binding);
    }

    #[test]
    fn runtime_intent_rejects_unprotected_admission_and_missing_recovery_links() {
        use aos_sandbox_core::PrincipalId;
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, _, _) = gated_operation_with_publication(1);
        let plan = plan
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x92; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.accept(&plan),
            Err(ReconcilerError::RuntimeAuthority(_))
        ));
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::Operation)
                .count(),
            0
        );
        drop(reconciler);

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        reconciler.accept(&plan).unwrap();
        let pending_key = reconciler
            .journal
            .records(RecordNamespace::RuntimeAuthority)
            .next()
            .unwrap()
            .0
            .to_vec();
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xa1; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::RuntimeAuthority,
                        pending_key,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(reconciler.accept(&plan).is_err());
        assert_eq!(reconciler.executor.apply_calls, 0);

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        reconciler.accept(&plan).unwrap();
        let mut operation = reconciler
            .journal
            .get(RecordNamespace::Operation, plan.operation_id().as_bytes())
            .unwrap()
            .to_vec();
        operation[8..].fill(0);
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xa2; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        plan.operation_id().into_bytes().to_vec(),
                        operation,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        let error = reconciler.accept(&plan).unwrap_err();
        assert!(matches!(
            error,
            ReconcilerError::RuntimeAuthority(
                crate::runtime_authority::RuntimeAuthorityError::CorruptState
            )
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn runtime_activation_rechecks_admitted_revision_without_partial_publication() {
        use aos_sandbox_core::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (first, draft, prepared) = gated_operation_with_publication(1);
        let first = first
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x93; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        let second = OperationPlan::ownership_gated(
            OperationId::from_bytes([0x94; 16]),
            IdempotencyKey::new(b"competing-runtime-intent".to_vec()).unwrap(),
            [0x95; 32],
            b"same-sandbox".to_vec(),
            b"competing-holder".to_vec(),
            vec![draft.bind_effect(draft.templates()[0].digest()).unwrap()],
            activation_claim(&draft, 1),
            draft.clone(),
        )
        .unwrap()
        .with_runtime_authority(
            RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x96; 16]), None)
                .unwrap(),
        )
        .unwrap();
        reconciler.accept(&first).unwrap();
        reconciler.accept(&second).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(first.operation_id(), activation)
            .unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        assert!(matches!(
            reconciler.activate_ownership_gate(second.operation_id(), activation),
            Err(ReconcilerError::RuntimeAuthority(
                crate::runtime_authority::RuntimeAuthorityError::CompareAndSwap
            ))
        ));
        assert!(matches!(
            reconciler.ownership_gate(second.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Pending(_))
        ));
        let current = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(draft.manifest().manifest().sandbox())
        .unwrap()
        .unwrap();
        assert_eq!(current.operation(), first.operation_id());
        assert_eq!(current.revision(), 1);
    }

    #[test]
    fn runtime_stop_revocation_commits_tombstone_before_executor_io_and_survives_reopen() {
        use aos_sandbox_core::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (bound, first_draft, first_prepared) = gated_operation_with_publication(1);
        let bound = bound
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0xb1; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        reconciler.accept(&bound).unwrap();
        let activation = gate_activation(&mut reconciler, &first_draft, &first_prepared);
        reconciler
            .activate_ownership_gate(bound.operation_id(), activation)
            .unwrap();

        let (draft, prepared) = descriptor_free_activation_fixture(2);
        let revoke = OperationPlan::ownership_gated(
            OperationId::from_bytes([0xb2; 16]),
            IdempotencyKey::new(b"revoke-holder".to_vec()).unwrap(),
            [0xb3; 32],
            b"runtime".to_vec(),
            b"stop".to_vec(),
            vec![draft.bind_effect(draft.templates()[0].digest()).unwrap()],
            activation_claim(&draft, 2),
            draft.clone(),
        )
        .unwrap()
        .with_runtime_authority(RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap())
        .unwrap();
        reconciler.accept(&revoke).unwrap();
        assert_eq!(
            reconciler.reconcile_once(revoke.operation_id()).unwrap(),
            ReconcileOutcome::OwnershipPending
        );
        let sandbox = draft.manifest().manifest().sandbox();
        assert_eq!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap()
            .state(),
            RuntimeAuthorityStateV1::Bound
        );
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(revoke.operation_id(), activation)
            .unwrap();
        let tombstone = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(tombstone.state(), RuntimeAuthorityStateV1::Revoked);
        assert_eq!(tombstone.holder(), None);
        assert_eq!(tombstone.revision(), 2);
        assert_eq!(tombstone.publication_digest(), prepared.digest());
        assert_eq!(reconciler.executor.apply_calls, 0);
        drop(reconciler);
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert_eq!(
            reconciler.accept(&revoke).unwrap(),
            AcceptOutcome::Replay(revoke.operation_id())
        );
        assert_eq!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap(),
            tombstone
        );
    }

    #[test]
    fn runtime_revocation_rejects_other_signed_actions_and_multiple_stop_effects() {
        use crate::publication::tests::descriptor_free_control_activation_fixture;
        use aos_proto::aos::sandbox::local::v1::RuntimeAction;
        for action in [
            RuntimeAction::RUNTIME_ACTION_FREEZE,
            RuntimeAction::RUNTIME_ACTION_THAW,
            RuntimeAction::RUNTIME_ACTION_KILL,
            RuntimeAction::RUNTIME_ACTION_STOP,
        ] {
            let (draft, _) = descriptor_free_control_activation_fixture(2, action);
            let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
            let effects = if action == RuntimeAction::RUNTIME_ACTION_STOP {
                vec![effect.clone(), effect]
            } else {
                vec![effect]
            };
            let plan = OperationPlan::ownership_gated(
                OperationId::from_bytes([0xb4; 16]),
                IdempotencyKey::new(b"wrong-revoke".to_vec()).unwrap(),
                [0xb5; 32],
                b"runtime".to_vec(),
                b"stop".to_vec(),
                effects,
                activation_claim(&draft, 2),
                draft,
            )
            .unwrap();
            assert!(
                matches!(
                    plan.with_runtime_authority(RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap()),
                    Err(ReconcilerError::InvalidPlan(_))
                ),
                "{action:?}"
            );
        }
    }

    #[test]
    fn runtime_revocation_cannot_stop_a_replacement_assignment_instead_of_current() {
        use aos_sandbox_core::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (bound, draft, prepared) = gated_operation_with_publication(1);
        let bound = bound
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0xb6; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        reconciler.accept(&bound).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(bound.operation_id(), activation)
            .unwrap();
        let replacement = crate::publication::tests::descriptor_free_stop_draft_with_node(99);
        assert_eq!(
            replacement.manifest().manifest().sandbox(),
            draft.manifest().manifest().sandbox()
        );
        assert_ne!(replacement.manifest(), draft.manifest());
        let revoke = OperationPlan::ownership_gated(
            OperationId::from_bytes([0xb7; 16]),
            IdempotencyKey::new(b"wrong-runtime-stop".to_vec()).unwrap(),
            [0xb8; 32],
            b"runtime".to_vec(),
            b"stop".to_vec(),
            vec![
                replacement
                    .bind_effect(replacement.templates()[0].digest())
                    .unwrap(),
            ],
            activation_claim(&replacement, 2),
            replacement,
        )
        .unwrap()
        .with_runtime_authority(RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap())
        .unwrap();
        assert!(matches!(
            reconciler.accept(&revoke),
            Err(ReconcilerError::RuntimeAuthority(
                crate::runtime_authority::RuntimeAuthorityError::ActivationConflict
            ))
        ));
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::Operation)
                .count(),
            1
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn runtime_recovery_rejects_removal_of_activated_binding_and_head() {
        use aos_sandbox_core::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let plan = plan
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x97; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        let deletions = reconciler
            .journal
            .records(RecordNamespace::RuntimeAuthority)
            .filter(|(key, _)| !key.starts_with(b"pending/"))
            .map(|(key, _)| JournalRecord::delete(RecordNamespace::RuntimeAuthority, key.to_vec()))
            .collect();
        reconciler
            .journal_mut()
            .commit(&JournalTransaction::new([0xa2; 16], deletions).unwrap())
            .unwrap();
        assert!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .is_err()
        );
        assert!(reconciler.accept(&plan).is_err());
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn runtime_successor_preserves_history_and_historical_replay_cannot_repoint_head() {
        use aos_sandbox_core::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let mut first = None;
        for generation in 1..=2_u8 {
            let (_, draft, prepared) = gated_operation_with_publication(u64::from(generation));
            let plan = OperationPlan::ownership_gated(
                OperationId::from_bytes([generation; 16]),
                IdempotencyKey::new(vec![generation]).unwrap(),
                [generation; 32],
                b"runtime".to_vec(),
                vec![generation],
                vec![draft.bind_effect(draft.templates()[0].digest()).unwrap()],
                activation_claim(&draft, u64::from(generation)),
                draft.clone(),
            )
            .unwrap()
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(
                    PrincipalId::from_bytes([generation + 10; 16]),
                    (generation > 1).then_some(u64::from(generation - 1)),
                )
                .unwrap(),
            )
            .unwrap();
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            if generation == 1 {
                first = Some((plan, draft, prepared));
            }
        }
        let (first, draft, prepared) = first.unwrap();
        let sandbox = draft.manifest().manifest().sandbox();
        let head = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(head.revision(), 2);
        assert_eq!(head.holder(), Some(PrincipalId::from_bytes([12; 16])));
        let replay = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(first.operation_id(), replay)
                .unwrap(),
            OwnershipGateActivationOutcome::Replay
        );
        assert_eq!(
            reconciler.accept(&first).unwrap(),
            AcceptOutcome::Replay(first.operation_id())
        );
        assert_eq!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap(),
            head
        );
        let mut substituted = first;
        substituted.runtime_authority = Some(
            RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([99; 16]), None).unwrap(),
        );
        assert!(matches!(
            reconciler.accept(&substituted),
            Err(ReconcilerError::IdempotencyConflict)
        ));
    }

    #[test]
    fn poisoned_journal_blocks_replay_and_all_executor_io_even_with_cached_validation() {
        for authority_bound in [false, true] {
            for cached_validation in [false, true] {
                let directory = TestDirectory::new();
                let (journal, _) =
                    Journal::open(directory.journal(), JournalLimits::default()).unwrap();
                let mut reconciler = Reconciler::new(journal, Executor::default());
                let plan = if authority_bound {
                    let (plan, draft, prepared) = gated_operation_with_publication(1);
                    reconciler.accept(&plan).unwrap();
                    let activation = gate_activation(&mut reconciler, &draft, &prepared);
                    reconciler
                        .activate_ownership_gate(plan.operation_id(), activation)
                        .unwrap();
                    plan
                } else {
                    let plan = operation();
                    reconciler.accept(&plan).unwrap();
                    plan
                };
                assert_eq!(
                    reconciler.reconcile_once(plan.operation_id()).unwrap(),
                    ReconcileOutcome::Progressed
                );
                assert_eq!(reconciler.executor.observe_calls, 0);

                // A directory at the exact temporary-file name forces the
                // real compaction I/O failure path, leaving diagnostic state.
                fs::create_dir(directory.0.join("state.journal.compact.tmp")).unwrap();
                assert!(matches!(
                    reconciler.journal.compact(),
                    Err(JournalError::Io(_))
                ));
                reconciler.ledger_validated = cached_validation;

                assert!(matches!(
                    reconciler.accept(&plan),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert!(matches!(
                    reconciler.ownership_gate(plan.operation_id()),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert!(matches!(
                    reconciler.reconcile_once(plan.operation_id()),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert!(matches!(
                    reconciler.reconcile_next(),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert_eq!(reconciler.executor.observe_calls, 0);
                assert_eq!(reconciler.executor.apply_calls, 0);
            }
        }
    }

    #[test]
    fn admission_is_atomic_and_exact_replay_is_idempotent() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Accepted(plan.operation_id())
        );
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Replay(plan.operation_id())
        );
    }

    #[test]
    fn operator_abandon_acknowledgment_cannot_be_replaced() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let target = OperationId::from_bytes([3; 16]);
        let plan = |identity: u8, idempotency: &'static [u8]| {
            let operation = OperationId::from_bytes([identity; 16]);
            let acknowledgment = crate::operator_abandon_ack::record_v1(
                operation,
                target,
                aos_sandbox_core::PrincipalId::from_bytes([4; 16]),
                aos_sandbox_core::ProjectId::from_bytes([5; 16]),
                idempotency,
                [6; 32],
                ObjectDigest::from_bytes([7; 32]),
                b"version",
            )
            .unwrap();
            OperationPlan::completed_operator_abandon(
                operation,
                target,
                IdempotencyKey::new(idempotency.to_vec()).unwrap(),
                [6; 32],
                vec![identity],
                b"desired".to_vec(),
                acknowledgment,
            )
            .unwrap()
        };
        let first = plan(1, b"first");
        let second = plan(2, b"second");

        assert_eq!(
            reconciler.accept(&first).unwrap(),
            AcceptOutcome::Accepted(first.operation_id())
        );
        assert_eq!(
            reconciler.accept(&first).unwrap(),
            AcceptOutcome::Replay(first.operation_id())
        );
        assert!(matches!(
            reconciler.accept(&second),
            Err(ReconcilerError::IdempotencyConflict)
        ));
    }

    #[test]
    fn unfinished_operation_audit_preserves_accepted_journal_and_executor_state() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        let before = fs::read(&path).unwrap();
        let before_length = fs::metadata(&path).unwrap().len();

        let unfinished = reconciler
            .validated_unfinished_operation()
            .unwrap()
            .unwrap();

        assert_eq!(unfinished.operation_id(), plan.operation_id());
        assert_eq!(unfinished.state(), UnfinishedOperationStateV1::Accepted);
        assert_eq!(fs::metadata(&path).unwrap().len(), before_length);
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(reconciler.executor.timing_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 0);
        assert_eq!(reconciler.executor.observe_calls, 0);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn unfinished_operation_audit_preserves_authority_applying_journal_without_executor_calls() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        reconciler.executor.timing_calls = 0;
        reconciler.executor.guardian_plan_requests.clear();
        reconciler.executor.observe_calls = 0;
        reconciler.executor.apply_calls = 0;
        reconciler.ledger_validated = false;
        let before = fs::read(&path).unwrap();
        let before_length = fs::metadata(&path).unwrap().len();

        let unfinished = reconciler
            .validated_unfinished_operation()
            .unwrap()
            .unwrap();

        assert_eq!(unfinished.operation_id(), plan.operation_id());
        assert_eq!(unfinished.state(), UnfinishedOperationStateV1::Applying);
        assert_eq!(fs::metadata(&path).unwrap().len(), before_length);
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(reconciler.executor.timing_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 0);
        assert_eq!(reconciler.executor.observe_calls, 0);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn unfinished_operation_audit_includes_ownership_pending() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = gated_operation();
        reconciler.accept(&plan).unwrap();

        let unfinished = reconciler
            .validated_unfinished_operation()
            .unwrap()
            .unwrap();

        assert_eq!(unfinished.operation_id(), plan.operation_id());
        assert_eq!(
            unfinished.state(),
            UnfinishedOperationStateV1::OwnershipPending
        );
        assert_eq!(reconciler.executor.timing_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 0);
        assert_eq!(reconciler.executor.observe_calls, 0);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn ownership_gate_admission_replay_and_restart_are_exact() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (plan, draft, _) = gated_operation_with_publication(1);
        let claim = activation_claim(&draft, 1);
        {
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            assert_eq!(
                reconciler.accept(&plan).unwrap(),
                AcceptOutcome::Accepted(plan.operation_id())
            );
            assert_eq!(
                reconciler.accept(&plan).unwrap(),
                AcceptOutcome::Replay(plan.operation_id())
            );
            assert_eq!(
                reconciler.reconcile_once(plan.operation_id()).unwrap(),
                ReconcileOutcome::OwnershipPending
            );
            assert_eq!(reconciler.executor.apply_calls, 0);
        }

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gate = reconciler
            .ownership_gate(plan.operation_id())
            .unwrap()
            .unwrap();
        let OwnershipGateStatusV1::Pending(recovered) = gate else {
            panic!("recovered gate was activated");
        };
        assert_eq!(recovered.claim(), &claim);
        assert_eq!(recovered.publication_draft(), &draft);
        assert_eq!(recovered.publication_draft_digest(), draft.digest());
        assert!(reconciler.reconcile_next().unwrap().is_none());
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn authority_effect_values_are_bound_to_operation_and_step_keys() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (draft, _) = descriptor_free_activation_fixture(1);
        let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
        let operation_id = OperationId::from_bytes([0xc1; 16]);
        let plan = OperationPlan::ownership_gated(
            operation_id,
            IdempotencyKey::new(b"location-bound-effects".to_vec()).unwrap(),
            [0xc2; 32],
            b"location-sandbox".to_vec(),
            b"pending".to_vec(),
            vec![effect.clone(), effect],
            activation_claim(&draft, 1),
            draft,
        )
        .unwrap();
        reconciler.accept(&plan).unwrap();
        let first_key = effect_key(operation_id, 0);
        let second_key = effect_key(operation_id, 1);
        let first = reconciler
            .journal
            .get(RecordNamespace::Effect, &first_key)
            .unwrap()
            .to_vec();
        let second = reconciler
            .journal
            .get(RecordNamespace::Effect, &second_key)
            .unwrap()
            .to_vec();
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xc3; 16],
                    vec![
                        JournalRecord::put(RecordNamespace::Effect, first_key.to_vec(), second),
                        JournalRecord::put(RecordNamespace::Effect, second_key.to_vec(), first),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.ownership_gate(operation_id),
            Err(ReconcilerError::CorruptLedger(_))
        ));
    }

    #[test]
    fn ownership_gate_activation_commits_publication_and_release_atomically() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let publication = prepared.digest();
        let lease_generation = prepared.lease_generation();
        let lease = prepared.lease_digest();
        {
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            assert_eq!(
                reconciler
                    .activate_ownership_gate(plan.operation_id(), activation)
                    .unwrap(),
                OwnershipGateActivationOutcome::Activated
            );
        }

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let current = AuthorityPublicationStore::new(reconciler.journal_mut())
            .current(draft.manifest().manifest().sandbox())
            .unwrap()
            .unwrap();
        assert_eq!(current.digest(), publication);
        assert!(matches!(
            reconciler.ownership_gate(plan.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Activated {
                publication_digest,
                lease_generation: recovered_generation,
                lease_digest,
                ..
            }) if publication_digest == publication
                && recovered_generation == lease_generation
                && lease_digest == lease
        ));
        let replay = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(plan.operation_id(), replay)
                .unwrap(),
            OwnershipGateActivationOutcome::Replay
        );
        let (changed_draft, changed_prepared) = descriptor_free_activation_fixture(2);
        let conflicting = gate_activation(&mut reconciler, &changed_draft, &changed_prepared);
        assert!(matches!(
            reconciler.activate_ownership_gate(plan.operation_id(), conflicting),
            Err(ReconcilerError::OwnershipActivationConflict)
        ));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn protected_gate_read_requires_validated_activation_publication() {
        let directory = TestDirectory::new();
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let plan = plan
            .with_public_operation(
                PublicOperationAdmissionV1::new(
                    crate::controller_query::PublicOperationMethodV1::StartSandbox,
                    1,
                    [0x41; 16],
                    100,
                    public_operation_authorization(),
                )
                .unwrap(),
            )
            .unwrap();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        reconciler.accept(&plan).unwrap();
        assert_eq!(
            activated_ownership_gate_digest_from_journal_v1(
                &reconciler.journal,
                plan.operation_id(),
            )
            .unwrap(),
            None,
        );
        let operation =
            recovered_public_operation_resource_v1(&reconciler.journal, plan.operation_id())
                .unwrap()
                .unwrap();
        let checked =
            crate::controller_query::CheckedOperationResourceV1::try_from(operation).unwrap();
        let recovery = crate::controller::prepare_operator_recovery_operation_current_v1(
            &reconciler.journal,
            &checked,
        )
        .unwrap()
        .into_record();
        assert_eq!(recovery.value().unwrap()[1] & 1, 1);

        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate_at(plan.operation_id(), activation, 101)
            .unwrap();
        assert_eq!(
            activated_ownership_gate_digest_from_journal_v1(
                &reconciler.journal,
                plan.operation_id(),
            )
            .unwrap(),
            Some(prepared.digest()),
        );
    }

    #[test]
    fn host_launch_signs_after_lease_selection_and_refreshes_before_absent_retry() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();

        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 1);
        let first_request = reconciler.executor.guardian_plan_requests[0].clone();
        assert_eq!(first_request.lease_generation(), 1);
        assert_eq!(first_request.lease_digest(), prepared.lease_digest());
        let first_record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let first_dispatch = first_record.dispatch.as_ref().unwrap();
        assert_eq!(first_dispatch.attempt().lease_generation(), 1);
        let first_companion = aos_sandbox_protocol::decode_host_guardian_companion_v1(
            first_dispatch.attempt().body(),
        )
        .unwrap();
        assert_eq!(
            first_companion.broker_plan(),
            signed_guardian_plan(&first_request).canonical_plan(),
        );

        reconciler
            .executor
            .failures
            .push_back(EffectFailure::Retryable("transport lost".to_owned()));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        assert_eq!(reconciler.executor.apply_calls, 1);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 2);

        let (_, renewed) = descriptor_free_launch_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("guardian-launch-renewal").unwrap(),
                OperationId::new(),
                [0xd8; 16],
            )
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        let renewed_request = reconciler.executor.guardian_plan_requests.last().unwrap();
        assert_eq!(renewed_request.lease_generation(), 2);
        assert_eq!(renewed_request.lease_digest(), renewed.lease_digest());
        assert_ne!(renewed_request.lease_digest(), first_request.lease_digest());
        let applied = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let applied_dispatch = applied.dispatch.as_ref().unwrap();
        assert_eq!(applied_dispatch.attempt().lease_generation(), 2);
        let renewed_companion = aos_sandbox_protocol::decode_host_guardian_companion_v1(
            applied_dispatch.attempt().body(),
        )
        .unwrap();
        assert_eq!(
            renewed_companion.broker_plan(),
            signed_guardian_plan(renewed_request).canonical_plan(),
        );
        assert_ne!(
            renewed_companion.broker_plan(),
            first_companion.broker_plan(),
        );
    }

    #[test]
    fn renewed_host_launch_rejects_a_stale_guardian_plan_before_apply() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let stale_guardian = signed_guardian_plan(&reconciler.executor.guardian_plan_requests[0]);
        let effect_key = effect_key(plan.operation_id(), 0);
        let before = reconciler
            .journal
            .get(RecordNamespace::Effect, &effect_key)
            .unwrap()
            .to_vec();

        let (_, renewed) = descriptor_free_launch_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("stale-guardian-renewal").unwrap(),
                OperationId::new(),
                [0xd9; 16],
            )
            .unwrap();
        reconciler.executor.guardian_plan_override = Some(stale_guardian);
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::AuthorityPublication(
                AuthorityPublicationError::DispatchAttempt(
                    crate::BrokerDispatchAttemptError::GuardianPlanMismatch
                        | crate::BrokerDispatchAttemptError::GuardianContextMismatch
                )
            ))
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
        assert_eq!(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key)
                .unwrap(),
            before,
        );
    }

    #[test]
    fn durable_host_launch_rejects_body_packet_and_boot_substitution_before_io() {
        for mutation in ["body", "packet", "boot"] {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            reconciler.reconcile_once(plan.operation_id()).unwrap();

            let effect_key = effect_key(plan.operation_id(), 0);
            let mut record = decode_effect(
                reconciler
                    .journal
                    .get(RecordNamespace::Effect, &effect_key)
                    .unwrap(),
            )
            .unwrap();
            let durable = record.dispatch.as_ref().unwrap();
            let mut body = durable.attempt().body().to_vec();
            let mut packet = durable.attempt().packet().to_vec();
            let mut host_boot_id = durable.preparation_host_boot_id();
            match mutation {
                "body" => *body.last_mut().unwrap() ^= 1,
                "packet" => *packet.last_mut().unwrap() ^= 1,
                "boot" => host_boot_id = [0x93; 16],
                _ => unreachable!(),
            }
            let substituted = BrokerDispatchAttemptV1::from_durable_parts(
                durable.attempt().template_digest(),
                durable.attempt().lease_digest(),
                durable.attempt().lease_generation(),
                durable.attempt().deadline_boottime_nanoseconds(),
                body,
                packet,
            );
            record.dispatch = Some(PreparedAuthorityEffectV1::from_durable_parts(
                durable.binding_digest(),
                durable.publication_digest(),
                durable.preparation_wall_seconds(),
                durable.preparation_boottime_nanoseconds(),
                host_boot_id,
                substituted,
            ));
            let replacement = JournalRecord::put(
                RecordNamespace::Effect,
                effect_key.to_vec(),
                encode_effect(&record).unwrap(),
            );
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        match mutation {
                            "body" => [0xe1; 16],
                            "packet" => [0xe2; 16],
                            "boot" => [0xe3; 16],
                            _ => unreachable!(),
                        },
                        vec![replacement],
                    )
                    .unwrap(),
                )
                .unwrap();

            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.observe_calls, 0, "{mutation}");
            assert_eq!(reconciler.executor.apply_calls, 0, "{mutation}");
        }
    }

    #[test]
    fn completed_v1_host_launch_remains_historical_after_reboot() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        let apply_calls = reconciler.executor.apply_calls;

        reconciler.executor.host_boot_id = Some([0x93; 16]);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Succeeded
        );
        assert_eq!(reconciler.executor.apply_calls, apply_calls);
    }

    #[test]
    fn authority_attempt_is_durable_before_io_and_reused_after_restart() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let durable_attempt;
        {
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            assert_eq!(
                reconciler.reconcile_once(plan.operation_id()).unwrap(),
                ReconcileOutcome::Progressed
            );
            assert_eq!(reconciler.executor.apply_calls, 0);
            let record = decode_effect(
                reconciler
                    .journal
                    .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                    .unwrap(),
            )
            .unwrap();
            durable_attempt = record.dispatch.unwrap();
        }

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let recovered = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap()
        .dispatch
        .unwrap();
        assert_eq!(recovered, durable_attempt);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(reconciler.executor.apply_calls, 1);
    }

    #[test]
    fn authenticated_pending_retains_the_exact_durable_attempt() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        let before = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        reconciler.executor.authority_pending = true;
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        let after = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(before, after);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn v1_durable_bytes_omit_clock_provenance_but_bind_host_boot() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let durable = record.dispatch.as_ref().unwrap();
        let alternate_clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([0xee; 16]).unwrap(),
            durable.preparation_host_boot_id(),
            durable.preparation_wall_seconds(),
            durable.preparation_boottime_nanoseconds(),
        )
        .unwrap();
        let mut alternate = record.clone();
        alternate.dispatch = Some(PreparedAuthorityEffectV1::new(
            durable.binding_digest(),
            durable.publication_digest(),
            alternate_clock,
            durable.attempt().clone(),
        ));
        assert_eq!(
            encode_effect(&record).unwrap(),
            encode_effect(&alternate).unwrap()
        );

        let another_boot = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([0xee; 16]).unwrap(),
            [0xef; 16],
            durable.preparation_wall_seconds(),
            durable.preparation_boottime_nanoseconds(),
        )
        .unwrap();
        alternate.dispatch = Some(PreparedAuthorityEffectV1::new(
            durable.binding_digest(),
            durable.publication_digest(),
            another_boot,
            durable.attempt().clone(),
        ));
        assert_ne!(
            encode_effect(&record).unwrap(),
            encode_effect(&alternate).unwrap()
        );
    }

    #[test]
    fn authenticated_absent_persists_current_replacement_before_failed_apply() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let (_, renewed) = descriptor_free_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("absent-renewal").unwrap(),
                OperationId::new(),
                [0xd1; 16],
            )
            .unwrap();
        reconciler
            .executor
            .failures
            .push_back(EffectFailure::Retryable("transport lost".to_owned()));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        let effect = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            effect.dispatch.unwrap().publication_digest(),
            renewed.digest()
        );
        assert_eq!(reconciler.executor.apply_calls, 1);
    }

    #[test]
    fn validated_receipt_tokens_cannot_cross_attempts_on_apply_or_observe() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let old = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap()
        .dispatch
        .unwrap();
        let old_apply_token = host_receipt(&old);
        let old_observe_token = host_receipt(&old);
        let (_, renewed) = descriptor_free_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("token-renewal").unwrap(),
                OperationId::new(),
                [0xda; 16],
            )
            .unwrap();

        reconciler.executor.authority_receipt_override = Some(old_apply_token);
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::InvalidExecutorOutput(_))
        ));
        let fresh = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap()
        .dispatch
        .unwrap();
        assert_eq!(fresh.publication_digest(), renewed.digest());

        reconciler.executor.authority_receipt_override = Some(old_observe_token);
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::InvalidExecutorOutput(_))
        ));
    }

    #[test]
    fn substituted_durable_authority_attempt_fails_before_executor_io() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        let mut record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let durable = record.dispatch.as_ref().unwrap();
        let mut packet = durable.attempt().packet().to_vec();
        packet.push(0xff);
        let substituted = BrokerDispatchAttemptV1::from_durable_parts(
            durable.attempt().template_digest(),
            durable.attempt().lease_digest(),
            durable.attempt().lease_generation(),
            durable.attempt().deadline_boottime_nanoseconds(),
            durable.attempt().body().to_vec(),
            packet,
        );
        record.dispatch = Some(PreparedAuthorityEffectV1::from_durable_parts(
            durable.binding_digest(),
            durable.publication_digest(),
            durable.preparation_wall_seconds(),
            durable.preparation_boottime_nanoseconds(),
            durable.preparation_host_boot_id(),
            substituted,
        ));
        let replacement = JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(plan.operation_id(), 0).to_vec(),
            encode_effect(&record).unwrap(),
        );
        reconciler
            .journal_mut()
            .commit(&JournalTransaction::new([0xd7; 16], vec![replacement]).unwrap())
            .unwrap();

        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::CorruptLedger(_))
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn substituted_applied_host_receipt_fails_recovery_before_executor_io() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let key = effect_key(plan.operation_id(), 0);
        let mut record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &key)
                .unwrap(),
        )
        .unwrap();
        let EffectState::Applied { attempt, .. } = record.state else {
            panic!("effect was not applied");
        };
        record.state = EffectState::Applied {
            attempt,
            receipt: EffectReceipt::new(vec![0xff]).unwrap(),
        };
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xd8; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Effect,
                        key.to_vec(),
                        encode_effect(&record).unwrap(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::CorruptLedger(_))
        ));
        assert_eq!(reconciler.executor.apply_calls, 1);
    }

    #[test]
    fn descriptor_bearing_authority_effect_is_explicitly_blocked_before_io() {
        let (draft, _) = descriptor_host_activation_fixture(1);
        let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
        assert!(matches!(
            OperationPlan::ownership_gated(
                OperationId::from_bytes([0xa1; 16]),
                IdempotencyKey::new(b"descriptor-gated".to_vec()).unwrap(),
                [0xa2; 32],
                b"descriptor-sandbox".to_vec(),
                b"pending".to_vec(),
                vec![effect],
                activation_claim(&draft, 1),
                draft,
            ),
            Err(ReconcilerError::InvalidPlan(_))
        ));
    }

    #[test]
    fn descriptor_free_mount_authority_effect_is_admitted() {
        let (draft, _) = descriptor_free_mount_activation_fixture();
        let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
        let plan = OperationPlan::ownership_gated(
            OperationId::from_bytes([0xa3; 16]),
            IdempotencyKey::new(b"mount-gated".to_vec()).unwrap(),
            [0xa4; 32],
            b"mount-sandbox".to_vec(),
            b"pending".to_vec(),
            vec![effect],
            activation_claim(&draft, 1),
            draft,
        )
        .unwrap();

        assert_eq!(plan.effects.len(), 1);
        assert_eq!(plan.effects[0].domain(), EffectDomain::Mount);
    }

    #[test]
    fn crafted_audience_method_mismatches_fail_before_executor_io() {
        for applying in [false, true] {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            if applying {
                let activation = gate_activation(&mut reconciler, &draft, &prepared);
                reconciler
                    .activate_ownership_gate(plan.operation_id(), activation)
                    .unwrap();
                reconciler.reconcile_once(plan.operation_id()).unwrap();
            }
            let key = effect_key(plan.operation_id(), 0);
            let mut bytes = reconciler
                .journal
                .get(RecordNamespace::Effect, &key)
                .unwrap()
                .to_vec();
            // The fixed header + operation + step + source digest precede audience.
            bytes[70] = 2;
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        [0xa5 + u8::from(applying); 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Effect,
                            key.to_vec(),
                            bytes,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }
    }

    #[test]
    fn ownership_gate_rejects_a_different_draft_with_the_same_claim_context() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, _) = gated_operation_with_publication(1);
        let (alternate_draft, alternate_prepared) = alternate_descriptor_free_activation_fixture();
        assert_eq!(
            activation_claim(&draft, 1),
            activation_claim(&alternate_draft, 1)
        );
        assert_ne!(draft.digest(), alternate_draft.digest());
        reconciler.accept(&plan).unwrap();

        let activation = gate_activation(&mut reconciler, &alternate_draft, &alternate_prepared);
        assert!(matches!(
            reconciler.activate_ownership_gate(plan.operation_id(), activation),
            Err(ReconcilerError::OwnershipActivationConflict)
        ));
        assert!(
            AuthorityPublicationStore::new(reconciler.journal_mut())
                .current(draft.manifest().manifest().sandbox())
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            reconciler.ownership_gate(plan.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Pending(_))
        ));
    }

    #[test]
    fn activated_gate_replays_its_prepared_publication_after_current_renews() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap(),
            OwnershipGateActivationOutcome::Activated
        );

        let (renewed_draft, renewed) = descriptor_free_activation_fixture(2);
        assert_eq!(renewed_draft.digest(), draft.digest());
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("renewed-current").unwrap(),
                OperationId::new(),
                [0xb1; 16],
            )
            .unwrap();
        let historical_replay = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(plan.operation_id(), historical_replay)
                .unwrap(),
            OwnershipGateActivationOutcome::Replay
        );
        assert_eq!(
            AuthorityPublicationStore::new(reconciler.journal_mut())
                .current(draft.manifest().manifest().sandbox())
                .unwrap()
                .unwrap()
                .digest(),
            renewed.digest()
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        let effect = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            effect.dispatch.unwrap().publication_digest(),
            renewed.digest()
        );
    }

    #[test]
    fn pending_activation_rechecks_current_after_bridge_preparation() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let stale_activation = gate_activation(&mut reconciler, &draft, &prepared);

        let (_, newer) = descriptor_free_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &newer,
                &IdempotencyKey::new("newer-before-activation").unwrap(),
                OperationId::new(),
                [0xb2; 16],
            )
            .unwrap();
        assert!(matches!(
            reconciler.activate_ownership_gate(plan.operation_id(), stale_activation),
            Err(ReconcilerError::OwnershipPublicationNotSuccessor)
        ));
        assert!(matches!(
            reconciler.ownership_gate(plan.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Pending(_))
        ));
        assert_eq!(
            AuthorityPublicationStore::new(reconciler.journal_mut())
                .current(draft.manifest().manifest().sandbox())
                .unwrap()
                .unwrap()
                .digest(),
            newer.digest()
        );
    }

    #[test]
    fn activated_gate_requires_gate_prepared_and_current_records() {
        for corruption in 0..3 {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();

            let record = match corruption {
                0 => JournalRecord::delete(
                    RecordNamespace::OwnershipGate,
                    plan.operation_id().into_bytes().to_vec(),
                ),
                1 => {
                    let key = reconciler
                        .journal
                        .records(RecordNamespace::AuthorityPublication)
                        .find(|(_, value)| *value == prepared.canonical_bytes())
                        .map(|(key, _)| key.to_vec())
                        .unwrap();
                    JournalRecord::delete(RecordNamespace::AuthorityPublication, key)
                }
                2 => {
                    let key = reconciler
                        .journal
                        .records(RecordNamespace::AuthorityPublication)
                        .find(|(_, value)| *value != prepared.canonical_bytes())
                        .map(|(key, _)| key.to_vec())
                        .unwrap();
                    JournalRecord::delete(RecordNamespace::AuthorityPublication, key)
                }
                _ => unreachable!(),
            };
            reconciler
                .journal_mut()
                .commit(&JournalTransaction::new([0xc0 + corruption; 16], vec![record]).unwrap())
                .unwrap();
            assert!(matches!(
                reconciler.ownership_gate(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }
    }

    #[test]
    fn gated_provenance_detects_deleted_gate_in_every_released_state() {
        for (case, state) in [
            (1_u8, OperationState::Accepted),
            (2, OperationState::Applying),
            (3, OperationState::Succeeded),
            (4, OperationState::PermanentlyBlocked),
        ] {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        [0xe0 + case; 16],
                        vec![
                            JournalRecord::put(
                                RecordNamespace::Operation,
                                plan.operation_id().into_bytes().to_vec(),
                                encode_operation(state, 1, true, None),
                            ),
                            JournalRecord::delete(
                                RecordNamespace::OwnershipGate,
                                plan.operation_id().into_bytes().to_vec(),
                            ),
                        ],
                    )
                    .unwrap(),
                )
                .unwrap();
            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }
    }

    #[test]
    fn operation_record_v1_is_fixed_and_rejects_noncanonical_headers() {
        let bytes = encode_operation(OperationState::Accepted, 1, false, None);
        assert_eq!(bytes.len(), OPERATION_RECORD_V1_BYTES);
        assert_eq!(&bytes[..8], &[RECORD_VERSION_V1, 1, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&bytes[8..], &[0; OPERATION_RUNTIME_INTENT_DIGEST_BYTES]);
        assert_eq!(
            decode_operation(&bytes).unwrap(),
            OperationRecord {
                state: OperationState::Accepted,
                effect_count: 1,
                ownership_gated: false,
                runtime_intent_digest: None,
                public_operation: None,
            }
        );

        let mut invalid = vec![
            bytes[..6].to_vec(),
            bytes[..8].to_vec(),
            bytes[..39].to_vec(),
            [bytes.clone(), vec![0]].concat(),
        ];
        for version in [0, 2, 3] {
            let mut unknown_version = bytes.clone();
            unknown_version[0] = version;
            invalid.push(unknown_version);
        }
        for (offset, value) in [(1, 0), (2, 0x80), (3, 1)] {
            let mut invalid_header = bytes.clone();
            invalid_header[offset] = value;
            invalid.push(invalid_header);
        }
        for count in [0_u32, u32::MAX] {
            let mut invalid_count = bytes.clone();
            invalid_count[4..8].copy_from_slice(&count.to_le_bytes());
            invalid.push(invalid_count);
        }
        for malformed in invalid {
            assert!(matches!(
                decode_operation(&malformed),
                Err(ReconcilerError::CorruptLedger(_))
            ));
        }
    }

    #[test]
    fn operation_record_v1_binds_only_gated_bounded_intent_provenance() {
        let intent = ObjectDigest::from_bytes([0x81; 32]);
        let bytes = encode_operation(OperationState::OwnershipPending, 1, true, Some(intent));
        assert_eq!(bytes[0], RECORD_VERSION_V1);
        assert_eq!(&bytes[8..], intent.as_bytes());
        assert_eq!(
            decode_operation(&bytes).unwrap().runtime_intent_digest,
            Some(intent)
        );

        let without_intent = encode_operation(OperationState::OwnershipPending, 1, true, None);
        assert_eq!(
            decode_operation(&without_intent)
                .unwrap()
                .runtime_intent_digest,
            None
        );

        assert!(
            decode_operation(&encode_operation(
                OperationState::Accepted,
                4093,
                false,
                None,
            ))
            .is_ok()
        );
        assert!(
            decode_operation(&encode_operation(
                OperationState::OwnershipPending,
                4092,
                true,
                None,
            ))
            .is_ok()
        );
        assert!(
            decode_operation(&encode_operation(
                OperationState::OwnershipPending,
                4093,
                true,
                None,
            ))
            .is_err()
        );
        assert!(
            decode_operation(&encode_operation(
                OperationState::OwnershipPending,
                4091,
                true,
                Some(intent),
            ))
            .is_ok()
        );

        for malformed in [
            encode_operation(OperationState::OwnershipPending, 1, false, None),
            encode_operation(OperationState::Accepted, 1, false, Some(intent)),
            encode_operation(OperationState::OwnershipPending, 4092, true, Some(intent)),
        ] {
            assert!(decode_operation(&malformed).is_err());
        }
    }

    #[test]
    fn public_operation_v2_survives_restart_and_tracks_atomic_progress() {
        use crate::controller_query::{
            CheckedOperationObservationV1, CheckedOperationPhaseV1, CheckedOperationResourceV1,
            PublicOperationMethodV1,
        };

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let plan = operation()
            .with_public_operation(
                PublicOperationAdmissionV1::new(
                    PublicOperationMethodV1::StartSandbox,
                    7,
                    [0xa1; 16],
                    100,
                    public_operation_authorization(),
                )
                .unwrap(),
            )
            .unwrap();
        let operation_id = plan.operation_id();
        let mut reconciler = Reconciler::new(journal, Executor::default());

        reconciler.accept(&plan).unwrap();
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Replay(operation_id)
        );
        let mismatched_scope = PublicOperationAuthorizationV1::new(
            ProjectId::from_bytes([0x91; 16]),
            ResourceKind::Sandbox,
            Selector::Resource {
                resource: ResourceId::from_bytes([0x93; 16]),
            },
        )
        .unwrap();
        let mismatched_plan = operation()
            .with_public_operation(
                PublicOperationAdmissionV1::new(
                    PublicOperationMethodV1::StartSandbox,
                    7,
                    [0xa1; 16],
                    100,
                    mismatched_scope,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.accept(&mismatched_plan),
            Err(ReconcilerError::IdempotencyConflict)
        ));
        assert_eq!(
            reconciler
                .public_operation_authorization(operation_id)
                .unwrap(),
            Some(public_operation_authorization())
        );
        let accepted = reconciler.public_operation(operation_id).unwrap().unwrap();
        let accepted_version = accepted.resource_version.clone();
        CheckedOperationResourceV1::try_from(accepted.clone()).unwrap();
        let checked = CheckedOperationObservationV1::try_from(accepted).unwrap();
        assert_eq!(
            checked.resource().phase(),
            CheckedOperationPhaseV1::Committed
        );
        assert_eq!(checked.resource().progress(), (0, 2));
        assert_eq!(checked.observation_sequence(), 1);
        assert!(!checked.resource().cancelable());

        assert!(matches!(
            reconciler.reconcile_once(operation_id),
            Err(ReconcilerError::PublicOperationClock)
        ));
        assert_eq!(
            reconciler
                .public_operation(operation_id)
                .unwrap()
                .unwrap()
                .resource_version,
            accepted_version
        );

        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 101).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 102).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        let first_applied = reconciler.public_operation(operation_id).unwrap().unwrap();
        let checked = CheckedOperationObservationV1::try_from(first_applied).unwrap();
        assert_eq!(checked.resource().progress(), (1, 2));
        assert_eq!(checked.observation_sequence(), 3);

        drop(reconciler);
        let journal = protected_runtime_journal(&directory);
        let mut reopened = Reconciler::new(journal, Executor::default());
        assert_eq!(
            reopened
                .public_operation_authorization(operation_id)
                .unwrap(),
            Some(public_operation_authorization())
        );
        let recovered = reopened.public_operation(operation_id).unwrap().unwrap();
        let checked = CheckedOperationObservationV1::try_from(recovered).unwrap();
        assert_eq!(
            checked.resource().method(),
            PublicOperationMethodV1::StartSandbox
        );
        assert_eq!(checked.resource().progress(), (1, 2));
        assert_eq!(checked.observation_sequence(), 3);

        assert_eq!(
            reopened.reconcile_once_at(operation_id, 103).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reopened.reconcile_once_at(operation_id, 104).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(
            reopened.reconcile_once_at(operation_id, 105).unwrap(),
            ReconcileOutcome::Succeeded
        );
        let completed = reopened.public_operation(operation_id).unwrap().unwrap();
        let checked = CheckedOperationObservationV1::try_from(completed).unwrap();
        assert_eq!(
            checked.resource().phase(),
            CheckedOperationPhaseV1::Succeeded
        );
        assert_eq!(checked.resource().progress(), (2, 2));
        assert_eq!(checked.observation_sequence(), 6);
        assert_eq!(
            checked
                .resource()
                .as_proto()
                .completed_at
                .as_option()
                .unwrap()
                .seconds,
            105
        );
    }

    #[test]
    fn controller_cancellation_receipt_projects_canceled_terminal_state() {
        use crate::controller_query::{CheckedOperationObservationV1, CheckedOperationPhaseV1};

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let plan = cancelable_controller_operation();
        let operation_id = plan.operation_id();
        let mut reconciler = Reconciler::new(journal, CanceledControllerExecutor);

        reconciler.accept(&plan).unwrap();
        let accepted = reconciler.public_operation(operation_id).unwrap().unwrap();
        let accepted = CheckedOperationObservationV1::try_from(accepted).unwrap();
        assert_eq!(
            accepted.resource().phase(),
            CheckedOperationPhaseV1::Accepted
        );
        assert!(accepted.resource().cancelable());

        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 101).unwrap(),
            ReconcileOutcome::Progressed
        );
        let applying = reconciler.public_operation(operation_id).unwrap().unwrap();
        let applying = CheckedOperationObservationV1::try_from(applying).unwrap();
        assert_eq!(
            applying.resource().phase(),
            CheckedOperationPhaseV1::Preparing
        );
        assert!(!applying.resource().cancelable());

        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 102).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 103).unwrap(),
            ReconcileOutcome::CanceledBeforeCommit
        );
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 104).unwrap(),
            ReconcileOutcome::CanceledBeforeCommit
        );

        let canceled = reconciler.public_operation(operation_id).unwrap().unwrap();
        let canceled = CheckedOperationObservationV1::try_from(canceled).unwrap();
        assert_eq!(
            canceled.resource().phase(),
            CheckedOperationPhaseV1::CanceledBeforeCommit
        );
        assert_eq!(canceled.resource().progress(), (1, 1));
        assert!(!canceled.resource().cancelable());
        assert_eq!(
            canceled
                .resource()
                .as_proto()
                .completed_at
                .as_option()
                .unwrap()
                .seconds,
            103
        );
    }

    #[test]
    fn public_operation_v2_rejects_corrupt_metadata_and_backward_time() {
        use crate::controller_query::PublicOperationMethodV1;

        let metadata = PublicOperationAdmissionV1::new(
            PublicOperationMethodV1::CreateView,
            9,
            [0xb1; 16],
            200,
            public_operation_authorization(),
        )
        .unwrap()
        .durable();
        let operation = OperationRecord {
            state: OperationState::Accepted,
            effect_count: 1,
            ownership_gated: false,
            runtime_intent_digest: None,
            public_operation: Some(metadata),
        };
        let bytes = encode_operation_record(operation);
        assert_eq!(bytes.len(), OPERATION_RECORD_V2_BYTES);
        assert_eq!(decode_operation(&bytes).unwrap(), operation);

        let mut reserved = bytes.clone();
        reserved[41] = 1;
        assert!(matches!(
            decode_operation(&reserved),
            Err(ReconcilerError::CorruptLedger(_))
        ));

        assert!(matches!(
            transition_operation(operation, OperationState::Applying, Some(199)),
            Err(ReconcilerError::PublicOperationClock)
        ));

        let authorization = public_operation_authorization();
        let mut authorization_bytes = authorization.encode().unwrap();
        assert_eq!(
            PublicOperationAuthorizationV1::decode(&authorization_bytes).unwrap(),
            authorization
        );
        let last = authorization_bytes.len() - 1;
        authorization_bytes[last] ^= 1;
        assert!(matches!(
            PublicOperationAuthorizationV1::decode(&authorization_bytes),
            Err(ReconcilerError::CorruptLedger(_))
        ));
    }

    #[test]
    fn ownership_pending_is_skipped_without_starving_ready_work() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gated = gated_operation();
        let mut ready = operation();
        ready.operation_id = OperationId::from_bytes([0x91; 16]);
        ready.idempotency_key = IdempotencyKey::new(b"ready-request".to_vec()).unwrap();
        ready.desired_key = b"ready-sandbox".to_vec();
        reconciler.accept(&gated).unwrap();
        reconciler.accept(&ready).unwrap();

        for expected in [
            ReconcileOutcome::Progressed,
            ReconcileOutcome::EffectApplied,
            ReconcileOutcome::Progressed,
            ReconcileOutcome::EffectApplied,
            ReconcileOutcome::Succeeded,
        ] {
            let (operation, outcome) = reconciler.reconcile_next().unwrap().unwrap();
            assert_eq!(operation, ready.operation_id());
            assert_eq!(outcome, expected);
        }
        assert!(reconciler.reconcile_next().unwrap().is_none());
        assert_eq!(reconciler.executor.apply_calls, 2);
    }

    #[test]
    fn ownership_gate_corruption_missing_and_extra_pending_fail_closed() {
        for corruption in 0..4 {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (gated, draft, _) = gated_operation_with_publication(1);
            reconciler.accept(&gated).unwrap();
            let record = match corruption {
                0 => JournalRecord::delete(
                    RecordNamespace::OwnershipGate,
                    gated.operation_id().into_bytes().to_vec(),
                ),
                1 => {
                    let mut bytes = reconciler
                        .journal
                        .get(
                            RecordNamespace::OwnershipGate,
                            gated.operation_id().as_bytes(),
                        )
                        .unwrap()
                        .to_vec();
                    *bytes.last_mut().unwrap() ^= 1;
                    JournalRecord::put(
                        RecordNamespace::OwnershipGate,
                        gated.operation_id().into_bytes().to_vec(),
                        bytes,
                    )
                }
                2 => JournalRecord::put(
                    RecordNamespace::Operation,
                    gated.operation_id().into_bytes().to_vec(),
                    encode_operation(OperationState::Accepted, 1, true, None),
                ),
                3 => {
                    let mut bytes = reconciler
                        .journal
                        .get(
                            RecordNamespace::OwnershipGate,
                            gated.operation_id().as_bytes(),
                        )
                        .unwrap()
                        .to_vec();
                    let mut wrong_claim = activation_claim(&draft, 1);
                    let assignment = wrong_claim.assignment();
                    wrong_claim = OwnershipClaimV1::acquire(
                        *wrong_claim.request_id(),
                        assignment,
                        wrong_claim.desired_generation(),
                        NodeId::from_bytes([0xfe; 16]),
                        wrong_claim.requested_maximum_seconds(),
                    )
                    .unwrap();
                    bytes[116..148].copy_from_slice(wrong_claim.digest().as_bytes());
                    let idempotency_length =
                        usize::from(u16::from_be_bytes(bytes[64..66].try_into().unwrap()));
                    let key_id_length =
                        usize::from(u16::from_be_bytes(bytes[66..68].try_into().unwrap()));
                    let claim_start = 252 + idempotency_length + key_id_length;
                    bytes[claim_start..claim_start + CLAIM_BYTES]
                        .copy_from_slice(wrong_claim.canonical_bytes());
                    JournalRecord::put(
                        RecordNamespace::OwnershipGate,
                        gated.operation_id().into_bytes().to_vec(),
                        bytes,
                    )
                }
                _ => unreachable!(),
            };
            reconciler
                .journal_mut()
                .commit(&JournalTransaction::new([corruption as u8 + 1; 16], vec![record]).unwrap())
                .unwrap();
            assert!(matches!(
                reconciler.reconcile_next(),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }

        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gated = gated_operation();
        reconciler.accept(&gated).unwrap();
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [9; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::Operation,
                        gated.operation_id().into_bytes().to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.reconcile_next(),
            Err(ReconcilerError::CorruptLedger("orphan ownership gate"))
        ));
    }

    #[test]
    fn activation_requires_the_exact_unadvanced_planned_effect_set() {
        for corruption in 0..6 {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (gated, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&gated).unwrap();
            let effect = EffectPlan::new(
                EffectDomain::Host,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                b"arm".to_vec(),
            )
            .unwrap();
            let record = match corruption {
                0 => JournalRecord::delete(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                ),
                1 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 1).to_vec(),
                    encode_effect(&EffectLedgerRecord {
                        plan: effect,
                        state: EffectState::Planned,
                        dispatch: None,
                    })
                    .unwrap(),
                ),
                2 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord {
                        plan: effect,
                        state: EffectState::Applying {
                            attempt: 1,
                            diagnostic: String::new(),
                        },
                        dispatch: None,
                    })
                    .unwrap(),
                ),
                3 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord {
                        plan: effect,
                        state: EffectState::Applied {
                            attempt: 1,
                            receipt: EffectReceipt::new(b"receipt".to_vec()).unwrap(),
                        },
                        dispatch: None,
                    })
                    .unwrap(),
                ),
                4 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord {
                        plan: effect,
                        state: EffectState::PermanentlyBlocked {
                            attempt: 1,
                            diagnostic: "blocked".to_owned(),
                        },
                        dispatch: None,
                    })
                    .unwrap(),
                ),
                5 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord {
                        plan: effect,
                        state: EffectState::Planned,
                        dispatch: None,
                    })
                    .unwrap(),
                ),
                _ => unreachable!(),
            };
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new([corruption as u8 + 21; 16], vec![record]).unwrap(),
                )
                .unwrap();

            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            let activation_error = reconciler
                .activate_ownership_gate(gated.operation_id(), activation)
                .unwrap_err();
            assert!(matches!(
                activation_error,
                ReconcilerError::CorruptLedger(_)
            ));
            assert!(
                AuthorityPublicationStore::new(reconciler.journal_mut())
                    .current(draft.manifest().manifest().sandbox())
                    .unwrap()
                    .is_none()
            );
            let recovered = reconciler.ownership_gate(gated.operation_id());
            assert!(matches!(recovered, Err(ReconcilerError::CorruptLedger(_))));
        }
    }

    #[test]
    fn ownership_gate_bounds_and_pending_backpressure_fail_before_effects() {
        let ordinary = operation();
        let (draft, _) = descriptor_free_activation_fixture(1);
        let manifest = draft.manifest();
        let semantics = manifest.manifest();
        let mismatched_claim = OwnershipClaimV1::acquire(
            [0x73; 16],
            LeaseAssignment::new(
                semantics.sandbox(),
                semantics.incarnation(),
                semantics.epoch(),
                manifest.digest(),
            )
            .unwrap(),
            semantics.desired_generation(),
            NodeId::from_bytes([0xff; 16]),
            60,
        )
        .unwrap();
        assert!(matches!(
            OperationPlan::ownership_gated(
                ordinary.operation_id,
                ordinary.idempotency_key.clone(),
                ordinary.request_digest,
                ordinary.desired_key.clone(),
                ordinary.desired_value.clone(),
                vec![draft.bind_effect(draft.templates()[0].digest()).unwrap()],
                mismatched_claim,
                draft.clone(),
            ),
            Err(ReconcilerError::InvalidPlan(_))
        ));
        let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
        assert!(matches!(
            OperationPlan::ownership_gated(
                ordinary.operation_id,
                ordinary.idempotency_key,
                ordinary.request_digest,
                ordinary.desired_key,
                ordinary.desired_value,
                vec![effect; MAXIMUM_GATED_EFFECTS + 1],
                activation_claim(&draft, 1),
                draft,
            ),
            Err(ReconcilerError::InvalidPlan(_))
        ));

        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gated = gated_operation();
        reconciler.accept_bounded(&gated, 1).unwrap();
        assert_eq!(
            reconciler.accept_bounded(&gated, 1).unwrap(),
            AcceptOutcome::Replay(gated.operation_id())
        );
        assert!(matches!(
            reconciler.accept_bounded(&operation(), 1),
            Err(ReconcilerError::AdmissionBackpressure)
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn effects_are_intended_before_execution_and_complete_in_order() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        reconciler.accept(&plan).unwrap();

        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(reconciler.executor.apply_calls, 1);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Succeeded
        );
    }

    #[test]
    fn restart_observes_ambiguous_effect_without_reapplying() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        reconciler.executor.applied.insert(
            (plan.operation_id(), 0),
            EffectReceipt::new(b"recovered".to_vec()).unwrap(),
        );
        let executor = reconciler.executor;
        drop(reconciler.journal);

        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, executor);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn retryable_failure_preserves_inflight_intent() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let executor = Executor {
            failures: VecDeque::from([EffectFailure::Retryable("busy".to_string())]),
            ..Executor::default()
        };
        let mut reconciler = Reconciler::new(journal, executor);
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        let effect = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            effect.state,
            EffectState::Applying {
                attempt: 2,
                ref diagnostic,
            } if diagnostic == "busy"
        ));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
    }

    #[test]
    fn permanent_failure_blocks_effect_and_operation_atomically() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let executor = Executor {
            failures: VecDeque::from([EffectFailure::Permanent("rejected".to_string())]),
            ..Executor::default()
        };
        let mut reconciler = Reconciler::new(journal, executor);
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::PermanentlyBlocked
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::PermanentlyBlocked
        );
    }

    #[test]
    fn fresh_request_cannot_overwrite_an_existing_operation_identity() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let first = operation();
        reconciler.accept(&first).unwrap();

        let mut collision = operation();
        collision.idempotency_key = IdempotencyKey::new(b"another-request".to_vec()).unwrap();
        collision.request_digest = [0x77; 32];
        assert!(matches!(
            reconciler.accept(&collision),
            Err(ReconcilerError::OperationAlreadyExists)
        ));
    }

    fn observe_reservation_fixture(execution: [u8; 16]) -> (OperationId, Vec<u8>) {
        let mut receipt = [5; 40];
        receipt[..8].copy_from_slice(b"AOSEXE01");
        let reservation = ControllerExecutionObserveReservationV1::new(
            aos_sandbox_core::ExecutionId::from_bytes(execution),
            OperationId::from_bytes([0x22; 16]),
            ObjectDigest::from_bytes([3; 32]),
            [4; 32],
            &receipt,
        )
        .unwrap();
        (reservation.observe_operation(), reservation.encode())
    }

    #[test]
    fn fresh_request_cannot_take_a_reserved_execution_observe_identity() {
        let directory = TestDirectory::new();
        let (mut journal, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let execution = [0x11; 16];
        let (reserved, value) = observe_reservation_fixture(execution);
        let transaction = JournalTransaction::new(
            [0x33; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerExecutionObserveReservation,
                execution.to_vec(),
                value,
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        drop(journal);

        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let sequence = reconciler.journal.snapshot_sequence();
        let mut collision = operation();
        collision.operation_id = reserved;
        assert!(matches!(
            reconciler.accept(&collision),
            Err(ReconcilerError::OperationAlreadyExists)
        ));
        assert_eq!(reconciler.journal.snapshot_sequence(), sequence);

        let other = operation();
        assert_eq!(
            reconciler.accept(&other).unwrap(),
            AcceptOutcome::Accepted(other.operation_id())
        );
    }

    #[test]
    fn corrupt_execution_observe_reservation_blocks_new_admission() {
        let directory = TestDirectory::new();
        let (mut journal, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let execution = [0x11; 16];
        let (_, mut value) = observe_reservation_fixture(execution);
        value[159] ^= 1;
        let transaction = JournalTransaction::new(
            [0x33; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerExecutionObserveReservation,
                execution.to_vec(),
                value,
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();

        let mut reconciler = Reconciler::new(journal, Executor::default());
        let sequence = reconciler.journal.snapshot_sequence();
        assert!(matches!(
            reconciler.accept(&operation()),
            Err(ReconcilerError::CorruptLedger(_))
        ));
        assert_eq!(reconciler.journal.snapshot_sequence(), sequence);
    }

    #[test]
    fn pending_operation_selection_advances_fairly() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let mut first = operation();
        first.operation_id = OperationId::from_bytes([0x11; 16]);
        first.idempotency_key = IdempotencyKey::new(b"first".to_vec()).unwrap();
        first.desired_key = b"first-sandbox".to_vec();
        let mut second = operation();
        second.operation_id = OperationId::from_bytes([0x22; 16]);
        second.idempotency_key = IdempotencyKey::new(b"second".to_vec()).unwrap();
        second.desired_key = b"second-sandbox".to_vec();
        reconciler.accept(&first).unwrap();
        reconciler.accept(&second).unwrap();

        let selected_first = reconciler.reconcile_next().unwrap().unwrap().0;
        let selected_second = reconciler.reconcile_next().unwrap().unwrap().0;
        assert_eq!(selected_first, first.operation_id());
        assert_eq!(selected_second, second.operation_id());
    }

    #[test]
    fn restart_after_every_durable_boundary_converges_without_duplicate_effects() {
        for crash_after in 0..=5 {
            let directory = TestDirectory::new();
            let path = directory.journal();
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let plan = operation();
            reconciler.accept(&plan).unwrap();

            for _ in 0..crash_after {
                reconciler.reconcile_once(plan.operation_id()).unwrap();
            }
            let executor = reconciler.executor;
            drop(reconciler.journal);

            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, executor);
            let mut terminal = false;
            for _ in 0..16 {
                if reconciler.reconcile_once(plan.operation_id()).unwrap()
                    == ReconcileOutcome::Succeeded
                {
                    terminal = true;
                    break;
                }
            }
            assert!(terminal, "did not converge after boundary {crash_after}");
            assert_eq!(reconciler.executor.apply_calls, 2);
            assert_eq!(reconciler.executor.applied.len(), 2);
        }
    }
}
