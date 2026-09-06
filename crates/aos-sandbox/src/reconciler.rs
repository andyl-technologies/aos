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
//! operation formats are closed and preserve legacy encodings:
//!
//! ```text
//! V1 = version:u8 state:u8 effect_count:u32le
//! V2 = version:u8 state:u8 flags:u8 reserved:u8 effect_count:u32le
//! V3 = V2 header with version=3 || runtime_intent_digest:32bytes
//! ```

use aos_sandbox_core::model::{KeyReference, KeyUsage, StableKeyId};
use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use aos_sandbox_ownership_protocol::{CLAIM_BYTES, OwnershipClaimV1};

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
    AuthorityBoundEffectPlanV2, AuthorityEffectAttemptTimingV1, AuthorityEffectObservationV2,
    EffectDomain, EffectPlan, PreparedAuthorityEffectV2, ValidatedHostEffectReceiptV1,
};
use effect::{
    EffectLedgerRecord, EffectState, MAXIMUM_DIAGNOSTIC_BYTES, decode_effect, encode_effect,
};

const RECORD_VERSION: u8 = 1;
const OPERATION_RECORD_VERSION: u8 = 2;
const RUNTIME_OPERATION_RECORD_VERSION: u8 = 3;
const OPERATION_FLAG_OWNERSHIP_GATED: u8 = 1;
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
        })
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
        effects: Vec<AuthorityBoundEffectPlanV2>,
        claim: OwnershipClaimV1,
        publication_draft: AuthorityPublicationDraftV1,
    ) -> Result<Self, ReconcilerError> {
        if effects.len() > MAXIMUM_GATED_EFFECTS {
            return Err(ReconcilerError::InvalidPlan(
                "ownership-gated operation has too many effects",
            ));
        }
        if effects.iter().any(|effect| {
            !effect.is_supported_host_apply()
                || effect.source_draft_digest() != publication_draft.digest()
        }) {
            return Err(ReconcilerError::InvalidPlan(
                "ownership-gated effects must be descriptor-free Host Apply templates",
            ));
        }
        let effects: Vec<EffectPlan> = effects
            .into_iter()
            .enumerate()
            .map(|(step, effect)| {
                effect.into_inner(operation_id, u32::try_from(step).unwrap_or(u32::MAX))
            })
            .collect();
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
    /// Returns an error for an ungated plan, more than 4091 effects, or revocation
    /// not bound to exactly one canonical Host Stop effect for this assignment.
    pub fn with_runtime_authority(
        mut self,
        intent: RuntimeAuthorityIntentV1,
    ) -> Result<Self, ReconcilerError> {
        if self.ownership_gate.is_none() || self.effects.len() > MAXIMUM_GATED_EFFECTS - 1 {
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
        _prepared: &PreparedAuthorityEffectV2,
    ) -> Result<AuthorityEffectObservationV2, EffectFailure> {
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
        _prepared: &PreparedAuthorityEffectV2,
    ) -> Result<ValidatedHostEffectReceiptV1, EffectFailure> {
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
    /// A permanent executor failure durably blocked the operation.
    PermanentlyBlocked,
}

/// Reports admission, ledger, journal, or executor-contract failures.
#[derive(Debug, thiserror::Error)]
pub enum ReconcilerError {
    /// Protected Mount-attempt history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("mount attempt failed: {0}")]
    MountAttempt(#[source] Box<crate::mount_attempt::MountAttemptError>),
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
    /// A legacy ownership-gated effect requires an explicit durable migration.
    #[error("legacy ownership-gated effects require migration")]
    MigrationRequired,
    /// An executor returned unbounded or empty evidence.
    #[error("effect executor violated its output contract: {0}")]
    InvalidExecutorOutput(&'static str),
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationRecord {
    state: OperationState,
    effect_count: u32,
    ownership_gated: bool,
    runtime_intent_digest: Option<ObjectDigest>,
}

impl OperationState {
    fn from_byte(value: u8) -> Result<Self, ReconcilerError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Applying),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::PermanentlyBlocked),
            5 => Ok(Self::OwnershipPending),
            _ => Err(ReconcilerError::CorruptLedger("unknown operation state")),
        }
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
        records.push(JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.into_bytes().to_vec(),
            encode_runtime_operation(
                OperationState::Accepted,
                operation.effect_count,
                true,
                operation.runtime_intent_digest,
            ),
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
                if self.load_operation(operation_id)?.runtime_intent_digest
                    != plan
                        .runtime_authority
                        .as_ref()
                        .map(RuntimeAuthorityIntentV1::digest)
                {
                    return Err(ReconcilerError::IdempotencyConflict);
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
        if let Some(maximum) = maximum_pending_operations {
            // Corrupt operation state must never be treated as spare capacity.
            if self.pending_operation_count()? >= maximum {
                return Err(ReconcilerError::AdmissionBackpressure);
            }
        }

        let effect_count = u32::try_from(plan.effects.len())
            .map_err(|_| ReconcilerError::InvalidPlan("too many effects"))?;
        let mut records =
            Vec::with_capacity(plan.effects.len() + 3 + usize::from(plan.ownership_gate.is_some()));
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            plan.desired_key.clone(),
            plan.desired_value.clone(),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::Operation,
            plan.operation_id.into_bytes().to_vec(),
            encode_runtime_operation(
                if plan.ownership_gate.is_some() {
                    OperationState::OwnershipPending
                } else {
                    OperationState::Accepted
                },
                effect_count,
                plan.ownership_gate.is_some(),
                plan.runtime_authority
                    .as_ref()
                    .map(RuntimeAuthorityIntentV1::digest),
            ),
        ));
        records.push(JournalRecord::idempotency(
            &plan.idempotency_key,
            plan.request_digest,
            plan.operation_id,
        ));
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
                OperationState::Succeeded | OperationState::PermanentlyBlocked
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
        self.ensure_ledger_validated()?;
        let operation = self.load_operation(operation_id)?;
        let gate = self.load_and_validate_ownership_gate(operation_id, operation)?;
        match operation.state {
            OperationState::OwnershipPending => return Ok(ReconcileOutcome::OwnershipPending),
            OperationState::Succeeded => return Ok(ReconcileOutcome::Succeeded),
            OperationState::PermanentlyBlocked => {
                return Ok(ReconcileOutcome::PermanentlyBlocked);
            }
            OperationState::Accepted | OperationState::Applying => {}
        }

        for step in 0..operation.effect_count {
            let key = effect_key(operation_id, step);
            let bytes = self
                .journal
                .get(RecordNamespace::Effect, &key)
                .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
            let record = decode_effect(bytes)?;
            match record.state {
                EffectState::Applied { .. } => continue,
                EffectState::PermanentlyBlocked { .. } => {
                    self.store_operation(
                        operation_id,
                        OperationState::PermanentlyBlocked,
                        operation.effect_count,
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
                        let (selected_publication, attempt) =
                            AuthorityPublicationStore::new(&mut self.journal)
                                .select_bound_current_attempt(
                                    sandbox,
                                    *publication_digest,
                                    binding.source_draft_digest,
                                    binding.audience,
                                    binding.template_digest,
                                    timing.deadline(),
                                    timing.clock(),
                                )?;
                        Some(PreparedAuthorityEffectV2::new(
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
                    self.store_effect(operation_id, step, &applying, Some(operation.effect_count))?;
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
                    );
                }
            }
        }

        self.store_operation(
            operation_id,
            OperationState::Succeeded,
            operation.effect_count,
        )?;
        Ok(ReconcileOutcome::Succeeded)
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
        self.ensure_ledger_validated()?;
        let mut first = None;
        let mut after_cursor = None;
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let operation_id = decode_operation_key(key)?;
            let operation = decode_operation(value)?;
            if matches!(
                operation.state,
                OperationState::Succeeded
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
        let outcome = self.reconcile_once(operation_id)?;
        Ok(Some((operation_id, outcome)))
    }

    fn validate_all_ownership_gates(&self) -> Result<(), ReconcilerError> {
        for (key, _) in self.journal.records(RecordNamespace::OwnershipGate) {
            let operation_id = decode_operation_key(key)?;
            let operation = self.load_operation(operation_id).map_err(|error| {
                if matches!(error, ReconcilerError::OperationNotFound) {
                    ReconcilerError::CorruptLedger("orphan ownership gate")
                } else {
                    error
                }
            })?;
            self.load_and_validate_ownership_gate(operation_id, operation)?;
        }
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let operation_id = decode_operation_key(key)?;
            self.load_and_validate_ownership_gate(operation_id, decode_operation(value)?)?;
        }
        Ok(())
    }

    fn ensure_ledger_validated(&mut self) -> Result<(), ReconcilerError> {
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
            self.validate_all_ownership_gates()?;
            validate_runtime_authority_operations(&self.journal)?;
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
            self.ledger_validated = true;
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
        &self,
        operation_id: OperationId,
    ) -> Result<(), ReconcilerError> {
        let operation = self.load_operation(operation_id)?;
        self.load_and_validate_ownership_gate(operation_id, operation)?;
        Ok(())
    }

    fn load_and_validate_ownership_gate(
        &self,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
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

    fn validate_effect_authority_bindings(
        &self,
        operation_id: OperationId,
        effect_count: u32,
        draft: Option<&AuthorityPublicationDraftV1>,
        activated_publication: Option<ObjectDigest>,
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
                        )
                        .map_err(|_| {
                            ReconcilerError::CorruptLedger(
                                "authority effect dispatch is missing or corrupt",
                            )
                        })?;
                        if let EffectState::Applied { receipt, .. } = &effect.state {
                            dispatch
                                .validate_host_receipt(receipt.as_bytes().to_vec())
                                .map_err(|_| {
                                    ReconcilerError::CorruptLedger(
                                        "authority effect receipt is malformed or substituted",
                                    )
                                })?;
                        }
                    }
                }
                (Some(_), None) => return Err(ReconcilerError::MigrationRequired),
                (None, Some(_)) => {
                    return Err(ReconcilerError::CorruptLedger(
                        "effect record version does not match operation provenance",
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
    fn reconcile_applying(
        &mut self,
        operation_id: OperationId,
        step: u32,
        effect_count: u32,
        attempt: u32,
        plan: EffectPlan,
        dispatch: Option<PreparedAuthorityEffectV2>,
        authority_gate: Option<(SandboxId, ObjectDigest)>,
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
                    );
                }
            };
            match observed {
                AuthorityEffectObservationV2::Applied(receipt) => {
                    receipt.into_effect_receipt_for(prepared)?
                }
                AuthorityEffectObservationV2::Pending => return Ok(ReconcileOutcome::RetryPending),
                AuthorityEffectObservationV2::Absent => {
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
                    let (publication_digest, fresh_attempt) =
                        AuthorityPublicationStore::new(&mut self.journal)
                            .select_bound_current_attempt(
                                sandbox,
                                activated_publication,
                                binding.source_draft_digest,
                                binding.audience,
                                binding.template_digest,
                                timing.deadline(),
                                timing.clock(),
                            )?;
                    let fresh = PreparedAuthorityEffectV2::new(
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
                    self.store_effect(operation_id, step, &refreshed, None)?;
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
                            self.store_effect(operation_id, step, &applied, None)?;
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
                            );
                        }
                    }
                }
            }
        } else {
            let observed = match self.executor.observe(operation_id, step, &plan) {
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
                    );
                }
            };
            match observed {
                EffectObservation::Applied(receipt) => receipt,
                EffectObservation::Absent => match self.executor.apply(operation_id, step, &plan) {
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
                        );
                    }
                },
            }
        };
        let applied = EffectLedgerRecord {
            plan,
            state: EffectState::Applied { attempt, receipt },
            dispatch,
        };
        self.store_effect(operation_id, step, &applied, None)?;
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
        dispatch: Option<PreparedAuthorityEffectV2>,
        failure: EffectFailure,
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
                self.store_effect(operation_id, step, &applying, None)?;
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
                self.store_effect(operation_id, step, &blocked, Some(effect_count))?;
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
    ) -> Result<(), ReconcilerError> {
        let operation = self.load_operation(operation_id)?;
        if operation.effect_count != effect_count {
            return Err(ReconcilerError::CorruptLedger(
                "operation effect count changed during transition",
            ));
        }
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.into_bytes().to_vec(),
            encode_runtime_operation(
                state,
                effect_count,
                operation.ownership_gated,
                operation.runtime_intent_digest,
            ),
        );
        self.commit_records(vec![record])
    }

    fn store_effect(
        &mut self,
        operation_id: OperationId,
        step: u32,
        record: &EffectLedgerRecord,
        operation_effect_count: Option<u32>,
    ) -> Result<(), ReconcilerError> {
        let mut records = vec![JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(operation_id, step).to_vec(),
            encode_effect(record)?,
        )];
        if let Some(effect_count) = operation_effect_count {
            let operation = self.load_operation(operation_id)?;
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
            records.push(JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_runtime_operation(
                    state,
                    effect_count,
                    operation.ownership_gated,
                    operation.runtime_intent_digest,
                ),
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

fn encode_operation(state: OperationState, effect_count: u32, ownership_gated: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8);
    bytes.push(OPERATION_RECORD_VERSION);
    bytes.push(state as u8);
    bytes.push(u8::from(ownership_gated) * OPERATION_FLAG_OWNERSHIP_GATED);
    bytes.push(0);
    bytes.extend_from_slice(&effect_count.to_le_bytes());
    bytes
}

fn encode_runtime_operation(
    state: OperationState,
    effect_count: u32,
    ownership_gated: bool,
    runtime_intent_digest: Option<ObjectDigest>,
) -> Vec<u8> {
    let mut bytes = encode_operation(state, effect_count, ownership_gated);
    if let Some(digest) = runtime_intent_digest {
        bytes[0] = RUNTIME_OPERATION_RECORD_VERSION;
        bytes.extend_from_slice(digest.as_bytes());
    }
    bytes
}

fn decode_operation(bytes: &[u8]) -> Result<OperationRecord, ReconcilerError> {
    if bytes.first() == Some(&RUNTIME_OPERATION_RECORD_VERSION) {
        if bytes.len() != 40 {
            return Err(ReconcilerError::CorruptLedger(
                "invalid runtime operation length",
            ));
        }
        // V3 preserves the V2 fixed header and adds an independent commitment
        // to the exact pending holder intent. Legacy records remain byte-exact.
        let mut header = [0; 8];
        header.copy_from_slice(&bytes[..8]);
        header[0] = OPERATION_RECORD_VERSION;
        let mut operation = decode_operation(&header)?;
        let digest: [u8; 32] = bytes[8..]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid runtime intent digest"))?;
        if !operation.ownership_gated
            || digest == [0; 32]
            || operation.effect_count as usize > MAXIMUM_GATED_EFFECTS - 1
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid runtime operation provenance",
            ));
        }
        operation.runtime_intent_digest = Some(ObjectDigest::from_bytes(digest));
        return Ok(operation);
    }
    let (state, effect_count, ownership_gated) = match bytes {
        [RECORD_VERSION, state, effect_count @ ..] if effect_count.len() == 4 => (
            OperationState::from_byte(*state)?,
            u32::from_le_bytes(
                effect_count
                    .try_into()
                    .map_err(|_| ReconcilerError::CorruptLedger("invalid effect count"))?,
            ),
            false,
        ),
        [
            OPERATION_RECORD_VERSION,
            state,
            flags,
            reserved,
            effect_count @ ..,
        ] if effect_count.len() == 4
            && flags & !OPERATION_FLAG_OWNERSHIP_GATED == 0
            && *reserved == 0 =>
        {
            (
                OperationState::from_byte(*state)?,
                u32::from_le_bytes(
                    effect_count
                        .try_into()
                        .map_err(|_| ReconcilerError::CorruptLedger("invalid effect count"))?,
                ),
                flags & OPERATION_FLAG_OWNERSHIP_GATED != 0,
            )
        }
        _ => {
            return Err(ReconcilerError::CorruptLedger(
                "invalid operation record version, flags, or length",
            ));
        }
    };
    if effect_count == 0 || effect_count as usize > MAXIMUM_EFFECTS {
        return Err(ReconcilerError::CorruptLedger("invalid effect count"));
    }
    if state == OperationState::OwnershipPending && !ownership_gated {
        return Err(ReconcilerError::CorruptLedger(
            "ownership-pending operation lacks gated provenance",
        ));
    }
    Ok(OperationRecord {
        state,
        effect_count,
        ownership_gated,
        runtime_intent_digest: None,
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
        ApplyRuntimeRequest, RuntimeObservation, RuntimeState,
    };
    use aos_sandbox_core::{LeaseAssignment, NodeId, RawClockProvenance, RawPairedClockSample};
    use buffa::Message as _;

    use super::*;
    use crate::BrokerDispatchAttemptV1;
    use crate::journal::JournalLimits;
    use crate::publication::tests::{
        activation_claim, alternate_descriptor_free_activation_fixture,
        descriptor_free_activation_fixture, descriptor_free_mount_activation_fixture,
        descriptor_host_activation_fixture,
    };
    use crate::publication::{AuthorityPublicationDraftV1, AuthorityPublicationStore};

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
        authority_pending: bool,
        authority_receipt_override: Option<ValidatedHostEffectReceiptV1>,
    }

    fn host_receipt_bytes(prepared: &PreparedAuthorityEffectV2) -> Vec<u8> {
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

    fn host_receipt(prepared: &PreparedAuthorityEffectV2) -> ValidatedHostEffectReceiptV1 {
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
            let provenance = RawClockProvenance::new_untrusted([0x91; 16]).unwrap();
            let clock =
                RawPairedClockSample::new_untrusted(provenance, [0x92; 16], 150, 1_000).unwrap();
            Some(AuthorityEffectAttemptTimingV1::new(clock, 2_000))
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
            prepared: &PreparedAuthorityEffectV2,
        ) -> Result<AuthorityEffectObservationV2, EffectFailure> {
            self.observe_calls += 1;
            Ok(if self.authority_pending {
                AuthorityEffectObservationV2::Pending
            } else if self.applied.contains_key(&(operation_id, step)) {
                AuthorityEffectObservationV2::Applied(
                    self.authority_receipt_override
                        .take()
                        .unwrap_or_else(|| host_receipt(prepared)),
                )
            } else {
                AuthorityEffectObservationV2::Absent
            })
        }

        fn apply_authority(
            &mut self,
            operation_id: OperationId,
            step: u32,
            prepared: &PreparedAuthorityEffectV2,
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

    fn operation() -> OperationPlan {
        OperationPlan::new(
            OperationId::from_bytes([0x44; 16]),
            IdempotencyKey::new(b"request".to_vec()).unwrap(),
            [0x55; 32],
            b"sandbox".to_vec(),
            b"running".to_vec(),
            vec![
                EffectPlan::new(EffectDomain::Storage, b"create".to_vec()).unwrap(),
                EffectPlan::new(EffectDomain::Host, b"start".to_vec()).unwrap(),
            ],
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
    fn runtime_intent_rejects_unprotected_admission_and_missing_pending_recovery() {
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
    fn v2_durable_bytes_omit_raw_clock_provenance_and_boot_identity() {
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
            [0xef; 16],
            durable.preparation_wall_seconds(),
            durable.preparation_boottime_nanoseconds(),
        )
        .unwrap();
        let mut alternate = record.clone();
        alternate.dispatch = Some(PreparedAuthorityEffectV2::new(
            durable.binding_digest(),
            durable.publication_digest(),
            alternate_clock,
            durable.attempt().clone(),
        ));
        assert_eq!(
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
        record.dispatch = Some(PreparedAuthorityEffectV2::from_durable_parts(
            durable.binding_digest(),
            durable.publication_digest(),
            durable.preparation_wall_seconds(),
            durable.preparation_boottime_nanoseconds(),
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
    fn descriptor_free_non_host_authority_effect_is_rejected_at_admission() {
        let (draft, _) = descriptor_free_mount_activation_fixture();
        let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
        assert!(matches!(
            OperationPlan::ownership_gated(
                OperationId::from_bytes([0xa3; 16]),
                IdempotencyKey::new(b"mount-gated".to_vec()).unwrap(),
                [0xa4; 32],
                b"mount-sandbox".to_vec(),
                b"pending".to_vec(),
                vec![effect],
                activation_claim(&draft, 1),
                draft,
            ),
            Err(ReconcilerError::InvalidPlan(_))
        ));
    }

    #[test]
    fn crafted_non_host_v2_planned_and_applying_records_fail_before_executor_io() {
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
            // V2 fixed header + operation + step + source digest precede audience.
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
                                encode_operation(state, 1, true),
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
    fn operation_records_decode_legacy_v1_and_reject_unknown_v2_flags() {
        let legacy = [RECORD_VERSION, OperationState::Accepted as u8, 1, 0, 0, 0];
        assert_eq!(
            decode_operation(&legacy).unwrap(),
            OperationRecord {
                state: OperationState::Accepted,
                effect_count: 1,
                ownership_gated: false,
                runtime_intent_digest: None,
            }
        );
        let mut unknown_flags = encode_operation(OperationState::Accepted, 1, false);
        unknown_flags[2] = 0x80;
        assert!(matches!(
            decode_operation(&unknown_flags),
            Err(ReconcilerError::CorruptLedger(_))
        ));
    }

    #[test]
    fn runtime_operation_v3_requires_gated_bounded_nonzero_intent_provenance() {
        let intent = ObjectDigest::from_bytes([0x81; 32]);
        let bytes =
            encode_runtime_operation(OperationState::OwnershipPending, 1, true, Some(intent));
        assert_eq!(
            decode_operation(&bytes).unwrap().runtime_intent_digest,
            Some(intent)
        );
        for malformed in [
            bytes[..39].to_vec(),
            encode_runtime_operation(OperationState::Accepted, 1, false, Some(intent)),
            encode_runtime_operation(
                OperationState::Accepted,
                1,
                true,
                Some(ObjectDigest::from_bytes([0; 32])),
            ),
            encode_runtime_operation(OperationState::Accepted, 4092, true, Some(intent)),
        ] {
            assert!(decode_operation(&malformed).is_err());
        }
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
                    encode_operation(OperationState::Accepted, 1, true),
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
            let effect = EffectPlan::new(EffectDomain::Guardian, b"arm".to_vec()).unwrap();
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
            if corruption >= 2 {
                assert!(matches!(
                    activation_error,
                    ReconcilerError::MigrationRequired
                ));
            } else {
                assert!(matches!(
                    activation_error,
                    ReconcilerError::CorruptLedger(_)
                ));
            }
            assert!(
                AuthorityPublicationStore::new(reconciler.journal_mut())
                    .current(draft.manifest().manifest().sandbox())
                    .unwrap()
                    .is_none()
            );
            let recovered = reconciler.ownership_gate(gated.operation_id());
            if corruption >= 2 {
                assert!(matches!(recovered, Err(ReconcilerError::MigrationRequired)));
            } else {
                assert!(matches!(recovered, Err(ReconcilerError::CorruptLedger(_))));
            }
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
