//! Single-node desired-state reconciliation and durable effect ledger.
//!
//! Admission stores the desired value, operation, idempotency decision, and
//! ordered effect plans in one journal transaction. Reconciliation writes an
//! `Applying` intent before invoking an effect executor. After restart, an
//! ambiguous `Applying` effect is observed by its stable operation/step key;
//! an absent effect is retried with the exact request bytes, while an applied
//! effect is completed from its durable executor receipt. This requires every
//! executor implementation to make one effect key idempotent.

use aos_sandbox_core::OperationId;

use crate::journal::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalRecord, JournalTransaction,
    RecordNamespace,
};

const RECORD_VERSION: u8 = 1;
const OPERATION_KEY_BYTES: usize = 16;
const EFFECT_KEY_BYTES: usize = 20;
// The default journal transaction bound is 4096 records. Admission also
// carries desired-state, operation, and idempotency records atomically.
const MAXIMUM_EFFECTS: usize = 4093;
const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
const MAXIMUM_RECEIPT_BYTES: usize = 64 * 1024;
const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4096;

/// Selects the sole fixed-function boundary allowed to execute an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EffectDomain {
    /// Typed systemd, cgroup, runtime, and freeze operations.
    Host = 1,
    /// Typed dataset, snapshot, hold, clone, quota, and destroy operations.
    Storage = 2,
    /// Descriptor-only mount preparation and namespace publication.
    Mount = 3,
    /// Typed network namespace, link, route, and packet-gate operations.
    Network = 4,
    /// Assignment ownership and fail-stop lease operations.
    Guardian = 5,
    /// Authenticated in-guest readiness, execution, and quiesce operations.
    Guest = 6,
}

impl EffectDomain {
    fn from_byte(value: u8) -> Result<Self, ReconcilerError> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::Storage),
            3 => Ok(Self::Mount),
            4 => Ok(Self::Network),
            5 => Ok(Self::Guardian),
            6 => Ok(Self::Guest),
            _ => Err(ReconcilerError::CorruptLedger("unknown effect domain")),
        }
    }
}

/// Defines one ordered, idempotent request to a fixed effect boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectPlan {
    domain: EffectDomain,
    request: Vec<u8>,
}

impl EffectPlan {
    /// Constructs a bounded effect plan from already validated request bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for an empty request or one
    /// exceeding the local broker protocol request bound.
    pub fn new(domain: EffectDomain, request: Vec<u8>) -> Result<Self, ReconcilerError> {
        if request.is_empty() || request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "invalid effect request length",
            ));
        }
        Ok(Self { domain, request })
    }

    /// Returns the fixed boundary selected for this effect.
    #[must_use]
    pub const fn domain(&self) -> EffectDomain {
        self.domain
    }

    /// Returns the exact idempotent request bytes sent to the executor.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }
}

/// Defines one atomically admitted desired mutation and its ordered effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPlan {
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    request_digest: [u8; 32],
    desired_key: Vec<u8>,
    desired_value: Vec<u8>,
    effects: Vec<EffectPlan>,
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
        })
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the digest of the normalized request admitted by this plan.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
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
}

/// Reports one bounded reconciliation pass outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
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
    /// Durable operation or effect bytes violate the closed v1 schema.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
    /// An executor returned unbounded or empty evidence.
    #[error("effect executor violated its output contract: {0}")]
    InvalidExecutorOutput(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum OperationState {
    Accepted = 1,
    Applying = 2,
    Succeeded = 3,
    PermanentlyBlocked = 4,
}

impl OperationState {
    fn from_byte(value: u8) -> Result<Self, ReconcilerError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Applying),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::PermanentlyBlocked),
            _ => Err(ReconcilerError::CorruptLedger("unknown operation state")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EffectState {
    Planned,
    Applying {
        attempt: u32,
        diagnostic: String,
    },
    Applied {
        attempt: u32,
        receipt: EffectReceipt,
    },
    PermanentlyBlocked {
        attempt: u32,
        diagnostic: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectLedgerRecord {
    plan: EffectPlan,
    state: EffectState,
}

/// Reconciles one exclusively owned single-node journal.
pub struct Reconciler<E> {
    journal: Journal,
    executor: E,
    scheduling_cursor: Option<OperationId>,
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
        }
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
        match self
            .journal
            .check_idempotency(&plan.idempotency_key, plan.request_digest)
        {
            IdempotencyOutcome::Replay(operation_id) => {
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
        let mut records = Vec::with_capacity(plan.effects.len() + 3);
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            plan.desired_key.clone(),
            plan.desired_value.clone(),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::Operation,
            plan.operation_id.into_bytes().to_vec(),
            encode_operation(OperationState::Accepted, effect_count),
        ));
        records.push(JournalRecord::idempotency(
            &plan.idempotency_key,
            plan.request_digest,
            plan.operation_id,
        ));
        for (index, effect) in plan.effects.iter().enumerate() {
            let step = u32::try_from(index)
                .map_err(|_| ReconcilerError::InvalidPlan("too many effects"))?;
            records.push(JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(plan.operation_id, step).to_vec(),
                encode_effect(&EffectLedgerRecord {
                    plan: effect.clone(),
                    state: EffectState::Planned,
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
            decode_operation_key(key)?;
            let (state, _) = decode_operation(value)?;
            if !matches!(
                state,
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
        let (operation_state, effect_count) = self.load_operation(operation_id)?;
        match operation_state {
            OperationState::Succeeded => return Ok(ReconcileOutcome::Succeeded),
            OperationState::PermanentlyBlocked => {
                return Ok(ReconcileOutcome::PermanentlyBlocked);
            }
            OperationState::Accepted | OperationState::Applying => {}
        }

        for step in 0..effect_count {
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
                        effect_count,
                    )?;
                    return Ok(ReconcileOutcome::PermanentlyBlocked);
                }
                EffectState::Planned => {
                    let applying = EffectLedgerRecord {
                        plan: record.plan,
                        state: EffectState::Applying {
                            attempt: 1,
                            diagnostic: String::new(),
                        },
                    };
                    self.store_effect(operation_id, step, &applying, Some(effect_count))?;
                    return Ok(ReconcileOutcome::Progressed);
                }
                EffectState::Applying { attempt, .. } => {
                    return self.reconcile_applying(
                        operation_id,
                        step,
                        effect_count,
                        attempt,
                        record.plan,
                    );
                }
            }
        }

        self.store_operation(operation_id, OperationState::Succeeded, effect_count)?;
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
        let mut first = None;
        let mut after_cursor = None;
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let operation_id = decode_operation_key(key)?;
            let (state, _) = decode_operation(value)?;
            if matches!(
                state,
                OperationState::Succeeded | OperationState::PermanentlyBlocked
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

    fn reconcile_applying(
        &mut self,
        operation_id: OperationId,
        step: u32,
        effect_count: u32,
        attempt: u32,
        plan: EffectPlan,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        let observed = match self.executor.observe(operation_id, step, &plan) {
            Ok(value) => value,
            Err(failure) => {
                return self.handle_failure(
                    operation_id,
                    step,
                    effect_count,
                    attempt,
                    plan,
                    failure,
                );
            }
        };
        let receipt = match observed {
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
                        failure,
                    );
                }
            },
        };
        let applied = EffectLedgerRecord {
            plan,
            state: EffectState::Applied { attempt, receipt },
        };
        self.store_effect(operation_id, step, &applied, None)?;
        Ok(ReconcileOutcome::EffectApplied)
    }

    fn handle_failure(
        &mut self,
        operation_id: OperationId,
        step: u32,
        effect_count: u32,
        attempt: u32,
        plan: EffectPlan,
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
                };
                self.store_effect(operation_id, step, &blocked, Some(effect_count))?;
                Ok(ReconcileOutcome::PermanentlyBlocked)
            }
        }
    }

    fn load_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<(OperationState, u32), ReconcilerError> {
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
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.into_bytes().to_vec(),
            encode_operation(state, effect_count),
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
                encode_operation(state, effect_count),
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

fn encode_operation(state: OperationState, effect_count: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6);
    bytes.push(RECORD_VERSION);
    bytes.push(state as u8);
    bytes.extend_from_slice(&effect_count.to_le_bytes());
    bytes
}

fn decode_operation(bytes: &[u8]) -> Result<(OperationState, u32), ReconcilerError> {
    if bytes.len() != 6 || bytes[0] != RECORD_VERSION {
        return Err(ReconcilerError::CorruptLedger(
            "invalid operation record version or length",
        ));
    }
    let state = OperationState::from_byte(bytes[1])?;
    let effect_count = u32::from_le_bytes(
        bytes[2..]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid effect count"))?,
    );
    if effect_count == 0 || effect_count as usize > MAXIMUM_EFFECTS {
        return Err(ReconcilerError::CorruptLedger("invalid effect count"));
    }
    Ok((state, effect_count))
}

fn encode_effect(record: &EffectLedgerRecord) -> Result<Vec<u8>, ReconcilerError> {
    let (state, attempt, receipt, diagnostic) = match &record.state {
        EffectState::Planned => (1_u8, 0_u32, &[][..], ""),
        EffectState::Applying {
            attempt,
            diagnostic,
        } => (2, *attempt, &[][..], diagnostic.as_str()),
        EffectState::Applied { attempt, receipt } => (3, *attempt, receipt.as_bytes(), ""),
        EffectState::PermanentlyBlocked {
            attempt,
            diagnostic,
        } => (4, *attempt, &[][..], diagnostic.as_str()),
    };
    if record.plan.request.is_empty()
        || record.plan.request.len() > MAXIMUM_REQUEST_BYTES
        || receipt.len() > MAXIMUM_RECEIPT_BYTES
        || diagnostic.len() > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::InvalidPlan("effect record exceeds bounds"));
    }
    let request_length = u32::try_from(record.plan.request.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect request exceeds bounds"))?;
    let receipt_length = u32::try_from(receipt.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect receipt exceeds bounds"))?;
    let diagnostic_length = u16::try_from(diagnostic.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect diagnostic exceeds bounds"))?;
    let mut bytes =
        Vec::with_capacity(16 + record.plan.request.len() + receipt.len() + diagnostic.len());
    bytes.push(RECORD_VERSION);
    bytes.push(record.plan.domain as u8);
    bytes.push(state);
    bytes.push(0);
    bytes.extend_from_slice(&attempt.to_le_bytes());
    bytes.extend_from_slice(&request_length.to_le_bytes());
    bytes.extend_from_slice(&receipt_length.to_le_bytes());
    bytes.extend_from_slice(&diagnostic_length.to_le_bytes());
    bytes.extend_from_slice(&record.plan.request);
    bytes.extend_from_slice(receipt);
    bytes.extend_from_slice(diagnostic.as_bytes());
    Ok(bytes)
}

fn decode_effect(bytes: &[u8]) -> Result<EffectLedgerRecord, ReconcilerError> {
    if bytes.len() < 18 || bytes[0] != RECORD_VERSION || bytes[3] != 0 {
        return Err(ReconcilerError::CorruptLedger(
            "invalid effect record header",
        ));
    }
    let domain = EffectDomain::from_byte(bytes[1])?;
    let state = bytes[2];
    let attempt = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid effect attempt"))?,
    );
    let request_length = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid request length"))?,
    ) as usize;
    let receipt_length = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid receipt length"))?,
    ) as usize;
    let diagnostic_length = u16::from_le_bytes(
        bytes[16..18]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid diagnostic length"))?,
    ) as usize;
    let expected = 18_usize
        .checked_add(request_length)
        .and_then(|length| length.checked_add(receipt_length))
        .and_then(|length| length.checked_add(diagnostic_length))
        .ok_or(ReconcilerError::CorruptLedger("effect length overflow"))?;
    if expected != bytes.len()
        || request_length == 0
        || request_length > MAXIMUM_REQUEST_BYTES
        || receipt_length > MAXIMUM_RECEIPT_BYTES
        || diagnostic_length > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::CorruptLedger("invalid effect lengths"));
    }
    let request_end = 18 + request_length;
    let receipt_end = request_end + receipt_length;
    let request = bytes[18..request_end].to_vec();
    let receipt = bytes[request_end..receipt_end].to_vec();
    let diagnostic = std::str::from_utf8(&bytes[receipt_end..])
        .map_err(|_| ReconcilerError::CorruptLedger("diagnostic is not UTF-8"))?
        .to_owned();
    let state = match state {
        1 if attempt == 0 && receipt.is_empty() && diagnostic.is_empty() => EffectState::Planned,
        2 if attempt > 0 && receipt.is_empty() => EffectState::Applying {
            attempt,
            diagnostic,
        },
        3 if attempt > 0 && !receipt.is_empty() && diagnostic.is_empty() => EffectState::Applied {
            attempt,
            receipt: EffectReceipt(receipt),
        },
        4 if attempt > 0 && receipt.is_empty() && !diagnostic.is_empty() => {
            EffectState::PermanentlyBlocked {
                attempt,
                diagnostic,
            }
        }
        _ => {
            return Err(ReconcilerError::CorruptLedger(
                "invalid effect state fields",
            ));
        }
    };
    Ok(EffectLedgerRecord {
        plan: EffectPlan { domain, request },
        state,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::journal::JournalLimits;

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
    }

    impl SingleNodeEffectExecutor for Executor {
        fn observe(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
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
