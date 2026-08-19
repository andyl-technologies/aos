//! Bounded single-host attempt admission and execution supervision.
//!
//! The supervisor implements the transport-neutral campaign
//! [`ExecutorService`] using a pluggable durable [`AssignmentLedger`]. It owns
//! only operational scheduling state: canonical attempt and observation
//! validation remains behind an injected read-only admission boundary, and no
//! campaign mutable-ref capability is accepted here.

use std::collections::{BTreeMap, VecDeque};

use crucible_campaign::{
    AttemptResourceLimits, CampaignCodecError, DaemonEpoch, ExecutionId, ExecutorRejection,
    ExecutorService, ObservationId, SubmitAttemptDisposition, SubmitAttemptRequest,
    SubmitAttemptResponse,
};

use crate::{
    AssignmentLedger, AssignmentPublish, AssignmentRecord, AttemptExecutionKey,
    AttemptRuntimeState, AttemptStateCas,
};

/// Read-only semantic and capability validation performed before guest work.
pub trait AttemptAdmissionValidator {
    /// Validates one complete immutable assignment basis.
    ///
    /// The implementation authenticates the attempt, lineage, referenced
    /// objects, and supported executor profile. Temporary input absence and
    /// stable incompatibility are protocol rejections, not transport errors.
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection>;

    /// Validates a published observation before durable completion admission.
    ///
    /// The default is deliberately fail-closed. Production validators
    /// authenticate the observation closure and exact attempt/lineage
    /// correspondence through the repository's read-only response validator.
    fn validate_completion(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        Err(CompletionValidationFailure::Incompatible)
    }
}

/// Stable reason a durable operational completion cannot be reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionValidationFailure {
    /// Referenced immutable input is not currently available for authentication.
    UnavailableInput,
    /// The immutable observation tier denied this executor access.
    Unauthorized,
    /// The observation is present but does not match the exact execution basis.
    Incompatible,
}

impl<F> AttemptAdmissionValidator for F
where
    F: Fn(&SubmitAttemptRequest) -> Result<(), ExecutorRejection>,
{
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        self(request)
    }
}

/// Admission validator used only by already-authenticated compositions/tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAllAttemptAdmission;

impl AttemptAdmissionValidator for AllowAllAttemptAdmission {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        Ok(())
    }

    fn validate_completion(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        Ok(())
    }
}

/// Hard single-host capacity advertised by one local executor incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorCapacity {
    maximum_concurrent_executions: u32,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_disk_bytes: u64,
    maximum_execution_quanta: u64,
}

impl ExecutorCapacity {
    /// Builds explicit bounded local execution capacity.
    ///
    /// A zero disk capacity is valid for read-only execution profiles.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorCapacityError`] when concurrency, CPU, resident
    /// memory, or execution-quanta capacity is zero.
    pub const fn new(
        maximum_concurrent_executions: u32,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_disk_bytes: u64,
        maximum_execution_quanta: u64,
    ) -> Result<Self, ExecutorCapacityError> {
        if maximum_concurrent_executions == 0 {
            return Err(ExecutorCapacityError::ZeroConcurrentExecutions);
        }
        if maximum_vcpus == 0 {
            return Err(ExecutorCapacityError::ZeroVcpus);
        }
        if maximum_resident_bytes == 0 {
            return Err(ExecutorCapacityError::ZeroResidentBytes);
        }
        if maximum_execution_quanta == 0 {
            return Err(ExecutorCapacityError::ZeroExecutionQuanta);
        }
        Ok(Self {
            maximum_concurrent_executions,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_disk_bytes,
            maximum_execution_quanta,
        })
    }

    /// Returns the maximum number of concurrent guest executions.
    #[must_use]
    pub const fn maximum_concurrent_executions(self) -> u32 {
        self.maximum_concurrent_executions
    }

    /// Returns the total virtual CPU capacity.
    #[must_use]
    pub const fn maximum_vcpus(self) -> u32 {
        self.maximum_vcpus
    }

    /// Returns the total resident-memory capacity in bytes.
    #[must_use]
    pub const fn maximum_resident_bytes(self) -> u64 {
        self.maximum_resident_bytes
    }

    /// Returns the total writable-materialization capacity in bytes.
    #[must_use]
    pub const fn maximum_disk_bytes(self) -> u64 {
        self.maximum_disk_bytes
    }

    /// Returns the per-execution deterministic work ceiling.
    #[must_use]
    pub const fn maximum_execution_quanta(self) -> u64 {
        self.maximum_execution_quanta
    }

    fn supports(self, resources: AttemptResourceLimits) -> bool {
        resources.maximum_vcpus() <= self.maximum_vcpus
            && resources.maximum_resident_bytes() <= self.maximum_resident_bytes
            && resources.maximum_disk_bytes() <= self.maximum_disk_bytes
            && resources.maximum_execution_quanta() <= self.maximum_execution_quanta
    }
}

/// Invalid local executor capacity configuration.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecutorCapacityError {
    /// No execution could ever be admitted.
    #[error("executor capacity has zero concurrent executions")]
    ZeroConcurrentExecutions,
    /// No request can satisfy a zero virtual CPU capacity.
    #[error("executor capacity has zero virtual CPUs")]
    ZeroVcpus,
    /// No request can satisfy a zero resident-memory capacity.
    #[error("executor capacity has zero resident bytes")]
    ZeroResidentBytes,
    /// No request can satisfy a zero deterministic work ceiling.
    #[error("executor capacity has zero execution quanta")]
    ZeroExecutionQuanta,
}

/// One accepted assignment ready for the local execution worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedAttempt {
    execution: ExecutionId,
    request: SubmitAttemptRequest,
}

impl QueuedAttempt {
    /// Returns the local execution incarnation allocated by the supervisor.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact immutable assignment request.
    #[must_use]
    pub const fn request(&self) -> &SubmitAttemptRequest {
        &self.request
    }
}

/// Idempotent result of publishing one executor completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// This call durably published the completion state.
    Completed,
    /// The exact observation was already durable for this execution.
    AlreadyCompleted,
    /// Cancellation won the race; the observation is diagnostic only.
    Canceled,
    /// The supplied execution is not the attempt's current execution.
    NotCurrent,
}

/// Idempotent result of canceling one local execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancellationOutcome {
    /// This call durably accepted cancellation.
    Canceled,
    /// The exact execution was already canceled.
    AlreadyCanceled,
    /// Completion won the race and remains eligible for validation.
    AlreadyCompleted {
        /// Immutable observation published before cancellation.
        observation: ObservationId,
    },
    /// The supplied execution is not the attempt's current execution.
    NotCurrent,
}

/// Failure from local executor ledger or internal state coordination.
#[derive(Debug, thiserror::Error)]
pub enum LocalExecutorError<E> {
    /// The operational ledger could not complete a safe read or publication.
    #[error("executor assignment ledger operation failed")]
    Ledger(E),
    /// A protocol response could not be constructed canonically.
    #[error(transparent)]
    Protocol(#[from] CampaignCodecError),
    /// The single-writer ledger contradicted the supervisor's validated basis.
    #[error("executor ledger invariant failed: {reason}")]
    LedgerInvariant {
        /// Stable invariant category.
        reason: &'static str,
    },
    /// One execution produced two different immutable observations.
    #[error("executor completion conflicts with the durable observation")]
    ConflictingCompletion,
    /// The semantic validator could not authenticate the completed observation.
    #[error("executor completion validation failed: {reason:?}")]
    CompletionValidation {
        /// Stable semantic failure category.
        reason: CompletionValidationFailure,
    },
    /// The daemon exhausted its process-local execution identity sequence.
    #[error("executor execution identity sequence is exhausted")]
    ExecutionIdentityExhausted,
}

#[derive(Clone, Debug)]
struct ActiveExecution {
    request: SubmitAttemptRequest,
}

#[derive(Clone, Copy, Debug, Default)]
struct UsedCapacity {
    vcpus: u32,
    resident_bytes: u64,
    disk_bytes: u64,
}

enum AttemptAdvance<E> {
    Committed,
    CommittedAfterError(E),
}

/// Sole-writer bounded local executor over one operational ledger.
pub struct LocalExecutorSupervisor<L, V> {
    ledger: L,
    validator: V,
    daemon_epoch: DaemonEpoch,
    capacity: ExecutorCapacity,
    next_execution_ordinal: u64,
    active: BTreeMap<ExecutionId, ActiveExecution>,
    queued: VecDeque<ExecutionId>,
    used: UsedCapacity,
}

impl<L, V> LocalExecutorSupervisor<L, V> {
    /// Creates an empty process-local supervisor over durable operational state.
    ///
    /// A restarted process supplies a fresh [`DaemonEpoch`]. Stale running
    /// records from older epochs are replaceable; completed observations remain
    /// durable and immediately replayable.
    #[must_use]
    pub fn new(
        ledger: L,
        validator: V,
        daemon_epoch: DaemonEpoch,
        capacity: ExecutorCapacity,
    ) -> Self {
        Self {
            ledger,
            validator,
            daemon_epoch,
            capacity,
            next_execution_ordinal: 0,
            active: BTreeMap::new(),
            queued: VecDeque::new(),
            used: UsedCapacity::default(),
        }
    }

    /// Returns this process's daemon incarnation.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the configured hard local capacity.
    #[must_use]
    pub const fn capacity(&self) -> ExecutorCapacity {
        self.capacity
    }

    /// Returns the number of current execution reservations.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Returns the number of accepted executions not yet taken by a worker.
    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.queued.len()
    }

    /// Returns the ledger for read-only diagnostics and tests.
    #[must_use]
    pub const fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Returns the owned ledger after supervisor shutdown.
    #[must_use]
    pub fn into_ledger(self) -> L {
        self.ledger
    }

    /// Takes the next accepted execution exactly once from the pending queue.
    #[must_use]
    pub fn next_queued(&mut self) -> Option<QueuedAttempt> {
        while let Some(execution) = self.queued.pop_front() {
            if let Some(active) = self.active.get(&execution) {
                return Some(QueuedAttempt {
                    execution,
                    request: active.request.clone(),
                });
            }
        }
        None
    }
}

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    /// Durably records a published observation and releases local capacity.
    ///
    /// The caller publishes and authenticates the immutable observation before
    /// invoking this method. If cancellation already won, the observation is
    /// not promoted to the attempt's completed runtime state.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for ledger failures, impossible
    /// single-writer state races, or a conflicting second observation.
    pub fn complete_execution(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        observation: ObservationId,
    ) -> Result<CompletionOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CompletionOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Completed {
                execution: current_execution,
                observation: current_observation,
                ..
            } if current_execution == execution && current_observation == observation => {
                self.release_active_if_present(execution)?;
                Ok(CompletionOutcome::AlreadyCompleted)
            }
            AttemptRuntimeState::Completed {
                execution: current_execution,
                ..
            } if current_execution == execution => Err(LocalExecutorError::ConflictingCompletion),
            AttemptRuntimeState::Canceled {
                execution: current_execution,
                ..
            } if current_execution == execution => {
                self.release_active_if_present(execution)?;
                Ok(CompletionOutcome::Canceled)
            }
            AttemptRuntimeState::Running {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                let Some(active) = self.active.get(&execution) else {
                    return Ok(CompletionOutcome::NotCurrent);
                };
                if AttemptExecutionKey::new(active.request.lineage(), active.request.attempt())
                    != key
                {
                    return Err(LocalExecutorError::LedgerInvariant {
                        reason: "active execution attempt mismatch",
                    });
                }
                self.validator
                    .validate_completion(&active.request, observation)
                    .map_err(|reason| LocalExecutorError::CompletionValidation { reason })?;
                let next = AttemptRuntimeState::Completed {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    observation,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                self.release_active_if_present(execution)?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CompletionOutcome::Completed)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(CompletionOutcome::NotCurrent),
        }
    }

    /// Durably accepts cancellation and releases local capacity.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for ledger failures or impossible
    /// single-writer state races.
    pub fn cancel_execution(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CancellationOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Completed {
                execution: current_execution,
                observation,
                ..
            } if current_execution == execution => {
                self.release_active_if_present(execution)?;
                Ok(CancellationOutcome::AlreadyCompleted { observation })
            }
            AttemptRuntimeState::Canceled {
                execution: current_execution,
                ..
            } if current_execution == execution => {
                self.release_active_if_present(execution)?;
                Ok(CancellationOutcome::AlreadyCanceled)
            }
            AttemptRuntimeState::Running {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                let next = AttemptRuntimeState::Canceled {
                    execution_basis,
                    daemon_epoch,
                    execution,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                self.release_active_if_present(execution)?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CancellationOutcome::Canceled)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(CancellationOutcome::NotCurrent),
        }
    }

    fn submit(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        if let Some(record) = self
            .ledger
            .load_assignment(request.assignment())
            .map_err(LocalExecutorError::Ledger)?
        {
            if record.request() == request {
                return Ok(record.response().clone());
            }
            return self.response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::ConflictingAssignment,
                },
            );
        }

        if request.daemon_epoch() != self.daemon_epoch {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Unauthorized,
                },
            );
        }
        if let Err(reason) = self.validator.validate(request) {
            return self.persist_response(request, SubmitAttemptDisposition::Rejected { reason });
        }
        if !self.capacity.supports(request.resources()) {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            );
        }

        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
        let execution_basis = request.execution_basis_digest();
        let mut prior = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        match prior {
            Some(AttemptRuntimeState::Completed {
                execution_basis: current_basis,
                observation,
                ..
            }) if current_basis == execution_basis => {
                match self.validator.validate_completion(request, observation) {
                    Ok(()) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::AlreadyCompleted { observation },
                        );
                    }
                    Err(CompletionValidationFailure::UnavailableInput) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::UnavailableInput,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Unauthorized) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Unauthorized,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Incompatible) => {
                        let advance = self.advance_attempt_optional(key, prior, None)?;
                        if let AttemptAdvance::CommittedAfterError(error) = advance {
                            return Err(LocalExecutorError::Ledger(error));
                        }
                        prior = None;
                    }
                }
            }
            Some(AttemptRuntimeState::Running {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
            }) if daemon_epoch == self.daemon_epoch
                && current_basis == execution_basis
                && self.active.contains_key(&execution) =>
            {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyRunning { execution },
                );
            }
            Some(AttemptRuntimeState::Running {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            }) if daemon_epoch == self.daemon_epoch && current_basis != execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::Completed { .. }) => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::Running { .. })
            | Some(AttemptRuntimeState::Canceled { .. })
            | None => {}
        }

        if !self.has_capacity(request.resources()) {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Backpressure,
                },
            );
        }

        let execution = self.allocate_execution_id()?;
        let running = AttemptRuntimeState::Running {
            execution_basis,
            daemon_epoch: self.daemon_epoch,
            execution,
        };
        let advance = self.advance_attempt_optional(key, prior, Some(running))?;
        if let AttemptAdvance::CommittedAfterError(error) = advance {
            self.reserve(request, execution)?;
            return Err(LocalExecutorError::Ledger(error));
        }
        let response =
            self.persist_response(request, SubmitAttemptDisposition::Accepted { execution });
        // State is durable before response publication. Even when publication
        // is indeterminate, retain and run the prepared work so a response that
        // did become visible can never name an execution the daemon abandoned.
        self.reserve(request, execution)?;
        response
    }

    fn persist_response(
        &mut self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        let response = self.response(request, disposition)?;
        let record = AssignmentRecord::new(request.clone(), response.clone())?;
        match self
            .ledger
            .publish_assignment(&record)
            .map_err(LocalExecutorError::Ledger)?
        {
            AssignmentPublish::Stored | AssignmentPublish::Existing => Ok(response),
            AssignmentPublish::Conflict => Err(LocalExecutorError::LedgerInvariant {
                reason: "assignment changed after absent lookup",
            }),
        }
    }

    fn response(
        &self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        SubmitAttemptResponse::new(request, disposition).map_err(Into::into)
    }

    fn advance_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: AttemptRuntimeState,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptAdvance<L::Error>, LocalExecutorError<L::Error>> {
        self.advance_attempt_optional(key, Some(expected), next)
    }

    fn advance_attempt_optional(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptAdvance<L::Error>, LocalExecutorError<L::Error>> {
        let outcome = match self.ledger.compare_exchange_attempt(key, expected, next) {
            Ok(outcome) => outcome,
            Err(error) => {
                let observed = self
                    .ledger
                    .load_attempt(key)
                    .map_err(LocalExecutorError::Ledger)?;
                if observed == next {
                    return Ok(AttemptAdvance::CommittedAfterError(error));
                }
                if observed == expected {
                    return Err(LocalExecutorError::Ledger(error));
                }
                return Err(LocalExecutorError::LedgerInvariant {
                    reason: "attempt state changed while reconciling failed compare-exchange",
                });
            }
        };
        match outcome {
            AttemptStateCas::Advanced => Ok(AttemptAdvance::Committed),
            AttemptStateCas::Conflict { .. } => Err(LocalExecutorError::LedgerInvariant {
                reason: "attempt state changed under sole writer",
            }),
        }
    }

    fn has_capacity(&self, resources: AttemptResourceLimits) -> bool {
        u32::try_from(self.active.len()).is_ok_and(|active| {
            active < self.capacity.maximum_concurrent_executions
                && self
                    .used
                    .vcpus
                    .checked_add(resources.maximum_vcpus())
                    .is_some_and(|total| total <= self.capacity.maximum_vcpus)
                && self
                    .used
                    .resident_bytes
                    .checked_add(resources.maximum_resident_bytes())
                    .is_some_and(|total| total <= self.capacity.maximum_resident_bytes)
                && self
                    .used
                    .disk_bytes
                    .checked_add(resources.maximum_disk_bytes())
                    .is_some_and(|total| total <= self.capacity.maximum_disk_bytes)
        })
    }

    fn reserve(
        &mut self,
        request: &SubmitAttemptRequest,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        let resources = request.resources();
        let used = UsedCapacity {
            vcpus: self
                .used
                .vcpus
                .checked_add(resources.maximum_vcpus())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved vcpu accounting overflow",
                })?,
            resident_bytes: self
                .used
                .resident_bytes
                .checked_add(resources.maximum_resident_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved memory accounting overflow",
                })?,
            disk_bytes: self
                .used
                .disk_bytes
                .checked_add(resources.maximum_disk_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved disk accounting overflow",
                })?,
        };
        if self.active.contains_key(&execution) {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "execution identity was already active",
            });
        }
        self.active.insert(
            execution,
            ActiveExecution {
                request: request.clone(),
            },
        );
        self.queued.push_back(execution);
        self.used = used;
        Ok(())
    }

    fn release_active(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        let Some(active) = self.active.get(&execution) else {
            return Ok(());
        };
        let resources = active.request.resources();
        let used = UsedCapacity {
            vcpus: self
                .used
                .vcpus
                .checked_sub(resources.maximum_vcpus())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved vcpu accounting underflow",
                })?,
            resident_bytes: self
                .used
                .resident_bytes
                .checked_sub(resources.maximum_resident_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved memory accounting underflow",
                })?,
            disk_bytes: self
                .used
                .disk_bytes
                .checked_sub(resources.maximum_disk_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved disk accounting underflow",
                })?,
        };
        if self.active.remove(&execution).is_none() {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "active execution disappeared during release",
            });
        }
        self.queued.retain(|queued| *queued != execution);
        self.used = used;
        Ok(())
    }

    fn release_active_if_present(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        if self.active.contains_key(&execution) {
            self.release_active(execution)?;
        }
        Ok(())
    }

    fn allocate_execution_id(&mut self) -> Result<ExecutionId, LocalExecutorError<L::Error>> {
        loop {
            self.next_execution_ordinal = self
                .next_execution_ordinal
                .checked_add(1)
                .ok_or(LocalExecutorError::ExecutionIdentityExhausted)?;
            let mut bytes = self.daemon_epoch.as_bytes();
            let suffix = u64::from_be_bytes(bytes[8..].try_into().map_err(|_| {
                LocalExecutorError::LedgerInvariant {
                    reason: "daemon epoch execution suffix width",
                }
            })?) ^ self.next_execution_ordinal;
            bytes[8..].copy_from_slice(&suffix.to_be_bytes());
            let Ok(execution) = ExecutionId::from_bytes(bytes) else {
                continue;
            };
            if !self.active.contains_key(&execution) {
                return Ok(execution);
            }
        }
    }
}

impl<L, V> ExecutorService for LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    type Error = LocalExecutorError<L::Error>;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.submit(request)
    }
}

#[cfg(test)]
mod tests;
