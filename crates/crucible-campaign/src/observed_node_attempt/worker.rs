//! Reservation-before-dispatch execution with publication-only completion retries.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use thiserror::Error;

use super::*;
use crate::{CampaignRepository, CampaignRepositoryError};

/// Executes an admitted independent observation without deterministic cache reuse.
///
/// The adapter owns native process handles and implements the admitted clock and
/// barrier policy for every coupled owner. Returned result provenance describes
/// actual boundary events. An error from `start` or `poll` is treated as uncertain
/// native ownership; the worker never starts the same nonce again.
/// The adapter retains pending result evidence as operational GC roots until
/// publication succeeds. A GC retention owner also inventories the worker's
/// [`ObservedAttemptWorker::retention_roots`] while holding its ownership fence.
/// Destruction transfers unresolved native, ledger and scheduler custody into
/// an already-reserved owning retirement slot; it cannot release live ownership
/// merely because the worker or adapter value was dropped.
pub trait ObservedAttemptBackend {
    /// Reports adapter failures without requiring campaign-specific errors.
    type Error: std::error::Error;

    /// Verifies the actual native realization before a reservation is published.
    ///
    /// # Errors
    ///
    /// Returns an error if actual implementation identities, clock modes, device
    /// profiles, owner closure or input policy differ from the admitted request.
    /// This includes physical-owner leases and incarnation fences: uncertain
    /// ownership from another worker cannot authorize a new budget or execution.
    fn validate_realization(&mut self, request: &ObservedAttemptRequest)
    -> Result<(), Self::Error>;

    /// Starts one native execution after its first authoritative reservation.
    ///
    /// # Errors
    ///
    /// Returns an error if startup fails or ownership becomes uncertain. Even
    /// an error that occurs after native startup cannot authorize another start.
    fn start(&mut self, request: &ObservedAttemptRequest) -> Result<(), Self::Error>;

    /// Advances or samples the existing native execution without restarting it.
    ///
    /// # Errors
    ///
    /// Returns an error if execution ownership, evidence completeness or native
    /// completion becomes uncertain. `None` means the same execution is active.
    fn poll(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<ObservedAttemptResult>, Self::Error>;

    /// Stops or fences every coupled owner of an uncertain execution.
    ///
    /// This operation is idempotent and never starts or resumes native work.
    /// `true` acknowledges complete containment; `false` retains native
    /// ownership while containment is pending. The adapter withholds further
    /// budgets and contains the whole world rather than only its compute node.
    ///
    /// # Errors
    ///
    /// Returns an error when containment cannot yet be proved. The worker keeps
    /// ownership and retries containment without redispatching execution.
    fn contain(&mut self, execution: ExecutionId) -> Result<bool, Self::Error>;

    /// Inventories immutable evidence retained by native or deferred custody.
    ///
    /// The default is suitable only for adapters retaining no unpublished CAS
    /// objects. Supporting adapters include partial transcripts and evidence
    /// copied before native acknowledgement, including after cancellation.
    fn retention_roots(&self) -> BTreeSet<ContentId> {
        BTreeSet::new()
    }
}

/// Reports an independent-observation worker failure.
#[derive(Debug, Error)]
pub enum ObservedWorkerError {
    /// Immutable evidence or authoritative ledger publication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// The native adapter failed; uncertain dispatch is never repeated.
    #[error("observed backend {operation} failed: {reason}")]
    Backend {
        /// Adapter operation that failed.
        operation: &'static str,
        /// Bounded diagnostic rendered from the adapter failure.
        reason: String,
    },
    /// The bounded worker cannot accept another active execution.
    #[error("observed worker active-execution limit reached")]
    Capacity,
    /// Uncertain native ownership has not acknowledged whole-world containment.
    #[error("observed worker cannot dispatch while native containment is pending")]
    ContainmentPending,
    /// No native execution with this nonce belongs to the worker incarnation.
    #[error("observed execution is not owned by this worker")]
    UnknownExecution,
    /// Native completion described a different request or execution nonce.
    #[error("observed backend completion differs from the reserved request")]
    ResultMismatch,
}

enum ActiveExecution {
    Running(ObservedExecutionPermit),
    Publishing {
        permit: ObservedExecutionPermit,
        result: Box<ObservedAttemptResult>,
    },
    Quarantining {
        permit: ObservedExecutionPermit,
        reason: &'static str,
        contained: bool,
    },
}

/// Runs independent observations over a bounded set of native executions.
///
/// Completion bytes remain in memory until publication succeeds. Further polls
/// then retry publication only, never guest execution. Reconstructing a worker
/// does not reconstruct dispatch authority: existing ledger reservations return
/// their state and require explicit reconciliation or a new execution nonce.
/// Concurrent owners acquire the repository's GC-exclusion guard before taking
/// the worker mutation fence, matching GC's ref-before-operational-owner order.
/// Backend callbacks run outside repository mutation locks.
pub struct ObservedAttemptWorker<B> {
    repository: Arc<CampaignRepository>,
    backend: B,
    limit: usize,
    active: BTreeMap<ExecutionId, ActiveExecution>,
}

impl<B: ObservedAttemptBackend> ObservedAttemptWorker<B> {
    /// Builds a worker with an explicit bound on active native executions.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero limit or more than 4,096 active executions.
    pub fn new(
        repository: Arc<CampaignRepository>,
        backend: B,
        limit: usize,
    ) -> Result<Self, CampaignCodecError> {
        if limit == 0 || limit > 4096 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed worker active limit is invalid",
            });
        }
        Ok(Self {
            repository,
            backend,
            limit,
            active: BTreeMap::new(),
        })
    }

    /// Reserves and starts a fresh execution, or returns the existing ledger state.
    ///
    /// # Errors
    ///
    /// Returns an error for failed admission/realization, capacity, uncertain
    /// native startup or ledger failure. A start failure leaves the nonce
    /// reserved or quarantined, never eligible for automatic redispatch.
    pub fn submit(
        &mut self,
        ledger: &str,
        request: &ObservedAttemptRequest,
        admission: &impl ObservedAttemptAdmission,
    ) -> Result<ObservedAttemptState, ObservedWorkerError> {
        if self
            .repository
            .observed_attempt_state(ledger, request.execution())?
            .is_some()
        {
            // Retry still authenticates immutable inputs and graph correspondence.
            match self
                .repository
                .reserve_observed_attempt(ledger, request, admission)?
            {
                ObservedReservation::Existing(authenticated) => return Ok(authenticated),
                ObservedReservation::Fresh(_) => return Err(ObservedWorkerError::ResultMismatch),
            }
        }
        if self.active.values().any(|active| {
            matches!(
                active,
                ActiveExecution::Quarantining {
                    contained: false,
                    ..
                }
            )
        }) {
            return Err(ObservedWorkerError::ContainmentPending);
        }
        if self.active.len() >= self.limit {
            return Err(ObservedWorkerError::Capacity);
        }
        if self.active.contains_key(&request.execution()) {
            return Err(ObservedWorkerError::ResultMismatch);
        }
        self.backend
            .validate_realization(request)
            .map_err(|error| backend_error("validate", &error))?;

        let permit = match self
            .repository
            .reserve_observed_attempt(ledger, request, admission)?
        {
            ObservedReservation::Existing(state) => return Ok(state),
            ObservedReservation::Fresh(permit) => permit,
        };
        match catch_unwind(AssertUnwindSafe(|| self.backend.start(permit.request()))) {
            Ok(Ok(())) => {
                self.active
                    .insert(request.execution(), ActiveExecution::Running(permit));
                Ok(ObservedAttemptState::Reserved(request.clone()))
            }
            Ok(Err(error)) => {
                self.active.insert(
                    request.execution(),
                    ActiveExecution::Quarantining {
                        permit,
                        reason: "native-start-uncertain",
                        contained: false,
                    },
                );
                // Preserve quarantine work in memory if the store is unavailable.
                let _ = self.poll(request.execution());
                Err(backend_error("start", &error))
            }
            Err(_) => {
                self.active.insert(
                    request.execution(),
                    ActiveExecution::Quarantining {
                        permit,
                        reason: "native-start-panicked",
                        contained: false,
                    },
                );
                Err(callback_panicked("start"))
            }
        }
    }

    /// Polls an owned execution or retries its retained result publication.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown nonce, uncertain native completion,
    /// divergent completion provenance or publication failure. Publication
    /// failures retain original result bytes and never poll the backend again.
    pub fn poll(
        &mut self,
        execution: ExecutionId,
    ) -> Result<ObservedAttemptState, ObservedWorkerError> {
        let active = match self.active.remove(&execution) {
            Some(active) => active,
            None => {
                return match self.repository.observed_execution_state(execution)? {
                    Some(
                        state @ (ObservedAttemptState::Completed(_)
                        | ObservedAttemptState::Quarantined { .. }),
                    ) => Ok(state),
                    _ => Err(ObservedWorkerError::UnknownExecution),
                };
            }
        };
        let active = match active {
            ActiveExecution::Running(permit) => {
                match catch_unwind(AssertUnwindSafe(|| self.backend.poll(execution))) {
                    Ok(Ok(None)) => {
                        let state = ObservedAttemptState::Reserved(permit.request().clone());
                        self.active
                            .insert(execution, ActiveExecution::Running(permit));
                        return Ok(state);
                    }
                    Ok(Ok(Some(result))) if result.request() == permit.request() => {
                        ActiveExecution::Publishing {
                            permit,
                            result: Box::new(result),
                        }
                    }
                    Ok(Ok(Some(_))) => {
                        self.active.insert(
                            execution,
                            ActiveExecution::Quarantining {
                                permit,
                                reason: "native-result-request-mismatch",
                                contained: false,
                            },
                        );
                        let _ = self.poll(execution);
                        return Err(ObservedWorkerError::ResultMismatch);
                    }
                    Ok(Err(error)) => {
                        self.active.insert(
                            execution,
                            ActiveExecution::Quarantining {
                                permit,
                                reason: "native-poll-uncertain",
                                contained: false,
                            },
                        );
                        let _ = self.poll(execution);
                        return Err(backend_error("poll", &error));
                    }
                    Err(_) => {
                        self.active.insert(
                            execution,
                            ActiveExecution::Quarantining {
                                permit,
                                reason: "native-poll-panicked",
                                contained: false,
                            },
                        );
                        return Err(callback_panicked("poll"));
                    }
                }
            }
            other => other,
        };

        let mut active = active;
        let mut containment_error = None;
        if let ActiveExecution::Quarantining { contained, .. } = &mut active
            && !*contained
        {
            match catch_unwind(AssertUnwindSafe(|| self.backend.contain(execution))) {
                Ok(Ok(acknowledged)) => *contained = acknowledged,
                Ok(Err(error)) => containment_error = Some(backend_error("contain", &error)),
                Err(_) => containment_error = Some(callback_panicked("contain")),
            }
        }

        let published = match &active {
            ActiveExecution::Publishing { permit, result } => self
                .repository
                .publish_observed_result(permit, result)
                .map(ObservedAttemptState::Completed),
            ActiveExecution::Quarantining { permit, reason, .. } => self
                .repository
                .quarantine_observed_attempt(permit.ledger(), permit.request(), reason),
            ActiveExecution::Running(_) => return Err(ObservedWorkerError::ResultMismatch),
        };
        match published {
            Ok(state) => {
                if matches!(
                    &active,
                    ActiveExecution::Quarantining {
                        contained: false,
                        ..
                    }
                ) {
                    self.active.insert(execution, active);
                }
                match containment_error {
                    Some(error) => Err(error),
                    None => Ok(state),
                }
            }
            Err(error) => {
                self.active.insert(execution, active);
                Err(error.into())
            }
        }
    }

    /// Contains an original active execution without admitting another dispatch.
    ///
    /// Pending completed bytes keep their publication-only path; cancellation
    /// never replaces an already observed terminal result. An active native run
    /// becomes a monotonic quarantine under its original permit. Further calls
    /// retry authentic whole-world containment and ledger publication only.
    ///
    /// # Errors
    /// Returns native containment or durable publication failure while retaining
    /// original custody, or refuses an execution this worker never owned.
    pub fn cancel(
        &mut self,
        execution: ExecutionId,
    ) -> Result<ObservedAttemptState, ObservedWorkerError> {
        if let Some(active) = self.active.remove(&execution) {
            let contained = match active {
                ActiveExecution::Running(permit) => ActiveExecution::Quarantining {
                    permit,
                    reason: "executor-cancelled",
                    contained: false,
                },
                other => other,
            };
            self.active.insert(execution, contained);
        }

        self.poll(execution)
    }

    /// Returns the number of owned native or pending-publication executions.
    #[must_use]
    pub fn active_executions(&self) -> usize {
        self.active.len()
    }

    /// Returns immutable roots owned by active execution or pending publication.
    ///
    /// A retention owner inventories these roots under the same fence that
    /// excludes worker mutations. Pending result traces remain rooted even
    /// while the authoritative ledger still contains only a dispatch reservation.
    #[must_use]
    pub fn retention_roots(&self) -> BTreeSet<ContentId> {
        let mut roots = self.backend.retention_roots();
        for active in self.active.values() {
            let permit = match active {
                ActiveExecution::Running(permit)
                | ActiveExecution::Publishing { permit, .. }
                | ActiveExecution::Quarantining { permit, .. } => permit,
            };
            roots.insert(permit.request().inputs());
            let roster = permit.request().capabilities().roster();
            roots.insert(roster.scenario().content_id());
            roots.insert(roster.configuration().content_id());
            if let ActiveExecution::Publishing { result, .. } = active {
                roots.extend([result.incoming(), result.outgoing(), result.evidence()]);
            }
        }
        roots
    }

    /// Returns the adapter for process-local status inspection.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }
}

fn backend_error(operation: &'static str, error: &impl std::fmt::Display) -> ObservedWorkerError {
    let reason: String = error.to_string().chars().take(4096).collect();
    ObservedWorkerError::Backend { operation, reason }
}

fn callback_panicked(operation: &'static str) -> ObservedWorkerError {
    ObservedWorkerError::Backend {
        operation,
        reason: "native callback panicked; original execution remains quarantined".into(),
    }
}
