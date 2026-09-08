//! Durable responses, attempt transitions, capacity, and execution identities.

use super::*;

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    pub(super) fn persist_response(
        &mut self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        self.persist_response_with_finding_candidate(request, disposition, None)
    }

    pub(super) fn persist_response_with_finding_candidate(
        &mut self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        let response =
            self.response_with_finding_candidate(request, disposition, finding_candidate)?;
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

    pub(super) fn response(
        &self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        self.response_with_finding_candidate(request, disposition, None)
    }

    pub(super) fn response_with_finding_candidate(
        &self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        match finding_candidate {
            Some(candidate) => {
                SubmitAttemptResponse::new_with_finding_candidate(request, disposition, candidate)
            }
            None => SubmitAttemptResponse::new(request, disposition),
        }
        .map_err(Into::into)
    }

    pub(super) fn advance_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: AttemptRuntimeState,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptAdvance<L::Error>, LocalExecutorError<L::Error>> {
        self.advance_attempt_optional(key, Some(expected), next)
    }

    pub(super) fn advance_attempt_optional(
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

    pub(super) fn has_capacity(&self, resources: AttemptResourceLimits) -> bool {
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

    pub(super) fn reserve(
        &mut self,
        request: &SubmitAttemptRequest,
        execution: ExecutionId,
        origin: AttemptExecutionOrigin,
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
                origin,
                cancellation: ExecutionCancellation::default(),
                checkpoint_request: ExecutionCheckpointRequest::default(),
                worker_in_flight: false,
            },
        );
        self.queued.push_back(execution);
        self.used = used;
        Ok(())
    }

    pub(super) fn reserve_checkpoint_recovery(
        &mut self,
        request: &SubmitAttemptRequest,
        execution: ExecutionId,
        origin: AttemptExecutionOrigin,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        self.reserve(request, execution, origin)?;
        let active = self
            .active
            .get(&execution)
            .ok_or(LocalExecutorError::LedgerInvariant {
                reason: "checkpoint recovery reservation disappeared",
            })?;
        active.checkpoint_request.request();
        Ok(())
    }

    pub(super) fn release_active(
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

    pub(super) fn release_active_if_present(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        if self.active.contains_key(&execution) {
            self.release_active(execution)?;
        }
        Ok(())
    }

    pub(super) fn release_active_if_idle(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        if self
            .active
            .get(&execution)
            .is_some_and(|active| !active.worker_in_flight)
        {
            self.release_active(execution)?;
        }
        Ok(())
    }

    pub(super) fn allocate_execution_id(
        &mut self,
    ) -> Result<ExecutionId, LocalExecutorError<L::Error>> {
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
