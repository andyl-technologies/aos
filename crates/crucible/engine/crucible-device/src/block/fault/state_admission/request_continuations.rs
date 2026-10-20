//! Request-phase deadlines, service evidence, and deferred execution continuations.

use super::*;

impl BlockFaultState {
    /// Returns the earliest exact integrated-service release coordinate.
    #[must_use]
    pub(in crate::block) fn next_service_completion_ticks(&self) -> Option<u64> {
        self.service.next_completion_ticks()
    }

    /// Returns the earliest request resolve/persist opportunity coordinate.
    #[must_use]
    pub(in crate::block) fn next_execution_deadline_ticks(&self) -> Option<u64> {
        self.execution_pending
            .values()
            .filter(|pending| pending.execution.is_none())
            .map(|pending| pending.opportunity.ready_ticks)
            .min()
    }

    /// Returns the earliest request mutation awaiting a persist decision.
    #[must_use]
    pub(in crate::block) fn next_request_persistence_deadline_ticks(&self) -> Option<u64> {
        self.request_persistence_pending
            .values()
            .filter(|pending| pending.persistence.is_none())
            .map(|pending| pending.opportunity.ready_ticks)
            .min()
    }

    /// Returns the earliest completion awaiting an exact delivery decision.
    #[must_use]
    pub(in crate::block) fn next_delivery_deadline_ticks(&self) -> Option<u64> {
        self.delivery_pending
            .values()
            .filter(|pending| {
                pending.delivery.is_none()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| self.actual_durable_frontier >= frontier)
            })
            .map(|pending| pending.opportunity.ready_ticks)
            .min()
    }

    /// Returns the earliest dependency-ready physical persistence boundary.
    #[must_use]
    pub(in crate::block) fn next_persistence_deadline_ticks(&self) -> Option<u64> {
        self.media_queue
            .keys()
            .filter(|sequence| self.persistence.is_ready_at(**sequence, u64::MAX))
            .filter_map(|sequence| self.persistence.deadline_ticks(*sequence))
            .min()
    }

    /// Drains contributor-level service evidence in canonical completion order.
    pub(in crate::block::fault) fn drain_service_outcomes_untracked(
        &mut self,
    ) -> Vec<BlockServiceCompletion> {
        observed_retain!(self, storage_outcome_order, |outcome| matches!(
            outcome,
            BlockStorageOutcomeRef::Persistence(_)
        ));
        observed_take!(self, service_outcomes)
    }

    /// Borrows integrated-service completion evidence without acknowledging it.
    #[must_use]
    pub fn service_outcomes(&self) -> &[BlockServiceCompletion] {
        &self.service_outcomes
    }

    pub(in crate::block::fault) fn defer_execution_untracked(
        &mut self,
        request: &BlockRequest,
        request_icount: u64,
        ready_ticks: u64,
        mut admission: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        if self
            .execution_pending
            .contains_key(&admission.request_sequence)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "request execution sequence is repeated",
            });
        }
        if self.execution_pending.len() == crate::block::service::HARD_BLOCK_SERVICE_JOBS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_execution_pending",
                hard: crate::block::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        if let Some(removed) = observed_remove!(self, pending, &request.identity()) {
            observed_set!(
                self,
                pending_bytes,
                self.pending_bytes
                    .checked_sub(directive_owned_bytes(&removed)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "pending directive byte accounting underflow",
                    })?
            );
        }
        admission.service_rules.clear();
        let sequence = admission.request_sequence;
        let pending = BlockExecutionPendingRequest {
            opportunity: BlockExecutionOpportunity {
                request_sequence: sequence,
                request: request.clone(),
                request_icount,
                wire_digest: admission.request_digest,
                ready_ticks,
                admission,
            },
            execution: None,
        };
        observed_set!(
            self,
            execution_pending_bytes,
            self.execution_pending_bytes
                .checked_add(execution_pending_owned_bytes(&pending)?)
                .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "block_execution_pending_bytes",
                    hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                })?
        );
        observed_insert!(self, execution_pending, sequence, pending);
        Ok(())
    }

    /// Executes every ready request whose resolve/persist decision is installed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when a decision is malformed, execution fails,
    /// or the resulting completion cannot be represented exactly.
    pub(in crate::block::fault) fn resume_execution_to_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let ready = next
            .execution_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_ticks <= now_ticks && pending.execution.is_some())
                    .then_some((pending.opportunity.ready_ticks, *sequence))
            })
            .collect::<BTreeSet<_>>();
        for (ready_ticks, sequence) in ready {
            let pending = observed_remove!(next, execution_pending, &sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready execution request disappeared",
                },
            )?;
            observed_set!(
                next,
                execution_pending_bytes,
                next.execution_pending_bytes
                    .checked_sub(execution_pending_owned_bytes(&pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "execution-pending byte accounting underflow",
                    })?
            );
            let directive = pending
                .execution
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready execution request lost its decision",
                })?;
            if matches!(
                pending.opportunity.request.op,
                BlockOp::Write | BlockOp::Discard | BlockOp::Flush
            ) && block_admission_error(&pending.opportunity.request, &directive, &next.config)
                .is_none()
                && directive.error_result.is_none()
            {
                next.defer_request_persistence(
                    pending.opportunity.request,
                    pending.opportunity.request_icount,
                    ready_ticks,
                    directive,
                )?;
                continue;
            }
            next.execute_to_delivery(
                base,
                &mut next_durable,
                &pending.opportunity.request,
                pending.opportunity.request_icount,
                directive,
                ready_ticks,
            )?;
        }
        if !next.persistence_execution_required {
            next.persist_due(base, &mut next_durable, now_ticks)?;
        }
        *self = next;
        *durable = next_durable;
        Ok(Vec::new())
    }

    pub(in crate::block::fault) fn defer_request_persistence_untracked(
        &mut self,
        request: BlockRequest,
        request_icount: u64,
        ready_ticks: u64,
        resolved: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        let sequence = resolved.request_sequence;
        if self.request_persistence_pending.contains_key(&sequence) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "request persistence sequence is repeated",
            });
        }
        if self.request_persistence_pending.len() == crate::block::service::HARD_BLOCK_SERVICE_JOBS
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_request_persistence_pending",
                hard: crate::block::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        let pending = BlockRequestPersistencePending {
            opportunity: BlockRequestPersistenceOpportunity {
                request_sequence: sequence,
                wire_digest: resolved.request_digest,
                request,
                request_icount,
                ready_ticks,
                resolved,
            },
            persistence: None,
        };
        observed_set!(
            self,
            request_persistence_pending_bytes,
            self.request_persistence_pending_bytes
                .checked_add(request_persistence_pending_owned_bytes(&pending)?)
                .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "block_request_persistence_pending_bytes",
                    hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                })?
        );
        observed_insert!(self, request_persistence_pending, sequence, pending);
        Ok(())
    }

    /// Executes every request whose exact persist decision is installed and ready.
    pub(in crate::block::fault) fn resume_request_persistence_to_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let ready = next
            .request_persistence_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_ticks <= now_ticks && pending.persistence.is_some())
                    .then_some((pending.opportunity.ready_ticks, *sequence))
            })
            .collect::<BTreeSet<_>>();
        for (ready_ticks, sequence) in ready {
            let pending = observed_remove!(next, request_persistence_pending, &sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready request-persistence opportunity disappeared",
                },
            )?;
            observed_set!(
                next,
                request_persistence_pending_bytes,
                next.request_persistence_pending_bytes
                    .checked_sub(request_persistence_pending_owned_bytes(&pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "request-persistence byte accounting underflow",
                    })?
            );
            let directive = pending
                .persistence
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready request-persistence opportunity lost its decision",
                })?;
            next.execute_to_delivery(
                base,
                &mut next_durable,
                &pending.opportunity.request,
                pending.opportunity.request_icount,
                directive,
                ready_ticks,
            )?;
        }
        *self = next;
        *durable = next_durable;
        Ok(Vec::new())
    }
}
