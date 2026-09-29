//! Block request execution, byte mutation, and durability progression.
//!
//! This module applies already-resolved directives to real overlay, cache,
//! controller, and media state; it never evaluates fault signals itself.

use super::*;

mod payload;
mod persistence;

impl BlockFaultState {
    pub(super) fn execute_to_delivery_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
        directive: ResolvedBlockFaultDirective,
        mutation_ticks: u64,
    ) -> Result<(), DeviceError> {
        if self
            .delivery_pending
            .contains_key(&directive.request_sequence)
            || self.delivery_pending.len() == crate::block::service::HARD_BLOCK_SERVICE_JOBS
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_delivery_pending",
                hard: crate::block::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let (response, mut persistence_wait_ticks) =
            next.execute_wire(base, &mut next_durable, request, &directive)?;
        if response.status == BlockStatus::Ok
            && matches!(request.op, BlockOp::Write | BlockOp::Discard)
            && next.config.completion_durability == BlockCompletionDurability::Durable
        {
            persistence_wait_ticks = persistence_wait_ticks.max(next.persist_through(
                base,
                &mut next_durable,
                next.next_cache_sequence,
                mutation_ticks,
            )?);
        }
        let ready_ticks = mutation_ticks.checked_add(persistence_wait_ticks).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "storage mutation and persistence wait overflow",
            },
        )?;
        let required_durable_frontier = (response.status == BlockStatus::Ok)
            .then(|| match request.op {
                BlockOp::Write | BlockOp::Discard
                    if next.config.completion_durability == BlockCompletionDurability::Durable =>
                {
                    matches!(
                        directive.write_disposition,
                        BlockFaultWriteDisposition::Apply
                            | BlockFaultWriteDisposition::Misdirected { .. }
                    )
                    .then_some(next.next_cache_sequence)
                }
                BlockOp::Flush
                    if matches!(
                        directive.flush_disposition,
                        BlockFaultFlushDisposition::Honest
                    ) =>
                {
                    Some(next.next_cache_sequence)
                }
                _ => None,
            })
            .flatten();
        let pending = BlockDeliveryPending {
            opportunity: BlockDeliveryOpportunity {
                request_sequence: directive.request_sequence,
                request: request.clone(),
                request_icount,
                ready_ticks,
                wire_digest: directive.request_digest,
                response,
                resolved: directive,
                required_durable_frontier,
            },
            delivery: None,
        };
        observed_set!(
            next,
            delivery_pending_bytes,
            next.delivery_pending_bytes
                .checked_add(delivery_pending_owned_bytes(&pending)?)
                .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "block_delivery_pending_bytes",
                    hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                })?
        );
        observed_insert!(
            next,
            delivery_pending,
            pending.opportunity.request_sequence,
            pending
        );
        *self = next;
        *durable = next_durable;
        Ok(())
    }

    /// Releases every computed completion with an installed deliver decision.
    pub(super) fn resume_delivery_to_untracked(
        &mut self,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let ready = next
            .delivery_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_ticks <= now_ticks
                    && pending.delivery.is_some()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| next.actual_durable_frontier >= frontier))
                .then_some((pending.opportunity.ready_ticks, *sequence))
            })
            .collect::<BTreeSet<_>>();
        let mut released = Vec::with_capacity(ready.len());
        for (ready_ticks, sequence) in ready {
            let pending = observed_remove!(next, delivery_pending, &sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready delivery opportunity disappeared",
                },
            )?;
            observed_set!(
                next,
                delivery_pending_bytes,
                next.delivery_pending_bytes
                    .checked_sub(delivery_pending_owned_bytes(&pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "delivery-pending byte accounting underflow",
                    })?
            );
            let directive = pending
                .delivery
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready delivery opportunity lost its decision",
                })?;
            let computed = next.finish_computed_response(
                &pending.opportunity.request,
                pending.opportunity.request_icount,
                pending.opportunity.response,
                0,
                &directive,
            )?;
            released.push(BlockDeferredResponse {
                finished_ticks: ready_ticks,
                request: pending.opportunity.request,
                request_icount: pending.opportunity.request_icount,
                computed,
            });
        }
        *self = next;
        Ok(released)
    }

    /// Advances service and executes every request released by all constraints.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when service state is malformed, persistence at
    /// an intervening boundary fails, or released device execution fails.
    pub(super) fn advance_service_to_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let service_count = next.service.continuations().len();
        let outcomes = next.service.advance_to(now_ticks)?;
        next.observation_changed |=
            !outcomes.is_empty() || next.service.continuations().len() != service_count;
        if next
            .service_outcomes
            .len()
            .checked_add(outcomes.len())
            .is_none_or(|count| count > crate::block::service::HARD_BLOCK_SERVICE_JOBS)
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_service_outcomes",
                hard: crate::block::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        let mut ready = BTreeMap::<(u64, u64), u64>::new();
        for outcome in &outcomes {
            let pending = next.service_pending.get_mut(&outcome.sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "service completion has no queued block request",
                },
            )?;
            if !pending.remaining_contributors.remove(&outcome.contributor) {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "service contributor completed a request twice",
                });
            }
            next.observation_changed = true;
            observed_member_set!(
                next,
                pending.finished_ticks,
                pending.finished_ticks.max(outcome.finished_ticks)
            );
            if pending.remaining_contributors.is_empty() {
                ready.insert(
                    (pending.finished_ticks, pending.directive.request_sequence),
                    outcome.sequence,
                );
            }
        }
        let first_outcome = next.service_outcomes.len();
        let outcome_end =
            first_outcome
                .checked_add(outcomes.len())
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "block_service_outcomes",
                    hard: crate::block::service::HARD_BLOCK_SERVICE_JOBS,
                })?;
        for index in first_outcome..outcome_end {
            observed_push!(
                next,
                storage_outcome_order,
                BlockStorageOutcomeRef::Service(index)
            );
        }
        next.service_outcomes.extend(outcomes);
        let mut released = Vec::with_capacity(ready.len());
        for ((finished_ticks, _request_sequence), sequence) in ready {
            next.persist_due(base, &mut next_durable, finished_ticks)?;
            let mut pending = observed_remove!(next, service_pending, &sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready service request disappeared",
                },
            )?;
            observed_set!(
                next,
                service_pending_bytes,
                next.service_pending_bytes
                    .checked_sub(service_pending_owned_bytes(&pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "service-pending byte accounting underflow",
                    })?
            );
            pending.directive.service_rules.clear();
            pending.directive.execution_ticks = finished_ticks;
            if !pending.directive.persistence_transforms.is_empty() {
                pending.directive.persistence_admitted_ticks = finished_ticks;
            }
            if next.execution_opportunities_required {
                next.defer_execution(
                    &pending.request,
                    pending.request_icount,
                    finished_ticks,
                    pending.directive,
                )?;
            } else {
                let computed = next.execute_immediate(
                    base,
                    &mut next_durable,
                    &pending.request,
                    pending.request_icount,
                    pending.directive,
                )?;
                released.push(BlockDeferredResponse {
                    finished_ticks,
                    request: pending.request,
                    request_icount: pending.request_icount,
                    computed,
                });
            }
        }
        next.persist_due(base, &mut next_durable, now_ticks)?;
        *self = next;
        *durable = next_durable;
        Ok(released)
    }

    pub(super) fn execute_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
    ) -> Result<ComputedResponse, DeviceError> {
        let identity = request.identity();
        let preserved_retry = self.retry_preserve_authorizations.contains(&identity);
        match self.transport_epoch {
            Some(epoch) if epoch != request.epoch && !preserved_retry => {
                return self
                    .dispose_retired_transport_request_if_needed(identity)?
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "stale block request did not produce a reset disposition",
                    })
                    .map(|primary| ComputedResponse {
                        primary: Some(primary),
                        additional: Vec::new(),
                        additional_latency_ticks: 0,
                    });
            }
            None => observed_set!(self, transport_epoch, Some(request.epoch)),
            Some(_) => {}
        }
        let mut directive = match self.pending.get(&identity) {
            Some(directive) => directive.clone(),
            None if self.execution_required => {
                return Err(DeviceError::MissingBlockFaultDirective {
                    request_id: request.request_id,
                });
            }
            None => {
                let mut directive =
                    ResolvedBlockFaultDirective::fault_free(request, self.config.length_bytes);
                directive.execution_ticks = request_icount;
                directive
            }
        };
        directive.validate_for(request, &self.config)?;
        let arrival_ticks = request_icount;
        if self
            .recovery_until_ticks
            .is_some_and(|deadline| arrival_ticks < deadline)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request crossed the host boundary during controller recovery",
            });
        }
        if self
            .recovery_until_ticks
            .is_some_and(|deadline| arrival_ticks >= deadline)
        {
            observed_set!(self, recovery_until_ticks, None);
        }
        if directive.retain_completion
            && self.retained_completions.contains_key(&request.identity())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "request identity already owns a retained completion",
            });
        }
        if directive.retain_completion
            && self.retained_completions.len() == HARD_BLOCK_RETAINED_COMPLETIONS
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "retained_completions",
                hard: HARD_BLOCK_RETAINED_COMPLETIONS,
            });
        }
        if !directive.service_rules.is_empty()
            && block_admission_error(request, &directive, &self.config).is_none()
        {
            if self
                .service_pending
                .values()
                .any(|pending| pending.request.request_id == request.request_id)
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "request identity is already queued for storage service",
                });
            }
            let admitted_ticks = directive.execution_ticks;
            let service_job = BlockServiceJob {
                sequence: directive.request_sequence,
                operation: request.op,
                bytes: u64::from(request.count),
                admitted_ticks,
            };
            let mut admitted_service = self.service.clone();
            match admitted_service.admit(service_job, &directive.service_rules) {
                Ok(()) => {}
                Err(DeviceError::BlockServiceQueueFull { .. }) => {
                    directive.service_rules.clear();
                    directive.error_result = Some(BlockFaultResult::Busy);
                }
                Err(error) => return Err(error),
            }
            if directive.service_rules.is_empty() {
                // Queue capacity is a modeled request rejection. Fall through
                // to consume the directive and return the stable Busy result.
            } else {
                let mut next = self.clone();
                if let Some(removed) = observed_remove!(next, pending, &identity) {
                    observed_set!(
                        next,
                        pending_bytes,
                        next.pending_bytes
                            .checked_sub(directive_owned_bytes(&removed)?)
                            .ok_or(DeviceError::InvalidBlockFaultDirective {
                                reason: "pending directive byte accounting underflow",
                            })?
                    );
                }
                observed_set!(next, service, admitted_service);
                let remaining_contributors = directive
                    .service_rules
                    .iter()
                    .map(|rule| rule.contributor)
                    .collect();
                let pending = BlockServicePendingRequest {
                    request: request.clone(),
                    request_icount,
                    directive,
                    remaining_contributors,
                    finished_ticks: admitted_ticks,
                };
                let owned_bytes = service_pending_owned_bytes(&pending)?;
                observed_set!(
                    next,
                    service_pending_bytes,
                    next.service_pending_bytes
                        .checked_add(owned_bytes)
                        .filter(|total| *total <= HARD_PENDING_BLOCK_FAULT_BYTES)
                        .ok_or(DeviceError::BlockFaultStateLimit {
                            field: "block_service_pending_bytes",
                            hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES)
                                .unwrap_or(usize::MAX),
                        })?
                );
                if observed_insert!(
                    next,
                    service_pending,
                    pending.directive.request_sequence,
                    pending
                )
                .is_some()
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage service request sequence is repeated",
                    });
                }
                if preserved_retry {
                    let removed = observed_remove!(next, retry_preserve_authorizations, &identity);
                    debug_assert!(removed, "accepted preserved retry had authorization");
                }
                *self = next;
                return Ok(ComputedResponse {
                    primary: None,
                    additional: Vec::new(),
                    additional_latency_ticks: 0,
                });
            }
        }
        if self.execution_opportunities_required
            && block_admission_error(request, &directive, &self.config).is_none()
        {
            let mut next = self.clone();
            next.defer_execution(
                request,
                request_icount,
                directive.execution_ticks,
                directive,
            )?;
            if preserved_retry {
                let removed = observed_remove!(next, retry_preserve_authorizations, &identity);
                debug_assert!(removed, "accepted preserved retry had authorization");
            }
            *self = next;
            return Ok(ComputedResponse {
                primary: None,
                additional: Vec::new(),
                additional_latency_ticks: 0,
            });
        }
        let computed = self.execute_immediate(base, durable, request, request_icount, directive)?;
        if preserved_retry {
            let removed = observed_remove!(self, retry_preserve_authorizations, &identity);
            debug_assert!(removed, "accepted preserved retry had authorization");
        }
        Ok(computed)
    }

    pub(super) fn dispose_retired_transport_request_if_needed_untracked(
        &mut self,
        identity: BlockRequestIdentity,
    ) -> Result<Option<Response>, DeviceError> {
        if self.transport_epoch.is_none()
            || self.transport_epoch == Some(identity.epoch)
            || self.retry_preserve_authorizations.contains(&identity)
        {
            return Ok(None);
        }
        let policy = self
            .retired_transport_epochs
            .get(&identity.epoch)
            .copied()
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "block request epoch has no retained reset policy",
            })?;
        if policy.queued == BlockTransportPending::RetryPreserveId
            && self.retry_preserve_authorizations.len() == HARD_BLOCK_RETRY_PRESERVE_AUTHORIZATIONS
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "retry_preserve_authorizations",
                hard: HARD_BLOCK_RETRY_PRESERVE_AUTHORIZATIONS,
            });
        }

        let mut next = self.clone();
        if let Some(removed) = observed_remove!(next, pending, &identity) {
            observed_set!(
                next,
                pending_bytes,
                next.pending_bytes
                    .checked_sub(directive_owned_bytes(&removed)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "pending directive byte accounting underflow",
                    })?
            );
        }
        if policy.queued == BlockTransportPending::RetryPreserveId
            && !observed_insert!(next, retry_preserve_authorizations, identity)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request already has a preserved-retry authorization",
            });
        }
        let response = transport_pending_response(identity, policy.queued, policy.failure_result)?;
        *self = next;
        Ok(Some(response))
    }

    pub(super) fn execute_immediate(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<ComputedResponse, DeviceError> {
        let mut next = self.clone();
        if let Some(removed) = observed_remove!(next, pending, &request.identity()) {
            observed_set!(
                next,
                pending_bytes,
                next.pending_bytes
                    .checked_sub(directive_owned_bytes(&removed)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "pending directive byte accounting underflow",
                    })?
            );
        }
        let mut next_durable = durable.clone();
        let (response, persistence_wait_ticks) =
            next.execute_wire(base, &mut next_durable, request, &directive)?;
        let computed = next.finish_computed_response(
            request,
            request_icount,
            response,
            persistence_wait_ticks,
            &directive,
        )?;
        *self = next;
        *durable = next_durable;
        Ok(computed)
    }

    pub(super) fn finish_computed_response(
        &mut self,
        request: &BlockRequest,
        request_icount: u64,
        response: BlockResponse,
        persistence_wait_ticks: u64,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<ComputedResponse, DeviceError> {
        let additional_latency_ticks = crate::ns_to_tick(directive.additional_latency_nanos)?
            .checked_add(persistence_wait_ticks)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "storage persistence and completion latency overflow",
            })?;
        let encoded = response.encode().map_err(DeviceError::Codec)?;
        let status = if response.status == BlockStatus::Ok {
            ResponseStatus::Ok
        } else {
            ResponseStatus::Error
        };
        let primary = Response::new(request.request_id, status, encoded);
        if directive.retain_completion {
            observed_insert!(
                self,
                retained_completions,
                request.identity(),
                BlockRetainedCompletion {
                    identity: request.identity(),
                    recovery_response: primary.clone(),
                    timeout_response: block_response_to_uniform(
                        directive.retention_timeout_response.as_ref().ok_or(
                            DeviceError::InvalidBlockFaultDirective {
                                reason: "retained completion lost its timeout response",
                            },
                        )?,
                    )?,
                    request_icount,
                    additional_latency_ticks,
                    timeout_ticks: directive.retention_timeout_ticks.ok_or(
                        DeviceError::InvalidBlockFaultDirective {
                            reason: "retained completion lost its timeout coordinate",
                        },
                    )?,
                    recovery_event: directive.retention_recovery_event,
                    recovery_after_ticks: directive.retention_recovery_after_ticks,
                    recovery_after_sequence: directive.retention_recovery_after_sequence,
                    persist_through_on_recovery: (request.op == BlockOp::Flush
                        && matches!(
                            directive.flush_disposition,
                            BlockFaultFlushDisposition::Stall
                        ))
                    .then_some(self.next_cache_sequence),
                },
            );
        }
        let additional = directive
            .duplicate_completions
            .iter()
            .map(|duplicate| {
                let (gap_nanos, response) = match duplicate {
                    ResolvedBlockDuplicateCompletion::Ignore { gap_nanos } => (
                        *gap_nanos,
                        block_response_to_uniform(&BlockResponse::ignored_duplicate(
                            request.identity(),
                        ))?,
                    ),
                    ResolvedBlockDuplicateCompletion::ProtocolError {
                        gap_nanos,
                        response,
                    } => (
                        *gap_nanos,
                        block_response_to_uniform(&BlockResponse::duplicate_protocol_error(
                            response,
                        ))?,
                    ),
                    ResolvedBlockDuplicateCompletion::Reset {
                        gap_nanos,
                        transition,
                    } => (
                        *gap_nanos,
                        block_response_to_uniform(&BlockResponse::transport_reset(
                            request.identity(),
                            transition.transport_reset(request.epoch)?,
                        ))?,
                    ),
                };
                Ok(AdditionalCompletion {
                    gap_ticks: crate::ns_to_tick(gap_nanos)?,
                    response,
                })
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        Ok(ComputedResponse {
            primary: (!directive.retain_completion).then_some(primary),
            additional,
            additional_latency_ticks,
        })
    }
}
