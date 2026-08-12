//! Block request execution, byte mutation, and durability progression.
//!
//! This module applies already-resolved directives to real overlay, cache,
//! controller, and media state; it never evaluates fault signals itself.

use super::*;

impl BlockFaultState {
    pub(in crate::block) fn execute_to_delivery(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
        directive: ResolvedBlockFaultDirective,
        mutation_nanos: u64,
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
        let (response, mut persistence_wait_nanos) =
            next.execute_wire(base, &mut next_durable, request, &directive)?;
        if response.status == BlockStatus::Ok
            && matches!(request.op, BlockOp::Write | BlockOp::Discard)
            && next.config.completion_durability == BlockCompletionDurability::Durable
        {
            persistence_wait_nanos = persistence_wait_nanos.max(next.persist_through(
                base,
                &mut next_durable,
                next.next_cache_sequence,
                mutation_nanos,
            )?);
        }
        let ready_nanos = mutation_nanos.checked_add(persistence_wait_nanos).ok_or(
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
                ready_nanos,
                wire_digest: directive.request_digest,
                response,
                resolved: directive,
                required_durable_frontier,
            },
            delivery: None,
        };
        next.delivery_pending_bytes = next
            .delivery_pending_bytes
            .checked_add(delivery_pending_owned_bytes(&pending)?)
            .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
            .ok_or(DeviceError::BlockFaultStateLimit {
                field: "block_delivery_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            })?;
        next.delivery_pending
            .insert(pending.opportunity.request_sequence, pending);
        *self = next;
        *durable = next_durable;
        Ok(())
    }

    /// Releases every computed completion with an installed deliver decision.
    pub(in crate::block) fn resume_delivery_to(
        &mut self,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let ready = next
            .delivery_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_nanos <= now_nanos
                    && pending.delivery.is_some()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| next.actual_durable_frontier >= frontier))
                .then_some((pending.opportunity.ready_nanos, *sequence))
            })
            .collect::<BTreeSet<_>>();
        let mut released = Vec::with_capacity(ready.len());
        for (ready_nanos, sequence) in ready {
            let pending = next.delivery_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready delivery opportunity disappeared",
                },
            )?;
            next.delivery_pending_bytes = next
                .delivery_pending_bytes
                .checked_sub(delivery_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "delivery-pending byte accounting underflow",
                })?;
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
                finished_nanos: ready_nanos,
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
    pub(in crate::block) fn advance_service_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let outcomes = next.service.advance_to(now_nanos)?;
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
            pending.finished_nanos = pending.finished_nanos.max(outcome.finished_nanos);
            if pending.remaining_contributors.is_empty() {
                ready.insert(
                    (pending.finished_nanos, pending.directive.request_sequence),
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
            next.storage_outcome_order
                .push(BlockStorageOutcomeRef::Service(index));
        }
        next.service_outcomes.extend(outcomes);
        let mut released = Vec::with_capacity(ready.len());
        for ((finished_nanos, _request_sequence), sequence) in ready {
            next.persist_due(base, &mut next_durable, finished_nanos)?;
            let mut pending = next.service_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready service request disappeared",
                },
            )?;
            next.service_pending_bytes = next
                .service_pending_bytes
                .checked_sub(service_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "service-pending byte accounting underflow",
                })?;
            pending.directive.service_rules.clear();
            pending.directive.execution_nanos = finished_nanos;
            if !pending.directive.persistence_transforms.is_empty() {
                pending.directive.persistence_admitted_nanos = finished_nanos;
            }
            if next.execution_opportunities_required {
                next.defer_execution(
                    &pending.request,
                    pending.request_icount,
                    finished_nanos,
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
                    finished_nanos,
                    request: pending.request,
                    request_icount: pending.request_icount,
                    computed,
                });
            }
        }
        next.persist_due(base, &mut next_durable, now_nanos)?;
        *self = next;
        *durable = next_durable;
        Ok(released)
    }

    pub(in crate::block) fn execute(
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
                        additional_latency_nanos: 0,
                    });
            }
            None => self.transport_epoch = Some(request.epoch),
            Some(_) => {}
        }
        let mut directive = match self.pending.get(&identity) {
            Some(directive) => directive.clone(),
            None if self.execution_required => {
                return Err(DeviceError::MissingBlockFaultDirective {
                    request_id: request.request_id,
                });
            }
            None => ResolvedBlockFaultDirective::fault_free(request, self.config.length_bytes),
        };
        directive.validate_for(request, &self.config)?;
        let arrival_nanos =
            crucible_shmem::icount_to_virtual_ns(request_icount, self.icount_shift)?;
        if self
            .recovery_until_nanos
            .is_some_and(|deadline| arrival_nanos < deadline)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request crossed the host boundary during controller recovery",
            });
        }
        if self
            .recovery_until_nanos
            .is_some_and(|deadline| arrival_nanos >= deadline)
        {
            self.recovery_until_nanos = None;
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
            let admitted_nanos = directive.execution_nanos;
            let service_job = BlockServiceJob {
                sequence: directive.request_sequence,
                operation: request.op,
                bytes: u64::from(request.count),
                admitted_nanos,
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
                if let Some(removed) = next.pending.remove(&identity) {
                    next.pending_bytes = next
                        .pending_bytes
                        .checked_sub(directive_owned_bytes(&removed)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "pending directive byte accounting underflow",
                        })?;
                }
                next.service = admitted_service;
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
                    finished_nanos: admitted_nanos,
                };
                let owned_bytes = service_pending_owned_bytes(&pending)?;
                next.service_pending_bytes = next
                    .service_pending_bytes
                    .checked_add(owned_bytes)
                    .filter(|total| *total <= HARD_PENDING_BLOCK_FAULT_BYTES)
                    .ok_or(DeviceError::BlockFaultStateLimit {
                        field: "block_service_pending_bytes",
                        hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                    })?;
                if next
                    .service_pending
                    .insert(pending.directive.request_sequence, pending)
                    .is_some()
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage service request sequence is repeated",
                    });
                }
                if preserved_retry {
                    let removed = next.retry_preserve_authorizations.remove(&identity);
                    debug_assert!(removed, "accepted preserved retry had authorization");
                }
                *self = next;
                return Ok(ComputedResponse {
                    primary: None,
                    additional: Vec::new(),
                    additional_latency_nanos: 0,
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
                directive.execution_nanos,
                directive,
            )?;
            if preserved_retry {
                let removed = next.retry_preserve_authorizations.remove(&identity);
                debug_assert!(removed, "accepted preserved retry had authorization");
            }
            *self = next;
            return Ok(ComputedResponse {
                primary: None,
                additional: Vec::new(),
                additional_latency_nanos: 0,
            });
        }
        let computed = self.execute_immediate(base, durable, request, request_icount, directive)?;
        if preserved_retry {
            let removed = self.retry_preserve_authorizations.remove(&identity);
            debug_assert!(removed, "accepted preserved retry had authorization");
        }
        Ok(computed)
    }

    pub(in crate::block) fn dispose_retired_transport_request_if_needed(
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
        if let Some(removed) = next.pending.remove(&identity) {
            next.pending_bytes = next
                .pending_bytes
                .checked_sub(directive_owned_bytes(&removed)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte accounting underflow",
                })?;
        }
        if policy.queued == BlockTransportPending::RetryPreserveId
            && !next.retry_preserve_authorizations.insert(identity)
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
        if let Some(removed) = next.pending.remove(&request.identity()) {
            next.pending_bytes = next
                .pending_bytes
                .checked_sub(directive_owned_bytes(&removed)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte accounting underflow",
                })?;
        }
        let mut next_durable = durable.clone();
        let (response, persistence_wait_nanos) =
            next.execute_wire(base, &mut next_durable, request, &directive)?;
        let computed = next.finish_computed_response(
            request,
            request_icount,
            response,
            persistence_wait_nanos,
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
        persistence_wait_nanos: u64,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<ComputedResponse, DeviceError> {
        let additional_latency_nanos = directive
            .additional_latency_nanos
            .checked_add(persistence_wait_nanos)
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
            self.retained_completions.insert(
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
                    additional_latency_nanos,
                    timeout_nanos: directive.retention_timeout_nanos.ok_or(
                        DeviceError::InvalidBlockFaultDirective {
                            reason: "retained completion lost its timeout coordinate",
                        },
                    )?,
                    recovery_event: directive.retention_recovery_event,
                    recovery_after_nanos: directive.retention_recovery_after_nanos,
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
                    } => {
                        (
                            *gap_nanos,
                            block_response_to_uniform(&BlockResponse::transport_reset(
                                request.identity(),
                                transition.transport_reset(request.epoch)?,
                            ))?,
                        )
                    }
                };
                Ok(AdditionalCompletion {
                    gap_nanos,
                    response,
                })
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        Ok(ComputedResponse {
            primary: (!directive.retain_completion).then_some(primary),
            additional,
            additional_latency_nanos,
        })
    }

    /// Applies one externally misdirected write without fabricating a guest request.
    ///
    /// The destination uses its own geometry and normal durability policy at
    /// `admitted_nanos`, the source persistence opportunity's exact coordinate.
    /// The returned stage and frontier identify the exact destination completion
    /// acknowledgement that must gate source delivery. The multi-device owner is
    /// responsible for executing this method on cloned source/destination devices
    /// and committing both together.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for destination range, atomicity, cache, retained
    /// version, or durable-overlay failures.
    pub(in crate::block) fn apply_external_write(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request_id: u32,
        request_sequence: u64,
        admitted_nanos: u64,
        destination_offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        let request = BlockRequest::write(request_id, destination_offset, bytes);
        let mut directive =
            ResolvedBlockFaultDirective::fault_free(&request, self.config.length_bytes);
        directive.request_sequence = request_sequence;
        directive.execution_nanos = admitted_nanos;
        directive.persistence_admitted_nanos = admitted_nanos;
        directive.validate_for(&request, &self.config)?;
        if u64::from(request.count) > self.config.maximum_request_bytes
            || !request_in_capacity(&request, self.config.length_bytes)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external write exceeds destination capacity or request geometry",
            });
        }
        match self.apply_write(base, durable, &request, &directive)? {
            BlockWriteOutcome::Applied(_persistence_wait_nanos) => {
                Ok((self.config.completion_durability, self.next_cache_sequence))
            }
            BlockWriteOutcome::Rejected(_) => Err(DeviceError::BlockCacheFull {
                requested_bytes: u64::from(request.count),
                available_bytes: self
                    .config
                    .volatile_cache_bytes
                    .saturating_sub(self.volatile_bytes),
            }),
        }
    }

    pub(super) fn execute_wire(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<(BlockResponse, u64), DeviceError> {
        let admission_error = block_admission_error(request, directive, &self.config);
        let media_error = if admission_error.is_none() && directive.error_result.is_none() {
            self.media.apply(
                request,
                directive.execution_nanos,
                self.config.length_bytes,
                &directive.media_rules,
            )?
        } else {
            None
        };
        let error = admission_error.or(directive.error_result).or(media_error);
        if let Some(error) = error {
            return Ok((BlockResponse::error_for(request.identity(), error), 0));
        }
        match request.op {
            BlockOp::Read => {
                let mut bytes =
                    self.read_visible(base, durable, request.offset, request.count, true)?;
                if !directive.persistence_media_rules.is_empty() {
                    self.flash.read(
                        request,
                        directive.execution_nanos,
                        self.config.length_bytes,
                        &directive.persistence_media_rules,
                        &mut bytes,
                    )?;
                }
                self.flash
                    .apply_persistent_read(request.offset, &mut bytes)?;
                apply_read_transforms(&mut bytes, &directive.read_transforms)?;
                Ok((BlockResponse::ok_for(request.identity(), bytes), 0))
            }
            BlockOp::Write => match self.apply_write(base, durable, request, directive)? {
                BlockWriteOutcome::Applied(wait) => {
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), wait))
                }
                BlockWriteOutcome::Rejected(result) => {
                    Ok((BlockResponse::error_for(request.identity(), result), 0))
                }
            },
            BlockOp::Discard => self.apply_discard(base, durable, request, directive),
            BlockOp::Flush => match directive.flush_disposition {
                BlockFaultFlushDisposition::Honest => {
                    let frontier = self.next_cache_sequence;
                    let wait = self.persist_all(base, durable, directive.execution_nanos)?;
                    if wait == 0 {
                        self.reported_durable_frontier = self.actual_durable_frontier;
                    } else {
                        self.pending_barrier_frontier = Some(
                            self.pending_barrier_frontier
                                .map_or(frontier, |existing| existing.max(frontier)),
                        );
                        self.pending_honest_flush_frontier = Some(
                            self.pending_honest_flush_frontier
                                .map_or(frontier, |existing| existing.max(frontier)),
                        );
                    }
                    if self.actual_durable_frontier >= frontier {
                        self.pending_barrier_frontier = None;
                    }
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), wait))
                }
                BlockFaultFlushDisposition::Error(error) => {
                    Ok((BlockResponse::error_for(request.identity(), error), 0))
                }
                BlockFaultFlushDisposition::Lie => {
                    let frontier = self.next_cache_sequence;
                    self.reported_durable_frontier = frontier;
                    self.pending_barrier_frontier = Some(
                        self.pending_barrier_frontier
                            .map_or(frontier, |existing| existing.max(frontier)),
                    );
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), 0))
                }
                BlockFaultFlushDisposition::Stall => {
                    let frontier = self.next_cache_sequence;
                    self.pending_barrier_frontier = Some(
                        self.pending_barrier_frontier
                            .map_or(frontier, |existing| existing.max(frontier)),
                    );
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), 0))
                }
            },
            BlockOp::GetLength => Ok((
                BlockResponse::ok_for(
                    request.identity(),
                    directive.reported_capacity_bytes.to_le_bytes().to_vec(),
                ),
                0,
            )),
        }
    }

    pub(super) fn apply_discard(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<(BlockResponse, u64), DeviceError> {
        let granularity = u64::from(self.config.discard_granularity_bytes);
        if granularity == 0
            || request.count == 0
            || !request.offset.is_multiple_of(granularity)
            || !u64::from(request.count).is_multiple_of(granularity)
        {
            return Ok((
                BlockResponse::error_for(request.identity(), BlockErrorCode::InvalidRange),
                0,
            ));
        }
        if self.config.discard_semantics == BlockDiscardSemantics::ReadsOldData
            && directive.persistence_media_rules.is_empty()
        {
            return Ok((BlockResponse::ok_for(request.identity(), Vec::new()), 0));
        }
        let count = usize::try_from(request.count).map_err(|_error| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "discard range does not fit memory",
            }
        })?;
        let bytes = if !directive.persistence_media_rules.is_empty() {
            vec![0xff; count]
        } else {
            match self.config.discard_semantics {
                BlockDiscardSemantics::DeterministicZero => vec![0; count],
                BlockDiscardSemantics::ReadsOldData => Vec::new(),
                BlockDiscardSemantics::UndefinedKeyed => {
                    keyed_discard_bytes(base.hash(), request, count)
                }
            }
        };
        let mut write = request.clone();
        write.data = bytes;
        match self.apply_write(base, durable, &write, directive)? {
            BlockWriteOutcome::Applied(wait) => {
                Ok((BlockResponse::ok_for(request.identity(), Vec::new()), wait))
            }
            BlockWriteOutcome::Rejected(result) => {
                Ok((BlockResponse::error_for(request.identity(), result), 0))
            }
        }
    }

    pub(in crate::block) fn read_visible(
        &mut self,
        base: &BaseImage,
        durable: &CowOverlay,
        offset: u64,
        count: u32,
        record_cache_access: bool,
    ) -> Result<Vec<u8>, DeviceError> {
        let mut bytes = durable.read(base, offset, u64::from(count))?;
        let end = offset.checked_add(u64::from(count)).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "read range overflow",
            },
        )?;
        let visible = self
            .controller
            .iter()
            .map(|(sequence, entry)| (*sequence, (entry.offset, entry.bytes.as_slice())))
            .chain(
                self.volatile
                    .iter()
                    .map(|(sequence, entry)| (*sequence, (entry.offset, entry.bytes.as_slice()))),
            )
            .chain(
                self.media_queue
                    .iter()
                    .map(|(sequence, entry)| (*sequence, (entry.offset, entry.bytes.as_slice()))),
            )
            .map(|(sequence, (entry_offset, entry_bytes))| {
                (sequence, (entry_offset, entry_bytes.to_vec()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut accessed = Vec::new();
        for (sequence, (entry_offset, entry_bytes)) in &visible {
            let entry_end = entry_offset
                .checked_add(u64::try_from(entry_bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "volatile entry range overflow",
                })?;
            let overlap_start = offset.max(*entry_offset);
            let overlap_end = end.min(entry_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let destination = usize::try_from(overlap_start - offset).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "read overlap does not fit memory",
                }
            })?;
            let source = usize::try_from(overlap_start - *entry_offset).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "cache overlap does not fit memory",
                }
            })?;
            let length = usize::try_from(overlap_end - overlap_start).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "cache overlap length does not fit memory",
                }
            })?;
            bytes[destination..destination + length]
                .copy_from_slice(&entry_bytes[source..source + length]);
            if record_cache_access
                && self.volatile.contains_key(sequence)
                && entry_contributes_visible(*sequence, overlap_start, overlap_end, &visible)
            {
                accessed.push(*sequence);
            }
        }
        for sequence in accessed {
            let access_sequence = self.next_cache_access_sequence;
            self.next_cache_access_sequence = self
                .next_cache_access_sequence
                .checked_add(1)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "cache access sequence overflow",
                })?;
            if let Some(entry) = self.volatile.get_mut(&sequence) {
                entry.last_access_sequence = access_sequence;
            }
        }
        Ok(bytes)
    }

    pub(super) fn apply_write(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<BlockWriteOutcome, DeviceError> {
        let intended_spans = canonical_atomic_spans(
            request.offset,
            u64::from(request.count),
            u64::from(self.config.atomic_write_bytes),
        )?;
        let (destination, spans) = match &directive.write_disposition {
            BlockFaultWriteDisposition::Apply => (request.offset, intended_spans.clone()),
            BlockFaultWriteDisposition::Lost => (request.offset, Vec::new()),
            BlockFaultWriteDisposition::Torn { spans }
            | BlockFaultWriteDisposition::ProgramFailure { spans } => {
                (request.offset, spans.clone())
            }
            BlockFaultWriteDisposition::Misdirected {
                destination: BlockFaultMisdirectionDestination::AttachedDevice,
                destination_offset,
            } => (*destination_offset, intended_spans.clone()),
            BlockFaultWriteDisposition::Misdirected {
                destination: BlockFaultMisdirectionDestination::ExternalDevice(_),
                ..
            } => {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "external misdirected write requires a two-device transaction",
                });
            }
        };
        let mut resolved = Vec::with_capacity(spans.len());
        let mut admitted_bytes = 0_u64;
        for (fragment_index, span) in intended_spans.iter().enumerate() {
            if !spans.iter().any(|selected| {
                selected.start <= span.start
                    && selected
                        .end()
                        .zip(span.end())
                        .is_some_and(|(selected_end, fragment_end)| selected_end >= fragment_end)
            }) {
                continue;
            }
            let start = usize::try_from(span.start).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write span does not fit memory",
                }
            })?;
            let end = usize::try_from(span.end().unwrap_or(u64::MAX)).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write span end does not fit memory",
                }
            })?;
            let offset = destination.checked_add(span.start).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write destination overflow",
                },
            )?;
            let bytes =
                request
                    .data
                    .get(start..end)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "write span exceeds request data",
                    })?;
            let byte_count = u64::try_from(bytes.len()).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write span length does not fit the device geometry",
                }
            })?;
            let range_end =
                offset
                    .checked_add(byte_count)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "write destination range overflow",
                    })?;
            if range_end > self.config.length_bytes {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "write destination exceeds the physical device",
                });
            }
            admitted_bytes = admitted_bytes.checked_add(byte_count).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write admission byte count overflow",
                },
            )?;
            resolved.push((fragment_index, offset, bytes));
        }

        let controller = directive.cache_policy.is_none()
            && self.config.completion_durability == BlockCompletionDurability::ControllerAccepted;
        let cache = directive.cache_policy.is_some()
            || self.config.completion_durability
                == BlockCompletionDurability::VolatileCacheAccepted;
        if controller {
            let available_entries = usize::try_from(self.config.controller_entries)
                .unwrap_or(usize::MAX)
                .saturating_sub(self.controller.len());
            let available_bytes = self
                .config
                .controller_buffer_bytes
                .saturating_sub(self.controller_bytes);
            if resolved.len() > available_entries || admitted_bytes > available_bytes {
                return Ok(BlockWriteOutcome::Rejected(BlockFaultResult::Busy));
            }
        } else if cache {
            let rejection = match directive.cache_policy {
                Some(policy) => self.prepare_cache_admission(
                    base,
                    durable,
                    resolved.len(),
                    admitted_bytes,
                    policy,
                    directive.execution_nanos,
                )?,
                None => {
                    let available_entries = usize::try_from(self.config.cache_entries)
                        .unwrap_or(usize::MAX)
                        .saturating_sub(self.volatile.len());
                    if resolved.len() <= available_entries
                        && admitted_bytes
                            <= self
                                .config
                                .volatile_cache_bytes
                                .saturating_sub(self.volatile_bytes)
                    {
                        None
                    } else {
                        Some(BlockFaultResult::Busy)
                    }
                }
            };
            if let Some(result) = rejection {
                return Ok(BlockWriteOutcome::Rejected(result));
            }
        }
        let sequence_count = u64::try_from(intended_spans.len()).map_err(|_error| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "intended write fragment count does not fit the sequence space",
            }
        })?;
        let first_sequence = self.next_cache_sequence;
        let media_identity = BlockMediaOperationIdentity {
            operation: request.op,
            operation_sequence: first_sequence,
            request_digest: directive.request_digest,
            request_offset: request.offset,
            request_count: request.count,
        };
        self.next_cache_sequence = self.next_cache_sequence.checked_add(sequence_count).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "write durability sequence overflow",
            },
        )?;
        let version_count = u64::try_from(resolved.len()).map_err(|_error| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "retained version count does not fit the sequence space",
            }
        })?;
        self.next_version_sequence
            .checked_add(version_count)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "retained version sequence overflow",
            })?;
        let applied_fragments = resolved
            .iter()
            .map(|(fragment_index, _, _)| *fragment_index)
            .collect::<BTreeSet<_>>();
        for fragment_index in 0..intended_spans.len() {
            if !applied_fragments.contains(&fragment_index) {
                let sequence = first_sequence
                    .checked_add(u64::try_from(fragment_index).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "lost write fragment sequence overflow",
                    })?;
                self.first_lost_sequence = Some(
                    self.first_lost_sequence
                        .map_or(sequence, |existing| existing.min(sequence)),
                );
            }
        }

        let persistence_fragments = resolved
            .iter()
            .map(|(fragment_index, offset, bytes)| {
                let sequence = first_sequence
                    .checked_add(u64::try_from(*fragment_index).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "persistence fragment sequence overflow",
                    })?;
                Ok((
                    sequence,
                    BlockWriteFragmentId {
                        request_id: request.request_id,
                        fragment_index: u32::try_from(*fragment_index).map_err(|_error| {
                            DeviceError::InvalidBlockFaultDirective {
                                reason: "persistence fragment index exceeds u32",
                            }
                        })?,
                        start: *offset,
                        length: u64::try_from(bytes.len()).map_err(|_error| {
                            DeviceError::InvalidBlockFaultDirective {
                                reason: "persistence fragment length overflow",
                            }
                        })?,
                    },
                ))
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        self.persistence.admit_request_with_barrier(
            &persistence_fragments,
            directive.persistence_admitted_nanos,
            &directive.persistence_transforms,
            self.pending_barrier_frontier,
        )?;
        if !directive.persistence_media_rules.is_empty() {
            self.flash
                .register_rules(self.config.length_bytes, &directive.persistence_media_rules)?;
            let next_count = self
                .pending_persistence_media
                .len()
                .checked_add(resolved.len())
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "pending_persistence_media",
                    hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
                })?;
            if next_count > HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
                return Err(DeviceError::BlockFaultStateLimit {
                    field: "pending_persistence_media",
                    hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
                });
            }
            for (fragment_index, offset, bytes) in &resolved {
                let sequence = first_sequence
                    .checked_add(u64::try_from(*fragment_index).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "persistence-media sequence overflow",
                    })?;
                self.pending_persistence_media.insert(
                    sequence,
                    ResolvedBlockPersistenceMediaDirective {
                        opportunity: BlockPersistenceOpportunity {
                            sequence,
                            request_id: request.request_id,
                            operation_sequence: media_identity.operation_sequence,
                            operation: media_identity.operation,
                            request_digest: media_identity.request_digest,
                            offset: *offset,
                            count: u32::try_from(bytes.len()).map_err(|_error| {
                                DeviceError::InvalidBlockFaultDirective {
                                    reason: "persistence-media fragment exceeds request width",
                                }
                            })?,
                            intended_digest: *blake3::hash(bytes).as_bytes(),
                            ready_nanos: self.persistence.deadline_nanos(sequence).unwrap_or(0),
                        },
                        flash_rules: directive.persistence_media_rules.clone(),
                    },
                );
            }
        }

        for (fragment_index, offset, bytes) in resolved {
            let sequence = first_sequence
                .checked_add(u64::try_from(fragment_index).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "applied write fragment sequence overflow",
                })?;
            self.retain_prior(
                base,
                durable,
                offset,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            )?;
            if controller {
                self.controller_write(
                    sequence,
                    request.request_id,
                    media_identity,
                    offset,
                    bytes.to_vec(),
                )?;
            } else if cache {
                self.cache_write(
                    sequence,
                    request.request_id,
                    media_identity,
                    offset,
                    bytes.to_vec(),
                    directive
                        .cache_policy
                        .is_some_and(|policy| policy.power_loss_protected),
                )?;
            } else {
                self.media_queue_write(
                    sequence,
                    request.request_id,
                    media_identity,
                    offset,
                    bytes.to_vec(),
                )?;
            }
        }
        let persistence_wait_nanos = if !cache && !controller {
            self.persist_through(
                base,
                durable,
                self.next_cache_sequence,
                directive.execution_nanos,
            )?
        } else {
            0
        };
        self.recompute_actual_durable_frontier();
        if !cache && !controller {
            self.reported_durable_frontier = self.actual_durable_frontier;
        }
        Ok(BlockWriteOutcome::Applied(persistence_wait_nanos))
    }

    pub(super) fn retain_prior(
        &mut self,
        base: &BaseImage,
        durable: &CowOverlay,
        offset: u64,
        length: u64,
    ) -> Result<(), DeviceError> {
        if self.retained.len()
            == usize::try_from(self.config.retained_versions).unwrap_or(usize::MAX)
        {
            let oldest = self.retained.keys().next().copied().ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "retained-version accounting is empty at capacity",
                },
            )?;
            self.retained.remove(&oldest);
        }
        let bytes = self.read_visible(
            base,
            durable,
            offset,
            u32::try_from(length).map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                reason: "retained range exceeds request width",
            })?,
            false,
        )?;
        let sequence = self.next_version_sequence;
        self.next_version_sequence = self.next_version_sequence.checked_add(1).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "retained version sequence overflow",
            },
        )?;
        self.retained.insert(
            sequence,
            BlockRetainedVersion {
                sequence,
                offset,
                bytes,
            },
        );
        Ok(())
    }

    pub(super) fn cache_write(
        &mut self,
        sequence: u64,
        request_id: u32,
        media_identity: BlockMediaOperationIdentity,
        offset: u64,
        bytes: Vec<u8>,
        power_loss_protected: bool,
    ) -> Result<(), DeviceError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next_bytes = self.volatile_bytes.checked_add(length).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "volatile byte count overflow",
            },
        )?;
        if self.volatile.len() == usize::try_from(self.config.cache_entries).unwrap_or(usize::MAX)
            || next_bytes > self.config.volatile_cache_bytes
        {
            return Err(DeviceError::BlockCacheFull {
                requested_bytes: length,
                available_bytes: self
                    .config
                    .volatile_cache_bytes
                    .saturating_sub(self.volatile_bytes),
            });
        }
        let access_sequence = self.next_cache_access_sequence;
        self.next_cache_access_sequence = self.next_cache_access_sequence.checked_add(1).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "cache access sequence overflow",
            },
        )?;
        self.volatile.insert(
            sequence,
            BlockVolatileEntry {
                sequence,
                request_id,
                media_identity,
                offset,
                bytes,
                last_access_sequence: access_sequence,
                power_loss_protected,
            },
        );
        self.volatile_bytes = next_bytes;
        Ok(())
    }

    pub(super) fn prepare_cache_admission(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        incoming_entries: usize,
        incoming_bytes: u64,
        policy: ResolvedBlockCachePolicy,
        now_nanos: u64,
    ) -> Result<Option<BlockFaultResult>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let rejection = next.prepare_cache_admission_staged(
            base,
            &mut next_durable,
            incoming_entries,
            incoming_bytes,
            policy,
            now_nanos,
        )?;
        if rejection.is_none() {
            *self = next;
            *durable = next_durable;
        }
        Ok(rejection)
    }

    pub(super) fn prepare_cache_admission_staged(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        incoming_entries: usize,
        incoming_bytes: u64,
        policy: ResolvedBlockCachePolicy,
        now_nanos: u64,
    ) -> Result<Option<BlockFaultResult>, DeviceError> {
        let entry_capacity = usize::try_from(self.config.cache_entries).unwrap_or(usize::MAX);
        if incoming_entries > entry_capacity || incoming_bytes > policy.capacity_bytes {
            return Ok(Some(BlockFaultResult::Busy));
        }
        while self
            .volatile
            .len()
            .checked_add(incoming_entries)
            .is_none_or(|entries| entries > entry_capacity)
            || self
                .volatile_bytes
                .checked_add(incoming_bytes)
                .is_none_or(|bytes| bytes > policy.capacity_bytes)
        {
            if let BlockFaultDirtyEviction::Fail(result) = policy.dirty_eviction {
                return Ok(Some(result));
            }
            let Some(victim) = (match policy.eviction {
                BlockFaultCacheEviction::Fifo => self
                    .volatile
                    .values()
                    .filter(|entry| self.persistence.is_ready(entry.sequence))
                    .min_by_key(|entry| entry.sequence)
                    .map(|entry| entry.sequence),
                BlockFaultCacheEviction::Lru => self
                    .volatile
                    .values()
                    .filter(|entry| self.persistence.is_ready(entry.sequence))
                    .min_by_key(|entry| (entry.last_access_sequence, entry.sequence))
                    .map(|entry| entry.sequence),
                BlockFaultCacheEviction::WritebackSequence => self
                    .volatile
                    .keys()
                    .filter(|sequence| self.persistence.is_ready(**sequence))
                    .filter_map(|sequence| {
                        self.persistence
                            .writeback_key(*sequence)
                            .map(|key| (key, *sequence))
                    })
                    .min_by_key(|(key, _sequence)| *key)
                    .map(|(_key, sequence)| sequence),
            }) else {
                return Ok(Some(BlockFaultResult::Busy));
            };
            self.schedule_volatile_persistence(victim)?;
        }
        if !self.persistence_execution_required {
            self.persist_due(base, durable, now_nanos)?;
        }
        Ok(None)
    }

    pub(super) fn schedule_volatile_persistence(
        &mut self,
        sequence: u64,
    ) -> Result<(), DeviceError> {
        let entry = self.volatile.get(&sequence).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "cache eviction selected an absent volatile fragment",
            },
        )?;
        self.media_queue_write(
            entry.sequence,
            entry.request_id,
            entry.media_identity,
            entry.offset,
            entry.bytes.clone(),
        )?;
        let removed =
            self.volatile
                .remove(&sequence)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "cache eviction fragment disappeared",
                })?;
        self.volatile_bytes = self
            .volatile_bytes
            .checked_sub(u64::try_from(removed.bytes.len()).unwrap_or(u64::MAX))
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile byte accounting underflow during persistence scheduling",
            })?;
        Ok(())
    }

    pub(in crate::block) fn persist_due(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<(), DeviceError> {
        loop {
            let sequence = self
                .media_queue
                .keys()
                .filter(|sequence| self.persistence.is_ready_at(**sequence, now_nanos))
                .filter(|sequence| {
                    !self.persistence_execution_required
                        || self.pending_persistence_media.contains_key(sequence)
                })
                .filter_map(|sequence| {
                    self.persistence
                        .writeback_key(*sequence)
                        .map(|key| (key, *sequence))
                })
                .min_by_key(|(key, _sequence)| *key)
                .map(|(_key, sequence)| sequence);
            let Some(sequence) = sequence else {
                break;
            };
            self.persist_sequence(base, durable, sequence, now_nanos)?;
        }
        self.recompute_actual_durable_frontier();
        if self
            .pending_honest_flush_frontier
            .is_some_and(|frontier| self.actual_durable_frontier >= frontier)
        {
            self.reported_durable_frontier = self.actual_durable_frontier;
            self.pending_honest_flush_frontier = None;
        }
        Ok(())
    }

    pub(super) fn controller_write(
        &mut self,
        sequence: u64,
        request_id: u32,
        media_identity: BlockMediaOperationIdentity,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.controller_bytes = self.controller_bytes.checked_add(length).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "controller byte count overflow",
            },
        )?;
        self.controller.insert(
            sequence,
            BlockControllerEntry {
                sequence,
                request_id,
                media_identity,
                offset,
                bytes,
            },
        );
        Ok(())
    }

    pub(super) fn media_queue_write(
        &mut self,
        sequence: u64,
        request_id: u32,
        media_identity: BlockMediaOperationIdentity,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DeviceError> {
        if self.media_queue.contains_key(&sequence) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "media-queue sequence is already present",
            });
        }
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next_bytes = self.media_queue_bytes.checked_add(length).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "media-queue byte count overflow",
            },
        )?;
        if next_bytes > HARD_BLOCK_MEDIA_QUEUE_BYTES {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "media-queue byte count exceeds its hard bound",
            });
        }
        self.media_queue_bytes = next_bytes;
        self.media_queue.insert(
            sequence,
            BlockControllerEntry {
                sequence,
                request_id,
                media_identity,
                offset,
                bytes,
            },
        );
        Ok(())
    }

    pub(super) fn persist_all(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<u64, DeviceError> {
        self.persist_through(base, durable, self.next_cache_sequence, now_nanos)
    }

    pub(super) fn persist_through(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        frontier: u64,
        now_nanos: u64,
    ) -> Result<u64, DeviceError> {
        if frontier > self.next_cache_sequence {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "flush persistence frontier exceeds issued storage sequence",
            });
        }
        let controller = self
            .controller
            .keys()
            .copied()
            .filter(|sequence| *sequence < frontier)
            .collect::<Vec<_>>();
        for sequence in controller {
            self.schedule_controller_persistence(sequence)?;
        }
        let volatile = self
            .volatile
            .keys()
            .copied()
            .filter(|sequence| *sequence < frontier)
            .collect::<Vec<_>>();
        for sequence in volatile {
            self.schedule_volatile_persistence(sequence)?;
        }
        if !self.persistence_execution_required {
            self.persist_due(base, durable, now_nanos)?;
        }
        let wait = self
            .media_queue
            .keys()
            .copied()
            .filter(|sequence| *sequence < frontier)
            .filter_map(|sequence| self.persistence.deadline_nanos(sequence))
            .map(|deadline| deadline.saturating_sub(now_nanos))
            .max()
            .unwrap_or(0);
        self.recompute_actual_durable_frontier();
        Ok(wait)
    }

    pub(super) fn schedule_controller_persistence(
        &mut self,
        sequence: u64,
    ) -> Result<(), DeviceError> {
        let entry = self.controller.get(&sequence).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "persistence selected an absent controller fragment",
            },
        )?;
        self.media_queue_write(
            entry.sequence,
            entry.request_id,
            entry.media_identity,
            entry.offset,
            entry.bytes.clone(),
        )?;
        let removed =
            self.controller
                .remove(&sequence)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "controller persistence fragment disappeared",
                })?;
        self.controller_bytes = self
            .controller_bytes
            .checked_sub(u64::try_from(removed.bytes.len()).unwrap_or(u64::MAX))
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "controller byte accounting underflow during persistence scheduling",
            })?;
        Ok(())
    }

    pub(super) fn persist_sequence(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        sequence: u64,
        now_nanos: u64,
    ) -> Result<(), DeviceError> {
        let (request_id, media_identity, offset, bytes) =
            if let Some(entry) = self.controller.get(&sequence) {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.clone(),
                )
            } else if let Some(entry) = self.media_queue.get(&sequence) {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.clone(),
                )
            } else if let Some(entry) = self.volatile.get(&sequence) {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.clone(),
                )
            } else {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready persistence fragment has no owning storage layer",
                });
            };
        let opportunity = self.persistence_opportunity(sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "persistence opportunity disappeared",
            },
        )?;
        let directive = self.pending_persistence_media.remove(&sequence);
        if self.persistence_execution_required && directive.is_none() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "missing resolved persistence-media directive",
            });
        }
        let flash = directive.map_or(
            Ok(BlockFlashMutationOutcome {
                spans: vec![BlockFaultByteSpan {
                    start: 0,
                    length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                }],
                failed: false,
            }),
            |directive| {
                let contributors = directive
                    .flash_rules
                    .iter()
                    .map(|rule| rule.contributor)
                    .collect::<Vec<_>>();
                match media_identity.operation {
                    BlockOp::Write => {
                        let request = BlockRequest::write(request_id, offset, bytes.clone());
                        self.flash.program_registered(
                            &request,
                            now_nanos,
                            self.config.length_bytes,
                            &contributors,
                        )
                    }
                    BlockOp::Discard => self.flash.erase_fragment_registered(
                        media_identity.operation_sequence,
                        media_identity.request_offset,
                        media_identity.request_count,
                        offset,
                        &bytes,
                        now_nanos,
                        self.config.length_bytes,
                        &contributors,
                    ),
                    _ => Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "physical persistence operation is not write or discard",
                    }),
                }
            },
        )?;
        let mut programmed = Vec::new();
        for span in &flash.spans {
            let start = usize::try_from(span.start).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "flash program span start does not fit memory",
                }
            })?;
            let end = usize::try_from(span.end().unwrap_or(u64::MAX)).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "flash program span end does not fit memory",
                }
            })?;
            let selected =
                bytes
                    .get(start..end)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "flash program span exceeds persistence fragment",
                    })?;
            durable.write(base, offset.saturating_add(span.start), selected)?;
            programmed.extend_from_slice(selected);
        }
        self.persistence.commit_persisted(sequence)?;
        if let Some(entry) = self.controller.remove(&sequence) {
            self.controller_bytes = self
                .controller_bytes
                .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "controller byte accounting underflow during persistence",
                })?;
        } else if let Some(entry) = self.media_queue.remove(&sequence) {
            self.media_queue_bytes = self
                .media_queue_bytes
                .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "media-queue byte accounting underflow during persistence",
                })?;
        } else if let Some(entry) = self.volatile.remove(&sequence) {
            self.volatile_bytes = self
                .volatile_bytes
                .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "volatile byte accounting underflow during persistence",
                })?;
        } else {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persisted fragment disappeared from its storage layer",
            });
        }
        if self.persistence_media_outcomes.len() == HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "persistence_media_outcomes",
                hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
            });
        }
        let outcome_index = self.persistence_media_outcomes.len();
        self.persistence_media_outcomes
            .push(BlockPersistenceMediaOutcome {
                opportunity,
                executed_nanos: now_nanos,
                applied_spans: flash.spans,
                media_failed: flash.failed,
                applied_digest: *blake3::hash(&programmed).as_bytes(),
            });
        self.storage_outcome_order
            .push(BlockStorageOutcomeRef::Persistence(outcome_index));
        self.recompute_actual_durable_frontier();
        Ok(())
    }

    pub(super) fn persistence_opportunity(
        &self,
        sequence: u64,
    ) -> Option<BlockPersistenceOpportunity> {
        let entry = self
            .controller
            .get(&sequence)
            .map(|entry| {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.as_slice(),
                )
            })
            .or_else(|| {
                self.media_queue.get(&sequence).map(|entry| {
                    (
                        entry.request_id,
                        entry.media_identity,
                        entry.offset,
                        entry.bytes.as_slice(),
                    )
                })
            })
            .or_else(|| {
                self.volatile.get(&sequence).map(|entry| {
                    (
                        entry.request_id,
                        entry.media_identity,
                        entry.offset,
                        entry.bytes.as_slice(),
                    )
                })
            })?;
        Some(BlockPersistenceOpportunity {
            sequence,
            request_id: entry.0,
            operation_sequence: entry.1.operation_sequence,
            operation: entry.1.operation,
            request_digest: entry.1.request_digest,
            offset: entry.2,
            count: u32::try_from(entry.3.len()).ok()?,
            intended_digest: *blake3::hash(entry.3).as_bytes(),
            ready_nanos: self.persistence.deadline_nanos(sequence).unwrap_or(0),
        })
    }

    pub(super) fn validate_persistence_media_directive(
        &self,
        directive: &ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        if self
            .persistence_opportunity(directive.opportunity.sequence)
            .as_ref()
            != Some(&directive.opportunity)
            || directive
                .flash_rules
                .windows(2)
                .any(|pair| pair[0].contributor >= pair[1].contributor)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persistence-media directive does not match its live opportunity",
            });
        }
        for rule in &directive.flash_rules {
            rule.validate(self.config.length_bytes)?;
        }
        Ok(())
    }

    pub(super) fn recompute_actual_durable_frontier(&mut self) {
        self.actual_durable_frontier = self
            .controller
            .keys()
            .next()
            .copied()
            .into_iter()
            .chain(self.volatile.keys().next().copied())
            .chain(self.media_queue.keys().next().copied())
            .chain(self.first_lost_sequence)
            .min()
            .unwrap_or(self.next_cache_sequence);
        if self.pending_barrier_frontier.is_some_and(|frontier| {
            !self
                .persistence
                .nodes()
                .keys()
                .any(|sequence| *sequence < frontier)
        }) {
            self.pending_barrier_frontier = None;
        }
    }
}
