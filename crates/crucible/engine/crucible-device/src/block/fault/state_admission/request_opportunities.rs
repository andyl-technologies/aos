//! Phase-specific request opportunities and exact directive admission.

use super::*;

impl BlockFaultState {
    /// Enables fail-closed resolve/persist opportunities after queue service.
    pub(in crate::block::fault) fn require_execution_opportunities_untracked(
        &mut self,
        required: bool,
    ) {
        observed_set!(self, execution_opportunities_required, required);
    }

    /// Returns the first request ready for resolve/persist phase evaluation.
    #[must_use]
    pub fn next_execution_opportunity(&self, now_ticks: u64) -> Option<BlockExecutionOpportunity> {
        self.execution_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_ticks <= now_ticks && pending.execution.is_none()
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_ticks,
                    pending.opportunity.request_sequence,
                )
            })
            .map(|pending| pending.opportunity.clone())
    }

    /// Installs the complete resolve/persist directive for one ready request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, the directive
    /// aliases another request, queue service is repeated, or a decision was
    /// already installed.
    pub(in crate::block::fault) fn install_execution_directive_untracked(
        &mut self,
        resolved: ResolvedBlockExecutionDirective,
    ) -> Result<(), DeviceError> {
        let request_sequence = resolved.opportunity.request_sequence;
        let directive = resolved.directive;
        let pending = self.execution_pending.get(&request_sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "execution directive has no ready request opportunity",
            },
        )?;
        directive.validate_for(&pending.opportunity.request, &self.config)?;
        if resolved.opportunity != pending.opportunity
            || directive.request_sequence != request_sequence
            || pending.execution.is_some()
            || !directive.service_rules.is_empty()
            || directive.execution_ticks != pending.opportunity.ready_ticks
            || (!directive.persistence_transforms.is_empty()
                && directive.persistence_admitted_ticks != pending.opportunity.ready_ticks)
            || directive.availability != pending.opportunity.admission.availability
            || directive.reported_capacity_bytes
                != pending.opportunity.admission.reported_capacity_bytes
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "execution directive identity or phase is invalid",
            });
        }
        let mut next = self.clone();
        let next_pending = next.execution_pending.get_mut(&request_sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "execution opportunity disappeared",
            },
        )?;
        observed_member_set!(next, next_pending.execution, Some(directive));
        let bytes = next
            .execution_pending
            .values()
            .try_fold(0_u64, |total, pending| {
                total
                    .checked_add(execution_pending_owned_bytes(pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "execution-pending byte accounting overflow",
                    })
            })?;
        if bytes > HARD_PENDING_BLOCK_FAULT_BYTES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_execution_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            });
        }
        observed_set!(next, execution_pending_bytes, bytes);
        *self = next;
        Ok(())
    }

    /// Returns the first resolved write/discard/flush awaiting persist evaluation.
    #[must_use]
    pub fn next_request_persistence_opportunity(
        &self,
        now_ticks: u64,
    ) -> Option<BlockRequestPersistenceOpportunity> {
        self.request_persistence_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_ticks <= now_ticks && pending.persistence.is_none()
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_ticks,
                    pending.opportunity.request_sequence,
                )
            })
            .map(|pending| pending.opportunity.clone())
    }

    /// Installs the complete persist decision for one exact mutation opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, repeated, or the
    /// directive alters fields already fixed by admit/queue/resolve.
    pub(in crate::block::fault) fn install_request_persistence_directive_untracked(
        &mut self,
        resolved: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<(), DeviceError> {
        let sequence = resolved.opportunity.request_sequence;
        let directive = resolved.directive;
        let pending = self.request_persistence_pending.get(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "persist directive has no ready request opportunity",
            },
        )?;
        directive.validate_for(&pending.opportunity.request, &self.config)?;
        let prior = &pending.opportunity.resolved;
        if resolved.opportunity != pending.opportunity
            || pending.persistence.is_some()
            || directive.request_sequence != sequence
            || directive.execution_ticks != pending.opportunity.ready_ticks
            || !directive.service_rules.is_empty()
            || directive.availability != prior.availability
            || directive.reported_capacity_bytes != prior.reported_capacity_bytes
            || directive.error_result != prior.error_result
            || directive.additional_latency_nanos != prior.additional_latency_nanos
            || !prior.external_durability_dependencies.is_empty()
            || directive.retain_completion != prior.retain_completion
            || directive.retention_timeout_response != prior.retention_timeout_response
            || directive.retention_timeout_ticks != prior.retention_timeout_ticks
            || directive.retention_recovery_event != prior.retention_recovery_event
            || directive.retention_recovery_after_ticks != prior.retention_recovery_after_ticks
            || directive.retention_recovery_after_sequence
                != prior.retention_recovery_after_sequence
            || directive.duplicate_completions != prior.duplicate_completions
            || directive.read_transforms != prior.read_transforms
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persist directive identity or earlier phases differ",
            });
        }
        let mut next = self.clone();
        let next_pending = next.request_persistence_pending.get_mut(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "request-persistence opportunity disappeared",
            },
        )?;
        observed_member_set!(next, next_pending.persistence, Some(directive));
        observed_set!(
            next,
            request_persistence_pending_bytes,
            next.request_persistence_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(request_persistence_pending_owned_bytes(pending)?)
                        .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                        .ok_or(DeviceError::BlockFaultStateLimit {
                            field: "block_request_persistence_pending_bytes",
                            hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES)
                                .unwrap_or(usize::MAX),
                        })
                })?
        );
        *self = next;
        Ok(())
    }

    /// Returns the first computed completion ready for deliver-phase evaluation.
    #[must_use]
    pub fn next_delivery_opportunity(&self, now_ticks: u64) -> Option<BlockDeliveryOpportunity> {
        self.delivery_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_ticks <= now_ticks
                    && pending.delivery.is_none()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| self.actual_durable_frontier >= frontier)
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_ticks,
                    pending.opportunity.request_sequence,
                )
            })
            .map(|pending| pending.opportunity.clone())
    }

    /// Installs the complete deliver-phase decision for one computed completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, repeated, or the
    /// directive changes fields fixed by an earlier request phase.
    pub(in crate::block::fault) fn install_delivery_directive_untracked(
        &mut self,
        resolved: ResolvedBlockDeliveryDirective,
    ) -> Result<(), DeviceError> {
        let sequence = resolved.opportunity.request_sequence;
        let directive = resolved.directive;
        let pending = self.delivery_pending.get(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "delivery directive has no computed completion opportunity",
            },
        )?;
        directive.validate_for(&pending.opportunity.request, &self.config)?;
        let prior = &pending.opportunity.resolved;
        if resolved.opportunity != pending.opportunity
            || pending.delivery.is_some()
            || directive.request_sequence != sequence
            || directive.execution_ticks != prior.execution_ticks
            || !directive.service_rules.is_empty()
            || directive.availability != prior.availability
            || directive.reported_capacity_bytes != prior.reported_capacity_bytes
            || directive.error_result != prior.error_result
            || directive.retain_completion != prior.retain_completion
            || directive.retention_timeout_response != prior.retention_timeout_response
            || directive.retention_timeout_ticks != prior.retention_timeout_ticks
            || directive.retention_recovery_event != prior.retention_recovery_event
            || directive.retention_recovery_after_ticks != prior.retention_recovery_after_ticks
            || directive.retention_recovery_after_sequence
                != prior.retention_recovery_after_sequence
            || directive.read_transforms != prior.read_transforms
            || directive.media_rules != prior.media_rules
            || directive.write_disposition != prior.write_disposition
            || directive.flush_disposition != prior.flush_disposition
            || directive.cache_policy != prior.cache_policy
            || directive.persistence_transforms != prior.persistence_transforms
            || directive.persistence_media_rules != prior.persistence_media_rules
            || directive.external_durability_dependencies != prior.external_durability_dependencies
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "delivery directive identity or earlier phases differ",
            });
        }
        let mut next = self.clone();
        let next_pending = next.delivery_pending.get_mut(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "delivery opportunity disappeared",
            },
        )?;
        observed_member_set!(next, next_pending.delivery, Some(directive));
        observed_set!(
            next,
            delivery_pending_bytes,
            next.delivery_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(delivery_pending_owned_bytes(pending)?)
                        .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                        .ok_or(DeviceError::BlockFaultStateLimit {
                            field: "block_delivery_pending_bytes",
                            hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES)
                                .unwrap_or(usize::MAX),
                        })
                })?
        );
        *self = next;
        Ok(())
    }
}
