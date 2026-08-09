//! Admission, scheduling, and recovery state for resolved block faults.
//!
//! Mutations are staged on cloned state and become visible only after every
//! directive, resource check, and persistence transition succeeds.

use super::*;

impl BlockFaultState {
    /// Creates fault-free write-through state for a device.
    #[must_use]
    pub fn write_through(length_bytes: u64) -> Self {
        Self {
            config: BlockDurabilityConfig::write_through(length_bytes),
            icount_shift: 0,
            transport_epoch: None,
            retired_transport_epochs: BTreeMap::new(),
            retry_preserve_authorizations: BTreeSet::new(),
            recovery_until_nanos: None,
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            service: BlockServiceState::default(),
            service_pending: BTreeMap::new(),
            service_pending_bytes: 0,
            service_outcomes: Vec::new(),
            storage_outcome_order: Vec::new(),
            execution_opportunities_required: false,
            execution_pending: BTreeMap::new(),
            execution_pending_bytes: 0,
            request_persistence_pending: BTreeMap::new(),
            request_persistence_pending_bytes: 0,
            delivery_pending: BTreeMap::new(),
            delivery_pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            media_queue: BTreeMap::new(),
            media_queue_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            media: BlockMediaState::default(),
            flash: BlockFlashState::default(),
            persistence_execution_required: false,
            pending_persistence_media: BTreeMap::new(),
            persistence_media_outcomes: Vec::new(),
            persistence: BlockPersistenceGraph::new(),
            pending_barrier_frontier: None,
            pending_honest_flush_frontier: None,
            next_cache_sequence: 0,
            next_cache_access_sequence: 0,
            next_version_sequence: 0,
            first_lost_sequence: None,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
        }
    }

    /// Reports whether accepted storage mutation remains outside durable media.
    ///
    /// This excludes request-phase and delivery queues: callers can combine it
    /// with transport quiescence to identify a checkpoint boundary at which the
    /// guest-visible operation has completed but controller, cache, or media
    /// work must still survive in the host continuation.
    #[must_use]
    pub fn has_pending_durability_continuation(&self) -> bool {
        !self.controller.is_empty()
            || !self.media_queue.is_empty()
            || !self.volatile.is_empty()
            || !self.pending_persistence_media.is_empty()
            || self.pending_barrier_frontier.is_some()
            || self.pending_honest_flush_frontier.is_some()
    }

    /// Creates a validated fault-free write-through state.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when `config` violates geometry or hard bounds.
    pub fn new(config: BlockDurabilityConfig) -> Result<Self, DeviceError> {
        config.validate()?;
        let persistence = BlockPersistenceGraph::with_edge_limit(
            usize::try_from(config.persistence_dependencies).unwrap_or(usize::MAX),
        )?;
        Ok(Self {
            config,
            icount_shift: 0,
            transport_epoch: None,
            retired_transport_epochs: BTreeMap::new(),
            retry_preserve_authorizations: BTreeSet::new(),
            recovery_until_nanos: None,
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            service: BlockServiceState::default(),
            service_pending: BTreeMap::new(),
            service_pending_bytes: 0,
            service_outcomes: Vec::new(),
            storage_outcome_order: Vec::new(),
            execution_opportunities_required: false,
            execution_pending: BTreeMap::new(),
            execution_pending_bytes: 0,
            request_persistence_pending: BTreeMap::new(),
            request_persistence_pending_bytes: 0,
            delivery_pending: BTreeMap::new(),
            delivery_pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            media_queue: BTreeMap::new(),
            media_queue_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            media: BlockMediaState::default(),
            flash: BlockFlashState::default(),
            persistence_execution_required: false,
            pending_persistence_media: BTreeMap::new(),
            persistence_media_outcomes: Vec::new(),
            persistence,
            pending_barrier_frontier: None,
            pending_honest_flush_frontier: None,
            next_cache_sequence: 0,
            next_cache_access_sequence: 0,
            next_version_sequence: 0,
            first_lost_sequence: None,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
        })
    }

    /// Enables or disables the fail-closed requirement for exact directives.
    pub fn require_directives(&mut self, required: bool) {
        self.execution_required = required;
    }

    /// Binds request arrival coordinates to the device's virtual-time scale.
    pub(in crate::block) fn set_icount_shift(&mut self, shift_bits: u8) {
        debug_assert!(shift_bits < 64);
        self.icount_shift = shift_bits;
    }

    /// Enables fail-closed resolve/persist opportunities after queue service.
    pub fn require_execution_opportunities(&mut self, required: bool) {
        self.execution_opportunities_required = required;
    }

    /// Returns the first request ready for resolve/persist phase evaluation.
    #[must_use]
    pub fn next_execution_opportunity(&self, now_nanos: u64) -> Option<BlockExecutionOpportunity> {
        self.execution_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_nanos <= now_nanos && pending.execution.is_none()
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_nanos,
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
    pub fn install_execution_directive(
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
            || directive.execution_nanos != pending.opportunity.ready_nanos
            || (!directive.persistence_transforms.is_empty()
                && directive.persistence_admitted_nanos != pending.opportunity.ready_nanos)
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
        next_pending.execution = Some(directive);
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
        next.execution_pending_bytes = bytes;
        *self = next;
        Ok(())
    }

    /// Returns the first resolved write/discard/flush awaiting persist evaluation.
    #[must_use]
    pub fn next_request_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockRequestPersistenceOpportunity> {
        self.request_persistence_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_nanos <= now_nanos && pending.persistence.is_none()
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_nanos,
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
    pub fn install_request_persistence_directive(
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
            || directive.execution_nanos != pending.opportunity.ready_nanos
            || !directive.service_rules.is_empty()
            || directive.availability != prior.availability
            || directive.reported_capacity_bytes != prior.reported_capacity_bytes
            || directive.error_result != prior.error_result
            || directive.additional_latency_nanos != prior.additional_latency_nanos
            || prior.external_durability_dependency.is_some()
            || directive.retain_completion != prior.retain_completion
            || directive.retention_timeout_response != prior.retention_timeout_response
            || directive.retention_timeout_nanos != prior.retention_timeout_nanos
            || directive.retention_recovery_event != prior.retention_recovery_event
            || directive.retention_recovery_after_nanos != prior.retention_recovery_after_nanos
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
        next_pending.persistence = Some(directive);
        next.request_persistence_pending_bytes = next
            .request_persistence_pending
            .values()
            .try_fold(0_u64, |total, pending| {
                total
                    .checked_add(request_persistence_pending_owned_bytes(pending)?)
                    .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                    .ok_or(DeviceError::BlockFaultStateLimit {
                        field: "block_request_persistence_pending_bytes",
                        hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                    })
            })?;
        *self = next;
        Ok(())
    }

    /// Returns the first computed completion ready for deliver-phase evaluation.
    #[must_use]
    pub fn next_delivery_opportunity(&self, now_nanos: u64) -> Option<BlockDeliveryOpportunity> {
        self.delivery_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_nanos <= now_nanos
                    && pending.delivery.is_none()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| self.actual_durable_frontier >= frontier)
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_nanos,
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
    pub fn install_delivery_directive(
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
            || directive.execution_nanos != prior.execution_nanos
            || !directive.service_rules.is_empty()
            || directive.availability != prior.availability
            || directive.reported_capacity_bytes != prior.reported_capacity_bytes
            || directive.error_result != prior.error_result
            || directive.retain_completion != prior.retain_completion
            || directive.retention_timeout_response != prior.retention_timeout_response
            || directive.retention_timeout_nanos != prior.retention_timeout_nanos
            || directive.retention_recovery_event != prior.retention_recovery_event
            || directive.retention_recovery_after_nanos != prior.retention_recovery_after_nanos
            || directive.retention_recovery_after_sequence
                != prior.retention_recovery_after_sequence
            || directive.read_transforms != prior.read_transforms
            || directive.media_rules != prior.media_rules
            || directive.write_disposition != prior.write_disposition
            || directive.flush_disposition != prior.flush_disposition
            || directive.cache_policy != prior.cache_policy
            || directive.persistence_transforms != prior.persistence_transforms
            || directive.persistence_media_rules != prior.persistence_media_rules
            || directive.external_durability_dependency != prior.external_durability_dependency
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
        next_pending.delivery = Some(directive);
        next.delivery_pending_bytes =
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
                })?;
        *self = next;
        Ok(())
    }

    /// Returns whether no request, mutation, or sequence has entered this state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.transport_epoch.is_none()
            && self.retired_transport_epochs.is_empty()
            && self.retry_preserve_authorizations.is_empty()
            && self.recovery_until_nanos.is_none()
            && self.pending.is_empty()
            && self.pending_bytes == 0
            && self.service.continuations().is_empty()
            && self.service_pending.is_empty()
            && self.service_pending_bytes == 0
            && self.service_outcomes.is_empty()
            && self.storage_outcome_order.is_empty()
            && self.execution_pending.is_empty()
            && self.execution_pending_bytes == 0
            && self.request_persistence_pending.is_empty()
            && self.request_persistence_pending_bytes == 0
            && self.delivery_pending.is_empty()
            && self.delivery_pending_bytes == 0
            && self.controller.is_empty()
            && self.controller_bytes == 0
            && self.media_queue.is_empty()
            && self.media_queue_bytes == 0
            && self.volatile.is_empty()
            && self.volatile_bytes == 0
            && self.retained.is_empty()
            && self.media.rules().is_empty()
            && self.flash.continuations().is_empty()
            && self.pending_persistence_media.is_empty()
            && self.persistence_media_outcomes.is_empty()
            && self.persistence.nodes().is_empty()
            && self.pending_barrier_frontier.is_none()
            && self.pending_honest_flush_frontier.is_none()
            && self.retained_completions.is_empty()
            && self.next_cache_sequence == 0
            && self.next_cache_access_sequence == 0
            && self.next_version_sequence == 0
            && self.first_lost_sequence.is_none()
            && self.actual_durable_frontier == 0
            && self.reported_durable_frontier == 0
    }

    /// Returns the epoch authenticated by the live block transport, if any.
    #[must_use]
    pub const fn transport_epoch(&self) -> Option<u64> {
        self.transport_epoch
    }

    /// Returns the exclusive virtual-nanosecond recovery deadline, if active.
    #[must_use]
    pub const fn recovery_until_nanos(&self) -> Option<u64> {
        self.recovery_until_nanos
    }

    /// Validates all checkpointed storage-state invariants against a device.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for geometry mismatch, accounting drift,
    /// out-of-range entries, exhausted bounds, or malformed retained responses.
    pub fn validate_restore(&self, device_length: u64) -> Result<(), DeviceError> {
        self.config.validate()?;
        self.media.validate_restore(device_length)?;
        self.flash.validate_restore(device_length)?;
        self.service.validate_restore()?;
        if self.config.length_bytes != device_length
            || self.pending.len() > HARD_PENDING_BLOCK_FAULT_DIRECTIVES
            || self.retired_transport_epochs.len() > HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS
            || self.retry_preserve_authorizations.len() > HARD_BLOCK_RETRY_PRESERVE_AUTHORIZATIONS
            || self.pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.service_pending.len() > crate::block::service::HARD_BLOCK_SERVICE_JOBS
            || self.service_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.service_outcomes.len() > crate::block::service::HARD_BLOCK_SERVICE_JOBS
            || self.storage_outcome_order.len()
                > crate::block::service::HARD_BLOCK_SERVICE_JOBS
                    .saturating_add(HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS)
            || self.execution_pending.len() > crate::block::service::HARD_BLOCK_SERVICE_JOBS
            || self.execution_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.request_persistence_pending.len()
                > crate::block::service::HARD_BLOCK_SERVICE_JOBS
            || self.request_persistence_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.delivery_pending.len() > crate::block::service::HARD_BLOCK_SERVICE_JOBS
            || self.delivery_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.volatile.len() > HARD_BLOCK_CACHE_ENTRIES
            || self.controller.len() > HARD_BLOCK_CONTROLLER_ENTRIES
            || self.media_queue.len() > HARD_BLOCK_CONTROLLER_ENTRIES
            || self.media_queue_bytes > HARD_BLOCK_MEDIA_QUEUE_BYTES
            || self.retained.len() > HARD_BLOCK_RETAINED_VERSIONS
            || self.retained_completions.len() > HARD_BLOCK_RETAINED_COMPLETIONS
            || self.pending_persistence_media.len() > HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS
            || self.persistence_media_outcomes.len() > HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS
            || self.volatile.len()
                > usize::try_from(self.config.cache_entries).unwrap_or(usize::MAX)
            || self.controller.len()
                > usize::try_from(self.config.controller_entries).unwrap_or(usize::MAX)
            || self.retained.len()
                > usize::try_from(self.config.retained_versions).unwrap_or(usize::MAX)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored block fault state violates configured bounds",
            });
        }
        if let Some(transport_epoch) = self.transport_epoch {
            if self
                .retired_transport_epochs
                .keys()
                .any(|epoch| *epoch >= transport_epoch)
                || self.retry_preserve_authorizations.iter().any(|identity| {
                    identity.epoch >= transport_epoch
                        || !self.retired_transport_epochs.contains_key(&identity.epoch)
                        || self.retired_transport_epochs[&identity.epoch].queued
                            != BlockTransportPending::RetryPreserveId
                })
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored retired block transport state is inconsistent",
                });
            }
        } else if !self.retired_transport_epochs.is_empty()
            || !self.retry_preserve_authorizations.is_empty()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored retired block transport state has no live epoch",
            });
        }
        if self.storage_outcome_order.len()
            != self
                .service_outcomes
                .len()
                .saturating_add(self.persistence_media_outcomes.len())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored storage outcome order does not cover every outcome",
            });
        }
        let mut seen_service = vec![false; self.service_outcomes.len()];
        let mut seen_persistence = vec![false; self.persistence_media_outcomes.len()];
        for outcome in &self.storage_outcome_order {
            let seen = match *outcome {
                BlockStorageOutcomeRef::Service(index) => seen_service.get_mut(index),
                BlockStorageOutcomeRef::Persistence(index) => seen_persistence.get_mut(index),
            }
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "restored storage outcome order contains an invalid index",
            })?;
            if std::mem::replace(seen, true) {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored storage outcome order contains a duplicate index",
                });
            }
        }
        let pending_bytes = self.pending.values().try_fold(0_u64, |total, directive| {
            total.checked_add(directive_owned_bytes(directive)?).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "restored pending directive byte accounting overflow",
                },
            )
        })?;
        if pending_bytes != self.pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored pending directive byte accounting differs",
            });
        }
        for (identity, directive) in &self.pending {
            directive.validate_static(identity.request_id, &self.config)?;
            if directive.request_epoch != identity.epoch {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored pending directive epoch differs from its key",
                });
            }
        }
        for (sequence, pending) in &self.service_pending {
            pending
                .directive
                .validate_for(&pending.request, &self.config)?;
            if *sequence != pending.directive.request_sequence
                || pending.directive.service_rules.is_empty()
                || pending.remaining_contributors.is_empty()
                || pending.remaining_contributors.iter().any(|contributor| {
                    !pending
                        .directive
                        .service_rules
                        .iter()
                        .any(|rule| rule.contributor == *contributor)
                })
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored queued storage service request is invalid",
                });
            }
        }
        let service_pending_bytes =
            self.service_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(service_pending_owned_bytes(pending)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "restored service-pending byte accounting overflow",
                        })
                })?;
        if service_pending_bytes != self.service_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored service-pending byte accounting differs",
            });
        }
        let execution_pending_bytes =
            self.execution_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(execution_pending_owned_bytes(pending)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "restored execution-pending byte accounting overflow",
                        })
                })?;
        if execution_pending_bytes != self.execution_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored execution-pending byte accounting differs",
            });
        }
        let request_persistence_pending_bytes = self
            .request_persistence_pending
            .values()
            .try_fold(0_u64, |total, pending| {
                total
                    .checked_add(request_persistence_pending_owned_bytes(pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored request-persistence byte accounting overflow",
                    })
            })?;
        if request_persistence_pending_bytes != self.request_persistence_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored request-persistence byte accounting differs",
            });
        }
        let delivery_pending_bytes =
            self.delivery_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(delivery_pending_owned_bytes(pending)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "restored delivery-pending byte accounting overflow",
                        })
                })?;
        if delivery_pending_bytes != self.delivery_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored delivery-pending byte accounting differs",
            });
        }
        for (sequence, pending) in &self.execution_pending {
            pending
                .opportunity
                .admission
                .validate_for(&pending.opportunity.request, &self.config)?;
            if *sequence != pending.opportunity.request_sequence
                || pending.opportunity.admission.request_sequence != *sequence
                || !pending.opportunity.admission.service_rules.is_empty()
                || pending.opportunity.admission.execution_nanos != pending.opportunity.ready_nanos
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored request execution opportunity is invalid",
                });
            }
            if let Some(execution) = &pending.execution {
                execution.validate_for(&pending.opportunity.request, &self.config)?;
                if execution.request_sequence != *sequence
                    || !execution.service_rules.is_empty()
                    || execution.execution_nanos != pending.opportunity.ready_nanos
                    || execution.availability != pending.opportunity.admission.availability
                    || execution.reported_capacity_bytes
                        != pending.opportunity.admission.reported_capacity_bytes
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored request execution decision is invalid",
                    });
                }
            }
        }
        for (sequence, pending) in &self.request_persistence_pending {
            let opportunity = &pending.opportunity;
            opportunity
                .resolved
                .validate_for(&opportunity.request, &self.config)?;
            if *sequence != opportunity.request_sequence
                || opportunity.resolved.request_sequence != *sequence
                || opportunity.resolved.execution_nanos != opportunity.ready_nanos
                || !matches!(
                    opportunity.request.op,
                    BlockOp::Write | BlockOp::Discard | BlockOp::Flush
                )
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored request-persistence opportunity is invalid",
                });
            }
            if let Some(persistence) = &pending.persistence {
                persistence.validate_for(&opportunity.request, &self.config)?;
                if persistence.request_sequence != *sequence
                    || persistence.execution_nanos != opportunity.ready_nanos
                    || persistence.availability != opportunity.resolved.availability
                    || persistence.reported_capacity_bytes
                        != opportunity.resolved.reported_capacity_bytes
                    || persistence.error_result != opportunity.resolved.error_result
                    || persistence.read_transforms != opportunity.resolved.read_transforms
                    || persistence.retain_completion != opportunity.resolved.retain_completion
                    || persistence.retention_timeout_response
                        != opportunity.resolved.retention_timeout_response
                    || persistence.retention_timeout_nanos
                        != opportunity.resolved.retention_timeout_nanos
                    || persistence.retention_recovery_event
                        != opportunity.resolved.retention_recovery_event
                    || persistence.retention_recovery_after_nanos
                        != opportunity.resolved.retention_recovery_after_nanos
                    || persistence.retention_recovery_after_sequence
                        != opportunity.resolved.retention_recovery_after_sequence
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored request-persistence decision is invalid",
                    });
                }
            }
        }
        for (sequence, pending) in &self.delivery_pending {
            let opportunity = &pending.opportunity;
            opportunity
                .resolved
                .validate_for(&opportunity.request, &self.config)?;
            if *sequence != opportunity.request_sequence
                || opportunity.resolved.request_sequence != *sequence
                || opportunity.wire_digest != opportunity.resolved.request_digest
                || opportunity.response.request_id != opportunity.request.request_id
                || !block_response_fits_transport(&opportunity.response)
                || opportunity
                    .required_durable_frontier
                    .is_some_and(|frontier| frontier > self.next_cache_sequence)
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored delivery opportunity is invalid",
                });
            }
            if let Some(delivery) = &pending.delivery {
                delivery.validate_for(&opportunity.request, &self.config)?;
                if delivery.request_sequence != *sequence
                    || delivery.execution_nanos != opportunity.resolved.execution_nanos
                    || delivery.availability != opportunity.resolved.availability
                    || delivery.reported_capacity_bytes
                        != opportunity.resolved.reported_capacity_bytes
                    || delivery.error_result != opportunity.resolved.error_result
                    || delivery.read_transforms != opportunity.resolved.read_transforms
                    || delivery.write_disposition != opportunity.resolved.write_disposition
                    || delivery.flush_disposition != opportunity.resolved.flush_disposition
                    || delivery.cache_policy != opportunity.resolved.cache_policy
                    || delivery.persistence_transforms
                        != opportunity.resolved.persistence_transforms
                    || delivery.persistence_media_rules
                        != opportunity.resolved.persistence_media_rules
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored delivery decision changes an earlier phase",
                    });
                }
            }
        }
        let expected_service_jobs = self
            .service_pending
            .iter()
            .flat_map(|(sequence, pending)| {
                pending
                    .remaining_contributors
                    .iter()
                    .map(|contributor| (*contributor, *sequence))
            })
            .collect::<BTreeSet<_>>();
        if self
            .service
            .live_job_keys()
            .into_iter()
            .collect::<BTreeSet<_>>()
            != expected_service_jobs
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored service queue differs from request contributor joins",
            });
        }
        let service_sequences = self
            .service_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let execution_sequences = self
            .execution_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let persistence_sequences = self
            .request_persistence_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let delivery_sequences = self
            .delivery_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let installed_sequences = self
            .pending
            .values()
            .map(|directive| directive.request_sequence)
            .collect::<BTreeSet<_>>();
        if installed_sequences.len() != self.pending.len()
            || !service_sequences.is_disjoint(&execution_sequences)
            || !service_sequences.is_disjoint(&installed_sequences)
            || !execution_sequences.is_disjoint(&installed_sequences)
            || !service_sequences.is_disjoint(&persistence_sequences)
            || !service_sequences.is_disjoint(&delivery_sequences)
            || !execution_sequences.is_disjoint(&persistence_sequences)
            || !execution_sequences.is_disjoint(&delivery_sequences)
            || !persistence_sequences.is_disjoint(&delivery_sequences)
            || !persistence_sequences.is_disjoint(&installed_sequences)
            || !delivery_sequences.is_disjoint(&installed_sequences)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored request sequence occupies multiple execution stages",
            });
        }
        let volatile_bytes = self.volatile.values().try_fold(0_u64, |total, entry| {
            validate_state_range(entry.offset, entry.bytes.len(), device_length)?;
            validate_media_entry(
                entry.media_identity,
                entry.sequence,
                entry.offset,
                entry.bytes.len(),
                device_length,
            )?;
            total
                .checked_add(u64::try_from(entry.bytes.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "restored volatile entry length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored volatile byte accounting overflow",
                })
        })?;
        let controller_bytes = self.controller.values().try_fold(0_u64, |total, entry| {
            validate_state_range(entry.offset, entry.bytes.len(), device_length)?;
            validate_media_entry(
                entry.media_identity,
                entry.sequence,
                entry.offset,
                entry.bytes.len(),
                device_length,
            )?;
            total
                .checked_add(u64::try_from(entry.bytes.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "restored controller entry length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored controller byte accounting overflow",
                })
        })?;
        let media_queue_bytes = self.media_queue.values().try_fold(0_u64, |total, entry| {
            validate_state_range(entry.offset, entry.bytes.len(), device_length)?;
            validate_media_entry(
                entry.media_identity,
                entry.sequence,
                entry.offset,
                entry.bytes.len(),
                device_length,
            )?;
            total
                .checked_add(u64::try_from(entry.bytes.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "restored media-queue entry length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored media-queue byte accounting overflow",
                })
        })?;
        if volatile_bytes != self.volatile_bytes
            || controller_bytes != self.controller_bytes
            || media_queue_bytes != self.media_queue_bytes
            || volatile_bytes > self.config.volatile_cache_bytes
            || controller_bytes > self.config.controller_buffer_bytes
            || self.volatile.iter().any(|(sequence, entry)| {
                *sequence != entry.sequence || *sequence >= self.next_cache_sequence
            })
            || self.retained.iter().any(|(sequence, version)| {
                *sequence != version.sequence
                    || *sequence >= self.next_version_sequence
                    || validate_state_range(version.offset, version.bytes.len(), device_length)
                        .is_err()
            })
            || self.controller.iter().any(|(sequence, entry)| {
                *sequence != entry.sequence || *sequence >= self.next_cache_sequence
            })
            || self.media_queue.iter().any(|(sequence, entry)| {
                *sequence != entry.sequence || *sequence >= self.next_cache_sequence
            })
            || self
                .volatile
                .values()
                .any(|entry| entry.last_access_sequence >= self.next_cache_access_sequence)
            || self
                .first_lost_sequence
                .is_some_and(|sequence| sequence >= self.next_cache_sequence)
            || self.actual_durable_frontier > self.next_cache_sequence
            || self.reported_durable_frontier > self.next_cache_sequence
            || self
                .pending_barrier_frontier
                .is_some_and(|frontier| frontier > self.next_cache_sequence)
            || self
                .pending_honest_flush_frontier
                .is_some_and(|frontier| frontier > self.next_cache_sequence)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored block fault state has invalid accounting or sequence",
            });
        }
        self.persistence.validate()?;
        if self.persistence.edge_limit()
            != usize::try_from(self.config.persistence_dependencies).unwrap_or(usize::MAX)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored persistence graph uses a different configured edge bound",
            });
        }
        let layer_sequences = self
            .controller
            .keys()
            .chain(self.media_queue.keys())
            .chain(self.volatile.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        if layer_sequences
            != self
                .persistence
                .nodes()
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored persistence graph differs from pending storage layers",
            });
        }
        let live_discard_operations = self
            .controller
            .values()
            .map(|entry| entry.media_identity)
            .chain(self.media_queue.values().map(|entry| entry.media_identity))
            .chain(self.volatile.values().map(|entry| entry.media_identity))
            .filter_map(|identity| {
                (identity.operation == BlockOp::Discard).then_some(identity.operation_sequence)
            })
            .collect::<BTreeSet<_>>();
        if self.flash.continuations().values().any(|continuation| {
            continuation
                .erase_decisions
                .keys()
                .any(|(operation, _block)| !live_discard_operations.contains(operation))
        }) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored flash erase decision has no live discard operation",
            });
        }
        let expected_durable_frontier = self
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
        if self.actual_durable_frontier != expected_durable_frontier {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored actual durable frontier differs from exact pending state",
            });
        }
        for (identity, completion) in &self.retained_completions {
            if *identity != completion.identity
                || completion.recovery_response.request_id != identity.request_id
                || completion.timeout_response.request_id != identity.request_id
                || completion
                    .persist_through_on_recovery
                    .is_some_and(|frontier| frontier > self.next_cache_sequence)
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored retained completion is malformed",
                });
            }
            for response in [&completion.recovery_response, &completion.timeout_response] {
                if response.payload.len() > crucible_shmem::MAX_FRAME_DATA {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored retained completion exceeds the block transport frame",
                    });
                }
                let decoded =
                    BlockResponse::decode(&response.payload).map_err(DeviceError::Codec)?;
                if decoded.identity() != *identity
                    || (decoded.status == BlockStatus::Ok)
                        != (response.status == ResponseStatus::Ok)
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored retained completion payload differs from its envelope",
                    });
                }
            }
        }
        for (sequence, directive) in &self.pending_persistence_media {
            if *sequence != directive.opportunity.sequence {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored persistence-media directive key differs",
                });
            }
            self.validate_persistence_media_directive(directive)?;
        }
        Ok(())
    }

    /// Enables fail-closed resolution at each physical persistence opportunity.
    pub fn require_persistence_media_directives(&mut self, required: bool) {
        self.persistence_execution_required = required;
    }

    /// Returns the first ready physical persistence opportunity in canonical order.
    #[must_use]
    pub fn next_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockPersistenceOpportunity> {
        self.media_queue
            .keys()
            .filter(|sequence| self.persistence.is_ready_at(**sequence, now_nanos))
            .filter(|sequence| !self.pending_persistence_media.contains_key(sequence))
            .filter_map(|sequence| {
                self.persistence
                    .writeback_key(*sequence)
                    .map(|key| (key, *sequence))
            })
            .min_by_key(|(key, _sequence)| *key)
            .and_then(|(_key, sequence)| self.persistence_opportunity(sequence))
    }

    /// Installs the exact media directive for one ready persistence opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for stale/mismatched opportunity identity,
    /// duplicate installation, invalid flash rules, or bounded-state exhaustion.
    pub fn install_persistence_media_directive(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        self.validate_persistence_media_directive(&directive)?;
        if self.pending_persistence_media.len() == HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_persistence_media",
                hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
            });
        }
        let sequence = directive.opportunity.sequence;
        if self.pending_persistence_media.contains_key(&sequence) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate persistence-media directive",
            });
        }
        let mut next = self.clone();
        next.flash
            .register_rules(self.config.length_bytes, &directive.flash_rules)?;
        next.pending_persistence_media.insert(sequence, directive);
        *self = next;
        Ok(())
    }

    /// Returns checkpointed sparse flash counters and changed-cell state.
    #[must_use]
    pub const fn flash_state(&self) -> &BlockFlashState {
        &self.flash
    }

    /// Drains completed persistence-media evidence after durable event recording.
    pub fn drain_persistence_media_outcomes(&mut self) -> Vec<BlockPersistenceMediaOutcome> {
        self.storage_outcome_order
            .retain(|outcome| matches!(outcome, BlockStorageOutcomeRef::Service(_)));
        std::mem::take(&mut self.persistence_media_outcomes)
    }

    /// Borrows completed physical-media outcomes without acknowledging them.
    #[must_use]
    pub fn persistence_media_outcomes(&self) -> &[BlockPersistenceMediaOutcome] {
        &self.persistence_media_outcomes
    }

    /// Returns every pending storage outcome in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when checkpointed outcome-order state contains
    /// an invalid reference.
    pub fn storage_outcomes(&self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.storage_outcome_order
            .iter()
            .map(|outcome| match *outcome {
                BlockStorageOutcomeRef::Service(index) => self
                    .service_outcomes
                    .get(index)
                    .copied()
                    .map(BlockStorageOutcome::Service),
                BlockStorageOutcomeRef::Persistence(index) => self
                    .persistence_media_outcomes
                    .get(index)
                    .cloned()
                    .map(BlockStorageOutcome::Persistence),
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "storage outcome order contains an invalid index",
            })
    }

    /// Drains every storage outcome in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutation when checkpointed outcome-order
    /// state contains an invalid reference.
    pub fn drain_storage_outcomes(&mut self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        let outcomes = self.storage_outcomes()?;
        self.storage_outcome_order.clear();
        self.service_outcomes.clear();
        self.persistence_media_outcomes.clear();
        Ok(outcomes)
    }

    /// Installs one directive, keyed by the exact guest request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate IDs or a hard pending-state limit.
    pub fn install(
        &mut self,
        identity: BlockRequestIdentity,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        directive.validate_static(identity.request_id, &self.config)?;
        if directive.request_epoch != identity.epoch {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block fault directive epoch differs from its installation identity",
            });
        }
        if self.pending.len() == HARD_PENDING_BLOCK_FAULT_DIRECTIVES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_directives",
                hard: HARD_PENDING_BLOCK_FAULT_DIRECTIVES,
            });
        }
        if self.pending.contains_key(&identity) {
            return Err(DeviceError::DuplicateBlockFaultDirective {
                request_id: identity.request_id,
            });
        }
        let bytes = directive_owned_bytes(&directive)?;
        let next_bytes =
            self.pending_bytes
                .checked_add(bytes)
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "pending_directive_bytes",
                    hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                })?;
        if next_bytes > HARD_PENDING_BLOCK_FAULT_BYTES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_directive_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            });
        }
        self.pending.insert(identity, directive);
        self.pending_bytes = next_bytes;
        Ok(())
    }

    /// Returns the immutable durability configuration.
    #[must_use]
    pub const fn config(&self) -> &BlockDurabilityConfig {
        &self.config
    }

    /// Returns volatile entries in cache sequence order.
    #[must_use]
    pub const fn volatile_entries(&self) -> &BTreeMap<u64, BlockVolatileEntry> {
        &self.volatile
    }

    /// Returns canonical cache-loss candidates for the requested protection scope.
    ///
    /// When `include_protected` is false, entries admitted under a
    /// power-loss-protected policy are excluded. A protection-failure impulse
    /// passes true and receives every live sequence.
    #[must_use]
    pub fn volatile_loss_candidates(&self, include_protected: bool) -> Vec<u64> {
        self.volatile
            .iter()
            .filter_map(|(sequence, entry)| {
                (include_protected || !entry.power_loss_protected).then_some(*sequence)
            })
            .collect()
    }

    /// Returns the canonical digest of the complete live volatile-cache entry set.
    #[must_use]
    pub fn volatile_entries_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-volatile-entry-set.v2\0");
        for (sequence, entry) in &self.volatile {
            hasher.update(&sequence.to_be_bytes());
            hasher.update(&entry.request_id.to_be_bytes());
            hasher.update(&[entry.media_identity.operation.to_wire()]);
            hasher.update(&entry.media_identity.operation_sequence.to_be_bytes());
            hasher.update(&entry.media_identity.request_digest);
            hasher.update(&entry.media_identity.request_offset.to_be_bytes());
            hasher.update(&entry.media_identity.request_count.to_be_bytes());
            hasher.update(&entry.offset.to_be_bytes());
            hasher.update(
                &u64::try_from(entry.bytes.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            hasher.update(blake3::hash(&entry.bytes).as_bytes());
            hasher.update(&entry.last_access_sequence.to_be_bytes());
            hasher.update(&[u8::from(entry.power_loss_protected)]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Returns controller-accepted writes in global sequence order.
    #[must_use]
    pub const fn controller_entries(&self) -> &BTreeMap<u64, BlockControllerEntry> {
        &self.controller
    }

    /// Returns writes admitted to the durable-media service queue.
    #[must_use]
    pub const fn media_queue_entries(&self) -> &BTreeMap<u64, BlockControllerEntry> {
        &self.media_queue
    }

    /// Returns the complete live persistence dependency graph.
    #[must_use]
    pub const fn persistence_graph(&self) -> &BlockPersistenceGraph {
        &self.persistence
    }

    /// Drains persistence graph mutations after canonical event recording.
    pub fn drain_persistence_transformation_evidence(
        &mut self,
    ) -> Vec<crate::block::persistence::BlockPersistenceTransformationEvidence> {
        self.persistence.drain_transformation_evidence()
    }

    /// Returns retained versions in version sequence order.
    #[must_use]
    pub const fn retained_versions(&self) -> &BTreeMap<u64, BlockRetainedVersion> {
        &self.retained
    }

    /// Returns checkpointed media overlays and activation counters.
    #[must_use]
    pub const fn media_state(&self) -> &BlockMediaState {
        &self.media
    }

    /// Returns completions waiting for an explicit recovery or timeout event.
    #[must_use]
    pub const fn retained_completions(
        &self,
    ) -> &BTreeMap<BlockRequestIdentity, BlockRetainedCompletion> {
        &self.retained_completions
    }

    /// Returns one retained completion without consuming it.
    #[must_use]
    pub fn retained_completion(
        &self,
        identity: BlockRequestIdentity,
    ) -> Option<&BlockRetainedCompletion> {
        self.retained_completions.get(&identity)
    }

    /// Returns retained requests whose timeout is due in canonical identity order.
    #[must_use]
    pub fn retained_timeouts_due(&self, now_nanos: u64) -> Vec<BlockRequestIdentity> {
        self.retained_completions
            .iter()
            .filter_map(|(identity, completion)| {
                (completion.timeout_nanos <= now_nanos).then_some(*identity)
            })
            .collect()
    }

    /// Returns retained requests subscribed to one recovery event identity.
    #[must_use]
    pub fn retained_recoveries_for(
        &self,
        event: [u8; 32],
        event_nanos: u64,
        event_sequence: u64,
    ) -> Vec<BlockRequestIdentity> {
        self.retained_completions
            .iter()
            .filter_map(|(identity, completion)| {
                (completion.recovery_event == Some(event)
                    && completion
                        .recovery_after_nanos
                        .zip(completion.recovery_after_sequence)
                        .is_some_and(|after| (event_nanos, event_sequence) > after))
                .then_some(*identity)
            })
            .collect()
    }

    /// Returns the earliest retained-completion timeout coordinate.
    #[must_use]
    pub fn next_retained_timeout_nanos(&self) -> Option<u64> {
        self.retained_completions
            .values()
            .map(|completion| completion.timeout_nanos)
            .min()
    }

    /// Resolves a retained completion and applies its recovery-only durability.
    ///
    /// Callers must execute this method on cloned state and commit the clone
    /// only after the response scheduler accepts the returned response.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the request is not retained or persistence
    /// of the captured flush frontier fails.
    pub(in crate::block) fn resolve_retained_completion(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
        now_nanos: u64,
    ) -> Result<Option<Response>, DeviceError> {
        let completion = self.retained_completions.get(&identity).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "storage completion is not retained",
            },
        )?;
        let response = match release {
            BlockRetainedRelease::Recovery {
                event_nanos,
                event_sequence,
            } => {
                let subscribed_after = completion
                    .recovery_after_nanos
                    .zip(completion.recovery_after_sequence)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage completion has no recovery subscription",
                    })?;
                if completion.recovery_event.is_none()
                    || (event_nanos, event_sequence) <= subscribed_after
                    || event_nanos > completion.timeout_nanos
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage recovery is outside its eligible subscription window",
                    });
                }
                if let Some(frontier) = completion.persist_through_on_recovery {
                    let wait = self.persist_through(base, durable, frontier, now_nanos)?;
                    if wait != 0 {
                        return Ok(None);
                    }
                    self.reported_durable_frontier = self.actual_durable_frontier;
                }
                completion.recovery_response
            }
            BlockRetainedRelease::Timeout => {
                if now_nanos < completion.timeout_nanos {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage timeout was released before its deadline",
                    });
                }
                completion.timeout_response
            }
        };
        self.retained_completions.remove(&identity);
        Ok(Some(response))
    }

    /// Returns the actual durable write/cache frontier.
    #[must_use]
    pub const fn actual_durable_frontier(&self) -> u64 {
        self.actual_durable_frontier
    }

    /// Returns the frontier acknowledged by one completion-durability stage.
    ///
    /// Controller and volatile-cache acknowledgement are irrevocable guest
    /// completion events once admission commits, even if a later modeled reset
    /// or power loss removes the accepted bytes. Durable acknowledgement instead
    /// follows the exact contiguous media frontier.
    #[must_use]
    pub const fn completion_frontier(&self, durability: BlockCompletionDurability) -> u64 {
        match durability {
            BlockCompletionDurability::ControllerAccepted
            | BlockCompletionDurability::VolatileCacheAccepted => self.next_cache_sequence,
            BlockCompletionDurability::Durable => self.actual_durable_frontier,
        }
    }

    /// Returns the frontier most recently reported durable to the guest.
    #[must_use]
    pub const fn reported_durable_frontier(&self) -> u64 {
        self.reported_durable_frontier
    }

    /// Drops exact volatile entries selected by cache sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a selected sequence is not currently live.
    pub fn lose_volatile(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        let selected = sequences.iter().copied().collect::<BTreeSet<_>>();
        if selected.len() != sequences.len()
            || selected
                .iter()
                .any(|sequence| !self.volatile.contains_key(sequence))
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile loss selection is not an exact live subset",
            });
        }
        let mut next = self.clone();
        for sequence in selected {
            if let Some(entry) = next.volatile.remove(&sequence) {
                next.persistence.commit_lost(sequence)?;
                next.first_lost_sequence = Some(
                    next.first_lost_sequence
                        .map_or(sequence, |existing| existing.min(sequence)),
                );
                next.volatile_bytes = next
                    .volatile_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "volatile byte accounting underflow",
                    })?;
            }
        }
        next.recompute_actual_durable_frontier();
        *self = next;
        Ok(())
    }

    /// Drops exact controller-accepted entries selected by global sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a selected sequence is not currently in the
    /// controller-accepted layer.
    pub fn lose_controller(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        let selected = sequences.iter().copied().collect::<BTreeSet<_>>();
        if selected.len() != sequences.len()
            || selected
                .iter()
                .any(|sequence| !self.controller.contains_key(sequence))
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "controller loss selection is not an exact live subset",
            });
        }
        let mut next = self.clone();
        for sequence in selected {
            if let Some(entry) = next.controller.remove(&sequence) {
                next.persistence.commit_lost(sequence)?;
                next.first_lost_sequence = Some(
                    next.first_lost_sequence
                        .map_or(sequence, |existing| existing.min(sequence)),
                );
                next.controller_bytes = next
                    .controller_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "controller byte accounting underflow",
                    })?;
            }
        }
        next.recompute_actual_durable_frontier();
        *self = next;
        Ok(())
    }

    /// Applies the host-side portion of a delivered controller reset.
    ///
    /// The caller must invoke this only after the corresponding reset response
    /// has crossed the delivery boundary. Requests removed from a host-owned
    /// lifecycle stage receive one explicit terminal or retry disposition; the
    /// returned responses are ordered by request sequence within each lifecycle
    /// stage and by the stage order queued, executing, resolved, then completed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a generated response cannot be encoded or if
    /// losing controller/cache state violates persistence accounting.
    pub(in crate::block) fn apply_transport_reset(
        &mut self,
        reset: BlockTransportReset,
        delivered_nanos: u64,
    ) -> Result<Vec<Response>, DeviceError> {
        let mut next = self.clone();
        let mut responses = Vec::new();

        let current_epoch = next.transport_epoch.unwrap_or(reset.next_epoch);
        match reset.request_ids {
            BlockTransportRequestIds::PreserveMonotonic if reset.next_epoch != current_epoch => {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "preserved block transport reset changed epoch",
                });
            }
            BlockTransportRequestIds::NewEpochFromZero
                if current_epoch.checked_add(1) != Some(reset.next_epoch) =>
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "block transport reset did not advance exactly one epoch",
                });
            }
            _ => {}
        }
        if reset.request_ids == BlockTransportRequestIds::NewEpochFromZero {
            if next.retired_transport_epochs.len() == HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS {
                return Err(DeviceError::BlockFaultStateLimit {
                    field: "retired_transport_epochs",
                    hard: HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS,
                });
            }
            if next
                .retired_transport_epochs
                .insert(
                    current_epoch,
                    BlockRetiredTransportEpoch {
                        queued: reset.queued,
                        failure_result: reset.failure_result,
                    },
                )
                .is_some()
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "block transport epoch was retired twice",
                });
            }
        }
        next.transport_epoch = Some(reset.next_epoch);
        next.recovery_until_nanos = Some(delivered_nanos.checked_add(reset.recovery_nanos).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "block transport recovery deadline overflow",
            },
        )?);

        let pending = std::mem::take(&mut next.pending);
        next.pending_bytes = 0;
        for (identity, _directive) in pending {
            responses.push(transport_pending_response(
                identity,
                reset.queued,
                reset.failure_result,
            )?);
        }

        let queued = std::mem::take(&mut next.service_pending);
        next.service_pending_bytes = 0;
        next.service = BlockServiceState::default();
        for pending in queued.into_values() {
            responses.push(transport_pending_response(
                pending.request.identity(),
                reset.queued,
                reset.failure_result,
            )?);
        }

        let executing = std::mem::take(&mut next.execution_pending);
        next.execution_pending_bytes = 0;
        for pending in executing.into_values() {
            responses.push(transport_pending_response(
                pending.opportunity.request.identity(),
                reset.executing,
                reset.failure_result,
            )?);
        }

        if reset.resolved != BlockTransportResolved::Complete {
            let persistence = std::mem::take(&mut next.request_persistence_pending);
            next.request_persistence_pending_bytes = 0;
            for pending in persistence.into_values() {
                responses.push(transport_resolved_response(
                    pending.opportunity.request.identity(),
                    reset.resolved,
                    reset.failure_result,
                )?);
            }

            let delivery = std::mem::take(&mut next.delivery_pending);
            next.delivery_pending_bytes = 0;
            for pending in delivery.into_values() {
                responses.push(transport_resolved_response(
                    pending.opportunity.request.identity(),
                    reset.resolved,
                    reset.failure_result,
                )?);
            }
        } else {
            for pending in next.delivery_pending.values_mut() {
                pending.opportunity.required_durable_frontier = None;
            }
        }

        if reset.completed_undelivered != BlockTransportUndelivered::Complete {
            let retained = std::mem::take(&mut next.retained_completions);
            for completion in retained.into_values() {
                let original = BlockResponse::decode(&completion.recovery_response.payload)
                    .map_err(DeviceError::Codec)?;
                responses.push(transport_undelivered_response(
                    original.identity(),
                    reset.completed_undelivered,
                    reset.failure_result,
                )?);
            }
        }

        if !reset.preserve_controller_buffer {
            let sequences = next.controller.keys().copied().collect::<Vec<_>>();
            next.lose_controller(&sequences)?;
        }
        if !reset.preserve_volatile_cache {
            let sequences = next.volatile.keys().copied().collect::<Vec<_>>();
            next.lose_volatile(&sequences)?;
        }

        *self = next;
        Ok(responses)
    }

    /// Returns the earliest exact integrated-service release coordinate.
    #[must_use]
    pub(in crate::block) fn next_service_completion_nanos(&self) -> Option<u64> {
        self.service.next_completion_nanos()
    }

    /// Returns the earliest request resolve/persist opportunity coordinate.
    #[must_use]
    pub(in crate::block) fn next_execution_deadline_nanos(&self) -> Option<u64> {
        self.execution_pending
            .values()
            .filter(|pending| pending.execution.is_none())
            .map(|pending| pending.opportunity.ready_nanos)
            .min()
    }

    /// Returns the earliest request mutation awaiting a persist decision.
    #[must_use]
    pub(in crate::block) fn next_request_persistence_deadline_nanos(&self) -> Option<u64> {
        self.request_persistence_pending
            .values()
            .filter(|pending| pending.persistence.is_none())
            .map(|pending| pending.opportunity.ready_nanos)
            .min()
    }

    /// Returns the earliest completion awaiting an exact delivery decision.
    #[must_use]
    pub(in crate::block) fn next_delivery_deadline_nanos(&self) -> Option<u64> {
        self.delivery_pending
            .values()
            .filter(|pending| {
                pending.delivery.is_none()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| self.actual_durable_frontier >= frontier)
            })
            .map(|pending| pending.opportunity.ready_nanos)
            .min()
    }

    /// Returns the earliest dependency-ready physical persistence boundary.
    #[must_use]
    pub(in crate::block) fn next_persistence_deadline_nanos(&self) -> Option<u64> {
        self.media_queue
            .keys()
            .filter(|sequence| self.persistence.is_ready_at(**sequence, u64::MAX))
            .filter_map(|sequence| self.persistence.deadline_nanos(*sequence))
            .min()
    }

    /// Drains contributor-level service evidence in canonical completion order.
    pub fn drain_service_outcomes(&mut self) -> Vec<BlockServiceCompletion> {
        self.storage_outcome_order
            .retain(|outcome| matches!(outcome, BlockStorageOutcomeRef::Persistence(_)));
        std::mem::take(&mut self.service_outcomes)
    }

    /// Borrows integrated-service completion evidence without acknowledging it.
    #[must_use]
    pub fn service_outcomes(&self) -> &[BlockServiceCompletion] {
        &self.service_outcomes
    }

    pub(in crate::block) fn defer_execution(
        &mut self,
        request: &BlockRequest,
        request_icount: u64,
        ready_nanos: u64,
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
        if let Some(removed) = self.pending.remove(&request.identity()) {
            self.pending_bytes = self
                .pending_bytes
                .checked_sub(directive_owned_bytes(&removed)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte accounting underflow",
                })?;
        }
        admission.service_rules.clear();
        let sequence = admission.request_sequence;
        let pending = BlockExecutionPendingRequest {
            opportunity: BlockExecutionOpportunity {
                request_sequence: sequence,
                request: request.clone(),
                request_icount,
                wire_digest: admission.request_digest,
                ready_nanos,
                admission,
            },
            execution: None,
        };
        self.execution_pending_bytes = self
            .execution_pending_bytes
            .checked_add(execution_pending_owned_bytes(&pending)?)
            .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
            .ok_or(DeviceError::BlockFaultStateLimit {
                field: "block_execution_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            })?;
        self.execution_pending.insert(sequence, pending);
        Ok(())
    }

    /// Executes every ready request whose resolve/persist decision is installed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when a decision is malformed, execution fails,
    /// or the resulting completion cannot be represented exactly.
    pub(in crate::block) fn resume_execution_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let ready = next
            .execution_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_nanos <= now_nanos && pending.execution.is_some())
                    .then_some((pending.opportunity.ready_nanos, *sequence))
            })
            .collect::<BTreeSet<_>>();
        for (ready_nanos, sequence) in ready {
            let pending = next.execution_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready execution request disappeared",
                },
            )?;
            next.execution_pending_bytes = next
                .execution_pending_bytes
                .checked_sub(execution_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "execution-pending byte accounting underflow",
                })?;
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
                    ready_nanos,
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
                ready_nanos,
            )?;
        }
        if !next.persistence_execution_required {
            next.persist_due(base, &mut next_durable, now_nanos)?;
        }
        *self = next;
        *durable = next_durable;
        Ok(Vec::new())
    }

    pub(in crate::block) fn defer_request_persistence(
        &mut self,
        request: BlockRequest,
        request_icount: u64,
        ready_nanos: u64,
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
                ready_nanos,
                resolved,
            },
            persistence: None,
        };
        self.request_persistence_pending_bytes = self
            .request_persistence_pending_bytes
            .checked_add(request_persistence_pending_owned_bytes(&pending)?)
            .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
            .ok_or(DeviceError::BlockFaultStateLimit {
                field: "block_request_persistence_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            })?;
        self.request_persistence_pending.insert(sequence, pending);
        Ok(())
    }

    /// Executes every request whose exact persist decision is installed and ready.
    pub(in crate::block) fn resume_request_persistence_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let ready = next
            .request_persistence_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_nanos <= now_nanos && pending.persistence.is_some())
                    .then_some((pending.opportunity.ready_nanos, *sequence))
            })
            .collect::<BTreeSet<_>>();
        for (ready_nanos, sequence) in ready {
            let pending = next.request_persistence_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready request-persistence opportunity disappeared",
                },
            )?;
            next.request_persistence_pending_bytes = next
                .request_persistence_pending_bytes
                .checked_sub(request_persistence_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "request-persistence byte accounting underflow",
                })?;
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
                ready_nanos,
            )?;
        }
        *self = next;
        *durable = next_durable;
        Ok(Vec::new())
    }
}
