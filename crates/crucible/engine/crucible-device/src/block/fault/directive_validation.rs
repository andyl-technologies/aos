//! Resolved directive construction and exact request/phase validation.

use super::*;

impl ResolvedBlockFaultDirective {
    /// Builds the exact fault-free directive for `request`.
    #[must_use]
    pub fn fault_free(request: &BlockRequest, capacity: u64) -> Self {
        Self {
            request_epoch: request.epoch,
            request_sequence: u64::from(request.request_id),
            operation: request.op,
            offset: request.offset,
            count: request.count,
            request_digest: request_digest(request),
            availability: BlockFaultAvailability::Online,
            reported_capacity_bytes: capacity,
            error_result: None,
            additional_latency_nanos: 0,
            external_durability_dependencies: Vec::new(),
            service_rules: Vec::new(),
            execution_ticks: 0,
            retain_completion: false,
            retention_timeout_response: None,
            retention_timeout_ticks: None,
            retention_recovery_event: None,
            retention_recovery_after_ticks: None,
            retention_recovery_after_sequence: None,
            duplicate_completions: Vec::new(),
            read_transforms: Vec::new(),
            media_rules: Vec::new(),
            write_disposition: BlockFaultWriteDisposition::Apply,
            flush_disposition: BlockFaultFlushDisposition::Honest,
            cache_policy: None,
            persistence_transforms: Vec::new(),
            persistence_media_rules: Vec::new(),
            persistence_admitted_ticks: 0,
        }
    }

    /// Expands an authored adjacent-completion gap into canonical primary-relative delays.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the copy count exceeds the hard bound, the
    /// gap is zero, multiplication overflows, or a protocol-error response does
    /// not match this directive's request identity and error status.
    pub fn configure_duplicate_completions(
        &mut self,
        request_id: u32,
        copies: u32,
        adjacent_gap_nanos: u64,
        policy: BlockDuplicatePolicy,
    ) -> Result<(), DeviceError> {
        let mut resolved = self.clone();
        resolved.duplicate_completions.clear();
        resolved.append_duplicate_completions(request_id, copies, adjacent_gap_nanos, policy)?;
        self.duplicate_completions = resolved.duplicate_completions;
        Ok(())
    }

    /// Appends duplicate outcomes after the current last primary-relative delay.
    ///
    /// The mutation is transactional: validation and all checked delay
    /// arithmetic complete before this directive is changed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the combined copy count exceeds the hard
    /// bound, the adjacent gap is zero, delay arithmetic overflows, or a
    /// protocol-error response does not match this directive's request.
    pub fn append_duplicate_completions(
        &mut self,
        request_id: u32,
        copies: u32,
        adjacent_gap_nanos: u64,
        policy: BlockDuplicatePolicy,
    ) -> Result<(), DeviceError> {
        let copies =
            usize::try_from(copies).map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate copy count does not fit memory",
            })?;
        if copies == 0
            || self
                .duplicate_completions
                .len()
                .checked_add(copies)
                .is_none_or(|total| total > HARD_BLOCK_DUPLICATE_COMPLETIONS)
            || adjacent_gap_nanos == 0
            || matches!(
                &policy,
                BlockDuplicatePolicy::ProtocolError(response)
                    if response.request_id != request_id
                        || response.status != BlockStatus::Error
            )
            || matches!(&policy, BlockDuplicatePolicy::Reset(transition) if transition.recovery_nanos == 0)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate completion policy is invalid",
            });
        }
        let base_gap_nanos = self
            .duplicate_completions
            .last()
            .map_or(0, ResolvedBlockDuplicateCompletion::gap_nanos);
        let mut resolved = Vec::with_capacity(copies);
        for index in 0..copies {
            let multiplier = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate completion index overflow",
                })?;
            let gap_nanos = adjacent_gap_nanos
                .checked_mul(multiplier)
                .and_then(|gap| base_gap_nanos.checked_add(gap))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate completion delay overflow",
                })?;
            resolved.push(match &policy {
                BlockDuplicatePolicy::Ignore => {
                    ResolvedBlockDuplicateCompletion::Ignore { gap_nanos }
                }
                BlockDuplicatePolicy::ProtocolError(response) => {
                    ResolvedBlockDuplicateCompletion::ProtocolError {
                        gap_nanos,
                        response: response.clone(),
                    }
                }
                BlockDuplicatePolicy::Reset(transition) if index == 0 => {
                    ResolvedBlockDuplicateCompletion::Reset {
                        gap_nanos,
                        transition: transition.clone(),
                    }
                }
                BlockDuplicatePolicy::Reset(_) => {
                    ResolvedBlockDuplicateCompletion::Ignore { gap_nanos }
                }
            });
        }
        self.duplicate_completions.extend(resolved);
        Ok(())
    }

    pub(super) fn validate_for(
        &self,
        request: &BlockRequest,
        config: &BlockDurabilityConfig,
    ) -> Result<(), DeviceError> {
        let device_length = config.length_bytes;
        self.validate_static(request.request_id, config)?;
        if self.request_epoch != request.epoch
            || self.operation != request.op
            || self.offset != request.offset
            || self.count != request.count
            || self.request_digest != request_digest(request)
            || (self.reported_capacity_bytes == 0 && device_length != 0)
            || self.reported_capacity_bytes > device_length
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "directive does not match the block request",
            });
        }
        Ok(())
    }

    pub(super) fn validate_static(
        &self,
        request_id: u32,
        config: &BlockDurabilityConfig,
    ) -> Result<(), DeviceError> {
        if (self.reported_capacity_bytes == 0 && config.length_bytes != 0)
            || self.reported_capacity_bytes > config.length_bytes
            || self.duplicate_completions.len() > HARD_BLOCK_DUPLICATE_COMPLETIONS
            || self.read_transforms.len() > HARD_BLOCK_WRITE_SPANS
            || self.media_rules.len() > HARD_BLOCK_WRITE_SPANS
            || self.persistence_transforms.len() > HARD_BLOCK_WRITE_SPANS
            || self.persistence_media_rules.len() > crate::block::flash::HARD_BLOCK_FLASH_RULES
            || self.service_rules.len() > crate::block::service::HARD_BLOCK_SERVICE_RULES
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "directive violates static block bounds",
            });
        }
        if self
            .service_rules
            .windows(2)
            .any(|pair| pair[0].contributor >= pair[1].contributor)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "storage service rules are not in canonical contributor order",
            });
        }
        for rule in &self.service_rules {
            rule.validate()?;
        }
        if self.retain_completion && !self.duplicate_completions.is_empty() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "a retained completion cannot also emit duplicates",
            });
        }
        if self.retain_completion
            != self
                .retention_timeout_response
                .as_ref()
                .is_some_and(|response| {
                    response.request_id == request_id && response.status == BlockStatus::Error
                })
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "retained completion lacks its matching typed timeout response",
            });
        }
        if self.retain_completion != self.retention_timeout_ticks.is_some()
            || self
                .retention_timeout_ticks
                .is_some_and(|deadline| deadline <= self.execution_ticks)
            || !self.retain_completion && self.retention_recovery_event.is_some()
            || self.retention_recovery_event.is_some()
                != self.retention_recovery_after_ticks.is_some()
            || self.retention_recovery_event.is_some()
                != self.retention_recovery_after_sequence.is_some()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "retained completion lacks a future timeout or has a stray recovery event",
            });
        }
        if self
            .retention_timeout_response
            .as_ref()
            .is_some_and(|response| !block_response_fits_transport(response))
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "retained timeout response exceeds the block transport frame",
            });
        }
        if !self
            .duplicate_completions
            .windows(2)
            .all(|pair| pair[0].gap_nanos() < pair[1].gap_nanos())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate completion gaps are not in strict canonical order",
            });
        }
        for duplicate in &self.duplicate_completions {
            if let ResolvedBlockDuplicateCompletion::ProtocolError { response, .. } = duplicate
                && (response.request_id != request_id
                    || response.epoch != self.request_epoch
                    || response.status != BlockStatus::Error
                    || !block_response_fits_transport(response))
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate protocol error is invalid for the request transport",
                });
            }
        }
        if self.operation != BlockOp::Read && !self.read_transforms.is_empty() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "read transforms require a read request",
            });
        }
        if self.operation != BlockOp::Write
            && self.operation != BlockOp::Discard
            && self.write_disposition != BlockFaultWriteDisposition::Apply
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "write dispositions require a write request",
            });
        }
        if !self.external_durability_dependencies.is_empty()
            && !matches!(
                (
                    self.operation,
                    &self.write_disposition,
                    self.flush_disposition
                ),
                (
                    BlockOp::Write | BlockOp::Discard,
                    &BlockFaultWriteDisposition::Lost,
                    BlockFaultFlushDisposition::Honest
                ) | (
                    BlockOp::Flush,
                    &BlockFaultWriteDisposition::Apply,
                    BlockFaultFlushDisposition::Lie
                )
            )
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external durability dependency requires an externally committed mutation",
            });
        }
        if self
            .external_durability_dependencies
            .windows(2)
            .any(|pair| pair[0].destination_device >= pair[1].destination_device)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external durability dependencies are not in unique device order",
            });
        }
        if !matches!(self.operation, BlockOp::Write | BlockOp::Discard)
            && self.cache_policy.is_some()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile-cache admission requires a write request",
            });
        }
        if (!matches!(self.operation, BlockOp::Write | BlockOp::Discard)
            && !self.persistence_transforms.is_empty())
            || (!matches!(
                self.operation,
                BlockOp::Read | BlockOp::Write | BlockOp::Discard
            ) && !self.persistence_media_rules.is_empty())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persistence transformations require a write request",
            });
        }
        if !self.persistence_transforms.is_empty() {
            if self.persistence_admitted_ticks != self.execution_ticks {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "persistence admission coordinate differs from request execution",
                });
            }
            BlockPersistenceGraph::validate_transforms(
                &self.persistence_transforms,
                self.persistence_admitted_ticks,
            )?;
        }
        if self
            .persistence_media_rules
            .windows(2)
            .any(|pair| pair[0].contributor >= pair[1].contributor)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persistence flash rules are not in canonical contributor order",
            });
        }
        for rule in &self.persistence_media_rules {
            rule.validate(config.length_bytes)?;
        }
        if self.cache_policy.is_some_and(|policy| {
            policy.capacity_bytes == 0
                || policy.capacity_bytes > config.volatile_cache_bytes
                || config.cache_entries == 0
        }) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile-cache policy exceeds the device contract",
            });
        }
        if self.operation != BlockOp::Flush
            && !matches!(self.flush_disposition, BlockFaultFlushDisposition::Honest)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "flush dispositions require a flush request",
            });
        }
        if matches!(self.flush_disposition, BlockFaultFlushDisposition::Stall)
            && !self.retain_completion
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "a stalled flush must retain its completion",
            });
        }
        validate_write_disposition(
            &self.write_disposition,
            self.offset,
            u64::from(self.count),
            u64::from(config.atomic_write_bytes),
            false,
        )?;
        for transform in &self.read_transforms {
            match transform {
                BlockFaultReadTransform::Xor { offset, mask } => {
                    if mask.is_empty()
                        || offset
                            .checked_add(u64::try_from(mask.len()).unwrap_or(u64::MAX))
                            .is_none_or(|end| end > u64::from(self.count))
                    {
                        return Err(DeviceError::InvalidBlockFaultDirective {
                            reason: "read XOR transform exceeds the declared response",
                        });
                    }
                }
                BlockFaultReadTransform::Replace { bytes }
                    if bytes.len() != usize::try_from(self.count).unwrap_or(usize::MAX) =>
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "replacement transform length differs from the declared response",
                    });
                }
                BlockFaultReadTransform::Replace { .. } => {}
            }
        }
        let mut media_contributors = BTreeSet::new();
        for rule in &self.media_rules {
            rule.validate(config.length_bytes)?;
            if !media_contributors.insert(rule.contributor) {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "media contributor is repeated in one directive",
                });
            }
        }
        Ok(())
    }
}
