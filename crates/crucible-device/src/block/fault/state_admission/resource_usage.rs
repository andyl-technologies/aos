//! Accounts retained and prospective block-fault resource ownership.

use super::*;

impl BlockFaultState {
    /// Returns the aggregate count and largest byte extent retained in pending phases.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when a count or byte
    /// extent cannot be represented as `u64`.
    pub fn pending_operation_usage(&self) -> Result<(u64, u64), DeviceError> {
        let operations = [
            self.pending.len(),
            self.service_pending.len(),
            self.execution_pending.len(),
            self.request_persistence_pending.len(),
            self.delivery_pending.len(),
            self.media_queue.len(),
            self.pending_persistence_media.len(),
            self.retained_completions.len(),
        ]
        .into_iter()
        .try_fold(0_u64, |total, count| {
            u64::try_from(count)
                .ok()
                .and_then(|count| total.checked_add(count))
        })
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "pending storage operation count overflow",
        })?;

        let mut largest_request = self
            .pending
            .values()
            .map(|directive| u64::from(directive.count))
            .max()
            .unwrap_or(0);
        for request in self
            .service_pending
            .values()
            .map(|pending| &pending.request)
        {
            largest_request = largest_request.max(block_request_extent(request)?);
        }
        for request in self
            .execution_pending
            .values()
            .map(|pending| &pending.opportunity.request)
        {
            largest_request = largest_request.max(block_request_extent(request)?);
        }
        for request in self
            .request_persistence_pending
            .values()
            .map(|pending| &pending.opportunity.request)
        {
            largest_request = largest_request.max(block_request_extent(request)?);
        }
        for request in self
            .delivery_pending
            .values()
            .map(|pending| &pending.opportunity.request)
        {
            largest_request = largest_request.max(block_request_extent(request)?);
        }
        for entry in self.media_queue.values() {
            largest_request = largest_request
                .max(u64::from(entry.media_identity.request_count))
                .max(u64::try_from(entry.bytes.len()).map_err(|_| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "pending storage request byte count overflow",
                    }
                })?);
        }
        for directive in self.pending_persistence_media.values() {
            largest_request = largest_request.max(u64::from(directive.opportunity.count));
        }

        Ok((operations, largest_request))
    }

    /// Returns the aggregate number of operations retained in pending storage phases.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when the aggregate
    /// count cannot be represented as `u64`.
    pub fn pending_operation_count(&self) -> Result<u64, DeviceError> {
        self.pending_operation_usage()
            .map(|(operations, _bytes)| operations)
    }

    /// Returns current media intervals and prospective new rule ownership.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when either count
    /// cannot be represented as `u64`.
    pub fn media_rule_usage(
        &self,
        rules: &[ResolvedBlockMediaRule],
    ) -> Result<(u64, u64), DeviceError> {
        let current = u64::try_from(self.media.rules().len()).map_err(|_| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "block media-rule count cannot be represented",
            }
        })?;
        let requested = rules
            .iter()
            .enumerate()
            .try_fold(0_u64, |count, (index, rule)| {
                if rules[..index]
                    .iter()
                    .any(|prior| prior.contributor == rule.contributor)
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "repeated block media-rule contributor",
                    });
                }
                if self.media.rules().contains_key(&rule.contributor) {
                    return Ok(count);
                }
                count
                    .checked_add(1)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "block media-rule growth cannot be represented",
                    })
            })?;
        Ok((current, requested))
    }
}

fn block_request_extent(request: &BlockRequest) -> Result<u64, DeviceError> {
    let payload =
        u64::try_from(request.data.len()).map_err(|_| DeviceError::InvalidBlockFaultDirective {
            reason: "pending storage request byte count overflow",
        })?;
    Ok(u64::from(request.count).max(payload))
}
