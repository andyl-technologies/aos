//! Complete checkpoint validation of retained block-fault ownership and accounting.

use super::*;

impl BlockFaultState {
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
            || self.array_dirty_ranges.len() > HARD_BLOCK_ARRAY_DIRTY_RANGES
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
        let array_dirty_bytes = self
            .array_dirty_ranges
            .values()
            .try_fold(0_u64, |total, range| {
                total.checked_add(u64::try_from(range.bytes.len()).unwrap_or(u64::MAX))
            })
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "restored array dirty byte accounting overflows",
            })?;
        if array_dirty_bytes > HARD_BLOCK_ARRAY_DIRTY_BYTES {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored array dirty bytes exceed the hard bound",
            });
        }
        if self
            .array_rebuild
            .next_ready_ticks
            .zip(self.array_rebuild.available_ticks)
            .is_some_and(|(ready, available)| ready <= available)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored array rebuild deadline does not follow charged service",
            });
        }
        if self
            .array_dirty_ranges
            .iter()
            .any(|(&(member, start), range)| {
                range.member_ordinal != member
                    || range.start_byte != start
                    || range.bytes.is_empty()
                    || range.generation >= self.array_rebuild.next_sequence
                    || start
                        .checked_add(u64::try_from(range.bytes.len()).unwrap_or(u64::MAX))
                        .is_none()
            })
            || self
                .array_dirty_ranges
                .values()
                .scan(None, |previous: &mut Option<(u16, u64)>, range| {
                    let overlaps = previous.is_some_and(|(member, end)| {
                        member == range.member_ordinal && end >= range.start_byte
                    });
                    *previous = Some((
                        range.member_ordinal,
                        range
                            .start_byte
                            .saturating_add(u64::try_from(range.bytes.len()).unwrap_or(u64::MAX)),
                    ));
                    Some(overlaps)
                })
                .any(|overlaps| overlaps)
            || match (
                self.array_rebuild.next_ready_ticks,
                self.array_rebuild.scheduled_member,
                self.array_rebuild.scheduled_start_byte,
                self.array_rebuild.scheduled_generation,
            ) {
                (None, None, None, None) => false,
                (Some(_), Some(member), Some(start), Some(generation)) => self
                    .array_dirty_ranges
                    .get(&(member, start))
                    .is_none_or(|range| range.generation != generation),
                _ => true,
            }
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored array dirty-range continuation is noncanonical",
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
                || pending.opportunity.admission.execution_ticks != pending.opportunity.ready_ticks
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored request execution opportunity is invalid",
                });
            }
            if let Some(execution) = &pending.execution {
                execution.validate_for(&pending.opportunity.request, &self.config)?;
                if execution.request_sequence != *sequence
                    || !execution.service_rules.is_empty()
                    || execution.execution_ticks != pending.opportunity.ready_ticks
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
                || opportunity.resolved.execution_ticks != opportunity.ready_ticks
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
                    || persistence.execution_ticks != opportunity.ready_ticks
                    || persistence.availability != opportunity.resolved.availability
                    || persistence.reported_capacity_bytes
                        != opportunity.resolved.reported_capacity_bytes
                    || persistence.error_result != opportunity.resolved.error_result
                    || persistence.read_transforms != opportunity.resolved.read_transforms
                    || persistence.retain_completion != opportunity.resolved.retain_completion
                    || persistence.retention_timeout_response
                        != opportunity.resolved.retention_timeout_response
                    || persistence.retention_timeout_ticks
                        != opportunity.resolved.retention_timeout_ticks
                    || persistence.retention_recovery_event
                        != opportunity.resolved.retention_recovery_event
                    || persistence.retention_recovery_after_ticks
                        != opportunity.resolved.retention_recovery_after_ticks
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
                    || delivery.execution_ticks != opportunity.resolved.execution_ticks
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
}
