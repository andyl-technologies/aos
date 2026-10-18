//! Cache and controller storage layers, physical persistence, and durable frontiers.

use super::*;

impl BlockFaultState {
    pub(in crate::block::fault) fn retain_prior(
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
            observed_remove!(self, retained, &oldest);
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
        observed_set!(
            self,
            next_version_sequence,
            self.next_version_sequence.checked_add(1).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "retained version sequence overflow",
                },
            )?
        );
        observed_insert!(
            self,
            retained,
            sequence,
            BlockRetainedVersion {
                sequence,
                offset,
                bytes,
            },
        );
        Ok(())
    }

    pub(in crate::block::fault) fn cache_write(
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
        observed_set!(
            self,
            next_cache_access_sequence,
            self.next_cache_access_sequence.checked_add(1).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "cache access sequence overflow",
                },
            )?
        );
        observed_insert!(
            self,
            volatile,
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
        observed_set!(self, volatile_bytes, next_bytes);
        Ok(())
    }

    pub(in crate::block::fault) fn prepare_cache_admission(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        incoming_entries: usize,
        incoming_bytes: u64,
        policy: ResolvedBlockCachePolicy,
        now_ticks: u64,
    ) -> Result<Option<BlockFaultResult>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let rejection = next.prepare_cache_admission_staged(
            base,
            &mut next_durable,
            incoming_entries,
            incoming_bytes,
            policy,
            now_ticks,
        )?;
        if rejection.is_none() {
            *self = next;
            *durable = next_durable;
        }
        Ok(rejection)
    }

    pub(in crate::block::fault) fn prepare_cache_admission_staged(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        incoming_entries: usize,
        incoming_bytes: u64,
        policy: ResolvedBlockCachePolicy,
        now_ticks: u64,
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
            self.persist_due(base, durable, now_ticks)?;
        }
        Ok(None)
    }

    pub(in crate::block::fault) fn schedule_volatile_persistence(
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
        let removed = observed_remove!(self, volatile, &sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "cache eviction fragment disappeared",
            },
        )?;
        observed_set!(
            self,
            volatile_bytes,
            self.volatile_bytes
                .checked_sub(u64::try_from(removed.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "volatile byte accounting underflow during persistence scheduling",
                })?
        );
        Ok(())
    }

    pub(in crate::block::fault) fn persist_due_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<(), DeviceError> {
        loop {
            let sequence = self
                .media_queue
                .keys()
                .filter(|sequence| self.persistence.is_ready_at(**sequence, now_ticks))
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
            self.persist_sequence(base, durable, sequence, now_ticks)?;
        }
        self.recompute_actual_durable_frontier();
        if self
            .pending_honest_flush_frontier
            .is_some_and(|frontier| self.actual_durable_frontier >= frontier)
        {
            observed_set!(
                self,
                reported_durable_frontier,
                self.actual_durable_frontier
            );
            observed_set!(self, pending_honest_flush_frontier, None);
        }
        Ok(())
    }

    pub(in crate::block::fault) fn controller_write(
        &mut self,
        sequence: u64,
        request_id: u32,
        media_identity: BlockMediaOperationIdentity,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        observed_set!(
            self,
            controller_bytes,
            self.controller_bytes.checked_add(length).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "controller byte count overflow",
                },
            )?
        );
        observed_insert!(
            self,
            controller,
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

    pub(in crate::block::fault) fn media_queue_write(
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
        observed_set!(self, media_queue_bytes, next_bytes);
        observed_insert!(
            self,
            media_queue,
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

    pub(in crate::block::fault) fn persist_all(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<u64, DeviceError> {
        self.persist_through(base, durable, self.next_cache_sequence, now_ticks)
    }

    pub(in crate::block::fault) fn persist_through(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        frontier: u64,
        now_ticks: u64,
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
            self.persist_due(base, durable, now_ticks)?;
        }
        let wait = self
            .media_queue
            .keys()
            .copied()
            .filter(|sequence| *sequence < frontier)
            .filter_map(|sequence| self.persistence.deadline_ticks(sequence))
            .map(|deadline| deadline.saturating_sub(now_ticks))
            .max()
            .unwrap_or(0);
        self.recompute_actual_durable_frontier();
        Ok(wait)
    }

    pub(in crate::block::fault) fn schedule_controller_persistence(
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
        let removed = observed_remove!(self, controller, &sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "controller persistence fragment disappeared",
            },
        )?;
        observed_set!(
            self,
            controller_bytes,
            self.controller_bytes
                .checked_sub(u64::try_from(removed.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "controller byte accounting underflow during persistence scheduling",
                })?
        );
        Ok(())
    }

    pub(in crate::block::fault) fn persist_sequence(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        sequence: u64,
        now_ticks: u64,
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
        // Validate the graph commit and layer accounting before the first
        // durable payload write. A failed plan must leave the real overlay intact.
        self.persistence.validate_persisted_commit(sequence)?;
        if self.persistence_media_outcomes.len() >= HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "persistence_media_outcomes",
                hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
            });
        }
        let length =
            u64::try_from(bytes.len()).map_err(|_| DeviceError::InvalidBlockFaultDirective {
                reason: "persistence fragment byte count overflows",
            })?;
        let (layer, remaining_bytes) = if self.controller.contains_key(&sequence) {
            (0, self.controller_bytes.checked_sub(length))
        } else if self.media_queue.contains_key(&sequence) {
            (1, self.media_queue_bytes.checked_sub(length))
        } else {
            (2, self.volatile_bytes.checked_sub(length))
        };
        let remaining_bytes = remaining_bytes.ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "storage layer byte accounting underflow during persistence",
        })?;
        let directive = observed_remove!(self, pending_persistence_media, &sequence);
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
                            now_ticks,
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
                        now_ticks,
                        self.config.length_bytes,
                        &contributors,
                    ),
                    _ => Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "physical persistence operation is not write or discard",
                    }),
                }
            },
        )?;
        let mut writes = Vec::with_capacity(flash.spans.len());
        let mut programmed = Vec::new();
        for span in &flash.spans {
            let start = usize::try_from(span.start).map_err(|_| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "flash program span start does not fit memory",
                }
            })?;
            let end = span.end().and_then(|end| usize::try_from(end).ok()).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "flash program span end overflows",
                },
            )?;
            let selected =
                bytes
                    .get(start..end)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "flash program span exceeds persistence fragment",
                    })?;
            let destination =
                offset
                    .checked_add(span.start)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "flash program destination overflows",
                    })?;
            if destination
                .checked_add(span.length)
                .is_none_or(|end| end > base.len())
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "flash program destination exceeds base image",
                });
            }
            programmed.extend_from_slice(selected);
            writes.push((destination, selected));
        }

        for (destination, selected) in writes {
            // This marker records an actual payload-effect attempt; it grants
            // no Source permission. An unexpected later error cannot return
            // the reserved observation revision to its pre-write value.
            debug_assert!(self.observation_mutation_active);
            self.observation_external_effect = true;
            durable.write(base, destination, selected)?;
        }
        self.persistence.commit_persisted(sequence)?;
        self.observation_changed = true;
        match layer {
            0 => {
                observed_remove!(self, controller, &sequence);
                observed_set!(self, controller_bytes, remaining_bytes);
            }
            1 => {
                observed_remove!(self, media_queue, &sequence);
                observed_set!(self, media_queue_bytes, remaining_bytes);
            }
            _ => {
                observed_remove!(self, volatile, &sequence);
                observed_set!(self, volatile_bytes, remaining_bytes);
            }
        }
        let outcome_index = self.persistence_media_outcomes.len();
        observed_push!(
            self,
            persistence_media_outcomes,
            BlockPersistenceMediaOutcome {
                opportunity,
                executed_ticks: now_ticks,
                applied_spans: flash.spans,
                media_failed: flash.failed,
                applied_digest: *blake3::hash(&programmed).as_bytes(),
            }
        );
        observed_push!(
            self,
            storage_outcome_order,
            BlockStorageOutcomeRef::Persistence(outcome_index)
        );
        self.recompute_actual_durable_frontier();
        Ok(())
    }

    pub(in crate::block::fault) fn persistence_opportunity(
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
            ready_ticks: self.persistence.deadline_ticks(sequence).unwrap_or(0),
        })
    }

    pub(in crate::block::fault) fn validate_persistence_media_directive(
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

    pub(in crate::block::fault) fn recompute_actual_durable_frontier(&mut self) {
        observed_set!(
            self,
            actual_durable_frontier,
            self.controller
                .keys()
                .next()
                .copied()
                .into_iter()
                .chain(self.volatile.keys().next().copied())
                .chain(self.media_queue.keys().next().copied())
                .chain(self.first_lost_sequence)
                .min()
                .unwrap_or(self.next_cache_sequence)
        );
        if self.pending_barrier_frontier.is_some_and(|frontier| {
            !self
                .persistence
                .nodes()
                .keys()
                .any(|sequence| *sequence < frontier)
        }) {
            observed_set!(self, pending_barrier_frontier, None);
        }
    }
}
