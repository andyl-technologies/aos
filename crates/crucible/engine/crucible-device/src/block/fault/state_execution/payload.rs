//! Resolved payload reads, writes, discard, and external-device mutations.

use super::*;

impl BlockFaultState {
    /// Applies one externally misdirected write without fabricating a guest request.
    ///
    /// The destination uses its own geometry and normal durability policy at
    /// `admitted_ticks`, the source persistence opportunity's exact coordinate.
    /// The returned stage and frontier identify the exact destination completion
    /// acknowledgement that must gate source delivery. The multi-device owner is
    /// responsible for executing this method on cloned source/destination devices
    /// and committing both together.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for destination range, atomicity, cache, retained
    /// version, or durable-overlay failures.
    // crucible-lint: allow rust-allow -- the atomic cross-device write carries independent request identity, time, range, and bytes.
    #[allow(
        clippy::too_many_arguments,
        reason = "the atomic cross-device write carries independent request identity, time, range, and bytes"
    )]
    pub(in crate::block::fault) fn apply_external_write_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request_id: u32,
        request_sequence: u64,
        admitted_ticks: u64,
        destination_offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        let request = BlockRequest::write(request_id, destination_offset, bytes);
        let mut directive =
            ResolvedBlockFaultDirective::fault_free(&request, self.config.length_bytes);
        directive.request_sequence = request_sequence;
        directive.execution_ticks = admitted_ticks;
        directive.persistence_admitted_ticks = admitted_ticks;
        directive.validate_for(&request, &self.config)?;
        if u64::from(request.count) > self.config.maximum_request_bytes
            || !request_in_capacity(&request, self.config.length_bytes)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external write exceeds destination capacity or request geometry",
            });
        }
        match self.apply_write(base, durable, &request, &directive)? {
            BlockWriteOutcome::Applied(_persistence_wait_ticks) => {
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

    /// Applies one externally owned array mutation without a guest completion.
    pub(in crate::block::fault) fn apply_external_mutation_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request_sequence: u64,
        admitted_ticks: u64,
        request: BlockRequest,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        if !matches!(
            request.op,
            BlockOp::Write | BlockOp::Discard | BlockOp::Flush
        ) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external array mutation must be write, discard, or flush",
            });
        }
        let mut directive =
            ResolvedBlockFaultDirective::fault_free(&request, self.config.length_bytes);
        directive.request_sequence = request_sequence;
        directive.execution_ticks = admitted_ticks;
        directive.persistence_admitted_ticks = admitted_ticks;
        directive.validate_for(&request, &self.config)?;
        if !request_in_capacity(&request, self.config.length_bytes)
            || u64::from(request.count) > self.config.maximum_request_bytes
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external array mutation exceeds member capacity or request geometry",
            });
        }
        let (response, _wait_ticks) = self.execute_wire(base, durable, &request, &directive)?;
        if response.status != BlockStatus::Ok {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external array mutation was rejected by the member",
            });
        }
        match request.op {
            BlockOp::Write | BlockOp::Discard => {
                Ok((self.config.completion_durability, self.next_cache_sequence))
            }
            BlockOp::Flush => Ok((BlockCompletionDurability::Durable, self.next_cache_sequence)),
            BlockOp::Read | BlockOp::GetLength => Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external array mutation operation changed during execution",
            }),
        }
    }

    pub(in crate::block::fault) fn execute_wire(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<(BlockResponse, u64), DeviceError> {
        let admission_error = block_admission_error(request, directive, &self.config);
        let media_error = if admission_error.is_none() && directive.error_result.is_none() {
            // Only selected contributor counters can change; unrelated
            // retained cache payloads and media rules are never copied here.
            let before = directive
                .media_rules
                .iter()
                .map(|rule| {
                    (
                        rule.contributor,
                        self.media
                            .rules()
                            .get(&rule.contributor)
                            .map(|continuation| continuation.access_count),
                    )
                })
                .collect::<Vec<_>>();
            let result = self.media.apply(
                request,
                directive.execution_ticks,
                self.config.length_bytes,
                &directive.media_rules,
            );
            self.observation_changed |= before.into_iter().any(|(contributor, count)| {
                self.media
                    .rules()
                    .get(&contributor)
                    .map(|continuation| continuation.access_count)
                    != count
            });
            result?
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
                    let registered = self.flash.continuations().len();
                    let result = self.flash.read(
                        request,
                        directive.execution_ticks,
                        self.config.length_bytes,
                        &directive.persistence_media_rules,
                        &mut bytes,
                    );
                    // Registration can survive a later read refusal. Mirror
                    // the successful read's actual page range: even a zero-
                    // byte read inside a page advances its disturb counter.
                    // Success guarantees validated nonzero page geometry.
                    let touched_pages = result.is_ok()
                        && request
                            .offset
                            .checked_add(u64::from(request.count))
                            .is_some_and(|end| {
                                directive.persistence_media_rules.iter().any(|rule| {
                                    request.offset / rule.program_page_bytes
                                        <= end.saturating_sub(1) / rule.program_page_bytes
                                })
                            });
                    self.observation_changed |=
                        self.flash.continuations().len() != registered || touched_pages;
                    result?;
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
                    let wait = self.persist_all(base, durable, directive.execution_ticks)?;
                    if wait == 0 {
                        observed_set!(
                            self,
                            reported_durable_frontier,
                            self.actual_durable_frontier
                        );
                    } else {
                        observed_set!(
                            self,
                            pending_barrier_frontier,
                            Some(
                                self.pending_barrier_frontier
                                    .map_or(frontier, |existing| existing.max(frontier)),
                            )
                        );
                        observed_set!(
                            self,
                            pending_honest_flush_frontier,
                            Some(
                                self.pending_honest_flush_frontier
                                    .map_or(frontier, |existing| existing.max(frontier)),
                            )
                        );
                    }
                    if self.actual_durable_frontier >= frontier {
                        observed_set!(self, pending_barrier_frontier, None);
                    }
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), wait))
                }
                BlockFaultFlushDisposition::Error(error) => {
                    Ok((BlockResponse::error_for(request.identity(), error), 0))
                }
                BlockFaultFlushDisposition::Lie => {
                    let frontier = self.next_cache_sequence;
                    observed_set!(self, reported_durable_frontier, frontier);
                    observed_set!(
                        self,
                        pending_barrier_frontier,
                        Some(
                            self.pending_barrier_frontier
                                .map_or(frontier, |existing| existing.max(frontier)),
                        )
                    );
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), 0))
                }
                BlockFaultFlushDisposition::Stall => {
                    let frontier = self.next_cache_sequence;
                    observed_set!(
                        self,
                        pending_barrier_frontier,
                        Some(
                            self.pending_barrier_frontier
                                .map_or(frontier, |existing| existing.max(frontier)),
                        )
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

    pub(in crate::block::fault) fn apply_discard(
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

    pub(in crate::block::fault) fn read_visible_untracked(
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
            observed_set!(
                self,
                next_cache_access_sequence,
                self.next_cache_access_sequence.checked_add(1).ok_or(
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "cache access sequence overflow",
                    }
                )?
            );
            if let Some(entry) = self.volatile.get_mut(&sequence) {
                observed_member_set!(self, entry.last_access_sequence, access_sequence);
            }
        }
        Ok(bytes)
    }

    pub(in crate::block::fault) fn apply_write(
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
                    directive.execution_ticks,
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
        observed_set!(
            self,
            next_cache_sequence,
            self.next_cache_sequence.checked_add(sequence_count).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write durability sequence overflow",
                },
            )?
        );
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
                observed_set!(
                    self,
                    first_lost_sequence,
                    Some(
                        self.first_lost_sequence
                            .map_or(sequence, |existing| existing.min(sequence)),
                    )
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
            directive.persistence_admitted_ticks,
            &directive.persistence_transforms,
            self.pending_barrier_frontier,
        )?;
        // Admission is transactional and each nonempty fragment installs a
        // previously absent graph node. Empty admission changes nothing.
        self.observation_changed |= !persistence_fragments.is_empty();
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
                observed_insert!(
                    self,
                    pending_persistence_media,
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
                            ready_ticks: self.persistence.deadline_ticks(sequence).unwrap_or(0),
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
        let persistence_wait_ticks = if !cache && !controller {
            self.persist_through(
                base,
                durable,
                self.next_cache_sequence,
                directive.execution_ticks,
            )?
        } else {
            0
        };
        self.recompute_actual_durable_frontier();
        if !cache && !controller {
            observed_set!(
                self,
                reported_durable_frontier,
                self.actual_durable_frontier
            );
        }
        Ok(BlockWriteOutcome::Applied(persistence_wait_ticks))
    }
}
