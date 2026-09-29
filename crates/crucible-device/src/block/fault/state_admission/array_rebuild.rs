//! Exact dirty-range recording and authenticated array rebuild continuation.

use super::*;

impl BlockFaultState {
    /// Records one exact physical mutation absent from an array member.
    ///
    /// Overlapping and adjacent ranges for a member are coalesced immediately,
    /// retaining the earliest dirty coordinate and newest mutation generation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for an empty/overflowing range or when the
    /// checkpointed dirty-range hard bound would be exceeded.
    pub(in crate::block::fault) fn record_array_dirty_range_untracked(
        &mut self,
        member: u16,
        start_byte: u64,
        bytes: Vec<u8>,
        dirty_ticks: u64,
    ) -> Result<(), DeviceError> {
        let length_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let end = start_byte
            .checked_add(length_bytes)
            .filter(|_| !bytes.is_empty())
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "array dirty range is empty or overflows",
            })?;
        let generation = self.array_rebuild.next_sequence;
        observed_member_set!(
            self,
            self.array_rebuild.next_sequence,
            self.array_rebuild.next_sequence.checked_add(1).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "array dirty-range generation overflow",
                },
            )?
        );
        if self.array_rebuild.scheduled_member == Some(member) {
            observed_member_set!(self, self.array_rebuild.next_ready_ticks, None);
            observed_member_set!(self, self.array_rebuild.scheduled_member, None);
            observed_member_set!(self, self.array_rebuild.scheduled_start_byte, None);
            observed_member_set!(self, self.array_rebuild.scheduled_generation, None);
        }
        let overlapping = self
            .array_dirty_ranges
            .range((member, 0)..=(member, u64::MAX))
            .filter_map(|(key, range)| {
                let range_end = range
                    .start_byte
                    .checked_add(u64::try_from(range.bytes.len()).unwrap_or(u64::MAX))?;
                (range.start_byte <= end && range_end >= start_byte)
                    .then_some((*key, range.clone()))
            })
            .collect::<Vec<_>>();
        let mut merged_start = start_byte;
        let mut merged_end = end;
        let mut merged_ticks = dirty_ticks;
        for (_, range) in &overlapping {
            merged_start = merged_start.min(range.start_byte);
            merged_end = merged_end.max(
                range
                    .start_byte
                    .saturating_add(u64::try_from(range.bytes.len()).unwrap_or(u64::MAX)),
            );
            merged_ticks = merged_ticks.min(range.dirty_ticks);
        }
        let merged_len = usize::try_from(merged_end - merged_start).map_err(|_| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "coalesced array dirty bytes do not fit memory",
            }
        })?;
        let removed_bytes = overlapping.iter().try_fold(0_u64, |total, (_, range)| {
            total
                .checked_add(u64::try_from(range.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "array dirty byte accounting overflows",
                })
        })?;
        let retained_bytes = self
            .array_dirty_ranges
            .values()
            .try_fold(0_u64, |total, range| {
                total
                    .checked_add(u64::try_from(range.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "array dirty byte accounting overflows",
                    })
            })?
            .checked_sub(removed_bytes)
            .and_then(|total| total.checked_add(u64::try_from(merged_len).ok()?))
            .filter(|total| *total <= HARD_BLOCK_ARRAY_DIRTY_BYTES)
            .ok_or(DeviceError::BlockFaultStateLimit {
                field: "block_array_dirty_bytes",
                hard: usize::try_from(HARD_BLOCK_ARRAY_DIRTY_BYTES).unwrap_or(usize::MAX),
            })?;
        debug_assert!(retained_bytes >= u64::try_from(merged_len).unwrap_or(u64::MAX));
        let mut merged = vec![0; merged_len];
        for (key, range) in overlapping {
            observed_remove!(self, array_dirty_ranges, &key);
            let offset = usize::try_from(range.start_byte - merged_start).map_err(|_| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "coalesced array dirty offset does not fit memory",
                }
            })?;
            merged[offset..offset + range.bytes.len()].copy_from_slice(&range.bytes);
        }
        let offset = usize::try_from(start_byte - merged_start).map_err(|_| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "array dirty offset does not fit memory",
            }
        })?;
        merged[offset..offset + bytes.len()].copy_from_slice(&bytes);
        if self.array_dirty_ranges.len() == HARD_BLOCK_ARRAY_DIRTY_RANGES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_array_dirty_ranges",
                hard: HARD_BLOCK_ARRAY_DIRTY_RANGES,
            });
        }
        observed_insert!(
            self,
            array_dirty_ranges,
            (member, merged_start),
            BlockArrayDirtyRange {
                member_ordinal: member,
                start_byte: merged_start,
                bytes: merged,
                generation,
                dirty_ticks: merged_ticks,
            },
        );
        Ok(())
    }

    /// Returns the canonical array dirty-range continuation.
    #[must_use]
    pub fn array_dirty_ranges(&self) -> Vec<BlockArrayDirtyRange> {
        self.array_dirty_ranges.values().cloned().collect()
    }

    /// Returns the checkpointed rebuild scheduler cursor.
    #[must_use]
    pub const fn array_rebuild_cursor(&self) -> BlockArrayRebuildCursor {
        self.array_rebuild
    }

    /// Returns the next modeled array-rebuild completion coordinate.
    #[must_use]
    pub(in crate::block) const fn next_array_rebuild_deadline_ticks(&self) -> Option<u64> {
        self.array_rebuild.next_ready_ticks
    }

    /// Schedules or returns the next exact bounded rebuild chunk.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for zero policy values or arithmetic overflow.
    pub(in crate::block::fault) fn next_array_rebuild_opportunity_untracked(
        &mut self,
        now_ticks: u64,
        chunk_bytes: u64,
        bytes_per_second: u64,
        operations_per_second: Option<u64>,
    ) -> Result<Option<BlockArrayRebuildOpportunity>, DeviceError> {
        if chunk_bytes == 0 || bytes_per_second == 0 || operations_per_second == Some(0) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "array rebuild service must have positive chunk and byte rate",
            });
        }
        let Some(range) = self.array_dirty_ranges.values().next() else {
            observed_set!(
                self,
                array_rebuild,
                BlockArrayRebuildCursor {
                    next_sequence: self.array_rebuild.next_sequence,
                    available_ticks: self.array_rebuild.available_ticks,
                    ..BlockArrayRebuildCursor::default()
                }
            );
            return Ok(None);
        };
        let count = usize::try_from(chunk_bytes)
            .unwrap_or(usize::MAX)
            .min(range.bytes.len());
        let byte_service_ticks = u128::try_from(count)
            .unwrap_or(u128::MAX)
            .checked_mul(1_000_000_000 * u128::from(crucible_shmem::TICKS_PER_NS))
            .and_then(|work| work.checked_add(u128::from(bytes_per_second - 1)))
            .map(|work| work / u128::from(bytes_per_second))
            .and_then(|nanos| u64::try_from(nanos).ok())
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "array rebuild service coordinate overflows",
            })?
            .max(1);
        let operation_service_ticks = operations_per_second
            .map(|rate| {
                (1_000_000_000_u64 * crucible_shmem::TICKS_PER_NS)
                    .checked_add(rate - 1)
                    .map(|nanos| nanos / rate)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "array rebuild IOPS coordinate overflows",
                    })
            })
            .transpose()?
            .unwrap_or(1);
        let service_ticks = byte_service_ticks.max(operation_service_ticks);
        let scheduled_matches = self.array_rebuild.scheduled_member == Some(range.member_ordinal)
            && self.array_rebuild.scheduled_start_byte == Some(range.start_byte)
            && self.array_rebuild.scheduled_generation == Some(range.generation);
        let ready_ticks = match (self.array_rebuild.next_ready_ticks, scheduled_matches) {
            (Some(ready), true) => ready,
            (None, _) | (Some(_), false) => {
                let service_start = self
                    .array_rebuild
                    .available_ticks
                    .unwrap_or(now_ticks)
                    .max(range.dirty_ticks);
                let ready = service_start.checked_add(service_ticks).ok_or(
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "array rebuild deadline overflows",
                    },
                )?;
                observed_member_set!(self, self.array_rebuild.next_ready_ticks, Some(ready));
                observed_member_set!(
                    self,
                    self.array_rebuild.scheduled_member,
                    Some(range.member_ordinal)
                );
                observed_member_set!(
                    self,
                    self.array_rebuild.scheduled_start_byte,
                    Some(range.start_byte)
                );
                observed_member_set!(
                    self,
                    self.array_rebuild.scheduled_generation,
                    Some(range.generation)
                );
                ready
            }
        };
        if ready_ticks > now_ticks {
            return Ok(None);
        }
        Ok(Some(BlockArrayRebuildOpportunity {
            sequence: self.array_rebuild.next_sequence,
            member_ordinal: range.member_ordinal,
            start_byte: range.start_byte,
            bytes: range.bytes[..count].to_vec(),
            generation: range.generation,
            ready_ticks,
        }))
    }

    /// Commits one exact previously offered rebuild chunk.
    pub(in crate::block::fault) fn complete_array_rebuild_untracked(
        &mut self,
        opportunity: &BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        let key = (opportunity.member_ordinal, opportunity.start_byte);
        let range =
            self.array_dirty_ranges
                .get(&key)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "array rebuild opportunity no longer names a dirty range",
                })?;
        if range.generation != opportunity.generation
            || !range.bytes.starts_with(&opportunity.bytes)
            || self.array_rebuild.next_ready_ticks != Some(opportunity.ready_ticks)
            || self.array_rebuild.scheduled_member != Some(opportunity.member_ordinal)
            || self.array_rebuild.scheduled_start_byte != Some(opportunity.start_byte)
            || self.array_rebuild.scheduled_generation != Some(opportunity.generation)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "array rebuild opportunity is stale or unauthenticated",
            });
        }
        let mut remainder = range.clone();
        observed_remove!(self, array_dirty_ranges, &key);
        if opportunity.bytes.len() < remainder.bytes.len() {
            remainder.start_byte = remainder
                .start_byte
                .checked_add(u64::try_from(opportunity.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "array rebuild cursor overflows",
                })?;
            remainder.bytes.drain(..opportunity.bytes.len());
            observed_insert!(
                self,
                array_dirty_ranges,
                (remainder.member_ordinal, remainder.start_byte),
                remainder
            );
        }
        observed_member_set!(
            self,
            self.array_rebuild.next_sequence,
            self.array_rebuild.next_sequence.checked_add(1).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "array rebuild sequence overflows",
                },
            )?
        );
        observed_member_set!(
            self,
            self.array_rebuild.available_ticks,
            Some(opportunity.ready_ticks)
        );
        observed_member_set!(self, self.array_rebuild.next_ready_ticks, None);
        observed_member_set!(self, self.array_rebuild.scheduled_member, None);
        observed_member_set!(self, self.array_rebuild.scheduled_start_byte, None);
        observed_member_set!(self, self.array_rebuild.scheduled_generation, None);
        Ok(())
    }

    /// Retires one failed rebuild attempt without repairing its dirty bytes.
    ///
    /// The next scheduler call charges the complete chunk service duration
    /// again, preventing a persistent failure from spinning at one coordinate.
    pub(in crate::block::fault) fn defer_array_rebuild_untracked(
        &mut self,
        opportunity: &BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        let range = self
            .array_dirty_ranges
            .get(&(opportunity.member_ordinal, opportunity.start_byte))
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "failed array rebuild opportunity no longer names a dirty range",
            })?;
        if range.generation != opportunity.generation
            || !range.bytes.starts_with(&opportunity.bytes)
            || self.array_rebuild.next_ready_ticks != Some(opportunity.ready_ticks)
            || self.array_rebuild.scheduled_member != Some(opportunity.member_ordinal)
            || self.array_rebuild.scheduled_start_byte != Some(opportunity.start_byte)
            || self.array_rebuild.scheduled_generation != Some(opportunity.generation)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "failed array rebuild opportunity is stale or unauthenticated",
            });
        }
        observed_member_set!(
            self,
            self.array_rebuild.next_sequence,
            self.array_rebuild.next_sequence.checked_add(1).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "array rebuild sequence overflows",
                },
            )?
        );
        observed_member_set!(
            self,
            self.array_rebuild.available_ticks,
            Some(opportunity.ready_ticks)
        );
        observed_member_set!(self, self.array_rebuild.next_ready_ticks, None);
        observed_member_set!(self, self.array_rebuild.scheduled_member, None);
        observed_member_set!(self, self.array_rebuild.scheduled_start_byte, None);
        observed_member_set!(self, self.array_rebuild.scheduled_generation, None);
        Ok(())
    }

    /// Pauses a scheduled rebuild while its destination is unavailable.
    pub(in crate::block::fault) fn pause_array_rebuild_untracked(
        &mut self,
        _now_ticks: u64,
        opportunity: &BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        let range = self
            .array_dirty_ranges
            .get(&(opportunity.member_ordinal, opportunity.start_byte))
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "paused array rebuild opportunity no longer names a dirty range",
            })?;
        if range.generation != opportunity.generation
            || self.array_rebuild.next_ready_ticks != Some(opportunity.ready_ticks)
            || self.array_rebuild.scheduled_member != Some(opportunity.member_ordinal)
            || self.array_rebuild.scheduled_start_byte != Some(opportunity.start_byte)
            || self.array_rebuild.scheduled_generation != Some(opportunity.generation)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "paused array rebuild opportunity is stale or unauthenticated",
            });
        }
        observed_member_set!(self, self.array_rebuild.available_ticks, None);
        observed_member_set!(self, self.array_rebuild.next_ready_ticks, None);
        observed_member_set!(self, self.array_rebuild.scheduled_member, None);
        observed_member_set!(self, self.array_rebuild.scheduled_start_byte, None);
        observed_member_set!(self, self.array_rebuild.scheduled_generation, None);
        Ok(())
    }
}
