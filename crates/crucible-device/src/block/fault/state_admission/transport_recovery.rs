//! Retained completion release, storage loss, and epoch-bound transport recovery.

use super::*;

impl BlockFaultState {
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
    pub fn retained_timeouts_due(&self, now_ticks: u64) -> Vec<BlockRequestIdentity> {
        self.retained_completions
            .iter()
            .filter_map(|(identity, completion)| {
                (completion.timeout_ticks <= now_ticks).then_some(*identity)
            })
            .collect()
    }

    /// Returns retained requests subscribed to one recovery event identity.
    #[must_use]
    pub fn retained_recoveries_for(
        &self,
        event: [u8; 32],
        event_ticks: u64,
        event_sequence: u64,
    ) -> Vec<BlockRequestIdentity> {
        self.retained_completions
            .iter()
            .filter_map(|(identity, completion)| {
                (completion.recovery_event == Some(event)
                    && completion
                        .recovery_after_ticks
                        .zip(completion.recovery_after_sequence)
                        .is_some_and(|after| (event_ticks, event_sequence) > after))
                .then_some(*identity)
            })
            .collect()
    }

    /// Returns the earliest retained-completion timeout coordinate.
    #[must_use]
    pub fn next_retained_timeout_ticks(&self) -> Option<u64> {
        self.retained_completions
            .values()
            .map(|completion| completion.timeout_ticks)
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
    pub(in crate::block::fault) fn resolve_retained_completion_untracked(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
        now_ticks: u64,
    ) -> Result<Option<Response>, DeviceError> {
        let completion = self.retained_completions.get(&identity).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "storage completion is not retained",
            },
        )?;
        let response = match release {
            BlockRetainedRelease::Recovery {
                event_ticks,
                event_sequence,
            } => {
                let subscribed_after = completion
                    .recovery_after_ticks
                    .zip(completion.recovery_after_sequence)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage completion has no recovery subscription",
                    })?;
                if completion.recovery_event.is_none()
                    || (event_ticks, event_sequence) <= subscribed_after
                    || event_ticks > completion.timeout_ticks
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage recovery is outside its eligible subscription window",
                    });
                }
                if let Some(frontier) = completion.persist_through_on_recovery {
                    let wait = self.persist_through(base, durable, frontier, now_ticks)?;
                    if wait != 0 {
                        return Ok(None);
                    }
                    observed_set!(
                        self,
                        reported_durable_frontier,
                        self.actual_durable_frontier
                    );
                }
                completion.recovery_response
            }
            BlockRetainedRelease::Timeout => {
                if now_ticks < completion.timeout_ticks {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage timeout was released before its deadline",
                    });
                }
                completion.timeout_response
            }
        };
        observed_remove!(self, retained_completions, &identity);
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
    pub(in crate::block::fault) fn lose_volatile_untracked(
        &mut self,
        sequences: &[u64],
    ) -> Result<(), DeviceError> {
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
            if let Some(entry) = observed_remove!(next, volatile, &sequence) {
                next.persistence.commit_lost(sequence)?;
                observed_set!(
                    next,
                    first_lost_sequence,
                    Some(
                        next.first_lost_sequence
                            .map_or(sequence, |existing| existing.min(sequence)),
                    )
                );
                observed_set!(
                    next,
                    volatile_bytes,
                    next.volatile_bytes
                        .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "volatile byte accounting underflow",
                        })?
                );
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
    pub(in crate::block::fault) fn lose_controller_untracked(
        &mut self,
        sequences: &[u64],
    ) -> Result<(), DeviceError> {
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
            if let Some(entry) = observed_remove!(next, controller, &sequence) {
                next.persistence.commit_lost(sequence)?;
                observed_set!(
                    next,
                    first_lost_sequence,
                    Some(
                        next.first_lost_sequence
                            .map_or(sequence, |existing| existing.min(sequence)),
                    )
                );
                observed_set!(
                    next,
                    controller_bytes,
                    next.controller_bytes
                        .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "controller byte accounting underflow",
                        })?
                );
            }
        }
        next.recompute_actual_durable_frontier();
        *self = next;
        Ok(())
    }

    /// Applies the host-side portion of a controller reset.
    ///
    /// For a response-triggered reset, the caller invokes this after the reset
    /// response crosses the delivery boundary. An asynchronous controller effect
    /// invokes it directly at its scheduler-authorized boundary. Requests removed
    /// from a host-owned lifecycle stage receive one explicit terminal or retry
    /// disposition; returned responses are ordered by request sequence within
    /// each stage and by queued, executing, resolved, then completed stage order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a generated response cannot be encoded or if
    /// losing controller/cache state violates persistence accounting.
    pub(in crate::block::fault) fn apply_transport_reset_untracked(
        &mut self,
        reset: BlockTransportReset,
        delivered_ticks: u64,
    ) -> Result<Vec<Response>, DeviceError> {
        let mut next = self.clone();
        let mut responses = Vec::new();

        let current_epoch = next.transport_epoch.unwrap_or(0);
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
            if observed_insert!(
                next,
                retired_transport_epochs,
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
        observed_set!(next, transport_epoch, Some(reset.next_epoch));
        observed_set!(
            next,
            recovery_until_ticks,
            Some(
                delivered_ticks
                    .checked_add(crate::ns_to_tick(reset.recovery_nanos)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "block transport recovery deadline overflow",
                    })?,
            )
        );

        let pending = observed_take!(next, pending);
        observed_set!(next, pending_bytes, 0);
        for (identity, _directive) in pending {
            responses.push(transport_pending_response(
                identity,
                reset.queued,
                reset.failure_result,
            )?);
        }

        let queued = observed_take!(next, service_pending);
        observed_set!(next, service_pending_bytes, 0);
        observed_set!(next, service, BlockServiceState::default());
        for pending in queued.into_values() {
            responses.push(transport_pending_response(
                pending.request.identity(),
                reset.queued,
                reset.failure_result,
            )?);
        }

        let executing = observed_take!(next, execution_pending);
        observed_set!(next, execution_pending_bytes, 0);
        for pending in executing.into_values() {
            responses.push(transport_pending_response(
                pending.opportunity.request.identity(),
                reset.executing,
                reset.failure_result,
            )?);
        }

        if reset.resolved != BlockTransportResolved::Complete {
            let persistence = observed_take!(next, request_persistence_pending);
            observed_set!(next, request_persistence_pending_bytes, 0);
            for pending in persistence.into_values() {
                responses.push(transport_resolved_response(
                    pending.opportunity.request.identity(),
                    reset.resolved,
                    reset.failure_result,
                )?);
            }

            let delivery = observed_take!(next, delivery_pending);
            observed_set!(next, delivery_pending_bytes, 0);
            for pending in delivery.into_values() {
                responses.push(transport_resolved_response(
                    pending.opportunity.request.identity(),
                    reset.resolved,
                    reset.failure_result,
                )?);
            }
        } else {
            for pending in next.delivery_pending.values_mut() {
                observed_member_set!(next, pending.opportunity.required_durable_frontier, None);
            }
        }

        if reset.completed_undelivered != BlockTransportUndelivered::Complete {
            let retained = observed_take!(next, retained_completions);
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
}
