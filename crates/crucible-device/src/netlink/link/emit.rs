//! Network-link construction, fault configuration, and frame emission.

use super::*;

impl NetLink {
    /// Builds a link with a clock shift, source id, base latency, floor, and faults.
    ///
    /// The base latency MUST be strictly positive and at or above `floor_ns`, and
    /// `floor_ns` MUST itself be strictly positive ([IO-33]): the base latency is
    /// what supplies the scheduler's conservative lookahead bound, so a
    /// zero-latency link is rejected rather than silently collapsing parallelism.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when `shift_bits >= 64`, and
    /// [`DeviceError::LinkLatencyBelowFloor`] when `floor_ns` is zero or
    /// `base_latency_ns < floor_ns`.
    pub fn new(
        shift_bits: u8,
        src_node: u32,
        base_latency_ns: u64,
        floor_ns: u64,
        faults: LinkFaults,
    ) -> Result<Self, DeviceError> {
        if floor_ns == 0 || base_latency_ns < floor_ns {
            return Err(DeviceError::LinkLatencyBelowFloor {
                base_latency_ns,
                floor_ns,
            });
        }
        Ok(Self {
            clock: VirtualClock::new(shift_bits)?,
            inflight: InflightQueue::new(),
            src_node,
            base_latency_ns,
            floor_ns,
            faults,
            next_seq: 0,
            lookahead_recompute_pending: false,
            rng_position: 0,
        })
    }

    /// Returns the link's current (consumer-frontier) icount.
    #[must_use]
    pub fn current_icount(&self) -> u64 {
        self.clock.current_icount()
    }

    /// Returns the link's base latency in virtual nanoseconds.
    #[must_use]
    pub fn base_latency_ns(&self) -> u64 {
        self.base_latency_ns
    }

    /// Returns the strictly-positive minimum link-latency floor.
    #[must_use]
    pub fn floor_ns(&self) -> u64 {
        self.floor_ns
    }

    /// Returns a read-only view of the effective fault table.
    #[must_use]
    pub fn faults(&self) -> &LinkFaults {
        &self.faults
    }

    /// Returns the per-device RNG stream cursor (draws consumed so far, [IO-23]).
    #[must_use]
    pub fn rng_position(&self) -> u64 {
        self.rng_position
    }

    /// Repositions the deterministic cursor after an explorer-injected draw set.
    ///
    /// This setter is intentionally narrow: the engine supplies a cursor derived
    /// from the exact draw vector consumed by [`NetLink::emit`]. General callers
    /// should use [`NetLink::emit_with_rng_draws`].
    pub fn set_rng_position_for_branch(&mut self, position: u64) {
        self.rng_position = position;
    }

    /// Returns the number of frames in flight (resolved but not yet delivered).
    #[must_use]
    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Returns the in-flight head's delivery icount: the next exact local event.
    ///
    /// The scheduler reads this to bound the destination's horizon; `None` when no
    /// frame is in flight.
    #[must_use]
    pub fn next_exact_local_event(&self) -> Option<u64> {
        self.inflight.next_exact_local_event()
    }

    /// Returns the link's **effective latency** in ns: base + added, clamped to the floor.
    ///
    /// A latency fault that *raises* the effective latency is honored as-is (it
    /// only widens lookahead); a fault that would push it below the floor is
    /// clamped up to the floor ([IO-33]). This is the value the scheduler's
    /// lookahead uses; it is always at or above the strictly-positive floor.
    #[must_use]
    pub fn effective_latency_ns(&self) -> u64 {
        let raised = self
            .base_latency_ns
            .saturating_add(self.faults.added_latency_ns);
        raised.max(self.floor_ns)
    }

    /// Replaces the effective fault table, flagging a lookahead recompute if needed.
    ///
    /// If the new table changes the link's conservative minimum effective latency
    /// ([IO-33]) -- currently the `added_latency_ns` component -- the link sets the
    /// lookahead-recompute flag so the scheduler recomputes its lookahead/horizon
    /// at the **next quantum boundary**, never mid-RUN. The signal is exposed via
    /// [`NetLink::take_lookahead_recompute`]; this method cannot call the
    /// scheduler (it lives in another crate), so it records the flag for the
    /// integration layer (CS-INT) to consume.
    ///
    /// Jitter, reorder, bandwidth, loss, duplicate, and corrupt changes do not
    /// raise the flag ([`LinkFaults::affects_latency`]). They may shift or alter
    /// individual frames, but they do not raise the scalar lower bound consumed by
    /// the scheduler's lookahead graph.
    ///
    /// The recompute predicate compares the fields that can change the scalar
    /// bound, not the full per-frame latency profile.
    pub fn set_faults(&mut self, faults: LinkFaults) {
        if Self::latency_profile_changed(&self.faults, &faults) {
            self.lookahead_recompute_pending = true;
        }
        self.faults = faults;
    }

    /// Returns whether two fault tables differ in the conservative latency bound.
    ///
    /// The bound-relevant fields are exactly those
    /// [`LinkFaults::affects_latency`] reports. Other fields can perturb a
    /// specific delivery after EMIT, but their minimum additional delay is zero and
    /// therefore they do not change the lookahead edge the scheduler reads
    /// ([IO-33]).
    pub(super) fn latency_profile_changed(before: &LinkFaults, after: &LinkFaults) -> bool {
        before.added_latency_ns != after.added_latency_ns
    }

    /// Takes and clears the pending lookahead-recompute signal ([IO-33]).
    ///
    /// Returns `true` exactly once after any conservative latency-bound change,
    /// then resets to `false`. The integration layer (CS-INT) consumes this at
    /// the quantum boundary to trigger the scheduler's lookahead/horizon
    /// recompute ([SCHED-37]).
    pub fn take_lookahead_recompute(&mut self) -> bool {
        core::mem::replace(&mut self.lookahead_recompute_pending, false)
    }

    /// Returns whether a lookahead recompute is pending without clearing it.
    #[must_use]
    pub fn lookahead_recompute_pending(&self) -> bool {
        self.lookahead_recompute_pending
    }

    /// Resolves and enqueues one emitted frame, applying the effective fault table.
    ///
    /// Computes the delivery icount from the base latency (clamped to the floor,
    /// [IO-33]) plus bandwidth serialization and seeded jitter/reorder shifts,
    /// then applies the probabilistic effects from `draws` ([IO-20]): loss drops
    /// the frame (zero deliveries), duplicate emits a second delivery at a
    /// deterministically-derived later icount, and corrupt mutates payload bytes.
    /// Each produced delivery is inserted into the delivery-ordered
    /// in-flight queue and is also returned in the [`ResolveOutcome`].
    ///
    /// The `draws` are injected here for unit testing;
    /// [`NetLink::emit_from_rng`] draws them from the seeded per-device RNG. The
    /// same `frame` and `draws` always yield byte-identical deliveries ([IO-4],
    /// [IO-22]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::CompletionOverflow`] / [`DeviceError::Clock`] /
    /// [`DeviceError::IcountOverflow`] when the virtual-time arithmetic overflows,
    /// and -- when `policy` is [`PastDeliveryPolicy::FailLoud`] --
    /// [`DeviceError::DeliveryReorderedIntoPast`] if a jitter/reorder shift would
    /// move the delivery to at or before the consumer's current frontier ([IO-34]).
    /// On any error no delivery is enqueued (the frame is fully rejected).
    pub fn emit(
        &mut self,
        frame: &Frame,
        draws: &FrameDraws,
        policy: PastDeliveryPolicy,
    ) -> Result<ResolveOutcome, DeviceError> {
        let mut outcome = ResolveOutcome::default();

        // --- partition (IO-20): drop the frame, no delivery ---
        if self.faults.partitioned {
            return Ok(outcome);
        }
        if frame.resolved_effects.is_dropped() {
            return Ok(outcome);
        }

        // --- delivery-time computation (deterministic shifts) ---
        let base_ns = self.clock.virtual_ns(frame.emit_icount)?;
        let base_latency = self.effective_latency_ns();
        let adjusted_latency = i128::from(base_latency)
            .checked_add(i128::from(frame.resolved_effects.latency_delta_nanos()))
            .ok_or(DeviceError::CompletionOverflow {
                request_icount: frame.emit_icount,
                latency_ns: base_latency,
            })?;
        let eff_latency =
            u64::try_from(adjusted_latency.max(i128::from(self.floor_ns))).map_err(|_| {
                DeviceError::CompletionOverflow {
                    request_icount: frame.emit_icount,
                    latency_ns: base_latency,
                }
            })?;
        let len = frame.payload.len() as u64;
        let base_serialization = if frame.resolved_effects.serialization_is_accounted() {
            0
        } else {
            self.faults.serialization_delay_ns(len)
        };
        let serialization = match frame.resolved_effects.serialization_rate_cap_bps() {
            _ if frame.resolved_effects.serialization_is_accounted() => 0,
            Some(rate) => {
                base_serialization.max(checked_serialization_delay_bits_per_sec(len, rate).ok_or(
                    DeviceError::CompletionOverflow {
                        request_icount: frame.emit_icount,
                        latency_ns: eff_latency,
                    },
                )?)
            }
            None => base_serialization,
        };
        let jitter = jitter_shift_ns(draws.jitter, self.faults.jitter_window_ns);
        let reorder = reorder_shift_ns(draws.reorder, self.faults.reorder_window_ns);

        let delivery_ns = base_ns
            .checked_add(eff_latency)
            .and_then(|v| v.checked_add(serialization))
            .and_then(|v| v.checked_add(jitter))
            .and_then(|v| v.checked_add(reorder))
            .and_then(|v| v.checked_add(frame.resolved_effects.additional_delay_nanos()))
            .ok_or(DeviceError::CompletionOverflow {
                request_icount: frame.emit_icount,
                latency_ns: eff_latency,
            })?;
        // The unguarded primary icount; kept so the duplicate gap can be re-derived
        // from raw values even when the primary is clamped into the future.
        let delivery_icount_raw = self.clock.ceil_ns_to_icount(delivery_ns)?;

        // --- into-the-past guard (IO-34): never silently deliver late ---
        let delivery_icount = self.guard_future(delivery_icount_raw, policy)?;

        // --- loss (IO-20): drop the frame, no delivery ---
        if self.faults.loss_fires(draws.loss, &draws.additional_loss) {
            return Ok(outcome);
        }

        // --- corrupt (IO-20): mutate payload bytes deterministically ---
        let mut payload = frame.payload.clone();
        if self.faults.corrupt.fires(draws.corrupt) {
            corrupt_link_payload(&self.faults, &mut payload, &draws.corrupt_bits);
        }

        let mut planned = vec![(delivery_icount, payload.clone())];

        // --- duplicate (IO-20): emit a second delivery at a later icount ---
        if self.faults.duplicate.fires(draws.duplicate) {
            let dup_ns = delivery_ns
                .checked_add(self.faults.duplicate_gap_ns)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: frame.emit_icount,
                    latency_ns: self.faults.duplicate_gap_ns,
                })?;
            let dup_icount_raw = self.clock.ceil_ns_to_icount(dup_ns)?;
            // The duplicate must also stay in the consumer's future ([IO-34]).
            let dup_icount_guarded = self.guard_future(dup_icount_raw, policy)?;
            // Preserve the duplicate gap under ClampToFuture: if both the primary
            // and the duplicate were clamped into the consumer's past, naively
            // clamping both to frontier+1 would collapse them onto one icount and
            // lose `duplicate_gap_ns`. Re-derive the gap in icounts from the
            // *unguarded* raw values and keep the duplicate at least that far past
            // the guarded primary (and always strictly after it). This is a no-op
            // on the normal path where neither was clamped.
            let gap_icount = dup_icount_raw
                .checked_sub(delivery_icount_raw)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: frame.emit_icount,
                    latency_ns: self.faults.duplicate_gap_ns,
                })?
                .max(1);
            let dup_floor =
                delivery_icount
                    .checked_add(gap_icount)
                    .ok_or(DeviceError::CompletionOverflow {
                        request_icount: frame.emit_icount,
                        latency_ns: self.faults.duplicate_gap_ns,
                    })?;
            let dup_icount = dup_icount_guarded.max(dup_floor);
            planned.push((dup_icount, payload.clone()));
        }

        for gap_nanos in frame.resolved_effects.duplicate_gaps_nanos() {
            let duplicate_ns =
                delivery_ns
                    .checked_add(*gap_nanos)
                    .ok_or(DeviceError::CompletionOverflow {
                        request_icount: frame.emit_icount,
                        latency_ns: *gap_nanos,
                    })?;
            let duplicate_icount_raw = self.clock.ceil_ns_to_icount(duplicate_ns)?;
            let duplicate_icount_guarded = self.guard_future(duplicate_icount_raw, policy)?;
            let gap_icount = duplicate_icount_raw
                .checked_sub(delivery_icount_raw)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: frame.emit_icount,
                    latency_ns: *gap_nanos,
                })?
                .max(1);
            let duplicate_floor =
                delivery_icount
                    .checked_add(gap_icount)
                    .ok_or(DeviceError::CompletionOverflow {
                        request_icount: frame.emit_icount,
                        latency_ns: *gap_nanos,
                    })?;
            let duplicate_icount = duplicate_icount_guarded.max(duplicate_floor);
            planned.push((duplicate_icount, payload.clone()));
        }

        let planned_count =
            u32::try_from(planned.len()).map_err(|_| DeviceError::CompletionOverflow {
                request_icount: frame.emit_icount,
                latency_ns: eff_latency,
            })?;
        self.next_seq
            .checked_add(planned_count)
            .ok_or(DeviceError::CompletionOverflow {
                request_icount: frame.emit_icount,
                latency_ns: eff_latency,
            })?;
        for (delivery_icount, delivery_payload) in planned {
            outcome.deliveries.push(self.enqueue_delivery(
                delivery_icount,
                frame.frame_id,
                delivery_payload,
            ));
        }

        Ok(outcome)
    }

    /// Resolves one emitted frame, drawing its faults from the seeded RNG ([IO-21]).
    ///
    /// Identical to [`NetLink::emit`] except the [`FrameDraws`] are produced by
    /// the seeded per-device RNG in the fixed model order
    /// ([`FrameDraws::from_rng_for_faults`]) rather than injected, and the link's RNG cursor
    /// ([`NetLink::rng_position`]) advances to match. The cursor is captured in the
    /// snapshot so a fork resumes the same draw sequence ([IO-23]). The draws are
    /// taken before any early-out so the cursor stays aligned whether or not the
    /// frame is lost.
    ///
    /// # Errors
    ///
    /// Same as [`NetLink::emit`].
    pub fn emit_from_rng(
        &mut self,
        frame: &Frame,
        rng: &mut DeviceRng,
        policy: PastDeliveryPolicy,
    ) -> Result<ResolveOutcome, DeviceError> {
        let (outcome, _draws) = self.emit_with_rng_draws(frame, rng, policy)?;
        Ok(outcome)
    }

    /// Resolves one emitted frame from the seeded RNG and returns the consumed draws.
    ///
    /// This is the recording-friendly twin of [`NetLink::emit_from_rng`]: it
    /// draws the frame's [`FrameDraws`] from `rng`, resolves the frame through
    /// [`NetLink::emit`], advances [`NetLink::rng_position`], and returns both the
    /// [`ResolveOutcome`] and the raw draws. The engine uses this to record the
    /// same draw stream as engine `RngDraw` decisions without re-deriving link
    /// effect choices from the final payload.
    ///
    /// # Errors
    ///
    /// Same as [`NetLink::emit`].
    pub fn emit_with_rng_draws(
        &mut self,
        frame: &Frame,
        rng: &mut DeviceRng,
        policy: PastDeliveryPolicy,
    ) -> Result<(ResolveOutcome, FrameDraws), DeviceError> {
        let draws = FrameDraws::from_rng_for_faults(rng, &self.faults);
        let outcome = self.emit(frame, &draws, policy)?;
        self.rng_position = rng.position();
        Ok((outcome, draws))
    }

    /// Builds a seeded RNG positioned at this link's captured cursor ([IO-23]).
    ///
    /// Forks the link stream by name-hash from the engine's decision-RNG
    /// `root_seed` in `domain` for `name` ([DET-25]) and resumes it at the
    /// captured cursor, so the returned RNG's next draw is byte-identical to the
    /// uninterrupted run's. The caller supplies the engine root seed and the
    /// link's stable stream domain and name (the engine owns the name-hash).
    #[must_use]
    pub fn rng(&self, root_seed: u64, domain: &str, name: &str) -> DeviceRng {
        DeviceRng::restore(root_seed, domain, name, self.rng_position)
    }

    /// Enforces that a delivery icount is in the consumer's strict future ([IO-34]).
    ///
    /// A delivery at or before the current frontier can never be made visible at
    /// its exact icount; per `policy` the link either fails loudly or clamps up to
    /// `frontier + 1`. Never silently delivers late.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::DeliveryReorderedIntoPast`] when `policy` is
    /// [`PastDeliveryPolicy::FailLoud`] and the delivery is not strictly in the
    /// future.
    pub(super) fn guard_future(
        &self,
        delivery_icount: u64,
        policy: PastDeliveryPolicy,
    ) -> Result<u64, DeviceError> {
        let frontier = self.clock.current_icount();
        if delivery_icount > frontier {
            return Ok(delivery_icount);
        }
        match policy {
            PastDeliveryPolicy::FailLoud => Err(DeviceError::DeliveryReorderedIntoPast {
                delivery_icount,
                consumer_frontier: frontier,
            }),
            // Clamp to the next deliverable future icount. `frontier` is below
            // u64::MAX in any real run; saturating keeps it total.
            PastDeliveryPolicy::ClampToFuture => Ok(frontier.saturating_add(1)),
        }
    }

    /// Inserts one delivery into the in-flight queue and returns it.
    ///
    /// Assigns the next per-frame sequence number so coincident deliveries break
    /// ties deterministically by `(delivery_icount, src_node, seq)`. The delivery
    /// is carried as a [`PendingResponse`] over the reused in-flight machinery;
    /// the [`Response`] payload is the (possibly corrupted) frame bytes.
    pub(super) fn enqueue_delivery(
        &mut self,
        delivery_icount: u64,
        frame_id: u32,
        payload: Vec<u8>,
    ) -> Delivery {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let key = FrameDeliveryKey {
            delivery_icount,
            src_node: self.src_node,
            seq,
        };
        let response = Response::new(frame_id, ResponseStatus::Ok, payload.clone());
        self.inflight.insert(PendingResponse::new(key, response));
        Delivery {
            key,
            frame_id,
            payload,
        }
    }
}
