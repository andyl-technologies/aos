//! Produces the one Cache Held pair using the same initialized and J originals.
//!
//! The body contains only preappend facts. Returned CommitResult, exact native
//! suffix/readback and later Root exchange remain in distinct retained owners.

use super::*;
use aos_sandbox_protocol::cache_state::NodeCacheQuotaV1;

impl<'cache> OriginalCreateStorageCacheLoanV1<'cache> {
    /// Captures, prices and appends the new Held pair exactly once.
    ///
    /// # Errors
    /// Retains the actual J admissions, source association, selection, native
    /// results and independent posts. Failure leaves the original loan armed;
    /// its enclosing retained continuation must not dispose or replace it.
    pub(crate) fn produce_held_once(
        &mut self,
        original: &mut CreateStorageOriginalLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.progress.producing || self.progress.first.is_some() {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.producing = true;
        let fixed = original.admit_cache_fixed_once(self);
        self.progress.payment[0] = Some(fixed);
        self.progress.mark(matches!(self.progress.payment[0], Some(Err(_))), Failure::Payment(0));
        if self.progress.first.is_some() { return Err(CacheHeldClosedV1); }

        let capture = original.admit_cache_capture(self);
        self.progress.payment[1] = Some(capture);
        self.progress.mark(matches!(self.progress.payment[1], Some(Err(_))), Failure::Payment(1));
        if self.progress.first.is_some() {
            if self.progress.posts[0].is_none() { self.observe_posts_once(0); }
            return Err(CacheHeldClosedV1);
        }

        self.progress.source = Some((|| {
            let lane = original.create_storage_lane_v1()?;
            Ok(original.source_held_data_v1()?.encode(lane)?)
        })());
        self.progress.mark(matches!(self.progress.source, Some(Err(_))), Failure::Source);
        self.join_once(original, 0);
        if self.progress.first.is_none() {
            self.audit_set(original, 0);
        }
        if self.progress.first.is_none() {
            self.capture_selection_once(original);
        }
        if self.progress.posts[0].is_none() { self.observe_posts_once(0); }
        if self.progress.first.is_some() { return Err(CacheHeldClosedV1); }

        self.encode_pair_once(original);
        if self.progress.first.is_none() { self.admit_append_once(original); }
        if self.progress.first.is_none() { self.append_pair_once(original); }
        if self.progress.first.is_none() {
            self.capture_returned_pair_once();
        }
        if self.progress.first.is_none() { self.audit_set(original, 5); }
        self.observe_posts_once(1);
        self.join_once(original, 3);
        if self.progress.first.is_some() { return Err(CacheHeldClosedV1); }
        self.held_receipt_data_v1().map(|_| ())
    }

    /// Borrows the actual completed Held stage while all originals stay armed.
    ///
    /// # Errors
    /// Refuses an incomplete/failed Held append, native audits or original posts.
    /// This borrow cannot release the barrier or stand in for a Root terminal.
    pub(crate) fn borrow_pre_root_cut_v1(&mut self)
        -> Result<CacheHeldPreRootCutV1<'_, 'cache>, CacheHeldClosedV1>
    {
        self.require_pre_root_cut_v1()?;
        Ok(CacheHeldPreRootCutV1 { original: self })
    }

    /// Borrows quota comparison rows without taking another mutable cut.
    ///
    /// The already-armed original remains held while its exact retained rows
    /// are borrowed beside the Ready owner's other immutable B components.
    /// This performs no IO, replay, allocation or encoding.
    ///
    /// # Errors
    /// Refuses incomplete Held/audit/payment/posts, later debt, Root entry or
    /// an absent/failed original selection. No new receiving loan is issued.
    pub(crate) fn node_quotas_for_bundle_v1(
        &self,
    ) -> Result<&[NodeCacheQuotaV1], CacheHeldClosedV1> {
        self.require_pre_root_cut_v1()?;
        let selection = self.progress.selection.as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        Ok(selection.node_quotas())
    }

    pub(super) fn require_pre_root_cut_v1(&self) -> Result<(), CacheHeldClosedV1> {
        if self.progress.first.is_some() || self.progress.audit_next != 10
            || !matches!(self.progress.append, Some(Ok(_)))
            || self.progress.joins[..4].iter().any(|result| !matches!(result, Some(Ok(()))))
            || !matches!(self.progress.payment, [Some(Ok(())), Some(Ok(()))])
            || self.progress.root.is_some() || self.progress.finished
        {
            return Err(CacheHeldClosedV1);
        }
        self.held_receipt_data_v1()?;
        Ok(())
    }

    fn join_once(&mut self, original: &mut CreateStorageOriginalLoanV1<'_>, index: usize) {
        if self.progress.joins[index].is_some() {
            self.progress.refuse();
            return;
        }
        self.progress.currentness_site = Some(match index {
            0 => CacheHeldCurrentnessSiteV1::BeforeCapture,
            1 => CacheHeldCurrentnessSiteV1::Transition,
            2 => CacheHeldCurrentnessSiteV1::FinalCrossing,
            3 => CacheHeldCurrentnessSiteV1::AfterAppend,
            4 => CacheHeldCurrentnessSiteV1::AfterRoot,
            _ => { self.progress.refuse(); return; }
        });
        let returned = original.require_cache_capture_current(self);
        self.progress.joins[index] = Some(returned);
        self.progress.mark(matches!(self.progress.joins[index], Some(Err(_))), Failure::Join(index));
    }

    fn audit_set(&mut self, original: &mut CreateStorageOriginalLoanV1<'_>, first: usize) {
        for index in first..first + 5 {
            if self.audit_once(original, index).is_err() { break; }
        }
    }

    fn capture_selection_once(&mut self, original: &CreateStorageOriginalLoanV1<'_>) {
        self.progress.selection = Some((|| {
            let source = self.source_held_bytes_v1().map_err(|_| CacheHeldErrorV1::Order)?;
            let body = SourceHeldReceiptDataV1::decode(source, original.create_storage_lane_v1()?)?
                .body(original.create_storage_lane_v1()?)?;
            let clock = self.originals.clock.as_ref().ok_or(CacheHeldErrorV1::Order)?;
            let hold = self.originals.hold.as_deref_mut().ok_or(CacheHeldErrorV1::Order)?;
            if self.progress.audit_next != 5 {
                return Err(CacheHeldErrorV1::Order);
            }
            let shape = self.progress.shape.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let mut selection_original = CacheHeldSelectionOriginalV1 {
                q04: self.originals.q04,
                original_hold: self.originals.original_hold,
                hold,
                writers: &shape.writers,
                audits: &self.progress.audits,
                comparison: &mut self.progress.selection_original,
            };
            let selection = self.originals.authority.capture_create_storage_selection_v1(
                self.originals.state, &mut selection_original, clock,
                aos_sandbox_model::ProjectId::from_bytes(body.project),
            )?;
            selection.require_physical_limits(self.originals.physical.limits())?;
            Ok(selection)
        })());
        self.progress.mark(matches!(self.progress.selection, Some(Err(_))), Failure::Selection);
    }

    fn encode_pair_once(&mut self, original: &CreateStorageOriginalLoanV1<'_>) {
        self.progress.body = Some((|| {
            let lane = original.create_storage_lane_v1()?;
            let (association, source_held) = {
                let receipt = SourceHeldReceiptDataV1::decode(
                    self.source_held_bytes_v1().map_err(|_| CacheHeldErrorV1::Order)?, lane,
                )?;
                let source = receipt.body(lane)?;
                let envelope = RecordEnvelopeV1::decode(receipt.record,
                    KeyV1::new(lane, OwnerV1::Source, 1)?, PhaseV1::new(OwnerV1::Source, 1)?)?;
                // Copy only fixed comparison fields before the disjoint
                // physical destination is mutably borrowed. The actual
                // Source receipt and all originals remain resident unchanged.
                (source.association(), envelope.checksum())
            };
            let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let selection = self.progress.selection.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let identity = self.originals.physical_identity.ok_or(CacheHeldErrorV1::Order)?;
            let snapshot = self.originals.physical.capture_create_storage_physical_once(
                &mut self.progress.body_physical, Some(identity))?;
            let (physical, [disk_count, negative_count, pin_count]) = snapshot.create_storage_physical_data_v1()?;
            let clock = self.originals.clock_owner.state.lock().map_err(|_| CacheHeldErrorV1::Order)?;
            let clock_floor = clock.floor.observed_unix_seconds;
            drop(clock);
            let [bootstrap, hold, state, authority, clock] = shape.writers.each_ref().map(|writer| writer.coordinates);
            Ok(CacheHeldBodyDataV1 {
                association, source_held,
                bootstrap, hold, state, authority, clock, physical,
                selected_partition: *selection.selected().partition().digest().as_bytes(),
                selected_head: *selection.selected().head().as_bytes(), quota: *selection.quota().as_bytes(),
                disk_count, negative_count, pin_count, clock_floor,
            })
        })());
        self.progress.mark(matches!(self.progress.body, Some(Err(_))), Failure::Encoding);
        if self.progress.first.is_some() { return; }
        self.progress.encoded_body = Some((|| {
            let body = self.progress.body.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            Ok(body.encode()?)
        })());
        self.progress.mark(matches!(self.progress.encoded_body, Some(Err(_))), Failure::Encoding);
        if self.progress.first.is_some() { return; }
        self.progress.checksum = Some((|| {
            let lane = original.create_storage_lane_v1()?;
            let body = self.progress.body.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let encoded = self.progress.encoded_body.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
                key: KeyV1::new(lane, OwnerV1::Cache, 1)?, phase: PhaseV1::new(OwnerV1::Cache, 1)?,
                predecessor: [0; 32], correlation: body.association.seed,
            }, encoded, &mut self.progress.record)?;
            self.progress.head = LatestHeadV1::new(1, checksum)?.encode();
            Ok(checksum)
        })());
        self.progress.mark(matches!(self.progress.checksum, Some(Err(_))), Failure::Encoding);
        if self.progress.first.is_some() { return; }
        self.progress.transaction = Some((|| {
            let lane = original.create_storage_lane_v1()?;
            Ok(Arc::new(prepare_history_pair_v1(KeyV1::new(lane, OwnerV1::Cache, 1)?,
                PhaseV1::new(OwnerV1::Cache, 1)?, &self.progress.record, &self.progress.head)?))
        })());
        self.progress.mark(matches!(self.progress.transaction, Some(Err(_))), Failure::Transaction);
    }

    fn admit_append_once(&mut self, original: &mut CreateStorageOriginalLoanV1<'_>) {
        self.progress.append_geometry = Some((|| {
            let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let complete = shape.complete_base();
            let transaction = self.progress.transaction.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let hold = self.originals.hold.as_deref().ok_or(JournalError::ProtectedBoundary)?;
            complete.checked_add(hold.cache_held_append_semantic_demand_v1(transaction)?)
                .map_err(|_| JournalError::LimitExceeded("Cache Held append semantic geometry"))
        })());
        self.progress.mark(matches!(self.progress.append_geometry, Some(Err(_))), Failure::AppendGeometry);
        if let Some(Ok(complete)) = self.progress.append_geometry.as_ref() {
            let shape = CacheHeldNativeSemanticShapeV1 { identity: self.identity, complete: *complete };
            self.progress.append_admission = Some(original.admit_cache_semantic_shape(&shape));
            self.progress.mark(matches!(self.progress.append_admission, Some(Err(_))), Failure::AppendGeometry);
        }
    }

    fn append_pair_once(&mut self, original: &mut CreateStorageOriginalLoanV1<'_>) {
        // Move only the mutable reference. The actual writer and expected
        // transaction remain resident; the loan's unwind fence stays armed.
        let Some(hold) = self.originals.hold.take() else {
            self.progress.refuse();
            return;
        };
        let transaction = self.progress.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .map(Arc::clone);
        let returned = match transaction.as_ref() {
            Some(transaction) => {
                let mut crossing = CacheHeldAppendLoanV1 { cache: self, original };
                hold.commit_create_storage_cache_held_v1(transaction, &mut crossing)
            }
            None => Err(JournalError::ProtectedBoundary),
        };
        self.originals.hold = Some(hold);
        self.progress.append = Some(returned);
        self.progress.mark(matches!(self.progress.append, Some(Err(_))), Failure::Append);
    }

    fn capture_returned_pair_once(&mut self) {
        self.progress.readback = Some((|| {
            let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let transaction = self.progress.transaction.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let committed = self.progress.append.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let hold = self.originals.hold.as_deref().ok_or(CacheHeldErrorV1::Order)?;
            let observed = readback_history_pair_v1(hold, transaction, &self.progress.record,
                &self.progress.head, shape.writers[1].coordinates.next, committed)?;
            let after = hold.capture_cache_held_shape_v1(&mut self.progress.after_hold_position, InitializerJournal::Hold, self.originals.uid)?;
            let before = shape.writers[1].coordinates;
            if after.coordinates.names != before.names || after.coordinates.next != observed.next
                || after.coordinates.end != before.end.checked_add(receiving::append_bytes()?).ok_or(CacheHeldErrorV1::Order)?
                || committed.durable_bytes != after.coordinates.end
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            self.progress.after_hold = Some(Ok(after));
            Ok(observed)
        })());
        self.progress.mark(matches!(self.progress.readback, Some(Err(_))), Failure::Readback);
    }
}

impl CacheHeldAppendLoanV1<'_, '_, '_> {
    /// Checks the sole exact pair under the same actual J/Cache originals.
    ///
    /// # Errors
    /// Refuses substitution, reentry or retained original/payment/post debt.
    pub(crate) fn require_transition(
        &mut self,
        target: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.crossing_once(target, Some(transaction), 0, 1)
    }

    /// Rejoins the genuine originals immediately before the existing appender.
    ///
    /// # Errors
    /// Refuses changed originals or any earlier or independently observed debt.
    pub(crate) fn final_crossing(&mut self, target: &Journal) -> Result<(), JournalError> {
        self.crossing_once(target, None, 1, 2)
    }

    fn crossing_once(
        &mut self,
        target: &Journal,
        transaction: Option<&JournalTransaction>,
        index: usize,
        join: usize,
    ) -> Result<(), JournalError> {
        if self.cache.progress.crossing[index].is_some() || self.cache.progress.first.is_some() {
            self.cache.progress.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        self.cache.progress.crossing[index] = Some((|| {
            let shape = self.cache.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            shape.writers[1].require(target)?;
            target.require_no_cache_held_history_v1()?;
            if let Some(transaction) = transaction {
                let body = self.cache.progress.body.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(CacheHeldErrorV1::Order)?;
                let prepared = self.cache.progress.transaction.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(CacheHeldErrorV1::Order)?;
                if prepared.as_ref() != transaction || body.hold != shape.writers[1].coordinates {
                    return Err(CacheHeldErrorV1::Order);
                }
            }
            Ok(())
        })());
        self.cache.progress.mark(matches!(self.cache.progress.crossing[index], Some(Err(_))), Failure::Crossing);
        let posts = audit::observe_bookends(&mut self.cache.originals, self.cache.progress, Some(target));
        self.cache.progress.mark(posts.failure().is_some(), Failure::Crossing);
        self.cache.progress.crossing_posts[index] = Some(posts);
        self.cache.join_once(self.original, join);
        if self.cache.progress.first.is_some() { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }
}
