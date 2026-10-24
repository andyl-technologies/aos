//! Retains native Held selection, encoding, geometry and returned pair DATA.
//!
//! Actual J admission and Controller/Source/Root orchestration remain upper.
//! These finite methods use only the same privately borrowed Cache originals;
//! their owning results stay resident before any independent upper posts.

use super::*;
use aos_sandbox_protocol::cache_state::NodeCacheQuotaV1;

impl OriginalCreateStorageCacheLoanV1<'_> {
    /// Arms the actual native Held producer once before any effect.
    ///
    /// # Errors
    /// Refuses reentry and earlier native debt.
    pub fn begin_production_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        if self.progress.producing || self.progress.first.is_some() {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.producing = true;
        Ok(())
    }

    /// Encodes the actual upper Source's borrowed receipt in its original slot.
    ///
    /// The actual Controller/Source original retains semantic authority. This
    /// performs only the same canonical encoding before its existing upper
    /// join, without another owning 508-byte forwarding representation.
    ///
    /// # Errors
    /// Retains the original canonical encoding failure and refuses reentry.
    pub fn capture_source_held_data_once_v1(
        &mut self,
        receipt: SourceHeldReceiptDataV1<'_>,
        lane: [u8; 16],
    ) -> Result<(), CacheHeldClosedV1> {
        if !self.progress.producing || self.progress.source.is_some() || self.progress.first.is_some() {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.source = Some(receipt.encode(lane).map_err(CacheHeldErrorV1::from));
        self.progress.mark(matches!(self.progress.source, Some(Err(_))), Failure::Source);
        if self.progress.first.is_some() {
            Err(CacheHeldClosedV1)
        } else {
            Ok(())
        }
    }

    /// Borrows the original exact prepared transaction without lending a writer.
    ///
    /// # Errors
    /// Refuses incomplete encoding or earlier native debt.
    pub fn append_transaction_data_v1(&self) -> Result<&Arc<JournalTransaction>, CacheHeldClosedV1> {
        if self.progress.first.is_some() {
            return Err(CacheHeldClosedV1);
        }
        self.progress.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CacheHeldClosedV1)
    }

    /// Borrows quota rows retained by the actual native Held selection.
    ///
    /// # Errors
    /// Refuses an incomplete native append, audit or original post.
    pub fn node_quotas_for_bundle_v1(&self) -> Result<&[NodeCacheQuotaV1], CacheHeldClosedV1> {
        self.require_pre_root_cut_v1()?;
        self.progress.selection.as_ref().and_then(|value| value.as_ref().ok())
            .map(CacheHeldSelectionV1::node_quotas).ok_or(CacheHeldClosedV1)
    }

    pub(super) fn require_pre_root_cut_v1(&self) -> Result<(), CacheHeldClosedV1> {
        if self.progress.first.is_some() || self.progress.audit_next != 10
            || !matches!(self.progress.append, Some(Ok(_)))
            || self.progress.finished
        {
            return Err(CacheHeldClosedV1);
        }
        self.held_receipt_data_v1()?;
        Ok(())
    }


    pub fn capture_selection_once_v1(&mut self, lane: [u8; 16]) {
        self.progress.selection = Some((|| {
            let source = self.source_held_bytes_v1().map_err(|_| CacheHeldErrorV1::Order)?;
            let body = SourceHeldReceiptDataV1::decode(source, lane)?
                .body(lane)?;
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

    pub fn encode_pair_once_v1(&mut self, lane: [u8; 16]) {
        self.progress.body = Some((|| {
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
            let clock_floor = self.originals.clock_owner.create_storage_floor_data_v1()?;
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
            Ok(Arc::new(prepare_history_pair_v1(KeyV1::new(lane, OwnerV1::Cache, 1)?,
                PhaseV1::new(OwnerV1::Cache, 1)?, &self.progress.record, &self.progress.head).map_err(|cause| match cause {
                    aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1::Envelope =>
                        JournalError::boundary(),
                    aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1::Transaction(cause) =>
                        JournalError::from(cause),
                })?))
        })());
        self.progress.mark(matches!(self.progress.transaction, Some(Err(_))), Failure::Transaction);
    }

    pub fn admit_append_once_v1(
        &mut self,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) {
        self.progress.append_geometry = Some((|| {
            let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::boundary())?;
            let complete = shape.complete_base();
            let transaction = self.progress.transaction.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::boundary())?;
            let hold = self.originals.hold.as_deref().ok_or(JournalError::boundary())?;
            complete.checked_add(hold.cache_held_append_semantic_demand_v1(transaction)?)
                .map_err(|_| JournalError::limit_exceeded("Cache Held append semantic geometry"))
        })());
        self.progress.mark(matches!(self.progress.append_geometry, Some(Err(_))), Failure::AppendGeometry);
        if let Some(Ok(complete)) = self.progress.append_geometry.as_ref() {
            let shape = CacheHeldNativeSemanticShapeV1 { identity: self.identity, complete: *complete };
            self.progress.append_admission = Some(funding.admit_complete_v1(shape.identity, shape.complete));
            self.progress.mark(matches!(self.progress.append_admission, Some(Err(_))), Failure::AppendGeometry);
        }
    }

    pub fn capture_returned_pair_once_v1(&mut self) {
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
                return Err(JournalError::stale_snapshot().into());
            }
            self.progress.after_hold = Some(Ok(after));
            Ok(observed)
        })());
        self.progress.mark(matches!(self.progress.readback, Some(Err(_))), Failure::Readback);
    }
}


/// Carries privately derived native append demand to the genuine funding loan.
pub struct CacheHeldNativeSemanticShapeV1 {
    identity: CacheHeldIdentityDataV1,
    complete: ResourceVector,
}

impl CacheHeldNativeSemanticShapeV1 {
    /// Returns comparison DATA from the original private shape.
    pub fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 {
        self.identity
    }

    /// Returns the privately computed complete actual demand.
    ///
    /// # Errors
    /// The constructor retains checked arithmetic failure before this exists.
    pub fn dominant_receiving_demand_v1(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        Ok(self.complete)
    }
}


impl<'cache> OriginalCreateStorageCacheLoanV1<'cache> {
    /// Binds the same real J to this privately captured native Cache shape.
    ///
    /// The returned loan borrows the original retained Controller association;
    /// it creates no account and performs no new initial debit. The actual
    /// upper J has already admitted this exact shape on its CacheHeld highwater.
    ///
    /// # Errors
    /// Preserves actual Controller, Source, profile and paid-bound refusal.
    pub fn bind_initial_audit_funding_v1<'funding, 'profile>(
        &self,
        original: aos_sandbox_broker::controller_receiving::bank_launch::
            ControllerCreateContinuationFundingLoanV1<'funding, 'profile>,
        source: &'funding ControllerSourceOriginalRefV1,
    ) -> Result<
        ControllerCacheAuditFundingLoanV1<'funding, 'profile>,
        ControllerCacheAuditFundingErrorV1,
    >
    where
        'cache: 'funding,
    {
        let construction: &'cache super::super::baseline::CacheConstructionOriginalsV1 =
            self.originals.construction;
        let shape = self.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(aos_sandbox_broker::controller_receiving::bank_launch::
                ControllerBankLaunchErrorV1::Conflict)?;
        construction.bind_initial_audit_funding_v1(
            original, source, self.identity, shape.complete_base(),
        )
    }

    /// Borrows the genuine native pre-Root cut after its actual native posts.
    ///
    /// The upper programme separately requires its real J admissions and
    /// original Controller/Source observations before borrowing this DATA view.
    ///
    /// # Errors
    /// Refuses any incomplete native append/readback/audit or later native debt.
    pub fn borrow_pre_root_cut_v1(&mut self) -> Result<CacheHeldPreRootCutV1<'_, 'cache>, CacheHeldClosedV1> {
        self.require_pre_root_cut_v1()?;
        Ok(CacheHeldPreRootCutV1 { original: self })
    }
}


impl OriginalCreateStorageCacheLoanV1<'_> {
    /// Prices the two native binding frames of the actual initial-J handoff.
    ///
    /// This is memory-only representation DATA, not an account or admission.
    #[must_use]
    pub fn initial_audit_funding_receiving_bytes_v1() -> Option<usize> {
        type Original<'funding, 'profile> =
            aos_sandbox_broker::controller_receiving::bank_launch::
                ControllerCreateContinuationFundingLoanV1<'funding, 'profile>;
        type Funding<'funding, 'profile> =
            ControllerCacheAuditFundingLoanV1<'funding, 'profile>;
        let baseline = std::mem::size_of::<(
            &super::super::baseline::CacheConstructionOriginalsV1,
            Original<'_, '_>,
            &ControllerSourceOriginalRefV1,
            CacheHeldIdentityDataV1,
            ResourceVector,
            Result<Funding<'_, '_>, ControllerCacheAuditFundingErrorV1>,
        )>();
        let original = std::mem::size_of::<(
            &Self,
            Original<'_, '_>,
            &ControllerSourceOriginalRefV1,
            Result<Funding<'_, '_>, ControllerCacheAuditFundingErrorV1>,
        )>();
        baseline.checked_add(original)
    }

    /// Runs the exact next five native audits under the same genuine J.
    ///
    /// # Errors
    /// Retains every actual parser/funding/native/post cause and refuses a
    /// skipped or repeated roster. Positive disposal precedes each peak reuse.
    pub fn audit_initial_set_once_v1(
        &mut self,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
        first: usize,
    ) -> Result<(), CacheHeldClosedV1> {
        if !matches!(first, 0 | 5 | 10) {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        for index in first..first + 5 {
            self.audit_once(funding, index)?;
        }
        Ok(())
    }

    /// Reports whether an original independent post set was already entered.
    #[must_use]
    pub fn original_post_observed_data_v1(&self, site: CacheHeldPostSiteV1) -> bool {
        self.progress.posts[site.index()].is_some()
    }

    /// Observes the same independently owed native original post set once.
    ///
    /// # Errors
    /// Retains native debt and refuses a repeated set without suppressing the
    /// original first observation or replacing any earlier native cause.
    pub fn observe_original_posts_once_v1(
        &mut self,
        site: CacheHeldPostSiteV1,
    ) -> Result<(), CacheHeldClosedV1> {
        self.observe_posts_once(site.index());
        if self.progress.first.is_some() {
            Err(CacheHeldClosedV1)
        } else {
            Ok(())
        }
    }

    /// Selects one actual upper currentness frontier without issuing permission.
    ///
    /// This changes only a comparison label on the same already borrowed
    /// original. It grants no native append stage or Root phase.
    pub fn select_currentness_site_v1(&mut self, site: CacheHeldCurrentnessSiteV1) {
        self.progress.currentness_site = Some(site);
    }
}

/// Names the three independently owed outer native post sets.
#[derive(Clone, Copy)]
pub enum CacheHeldPostSiteV1 {
    /// Follows initial capture, readback and selection.
    Capture,
    /// Follows the Held append and its returned-prefix audits.
    Append,
    /// Follows the actual upper Root exchange.
    Root,
}

impl CacheHeldPostSiteV1 {
    const fn index(self) -> usize {
        match self {
            Self::Capture => 0,
            Self::Append => 1,
            Self::Root => 2,
        }
    }
}
