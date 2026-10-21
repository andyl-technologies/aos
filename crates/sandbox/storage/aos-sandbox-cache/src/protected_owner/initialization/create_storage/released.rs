//! Retains the same Hold writer's native Released stages and terminal audits.
//!
//! The upper programme keeps actual U, Root, Source, Controller and paired-clock
//! observations. This owner keeps the original five writers, exact pair bytes,
//! shape, append result, failed reader and independently owed native bookends.

use super::*;
use aos_sandbox_model::ResourceDimension as D;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KEY_BYTES,
    continuation::ContinuationNativeReceiptDataV1,
    outcome::{RELEASED_BODY_BYTES_V1, RELEASED_RECORD_BYTES_V1, ReleasedBodyDataV1},
};

/// Keeps every actual native Released result around the same initialized Cache.
#[derive(Default)]
pub struct CacheReleasedOriginalsV1 {
    pub(super) entered: bool,
    pub(super) entry: Option<Result<(), CacheHeldErrorV1>>,
    pub(super) shape: Option<Result<CacheReleasedShapeV1, CacheHeldErrorV1>>,
    pub(super) before: Option<audit::CacheHeldBookendsV1>,
    pub(super) body: Option<Result<[u8; RELEASED_BODY_BYTES_V1], CacheHeldErrorV1>>,
    pub(super) record: Option<Result<[u8; RELEASED_RECORD_BYTES_V1], CacheHeldErrorV1>>,
    pub(super) head: Option<[u8; HEAD_BYTES]>,
    pub(super) lane: Option<[u8; 16]>,
    pub(super) transaction: Option<Result<Arc<JournalTransaction>, CacheHeldErrorV1>>,
    pub(super) crossing: [Option<Result<(), CacheHeldErrorV1>>; 2],
    pub(super) crossing_posts: [Option<audit::CacheHeldBookendsV1>; 2],
    pub(super) original: Option<Result<(), ControllerCacheAuditFundingErrorV1>>,
    pub(super) append_geometry: Option<Result<ResourceVector, JournalError>>,
    pub(super) append_funding: Option<Result<(), ControllerCacheAuditFundingErrorV1>>,
    pub(super) append: Option<Result<CommitResult, JournalError>>,
    pub(super) readback:
        Option<Result<HistoryPairReadbackDataV1<RELEASED_RECORD_BYTES_V1>, CacheHeldErrorV1>>,
    pub(super) after_hold_position: crate::journal::CreateStorageWriterPositionOriginalV1,
    pub(super) after_hold: Option<Result<CacheHeldWriterShapeV1, CacheHeldErrorV1>>,
    pub(super) after: Option<audit::CacheHeldBookendsV1>,
    pub(super) audit_returned: Option<Result<(), CacheHeldClosedV1>>,
    pub(super) failed_audit: Option<audit::CacheHeldAuditV1>,
    pub(super) refused: bool,
    pub(super) complete: bool,
}

/// Describes the actual bounded post-release five-reader demand.
#[derive(Clone, Copy)]
pub struct CacheReleasedShapeV1 {
    identity: CacheHeldIdentityDataV1,
    extents: [crate::journal::ProtectedJournalPreopenReplayExtentV1; 5],
    semantic_peak: ResourceVector,
    semantic_supplement: ResourceVector,
    complete: ResourceVector,
}

impl PartialEq for CacheReleasedShapeV1 {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.semantic_peak == other.semantic_peak
            && self.semantic_supplement == other.semantic_supplement
            && self.complete == other.complete
            && self
                .extents
                .iter()
                .zip(&other.extents)
                .all(|(left, right)| {
                    left.limits() == right.limits() && left.native_bytes() == right.native_bytes()
                })
    }
}

impl Eq for CacheReleasedShapeV1 {}

impl CacheReleasedShapeV1 {
    /// Returns same-original comparison DATA without creating a lender.
    pub fn identity_v1(&self) -> CacheHeldIdentityDataV1 {
        self.identity
    }

    /// Returns the complete passive receiving quote.
    pub fn complete_receiving_demand_v1(&self) -> ResourceVector {
        self.complete
    }

    /// Returns the actual five-prefix sequential semantic peak.
    pub fn semantic_peak_v1(&self) -> ResourceVector {
        self.semantic_peak
    }
}

impl CacheReleasedOriginalsV1 {
    /// Borrows the original captured passive release forecast.
    ///
    /// # Errors
    /// Refuses an absent or failed native forecast.
    pub fn shape_v1(&self) -> Result<&CacheReleasedShapeV1, CacheHeldClosedV1> {
        self.shape
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)
    }

    /// Reports whether the actual once-only native entry was reached.
    pub fn started(&self) -> bool {
        self.entered
    }

    /// Borrows the actual first native cause while failed owners stay resident.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.entry)
            .or_else(|| error(&self.shape))
            .or_else(|| {
                self.before
                    .as_ref()
                    .and_then(audit::CacheHeldBookendsV1::failure)
            })
            .or_else(|| error(&self.body))
            .or_else(|| error(&self.record))
            .or_else(|| error(&self.transaction))
            .or_else(|| error(&self.append_geometry))
            .or_else(|| error(&self.append_funding))
            .or_else(|| error(&self.original))
            .or_else(|| error(&self.crossing[0]))
            .or_else(|| {
                self.crossing_posts[0]
                    .as_ref()
                    .and_then(audit::CacheHeldBookendsV1::failure)
            })
            .or_else(|| error(&self.crossing[1]))
            .or_else(|| {
                self.crossing_posts[1]
                    .as_ref()
                    .and_then(audit::CacheHeldBookendsV1::failure)
            })
            .or_else(|| error(&self.append))
            .or_else(|| error(&self.readback))
            .or_else(|| self.after_hold_position.failure())
            .or_else(|| error(&self.after_hold))
            .or_else(|| {
                self.after
                    .as_ref()
                    .and_then(audit::CacheHeldBookendsV1::failure)
            })
            .or_else(|| {
                self.failed_audit
                    .as_ref()
                    .and_then(audit::CacheHeldAuditV1::failure)
            })
            .or_else(|| error(&self.audit_returned))
    }

    /// Returns the actual funding selection after positive geometry.
    pub fn append_funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.append_geometry, Some(Ok(_))) && matches!(self.append_funding, Some(Err(_)))
    }

    /// Returns the native receipt only after every real terminal audit passed.
    ///
    /// # Errors
    /// Refuses incomplete stages or retained native/upper debt.
    pub fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, CacheHeldClosedV1> {
        if !self.complete || self.refused || self.failure().is_some() {
            return Err(CacheHeldClosedV1);
        }
        let observed = self
            .readback
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let shape = self
            .after_hold
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        Ok(ContinuationNativeReceiptDataV1 {
            record: &observed.record,
            latest_head: observed.head,
            names: shape.coordinates.names,
            after_next: observed.next,
            after_end: shape.coordinates.end,
        })
    }

    /// Returns the completed native original's comparison identity.
    ///
    /// # Errors
    /// Refuses an incomplete or failed native Released stage.
    pub fn identity_v1(&self) -> Result<CacheHeldIdentityDataV1, CacheHeldClosedV1> {
        self.receipt_v1()?;
        self.shape
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|shape| shape.identity)
            .ok_or(CacheHeldClosedV1)
    }

    /// Permanently fences later native continuation after an upper refusal.
    pub fn reject_upper_once_v1(&mut self) {
        self.refused = true;
    }

    pub(super) fn positive(&self) -> Result<(), CacheHeldClosedV1> {
        if self.refused || self.failure().is_some() {
            Err(CacheHeldClosedV1)
        } else {
            Ok(())
        }
    }
}

/// Prices the exact two canonical Released records' durable append bytes.
///
/// # Errors
/// Rejects checked encoded-record arithmetic overflow.
pub fn release_append_bytes_v1() -> Result<u64, CacheHeldErrorV1> {
    aos_sandbox_journal::geometry::encoded_transaction_append_bytes(
        [
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: KEY_BYTES,
                value_bytes: Some(RELEASED_RECORD_BYTES_V1),
            },
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: KEY_BYTES,
                value_bytes: Some(HEAD_BYTES),
            },
        ]
        .into_iter(),
    )
    .map_err(|_| CacheHeldErrorV1::Order)
}

/// Prices the actual native Released resident, append and sequential readers.
///
/// # Errors
/// Rejects an over-limit native prefix or checked demand arithmetic overflow.
pub fn release_receiving_demand_v1(
    extents: &[crate::journal::ProtectedJournalPreopenReplayExtentV1; 5],
    upper_fixed: Option<ResourceVector>,
    semantic_supplement: Option<ResourceVector>,
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let append = release_append_bytes_v1()?;
    let mut after = *extents;
    after[1] = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        extents[1].limits(),
        extents[1]
            .native_bytes()
            .checked_add(append)
            .ok_or(CacheHeldErrorV1::Order)?,
    )?;
    let bytes = std::mem::size_of::<CacheReleasedOriginalsV1>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::align_of::<CacheReleasedOriginalsV1>()))
        .and_then(|bytes| {
            bytes.checked_add(CacheHeldAppendContextV1::receiving_construction_bytes_v1()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                crate::journal::readonly_receiving::full_prefix_peak_control_bytes_v1()?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<(
                    [Option<ResourceVector>; 4],
                    Result<CacheReleasedShapeV1, CacheHeldErrorV1>,
                    [Result<ResourceVector, CacheHeldErrorV1>; 2],
                )>()
                .checked_mul(2)?,
            )
        })
        .ok_or(CacheHeldErrorV1::Order)?;
    // Keep the original upper clock/fixed quote after native extent/owner
    // geometry and before framing or the native/full-semantic peak recipes.
    let upper_fixed = upper_fixed.ok_or(JournalError::DeferredUpperFixedQuote)?;
    let framing = usize::try_from(append)
        .ok()
        .and_then(|bytes| bytes.checked_add(KEY_BYTES * 2 + RELEASED_RECORD_BYTES_V1 + HEAD_BYTES))
        .and_then(|bytes| bytes.checked_add(7 + KEY_BYTES + RELEASED_RECORD_BYTES_V1))
        .and_then(|bytes| bytes.checked_add(aos_sandbox_journal::framing::COMMIT_PAYLOAD_BYTES))
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<(
                JournalTransaction,
                [crate::journal::JournalRecord; 2],
                [Vec<u8>; 4],
            )>())
        })
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<(Vec<u8>, [usize; 6])>()))
        .ok_or(CacheHeldErrorV1::Order)?;
    receiving::fixed_readonly_demand(bytes, 25)?
        .checked_add(upper_fixed)?
        .checked_add(
            current_receiving::create_storage_cache_current_dynamic_with_upper_semantic_quote_v1(
                &after,
                semantic_supplement,
            )?,
        )?
        .checked_add(
            ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(framing).map_err(|_| CacheHeldErrorV1::Order)?,
                )
                .with(D::MetadataEntries, 1)
                .with(D::StorageBytes, append)
                .with(D::OutputBytes, append)
                .with(D::PublicationStagingBytes, append),
        )
        .map_err(Into::into)
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    /// Computes the Held envelope's checksum DATA at the original upper slot.
    ///
    /// # Errors
    /// Refuses an incomplete Held receipt or mismatched canonical lane.
    pub fn held_predecessor_data_v1(&self, lane: [u8; 16]) -> Result<[u8; 32], CacheHeldErrorV1> {
        let held = self
            .held_receipt_data_v1()
            .map_err(|_| CacheHeldErrorV1::Order)?;
        Ok(RecordEnvelopeV1::decode(
            held.record,
            KeyV1::new(lane, OwnerV1::Cache, 1)?,
            PhaseV1::new(OwnerV1::Cache, 1)?,
        )?
        .checksum())
    }

    /// Captures the actual post-release five-prefix receiving forecast.
    ///
    /// # Errors
    /// Refuses an incomplete Held stage or invalid native/semantic forecast.
    pub fn release_receiving_shape_v1(
        &self,
        upper_fixed: Option<ResourceVector>,
        semantic_supplement: Option<ResourceVector>,
    ) -> Result<CacheReleasedShapeV1, CacheHeldErrorV1> {
        self.require_pre_root_cut_v1()
            .map_err(|_| CacheHeldErrorV1::Order)?;
        let body = self
            .progress
            .body
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldErrorV1::Order)?;
        let mut snapshot = *body;
        snapshot.hold = self
            .progress
            .after_hold
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldErrorV1::Order)?
            .coordinates;
        let current = CreateStorageCacheCurrentExtentsDataV1::from_current_snapshot_v1(&snapshot)?;
        let mut after = *current.extents_v1();
        after[1] = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            after[1].limits(),
            after[1]
                .native_bytes()
                .checked_add(release_append_bytes_v1()?)
                .ok_or(CacheHeldErrorV1::Order)?,
        )?;
        let semantic_peak =
            crate::journal::readonly_receiving::full_prefix_semantic_peak_with_supplement_v1(
                &after,
                semantic_supplement,
            )?;
        let semantic_supplement =
            semantic_supplement.ok_or(JournalError::DeferredUpperSemanticQuote)?;
        Ok(CacheReleasedShapeV1 {
            identity: self.identity,
            extents: after,
            semantic_peak,
            semantic_supplement,
            complete: release_receiving_demand_v1(
                current.extents_v1(),
                upper_fixed,
                Some(semantic_supplement),
            )?,
        })
    }

    /// Enters the real once-only Released owner before the upper fixed check.
    ///
    /// # Errors
    /// Retains reentry, Held-native debt or an invalid forecast.
    pub fn begin_released_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        upper_fixed: Option<ResourceVector>,
        semantic_supplement: Option<ResourceVector>,
    ) -> Result<(), CacheHeldClosedV1> {
        if released.entered {
            released.refused = true;
            return Err(CacheHeldClosedV1);
        }
        released.entered = true;
        released.entry = Some(
            self.require_pre_root_cut_v1()
                .map_err(|_| CacheHeldErrorV1::Order),
        );
        released.shape = Some(self.release_receiving_shape_v1(upper_fixed, semantic_supplement));
        released.positive()
    }

    /// Retains the exact owed native observation before the Released body.
    ///
    /// # Errors
    /// Reports retained native debt after observing the original bookends.
    pub fn observe_released_before_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        if released.before.is_some() {
            released.refused = true;
            return Err(CacheHeldClosedV1);
        }
        released.before = Some(audit::observe_bookends(
            &mut self.originals,
            self.progress,
            None,
        ));
        released.positive()
    }

    /// Encodes the real upper outcome DATA into the same native Released slots.
    ///
    /// # Errors
    /// Retains exact canonical encoding/transaction errors and refuses reentry.
    pub fn encode_released_pair_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        lane: [u8; 16],
        body: ReleasedBodyDataV1,
    ) -> Result<(), CacheHeldClosedV1> {
        released.positive()?;
        if released.body.is_some() {
            released.refused = true;
            return Err(CacheHeldClosedV1);
        }
        released.lane = Some(lane);
        released.body = Some(body.encode(OwnerV1::Cache).map_err(Into::into));
        released.record = Some((|| {
            let held = self
                .held_receipt_data_v1()
                .map_err(|_| CacheHeldErrorV1::Order)?;
            let held = RecordEnvelopeV1::decode(
                held.record,
                KeyV1::new(lane, OwnerV1::Cache, 1)?,
                PhaseV1::new(OwnerV1::Cache, 1)?,
            )?;
            let body = released
                .body
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let mut record = [0; RELEASED_RECORD_BYTES_V1];
            let checksum = RecordEnvelopeV1::encode_into(
                RecordCoordinatesV1 {
                    key: KeyV1::new(lane, OwnerV1::Cache, 2)?,
                    phase: PhaseV1::new(OwnerV1::Cache, 2)?,
                    predecessor: held.checksum(),
                    correlation: held.coordinates().correlation,
                },
                body,
                &mut record,
            )?;
            released.head = Some(LatestHeadV1::new(2, checksum)?.encode());
            Ok(record)
        })());
        released.transaction = Some((|| {
            let record = released
                .record
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let head = released.head.as_ref().ok_or(CacheHeldErrorV1::Order)?;
            Ok(Arc::new(
                prepare_history_pair_v1(
                    KeyV1::new(lane, OwnerV1::Cache, 2)?,
                    PhaseV1::new(OwnerV1::Cache, 2)?,
                    record,
                    head,
                )
                .map_err(JournalError::from)?,
            ))
        })());
        released.positive()
    }

    /// Borrows the actual prepared Released transaction allocation.
    ///
    /// # Errors
    /// Refuses incomplete or failed native encoding.
    pub fn released_append_transaction_data_v1<'view>(
        &self,
        released: &'view CacheReleasedOriginalsV1,
    ) -> Result<&'view Arc<JournalTransaction>, CacheHeldClosedV1> {
        released.positive()?;
        released
            .transaction
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)
    }

    /// Admits the old reached semantic delta through the same real U account.
    ///
    /// # Errors
    /// Retains native geometry separately from the actual admission cause.
    pub fn admit_released_append_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) -> Result<(), CacheHeldClosedV1> {
        released.positive()?;
        released.append_geometry = Some((|| {
            let transaction = released
                .transaction
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or_else(JournalError::boundary)?;
            let semantic = self
                .originals
                .hold
                .as_deref()
                .ok_or_else(JournalError::boundary)?
                .cache_held_append_semantic_demand_v1(transaction)?;
            let shape = released
                .shape
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or_else(JournalError::boundary)?;
            semantic
                .componentwise_max(shape.semantic_peak)
                .checked_sub(shape.semantic_peak)
                .and_then(|extra| shape.complete.checked_add(extra))
                .map_err(JournalError::from)
        })());
        if let Some(Ok(complete)) = released.append_geometry.as_ref() {
            released.append_funding = Some(funding.admit_complete_v1(self.identity, *complete));
        }
        released.positive()
    }

    /// Retains the actual returned pair and post-append Hold shape.
    ///
    /// # Errors
    /// Preserves exact readback/native errors and refuses a changed successor.
    pub fn capture_released_returned_pair_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        released.positive()?;
        released.readback = Some((|| {
            let transaction = released
                .transaction
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let committed = released
                .append
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let before = self
                .progress
                .after_hold
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let record = released
                .record
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let head = released.head.as_ref().ok_or(CacheHeldErrorV1::Order)?;
            Ok(readback_history_pair_v1(
                self.originals
                    .hold
                    .as_deref()
                    .ok_or(CacheHeldErrorV1::Order)?,
                transaction,
                record,
                head,
                before.coordinates.next,
                committed,
            )?)
        })());
        released.after_hold = Some((|| {
            let hold = self
                .originals
                .hold
                .as_deref()
                .ok_or(CacheHeldErrorV1::Order)?;
            let after = hold.capture_cache_held_shape_v1(
                &mut released.after_hold_position,
                InitializerJournal::Hold,
                self.originals.uid,
            )?;
            let before = self
                .progress
                .after_hold
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let observed = released
                .readback
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let committed = released
                .append
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            let forecast = released
                .shape
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            if after.coordinates.names != before.coordinates.names
                || after.coordinates.next != observed.next
                || after.coordinates.end != committed.durable_bytes
                || after.extent.limits() != forecast.extents[1].limits()
                || after.extent.native_bytes() != forecast.extents[1].native_bytes()
            {
                return Err(CacheHeldErrorV1::Order);
            }
            Ok(after)
        })());
        released.positive()
    }

    /// Observes the independently owed native after set even after body failure.
    ///
    /// # Errors
    /// Returns retained native debt after the original complete post set.
    pub fn observe_released_after_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        if released.after.is_some() {
            released.refused = true;
            return Err(CacheHeldClosedV1);
        }
        let after = released
            .after_hold
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        released.after = Some(audit::observe_bookends_with_hold_v1(
            &mut self.originals,
            self.progress,
            None,
            after,
        ));
        released.positive()
    }

    /// Reports the next real terminal ordinal without admitting an effect.
    pub fn released_audit_ordinal_data_v1(&self) -> usize {
        self.progress.audit_next
    }

    /// Replays one actual terminal reader and retains all its native posts.
    ///
    /// The upper paired-clock attempt remains owed after an error here. Its
    /// failure leaves this same reader resident; it cannot start the next one.
    ///
    /// # Errors
    /// Retains native replay, exact suffix, equality and independent-post debt.
    pub fn capture_released_reader_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) -> Result<(), CacheHeldClosedV1> {
        released.positive()?;
        let index = self.progress.audit_next;
        if !(10..15).contains(&index) || self.progress.active_audit.is_some() {
            return Err(CacheHeldClosedV1);
        }
        let writer = index % 5;
        let shape = self
            .progress
            .shape
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let held = self
            .progress
            .after_hold
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let after = released
            .after_hold
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let expected = if writer == 1 {
            after
        } else {
            &shape.writers[writer]
        };
        let held_transaction = self
            .progress
            .transaction
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let release_transaction = released
            .transaction
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let positions = [
            shape.writers[1].coordinates,
            held.coordinates,
            after.coordinates,
        ];
        let bound = released
            .shape
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        self.progress.active_audit = Some(audit::CacheHeldAuditV1::new());
        let active = self
            .progress
            .active_audit
            .as_mut()
            .ok_or(CacheHeldClosedV1)?;
        released.audit_returned = Some(active.replay_released_once(
            &self.originals,
            funding,
            self.identity,
            bound.complete,
            bound.semantic_peak,
            expected,
            writer,
            held_transaction,
            release_transaction,
            positions,
        ));
        let posts = audit::observe_bookends_with_hold_v1(
            &mut self.originals,
            self.progress,
            None,
            Some(after),
        );
        self.progress
            .active_audit
            .as_mut()
            .ok_or(CacheHeldClosedV1)?
            .posts = Some(posts);
        match released.audit_returned {
            Some(Ok(())) => Ok(()),
            _ => Err(CacheHeldClosedV1),
        }
    }

    /// Retires only the actual positive reader after its upper clock passed.
    ///
    /// This method accepts no success flag or borrowed error. Native replay,
    /// suffix, equality and independently owed native posts remain mandatory.
    ///
    /// # Errors
    /// Keeps the failed reader resident and refuses a skipped/repeated ordinal.
    pub fn retire_released_reader_after_upper_clock_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        let index = self.progress.audit_next;
        let writer = index % 5;
        let active = self
            .progress
            .active_audit
            .as_ref()
            .ok_or(CacheHeldClosedV1)?;
        if !matches!(released.audit_returned, Some(Ok(())))
            || active.failure().is_some()
            || !matches!(active.equality, Some(Ok(())))
            || writer == 1 && !active.released_suffix_is_complete_v1()
        {
            released.failed_audit = self.progress.active_audit.take();
            return Err(CacheHeldClosedV1);
        }
        let report = active
            .report
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(CacheHeldClosedV1)?;
        let shape = self
            .progress
            .shape
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let after = released
            .after_hold
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let coordinates = if writer == 1 {
            after.coordinates
        } else {
            shape.writers[writer].coordinates
        };
        self.progress.audits[index] = Some(audit::CacheHeldAuditDataV1 {
            coordinates,
            report,
        });
        drop(self.progress.active_audit.take());
        released.audit_returned = None;
        self.progress.audit_next += 1;
        Ok(())
    }

    /// Retains the entered reader when its independent upper clock fails.
    pub fn reject_released_reader_after_upper_clock_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
    ) {
        released.failed_audit = self.progress.active_audit.take();
        released.refused = true;
    }

    /// Marks native Released completion only after all real terminal ordinals.
    ///
    /// # Errors
    /// Refuses native/upper debt or incomplete actual replay/readback stages.
    pub fn finish_released_native_once_v1(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
    ) -> Result<(), CacheHeldClosedV1> {
        released.positive()?;
        if self.progress.audit_next != 15
            || self.progress.active_audit.is_some()
            || !matches!(released.append, Some(Ok(_)))
            || !matches!(released.readback, Some(Ok(_)))
            || released
                .after
                .as_ref()
                .is_none_or(|posts| posts.failure().is_some())
        {
            return Err(CacheHeldClosedV1);
        }
        released.complete = true;
        Ok(())
    }
}

impl<'cache> OriginalCreateStorageCacheLoanV1<'cache> {
    /// Debits the actual old release frontier through the same native U.
    ///
    /// Cache derives its full native shape and five-prefix peak. The caller
    /// supplies only its actual compiled upper fixed and separate Root quote.
    ///
    /// # Errors
    /// Preserves genuine Controller/Source/profile affinity and U admission.
    pub fn bind_release_audit_funding_v1<'funding, 'profile>(
        &self,
        original: aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateStorageUseFundingLoanV1<'funding, 'profile>,
        source: &'funding ControllerSourceOriginalRefV1,
        upper_fixed: Option<ResourceVector>,
        semantic_supplement: Option<ResourceVector>,
        non_cache: ResourceVector,
    ) -> Result<
        ControllerCacheAuditFundingLoanV1<'funding, 'profile>,
        ControllerCacheAuditFundingErrorV1,
    >
    where
        'cache: 'funding,
    {
        let shape = self.release_receiving_shape_v1(upper_fixed, semantic_supplement).map_err(|_| {
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheAuditFundingErrorV1::Native(
                aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1::Conflict)
        })?;
        let construction: &'cache super::super::baseline::CacheConstructionOriginalsV1 =
            self.originals.construction;
        construction.bind_release_audit_funding_v1(
            original,
            source,
            self.identity,
            non_cache,
            shape.complete,
            shape.semantic_peak,
        )
    }
}

#[cfg(test)]
mod forecast_tests {
    use super::*;
    use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;

    fn extents() -> [crate::journal::ProtectedJournalPreopenReplayExtentV1; 5] {
        [CacheJournalRecipeRoleV1::Bootstrap, CacheJournalRecipeRoleV1::Hold,
            CacheJournalRecipeRoleV1::State, CacheJournalRecipeRoleV1::Authority,
            CacheJournalRecipeRoleV1::Clock].map(|role| {
                crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                    role.limits_v1(), 0,
                ).unwrap()
            })
    }

    #[test]
    fn missing_fixed_quote_precedes_missing_semantic_quote() {
        let result = release_receiving_demand_v1(&extents(), None, None);

        assert!(matches!(result, Err(CacheHeldErrorV1::Journal(
            JournalError::DeferredUpperFixedQuote,
        ))));
    }

    #[test]
    fn full_prefix_semantic_supplement_is_charged_once() {
        let extents = extents();
        let base = release_receiving_demand_v1(&extents,
            Some(ResourceVector::ZERO), Some(ResourceVector::ZERO)).unwrap();
        let supplemented = release_receiving_demand_v1(&extents,
            Some(ResourceVector::ZERO), Some(ResourceVector::ZERO.with(D::MemoryBytes, 4096))).unwrap();

        assert_eq!(supplemented.get(D::MemoryBytes), base.get(D::MemoryBytes) + 4096);
    }
}
