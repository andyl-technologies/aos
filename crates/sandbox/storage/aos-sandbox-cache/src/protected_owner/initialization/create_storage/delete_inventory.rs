//! Keeps the five actual Cache writers through the finite Delete read purpose.
//!
//! Controller/Source authorization, the C17 turn, semantic first causes and
//! paired nonce posts stay in the upper programme. This owner retains actual
//! Clock custody, captured prefixes, whole readers and physical metadata. It
//! accepts only a genuine financial borrower at each native replay frontier.

use super::*;
use aos_sandbox_model::ResourceDimension as D;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerDeletePreacceptTurnDisposalV1;
use crate::recovery::{
    CacheReplayRepresentationPhaseV1, general_replay_representation_bound_v1,
};

mod metadata;

/// Retains the actual initialized Cache through one Delete query and its posts.
///
/// This borrows existing native owners. It cannot be assembled from writer,
/// descriptor, history, paid-vector or decoded inventory DATA.
pub struct CacheDeleteNativeOriginalV1<'cache> {
    originals: CacheHeldOriginalsV1<'cache>,
    identity: CacheHeldIdentityDataV1,
    payload: CacheDeleteNativePayloadsV1<'cache>,
    armed: bool,
    finished: bool,
    semantic_supplement: Option<ResourceVector>,
}

/// Keeps the first completed native payloads while the same writers are reread.
///
/// Only the genuine original constructs this value. It retains completed
/// inventories and physical metadata without transferring any writer loan.
pub struct CacheDeleteNativePayloadsV1<'cache> {
    progress: CacheHeldProgressV1,
    inventory: Option<Result<CacheLifecycleBootInventoryV1, CacheResidencyProtectedJournalErrorV1>>,
    authority_post: Option<CacheResidencyProtectedJournalErrorV1>,
    reader_returned: Option<Result<(), CacheHeldClosedV1>>,
    completed_readers: usize,
    metadata: metadata::CacheDeleteMetadataOriginalsV1<'cache>,
}

impl Default for CacheDeleteNativePayloadsV1<'_> {
    fn default() -> Self {
        Self {
            progress: Default::default(),
            inventory: None,
            authority_post: None,
            reader_returned: None,
            completed_readers: 0,
            metadata: Default::default(),
        }
    }
}

pub(super) fn fixed_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
    let memory = std::mem::size_of::<CacheDeleteNativeOriginalV1<'_>>()
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(
            crate::DormantCacheOwnerV1::original_q04_recheck_scratch_bytes(),
        ))
        .and_then(|bytes| bytes.checked_add(control_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(metadata::control_bytes_v2()?))
        .and_then(|bytes| bytes.checked_add(crate::journal::readonly_receiving::full_prefix_peak_control_bytes_v1()?))
        .ok_or(CacheHeldErrorV1::Order)?;
    receiving::fixed_readonly_demand(memory, 2 * 5 + 5 * 5)
}

fn control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    size_of::<Result<(), CacheHeldClosedV1>>().checked_mul(6)?
        .checked_add(size_of::<capture::CacheCapturePurposeV1>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut CacheDeleteNativeOriginalV1<'_>, Option<ResourceVector>)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(6)?)?
        .checked_add(size_of::<(&crate::journal::ProtectedJournalPreopenReplayExtentV1, ResourceVector, ResourceVector)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, CacheHeldErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, ControllerCacheAuditFundingErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ControllerCacheAuditFundingErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut CacheDeleteNativeOriginalV1<'_>, &mut ControllerCacheAuditFundingLoanV1<'_, '_>)>().checked_mul(3)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&CacheCreateStorageReceivingShapeV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<&CacheLifecycleBootInventoryV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<CacheDeleteNativePayloadsV1<'_>, CacheHeldClosedV1>>().checked_mul(3)?)
}

pub(super) fn additional_demand_v1(
    writers: &[CacheHeldWriterShapeV1; 5],
    authority: &Journal,
    state: &Journal,
    supplement: Option<ResourceVector>,
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let mut native = ResourceVector::ZERO;
    let mut semantic = ResourceVector::ZERO;
    for writer in writers {
        native = native.componentwise_max(writer.extent.dominant_native_receiving_demand_v1().map_err(JournalError::from_ordinary_native_v1)?);
        semantic = semantic.componentwise_max(crate::journal::readonly_receiving::full_prefix_semantic_with_supplement_v1(&writer.extent, supplement)?);
    }
    let geometry = CacheReplayManifestGeometryV1::from_initial_journals(
        authority, state, CacheRecoveryLimitsV1::default(),
    )?;
    let models = general_replay_representation_bound_v1(
        geometry.encoded_bytes(), geometry.partition_bound(), CacheReplayRepresentationPhaseV1::InitialInventory,
    )?;
    let entries = geometry.encoded_bytes().checked_mul(3)
        .and_then(|count| count.checked_mul(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleBootDomainEntryDataV1>()))
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheLifecycleBootInventoryV1>().checked_mul(3)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(CacheHeldErrorV1::Order)?;
    native.checked_add(semantic)?.checked_add(models)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, entries)).map_err(Into::into)
}

impl CacheResidentInitializationV1 {
    /// Borrows the same genuinely initialized five-owner Cache for Delete.
    ///
    /// # Errors
    /// Refuses incomplete or failed initialization, changed originals or a
    /// different Controller profile. The split performs no native observation.
    pub fn borrow_delete_inventory_originals_v1<'cache>(
        &'cache mut self,
        owner: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache crate::DormantCacheOwnerV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<CacheDeleteNativeOriginalV1<'cache>, CacheHeldClosedV1> {
        let same_clock = self.clock.as_ref().zip(owner.clock.as_ref())
            .is_some_and(|(initial, current)| Arc::ptr_eq(initial, current));
        let same_authority = self.targets.initialized_authority.as_ref()
            .is_some_and(|initial| Arc::ptr_eq(initial, &owner.authority));
        let selected = self.selected_baseline.as_ref().ok_or(CacheHeldClosedV1)?;
        if self.first_failure.is_some() || self.postcheck.is_some() || selected.originals.failure().is_some()
            || self.create_storage_held.failure().is_some()
            || !(self.complete || self.require_create_storage_terminal_native_v1().is_ok())
            || !same_clock || !same_authority || !selected.originals.matches_original(profile)
        {
            return Err(CacheHeldClosedV1);
        }
        let initialization = self as *const Self as usize;
        let owner_identity = owner as *const CacheResidencyProtectedOwnerV1 as usize;
        let (Some(clock_owner), Some(source), Some((hold, _)), Some(state)) =
            (self.clock.as_ref(), self.source.as_mut(), self.hold.as_mut(), owner.state_journal.as_mut())
        else { return Err(CacheHeldClosedV1); };
        let identity = CacheHeldIdentityDataV1 {
            initialization, owner: owner_identity, source: source as *const _ as usize,
            state: state as *const Journal as usize, authority: Arc::as_ptr(&owner.authority) as usize,
            clock: Arc::as_ptr(clock_owner) as usize, physical: physical as *const _ as usize,
            uid: owner.owner_uid,
        };
        Ok(CacheDeleteNativeOriginalV1 {
            originals: CacheHeldOriginalsV1 {
                construction: &selected.originals, q04: &self.q04, original_hold: self.original_hold,
                source, state, hold: Some(hold), authority: &owner.authority,
                clock_owner, clock: None, physical, physical_identity: None, uid: owner.owner_uid,
            },
            identity, payload: Default::default(),
            armed: false, finished: false, semantic_supplement: None,
        })
    }
}

impl<'cache> CacheDeleteNativeOriginalV1<'cache> {
    /// Prices fixed native construction before the original Source admission.
    ///
    /// # Errors
    /// Refuses checked representation or path geometry overflow.
    pub fn fixed_receiving_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
        fixed_demand_v1()
    }

    /// Returns equality DATA derived from these same actual native references.
    pub fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 {
        self.identity
    }

    /// Holds the actual Clock and captures the five physical shapes once.
    ///
    /// # Errors
    /// Retains actual Clock, writer position, physical and geometry causes.
    pub fn capture_receiving_shape_once_v1(
        &mut self,
        supplement: Option<ResourceVector>,
    ) -> Result<(), CacheHeldClosedV1> {
        if self.armed || self.payload.progress.shape.is_some() {
            self.payload.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.armed = true;
        self.finished = false;
        self.semantic_supplement = supplement;
        let clock: &'cache ProtectedCacheClockV1 = self.originals.clock_owner.as_ref();
        match clock.hold_writer_for_create_storage_readback(&mut self.payload.progress.clock_position) {
            Ok(guard) => {
                self.originals.clock = Some(guard);
                self.payload.progress.clock = Some(Ok(()));
            }
            Err(cause) => {
                self.payload.progress.clock = Some(Err(cause.into()));
                self.payload.progress.first = Some(Failure::Clock);
                return Err(CacheHeldClosedV1);
            }
        }
        self.payload.progress.shape = Some(capture::capture_shape_for_originals_v1(
            &mut self.originals, &mut self.payload.progress, self.identity,
            capture::CacheCapturePurposeV1::Delete(supplement),
        ));
        if matches!(self.payload.progress.shape, Some(Err(_))) {
            self.payload.progress.first = Some(Failure::Shape);
            return Err(CacheHeldClosedV1);
        }
        Ok(())
    }

    /// Borrows the actual captured shape without lending a writer or grant.
    ///
    /// # Errors
    /// Refuses absent or failed shape capture.
    pub fn captured_shape_v1(&self) -> Result<&CacheCreateStorageReceivingShapeV1, CacheHeldClosedV1> {
        self.payload.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CacheHeldClosedV1)
    }

    /// Returns the fixed five captured extents as non-authorizing comparison DATA.
    ///
    /// # Errors
    /// Refuses absent or failed capture.
    pub fn captured_extents_data_v1(&self) -> Result<CreateStorageCacheCurrentExtentsDataV1, CacheHeldClosedV1> {
        Ok(CreateStorageCacheCurrentExtentsDataV1::from_captured_extents_v1(
            self.captured_shape_v1()?.writers.each_ref().map(|writer| writer.extent),
        ))
    }

    /// Independently derives the exact native semantic component from all five.
    ///
    /// # Errors
    /// Preserves the actual canonical arithmetic cause; this value pays nothing.
    pub fn native_semantic_demand_v1(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        let mut semantic = ResourceVector::ZERO;
        for writer in &self.captured_shape_v1().map_err(|_| CacheHeldErrorV1::Order)?.writers {
            semantic = semantic.componentwise_max(crate::journal::readonly_receiving::full_prefix_semantic_demand_v1(&writer.extent)?);
        }
        crate::journal::readonly_receiving::with_semantic_supplement_v1(
            semantic, self.semantic_supplement.ok_or(CacheHeldErrorV1::Order)?,
        ).map_err(Into::into)
    }

    /// Returns the exact captured complete quote without supplying admission.
    ///
    /// # Errors
    /// Refuses a failed or absent shape.
    pub fn complete_receiving_demand_v1(&self) -> Result<ResourceVector, CacheHeldClosedV1> {
        Ok(self.captured_shape_v1()?.complete_base())
    }

    /// Runs only the next actual native reader under the genuine C17 borrower.
    ///
    /// The reader and its posts remain resident until the upper deadline sample
    /// permits the separate positive-disposal method.
    ///
    /// # Errors
    /// Retains parser, equality, native post and financial rejoin refusals.
    pub fn audit_next_once_v1(
        &mut self,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) -> Result<(), CacheHeldClosedV1> {
        let writer = self.payload.completed_readers;
        if writer >= 5 || self.payload.progress.active_audit.is_some() {
            self.payload.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        let semantic = self.native_semantic_demand_v1().map_err(|_| CacheHeldClosedV1)?;
        let shape = self.captured_shape_v1()?;
        let complete = shape.complete_base();
        let progress = &mut self.payload.progress;
        let Some(Ok(shape)) = progress.shape.as_ref() else { return Err(CacheHeldClosedV1); };
        let expected = &shape.writers[writer];
        progress.active_audit = Some(audit::CacheHeldAuditV1::new());
        if let Some(active) = progress.active_audit.as_mut() {
            self.payload.reader_returned = Some(active.replay_once(
                &self.originals, funding, self.identity, complete, semantic, expected, writer, None,
            ));
        }
        let posts = audit::observe_bookends(&mut self.originals, progress, None);
        if let Some(active) = progress.active_audit.as_mut() { active.posts = Some(posts); }
        if self.active_reader_is_positive_v1() { Ok(()) } else { Err(CacheHeldClosedV1) }
    }

    fn active_reader_is_positive_v1(&self) -> bool {
        self.payload.progress.active_audit.as_ref().is_some_and(|active| {
            matches!(self.payload.reader_returned, Some(Ok(()))) && active.failure().is_none()
                && matches!(active.equality, Some(Ok(()))) && matches!(active.report, Some(Ok(_)))
        })
    }

    /// Disposes the same complete reader only after its upper cutoff succeeded.
    ///
    /// # Errors
    /// Refuses failed/incomplete reader custody and retains it without peak reuse.
    pub fn finish_positive_reader_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        if !self.active_reader_is_positive_v1() { return Err(CacheHeldClosedV1); }
        let writer = self.payload.completed_readers;
        let shape = self.payload.progress.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let report = self.payload.progress.active_audit.as_ref()
            .and_then(|active| active.report.as_ref()).and_then(|value| value.as_ref().ok())
            .copied().ok_or(CacheHeldClosedV1)?;
        self.payload.progress.audits[writer] = Some(audit::CacheHeldAuditDataV1 {
            coordinates: shape.writers[writer].coordinates, report,
        });
        drop(self.payload.progress.active_audit.take());
        self.payload.reader_returned = None;
        self.payload.completed_readers += 1;
        Ok(())
    }

    /// Reconstructs the same whole protected reducer inventory under authority.
    ///
    /// # Errors
    /// Retains the full projection/body error before the independently owed post.
    pub fn project_inventory_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        if self.payload.completed_readers != 5 || self.payload.inventory.is_some() {
            return Err(CacheHeldClosedV1);
        }
        let authority = self.originals.authority;
        let state = &mut *self.originals.state;
        authority.while_authority_current_resident(
            &mut self.payload.inventory, &mut self.payload.authority_post,
            |_owner, _now, validator| {
                let projection = CacheResidencyProtectedJournalV1::claim(state, validator.clone())?.replay()?;
                let inventories = reconstruct_cache_history(projection.records(), &validator)?;
                let entries = super::super::super::lifecycle_inventory::actionable_rows_v1(inventories)?;
                Ok(CacheLifecycleBootInventoryV1 { root: projection.root(), entries })
            },
        );
        if matches!(self.payload.inventory, Some(Ok(_))) && self.payload.authority_post.is_none() {
            Ok(())
        } else { Err(CacheHeldClosedV1) }
    }

    /// Attempts the independent outer five-owner post set even after refusal.
    ///
    /// # Errors
    /// Retains all native causes; a later post cannot replace an earlier primary.
    pub fn observe_original_posts_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        if self.payload.progress.posts[2].is_some() { return Err(CacheHeldClosedV1); }
        self.payload.progress.posts[2] = Some(audit::observe_bookends(
            &mut self.originals, &self.payload.progress, None,
        ));
        if self.payload.progress.posts[2].as_ref().is_some_and(|posts| posts.failure().is_none()) {
            Ok(())
        } else { Err(CacheHeldClosedV1) }
    }

    /// Borrows the precise retained native cause without moving any original.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.payload.progress.failure()
            .or_else(|| self.payload.progress.active_audit.as_ref().and_then(audit::CacheHeldAuditV1::failure))
            .or_else(|| error(&self.payload.reader_returned))
            .or_else(|| error(&self.payload.inventory))
            .or_else(|| self.payload.authority_post.as_ref().map(|cause| cause as _))
            .or_else(|| self.payload.progress.posts[2].as_ref().and_then(audit::CacheHeldBookendsV1::failure))
            .or_else(|| self.payload.metadata.failure())
    }
}

impl<'cache> CacheDeleteNativeOriginalV1<'cache> {
    /// Reports whether all five local readers actually disposed positively.
    pub fn completed_readers_data_v1(&self) -> usize {
        self.payload.completed_readers
    }

    /// Classifies only the captured pure quote marker, never native authority.
    pub fn entry_deferred_semantic_quote_data_v1(&self) -> bool {
        matches!(self.payload.progress.shape,
            Some(Err(CacheHeldErrorV1::Journal(crate::CacheJournalErrorV1::DeferredUpperSemanticQuote))))
    }

    /// Borrows only the actual capture/Clock cause at the entry frontier.
    pub fn entry_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.payload.progress.failure()
    }

    /// Borrows only the active reader's actual cause before its coarse return.
    pub fn reader_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.payload.progress.active_audit.as_ref().and_then(audit::CacheHeldAuditV1::failure)
            .or_else(|| error(&self.payload.reader_returned))
    }

    /// Borrows the exact protected body error before its independent post.
    pub fn projection_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.payload.inventory)
            .or_else(|| self.payload.authority_post.as_ref().map(|cause| cause as _))
    }

    /// Borrows only the independently owed outer native post set's cause.
    pub fn outer_post_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.payload.progress.posts[2].as_ref().and_then(audit::CacheHeldBookendsV1::failure)
    }

    /// Borrows only retained physical metadata debt at its original frontier.
    pub fn metadata_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.payload.metadata.failure()
    }

    /// Identifies a genuine financial refusal retained by the active reader.
    pub fn reader_funding_failed_data_v1(&self) -> bool {
        self.payload.progress.active_audit.as_ref().is_some_and(|active| {
            matches!(active.prepared, Some(Err(CacheHeldErrorV1::Funding(_))))
                || matches!(active.admission, Some(Err(_)))
        })
    }

    /// Borrows the whole actual protected inventory root as comparison DATA.
    ///
    /// # Errors
    /// Refuses a missing/failed reducer or its independent authority post.
    pub fn inventory_root_data_v1(&self) -> Result<aos_sandbox_model::ObjectDigest, CacheHeldClosedV1> {
        if self.payload.authority_post.is_some() { return Err(CacheHeldClosedV1); }
        self.payload.inventory.as_ref().and_then(|value| value.as_ref().ok())
            .map(|inventory| inventory.root()).ok_or(CacheHeldClosedV1)
    }

    /// Borrows the same complete actionable rows without constructing a grant.
    ///
    /// # Errors
    /// Refuses a missing/failed reducer or its independent authority post.
    pub fn inventory_entries_data_v1(&self) -> Result<&[aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleBootDomainEntryDataV1], CacheHeldClosedV1> {
        if self.payload.authority_post.is_some() { return Err(CacheHeldClosedV1); }
        self.payload.inventory.as_ref().and_then(|value| value.as_ref().ok())
            .map(|inventory| inventory.entries()).ok_or(CacheHeldClosedV1)
    }

    /// Copies physical comparison DATA from the same actual captured owner.
    ///
    /// # Errors
    /// Refuses missing capture or the existing actual physical limits recipe.
    pub fn physical_comparison_data_v2(&self) -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1, crate::CacheOwnerErrorV1> {
        self.originals.physical_identity.ok_or(crate::CacheOwnerErrorV1::Stale)?
            .physical_comparison_data_v2(self.originals.physical.limits())
    }

    /// Copies all five actual captured native cuts in their fixed owner order.
    ///
    /// # Errors
    /// Refuses absent or failed shape capture.
    pub fn native_coordinates_data_v1(&self) -> Result<[CacheJournalDataV1; 5], CacheHeldClosedV1> {
        Ok(self.captured_shape_v1()?.writers.each_ref().map(|writer| writer.coordinates))
    }

    /// Retires successful physical reads while the genuine D disposal is held.
    ///
    /// This checks local native completion only. Upper Source/Root/Controller
    /// and deadline checks remain required on the concrete query before entry.
    ///
    /// # Errors
    /// Refuses any incomplete or failed native reader, reducer or outer post.
    pub fn finish_positive_after_posts_once_v2(
        &mut self,
        _disposal: &ControllerDeletePreacceptTurnDisposalV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if !self.armed || self.finished || self.payload.completed_readers != 5
            || self.payload.progress.active_audit.is_some() || self.failure().is_some()
            || self.inventory_root_data_v1().is_err()
            || self.payload.progress.posts[2].is_none()
        { return Err(CacheHeldClosedV1); }
        self.retire_metadata_after_posts_v2();
        self.finished = true;
        Ok(())
    }

    /// Moves completed payload custody aside before the same owners are queried.
    ///
    /// No writer is reopened, Clock released or previous payload dropped. The
    /// upper owner retains this opaque value in its already-priced predecessor.
    ///
    /// # Errors
    /// Refuses a query that did not complete its actual native/post retirement.
    pub fn begin_pending_once_v2(&mut self) -> Result<CacheDeleteNativePayloadsV1<'cache>, CacheHeldClosedV1> {
        if !self.finished || !self.payload.metadata.retired { return Err(CacheHeldClosedV1); }
        let completed = std::mem::take(&mut self.payload);
        self.armed = false;
        self.finished = false;
        self.semantic_supplement = None;
        Ok(completed)
    }
}

impl Drop for CacheDeleteNativeOriginalV1<'_> {
    fn drop(&mut self) {
        if self.armed && !self.finished {
            // This precedes disposal of the frozen Clock or any failed reader.
            std::process::abort();
        }
    }
}
