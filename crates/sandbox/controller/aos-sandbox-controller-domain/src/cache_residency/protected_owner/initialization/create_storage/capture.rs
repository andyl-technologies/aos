//! Captures actual initialized Cache shape only after the same J fixed entry.

use super::*;

impl<'cache> OriginalCreateStorageCacheLoanV1<'cache> {
    /// Borrows the actual earliest retained Cache cause without moving custody.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.progress.failure()
    }

    /// Returns comparison DATA from the same retained successful Q04 original.
    ///
    /// # Errors
    /// Refuses missing/failed original terminal progression or a different saved
    /// cleared Hold. Actual J must compare this cut with its genuine parent;
    /// decoding the returned DATA cannot reconstruct either original owner.
    pub(crate) fn original_q04_identity_data_v1(
        &self,
    ) -> Result<crate::policy_compiler::create_q04::Q04CutIdentityV1, CacheHeldClosedV1> {
        self.originals.q04.identity_after_original_clearance(self.originals.original_hold)
            .map_err(|_| CacheHeldClosedV1)
    }

    /// Checks the original B/profile association without issuing a new grant.
    ///
    /// # Errors
    /// Refuses a different original selected Controller or preexisting B debt.
    pub(crate) fn require_same_controller_original_v1(
        &self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.originals.construction.failure().is_some()
            || !self.originals.construction.matches_original(profile.lower_original_v1())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Returns the actual independently retained callback site as comparison DATA.
    ///
    /// # Errors
    /// Refuses use outside the producer's named currentness crossing.
    pub(crate) fn currentness_site_v1(&self) -> Result<CacheHeldCurrentnessSiteV1, CacheHeldClosedV1> {
        self.progress.currentness_site.ok_or(CacheHeldClosedV1)
    }

    /// Supplies pure fixed preparation geometry without observing any original.
    ///
    /// # Errors
    /// Returns only checked compiler-layout/path-width representation refusal.
    pub(crate) fn fixed_receiving_demand_v1(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        receiving::fixed_demand()
    }

    /// Returns comparison DATA while every actual initialized owner stays held.
    pub(crate) fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 { self.identity }

    /// Captures the actual shape once within the same J's prepaid fixed entry.
    ///
    /// # Errors
    /// Retains clock, actual metadata, geometry and physical errors. No replay,
    /// typed reconstruction, variable encoding or append precedes J admission.
    pub(crate) fn capture_receiving_shape_once(
        &mut self,
    ) -> Result<&CacheCreateStorageReceivingShapeV1, CacheHeldClosedV1> {
        if self.progress.shape.is_some() || self.progress.first.is_some() {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        let clock: &'cache ProtectedCacheClockV1 = self.originals.clock_owner.as_ref();
        match clock.hold_writer_for_create_storage_readback(&mut self.progress.clock_position) {
            Ok(guard) => {
                self.originals.clock = Some(guard);
                self.progress.clock = Some(Ok(()));
            }
            Err(cause) => {
                self.progress.clock = Some(Err(cause.into()));
                self.progress.first = Some(Failure::Clock);
                self.observe_posts_once(0);
                return Err(CacheHeldClosedV1);
            }
        }
        self.progress.shape = Some(self.capture_shape_inner());
        self.progress.mark(matches!(self.progress.shape, Some(Err(_))), Failure::Shape);
        if self.progress.first.is_some() {
            // Fixed name/physical/clock posts are already funded; no variable
            // Native audit or model allocation follows this failed frontier.
            self.observe_posts_once(0);
            return Err(CacheHeldClosedV1);
        }
        self.progress.shape.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)
    }

    fn capture_shape_inner(&mut self) -> Result<CacheCreateStorageReceivingShapeV1, CacheHeldErrorV1> {
        capture_shape_for_originals_v1(&mut self.originals, self.progress, self.identity,
            CacheCapturePurposeV1::InitialCreate)
    }

    /// Borrows the produced comparison body without lending a live original.
    ///
    /// # Errors
    /// Refuses missing production or any earlier retained Cache debt.
    pub(crate) fn held_body_data_v1(&self) -> Result<&CacheHeldBodyDataV1, CacheHeldClosedV1> {
        if self.progress.first.is_some() { return Err(CacheHeldClosedV1); }
        self.progress.body.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldClosedV1)
    }

    /// Borrows the exact copied actual Source receipt even during negative posts.
    ///
    /// # Errors
    /// Refuses a missing/failed Source receipt; copied bytes grant no authority.
    pub(crate) fn source_held_bytes_v1(&self) -> Result<&[u8; SOURCE_HELD_RECEIPT_BYTES_V1], CacheHeldClosedV1> {
        self.progress.source.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CacheHeldClosedV1)
    }

    /// Borrows the exact new marker and returned native receipt as inert DATA.
    ///
    /// # Errors
    /// Refuses failed/incomplete append/readback or any later observed debt.
    pub(crate) fn held_receipt_data_v1(&self) -> Result<CacheHeldReceiptDataV1<'_>, CacheHeldClosedV1> {
        if self.progress.first.is_some() { return Err(CacheHeldClosedV1); }
        let observed = self.progress.readback.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        let shape = self.progress.after_hold.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheHeldClosedV1)?;
        Ok(CacheHeldReceiptDataV1 {
            record: &observed.record, latest_head: observed.head,
            hold_names: shape.coordinates.names, hold_after_next: observed.next,
            hold_after_end: shape.coordinates.end,
        })
    }
}

impl Drop for OriginalCreateStorageCacheLoanV1<'_> {
    fn drop(&mut self) {
        if !self.progress.finished {
            self.progress.refuse();
            self.initialization_failure.get_or_insert(InitializationCauseV1::CreateStorageHeld);
            // This executes before the actual clock guard could unfreeze, and
            // before any borrowed original or J worker can be disposed.
            std::process::abort();
        }
    }
}


// Only genuine purpose-specific factories can build the actual originals.
// Delete checks the actual completed initialization or genuine Root6 continuation;
// it never borrows/reset the Initial Create once-purpose or skips a native read.
pub(super) enum CacheCapturePurposeV1 {
    InitialCreate,
    Delete,
}

pub(super) fn capture_shape_for_originals_v1(
    originals: &mut CacheHeldOriginalsV1<'_>,
    progress: &mut CacheHeldProgressV1,
    identity: CacheHeldIdentityDataV1,
    purpose: CacheCapturePurposeV1,
) -> Result<CacheCreateStorageReceivingShapeV1, CacheHeldErrorV1> {
    let snapshot = originals.physical.capture_create_storage_physical_once(
        &mut progress.initial_physical, None)?;
    if snapshot.owner_uid() != originals.uid {
        return Err(CacheHeldErrorV1::Order);
    }
    originals.physical_identity = Some(snapshot.identity());
    let source = originals.source.create_storage_writer_shape_v1(&mut progress.initial_positions[0])?;
    let hold = originals.hold.as_deref().ok_or(CacheHeldErrorV1::Order)?;
    if matches!(purpose, CacheCapturePurposeV1::InitialCreate) {
        hold.require_no_cache_held_history_v1()?;
    }
    let hold_shape = hold.capture_cache_held_shape_v1(&mut progress.initial_positions[1], InitializerJournal::Hold, originals.uid)?;
    let state_shape = originals.state.capture_cache_held_shape_v1(&mut progress.initial_positions[2], InitializerJournal::State, originals.uid)?;
    let clock_state = originals.clock_owner.state.lock()
        .map_err(|_| CacheHeldErrorV1::Order)?;
    let clock_journal = clock_state.journal.as_ref().ok_or(CacheHeldErrorV1::Order)?;
    let clock_shape = clock_journal.capture_cache_held_shape_v1(&mut progress.initial_positions[4], InitializerJournal::Clock, originals.uid)?;
    drop(clock_state);
    originals.clock.as_ref().ok_or(CacheHeldErrorV1::Order)?
        .require_create_storage_shape_v1(&clock_shape)?;
    let mut returned = None;
    let checked = originals.authority.check_named_location(|journal| {
        returned = Some((|| {
            let authority_shape = journal.capture_cache_held_shape_v1(&mut progress.initial_positions[3], InitializerJournal::Authority, originals.uid)?;
            let writers = [source, hold_shape, state_shape, authority_shape, clock_shape];
            let (additional, fixed) = match purpose {
                CacheCapturePurposeV1::InitialCreate => (
                    receiving::additional_demand(&writers, journal, originals.state)?,
                    receiving::fixed_demand()?,
                ),
                CacheCapturePurposeV1::Delete => (
                    super::delete_inventory::additional_demand_v1(&writers, journal, originals.state)?,
                    super::delete_inventory::fixed_demand_v1()?,
                ),
            };
            let complete = fixed.checked_add(additional)?;
            Ok(CacheCreateStorageReceivingShapeV1 {
                identity: identity, writers, additional, fixed, complete,
            })
        })());
        if matches!(returned, Some(Ok(_))) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    });
    match returned {
        Some(result) => result,
        None => Err(checked.err().ok_or(CacheHeldErrorV1::Order)?.into()),
    }
}
