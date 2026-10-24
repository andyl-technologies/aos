//! Keeps the actual Cache originals across Q pricing and its first held cut.
//!
//! Parking only borrows already-owned state. Genuine Q acquisition precedes
//! shape observation and fixed pricing. The same consuming loan checks that
//! shape before any existing initialization or physical currentness capture.

use super::original_q04::OriginalQ04CacheOwnerCutV1;
use super::*;
use crate::controller_bootstrap::OriginalQ04CacheSourceShapeV1;

pub(super) const SHAPE_POSTS: usize = 3;

pub(super) type ShapeResult =
    Result<OriginalQ04CacheCaptureShapeV1, CacheReplayControllerBootstrapErrorV1>;

/// Retains actual initialized Cache owners through the prepaid Q entrance.
pub struct OriginalQ04CachePreflightLoanV1<'cache> {
    initialization: &'cache mut CacheResidentInitializationV1,
    owner: &'cache mut CacheResidencyProtectedOwnerV1,
    physical: &'cache crate::DormantCacheOwnerV1,
}

/// Describes actual existing geometry as passive comparison DATA.
pub struct OriginalQ04CacheCaptureShapeV1 {
    source: OriginalQ04CacheSourceShapeV1,
    initialization: usize,
    owner: usize,
    physical: usize,
    clock: usize,
    state: usize,
    authority: usize,
    uid: u32,
    physical_limits: crate::CacheOwnerLimitsV1,
    physical_head: crate::CacheOwnerCurrentnessV1,
}

impl OriginalQ04CacheCaptureShapeV1 {
    fn same_original(&self, other: &Self) -> bool {
        self.source.same_original(&other.source)
            && self.initialization == other.initialization
            && self.owner == other.owner
            && self.physical == other.physical
            && self.clock == other.clock
            && self.state == other.state
            && self.authority == other.authority
            && self.uid == other.uid
            && self.physical_limits == other.physical_limits
            && self.physical_head == other.physical_head
    }
}

impl<'cache> OriginalQ04CachePreflightLoanV1<'cache> {
    /// Parks the original borrowers without observing or allocating Cache DATA.
    pub fn park(
        initialization: &'cache mut CacheResidentInitializationV1,
        owner: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache crate::DormantCacheOwnerV1,
    ) -> Self {
        Self {
            initialization,
            owner,
            physical,
        }
    }

    /// Captures the first actual shape once, after genuine Q acquisition.
    ///
    /// # Errors
    /// Refuses another capture or any unavailable/mismatched original owner.
    /// The exact native cause remains in the actual initialization reservoir.
    pub fn capture_shape(
        &mut self,
    ) -> Result<&OriginalQ04CacheCaptureShapeV1, CacheResidentUnavailableV1> {
        if self.initialization.q04_capture_blocked()
            || self.initialization.q04_capture_shape.is_some()
        {
            return Err(CacheResidentUnavailableV1);
        }
        let returned = self.observe_shape();
        if returned.is_err() {
            self.initialization
                .first_failure
                .get_or_insert(InitializationCauseV1::Q04Preflight);
        }
        self.initialization.q04_capture_shape = Some(returned);
        self.initialization
            .q04_capture_shape
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheResidentUnavailableV1)
    }

    /// Supplies the actual fixed additional capture layouts without another read.
    ///
    /// # Errors
    /// Refuses absent/failed original capture or an unrepresentable layout sum.
    pub fn fixed_capture_memory_bytes(&self) -> Result<usize, CacheResidentUnavailableV1> {
        if self.initialization.q04_capture_blocked()
            || self
                .initialization
                .q04_capture_shape
                .as_ref()
                .is_none_or(Result::is_err)
        {
            return Err(CacheResidentUnavailableV1);
        }
        let state = std::mem::size_of::<(
            Self,
            OriginalQ04CacheOwnerCutV1<'_>,
            Option<ShapeResult>,
            [Option<ShapeResult>; SHAPE_POSTS],
            usize,
            Option<CacheReplayControllerBootstrapErrorV1>,
            OriginalQ04CacheSourceShapeV1,
            OriginalQ04CacheSourceShapeV1,
        )>();
        // Each prepared value has a callee constructor, an ABI Result return
        // and a caller-held value across its actual upper-only frontier. These
        // are control planes; the existing Q recipe retains backing separately.
        let frontiers = prepared_return_bytes_v1::<
            super::original_q04::CacheQ04RecipeCaptureBorrowV1<'_, '_, '_>,
        >()
        .and_then(|bytes| {
            bytes.checked_add(prepared_return_bytes_v1::<
                super::original_q04::CacheQ04ReleaseBindingBorrowV1<'_, '_, '_, '_, '_>,
            >()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(prepared_return_bytes_v1::<
                super::original_q04::CacheQ04AppendOriginalBorrowV1<'_, '_, '_, '_, '_>,
            >()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(prepared_return_bytes_v1::<
                super::original_q04::CacheQ04TerminalBorrowV1<'_, '_, '_, '_, '_>,
            >()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(prepared_return_bytes_v1::<
                super::original_q04::CacheQ04SigningBorrowV1<'_, '_, '_, '_, '_>,
            >()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(prepared_return_bytes_v1::<
                super::original_q04::CacheQ04UnsignedSigningBorrowV1<'_, '_, '_, '_, '_>,
            >()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(prepared_return_bytes_v1::<
                super::original_q04::CacheQ04FinalCompletionBorrowV1<'_, '_, '_, '_, '_>,
            >()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<(Result<(), crate::CacheQ04ErrorV1>, bool)>().checked_mul(2)?,
            )
        })
        .ok_or(CacheResidentUnavailableV1)?;
        crate::DormantCacheOwnerV1::original_q04_recheck_scratch_bytes()
            .checked_add(state)
            .and_then(|bytes| bytes.checked_add(frontiers))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::original_q04::Q04ResidentCacheProgressV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(crate::protected_journal::q04_readback_control_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(super::original_q04::append_receiving_control_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_broker::canonical_journal::preflight::schedule::control_receiving_bytes_v1::<crate::CacheJournalErrorV1>()?))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_broker::canonical_journal::preflight::schedule::model_receiving_bytes_v1()?))
            .ok_or(CacheResidentUnavailableV1)
    }

    /// Retains an independent same-original shape result before capture.
    ///
    /// # Errors
    /// Refuses changed originals, earlier uncertainty or a fourth observation.
    pub fn require_shape(&mut self) -> Result<(), CacheResidentUnavailableV1> {
        let index = self.initialization.q04_capture_post_count;
        if self.initialization.q04_capture_blocked()
            || index >= SHAPE_POSTS
            || self
                .initialization
                .q04_capture_shape
                .as_ref()
                .is_none_or(Result::is_err)
            || self.initialization.q04_capture_posts[..index]
                .iter()
                .any(|result| result.as_ref().is_none_or(Result::is_err))
        {
            return Err(CacheResidentUnavailableV1);
        }
        let returned = self.observe_shape();
        if returned.is_err() {
            self.initialization
                .first_failure
                .get_or_insert(InitializationCauseV1::Q04Preflight);
        }
        self.initialization.q04_capture_posts[index] = Some(returned);
        self.initialization.q04_capture_post_count = index + 1;

        let original = self
            .initialization
            .q04_capture_shape
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheResidentUnavailableV1)?;
        let observed = self.initialization.q04_capture_posts[index]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheResidentUnavailableV1)?;
        if !original.same_original(observed) {
            self.initialization.q04_capture_changed =
                Some(CacheReplayControllerBootstrapErrorV1::InvalidSource);
            self.initialization
                .first_failure
                .get_or_insert(InitializationCauseV1::Q04Preflight);
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Consumes these same originals only after the actual Q was committed.
    ///
    /// # Errors
    /// Refuses unpaid Q, changed geometry or the existing held-cut validation.
    /// Original failures stay resident; this never opens replacement owners.
    pub fn require_prepared_native_capture_v1(&self) -> Result<(), CacheResidentUnavailableV1> {
        if !self.initialization.q04_capture_ready_to_begin() {
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Consumes the same prepared native capture after the upper paid-intake check.
    ///
    /// This is an observation-only held cut. Every mutation additionally
    /// requires the real same-wire Root flight, never this shape or a bool.
    ///
    /// # Errors
    /// Retains the actual third native shape and held-owner refusal.
    pub fn begin_native_after_intake_v1(
        mut self,
    ) -> Result<OriginalQ04CacheOwnerCutV1<'cache>, CacheResidentUnavailableV1> {
        self.require_prepared_native_capture_v1()?;
        self.require_shape()?;
        let Self {
            initialization,
            owner,
            physical,
        } = self;
        initialization.begin_original_q04(owner, physical)
    }

    fn observe_shape(&mut self) -> ShapeResult {
        let reject = || CacheReplayControllerBootstrapErrorV1::InvalidSource;
        if !self.initialization.complete
            || self.initialization.first_failure.is_some()
            || self.initialization.postcheck.is_some()
            || self.initialization.q04.has_started()
        {
            return Err(reject());
        }
        let clock = self.initialization.clock.as_ref().ok_or_else(reject)?;
        if self
            .owner
            .clock
            .as_ref()
            .is_none_or(|owner_clock| !Arc::ptr_eq(clock, owner_clock))
            || self.initialization.physical_limits != Some(self.physical.limits())
        {
            return Err(reject());
        }
        let source = self.initialization.source.as_mut().ok_or_else(reject)?;
        if source.owner_uid() != self.owner.owner_uid {
            return Err(reject());
        }
        let source = source.capture_original_q04_shape()?;
        let state = self.owner.state_journal.as_ref().ok_or_else(reject)?;
        Ok(OriginalQ04CacheCaptureShapeV1 {
            source,
            initialization: self.initialization as *const _ as usize,
            owner: self.owner as *const _ as usize,
            physical: self.physical as *const _ as usize,
            clock: Arc::as_ptr(clock) as usize,
            state: state as *const _ as usize,
            authority: Arc::as_ptr(&self.owner.authority) as usize,
            uid: self.owner.owner_uid,
            physical_limits: self.physical.limits(),
            physical_head: self.physical.currentness(),
        })
    }
}

impl CacheResidentInitializationV1 {
    fn q04_capture_blocked(&self) -> bool {
        !self.complete
            || self.first_failure.is_some()
            || self.postcheck.is_some()
            || self.q04.has_started()
            || self.q04_capture_changed.is_some()
    }

    fn q04_capture_ready_to_begin(&self) -> bool {
        !self.q04_capture_blocked()
            && self.q04_capture_shape.as_ref().is_some_and(Result::is_ok)
            && self.q04_capture_post_count == SHAPE_POSTS - 1
            && self.q04_capture_posts[..SHAPE_POSTS - 1]
                .iter()
                .all(|result| result.as_ref().is_some_and(Result::is_ok))
            && self.q04_capture_posts[SHAPE_POSTS - 1].is_none()
    }

    pub(super) fn q04_capture_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.q04_capture_shape
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.q04_capture_posts.iter().find_map(|result| {
                    result
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn std::error::Error + 'static))
                })
            })
            .or_else(|| {
                self.q04_capture_changed
                    .as_ref()
                    .map(|cause| cause as &(dyn std::error::Error + 'static))
            })
    }
}

// The concrete callers above form the finite roster. This helper measures only
// layouts and cannot select a recipe, admit funding or construct any borrower.
fn prepared_return_bytes_v1<T>() -> Option<usize> {
    std::mem::size_of::<T>()
        .checked_mul(2)?
        .checked_add(std::mem::size_of::<Result<T, ()>>())
}
