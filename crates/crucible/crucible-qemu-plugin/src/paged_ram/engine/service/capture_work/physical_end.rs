//! Retains the genuine native physical-end call and independent observation.
//!
//! These process-private scalars match the frozen native SDK shape. They issue no
//! exclusion, Original, worker or physical-return authority. Only a fresh
//! same-token receipt written by the actual resolved native producer can
//! consume this body's cleanup identity. Matching declarations alone do not
//! establish native implementation correctness or runtime activation.

// SPDX-License-Identifier: GPL-2.0-only

use super::*;

pub(super) const LIFECYCLE_IDLE: u8 = 0;
const LIFECYCLE_ACTION: u8 = 1;
const LIFECYCLE_CLEANUP: u8 = 2;

const END_SCHEMA_VERSION: u32 = 2;
const END_STAGE_COUNT: usize = 7;
const END_STAGE_MASK: u64 = (1_u64 << END_STAGE_COUNT) - 1;

/// Matches one exact scalar stage in the private native receipt.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::paged_ram::engine) struct NativeReleaseStep {
    attempts: u64,
    first_status: i32,
    last_status: i32,
    effect_status: i32,
    post_status: i32,
    unlock_status: i32,
    entered: u32,
    released: u32,
    post_entered: u32,
    post_returned: u32,
    post_complete: u32,
    complete: u32,
    uncertain: u32,
}

/// Matches the actual versioned native physical-end output, without pointers.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::paged_ram::engine) struct NativePhysicalEnd {
    schema_version: u32,
    struct_size: u32,
    token: u64,
    required_mask: u64,
    attempted_mask: u64,
    released_mask: u64,
    complete_mask: u64,
    uncertain_mask: u64,
    first_status: i32,
    last_status: i32,
    entered: u32,
    exclusion_revoked: u32,
    effects_complete: u32,
    return_complete: u32,
    stage: [NativeReleaseStep; END_STAGE_COUNT],
}

impl NativePhysicalEnd {
    fn initialized() -> Result<Self, RamError> {
        let struct_size = u32::try_from(size_of::<Self>())
            .map_err(|_| RamError::Invariant("native end receipt extent overflow"))?;
        Ok(Self {
            schema_version: END_SCHEMA_VERSION,
            struct_size,
            ..Self::default()
        })
    }

    // Unchanged initialized output is a refusal, never a return witness. The
    // producer intentionally leaves refused spans untouched.
    fn check(&self, token: u64) -> Result<bool, RamError> {
        if self.token == 0 {
            return Ok(false);
        }
        if token == 0
            || self.token != token
            || self.schema_version != END_SCHEMA_VERSION
            || self.struct_size as usize != size_of::<Self>()
            || self.first_status > 0
            || self.last_status > 0
        {
            return Err(RamError::Invariant(
                "native end receipt identity or shape changed",
            ));
        }
        for flag in [
            self.entered,
            self.exclusion_revoked,
            self.effects_complete,
            self.return_complete,
        ] {
            if flag > 1 {
                return Err(RamError::Invariant("native end receipt flag is invalid"));
            }
        }
        if self.entered != self.exclusion_revoked
            || (self.required_mask
                | self.attempted_mask
                | self.released_mask
                | self.complete_mask
                | self.uncertain_mask)
                & !END_STAGE_MASK
                != 0
            || self.attempted_mask & !self.required_mask != 0
            || self.released_mask & !self.attempted_mask != 0
            || self.complete_mask & !self.released_mask != 0
            || self.uncertain_mask & !self.attempted_mask != 0
            || self.complete_mask & self.uncertain_mask != 0
        {
            return Err(RamError::Invariant(
                "native end receipt masks are inconsistent",
            ));
        }
        for (index, stage) in self.stage.iter().enumerate() {
            for flag in [
                stage.entered,
                stage.released,
                stage.post_entered,
                stage.post_returned,
                stage.post_complete,
                stage.complete,
                stage.uncertain,
            ] {
                if flag > 1 {
                    return Err(RamError::Invariant("native end stage flag is invalid"));
                }
            }
            for status in [
                stage.first_status,
                stage.last_status,
                stage.effect_status,
                stage.post_status,
                stage.unlock_status,
            ] {
                if status > 0 {
                    return Err(RamError::Invariant("native end stage status is invalid"));
                }
            }
            if stage.post_returned > stage.post_entered || stage.post_complete > stage.post_returned
            {
                return Err(RamError::Invariant(
                    "native end post history is inconsistent",
                ));
            }
            let bit = 1_u64 << index;
            if (stage.entered != 0) != (self.attempted_mask & bit != 0)
                || (stage.released != 0) != (self.released_mask & bit != 0)
                || (stage.complete != 0) != (self.complete_mask & bit != 0)
                || (stage.uncertain != 0) != (self.uncertain_mask & bit != 0)
            {
                return Err(RamError::Invariant("native end stage and summary disagree"));
            }
        }
        if self.return_complete != 0
            && (self.entered == 0
                || self.effects_complete == 0
                || self.uncertain_mask != 0
                || self.complete_mask & self.required_mask != self.required_mask)
        {
            return Err(RamError::Invariant(
                "native end returned incomplete custody",
            ));
        }
        Ok(true)
    }
}

/// Keeps both actual API results and their outputs in one already paid body.
pub(super) struct PhysicalEndCustody {
    token: u64,
    birth_status: i32,
    birth_entered: bool,
    birth_returned: bool,
    cleanup_held: bool,
    join_result: Option<Result<(), RamError>>,
    join_pre: Option<Result<(), RamError>>,
    join_return: Option<Result<(), RamError>>,
    join_physical_returned: bool,
    join_post: Option<Result<(), RamError>>,
    invoked: bool,
    call_returned: bool,
    call_status: i32,
    call_output: NativePhysicalEnd,
    observation_attempts: u64,
    observation_returned: bool,
    observation_status: i32,
    observation_output: NativePhysicalEnd,
    first_observation_status: Option<i32>,
    first_observation_output: Option<NativePhysicalEnd>,
    observation_running: bool,
    observation_runner_entered: bool,
    observation_runner_returned: bool,
    observation_runner_status: i32,
    first_observation_runner_status: Option<i32>,
    observation_callback_entered: bool,
    observation_callback_returned: bool,
    observation_callback_status: i32,
    first_observation_callback_status: Option<i32>,
    observation_pre: Option<Result<(), RamError>>,
    observation_post: Option<Result<(), RamError>>,
    first_observation_pre_failure: Option<RamError>,
    first_observation_post_failure: Option<RamError>,
    latest_valid: Option<NativePhysicalEnd>,
    returned: bool,
    first_failure: Option<RamError>,
    gate_failure: Option<RamError>,
}

impl PhysicalEndCustody {
    pub(super) fn new() -> Result<Self, RamError> {
        let initialized = NativePhysicalEnd::initialized()?;
        Ok(Self {
            token: 0,
            birth_status: 0,
            birth_entered: false,
            birth_returned: false,
            cleanup_held: false,
            join_result: None,
            join_pre: None,
            join_return: None,
            join_physical_returned: false,
            join_post: None,
            invoked: false,
            call_returned: false,
            call_status: 0,
            call_output: initialized,
            observation_attempts: 0,
            observation_returned: false,
            observation_status: 0,
            observation_output: initialized,
            first_observation_status: None,
            first_observation_output: None,
            observation_running: false,
            observation_runner_entered: false,
            observation_runner_returned: false,
            observation_runner_status: 0,
            first_observation_runner_status: None,
            observation_callback_entered: false,
            observation_callback_returned: false,
            observation_callback_status: 0,
            first_observation_callback_status: None,
            observation_pre: None,
            observation_post: None,
            first_observation_pre_failure: None,
            first_observation_post_failure: None,
            latest_valid: None,
            returned: false,
            first_failure: None,
            gate_failure: None,
        })
    }

    fn retain_failure(&mut self, failure: RamError) {
        if self.first_failure.is_none() {
            self.first_failure = Some(failure);
        }
    }

    fn accept_snapshot(&mut self, output: NativePhysicalEnd) {
        match output.check(self.token) {
            Ok(true) => {
                // The actual producer's physical fact is sticky. A subsequent
                // observer refusal or negative semantic history cannot undo it.
                self.returned |= output.return_complete != 0;
                self.latest_valid = Some(output);
                if output.first_status != 0 {
                    self.retain_failure(RamError::Native {
                        operation: "native physical end first cause",
                        status: output.first_status,
                    });
                }
            }
            Ok(false) => {}
            Err(error) => self.retain_failure(error),
        }
    }

    fn observe(&mut self, native: NativeOperations) -> Result<(), RamError> {
        self.observation_attempts = self
            .observation_attempts
            .checked_add(1)
            .ok_or("native end observation count exhausted")?;
        self.observation_output = NativePhysicalEnd::initialized()?;
        self.observation_returned = false;
        let status = (native.end_observe)(self.token, &mut self.observation_output);
        // Save function result AND actual output before interpreting either.
        self.observation_status = status;
        self.observation_returned = true;
        if self.first_observation_status.is_none() {
            self.first_observation_status = Some(status);
            self.first_observation_output = Some(self.observation_output);
        }
        self.accept_snapshot(self.observation_output);
        if status != 0 {
            self.retain_failure(RamError::Native {
                operation: "native physical end identity observation",
                status,
            });
        }
        Ok(())
    }

    fn finish(
        &mut self,
        native: NativeOperations,
        dispatch: &PlacementDispatchJournal,
    ) -> Result<EndOutcome, RamError> {
        if self.token == 0 || self.invoked {
            return Err(RamError::Invariant(
                "native physical end cannot be replayed",
            ));
        }
        self.call_output = NativePhysicalEnd::initialized()?;
        self.invoked = true;
        dispatch.end_entered.store(true, Ordering::Release);
        let status = (native.end)(self.token, &mut self.call_output);
        // A negative can coexist with a fresh returned receipt. Neither a
        // signed result nor preinitialized caller storage consumes identity.
        self.call_status = status;
        self.call_returned = true;
        dispatch.end_status.store(status, Ordering::Release);
        dispatch.end_returned.store(true, Ordering::Release);
        dispatch.record_first_negative(status);
        self.accept_snapshot(self.call_output);
        if status != 0 {
            self.retain_failure(RamError::Native {
                operation: "native physical end invocation",
                status,
            });
        }
        if let Err(error) = self.observe(native) {
            self.retain_failure(error);
        }
        if !self.returned && self.first_failure.is_none() {
            self.retain_failure(RamError::Invariant(
                "native physical end remains unresolved",
            ));
        }
        Ok(self.outcome())
    }

    fn record_observation_dispatch(&mut self, status: i32) {
        self.observation_runner_status = status;
        self.observation_runner_returned = true;
        if self.first_observation_runner_status.is_none() {
            self.first_observation_runner_status = Some(status);
        }
        if status != 0 {
            self.retain_failure(RamError::Native {
                operation: "native physical end observation dispatch",
                status,
            });
        }
        if !self.observation_callback_returned {
            self.retain_failure(RamError::Invariant(
                "native end observation callback omitted",
            ));
        }
    }

    fn save_observation_attempt(&mut self, attempt: OwnedObservationAttempt) {
        self.observation_pre = Some(attempt.pre.clone());
        if let Err(error) = attempt.pre {
            if self.first_observation_pre_failure.is_none() {
                self.first_observation_pre_failure = Some(error.clone());
            }
            self.retain_failure(error);
        }
        if let Some(Err(error)) = attempt.dispatch {
            self.retain_failure(error);
        }
        self.observation_post = Some(attempt.post.clone());
        if let Err(error) = attempt.post {
            if self.first_observation_post_failure.is_none() {
                self.first_observation_post_failure = Some(error.clone());
            }
            self.retain_failure(error);
        }
        // Running includes the independent owned post even if pre refused and
        // no native callback was entered. Only this actual completion clears it.
        self.observation_running = false;
    }

    pub(super) fn unresolved(&self) -> bool {
        (self.token != 0 && !self.returned)
            || (self.birth_entered && !self.birth_returned)
            || self.cleanup_held
            || self.observation_running
            || self.first_failure.is_some()
            || self.gate_failure.is_some()
    }

    fn outcome(&self) -> EndOutcome {
        EndOutcome {
            returned: self.returned,
            failure: self.first_failure.clone(),
        }
    }
}

/// Reports retained facts after the actual native calls, never a caller grant.
pub(in crate::paged_ram::engine) struct EndOutcome {
    pub(in crate::paged_ram::engine) returned: bool,
    pub(in crate::paged_ram::engine) failure: Option<RamError>,
}

impl FaultWorkOwner {
    /// Refuses a new action while actual cleanup identity or failure is retained.
    ///
    /// # Errors
    /// Refuses prior unknown end, failed post or a missing body.
    pub(in crate::paged_ram::engine) fn require_end_ready(&self) -> Result<(), RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if body.end_pending.load(Ordering::Acquire)
            || body.end_failed.load(Ordering::Acquire)
            || body
                .end
                .try_lock()
                .map_or(true, |custody| custody.unresolved())
        {
            return Err(RamError::Invariant(
                "native physical end custody remains retained",
            ));
        }
        Ok(())
    }

    // The actual mutex slot is acquired before any native birth. Cleanup takes
    // the same admission before requesting an Original, so contention refuses
    // before either side can expose an unbound birth or join a live creator.
    fn prepare_physical_birth(&self) -> Result<MutexGuard<'_, PhysicalEndCustody>, RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        let custody = body
            .end
            .try_lock()
            .map_err(|_| "native end custody unavailable")?;
        if body.end_pending.load(Ordering::Acquire)
            || body.end_failed.load(Ordering::Acquire)
            || body.placement.load(Ordering::Acquire)
            || custody.unresolved()
        {
            return Err(RamError::Invariant(
                "native physical birth custody remains retained",
            ));
        }
        Ok(custody)
    }

    /// Creates only through the actual service, recording output in its paid slot.
    ///
    /// No fallible borrow follows native begin. The real output and raw status
    /// are saved before either caller or cleanup-facing cache can see the birth.
    /// The slot mutex excludes cleanup admission throughout actual construction;
    /// it is neither a Source mutex nor an actor/work lock.
    ///
    /// # Errors
    /// Refuses a foreign/stopping service or unavailable custody before calling
    /// native code. Returned native status remains independent of its born token.
    pub(in crate::paged_ram::engine) fn begin_physical(
        &self,
        service: &FaultService,
        generation: u64,
        action: &PhysicalActionAdmission<'_>,
    ) -> Result<PhysicalBirth, RamError> {
        if !std::ptr::eq(self, &service.capture_work)
            || !std::ptr::eq(self, action.owner)
            || action.body.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTION
        {
            return Err(RamError::Invariant("native physical birth service changed"));
        }
        let mut custody = self.prepare_physical_birth()?;
        if service.stop.load(Ordering::Acquire) || service.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "native physical birth service is stopping",
            ));
        }
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        *custody = PhysicalEndCustody::new()?;
        custody.birth_entered = true;
        body.dispatch.begin_entered.store(true, Ordering::Release);
        let status = (service.native.begin)(generation, &mut custody.token);
        custody.birth_status = status;
        custody.birth_returned = true;
        let token = custody.token;
        body.dispatch.token.store(token, Ordering::Release);
        body.dispatch.begin_status.store(status, Ordering::Release);
        body.dispatch.begin_returned.store(true, Ordering::Release);
        body.dispatch.record_first_negative(status);
        body.end_pending.store(token != 0, Ordering::Release);
        if token != 0 && status != 0 {
            custody.retain_failure(RamError::Native {
                operation: "native physical begin",
                status,
            });
            body.end_failed.store(true, Ordering::Release);
        }
        // This is only a cache of the bound canonical output. Cleanup admission
        // always inspects the same actual slot before deciding it can join.
        service.retained_token.store(token, Ordering::Release);
        Ok(PhysicalBirth { token, status })
    }

    /// Serializes one actual callback before any native begin or RAM action.
    ///
    /// This local entry gate issues no Source operation or native authority.
    /// Cleanup cannot borrow the journal of an already entered action, including
    /// while that action is about to acquire the journal for physical end.
    ///
    /// # Errors
    /// Refuses an active callback, retained teardown or absent paid body.
    pub(in crate::paged_ram::engine) fn admit_physical_action(
        &self,
    ) -> Result<PhysicalActionAdmission<'_>, RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        body.lifecycle
            .compare_exchange(
                LIFECYCLE_IDLE,
                LIFECYCLE_ACTION,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| "native physical lifecycle is already admitted")?;
        Ok(PhysicalActionAdmission { owner: self, body })
    }

    /// Reserves same-body teardown before requesting its existing Cleanup Original.
    ///
    /// CAS precedes the mutex: cleanup cannot steal the end-journal lock from an
    /// already entered callback. Failed admission owns no Original and cannot
    /// reach join. The actual paid guard remains through observation/join/posts.
    ///
    /// # Errors
    /// Refuses an active action, busy/poisoned journal or retained cleanup owner.
    pub(in crate::paged_ram::engine) fn admit_physical_cleanup(
        &self,
    ) -> Result<PhysicalCleanupAdmission<'_>, RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        body.lifecycle
            .compare_exchange(
                LIFECYCLE_IDLE,
                LIFECYCLE_CLEANUP,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| "native physical lifecycle is already admitted")?;
        let mut custody = match body.end.try_lock() {
            Ok(custody) => custody,
            Err(_) => {
                body.lifecycle.store(LIFECYCLE_IDLE, Ordering::Release);
                return Err(RamError::Invariant("native end custody unavailable"));
            }
        };
        if custody.cleanup_held
            || custody.observation_running
            || (custody.birth_entered && !custody.birth_returned)
        {
            body.lifecycle.store(LIFECYCLE_IDLE, Ordering::Release);
            return Err(RamError::Invariant(
                "native physical cleanup admission remains retained",
            ));
        }
        custody.cleanup_held = true;
        let observe =
            custody.token != 0 && (!custody.returned || body.placement.load(Ordering::Acquire));
        Ok(PhysicalCleanupAdmission {
            owner: self,
            body,
            identity: custody.token,
            token: observe.then_some(custody.token),
            first: custody.first_failure.clone(),
            custody,
        })
    }

    /// Keeps the initiating RAM failure with its actual retained birth.
    ///
    /// This records an error only; it cannot create cleanup identity or return.
    ///
    /// # Errors
    /// Refuses a missing body, mismatched birth or inaccessible fixed storage.
    pub(in crate::paged_ram::engine) fn retain_physical_action_failure(
        &self,
        token: u64,
        error: &RamError,
    ) -> Result<(), RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        let mut custody = body
            .end
            .try_lock()
            .map_err(|_| "native end custody unavailable")?;
        if token == 0 || custody.token != token {
            return Err(RamError::Invariant("native physical action owner changed"));
        }
        custody.retain_failure(error.clone());
        body.end_failed.store(true, Ordering::Release);
        Ok(())
    }

    /// Calls real end once and saves its independent identity observation.
    ///
    /// No new Original, clock or retry is issued. This runs only in the existing
    /// authenticated mainloop callback; the native owner checks that context.
    ///
    /// # Errors
    /// Refuses missing/foreign cleanup identity or inaccessible fixed storage.
    pub(in crate::paged_ram::engine) fn end_physical(
        &self,
        native: NativeOperations,
        token: u64,
    ) -> Result<EndOutcome, RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        let mut custody = body
            .end
            .try_lock()
            .map_err(|_| "native end custody unavailable")?;
        if custody.token != token || token == 0 {
            return Err(RamError::Invariant("native physical end owner changed"));
        }
        let outcome = custody.finish(native, &body.dispatch)?;
        body.end_pending.store(!outcome.returned, Ordering::Release);
        body.end_failed
            .store(outcome.failure.is_some(), Ordering::Release);
        Ok(outcome)
    }

    fn observe_end_on_mainloop(
        &self,
        native: NativeOperations,
        token: u64,
        custody: &mut PhysicalEndCustody,
    ) -> Result<(), RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if token == 0
            || custody.token != token
            || !custody.cleanup_held
            || !custody.observation_running
        {
            return Err(RamError::Invariant("native end callback owner changed"));
        }
        custody.observation_callback_entered = true;
        if let Err(error) = custody.observe(native) {
            custody.retain_failure(error);
        }
        body.end_pending.store(!custody.returned, Ordering::Release);
        body.end_failed
            .store(custody.first_failure.is_some(), Ordering::Release);
        // The actual guard already owns this exact journal. Identity observation
        // lends no RAM bytes; the separate actual work lock settles old scratch.
        let gate = if custody.returned {
            self.return_gate_with_custody(custody, token)
        } else {
            Ok(())
        };
        let result = custody.first_failure.clone().map_or(gate, Err);
        if let Err(error) = &result {
            custody.retain_failure(error.clone());
        }
        custody.observation_callback_status = if result.is_ok() { 0 } else { -libc::EIO };
        if custody.first_observation_callback_status.is_none() {
            custody.first_observation_callback_status = Some(custody.observation_callback_status);
        }
        custody.observation_callback_returned = true;
        result
    }

    /// Returns the actual scratch gate only from its same-token native receipt.
    ///
    /// # Errors
    /// Retains byte custody if physical return or scratch settlement is unproved.
    pub(in crate::paged_ram::engine) fn return_gate_after_end(
        &self,
        token: u64,
    ) -> Result<(), RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        let mut custody = body
            .end
            .try_lock()
            .map_err(|_| "native end custody unavailable")?;
        self.return_gate_with_custody(&mut custody, token)
    }

    fn return_gate_with_custody(
        &self,
        custody: &mut PhysicalEndCustody,
        token: u64,
    ) -> Result<(), RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        let result = (|| {
            if token == 0 || custody.token != token || !custody.returned {
                return Err(RamError::Invariant("native physical return is unproved"));
            }
            if !body.placement.load(Ordering::Acquire) {
                return Ok(());
            }
            let mut work = self.try_lock()?;
            if !body.scratch_returned.load(Ordering::Acquire) || work.unresolved() {
                return Err(RamError::Invariant(
                    "physical return retains scratch custody",
                ));
            }
            if custody.first_failure.is_some() {
                work.fail();
            }
            drop(work);
            body.scratch_returned.store(false, Ordering::Release);
            body.placement.store(false, Ordering::Release);
            Ok(())
        })();
        if let Err(error) = &result {
            if custody.gate_failure.is_none() {
                custody.gate_failure = Some(error.clone());
            }
            custody.retain_failure(error.clone());
            body.end_failed.store(true, Ordering::Release);
        }
        result
    }
}

/// Describes actual native output; it grants no validation or RAM access.
pub(in crate::paged_ram::engine) struct PhysicalBirth {
    pub(in crate::paged_ram::engine) token: u64,
    pub(in crate::paged_ram::engine) status: i32,
}

/// Retains local callback entry until its actual work/end/gate has returned.
///
/// Dropping this borrow cannot clear the phase; only the actual tail calls finish.
pub(in crate::paged_ram::engine) struct PhysicalActionAdmission<'a> {
    owner: &'a FaultWorkOwner,
    body: &'a FaultWorkAllocation,
}

impl PhysicalActionAdmission<'_> {
    /// Returns local entry after the actual callback's physical work is finished.
    ///
    /// # Errors
    /// Retains failed disposition when the same lifecycle state cannot return.
    pub(in crate::paged_ram::engine) fn finish(self) -> Result<(), RamError> {
        self.body
            .lifecycle
            .compare_exchange(
                LIFECYCLE_ACTION,
                LIFECYCLE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| {
                self.body.end_failed.store(true, Ordering::Release);
                self.body
                    .dispatch
                    .callback_post_failed
                    .store(true, Ordering::Release);
                RamError::Invariant("physical callback lifecycle changed")
            })?;
        Ok(())
    }
}

/// Excludes new birth until this exact teardown has physically settled.
///
/// Abandonment retains admission in the paid owner; Drop never joins or reopens.
pub(in crate::paged_ram::engine) struct PhysicalCleanupAdmission<'a> {
    owner: &'a FaultWorkOwner,
    body: &'a FaultWorkAllocation,
    custody: MutexGuard<'a, PhysicalEndCustody>,
    identity: u64,
    pub(in crate::paged_ram::engine) token: Option<u64>,
    pub(in crate::paged_ram::engine) first: Option<RamError>,
}

impl PhysicalCleanupAdmission<'_> {
    /// Retains factory refusal before an Original could be returned.
    pub(in crate::paged_ram::engine) fn retain_failure(&mut self, error: &RamError) {
        self.custody.retain_failure(error.clone());
        self.body.end_failed.store(true, Ordering::Release);
    }

    /// Observes retained cleanup through the existing Cleanup operation.
    ///
    /// The native runner lends only this synchronous callback. No begin, end,
    /// current, validation or RAM action is replayed; the same Cleanup Original
    /// pays both deadline checks. The exclusive journal is lent synchronously; no
    /// Source, Native, BQL, Root or work lock is retained by this journal guard.
    ///
    /// The outcome retains unknown identity and each actual pre/post or runner
    /// refusal. Physical return and semantic failure remain independent facts.
    pub(in crate::paged_ram::engine) fn observe_retained_end(
        &mut self,
        native: NativeOperations,
        operation: &dyn SourceOperation,
    ) -> EndOutcome {
        let body = self.body;
        let owner = self.owner;
        let token = self.token.unwrap_or(0);
        let custody = &mut *self.custody;
        custody.observation_running = true;
        custody.observation_runner_entered = false;
        custody.observation_runner_returned = false;
        custody.observation_callback_entered = false;
        custody.observation_callback_returned = false;
        custody.observation_pre = None;
        custody.observation_post = None;
        let attempt = run_owned_observation(operation, || {
            if token == 0 || custody.token != token || !custody.cleanup_held {
                return Err(RamError::Invariant("native end cleanup admission changed"));
            }
            custody.observation_runner_entered = true;
            let status = {
                let mut callback = EndObservationCallback {
                    owner,
                    native,
                    token,
                    custody: &mut *custody,
                };
                // The exclusive journal loan travels only through this existing
                // synchronous callback; the callback never reacquires its lock.
                (native.run)(
                    observe_physical_end,
                    (&mut callback as *mut EndObservationCallback<'_>).cast(),
                )
            };
            custody.record_observation_dispatch(status);
            Ok(())
        });
        // No fallible reborrow follows native work or the owned post. The same
        // already-paid guard retains every actual output before propagation.
        custody.save_observation_attempt(attempt);
        if !custody.returned && custody.first_failure.is_none() {
            custody.retain_failure(RamError::Invariant(
                "native physical end remains unresolved",
            ));
        }
        body.end_pending.store(!custody.returned, Ordering::Release);
        body.end_failed
            .store(custody.first_failure.is_some(), Ordering::Release);
        custody.outcome()
    }

    /// Records actual join/post facts independently of earlier logical failure.
    ///
    /// # Errors
    /// Retains the local admission if identity or actual physical/post return is
    /// unproved. Semantic failure remains retained even after admission returns.
    pub(in crate::paged_ram::engine) fn settle_after_join(
        mut self,
        joined: &WorkerJoinDisposition,
    ) -> Result<(), RamError> {
        let body = self.body;
        let custody = &mut *self.custody;
        custody.join_result = Some(joined.result.clone());
        custody.join_pre = joined.pre.clone();
        custody.join_return = joined.join.clone();
        custody.join_physical_returned = joined.physical_returned;
        custody.join_post = joined.post.clone();
        if let Err(error) = &joined.result {
            custody.retain_failure(error.clone());
            body.end_failed.store(true, Ordering::Release);
        }
        if !custody.cleanup_held
            || custody.token != self.identity
            || custody.observation_running
            || (custody.token != 0 && !custody.returned)
            || !joined.physical_returned
            || !matches!(joined.post.as_ref(), Some(Ok(())))
        {
            return Err(RamError::Invariant(
                "physical cleanup admission remains unsettled",
            ));
        }
        // This returns only the local birth/teardown exclusion. It does not
        // erase failed work, issue a new Original, restore health or refund it.
        body.lifecycle
            .compare_exchange(
                LIFECYCLE_CLEANUP,
                LIFECYCLE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| "physical cleanup lifecycle changed")?;
        custody.cleanup_held = false;
        Ok(())
    }
}

/// Saves both real owned checks even when pre forbids the native dispatch.
struct OwnedObservationAttempt {
    pre: Result<(), RamError>,
    dispatch: Option<Result<(), RamError>>,
    post: Result<(), RamError>,
}

fn run_owned_observation(
    operation: &dyn SourceOperation,
    dispatch: impl FnOnce() -> Result<(), RamError>,
) -> OwnedObservationAttempt {
    let pre = operation.wait_slice().map(|_| ()).map_err(RamError::from);
    let dispatch = if pre.is_ok() { Some(dispatch()) } else { None };
    let post = operation.wait_slice().map(|_| ()).map_err(RamError::from);
    OwnedObservationAttempt {
        pre,
        dispatch,
        post,
    }
}

/// Borrows only an existing owner and token until the synchronous runner returns.
struct EndObservationCallback<'a> {
    owner: &'a FaultWorkOwner,
    native: NativeOperations,
    token: u64,
    custody: &'a mut PhysicalEndCustody,
}

extern "C" fn observe_physical_end(opaque: *mut c_void) -> c_int {
    // SAFETY: the actual synchronous runner borrows this exclusive context
    // through callback return and retains no pointer. Its calling thread keeps
    // the journal guard and accesses none of the lent data while suspended.
    // This callback reborrows the same journal without locking or touching RAM.
    let callback = unsafe { &mut *opaque.cast::<EndObservationCallback<'_>>() };
    match callback
        .owner
        .observe_end_on_mainloop(callback.native, callback.token, callback.custody)
    {
        Ok(()) => 0,
        Err(_) => -libc::EIO,
    }
}

#[cfg(test)]
mod tests;
