//! Keeps canonical admission inside the same actual two-Session C18 borrower.
//!
//! The SDK continuously holds both Sessions. This finite crossing rechecks their
//! physical originals and original remote cutoffs, prepays native clock owners,
//! then borrows the sole Core admission kernel and existing append recipe.
//! No decoded response, detached Ready value or separate native owner can enter.

use aos_sandbox_model::RawPairedClockSample;

/// Keeps this actual Controller admission's native clock diagnostics concrete.
#[derive(Debug, thiserror::Error)]
enum ExecutionAdmissionClockErrorV2 {
    #[error("the original Execution admission clock is stale or incomplete")]
    Stale,
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
}

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for ExecutionAdmissionClockErrorV2 {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(cause: aos_sandbox_linux::Error) -> Self {
        Self::Kernel(cause)
    }
}

type Clock = aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<
    ExecutionAdmissionClockErrorV2,
>;

use super::*;

pub(super) struct ExecutionAvailabilityAdmissionOriginalV2 {
    geometry: Slot<ResourceVector, ResourceReservationErrorV1>,
    funding: Slot<(), ResourceReservationErrorV1>,
    host: Slot<(), ControllerExecutionAvailabilitySessionCurrentnessErrorV2>,
    storage: Slot<(), ControllerExecutionAvailabilitySessionCurrentnessErrorV2>,
    cutoff: Slot<u64, ResourceReservationErrorV1>,
    horizon: Slot<(RawPairedClockSample, i64, u64, u64), JournalError>,
    before_clock: Option<Box<Clock>>,
    before: Slot<RawPairedClockSample, ExecutionAdmissionClockErrorV2>,
    before_relation: Slot<(), JournalError>,
    crossing_clock: Option<Box<Clock>>,
    crossing: Slot<RawPairedClockSample, ExecutionAdmissionClockErrorV2>,
    crossing_relation: Slot<(), JournalError>,
    after_clock: Option<Box<Clock>>,
    after: Slot<RawPairedClockSample, ExecutionAdmissionClockErrorV2>,
    after_relation: Slot<(), JournalError>,
    reentry: Option<ResourceReservationErrorV1>,
}

impl ExecutionAvailabilityAdmissionOriginalV2 {
    pub(super) fn retained_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !matches!(self.funding, Some(Ok(()))) { return Ok(ResourceVector::ZERO); }
        self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            host: None,
            storage: None,
            cutoff: None,
            horizon: None,
            before_clock: None,
            before: None,
            before_relation: None,
            crossing_clock: None,
            crossing: None,
            crossing_relation: None,
            after_clock: None,
            after: None,
            after_relation: None,
            reentry: None,
        }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.geometry)
            .or_else(|| error(&self.funding))
            .or_else(|| error(&self.host))
            .or_else(|| error(&self.storage))
            .or_else(|| error(&self.cutoff))
            .or_else(|| error(&self.horizon))
            .or_else(|| self.before_clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| error(&self.before))
            .or_else(|| error(&self.before_relation))
            .or_else(|| {
                self.crossing_clock
                    .as_ref()
                    .and_then(|clock| clock.failure())
            })
            .or_else(|| error(&self.crossing))
            .or_else(|| error(&self.crossing_relation))
            .or_else(|| self.after_clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.after_relation))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    fn geometry_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = Clock::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = Clock::receiving_metadata_cells_v1()
            .and_then(|cells| cells.checked_mul(3))
            .and_then(|cells| u64::try_from(cells).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let files = u64::try_from(Clock::MAXIMUM_RETAINED_FILES_V1)
            .ok()
            .and_then(|files| files.checked_mul(3))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, names)
            .with(D::OpenFiles, files))
    }
}

impl ControllerExecutionAvailabilityClientLoanV2<'_> {
    /// Admits the retained compiler plan while the SDK still holds both Sessions.
    ///
    /// The exact service-owned pending bound affects admission policy only. It
    /// cannot select a payer, plan, native source, response or replacement D.
    ///
    /// # Errors
    /// Refuses incomplete/repeated preaccept, changed physical Sessions, expired
    /// original sources, failed receiving or any existing canonical Core check.
    /// A committed admission remains retained even if its owed after refuses.
    #[doc(hidden)]
    pub fn admit_prepared_public_request_once_v2(
        &mut self,
        maximum_pending_operations: usize,
        host_journal: &Journal,
        host_socket: &SeqpacketSocket,
        host_transcript: &VerifiedBrokerSessionTranscriptV1,
        storage_journal: &Journal,
        storage_socket: &SeqpacketSocket,
        storage_transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<crate::AcceptOutcome, ResourceReservationErrorV1> {
        if self.active != 2 || self.scope.prefix.accepted_outcome.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.original_v2()?;
        let original = self
            .scope
            .prefix
            .availability
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if original.admission.geometry.is_some() {
            original
                .admission
                .reentry
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.admission.geometry = Some(ExecutionAvailabilityAdmissionOriginalV2::geometry_v2());
        let incoming = original
            .admission
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let funding = self
            .complete_transport_base_v2(incoming)
            .and_then(|complete| self.require_transport_complete_v2(complete));
        let original = self
            .scope
            .prefix
            .availability
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        original.admission.funding = Some(funding);
        if !matches!(original.admission.funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.admission.host = Some(
            ExecutionAvailabilitySessionNativeOriginalV2::observe_same_v2(
                Some(&original.host),
                host_journal,
                host_socket,
                host_transcript,
            ),
        );
        original.admission.storage = Some(
            ExecutionAvailabilitySessionNativeOriginalV2::observe_same_v2(
                Some(&original.storage),
                storage_journal,
                storage_socket,
                storage_transcript,
            ),
        );
        original.admission.horizon = Some(
            self.scope
                .prefix
                .compiler
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|compiler| compiler.preaccept_horizon_checked_v2()),
        );
        original.admission.cutoff = Some(
            original
                .admission
                .horizon
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)
                .and_then(|horizon| {
                    original.io.preaccept_cutoff_data_v2(horizon.0.host_boot_id())
                }),
        );
        if !matches!(original.admission.host, Some(Ok(())))
            || !matches!(original.admission.storage, Some(Ok(())))
            || !matches!(original.admission.cutoff, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // These distinct, already-paid destinations remain reachable on every
        // later return, including a refused Core append and its owed after.
        original.admission.before_clock = Some(Box::new(Clock::default()));
        original.admission.crossing_clock = Some(Box::new(Clock::default()));
        original.admission.after_clock = Some(Box::new(Clock::default()));
        let before = self.observe_admission_bookend_v2(false);
        let returned = if before.is_ok() {
            match self.scope.prefix.plan.as_ref().map(Arc::clone) {
                Some(plan) => self
                    .controller
                    .admit_execution_publication_with_original_v2(
                        self.scope,
                        &plan,
                        maximum_pending_operations,
                    )
                    .map_err(crate::ControllerServiceError::Reconciler),
                None => Err(crate::ControllerServiceError::Reconciler(
                    crate::ReconcilerError::InvalidPlan("the original Execution plan is absent"),
                )),
            }
        } else {
            self.scope.prefix.first.get_or_insert(First::Availability);
            Err(crate::ControllerServiceError::Reconciler(
                crate::ReconcilerError::InvalidPlan(
                    "the original Execution interval is no longer current",
                ),
            ))
        };
        self.scope.retain_acceptance_once_v2(returned);
        // This native after runs even when the canonical body retained failure.
        let post = self.observe_admission_bookend_v2(true);
        let accepted = self
            .scope
            .prefix
            .accepted_outcome
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied();
        if post.is_err() {
            self.scope.prefix.first.get_or_insert(First::Availability);
        }
        post?;
        accepted.ok_or(ResourceReservationErrorV1::Conflict)
    }

    fn observe_admission_bookend_v2(
        &mut self,
        after: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        let original = self
            .scope
            .prefix
            .availability
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        // The already-armed after borrows retained original DATA even when the
        // body failed. A healthy-only scope getter must never suppress it.
        let horizon = original
            .admission
            .horizon
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let local_cutoff = original
            .cutoff
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let admission = &mut original.admission;
        let cutoff = admission
            .cutoff
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .min(local_cutoff);
        let (clock, result, relation) = if after {
            (
                &mut admission.after_clock,
                &mut admission.after,
                &mut admission.after_relation,
            )
        } else {
            (
                &mut admission.before_clock,
                &mut admission.before,
                &mut admission.before_relation,
            )
        };
        if result.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        *result = Some(
            clock
                .as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .observe_once(Some(horizon.0)),
        );
        *relation = Some(
            require_admission_clock_v2(result, horizon.0, horizon.1, cutoff).and_then(|()| {
                original
                    .io
                    .require_observed_before_data_v2(
                        result
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .ok_or(JournalError::ProtectedBoundary)?
                            .boottime_nanoseconds(),
                    )
                    .map_err(|_| JournalError::ProtectedBoundary)
            }),
        );
        if matches!(relation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}

impl ExecutionPublicAdmissionScopeV2 {
    pub(crate) fn require_availability_admission_crossing_once_v2(
        &mut self,
        controller: &Journal,
    ) -> Result<(), JournalError> {
        self.require_current_v2(controller)?;
        let source = self.preaccept_source_data_v2()?;
        let first = source.original_authorization_clock_v2();
        let expires = source.authorization_expires_v2();
        let original = self
            .prefix
            .availability
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        let local_cutoff = original
            .cutoff
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let admission = &mut original.admission;
        if !matches!(admission.before_relation, Some(Ok(()))) || admission.crossing.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let cutoff = admission
            .cutoff
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?
            .min(local_cutoff);
        admission.crossing = Some(
            admission
                .crossing_clock
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_once(Some(first)),
        );
        admission.crossing_relation = Some(require_admission_clock_v2(
            &admission.crossing,
            first,
            expires,
            cutoff,
        ));
        if matches!(admission.crossing_relation, Some(Ok(()))) {
            Ok(())
        } else {
            self.prefix.first.get_or_insert(First::Availability);
            Err(JournalError::ProtectedBoundary)
        }
    }
}

fn require_admission_clock_v2(
    current: &Slot<RawPairedClockSample, ExecutionAdmissionClockErrorV2>,
    first: RawPairedClockSample,
    expires: i64,
    cutoff: u64,
) -> Result<(), JournalError> {
    let current = current
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .copied()
        .ok_or(JournalError::ProtectedBoundary)?;
    first
        .validate_later_sample(current)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    if current.boottime_nanoseconds() >= cutoff || current.wall_seconds() >= expires {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(boot: [u8; 16], wall: i64, time: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            boot,
            wall,
            time,
        )
        .unwrap()
    }

    #[test]
    fn admission_uses_exclusive_original_and_remote_horizons() {
        let first = sample([1; 16], 100, 1_000_000_000);
        let current = Some(Ok(sample([1; 16], 101, 2_000_000_000)));
        assert!(require_admission_clock_v2(&current, first, 102, 2_000_000_001).is_ok());
        assert!(require_admission_clock_v2(&current, first, 102, 2_000_000_000).is_err());
        assert!(require_admission_clock_v2(&current, first, 101, 3_000_000_000).is_err());
        assert!(
            require_admission_clock_v2(
                &Some(Ok(sample([2; 16], 101, 2_000_000_000))),
                first,
                102,
                3_000_000_000
            )
            .is_err()
        );
        assert!(
            require_admission_clock_v2(
                &Some(Ok(sample([1; 16], 99, 2_000_000_000))),
                first,
                102,
                3_000_000_000
            )
            .is_err()
        );
    }

    #[test]
    fn retained_admission_clock_originals_are_send_and_sync() {
        fn require<T: Send + Sync>() {}
        require::<ExecutionAvailabilityAdmissionOriginalV2>();
    }
}
