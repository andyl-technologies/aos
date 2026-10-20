//! Pays and publishes a genuine Stop seed before its accepted graph is decoded.
//!
//! The initial-generation path delegates its unchanged existing body. A
//! recovered invocation requires the retained completed enrollment, a new
//! exact permanent B debit and its canonical row under independently owed
//! fresh Source/C/clock bookends. No Recover deadline is reused as permission.

use super::*;
use super::source::Pair;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use aos_sandbox_model::{OwnershipLeaseVerificationError, RawPairedClockSample};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;

type AppendError = crate::journal::JournalAppendReceivingDemandErrorV1;
const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;

#[derive(Clone, Copy)]
enum StopSeedEntryV4<'entry, 'completed> {
    Ordinary(&'entry crate::OperatorFirstLocalOrdinaryEnrollmentOriginalV2),
    Cleanup {
        completed: &'entry crate::OperatorStopCleanupRecoveryCompletedHandoffV1<'completed>,
        association: aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1,
        original: RawPairedClockSample,
    },
}

impl StopSeedEntryV4<'_, '_> {
    fn require_clock_v4(self, sample: RawPairedClockSample) -> Result<()> {
        let Self::Cleanup { completed, original, .. } = self else { return Ok(()); };
        original.validate_same_boot_elapsed_data_v1(sample).map_err(|_| CLOSED)?;
        let (cutoff, expiry) = completed.cleanup_authorization_horizon_data_v1()?;
        if sample.boottime_nanoseconds() >= cutoff || sample.wall_seconds() >= expiry {
            return Err(CLOSED);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum First { Geometry, Funding, Source, Clock, AppendGeometry, AppendFunding, Publication, Binding, Accepted, SourceAfter, ControllerAfter, FinalClock, Continuity, Disposal, Reentry }

#[derive(Default)]
pub(super) struct RecoveredStopSeedOriginalV3 {
    entered: bool,
    append_metadata: Option<std::io::Result<std::fs::Metadata>>,
    append: Option<std::result::Result<ResourceVector, AppendError>>,
    append_funding: Option<Result<()>>,
    geometry: Option<Result<ResourceVector>>,
    native_source: Option<Result<SourceProvisioningCurrentnessOriginalV1>>,
    before_native: Pair,
    after_native: Pair,
    before: Option<std::result::Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after: Option<std::result::Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    publication: Option<Result<()>>,
    binding: Option<Result<()>>,
    source_after: Option<std::result::Result<(), crate::JournalError>>,
    controller_after: Option<Result<()>>,
    continuity: Option<std::result::Result<(), OwnershipLeaseVerificationError>>,
    horizon: Option<Result<()>>,
    final_horizon: Option<Result<()>>,
    disposal: Option<Result<()>>,
    first: Option<First>,
}

impl RecoveredStopSeedOriginalV3 {
    fn geometry<T>(&mut self, controller: &Journal) -> Result<ResourceVector> {
        let models = crate::reconciler::accepted_public_effect_models_receiving_bytes_retaining_v4(controller)?;
        let bytes = std::mem::size_of::<ControllerLifecycleStopOriginalV4>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<T>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(models))
            .and_then(|bytes| bytes.checked_add(Pair::dominant_requested_bytes_v1()?.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
        let files = u64::try_from(Pair::MAXIMUM_RETAINED_FILES_V1.checked_mul(2).ok_or(CLOSED)?)
            .map_err(|_| CLOSED)?;
        let names = u64::try_from(Pair::receiving_metadata_cells_v1().and_then(|names| names.checked_mul(2))
            .ok_or(CLOSED)?).map_err(|_| CLOSED)?;
        ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files).with(D::MetadataEntries, names)
            .checked_add(ControllerLifecycleStopOriginalV4::inactive_receiving_demand_v4()?)?
            .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?).map_err(Into::into)
    }

    pub(super) fn failure<'owner>(&'owner self, native: Option<&'owner ControllerCreateProvisioningReceivingV1>)
        -> Option<&'owner (dyn Error + 'static)> {
        let marker = match self.first? {
            First::Geometry => error(&self.geometry),
            First::AppendGeometry => self.append_metadata.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.append.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)),
            First::AppendFunding => native.and_then(|native| native.failure()).or_else(|| error(&self.append_funding)),
            First::Funding => native.and_then(|native| native.failure()),
            First::ControllerAfter => native.and_then(|native| native.failure())
                .or_else(|| error(&self.controller_after)),
            First::Source => self.native_source.as_ref().and_then(|value| match value {
                Ok(native) => native.failure(), Err(cause) => Some(cause as &(dyn Error + 'static)),
            }),
            First::Clock => self.before_native.failure()
                .or_else(|| self.before.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
                .or_else(|| error(&self.horizon)),
            First::Publication => native.and_then(|native| native.recovered_stop_publication_local_failure_v3())
                .or_else(|| error(&self.publication)),
            First::Binding => error(&self.binding),
            First::SourceAfter => self.source_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::FinalClock => self.after_native.failure().or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Continuity => self.continuity.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
                .or_else(|| error(&self.final_horizon)),
            First::Disposal => error(&self.disposal),
            First::Accepted | First::Reentry => None,
        };
        marker
    }
}

impl ControllerLifecycleStopOriginalV4 {
    /// Uses an actual recovered Stop seed or the unchanged initial entry.
    ///
    /// # Errors
    /// Retains missing enrollment, funding, native publication, accepted graph
    /// or independent post refusal without adopting a predecessor intake.
    pub fn prepare_accepted_with_recovered_enrollment_once_v6<T>(&mut self,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        enrolled: &crate::OperatorFirstLocalOrdinaryEnrollmentOriginalV2,
    ) -> Result<()> {
        self.prepare_stop_seed_engine_v4::<T>(controller, source, StopSeedEntryV4::Ordinary(enrolled))
    }

    pub(super) fn prepare_cleanup_seed_once_v1<T>(&mut self,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        completed: &crate::OperatorStopCleanupRecoveryCompletedHandoffV1<'_>,
        association: aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1,
        original: RawPairedClockSample,
    ) -> Result<()> {
        self.prepare_stop_seed_engine_v4::<T>(controller, source,
            StopSeedEntryV4::Cleanup { completed, association, original })
    }

    fn prepare_stop_seed_engine_v4<T>(&mut self,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        origin: StopSeedEntryV4<'_, '_>,
    ) -> Result<()> {
        let recovered = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .lifecycle_stop_requires_recovered_seed_v3();
        if !recovered && matches!(origin, StopSeedEntryV4::Ordinary(_)) {
            return self.prepare_accepted_once_v4::<T>(controller);
        }
        if self.entered {
            self.first.get_or_insert(super::First::Reentry);
            self.recovered_seed.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.entered = true;
        let seed = &mut self.recovered_seed;
        seed.entered = true;
        seed.geometry = Some(seed.geometry::<T>(controller).and_then(|fixed| {
            if matches!(origin, StopSeedEntryV4::Cleanup { .. }) {
                fixed.checked_add(super::cleanup::StopCleanupOriginalV1::fixed_demand(controller)?)
                    .map_err(Into::into)
            } else { Ok(fixed) }
        }));
        let primary = (|| {
            let complete = seed.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
                .ok_or_else(|| { seed.first = Some(First::Geometry); CLOSED })?;
            self.geometry = Some(Ok(complete));
            self.native = Some((|| {
                // Lock and validate while the old payer is still parked. Every
                // fallible handoff returns that same owning payer on refusal.
                let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
                if matches!(origin, StopSeedEntryV4::Cleanup { .. }) && self.retained_stop_intake.is_some() {
                    return Err(CLOSED);
                }
                if let Some(intake) = self.retained_stop_intake.as_ref() {
                    bank.require_retained_lifecycle_stop_entry_v3(intake, controller, self.profile.as_ref())?;
                }
                if let Some(intake) = self.retained_stop_intake.take() {
                    match bank.begin_retained_recovered_lifecycle_stop_native_v3(
                        intake, controller, self.profile.as_ref(), complete,
                    ) {
                        Ok(native) => Ok(native),
                        Err((intake, cause)) => { self.retained_stop_intake = Some(intake); Err(cause) }
                    }
                } else {
                    match origin {
                        StopSeedEntryV4::Ordinary(enrolled) => bank.begin_recovered_lifecycle_stop_native_v3(
                            enrolled, controller, self.profile.as_ref(), complete),
                        StopSeedEntryV4::Cleanup { completed, association, .. } => bank.begin_host_stop_cleanup_native_v1(
                            completed, association, controller, self.profile.as_ref(), complete),
                    }
                }
            })());
            let native = self.native.as_mut().and_then(|value| value.as_mut().ok())
                .ok_or_else(|| { seed.first = Some(First::Funding); CLOSED })?;
            if native.failure().is_some() { seed.first = Some(First::Funding); return Err(CLOSED); }
            seed.native_source = Some((|| {
                self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .begin_provisioning_source_native_v1(native, controller, source.journal(), self.profile.as_ref(), complete)
            })());
            if seed.native_source.as_ref().and_then(|value| value.as_ref().ok())
                .is_none_or(|source| source.failure().is_some())
            { seed.first = Some(First::Source); return Err(CLOSED); }
            seed.before = Some(seed.before_native.observe_once(None));
            if !matches!(seed.before, Some(Ok(_))) { seed.first = Some(First::Clock); return Err(CLOSED); }
            seed.horizon = Some(origin.require_clock_v4(*seed.before.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?));
            if !matches!(seed.horizon, Some(Ok(()))) { seed.first = Some(First::Clock); return Err(CLOSED); }
            if native.requires_recovered_stop_seed_publication_v3() {
                // This real fstat is reached only after the genuine seed paid
                // its fixed destination and the C/Source native before. Keep
                // the actual result through every independent post.
                seed.append = Some(controller.append_receiving_demand_retaining_metadata_v6(
                    std::iter::once(aos_sandbox_journal::geometry::RecordShape {
                        key_bytes: 17,
                        value_bytes: Some(match origin {
                            StopSeedEntryV4::Ordinary(_) => aos_sandbox_protocol::domain_ledger::resource_bank::RECOVERED_LIFECYCLE_STOP_SEED_BYTES_V2,
                            StopSeedEntryV4::Cleanup { .. } => aos_sandbox_protocol::domain_ledger::resource_bank::RECOVERED_HOST_STOP_CLEANUP_SEED_BYTES_V1,
                        }),
                    }), &mut seed.append_metadata,
                ));
                let Some(append) = seed.append.as_ref().and_then(|value| value.as_ref().ok()).copied() else {
                    seed.first = Some(First::AppendGeometry);
                    return Err(CLOSED);
                };
                seed.append_funding = Some((|| {
                    self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                        .require_lifecycle_stop_seed_publication_complete_v3(native, controller,
                            self.profile.as_ref(), complete.checked_add(append)?)
                })());
                if !matches!(seed.append_funding, Some(Ok(()))) {
                    seed.first = Some(First::AppendFunding);
                    return Err(CLOSED);
                }
                seed.publication = Some((|| {
                    self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                        .publish_recovered_lifecycle_stop_seed_v3(native, controller, self.profile.as_ref())
                })());
                if !matches!(seed.publication, Some(Ok(()))) { seed.first = Some(First::Publication); return Err(CLOSED); }
            }
            seed.binding = Some((|| {
                self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_recovered_lifecycle_stop_seed_v3(native, controller, self.profile.as_ref())
            })());
            if !matches!(seed.binding, Some(Ok(()))) { seed.first = Some(First::Binding); return Err(CLOSED); }
            // Only the genuine debit, exact protected seed and finite original
            // association permit this single paid accepted Stop decoder.
            self.accepted = Some(crate::reconciler::accepted_stop_effect_from_journal_v4(controller, self.operation));
            if !matches!(self.accepted, Some(Ok(Some(_)))) { seed.first = Some(First::Accepted); return Err(CLOSED); }
            Ok(())
        })();
        if let Some(Ok(source_native)) = seed.native_source.as_mut() {
            seed.source_after = Some(source.journal_ref_v1().finish_source_provisioning_native_v1(source_native));
            if !matches!(seed.source_after, Some(Ok(()))) { seed.first.get_or_insert(First::SourceAfter); }
        }
        if let Some(Ok(native)) = self.native.as_mut() {
            seed.controller_after = Some((|| {
                self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .finish_lifecycle_stop_native_once_v4(native, controller, self.profile.as_ref())
            })());
            if !matches!(seed.controller_after, Some(Ok(()))) { seed.first.get_or_insert(First::ControllerAfter); }
        }
        if seed.native_source.as_ref().is_some_and(std::result::Result::is_ok) {
            seed.after = Some(seed.after_native.observe_once(seed.before.as_ref().and_then(|value| value.as_ref().ok()).copied()));
            if !matches!(seed.after, Some(Ok(_))) { seed.first.get_or_insert(First::FinalClock); }
            if let (Some(Ok(before)), Some(Ok(after))) = (seed.before.as_ref(), seed.after.as_ref()) {
                seed.continuity = Some(before.validate_later_sample(*after));
                if !matches!(seed.continuity, Some(Ok(()))) { seed.first.get_or_insert(First::Continuity); }
                seed.final_horizon = Some(origin.require_clock_v4(*after));
                if !matches!(seed.final_horizon, Some(Ok(()))) { seed.first.get_or_insert(First::Continuity); }
            }
        }
        if primary.is_ok() && seed.first.is_none() {
            seed.disposal = Some((|| {
                let native = self.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
                let source_native = seed.native_source.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
                self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .dispose_provisioning_source_native_v1(source_native, native, controller, source.journal(), self.profile.as_ref())
            })());
            if !matches!(seed.disposal, Some(Ok(()))) { seed.first = Some(First::Disposal); }
        }
        if seed.first.is_some() {
            self.first = Some(if matches!(seed.first, Some(First::Accepted)) { super::First::Context }
                else { super::First::RecoveredSeed });
            return Err(CLOSED);
        }
        self.after = Some(Ok(()));
        Ok(())
    }
}

fn error<T>(value: &Option<Result<T>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
