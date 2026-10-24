//! Retains one same-Controller chunk through copy and independent Root posts.
//!
//! Only actual positive completion disposes its native peak. The cumulative
//! raw byte buffer stays with the enclosing Ready owner for later frame checks.

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;

use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{
    NormalRootStartupErrorV1, RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1,
};

use crate::controller_resource_reservation::{RootExecutionNoApplyChunkPostsV2, RootStopCleanupChunkPostsV1, RootDeleteChunkPostsV1, RootApplyChunkPostsV1, RootStartAssignmentInputsChunkPostsV2, RootHostLaunchChunkPostsV2, RootMaintenanceStorageChunkPostsV2};
use super::storage_apply_root::RootStorageApplyOpeningOriginalV1;
use super::host_launch_root::RootHostLaunchOpeningOriginalV2;
use super::host_launch_root::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::policy_compiler::create_storage_current::RootCreateStorageCurrentErrorV1 as Error;
use crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1;
use crate::policy_compiler::delete_root::RootDeleteChallengeOriginalsV1;
use crate::policy_compiler::root_subject_readiness::RootSubjectReadinessV1 as RootCurrentReadinessV1;

#[derive(Default)]
pub(crate) struct RootSubjectChunkReceivingV1 {
    purpose_posts: Option<Box<RootChunkPostsV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    readiness: RootCurrentReadinessV1,
    received: Option<Result<(), SubjectStreamReadErrorV1>>,
    subject: Option<RootControllerChunkSubjectSampleV1>,
    binding: Option<Result<(), NormalRootStartupErrorV1>>,
    copied: Option<Result<(), SubjectStreamReadErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_original: Option<RetainedKernelPairedClockAttemptV1>,
    clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cutoff: Option<Result<(), JournalError>>,
    reached: u64,
}

impl RootSubjectChunkReceivingV1 {
    pub(crate) fn receive_exact(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        root_open: &RootCurrentOpenStateV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
    ) -> Result<(), Error> {
        let cutoff = root_open.completed_body()?.cutoff;
        self.receive_exact_until(flight, original, buffer, root_open, geometry, cutoff)
    }

    // Later purposes additionally intersect the unchanged J deadline already
    // known from complete B. This private adapter can only narrow Root's cut.
    pub(crate) fn receive_exact_until(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        root_open: &RootCurrentOpenStateV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        cutoff_nanoseconds: u64,
    ) -> Result<(), Error> {
        if cutoff_nanoseconds == 0 || cutoff_nanoseconds > root_open.completed_body()?.cutoff {
            return Err(Error::Ready);
        }
        self.receive_inner(
            flight,
            original,
            buffer,
            geometry,
            cutoff_nanoseconds,
            RootSubjectPurposeV1::Create(root_open),
        )
    }

    pub(crate) fn receive_delete_exact_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        owner: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), Error> {
        let cutoff = owner.current_cutoff_v1().map_err(|_| Error::Ready)?;
        self.receive_inner(
            flight,
            original,
            buffer,
            geometry,
            cutoff,
            RootSubjectPurposeV1::Delete(owner),
        )
    }

    pub(crate) fn receive_apply_exact_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        owner: &RootStorageApplyOpeningOriginalV1,
    ) -> Result<(), Error> {
        self.receive_inner(flight, original, buffer, geometry,
            owner.current_cutoff_v1().map_err(|_| Error::Ready)?,
            RootSubjectPurposeV1::Apply(owner))
    }

    pub(crate) fn receive_host_launch_exact_v2(
        &mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        owner: &RootHostLaunchOpeningOriginalV2,
    ) -> Result<(), Error> {
        self.receive_inner(flight, original, buffer, geometry,
            owner.current_cutoff_v1().map_err(|_| Error::Ready)?, RootSubjectPurposeV1::Host(owner))
    }

    pub(crate) fn receive_execution_no_apply_exact_v2(
        &mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        owner: &crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyOpeningOriginalV2,
    ) -> Result<(), Error> {
        self.receive_inner(flight, original, buffer, geometry,
            owner.current_cutoff_v1().map_err(|_| Error::Ready)?, RootSubjectPurposeV1::ExecutionNoApply(owner))
    }

    pub(crate) fn receive_stop_cleanup_exact_v1(
        &mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        owner: &crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupOpeningOriginalV1,
    ) -> Result<(), Error> {
        self.receive_inner(flight, original, buffer, geometry,
            owner.current_cutoff_v1().map_err(|_| Error::Ready)?, RootSubjectPurposeV1::StopCleanup(owner))
    }

    pub(crate) fn receive_maintenance_storage_exact_v2(
        &mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        owner: &RootMaintenanceStorageOpeningOriginalV2,
    ) -> Result<(), Error> {
        self.receive_inner(flight, original, buffer, geometry,
            owner.current_cutoff_v1().map_err(|_| Error::Ready)?, RootSubjectPurposeV1::MaintenanceStorage(owner))
    }

    pub(crate) fn receive_start_assignment_inputs_exact_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        owner: &crate::policy_compiler::start_assignment_inputs_root::opening::RootStartAssignmentInputsOpeningOriginalV2,
    ) -> Result<(), Error> {
        self.receive_inner(flight, original, buffer, geometry,
            owner.current_cutoff_v1().map_err(|_| Error::Ready)?,
            RootSubjectPurposeV1::StartInputs(owner))
    }

    fn receive_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        cutoff_nanoseconds: u64,
        purpose: RootSubjectPurposeV1<'_>,
    ) -> Result<(), Error> {
        let Self {
            purpose_posts,
            before,
            readiness,
            received,
            subject,
            binding,
            copied,
            after,
            clock_original,
            clock,
            cutoff,
            reached,
        } = self;
        // This private lexical adapter adds no runtime carrier or callback.
        // Each arm remains in this actual owner's original frame; the shared
        // macro supplies only the single fixed iteration and stage order.
        macro_rules! legacy_chunk_stage_v1 {
            (completed_exact_v1) => {
                buffer.completed_exact()
            };
            (require_empty_once_v1) => {{
                if purpose_posts.is_some()
                    || before.is_some()
                    || readiness.entered()
                    || received.is_some()
                    || subject.is_some()
                    || binding.is_some()
                    || copied.is_some()
                    || after.is_some()
                    || clock_original.is_some()
                    || clock.is_some()
                    || cutoff.is_some()
                {
                    return Err(Error::Ready);
                }
            }};
            (observe_before_once_v1) => {{
                *before = Some(match purpose {
                    RootSubjectPurposeV1::Create(_) => flight.recheck_current_controller_peer_once(),
                    RootSubjectPurposeV1::Delete(owner) => {
                        // The whole D challenge prepaid this resident peak. Debit
                        // this reached schedule before its first arm/native work.
                        *purpose_posts = Some(Box::new(RootChunkPostsV1::Delete(Default::default())));
                        let posts = purpose_posts.as_mut().ok_or(Error::Ready)?;
                        if flight.arm_delete_chunk_posts_once_v1(owner, posts.delete_mut_v1()?).is_err() {
                            // Any earlier successful arms were independently posted
                            // by the armer before its retained failure returned.
                            return Err(Error::Ready);
                        }
                        posts.observe_before_v1(flight, purpose)
                    }
                    RootSubjectPurposeV1::Apply(owner) => {
                        *purpose_posts = Some(Box::new(RootChunkPostsV1::Apply(Default::default())));
                        let posts = purpose_posts.as_mut().ok_or(Error::Ready)?;
                        if flight.arm_apply_chunk_posts_once_v1(owner, posts.apply_mut_v1()?).is_err() {
                            return Err(Error::Ready);
                        }
                        posts.observe_before_v1(flight, purpose)
                    }
                    RootSubjectPurposeV1::Host(owner) => {
                        *purpose_posts = Some(Box::new(RootChunkPostsV1::Host(Default::default())));
                        let posts = purpose_posts.as_mut().ok_or(Error::Ready)?;
                        if flight.arm_host_launch_chunk_posts_once_v2(owner, posts.host_mut_v2()?).is_err() {
                            return Err(Error::Ready);
                        }
                        posts.observe_before_v1(flight, purpose)
                    }
                    RootSubjectPurposeV1::ExecutionNoApply(owner) => {
                        *purpose_posts = Some(Box::new(RootChunkPostsV1::ExecutionNoApply(Default::default())));
                        let posts = purpose_posts.as_mut().ok_or(Error::Ready)?;
                        if flight.arm_execution_no_apply_chunk_posts_once_v2(owner, posts.execution_no_apply_mut_v2()?).is_err() {
                            return Err(Error::Ready);
                        }
                        posts.observe_before_v1(flight, purpose)
                    }

                    RootSubjectPurposeV1::StopCleanup(owner) => {
                        *purpose_posts = Some(Box::new(RootChunkPostsV1::StopCleanup(Default::default())));
                        let posts = purpose_posts.as_mut().ok_or(Error::Ready)?;
                        if flight.arm_stop_cleanup_chunk_posts_once_v1(owner, posts.stop_cleanup_mut_v1()?).is_err() {
                            return Err(Error::Ready);
                        }
                        posts.observe_before_v1(flight, purpose)
                    }
                    RootSubjectPurposeV1::MaintenanceStorage(owner) => {
                        *purpose_posts = Some(Box::new(RootChunkPostsV1::MaintenanceStorage(Default::default())));
                        let posts = purpose_posts.as_mut().ok_or(Error::Ready)?;
                        if flight.arm_maintenance_storage_chunk_posts_once_v2(owner, posts.maintenance_storage_mut_v2()?).is_err() {
                            return Err(Error::Ready);
                        }
                        posts.observe_before_v1(flight, purpose)
                    }
                    RootSubjectPurposeV1::StartInputs(owner) => {
                        *purpose_posts = Some(Box::new(RootChunkPostsV1::StartInputs(Default::default())));
                        let posts = purpose_posts.as_mut().ok_or(Error::Ready)?;
                        if flight.arm_start_assignment_inputs_chunk_posts_once_v2(owner, posts.start_inputs_mut_v2()?).is_err() {
                            return Err(Error::Ready);
                        }
                        posts.observe_before_v1(flight, purpose)
                    }
                });
                if matches!(purpose, RootSubjectPurposeV1::Create(_)) {
                    positive(before)?;
                }
            }};
            (poll_receive_once_v1) => {{
                // recvmsg is MSG_DONTWAIT even on this blocking UnixStream. Wait
                // on the same original first, retaining the finite poll sample.
                if matches!(before, Some(Ok(()))) && readiness.wait_once(original, cutoff_nanoseconds) {
                    *received = Some(match purpose {
                        RootSubjectPurposeV1::Create(_) => {
                            flight.receive_current_subject_chunk_into(buffer, geometry)
                        }
                        RootSubjectPurposeV1::Delete(_) => {
                            flight.receive_delete_subject_chunk_into_v1(buffer, geometry)
                        }
                        RootSubjectPurposeV1::Apply(_) => {
                            flight.receive_apply_subject_chunk_into_v1(buffer, geometry)
                        }
                        RootSubjectPurposeV1::Host(_) => {
                            flight.receive_host_launch_subject_chunk_into_v1(buffer, geometry)
                        }
                        RootSubjectPurposeV1::ExecutionNoApply(_) => {
                            flight.receive_execution_no_apply_subject_chunk_into_v2(buffer, geometry)
                        }

                        RootSubjectPurposeV1::StopCleanup(_) => {
                            flight.receive_stop_cleanup_subject_chunk_into_v1(buffer, geometry)
                        }
                        RootSubjectPurposeV1::MaintenanceStorage(_) => {
                            flight.receive_maintenance_storage_subject_chunk_into_v2(buffer, geometry)
                        }
                        RootSubjectPurposeV1::StartInputs(_) => {
                            flight.receive_start_assignment_inputs_subject_chunk_into_v2(buffer, geometry)
                        }
                    });
                    *subject = Some(RootControllerChunkSubjectSampleV1::default());
                }
            }};
            (observe_subject_copy_once_v1) => {{
                if matches!(received, Some(Ok(()))) {
                    let sample = subject.as_mut().ok_or(Error::Ready)?;
                    *binding = Some(match purpose {
                        RootSubjectPurposeV1::Create(_) => {
                            flight.observe_current_chunk_subject_into(buffer, sample)
                        }
                        RootSubjectPurposeV1::Delete(_) => {
                            flight.observe_delete_chunk_subject_into_v1(buffer, sample)
                        }
                        RootSubjectPurposeV1::Apply(_) => {
                            flight.observe_apply_chunk_subject_into_v1(buffer, sample)
                        }
                        RootSubjectPurposeV1::Host(_) => {
                            flight.observe_host_launch_chunk_subject_into_v1(buffer, sample)
                        }
                        RootSubjectPurposeV1::ExecutionNoApply(_) => {
                            flight.observe_execution_no_apply_chunk_subject_into_v2(buffer, sample)
                        }
                        RootSubjectPurposeV1::StopCleanup(_) => {
                            flight.observe_stop_cleanup_chunk_subject_into_v1(buffer, sample)
                        }
                        RootSubjectPurposeV1::MaintenanceStorage(_) => {
                            flight.observe_maintenance_storage_chunk_subject_into_v2(buffer, sample)
                        }
                        RootSubjectPurposeV1::StartInputs(_) => {
                            flight.observe_start_assignment_inputs_chunk_subject_into_v2(buffer, sample)
                        }
                    });
                    if matches!(binding, Some(Ok(()))) {
                        *copied = Some(buffer.append_pending_payload_once());
                    }
                }
            }};
            (observe_after_once_v1) => {{
                // A native/chunk/copy error does not suppress independent currentness.
                *after = Some(match purpose {
                    RootSubjectPurposeV1::Create(_) => flight.recheck_current_controller_peer_once(),
                    RootSubjectPurposeV1::Delete(_) | RootSubjectPurposeV1::Apply(_)
                        | RootSubjectPurposeV1::StartInputs(_) | RootSubjectPurposeV1::Host(_)
                        | RootSubjectPurposeV1::MaintenanceStorage(_) | RootSubjectPurposeV1::ExecutionNoApply(_) | RootSubjectPurposeV1::StopCleanup(_) => purpose_posts
                        .as_mut()
                        .ok_or(Error::Ready)?
                        .observe_after_v1(flight, purpose),
                });
            }};
            (observe_clock_once_v1) => {{
                *clock_original = Some(RetainedKernelPairedClockAttemptV1::default());
                *clock = Some(
                    clock_original
                        .as_mut()
                        .ok_or(Error::Ready)?
                        .observe_once(None),
                );
                *cutoff = Some((|| {
                    let now = *positive(clock).map_err(|_| JournalError::ProtectedBoundary)?;
                    match purpose {
                        RootSubjectPurposeV1::Create(root) => root.require_clock(now)?,
                        RootSubjectPurposeV1::Delete(owner) => owner.require_current_clock_v1(now)?,
                        RootSubjectPurposeV1::Apply(owner) => owner.require_current_clock_v1(now)?,
                        RootSubjectPurposeV1::Host(owner) => owner.require_current_clock_v1(now)?,
                        RootSubjectPurposeV1::ExecutionNoApply(owner) => owner.require_current_clock_v1(now)?,
                        RootSubjectPurposeV1::StopCleanup(owner) => owner.require_current_clock_v1(now)?,
                        RootSubjectPurposeV1::MaintenanceStorage(owner) => owner.require_current_clock_v1(now)?,
                        RootSubjectPurposeV1::StartInputs(owner) => owner.require_current_clock_v1(now)?,
                    }
                    if now.boottime_nanoseconds() >= cutoff_nanoseconds {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    Ok(())
                })());
            }};
            (require_positive_once_v1) => {{
                positive(before)?;
                if !readiness.positive() {
                    return Err(Error::Ready);
                }
                positive(received)?;
                positive(binding)?;
                positive(copied)?;
                positive(after)?;
                positive(cutoff)?;
                if let Some(posts) = purpose_posts.as_ref() {
                    posts.require_positive_v1().map_err(|_| Error::Ready)?;
                }
            }};
            (dispose_positive_once_v1) => {{
                *reached = reached.checked_add(1).ok_or(Error::Ready)?;
                let chunk = buffer.take_copied_chunk_once().map_err(|_| Error::Ready)?;
                drop(chunk);
                drop(subject.take());
                // Only the actual complete receive/subject/copy/native/paired-clock
                // conjunction permits another chunk. Traffic remains spent on R.
                drop(purpose_posts.take());
                *before = None;
                *readiness = RootCurrentReadinessV1::default();
                *received = None;
                *binding = None;
                *copied = None;
                *after = None;
                drop(clock_original.take());
                *clock = None;
                *cutoff = None;
            }};
        }

        aos_sandbox_broker::root_subject_chunk_programme_v1!(legacy_chunk_stage_v1)
    }

    // The existing Ready recipe and later fixed Root frames share this same
    // raw/subject/readiness peak. Payload Vecs, owning parent fields and purpose
    // controls stay with each caller's own explicit fixed layout and census.
    pub(crate) fn additional_receiving_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        aos_sandbox_broker::root_subject_receiving_demand_v1! {
            sample: RootControllerChunkSubjectSampleV1,
            readiness: RootCurrentReadinessV1,
            error: JournalError::LimitExceeded("fixed Root Ready receiving shape"),
        }
    }

    // New D never imports the old Create512 metadata-field allowance. Native
    // subject/FD/membership/readiness byte peaks are the same existing engine;
    // the concrete paired-clock and two full independent post owners are added.
    pub(crate) fn delete_receiving_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let invalid = || JournalError::JournalTooLarge;
        let native = Self::additional_receiving_demand_v1()?.with(D::MetadataEntries, 0);
        let posts = RootDeleteChunkPostsV1::fixed_demand_v1().map_err(|_| invalid())?;
        let clock = Self::additional_clock_demand_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(5 * std::mem::size_of::<usize>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        native
            .checked_add(posts)
            .map_err(JournalError::ReceivingAccounting)?
            .checked_add(clock)
            .map_err(JournalError::ReceivingAccounting)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn apply_receiving_demand_v1()
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        Self::resource_receiving_demand_v2(RootApplyChunkPostsV1::fixed_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?)
    }

    pub(crate) fn host_receiving_demand_v2()
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        Self::resource_receiving_demand_v2(RootHostLaunchChunkPostsV2::fixed_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?)
    }

    pub(crate) fn execution_no_apply_receiving_demand_v2()
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        Self::resource_receiving_demand_v2(RootExecutionNoApplyChunkPostsV2::fixed_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?)
    }

    pub(crate) fn stop_cleanup_receiving_demand_v1()
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        Self::resource_receiving_demand_v2(RootStopCleanupChunkPostsV1::fixed_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?)
    }

    pub(crate) fn maintenance_storage_receiving_demand_v2()
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        Self::resource_receiving_demand_v2(RootMaintenanceStorageChunkPostsV2::fixed_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?)
    }

    // Pure private geometry receives only the two closed compiled post recipes;
    // it cannot select authority or accept an external amount as a permit.
    fn resource_receiving_demand_v2(posts: aos_sandbox_model::ResourceVector)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        Self::continuation_receiving_demand_v2(posts)
    }

    pub(crate) fn start_assignment_inputs_receiving_demand_v2()
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        Self::continuation_receiving_demand_v2(RootStartAssignmentInputsChunkPostsV2::fixed_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?)
    }

    fn continuation_receiving_demand_v2(posts: aos_sandbox_model::ResourceVector)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        use aos_sandbox_model::ResourceDimension as D;
        // The common native peak is unchanged. Only the closed typed post
        // owner differs; both variants occupy the one lazy enum allocation.
        let common = Self::additional_receiving_demand_v1()?.with(D::MetadataEntries, 0);
        let bytes = u64::try_from(std::mem::size_of::<RootChunkPostsV1>()
            .checked_mul(3).ok_or(JournalError::JournalTooLarge)?)
            .map_err(|_| JournalError::JournalTooLarge)?;
        common.checked_add(posts).and_then(|demand| demand.checked_add(
            aos_sandbox_model::ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(JournalError::ReceivingAccounting)?
            .checked_add(Self::additional_clock_demand_v1()?)
            .map_err(JournalError::ReceivingAccounting)
    }

    // The surrounding fixed owner pays the resident Option in sizeof(Self).
    // This separate one-pair lane pays its later constructor and dynamic raw
    // readers. Complete positive disposal precedes every next payload sample;
    // a failed pair stops this helper with the actual raw File/results resident.
    pub(crate) fn additional_clock_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let invalid = || JournalError::JournalTooLarge;
        let bytes = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let cells = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(
                D::MetadataEntries,
                u64::try_from(cells).map_err(|_| invalid())?,
            )
            .with(
                D::OpenFiles,
                RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
            ))
    }

    pub(crate) fn native_sample_disposed(&self) -> bool {
        self.reached != 0
            && self.purpose_posts.is_none()
            && self.before.is_none()
            && !self.readiness.entered()
            && self.received.is_none()
            && self.subject.is_none()
            && self.binding.is_none()
            && self.copied.is_none()
            && self.after.is_none()
            && self.clock_original.is_none()
            && self.clock.is_none()
            && self.cutoff.is_none()
    }

    pub(crate) fn financial_failure_is_selected_v1(&self) -> bool {
        self.purpose_posts
            .as_ref()
            .is_some_and(|posts| posts.funding_failed_v1())
    }

    pub(crate) fn property_failure_view_v1(
        &self,
        buffer: &RetainedSubjectStreamReadV1,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let first = self.failure_with_buffer(buffer)?;
        self.purpose_posts.as_ref()?.property_failure_view_v1(first)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.failure_inner(None)
    }

    // Resolves only the actual returned DATA marker at its original receive or
    // copy site; a later independent post cannot replace an earlier cause.
    pub(crate) fn failure_with_buffer<'a>(
        &'a self,
        buffer: &'a RetainedSubjectStreamReadV1,
    ) -> Option<&'a (dyn StdError + 'static)> {
        self.failure_inner(Some(buffer))
    }

    fn failure_inner<'a>(
        &'a self,
        buffer: Option<&'a RetainedSubjectStreamReadV1>,
    ) -> Option<&'a (dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        self.purpose_posts
            .as_ref()
            .and_then(|posts| posts.before_failure_v1())
            .or_else(|| cause!(self.before))
            .or_else(|| self.readiness.failure())
            .or_else(|| {
                if matches!(self.received, Some(Err(SubjectStreamReadErrorV1::Retained))) {
                    buffer
                        .and_then(RetainedSubjectStreamReadV1::failure)
                        .or_else(|| cause!(self.received))
                } else {
                    cause!(self.received)
                }
            })
            .or_else(|| self.subject.as_ref().and_then(|sample| sample.failure()))
            .or_else(|| cause!(self.binding))
            .or_else(|| {
                if matches!(self.copied, Some(Err(SubjectStreamReadErrorV1::Retained))) {
                    buffer
                        .and_then(RetainedSubjectStreamReadV1::failure)
                        .or_else(|| cause!(self.copied))
                } else {
                    cause!(self.copied)
                }
            })
            .or_else(|| {
                self.purpose_posts
                    .as_ref()
                    .and_then(|posts| posts.after_failure_v1())
            })
            .or_else(|| cause!(self.after))
            .or_else(|| {
                self.clock_original
                    .as_ref()
                    .and_then(|original| original.failure())
            })
            .or_else(|| cause!(self.clock))
            .or_else(|| cause!(self.cutoff))
    }
}

#[derive(Clone, Copy)]
enum RootSubjectPurposeV1<'a> {
    ExecutionNoApply(&'a crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyOpeningOriginalV2),
    StopCleanup(&'a crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupOpeningOriginalV1),
    Create(&'a RootCurrentOpenStateV1),
    Delete(&'a RootDeleteChallengeOriginalsV1),
    Apply(&'a RootStorageApplyOpeningOriginalV1),
    Host(&'a RootHostLaunchOpeningOriginalV2),
    MaintenanceStorage(&'a RootMaintenanceStorageOpeningOriginalV2),
    StartInputs(&'a crate::policy_compiler::start_assignment_inputs_root::opening::RootStartAssignmentInputsOpeningOriginalV2),
}

// One lazy closed variant keeps the sole per-chunk native engine. Empty
// receivers never allocate idle Delete and Apply capsules in parallel.
enum RootChunkPostsV1 {
    ExecutionNoApply(RootExecutionNoApplyChunkPostsV2),
    StopCleanup(RootStopCleanupChunkPostsV1),
    Delete(RootDeleteChunkPostsV1),
    Apply(RootApplyChunkPostsV1),
    StartInputs(RootStartAssignmentInputsChunkPostsV2),
    Host(RootHostLaunchChunkPostsV2),
    MaintenanceStorage(RootMaintenanceStorageChunkPostsV2),
}

impl RootChunkPostsV1 {
    fn delete_mut_v1(&mut self) -> Result<&mut RootDeleteChunkPostsV1, Error> {
        match self { Self::Delete(posts) => Ok(posts), _ => Err(Error::Ready) }
    }

    fn apply_mut_v1(&mut self) -> Result<&mut RootApplyChunkPostsV1, Error> {
        match self { Self::Apply(posts) => Ok(posts), _ => Err(Error::Ready) }
    }

    fn host_mut_v2(&mut self) -> Result<&mut RootHostLaunchChunkPostsV2, Error> {
        match self { Self::Host(posts) => Ok(posts), _ => Err(Error::Ready) }
    }

    fn execution_no_apply_mut_v2(&mut self) -> Result<&mut RootExecutionNoApplyChunkPostsV2, Error> {
        match self { Self::ExecutionNoApply(posts) => Ok(posts), _ => Err(Error::Ready) }
    }

    fn stop_cleanup_mut_v1(&mut self) -> Result<&mut RootStopCleanupChunkPostsV1, Error> {
        match self { Self::StopCleanup(posts) => Ok(posts), _ => Err(Error::Ready) }
    }

    fn maintenance_storage_mut_v2(&mut self) -> Result<&mut RootMaintenanceStorageChunkPostsV2, Error> {
        match self { Self::MaintenanceStorage(posts) => Ok(posts), _ => Err(Error::Ready) }
    }

    fn start_inputs_mut_v2(&mut self) -> Result<&mut RootStartAssignmentInputsChunkPostsV2, Error> {
        match self { Self::StartInputs(posts) => Ok(posts), _ => Err(Error::Ready) }
    }

    fn observe_before_v1(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        owner: RootSubjectPurposeV1<'_>) -> Result<(), NormalRootStartupErrorV1>
    {
        match (self, owner) {
            (Self::Delete(posts), RootSubjectPurposeV1::Delete(owner)) =>
                posts.observe_before_once_v1(flight, owner),
            (Self::Apply(posts), RootSubjectPurposeV1::Apply(owner)) =>
                posts.observe_before_once_v1(flight, owner),
            (Self::Host(posts), RootSubjectPurposeV1::Host(owner)) =>
                posts.observe_before_once_v1(flight, owner),
            (Self::ExecutionNoApply(posts), RootSubjectPurposeV1::ExecutionNoApply(owner)) =>
                posts.observe_before_once_v1(flight, owner),
            (Self::StopCleanup(posts), RootSubjectPurposeV1::StopCleanup(owner)) =>
                posts.observe_before_once_v1(flight, owner),
            (Self::MaintenanceStorage(posts), RootSubjectPurposeV1::MaintenanceStorage(owner)) =>
                posts.observe_before_once_v1(flight, owner),
            (Self::StartInputs(posts), RootSubjectPurposeV1::StartInputs(owner)) =>
                posts.observe_before_once_v1(flight, owner),
            _ => Err(NormalRootStartupErrorV1::Service),
        }
    }

    fn observe_after_v1(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        owner: RootSubjectPurposeV1<'_>) -> Result<(), NormalRootStartupErrorV1>
    {
        match (self, owner) {
            (Self::Delete(posts), RootSubjectPurposeV1::Delete(owner)) =>
                posts.observe_after_once_v1(flight, owner),
            (Self::Apply(posts), RootSubjectPurposeV1::Apply(owner)) =>
                posts.observe_after_once_v1(flight, owner),
            (Self::Host(posts), RootSubjectPurposeV1::Host(owner)) =>
                posts.observe_after_once_v1(flight, owner),
            (Self::ExecutionNoApply(posts), RootSubjectPurposeV1::ExecutionNoApply(owner)) =>
                posts.observe_after_once_v1(flight, owner),
            (Self::StopCleanup(posts), RootSubjectPurposeV1::StopCleanup(owner)) =>
                posts.observe_after_once_v1(flight, owner),
            (Self::MaintenanceStorage(posts), RootSubjectPurposeV1::MaintenanceStorage(owner)) =>
                posts.observe_after_once_v1(flight, owner),
            (Self::StartInputs(posts), RootSubjectPurposeV1::StartInputs(owner)) =>
                posts.observe_after_once_v1(flight, owner),
            _ => Err(NormalRootStartupErrorV1::Service),
        }
    }

    fn require_positive_v1(&self) -> Result<(), NormalRootStartupErrorV1> {
        match self { Self::Delete(posts) => posts.require_positive_v1(),
            Self::Apply(posts) => posts.require_positive_v1(),
            Self::StartInputs(posts) => posts.require_positive_v1(),
            Self::ExecutionNoApply(posts) => posts.require_positive_v1(),
            Self::StopCleanup(posts) => posts.require_positive_v1(),
            Self::MaintenanceStorage(posts) => posts.require_positive_v1(),
            Self::Host(posts) => posts.require_positive_v1() }
    }

    fn funding_failed_v1(&self) -> bool {
        match self { Self::Delete(posts) => posts.funding_failed_v1(),
            Self::Apply(posts) => posts.funding_failed_v1(),
            Self::StartInputs(posts) => posts.funding_failed_v1(),
            Self::ExecutionNoApply(posts) => posts.funding_failed_v1(),
            Self::StopCleanup(posts) => posts.funding_failed_v1(),
            Self::MaintenanceStorage(posts) => posts.funding_failed_v1(),
            Self::Host(posts) => posts.funding_failed_v1() }
    }

    fn before_failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        match self { Self::Delete(posts) => posts.before_failure_v1(),
            Self::Apply(posts) => posts.before_failure_v1(),
            Self::StartInputs(posts) => posts.before_failure_v1(),
            Self::ExecutionNoApply(posts) => posts.before_failure_v1(),
            Self::StopCleanup(posts) => posts.before_failure_v1(),
            Self::MaintenanceStorage(posts) => posts.before_failure_v1(),
            Self::Host(posts) => posts.before_failure_v1() }
    }

    fn after_failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        match self { Self::Delete(posts) => posts.after_failure_v1(),
            Self::Apply(posts) => posts.after_failure_v1(),
            Self::StartInputs(posts) => posts.after_failure_v1(),
            Self::ExecutionNoApply(posts) => posts.after_failure_v1(),
            Self::StopCleanup(posts) => posts.after_failure_v1(),
            Self::MaintenanceStorage(posts) => posts.after_failure_v1(),
            Self::Host(posts) => posts.after_failure_v1() }
    }

    fn property_failure_view_v1(&self, first: &(dyn StdError + 'static))
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    {
        match self { Self::Delete(posts) => posts.property_failure_view_v1(first),
            Self::Apply(posts) => posts.property_failure_view_v1(first),
            Self::StartInputs(posts) => posts.property_failure_view_v1(first),
            Self::ExecutionNoApply(posts) => posts.property_failure_view_v1(first),
            Self::StopCleanup(posts) => posts.property_failure_view_v1(first),
            Self::MaintenanceStorage(posts) => posts.property_failure_view_v1(first),
            Self::Host(posts) => posts.property_failure_view_v1(first) }
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Error> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(Error::Ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_buffer_failure_precedes_a_later_independent_peer_failure() {
        let mut buffer = RetainedSubjectStreamReadV1::new();
        assert!(buffer.prepare_exact_once(usize::MAX).is_err());
        let mut sample = RootSubjectChunkReceivingV1::default();
        sample.received = Some(Err(SubjectStreamReadErrorV1::Retained));
        sample.after = Some(Err(NormalRootStartupErrorV1::Service));

        let cause = sample.failure_with_buffer(&buffer).unwrap();

        assert!(cause.is::<std::collections::TryReserveError>());
        assert!(sample.after.as_ref().unwrap().is_err());
    }
}
