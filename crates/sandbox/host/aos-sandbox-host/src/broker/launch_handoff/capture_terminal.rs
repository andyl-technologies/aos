//! Finishes physical Capture on the one existing terminal Complete and marker.
//!
//! This continuation owns no Guest request, effect child, sequence or capacity
//! release. It keeps the actual Stage/Launch/Storage originals and pays one
//! separate native pair before joining Storage's full result to C1. Failure
//! parks every reached original and marks the resident unknown.

use std::sync::{Arc, atomic::Ordering};
use aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1;
use aos_sandbox_controller_domain::runtime_execution::{DormantRuntimeExecutionClaimV1,
    DormantRuntimeExecutionOwnerV1, DormantRuntimeExecutionOwnerErrorV1};
use aos_sandbox_broker::paired_clock::PairedClockIncrementalSamplesV3;
use aos_sandbox_model::{ObjectDigest, ResourceDimension as D, ResourceVector};
use aos_sandbox_model::runtime_backend::DurableExecutionEffectV1;
use crate::live_agent::{HostAgentLiveSessionV1, argument_attempt::HostArgumentAttemptOpeningV2};
use crate::plan::{HostCatalog, HostComponentControlStartupV2,
    ExecutionMonitorReservationV5};
use crate::state::HostStateStore;
use crate::storage_existing_output::capture::StorageCaptureOriginalV2;
use crate::worker::HostWorker;
use crate::{HostError, Result};
use super::super::{HostBroker, argument_handoff::ArgumentStageOriginalV2};
use super::super::accepted_execution::ongoing::HostExecutionMonitorPermissionV5;
use super::execution_monitor::{MonitorBookendsV5, ExecutionMonitorStorageDisposedV5, NativeMonitorPostsV5};

#[derive(Debug, thiserror::Error)]
enum TerminalErrorV3 {
    #[error(transparent)] Host(#[from] HostError),
    #[error(transparent)] Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    #[error(transparent)] Append(#[from] JournalAppendReceivingDemandErrorV1),
    #[error(transparent)] Agent(#[from] crate::live_agent::HostAgentLiveErrorV1),
    #[error(transparent)] Effect(#[from] crate::execution_effect::HostExecutionEffectErrorV1),
}

#[derive(Clone, Copy)]
enum FailureSiteV3 { Forecast, Extension, Clock, Entry, Before, NamesBefore, ArgumentBefore,
    Original, Storage, NamesAfter, ArgumentAfter, After, Native, Marker }

struct TerminalFailureGuardV3 {
    unknown: Arc<std::sync::atomic::AtomicBool>,
    positive: bool,
}

impl Drop for TerminalFailureGuardV3 {
    fn drop(&mut self) {
        if !self.positive { self.unknown.store(true, Ordering::Release); }
    }
}

/// Retains the one actual same-C1 terminal continuation and every failed prefix.
pub(in crate::broker) struct HostCaptureTerminalOriginalV3 {
    reservation: ExecutionMonitorReservationV5,
    first: Option<FailureSiteV3>,
    forecast: Option<std::result::Result<ResourceVector, TerminalErrorV3>>,
    extension: Option<Result<()>>,
    entry: Option<Result<()>>,
    original: Option<std::result::Result<(), TerminalErrorV3>>,
    storage: Option<Result<()>>,
    abort: Option<Result<()>>,
    marker: Option<std::result::Result<(), TerminalErrorV3>>,
    bookends: MonitorBookendsV5,
}

impl HostCaptureTerminalOriginalV3 {
    fn new(reservation: ExecutionMonitorReservationV5) -> Self {
        Self { reservation, first: None, forecast: None, extension: None,
            entry: None, original: None, storage: None, abort: None, marker: None,
            bookends: MonitorBookendsV5::new() }
    }

    fn fixed_demand() -> Result<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(ExecutionMonitorReservationV5::receiving_bytes_v5()?))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<TerminalFailureGuardV3>()))
            .and_then(|bytes| bytes.checked_add(10 * std::mem::size_of::<std::fs::Metadata>()))
            .and_then(|bytes| bytes.checked_add(PairedClockIncrementalSamplesV3::receiving_bytes_v3()?.checked_mul(2)?))
            .ok_or(HostError::ResourceExhausted)?;
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?)
            // A refused primary retains both boot files while the
            // independently owed final pair opens its own two files.
            .with(D::OpenFiles, 5).with(D::MetadataEntries, 1);
        [DormantRuntimeExecutionOwnerV1::execution_currentness_demand_v2(),
            DormantRuntimeExecutionOwnerV1::execution_currentness_post_demand_v2(),
            HostArgumentAttemptOpeningV2::names_receiving_demand_v2(),
            HostArgumentAttemptOpeningV2::names_post_receiving_demand_v2()]
            .into_iter().try_fold(fixed, |total, term| total.checked_add(
                term.ok_or(HostError::ResourceExhausted)?).map_err(|_| HostError::ResourceExhausted))
    }

    pub(in crate::broker) fn first_failure_v3<'owner>(&'owner self,
        storage: &'owner StorageCaptureOriginalV2,
        component: &'owner HostComponentControlStartupV2,
    ) -> Option<&'owner (dyn std::error::Error + 'owner)> {
        match self.first? {
            FailureSiteV3::Forecast => self.forecast.as_ref()?.as_ref().err().map(|cause| cause as _),
            FailureSiteV3::Extension => self.extension.as_ref()?.as_ref().err().map(|cause| cause as _),
            FailureSiteV3::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            FailureSiteV3::Clock => self.bookends.clock_failure_v3(),
            FailureSiteV3::Before | FailureSiteV3::After | FailureSiteV3::Native => Some(component.failure()),
            FailureSiteV3::NamesBefore | FailureSiteV3::NamesAfter => {
                let index = usize::from(matches!(self.first, Some(FailureSiteV3::NamesAfter)));
                self.bookends.names[index].iter().find_map(|names| names.failure()).or_else(||
                    self.bookends.name_results[index].iter().find_map(|result|
                        result.as_ref()?.as_ref().err().map(|cause| cause as _)))
            }
            FailureSiteV3::ArgumentBefore | FailureSiteV3::ArgumentAfter => {
                let index = usize::from(matches!(self.first, Some(FailureSiteV3::ArgumentAfter)));
                self.bookends.argument_names[index].failure().or_else(||
                    self.bookends.argument_results[index].as_ref()?.as_ref().err().map(|cause| cause as _))
            }
            FailureSiteV3::Original => self.original.as_ref()?.as_ref().err().map(|cause| cause as _),
            FailureSiteV3::Storage => storage.failure().or_else(||
                self.storage.as_ref()?.as_ref().err().map(|cause| cause as _)),
            FailureSiteV3::Marker => {
                let returned = self.marker.as_ref()?.as_ref().err()?;
                // This API retains the exact original JournalError itself;
                // no later raw destination may replace its returned cause.
                Some(returned as _)
            }
        }
    }
}

// No DATA decoder or caller-supplied bool constructs this private borrower.
// It continuously borrows the actual Storage terminal owner, original signed
// permission, exact C1 and independently completed native/name/clock posts.
struct CaptureTerminalPostsPositiveV3<'posts> {
    storage: &'posts StorageCaptureOriginalV2,
    terminal: &'posts DurableExecutionEffectV1,
    permission: &'posts HostExecutionMonitorPermissionV5<'posts>,
    bookends: &'posts MonitorBookendsV5,
    native: &'posts dyn NativeMonitorPostsV5,
}

impl CaptureTerminalPostsPositiveV3<'_> {
    fn extend_original_marker_v3(&self, claim: &mut DormantRuntimeExecutionClaimV1<'_>)
        -> std::result::Result<(), TerminalErrorV3> {
        self.bookends.require_positive(self.permission)?;
        self.native.require_positive(self.terminal.issue().sequence().get())?;
        self.permission.require_claim_binding_v5(claim)?;
        let complete = self.storage.completed_result_v2()?;
        if complete.source_digest != self.permission.source_digest_v5()
            || complete.execution != *self.permission.lifetime_v5().execution_v2().as_bytes()
            || complete.create_operation != *self.permission.lifetime_v5().original_create_operation_v2().as_bytes()
            || complete.host_settlement_digest != self.terminal.record_commitment()
            || self.bookends.final_sample.as_ref().ok_or_else(refused)?.boottime_nanoseconds()
                >= self.storage.held_cutoff_v2()?
        { return Err(refused().into()); }
        claim.extend_capture_terminal_marker_v3(self.terminal, *complete)?;
        let marker = claim.capture_terminal_marker_v3(self.terminal)?.ok_or_else(refused)?;
        if marker.complete_record_v3() != complete { return Err(refused().into()); }
        Ok(())
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) fn resident_capture_terminal_due_data_v3(&self) -> Result<bool> {
        let launch = self.launch_original.as_ref().ok_or_else(refused)?.lock().map_err(|_| refused())?;
        let (stage, _, _, _, _) = launch.capture.as_ref().ok_or_else(refused)?.monitor_association_v5()?;
        let held = stage.lock().map_err(|_| refused())?;
        Ok(held.accepted.as_ref().ok_or_else(refused)?.capture_terminal_due_data_v3())
    }

    pub(super) async fn finish_resident_capture_terminal_v3(
        &mut self, agent: &mut HostAgentLiveSessionV1,
    ) -> Result<()> {
        let (stage, accept, observe, unknown, execution, launch_binding) = {
            let launch = self.launch_original.as_ref().ok_or_else(refused)?.lock().map_err(|_| refused())?;
            if !launch.authenticated_sent || launch.first.is_some()
                || launch.agent_binding != Some(agent.session_binding()) { return Err(refused()); }
            let (stage, accept, observe, unknown, execution) = launch.capture.as_ref()
                .ok_or_else(refused)?.monitor_association_v5()?;
            (stage, accept, observe, unknown, execution, crate::plan::HostExecutionRequestBindingV2 {
                id: launch.request.0, session: launch.request.1, signed: launch.request.2 })
        };
        let mut guard = TerminalFailureGuardV3 { unknown, positive: false };
        let mut component = self.component_control.as_ref().ok_or_else(refused)?
            .lock().map_err(|_| refused())?;
        let mut held = stage.lock().map_err(|_| refused())?;
        let ArgumentStageOriginalV2 { owner, argument, accepted, .. } = &mut *held;
        let owner = owner.as_mut().ok_or_else(refused)?;
        let argument = argument.as_mut().ok_or_else(refused)?;
        let (terminal, ongoing, storage, destination, settlement_entered, abort_entered, completed) = accepted.as_mut()
            .ok_or_else(refused)?.capture_terminal_parts_v3()?;
        let (permission, clock) = ongoing.borrow_monitor_v5(&stage, accept)?;
        if permission.lifetime_v5().execution_v2() != execution { return Err(refused()); }
        let (native, maximum) = component.execution_monitor_native_demand_v5()?;
        let fixed = HostCaptureTerminalOriginalV3::fixed_demand()?.checked_add(native)
            .map_err(|_| HostError::ResourceExhausted)?;
        let ordinal = terminal.issue().sequence().get();
        let identity = component.prepare_capture_terminal_receiving_v3(launch_binding, accept, observe,
            permission.source_digest_v5(), execution, fixed, terminal.record_commitment(), ordinal)?;
        *destination = Some(Box::new(HostCaptureTerminalOriginalV3::new(identity)));
        let original = destination.as_mut().ok_or_else(refused)?;
        original.forecast = Some(owner.capture_terminal_marker_receiving_demand_v3(
            terminal.admission().specification_bytes().len()).map_err(Into::into));
        if original.forecast.as_ref().is_some_and(std::result::Result::is_err) {
            original.first.get_or_insert(FailureSiteV3::Forecast);
        }
        let forecast = original.forecast.as_ref().and_then(|result| result.as_ref().ok()).copied();
        original.extension = Some(forecast.ok_or_else(refused).and_then(|demand|
            fixed.checked_add(demand).map_err(|_| HostError::ResourceExhausted))
            .and_then(|complete| component.extend_execution_monitor_receiving_v5(&original.reservation, complete)));
        if !matches!(original.extension, Some(Ok(()))) {
            original.first.get_or_insert(FailureSiteV3::Extension);
            return Err(refused());
        }
        let preparation = (|| -> Result<()> {
            if original.bookends.sample(clock, &permission).is_err() {
                original.first.get_or_insert(FailureSiteV3::Clock); return Err(refused());
            }
            original.entry = Some(component.require_capture_terminal_receiving_identity_v3(
                &original.reservation, terminal.record_commitment(), ordinal));
            if !matches!(original.entry, Some(Ok(()))) {
                original.first.get_or_insert(FailureSiteV3::Entry); return Err(refused());
            }
            Ok(())
        })();
        if preparation.is_err() {
            let _ = original.bookends.finish_entered_clock_post_v3(clock,
                |sample| permission.require_clock_v5(sample));
            return Err(refused());
        }
        let mut receiving = match component.begin_execution_monitor_receiving_v5(&original.reservation, ordinal, maximum) {
            Ok(receiving) => receiving,
            Err(cause) => { original.entry = Some(Err(cause)); original.first.get_or_insert(FailureSiteV3::Entry);
                let _ = original.bookends.finish_entered_clock_post_v3(clock,
                    |sample| permission.require_clock_v5(sample));
                return Err(refused()); }
        };
        original.entry = Some(Ok(()));
        original.bookends.before = Some(receiving.observe_before_v2().await);
        if !matches!(original.bookends.before, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::Before); }
        if matches!(original.bookends.before, Some(Ok(()))) {
            if original.bookends.sample(clock, &permission).is_err() {
                original.first.get_or_insert(FailureSiteV3::Clock);
            } else {
                let _ = owner.observe_execution_names_v2(&mut original.bookends.names[0], &mut original.bookends.name_results[0]);
                original.bookends.argument_results[0] = Some(argument.observe_names_before_v2(&mut original.bookends.argument_names[0]));
                if !original.bookends.name_results[0].iter().all(|result| matches!(result, Some(Ok(())))) {
                    original.first.get_or_insert(FailureSiteV3::NamesBefore);
                } else if !matches!(original.bookends.argument_results[0], Some(Ok(()))) {
                    original.first.get_or_insert(FailureSiteV3::ArgumentBefore);
                }
                if original.first.is_none() {
                    original.original = Some((|| {
                        let claim = owner.claim()?;
                        permission.require_claim_binding_v5(&claim)?;
                        agent.validate_claim(&claim)?;
                        if claim.load_effect(terminal.issue().idempotency().operation().as_bytes())?.as_ref() != Some(terminal) {
                            return Err(refused().into());
                        }
                        let completion = terminal.completion().ok_or_else(refused)?;
                        if crate::execution_effect::terminal_guest_result(&claim, terminal, completion)
                            .map_err(TerminalErrorV3::Effect)?.is_empty()
                        { return Err(refused().into()); }
                        Ok(())
                    })());
                    if !matches!(original.original, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::Original); }
                }
                if original.first.is_none() {
                    if original.bookends.sample(clock, &permission).is_err() {
                        original.first.get_or_insert(FailureSiteV3::Clock);
                    } else {
                        *settlement_entered = true;
                        original.storage = Some(storage.settle_once(terminal.record_commitment()));
                        if !matches!(original.storage, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::Storage); }
                    }
                }
            }
        }
        if original.first.is_some() && !*settlement_entered && !*abort_entered {
            // Abort/Ack uses only the existing prearmed negative delivery
            // interval. Its success cannot dispose physical Capture or prove EOF.
            *abort_entered = true;
            original.abort = Some(storage.abort_once());
        }
        // These scopes are independently owed even after Storage, clock,
        // currentness or financial refusal. No positive gate skips them.
        let _ = owner.observe_execution_names_post_v2(&mut original.bookends.names[1], &mut original.bookends.name_results[1]);
        original.bookends.argument_results[1] = Some(argument.observe_names_post_v2(&mut original.bookends.argument_names[1]));
        if !original.bookends.name_results[1].iter().all(|result| matches!(result, Some(Ok(())))) {
            original.first.get_or_insert(FailureSiteV3::NamesAfter);
        } else if !matches!(original.bookends.argument_results[1], Some(Ok(()))) {
            original.first.get_or_insert(FailureSiteV3::ArgumentAfter);
        }
        original.bookends.after = Some(receiving.observe_after_v2().await);
        if !matches!(original.bookends.after, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::After); }
        original.bookends.native = Some(receiving.finish_native_v2());
        if !matches!(original.bookends.native, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::Native); }
        original.bookends.final_sample = original.bookends.sample_post_v3(clock, &permission).ok();
        if original.bookends.final_sample.is_none() { original.first.get_or_insert(FailureSiteV3::Clock); }
        if original.first.is_none() {
            original.marker = Some((|| {
                let mut claim = owner.claim()?;
                let posts = CaptureTerminalPostsPositiveV3 { storage, terminal, permission: &permission,
                    bookends: &original.bookends, native: &receiving };
                posts.extend_original_marker_v3(&mut claim)
            })());
            if !matches!(original.marker, Some(Ok(()))) {
                original.first.get_or_insert(FailureSiteV3::Marker);
            }
        }
        if original.first.is_some() || !matches!(original.marker, Some(Ok(()))) { return Err(refused()); }
        original.bookends.require_positive(&permission)?;
        receiving.require_monitor_posts_positive_v5(ordinal)?;
        let kept = aos_sandbox_model::component_receiving::without_operation_traffic_v1(
            fixed.checked_add(forecast.ok_or_else(refused)?).map_err(|_| HostError::ResourceExhausted)?)
            .with(D::OpenFiles, 0);
        for names in original.bookends.names.iter_mut().flatten() { names.settle_positive_once_v1(); }
        for names in &mut original.bookends.argument_names { names.settle_positive_once_v1(); }
        let identity = original.reservation.duplicate_disposal_identity_v5();
        drop(destination.take());
        receiving.finish_monitor_storage_disposal_v5(&ExecutionMonitorStorageDisposedV5 { identity, ordinal, kept })?;
        *completed = true;
        guard.positive = true;
        Ok(())
    }
}

fn refused() -> HostError { HostError::Fence("Capture retains unresolved same-terminal custody") }
