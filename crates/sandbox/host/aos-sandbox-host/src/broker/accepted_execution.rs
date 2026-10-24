//! Keeps the actual accepted Guest original through Authorize and first Observe.
//!
//! This private owner is constructed and fully priced before method59. The
//! subsequent signed Apply methods borrow its SAME four runtime journals,
//! fifth argument journal, live Guest session and genuine Storage hold. No
//! Controller receipt, decoded spec, caller boolean or path creates a claim.

pub(in crate::broker) mod ongoing;

use std::error::Error;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use aos_sandbox_api::aos::sandbox::local::v1::{ApplyHostExecutionRequestV1,
    BrokerMethod, HostExecutionActionV1};
use aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1 as Names;
use aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionOwnerV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_model::runtime_backend::{DurableExecutionEffectV1, EffectOperationV1, EffectPhaseV1, EffectCompletionStatusV1};
use aos_linux_descriptors::ImmutableFileError;
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::execution_spec_attempt::ExecutionSpecAttemptFieldsV1;
use aos_sandbox_protocol::host_execution::admission_content::{HostExecutionAdmissionContentV5};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};
use crate::execution_effect::{self, HostExecutionEffectErrorV1};

pub(in crate::broker) mod terminal_disposal;
use crate::live_agent::{HostAgentLiveSessionV1,
    execution_original::AgentExecutionOriginalV2};
use crate::live_agent::argument_attempt::{HostArgumentAttemptErrorV1, HostArgumentAttemptOpeningV2};
use crate::plan::{AcceptedContinuationV2, HostExecutionRequestBindingV2, HostComponentControlStartupV2};
use crate::state::{HostStateStore, HostStateWriteAttemptV2};
use crate::storage_existing_output::{ExpectedExistingOutputV1, StorageExistingOutputOriginalV2};
use crate::{HostError, Result};
use super::argument_handoff::{ArgumentClockV2, ArgumentStageOriginalV2, ArgumentStateWritesV2};
use super::{HostBroker, HostExecutionGrantRequestV1, HostExecutionGrantReservationV1};

#[derive(Debug, thiserror::Error)]
enum AcceptedErrorV2 {
    #[error(transparent)] Host(#[from] HostError),
    #[error(transparent)] Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error(transparent)] Argument(#[from] HostArgumentAttemptErrorV1),
    #[error(transparent)] Owner(#[from] aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionOwnerErrorV1),
    #[error(transparent)] Effect(#[from] HostExecutionEffectErrorV1),
}

#[derive(Clone, Copy)]
enum FailureSiteV2 { Mapping, Entry, Before, NamesBefore, ArgumentBefore,
    Primary, Storage, Ongoing, NamesAfter, ArgumentAfter, After, Native, Residency, External }

struct AcceptedTurnV2 {
    request: Option<HostExecutionRequestBindingV2>,
    writes: Option<Arc<Mutex<ArgumentStateWritesV2>>>,
    clock: Option<ArgumentClockV2>,
    descriptor: Option<std::io::Result<OwnedFd>>,
    mapping_alias: Option<std::io::Result<OwnedFd>>,
    mapping: Option<std::result::Result<Vec<u8>, ImmutableFileError>>,
    guest: Option<AgentExecutionOriginalV2>,
    reservation: Option<HostExecutionGrantReservationV1>,
    effect: Option<DurableExecutionEffectV1>,
    terminal_native: Option<terminal_disposal::HostGuestTerminalNativeV3>,
    shared_directory: Names,
    names: [[Names; 4]; 2],
    name_results: [[Option<std::result::Result<(), aos_sandbox_controller_domain::JournalError>>; 4]; 2],
    argument_names: [Names; 2],
    argument_name_results: [Option<std::result::Result<(), aos_sandbox_controller_domain::JournalError>>; 2],
    entry: Option<Result<()>>,
    before: Option<Result<()>>,
    primary: Option<std::result::Result<Vec<u8>, AcceptedErrorV2>>,
    after: Option<Result<()>>,
    native: Option<Result<()>>,
    authenticated: bool,
    scratch_disposed: bool,
    disposal: Option<Result<()>>,
    frontier: FailureSiteV2,
    first_site: Option<FailureSiteV2>,
}

impl AcceptedTurnV2 {
    fn new() -> Self {
        Self { request: None, writes: Some(Arc::new(Mutex::new(ArgumentStateWritesV2::new()))),
            clock: None, descriptor: None, mapping_alias: None, mapping: None, guest: Some(AgentExecutionOriginalV2::new()),
            reservation: None, effect: None, terminal_native: None,
            shared_directory: Names::new(),
            names: std::array::from_fn(|_| std::array::from_fn(|_| Names::new())),
            name_results: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            argument_names: std::array::from_fn(|_| Names::new()),
            argument_name_results: std::array::from_fn(|_| None), entry: None, before: None,
            primary: None, after: None, native: None, authenticated: false, scratch_disposed: false, disposal: None, frontier: FailureSiteV2::Mapping, first_site: None }
    }

    // These completed local samples are not borrowed by the later claim,
    // Guest effect, append or independently owed post. Each actual positive
    // leaf can close now even when another independent sample failed. Failed
    // native prefixes stay intact, and all completion/reentry tombstones stay.
    fn retire_positive_before_names_v6(
        names: &mut [Names; 4],
        results: &[Option<std::result::Result<(), aos_sandbox_controller_domain::JournalError>>; 4],
        argument: &mut Names,
        argument_result: &Option<std::result::Result<(), aos_sandbox_controller_domain::JournalError>>,
    ) {
        for (original, result) in names.iter_mut().zip(results) {
            if matches!(result, Some(Ok(()))) {
                original.settle_positive_once_v1();
            }
        }
        if matches!(argument_result, Some(Ok(()))) {
            argument.settle_positive_once_v1();
        }
    }

    fn require_positive_before_names_v6(shared: &Names, names: &[Names; 4], argument: &Names) -> Result<()> {
        if !shared.is_complete() || shared.retained_file_count() != 0
            || names.iter().chain(std::iter::once(argument))
                .any(|original| !original.is_complete() || original.retained_file_count() != 0)
        { return Err(refused()); }
        Ok(())
    }

    fn require_positive_scratch_v2(&self) -> Result<()> {
        if !self.authenticated || self.scratch_disposed || self.first_site.is_some()
            || self.primary.is_some()
            || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.before, Some(Ok(())))
            || !matches!(self.after, Some(Ok(())))
            || !matches!(self.native, Some(Ok(())))
            || !self.shared_directory.is_complete()
            || !self.names.iter().flatten().all(Names::is_complete)
            || !self.name_results.iter().flatten().all(|r| matches!(r, Some(Ok(()))))
            || !self.argument_names.iter().all(Names::is_complete)
            || !self.argument_name_results.iter().all(|r| matches!(r, Some(Ok(()))))
            || !self.guest.as_ref().is_some_and(AgentExecutionOriginalV2::completed_positive_v2)
            || self.clock.as_ref().is_none_or(|clock| clock.failure().is_some())
        {
            return Err(refused());
        }
        let writes = self.writes.as_ref().ok_or_else(refused)?;
        // No State callback or diagnostic may keep an alias past this boundary.
        if Arc::strong_count(writes) != 1 { return Err(refused()); }
        writes.lock().map_err(|_| refused())?.require_positive_disposal_v2()
    }

    fn dispose_positive_scratch_v2(
        &mut self,
        ongoing: Option<&mut ongoing::HostExecutionOngoingOriginalV5>,
    ) -> Result<()> {
        self.require_positive_scratch_v2()?;
        if let Some(permission) = ongoing {
            permission.retain_positive_original_clock_v5(&mut self.clock)?;
        }
        for names in self.names.iter_mut().flatten() {
            names.settle_positive_once_v1();
        }
        for names in &mut self.argument_names {
            names.settle_positive_once_v1();
        }
        // Ongoing execution retains the SAME original native clock in its owning
        // permission. Other completed scratch leaves are no longer borrowed.
        drop(self.writes.take());
        drop(self.guest.take());
        drop(self.clock.take());
        drop(self.descriptor.take());
        drop(self.mapping_alias.take());
        drop(self.mapping.take());
        self.scratch_disposed = true;
        Ok(())
    }

    fn failure<'owner>(&'owner self, ongoing: Option<&'owner ongoing::HostExecutionOngoingOriginalV5>)
        -> Option<&'owner (dyn Error + 'static)> {
        match self.first_site? {
            FailureSiteV2::Mapping => self.descriptor.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _)
                .or_else(|| self.mapping_alias.as_ref()?.as_ref().err().map(|e| e as _))
                .or_else(|| self.mapping.as_ref()?.as_ref().err().map(|e| e as _)),
            FailureSiteV2::Entry => self.clock.as_ref().and_then(ArgumentClockV2::failure)
                .or_else(|| self.entry.as_ref()?.as_ref().err().map(|e| e as _)),
            FailureSiteV2::Before => self.before.as_ref()?.as_ref().err().map(|e| e as _),
            FailureSiteV2::NamesBefore | FailureSiteV2::NamesAfter => {
                let index = usize::from(matches!(self.first_site, Some(FailureSiteV2::NamesAfter)));
                (if index == 0 { self.shared_directory.failure() } else { None })
                    .or_else(|| self.names[index].iter().find_map(Names::failure))
                    .or_else(|| self.name_results[index].iter().find_map(|r| r.as_ref()?.as_ref().err().map(|e| e as _)))
            }
            FailureSiteV2::ArgumentBefore | FailureSiteV2::ArgumentAfter => {
                let index = usize::from(matches!(self.first_site, Some(FailureSiteV2::ArgumentAfter)));
                self.argument_names[index].failure()
                    .or_else(|| self.argument_name_results[index].as_ref()?.as_ref().err().map(|e| e as _))
            }
            FailureSiteV2::Primary => self.clock.as_ref().and_then(ArgumentClockV2::failure)
                .or_else(|| self.guest.as_ref().and_then(AgentExecutionOriginalV2::failure))
                .or_else(|| self.primary.as_ref()?.as_ref().err().map(|e| e as _)),
            FailureSiteV2::Ongoing => ongoing.and_then(ongoing::HostExecutionOngoingOriginalV5::failure)
                .or_else(|| self.primary.as_ref()?.as_ref().err().map(|cause| cause as _)),
            FailureSiteV2::Storage | FailureSiteV2::Residency | FailureSiteV2::External => None,
            FailureSiteV2::After => self.after.as_ref()?.as_ref().err().map(|e| e as _),
            FailureSiteV2::Native => self.native.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _)
                .or_else(|| self.disposal.as_ref()?.as_ref().err().map(|e| e as _)),
        }
    }

}

pub(super) struct AcceptedExecutionOriginalV2 {
    storage: StorageExistingOutputOriginalV2,
    capture: Option<crate::storage_existing_output::capture::StorageCaptureOriginalV2>,
    capture_negative: Option<super::launch_handoff::capture_resident::HostCaptureNegativeDispositionV3>,
    capture_stop_financial: Option<Result<crate::plan::HostCaptureNegativeLoanV3>>,
    capture_stop_entry: Option<Result<()>>,
    capture_stop_request: Option<HostExecutionRequestBindingV2>,
    ongoing: Option<ongoing::HostExecutionOngoingOriginalV5>,
    monitor: Option<Box<super::launch_handoff::execution_monitor::HostExecutionMonitorOriginalV5>>,
    monitor_complete: Option<super::launch_handoff::execution_monitor::MonitorCompletedDataV5>,
    capture_terminal: Option<Box<super::launch_handoff::capture_terminal::HostCaptureTerminalOriginalV3>>,
    capture_terminal_complete: bool,
    query: Option<Box<super::launch_handoff::execution_query::HostExecutionQueryOriginalV3>>,
    capture_residency: Option<Result<()>>,
    turns: [AcceptedTurnV2; 2],
    cutoff: Option<u64>,
    execution: Option<aos_sandbox_model::ExecutionId>,
    source: Option<aos_sandbox_model::ObjectDigest>,
    first: Option<usize>,
    storage_settlement_entered: bool,
    storage_abort_entered: bool,
}

impl AcceptedExecutionOriginalV2 {
    pub(super) fn new() -> Self {
        Self { storage: StorageExistingOutputOriginalV2::new(), capture: None, capture_negative: None, capture_stop_financial: None, capture_stop_entry: None, capture_stop_request: None, ongoing: None, monitor: None, monitor_complete: None, capture_terminal: None, capture_terminal_complete: false, query: None, capture_residency: None,
            turns: std::array::from_fn(|_| AcceptedTurnV2::new()), cutoff: None,
            execution: None, source: None, first: None, storage_settlement_entered: false, storage_abort_entered: false }
    }

    pub(in crate::broker) fn prepare_capture_stop_financial_once_v4(
        &mut self,
        failed: &super::launch_handoff::capture_stop::HostCaptureFailedStageV4,
        admitted: &aos_sandbox_broker::VerifiedBrokerAdmission,
        actual: &Arc<Mutex<HostComponentControlStartupV2>>,
        original: &mut HostComponentControlStartupV2,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if self.capture_stop_financial.is_some() || self.capture_stop_request.is_some() {
            return Err(refused());
        }
        self.capture_stop_request = Some(HostExecutionRequestBindingV2 {
            id: request.request_id(), session: request.session_binding(), signed: request.signed_request_digest(),
        });
        // Own the entire financial return before classifying it. The old
        // accepted failure and every native Capture owner stay in place.
        self.capture_stop_financial = Some((|| {
            let parent = self.capture.as_ref().ok_or_else(refused)?.stop_parent_v4()?;
            self.capture_negative.as_mut().ok_or_else(refused)?
                .enter_stop_financial_once_v4(failed, admitted, parent.source_v4(), actual, original)
        })());
        if matches!(self.capture_stop_financial, Some(Ok(_))) { Ok(()) } else { Err(refused()) }
    }

    pub(in crate::broker) fn capture_for_stop_v4(&mut self)
        -> Result<&mut crate::storage_existing_output::capture::StorageCaptureOriginalV2> {
        if !matches!(self.capture_stop_financial, Some(Ok(_))) { return Err(refused()); }
        self.capture.as_mut().ok_or_else(refused)
    }

    pub(in crate::broker) fn capture_stop_inputs_v4(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(
        &crate::plan::HostCaptureNegativeLoanV3,
        crate::storage_existing_output::capture::StorageCaptureStopParentV4<'_>,
        &mut Option<Result<()>>,
    )> {
        let binding = HostExecutionRequestBindingV2 {
            id: request.request_id(), session: request.session_binding(), signed: request.signed_request_digest(),
        };
        if self.capture_stop_entry.is_some() || self.capture_stop_request != Some(binding) { return Err(refused()); }
        let loan = self.capture_stop_financial.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
        let held = self.capture.as_ref().ok_or_else(refused)?.stop_parent_v4()?;
        Ok((loan, held, &mut self.capture_stop_entry))
    }

    pub(in crate::broker) fn format_capture_stop_entry_failure_v4(
        &self, component: &HostComponentControlStartupV2, formatter: &mut std::fmt::Formatter<'_>,
    ) -> Option<std::fmt::Result> {
        let request = self.capture_stop_request?;
        if let Some(Err(cause)) = self.capture_stop_financial.as_ref() {
            return Some(std::fmt::Display::fmt(cause, formatter));
        }
        let returned = self.capture_stop_entry.as_ref()?.as_ref().err()?;
        Some(match component.capture_stop_failure_v4((request.id, request.session, request.signed), false) {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => std::fmt::Display::fmt(returned, formatter),
        })
    }

    pub(in crate::broker) fn format_capture_stop_native_failure_v4(
        &self, clock: Option<&dyn std::error::Error>, formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let Some(capture) = self.capture.as_ref() else { return formatter.write_str("Capture Stop original is absent"); };
        if capture.stop_clock_failure_selected_v4() {
            if let Some(cause) = clock { return std::fmt::Display::fmt(cause, formatter); }
        }
        match capture.stop_failure_v4() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Capture Stop retains unresolved native custody"),
        }
    }

    pub(super) fn fixed_demand_v2() -> Option<ResourceVector> {
        let planes = aos_sandbox_protocol::host_execution::admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5.checked_mul(12)?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(crate::state::historical_execution::HistoricalExecutionReadBindingV5::receiving_bytes_v5()?)?
            .checked_add(crate::plan::HostComponentControlStartupV2::terminal_stage_disposal_receiving_bytes_v3()?)?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(planes).ok()?)
            // Two incoming sealed descriptor aliases remain through the real
            // signed response; neither receiver's original FD is credited.
            .with(D::OpenFiles, 3)
            .with(D::OutputBytes, u64::try_from(
                aos_sandbox_guest_protocol::signed_outcome_packet::MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES.checked_mul(4)?).ok()?);
        let logical = StorageExistingOutputOriginalV2::preparation_demand_v2()?;
        let capture = crate::storage_existing_output::capture::StorageCaptureOriginalV2::preparation_demand_v2()?;
        // Actual validated content selects exactly one native branch before
        // either client captures. Both byte/traffic reservoirs remain paid;
        // the logical owner stays inert throughout the physical branch.
        let storage = logical.checked_add(capture).ok()?.with(D::OpenFiles,
            logical.get(D::OpenFiles).max(capture.get(D::OpenFiles)));
        demand = demand.checked_add(storage).ok()?;
        let guest = aos_sandbox_guest_protocol::capture_receiving::capture_guest_receiving_bytes_v2(
            aos_sandbox_guest_protocol::MAX_AGENT_SEALED_SPEC_BYTES_V1)?;
        demand = demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(guest).ok()?)
            .with(D::OpenFiles, u64::try_from(
                aos_sandbox_linux::seqpacket::SeqpacketSocket::maximum_agent_authorize_descriptor_slots_v2()
                    .checked_mul(2)?).ok()?)).ok()?;

        let clock = ArgumentClockV2::receiving_demand_v2()?
            .checked_add(ArgumentClockV2::effect_write_demand_v4()?).ok()?;
        let writes = HostStateWriteAttemptV2::argument_pair_demand_v2()?;
        let agent = AgentExecutionOriginalV2::receiving_demand_v2()?;
        let before_names = DormantRuntimeExecutionOwnerV1::execution_shared_directory_demand_v6()?
            .checked_add(DormantRuntimeExecutionOwnerV1::execution_shared_names_demand_v6()?).ok()?
            .checked_add(HostArgumentAttemptOpeningV2::names_post_receiving_demand_v2()?).ok()?;
        let after_names = DormantRuntimeExecutionOwnerV1::execution_currentness_post_demand_v2()?
            .checked_add(HostArgumentAttemptOpeningV2::names_post_receiving_demand_v2()?).ok()?;
        let turn = clock.checked_add(writes).ok()?.checked_add(agent).ok()?
            .checked_add(before_names).ok()?.checked_add(after_names).ok()?;
        // Both turns' byte/traffic/storage liabilities stay summed. Only fresh
        // scratch descriptors form a sequential peak: the sealed Observe entry
        // requires actual Authorize Sent+posts and completed scratch disposal.
        // On any ambiguity that gate refuses before a second native entry.
        let both = turn.checked_add(turn).ok()?
            .with(D::OpenFiles, turn.get(D::OpenFiles));
        demand = demand.checked_add(both).ok()?;
        let lifetime = AgentExecutionOriginalV2::guest_lifetime_residency_demand_v1()?;
        demand = demand.checked_add(lifetime).ok()?;

        // The actual installed feature8 receiver restricts its socket after
        // verified Authorize and before Child/native creation. Raw48 failures
        // cannot reach spawn. Later active receives require the same native0
        // proof and their distinct native3 is already included in lifetime.
        let raw = u64::try_from(aos_sandbox_linux::seqpacket::SeqpacketSocket::
            maximum_agent_authorize_descriptor_slots_v2().checked_mul(2)?).ok()?;
        let verified = u64::try_from(aos_sandbox_linux::seqpacket::SeqpacketSocket::
            agent_authorize_verified_retained_files_v2()).ok()?;
        let guest_phase = raw.max(verified.checked_add(lifetime.get(D::OpenFiles))?);
        let held = StorageExistingOutputOriginalV2::held_terminal_files_v6()?
            .max(crate::storage_existing_output::capture::StorageCaptureOriginalV2::held_terminal_files_v6()?);
        // Failed before probes keep every prefix and all independent posts.
        // No State reservation/Agent effect can enter that branch; an earlier
        // live Guest and the real owed Storage Abort/Ack stay co-live.
        let before_failure = before_names.get(D::OpenFiles)
            .checked_add(after_names.get(D::OpenFiles))?.checked_add(clock.get(D::OpenFiles))?
            .checked_add(lifetime.get(D::OpenFiles))?.checked_add(held)?;
        // Actual successful before leaves must be physically empty before
        // either Storage acquisition or Guest issue. Full State/Agent/native
        // after costs remain alongside every primary failure and owed Abort.
        let primary = clock.get(D::OpenFiles).checked_add(writes.get(D::OpenFiles))?
            .checked_add(agent.get(D::OpenFiles))?.checked_add(after_names.get(D::OpenFiles))?
            .checked_add(guest_phase)?.checked_add(held)?;
        // Storage's descriptor-bearing acquisition happens only in Authorize,
        // before any child exists. A failure retains its whole raw prefix and
        // still runs Host posts, but cannot reach Guest or a second receiver.
        let acquisition = turn.get(D::OpenFiles).checked_add(storage.get(D::OpenFiles))?;
        let incoming = 3_u64;
        let files = incoming.checked_add(before_failure.max(primary).max(acquisition))?;
        Some(demand.with(D::OpenFiles, files))
    }

    fn held_cutoff_v3(&self) -> Result<u64> {
        match self.capture.as_ref() {
            Some(capture) => capture.held_cutoff_v2(),
            None => self.storage.held_cutoff_v2(),
        }
    }

    fn abort_storage_v3(
        capture: &mut Option<crate::storage_existing_output::capture::StorageCaptureOriginalV2>,
        negative: &Option<super::launch_handoff::capture_resident::HostCaptureNegativeDispositionV3>,
        storage: &mut StorageExistingOutputOriginalV2,
        cutoff: u64,
    ) -> Result<()> {
        if let Some(plan) = negative {
            plan.retain_unknown_v3();
        }
        match capture.as_mut() {
            Some(capture) => capture.abort_once(),
            None => storage.abort_once(cutoff),
        }
    }

    pub(super) fn require_capture_residency_v3(&self) -> Result<(aos_sandbox_model::ExecutionId, u64)> {
        if self.first.is_some() || self.capture.is_some() && self.storage_settlement_entered || self.storage_abort_entered
            || self.capture.as_ref().is_some_and(|capture| capture.failure().is_some())
            || self.capture.is_none() && self.storage.failure().is_some()
            || self.capture_negative.is_none()
            || !self.turns.iter().all(|turn| turn.authenticated && turn.first_site.is_none()
                && turn.primary.is_none() && matches!(turn.native, Some(Ok(())))
                && matches!(turn.before, Some(Ok(()))) && matches!(turn.after, Some(Ok(()))))
            || !self.turns[0].scratch_disposed
        {
            return Err(refused());
        }
        if self.capture.is_none() && !self.storage_settlement_entered { return Err(refused()); }
        let held_cutoff = self.capture.as_ref().map(|capture| capture.held_cutoff_v2()).transpose()?
            .unwrap_or(u64::MAX);
        let cutoff = self.ongoing.as_ref().ok_or_else(refused)?.deadline_v5()?.min(held_cutoff);
        Ok((self.execution.ok_or_else(refused)?, cutoff))
    }

    pub(in crate::broker) fn ongoing_permission_v5(&self)
        -> Option<&ongoing::HostExecutionOngoingOriginalV5> {
        self.ongoing.as_ref()
    }

    pub(in crate::broker) fn monitor_original_v5(&self)
        -> Option<&super::launch_handoff::execution_monitor::HostExecutionMonitorOriginalV5> {
        self.monitor.as_deref()
    }

    pub(in crate::broker) fn monitor_due_data_v5(&self) -> Option<u64> {
        if !matches!(self.capture_residency, Some(Ok(())))
            || !self.turns[1].scratch_disposed || self.monitor.is_some()
            || self.capture_terminal.is_some() || self.capture_terminal_complete || self.query.is_some()
        { return None; }
        if self.terminal_c1_data_v3().is_some() {
            return self.capture.as_ref().map(|_| self.ongoing.as_ref()
                .map(|ongoing| ongoing.lifetime_v5().first_pre_spawn_clock_v2().boottime_nanoseconds()))
                .flatten();
        }
        match &self.monitor_complete {
            Some(complete) if !complete.terminal => Some(complete.next_due),
            Some(_) => None,
            // This already-paid original scalar schedules an immediate first
            // tick. Only the actual owning driver can check/use permission.
            None => Some(self.ongoing.as_ref()?.lifetime_v5()
                .first_pre_spawn_clock_v2().boottime_nanoseconds()),
        }
    }

    pub(in crate::broker) fn monitor_parts_v5(&mut self) -> Result<(
        aos_sandbox_model::runtime_backend::BackendOperationIdV1, usize,
        &mut ongoing::HostExecutionOngoingOriginalV5,
        &mut Option<Box<super::launch_handoff::execution_monitor::HostExecutionMonitorOriginalV5>>,
        &mut Option<super::launch_handoff::execution_monitor::MonitorCompletedDataV5>,
    )> {
        self.require_capture_residency_v3()?;
        if !self.turns[1].scratch_disposed || self.monitor.is_some()
            || self.terminal_c1_data_v3().is_some()
        { return Err(refused()); }
        let first = self.turns[1].effect.as_ref().ok_or_else(refused)?;
        if first.phase() != EffectPhaseV1::Complete || first.issue().operation() != EffectOperationV1::Observe {
            return Err(refused());
        }
        Ok((first.issue().idempotency().operation(), first.admission().specification_bytes().len(),
            self.ongoing.as_mut().ok_or_else(refused)?, &mut self.monitor, &mut self.monitor_complete))
    }

    pub(in crate::broker) fn transition_clock_v5(&mut self,
        stage: &Arc<Mutex<super::argument_handoff::ArgumentStageOriginalV2>>,
        accept: crate::plan::HostExecutionRequestBindingV2,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<&mut super::argument_handoff::ArgumentClockV2> {
        self.require_terminal_storage_disposal_v3()?;
        self.ongoing.as_mut().ok_or_else(refused)?
            .borrow_transition_admission_clock_v5(stage, accept, request)
    }

    fn terminal_c1_data_v3(&self) -> Option<&aos_sandbox_model::runtime_backend::DurableExecutionEffectV1> {
        let effect = match self.monitor_complete.as_ref() {
            Some(complete) => if complete.terminal { &complete.effect } else { return None; },
            None => self.turns[1].effect.as_ref()?,
        };
        let completion = effect.completion()?;
        aos_sandbox_protocol::execution_evidence::completion_observes_terminal_execution(effect, completion)
            .ok().filter(|terminal| *terminal).map(|_| effect)
    }

    pub(in crate::broker) fn require_terminal_storage_disposal_v3(&self) -> Result<()> {
        if self.first.is_some() || self.storage_abort_entered || self.monitor.is_some()
            || self.capture_terminal.is_some() || self.query.is_some()
            || !matches!(self.capture_residency, Some(Ok(())))
            || !self.turns.iter().all(|turn| turn.authenticated && turn.scratch_disposed
                && turn.first_site.is_none() && turn.primary.is_none()
                && matches!(turn.before, Some(Ok(()))) && matches!(turn.after, Some(Ok(())))
                && matches!(turn.native, Some(Ok(()))) && matches!(turn.disposal, Some(Ok(()))))
        { return Err(refused()); }
        let effect = self.terminal_c1_data_v3().ok_or_else(refused)?;
        let terminal = match self.monitor_complete.as_ref() {
            Some(completed) => completed.terminal_native.as_ref(),
            None => self.turns[1].terminal_native.as_ref(),
        }.ok_or_else(refused)?;
        if !terminal.matches_actual_complete_v3(effect) { return Err(refused()); }
        self.ongoing.as_ref().ok_or_else(refused)?.require_retained_storage_positive_v3()?;
        match self.capture.as_ref() {
            Some(capture) => {
                // The private completed frontier is installed only after the
                // actual native828 readback and every independent native post.
                // The SAME physical owner still lends the authenticated676.
                let complete = capture.completed_result_v2()?;
                if !self.capture_terminal_complete || !self.storage_settlement_entered
                    || complete.host_settlement_digest != effect.record_commitment()
                    || complete.execution != *effect.admission().execution().as_bytes()
                { return Err(refused()); }
            }
            None => {
                if self.storage.failure().is_some() || !self.storage_settlement_entered {
                    return Err(refused());
                }
            }
        }
        Ok(())
    }

    pub(in crate::broker) fn capture_terminal_due_data_v3(&self) -> bool {
        self.capture.is_some() && !self.capture_terminal_complete
            && self.capture_terminal.is_none() && self.terminal_c1_data_v3().is_some()
    }

    pub(in crate::broker) fn capture_terminal_failure_v3<'owner>(&'owner self,
        component: &'owner crate::plan::HostComponentControlStartupV2,
    ) -> Option<&'owner (dyn std::error::Error + 'owner)> {
        self.capture_terminal.as_deref()?.first_failure_v3(self.capture.as_ref()?, component)
    }

    pub(in crate::broker) fn capture_terminal_parts_v3(&mut self) -> Result<(
        &aos_sandbox_model::runtime_backend::DurableExecutionEffectV1,
        &mut ongoing::HostExecutionOngoingOriginalV5,
        &mut crate::storage_existing_output::capture::StorageCaptureOriginalV2,
        &mut Option<Box<super::launch_handoff::capture_terminal::HostCaptureTerminalOriginalV3>>,
        &mut bool, &mut bool, &mut bool,
    )> {
        self.require_capture_residency_v3()?;
        if !self.turns[1].scratch_disposed || self.monitor.is_some()
            || self.capture_terminal.is_some() || self.capture_terminal_complete
        { return Err(refused()); }
        // Validate before splitting the actual separately owned fields.
        if self.terminal_c1_data_v3().is_none() { return Err(refused()); }
        let c1 = match &self.monitor_complete {
            Some(complete) => &complete.effect,
            None => self.turns[1].effect.as_ref().ok_or_else(refused)?,
        };
        Ok((c1, self.ongoing.as_mut().ok_or_else(refused)?,
            self.capture.as_mut().ok_or_else(refused)?, &mut self.capture_terminal,
            &mut self.storage_settlement_entered, &mut self.storage_abort_entered,
            &mut self.capture_terminal_complete))
    }

    pub(in crate::broker) fn query_parts_v3(&mut self) -> Result<(
        aos_sandbox_model::runtime_backend::BackendOperationIdV1, usize,
        &mut ongoing::HostExecutionOngoingOriginalV5,
        &mut Option<Box<super::launch_handoff::execution_query::HostExecutionQueryOriginalV3>>,
    )> {
        // Read permission comes only from the new actual authenticated Query.
        // An old execution/Storage cutoff or sticky unknown never becomes a
        // fresh effect grant. Native/payer refusal still prevents new IO.
        if self.query.is_some() || !self.turns[1].scratch_disposed { return Err(refused()); }
        let first = self.turns[1].effect.as_ref().ok_or_else(refused)?;
        Ok((first.issue().idempotency().operation(), first.admission().specification_bytes().len(),
            self.ongoing.as_mut().ok_or_else(refused)?, &mut self.query))
    }

    pub(in crate::broker) fn query_original_v3(&self)
        -> Option<&super::launch_handoff::execution_query::HostExecutionQueryOriginalV3> {
        self.query.as_deref()
    }

    pub(in crate::broker) fn query_destination_v3(&mut self)
        -> &mut Option<Box<super::launch_handoff::execution_query::HostExecutionQueryOriginalV3>> {
        &mut self.query
    }

    pub(super) fn failed_primary_v2(&self) -> bool {
        self.first.and_then(|index| self.turns.get(index))
            .is_some_and(|turn| matches!(turn.first_site, Some(FailureSiteV2::Primary)))
    }

    pub(super) fn failed_intrinsic_v2(&self) -> bool {
        self.first.is_some_and(|index| matches!(self.turns[index].first_site,
            Some(FailureSiteV2::Before | FailureSiteV2::After | FailureSiteV2::Native)))
    }

    pub(super) fn failed_writes_v2(&self) -> Option<&Arc<Mutex<ArgumentStateWritesV2>>> {
        let index = self.first?;
        if matches!(self.turns[index].first_site, Some(FailureSiteV2::Primary)) {
            self.turns[index].writes.as_ref()
        } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let index = self.first?;
        if matches!(self.turns[index].first_site, Some(FailureSiteV2::Residency)) {
            self.capture_residency.as_ref()?.as_ref().err().map(|cause| cause as _)
        } else if matches!(self.turns[index].first_site, Some(FailureSiteV2::Storage | FailureSiteV2::External)) {
            self.capture.as_ref().and_then(|capture| capture.failure())
                .or_else(|| self.storage.failure())
                .or_else(|| self.turns[index].primary.as_ref()?.as_ref().err().map(|e| e as _))
        } else { self.turns[index].failure(self.ongoing.as_ref()) }
    }
}

fn refused() -> HostError { HostError::Fence("Host accepted execution retains unresolved custody") }

impl<S: HostStateStore, W: crate::worker::HostWorker> HostBroker<crate::catalog::FileHostCatalog, S, W> {
    pub(crate) async fn execute_accepted_execution_v2(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
        descriptor: &OwnedFd, protected_boot: [u8; 16],
        agent: &mut HostAgentLiveSessionV1, header_cutoff: u64,
    ) -> Result<Vec<u8>> {
        // Decode only the bounded protobuf selector before the real existing
        // financial/original join. Full sealed content is mapped afterward.
        let selector = ApplyHostExecutionRequestV1::decode_from_slice(request.exact_body())
            .map_err(|_| refused())?;
        let purpose = match selector.action.as_known() {
            Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE) if selector.spec_transfer_version == 5 => AcceptedContinuationV2::Authorize,
            Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE) if selector.spec_transfer_version == 1 => AcceptedContinuationV2::Observe,
            _ => return Err(refused()),
        };
        let index = match purpose { AcceptedContinuationV2::Authorize => 0, AcceptedContinuationV2::Observe => 1 };
        if !self.state_healthy || self.active_argument_writes.is_some() { return Err(refused()); }
        let held = self.argument_stages[1].as_ref().cloned().ok_or_else(refused)?;
        let original_arc = self.component_control.as_ref().cloned().ok_or_else(refused)?;
        let mut original = original_arc.lock().map_err(|_| refused())?;
        let held_arc = Arc::clone(&held);
        let mut held = held.lock().map_err(|_| refused())?;
        if !held.authenticated || held.request.2 != request.session_binding() { return Err(refused()); }
        held.require_positive_opening_residency_v6()?;
        original.require_argument_boot_v2(protected_boot)?;
        let binding = HostExecutionRequestBindingV2 { id: held.request.1, session: held.request.2, signed: held.request.3 };
        {
            // These fixed, already-priced scalar slots identify the actual
            // entered request even if the financial/native entry itself refuses.
            let accepted = held.accepted.as_mut().ok_or_else(refused)?;
            if accepted.first.is_some() || accepted.turns[index].request.is_some()
                || (index == 1 && (!accepted.turns[0].authenticated || !accepted.turns[0].scratch_disposed)) { return Err(refused()); }
            accepted.turns[index].request = Some(HostExecutionRequestBindingV2 {
                id: request.request_id(), session: request.session_binding(),
                signed: request.signed_request_digest(),
            });
        }
        let receiving = original.begin_accepted_execution_v2(purpose, binding, request, held.complete_demand);
        let mut receiving = match receiving {
            Ok(receiving) => receiving,
            Err(error) => {
                let accepted = held.accepted.as_mut().ok_or_else(refused)?;
                accepted.first.get_or_insert(index);
                let turn = &mut accepted.turns[index];
                turn.first_site.get_or_insert(FailureSiteV2::Native);
                turn.entry = Some(Err(error));
                if !accepted.storage_settlement_entered && !accepted.storage_abort_entered {
                    accepted.storage_abort_entered = true;
                    if let Some(cutoff) = accepted.cutoff { let _ = AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, cutoff); }
                }
                return Err(refused());
            }
        };
        let mut complete_demand = held.complete_demand;
        let ArgumentStageOriginalV2 { owner, argument, accepted, .. } = &mut *held;
        let owner = owner.as_mut().ok_or_else(refused)?;
        let argument = argument.as_ref().ok_or_else(refused)?;
        let accepted = accepted.as_mut().ok_or_else(refused)?;
        let original_cutoff = argument.completed_original_cutoff_v2().map_err(|_| refused())?;
        if accepted.cutoff.is_some_and(|old| old != original_cutoff) { return Err(refused()); }
        accepted.cutoff = Some(original_cutoff);
        let cutoff = original_cutoff.min(header_cutoff);
        // Observe must preserve the ORIGINAL live hold's possibly shorter
        // deadline, never renew it from the source or a later request header.
        let cutoff = if index == 1 {
            cutoff.min(accepted.held_cutoff_v3()?)
        } else { cutoff };
        let turn = &mut accepted.turns[index];
        turn.clock = Some(ArgumentClockV2::capture_effect_v4(protected_boot));
        let clock = turn.clock.as_mut().ok_or_else(refused)?;
        turn.entry = Some(clock.deadline(cutoff).map(|_| ()));
        if !turn.entry.as_ref().is_some_and(Result::is_ok) {
            turn.first_site = Some(FailureSiteV2::Entry);
            accepted.first = Some(index);
            if !accepted.storage_settlement_entered && !accepted.storage_abort_entered {
                accepted.storage_abort_entered = true;
                let _ = AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, cutoff);
            }
            return Err(refused());
        }
        // Keep this SAME original OFD alias through the protected outcome and
        // Sent boundary. The extra alias exists solely for the consuming shared
        // mapping engine and its finite peak is included before59.
        turn.descriptor = Some(descriptor.as_fd().try_clone_to_owned());
        turn.mapping_alias = match turn.descriptor.as_ref() {
            Some(Ok(descriptor)) => Some(descriptor.as_fd().try_clone_to_owned()),
            _ => None,
        };
        match turn.mapping_alias.take() {
            Some(Ok(fd)) => turn.mapping = Some(SealedMemfdMapping::run(fd, selector.spec_content_bytes,
                aos_sandbox_protocol::host_execution::admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5 as u64, |bytes, _| bytes.to_vec())),
            retained => turn.mapping_alias = retained,
        }
        // The held descriptor above survives both mapping and later transport
        // errors. The actual immutable-file cause stays beside its original.
        let mapped = turn.mapping.as_ref().and_then(|result| result.as_ref().ok());
        if mapped.is_none() {
            turn.first_site = Some(FailureSiteV2::Mapping);
            accepted.first = Some(index);
            if !accepted.storage_settlement_entered && !accepted.storage_abort_entered {
                accepted.storage_abort_entered = true;
                let _ = AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, cutoff);
            }
            return Err(refused());
        }
        turn.entry = Some(clock.deadline(cutoff).map(|_| ()));
        turn.before = Some(if turn.entry.as_ref().is_some_and(Result::is_ok) {
            receiving.observe_before_v2().await
        } else { Err(refused()) });
        if !turn.entry.as_ref().is_some_and(Result::is_ok) {
            turn.first_site = Some(FailureSiteV2::Entry);
        } else if !turn.before.as_ref().is_some_and(Result::is_ok) {
            turn.first_site = Some(FailureSiteV2::Before);
        }
        // The awaited PID1 round cannot extend the original source cutoff.
        // Retain its new clock refusal before any of the five native probes.
        if turn.before.as_ref().is_some_and(Result::is_ok) {
            turn.entry = Some(clock.deadline(cutoff).map(|_| ()));
            if !turn.entry.as_ref().is_some_and(Result::is_ok) {
                turn.first_site = Some(FailureSiteV2::Entry);
            }
        }
        if turn.before.as_ref().is_some_and(Result::is_ok)
            && turn.entry.as_ref().is_some_and(Result::is_ok)
        {
            // All five actual writers name the same fixed protected root.
            // Resolve it once for this interval; each writer still performs its
            // own exact UID/path/limits/held-directory and Lock/Journal checks.
            let _ = owner.observe_execution_directory_v6(&mut turn.shared_directory);
            let native_before = owner.observe_execution_names_with_directory_v6(
                &turn.shared_directory, &mut turn.names[0], &mut turn.name_results[0]);
            turn.argument_name_results[0] = Some(argument.observe_names_before_with_directory_v6(
                &turn.shared_directory, &mut turn.argument_names[0]));
            turn.shared_directory.settle_positive_once_v1();
            AcceptedTurnV2::retire_positive_before_names_v6(
                &mut turn.names[0], &turn.name_results[0],
                &mut turn.argument_names[0], &turn.argument_name_results[0]);
            let primary = (|| -> std::result::Result<Vec<u8>, AcceptedErrorV2> {
                if native_before.is_err() || !matches!(turn.argument_name_results[0], Some(Ok(()))) {
                    turn.frontier = if native_before.is_err() { FailureSiteV2::NamesBefore }
                        else { FailureSiteV2::ArgumentBefore };
                    return Err(refused().into());
                }
                turn.frontier = FailureSiteV2::Primary;
                AcceptedTurnV2::require_positive_before_names_v6(
                    &turn.shared_directory, &turn.names[0], &turn.argument_names[0])?;
                let mut claim = owner.claim()?;
                let sample = clock.sample()?;
                if sample.boottime_nanoseconds() >= cutoff { return Err(refused().into()); }
                let bytes = turn.mapping.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(refused)?;
                if index == 0 {
                    let content = HostExecutionAdmissionContentV5::decode(bytes)?;
                    let physical = content.capture_source_v2().is_some();
                    let fields = ExecutionSpecAttemptFieldsV1::decode(content.attempt_bytes())
                        .map_err(|_| refused())?;
                    if physical {
                        // Capture construction occurs only after its complete
                        // fixed supplier was joined before59. Keep the original
                        // before any fallible native capture or Begin.
                        argument.require_capture_preparation_v5(
                            &claim, agent, &content, request.session_binding(), sample)?;
                        clock.deadline(cutoff.min(content.capture_source_v2().ok_or_else(refused)?.original_source_v1().original_deadline_boottime_nanoseconds())
                            .min(content.capture_attempt_v1().ok_or_else(refused)?.effective_deadline_boottime_nanoseconds().ok_or_else(refused)?))?;
                        accepted.capture = Some(crate::storage_existing_output::capture::StorageCaptureOriginalV2::new());
                        let storage = accepted.capture.as_mut().ok_or_else(refused)?;
                        turn.frontier = FailureSiteV2::Storage;
                        self.catalog.capture_execution_capture_original_v3(storage)?;
                        storage.begin_ongoing_once_v4(
                            *content.capture_source_v2().ok_or_else(refused)?, content.capture_attempt_v1().ok_or_else(refused)?, cutoff)?;
                        let pipes = storage.pipe_loan_v2()?;
                        turn.frontier = FailureSiteV2::Primary;
                        argument.require_capture_specification_v5(
                            &claim, agent, &content, &pipes, request.session_binding(), sample)?;
                    } else {
                        argument.require_specification_v2(&claim, agent, &fields,
                            request.session_binding(), sample)?;
                        complete_demand = receiving.prepay_ssh_birth_once_v1(
                            complete_demand, turn.guest.as_mut().ok_or_else(refused)?)?;
                    }
                    let response = aos_sandbox_protocol::storage_output_reserve::continuation
                        ::decode_storage_output_registration_response_data_v1(content.storage_response_bytes())?;
                    let row = &response.canonical_reservation;
                    let amount = |start| -> Result<u64> {
                        Ok(u64::from_be_bytes(row[start..start + 8].try_into().map_err(|_| refused())?))
                    };
                    let expected = ExpectedExistingOutputV1::new(Sha256::digest(row).into(),
                        *fields.source_heads.output_claim.as_bytes(), amount(104)?, amount(112)?, amount(120)?)?;
                    turn.frontier = FailureSiteV2::Storage;
                    if !physical {
                        self.catalog.capture_execution_storage_original_v2(&mut accepted.storage)?;
                        accepted.storage.query_once(*fields.execution.as_bytes(), *fields.create_operation.as_bytes(),
                            *fields.source_heads.assignment_digest.as_bytes(), expected, cutoff)?;
                        accepted.storage.begin_hold_once(cutoff)?;
                    }
                    accepted.execution = Some(fields.execution);
                }
                turn.frontier = FailureSiteV2::Storage;
                if let Some(capture) = accepted.capture.as_ref() {
                    // After Authorize's real Sent, pipe aliases are retired;
                    // the original physical session still lends its cutoff.
                    capture.held_cutoff_v2()?;
                } else {
                    accepted.storage.held_proof_v2()?;
                }
                turn.frontier = FailureSiteV2::Primary;
                agent.validate_claim(&claim).map_err(HostArgumentAttemptErrorV1::from)?;
                self.active_argument_writes = Some(Arc::clone(turn.writes.as_ref().ok_or_else(refused)?));
                if index == 0 {
                    self.active_accepted_authorization = Some((request.request_id(),
                        request.session_binding(), request.signed_request_digest()));
                }
                let reservation = self.reserve_host_execution(&claim, request, Some(bytes), protected_boot, || clock.sample());
                self.active_accepted_authorization = None;
                turn.reservation = Some(reservation?);
                if index == 0 {
                    let content = HostExecutionAdmissionContentV5::decode(bytes)?;
                    let pipes = accepted.capture.as_ref().map(|capture| capture.pipe_loan_v2()).transpose()?;
                    let launch = self.launch_original.as_ref().ok_or_else(refused)?;
                    let reservation = turn.reservation.take().ok_or_else(refused)?;
                    // Park the whole signed native reservation for either mode
                    // before any fallible ongoing comparison or Guest issue.
                    accepted.ongoing = Some(ongoing::HostExecutionOngoingOriginalV5::new(
                        reservation, &content, &held_arc, launch, binding));
                    turn.frontier = FailureSiteV2::Ongoing;
                    let ongoing = accepted.ongoing.as_mut().ok_or_else(refused)?;
                    ongoing.prepare_before_issue_v5(request, &claim, &accepted.storage, pipes.as_ref())?;
                    ongoing.require_same_v5(&held_arc, binding, &accepted.storage, pipes.as_ref())?;
                    turn.frontier = FailureSiteV2::Primary;
                }
                let reservation = if index == 0 {
                    accepted.ongoing.as_ref().ok_or_else(refused)?.reservation()
                } else { turn.reservation.as_ref().ok_or_else(refused)? };
                let HostExecutionGrantRequestV1::Apply(apply) = reservation.request() else { return Err(refused().into()); };
                if accepted.execution != Some(apply.execution_id())
                    || apply.action() != if index == 0 { EffectOperationV1::AuthorizeExecution } else { EffectOperationV1::Observe }
                    || (index == 1 && accepted.source != Some(apply.source_commitment()))
                { return Err(refused().into()); }
                accepted.source = Some(apply.source_commitment());
                turn.frontier = FailureSiteV2::Storage;
                let live_cutoff = cutoff.min(match accepted.capture.as_ref() {
                    Some(capture) => capture.held_cutoff_v2()?,
                    None => accepted.storage.held_cutoff_v2()?,
                });
                turn.frontier = FailureSiteV2::Ongoing;
                // Acquisition permission and execution lifetime both constrain
                // the final native write, including after readiness waits.
                let live_cutoff = live_cutoff.min(
                    accepted.ongoing.as_ref().ok_or_else(refused)?.deadline_v5()?);
                turn.frontier = FailureSiteV2::Primary;
                let deadline = clock.deadline(live_cutoff)?;
                clock.bind_effect_write_v4(&reservation.effect)?;
                let mut before_native_write = || clock.sample_effect_write_v4(live_cutoff)
                    .map_err(|_| crate::live_agent::HostAgentLiveErrorV1::RetainedEffectClock);
                if index == 0 {
                    let pipes = accepted.capture.as_ref().map(|capture| capture.pipe_loan_v2()).transpose()?;
                    let ongoing = accepted.ongoing.as_ref().ok_or_else(refused)?;
                    accepted.capture_negative = Some(self.prearm_execution_hold_v5(
                        &held_arc, &mut receiving, &original_arc, binding, agent,
                        &accepted.storage, pipes.as_ref(), ongoing.deadline_v5()?, ongoing,
                    )?);
                    accepted.capture_negative.as_ref().ok_or_else(refused)?
                        .require_prearmed_v3(&held_arc, ongoing)?;
                }
                turn.effect = Some(if index == 0 && accepted.capture.is_some() {
                    let pipes = accepted.capture.as_ref().ok_or_else(refused)?.pipe_loan_v2()?;
                    execution_effect::execute_reserved_effect_retaining_capture_v3(
                        reservation, &mut claim, agent, live_cutoff, deadline,
                        turn.guest.as_mut().ok_or_else(refused)?, &mut before_native_write, &pipes)?
                } else {
                    execution_effect::execute_reserved_effect_retaining_v2(
                        reservation, &mut claim, agent, live_cutoff, deadline,
                        turn.guest.as_mut().ok_or_else(refused)?, &mut before_native_write)?
                });
                let effect = turn.effect.as_ref().ok_or_else(refused)?;
                if effect.phase() != EffectPhaseV1::Complete
                    || !effect.completion().is_some_and(|completion|
                        completion.status() == EffectCompletionStatusV1::Succeeded)
                { return Err(refused().into()); }
                turn.terminal_native = terminal_disposal::HostGuestTerminalNativeV3::observe_actual_claim_v3(
                    &claim, effect)?;
                let body = execution_effect::outcome(
                    apply.operation_id(), apply.execution_id(), apply.source_commitment(), Some(effect), &claim,
                )?.encode_to_vec();
                if !reservation.matches(request.method(), request.request_id(), request.exact_body(), &claim) {
                    return Err(refused().into());
                }
                self.complete_host_execution_reservation(reservation, &claim, &body)?;
                if index == 1 && accepted.capture.is_none() {
                    clock.deadline(cutoff)?;
                    turn.frontier = FailureSiteV2::Storage;
                    accepted.storage_settlement_entered = true;
                    accepted.storage.settle_once(*effect.record_commitment().as_bytes(), cutoff)?;
                }
                Ok(body)
            })();
            if primary.is_err() { turn.first_site.get_or_insert(turn.frontier); }
            turn.primary = Some(primary);
        }
        self.active_argument_writes = None;
        self.active_accepted_authorization = None;
        // Every entered primary owes these native/name and PID1 posts even if
        // append or settlement poisoned its financial/semantic result.
        if !turn.primary.as_ref().is_some_and(|r| r.is_ok()) {
            accepted.first = Some(index);
            if !accepted.storage_settlement_entered && !accepted.storage_abort_entered {
                accepted.storage_abort_entered = true;
                let _ = AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, cutoff);
            }
        }
        let _ = owner.observe_execution_names_post_v2(&mut turn.names[1], &mut turn.name_results[1]);
        turn.argument_name_results[1] = Some(argument.observe_names_post_v2(&mut turn.argument_names[1]));
        turn.after = Some(receiving.observe_after_v2().await);
        if !turn.before.as_ref().is_some_and(Result::is_ok)
            || !turn.primary.as_ref().is_some_and(|r| r.is_ok())
            || !turn.after.as_ref().is_some_and(Result::is_ok)
            || !turn.name_results[1].iter().all(|r| matches!(r, Some(Ok(()))))
            || !matches!(turn.argument_name_results[1], Some(Ok(())))
        {
            if !turn.name_results[1].iter().all(|r| matches!(r, Some(Ok(())))) {
                turn.first_site.get_or_insert(FailureSiteV2::NamesAfter);
            } else if !matches!(turn.argument_name_results[1], Some(Ok(()))) {
                turn.first_site.get_or_insert(FailureSiteV2::ArgumentAfter);
            } else if !turn.after.as_ref().is_some_and(Result::is_ok) {
                turn.first_site.get_or_insert(FailureSiteV2::After);
            }
            accepted.first = Some(index);
            if !accepted.storage_settlement_entered && !accepted.storage_abort_entered {
                accepted.storage_abort_entered = true;
                let _ = AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, cutoff);
            }
            return Err(refused());
        }
        turn.native = Some(receiving.finish_native_v2());
        if !turn.native.as_ref().is_some_and(Result::is_ok) {
            turn.first_site.get_or_insert(FailureSiteV2::Native);
            accepted.first = Some(index);
            if !accepted.storage_settlement_entered && !accepted.storage_abort_entered {
                accepted.storage_abort_entered = true;
                let _ = AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, cutoff);
            }
            return Err(refused());
        }
        let body = match turn.primary.take() {
            Some(Ok(body)) => body,
            retained => { turn.primary = retained; return Err(refused()); }
        };
        receiving.retain_pending_authenticated_v2()?;
        Ok(body)
    }
}


impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker> HostBroker<C, S, W> {
    // Called only from the existing protected Session CAS/readback/Sent finish.
    // No caller-supplied completion bool or receipt can release this owner.
    // Comparison-only transport selection. The sealed callee still rechecks
    // the full actual owner/Session/phase before touching any native original.
    pub(crate) fn has_accepted_execution_v2(&self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        let Some(stage) = self.argument_stages[1].as_ref() else { return false; };
        let Ok(stage) = stage.lock() else { return false; };
        let Some(accepted) = stage.accepted.as_ref() else { return false; };
        let Ok(selector) = ApplyHostExecutionRequestV1::decode_from_slice(request.exact_body()) else { return false; };
        // Failure-closed custody for this same identity remains on this route;
        // unrelated historical observations retain their existing dispatch.
        stage.authenticated && stage.request.2 == request.session_binding()
            && selector.action.as_known() == Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE)
            && accepted.execution.is_some_and(|execution| selector.execution_id.as_slice() == execution.as_bytes())
            && accepted.source.is_some_and(|source| selector.source_operation_commitment.as_slice() == source.as_bytes())
    }

    pub(crate) fn abort_pending_accepted_execution_v2(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;
        // Only the actual received authenticated Session and exact existing
        // continuation identity can close a still-held predecessor on an
        // outer pre-dispatch refusal. Unrelated requests cannot select it.
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.authorization().is_none() || !self.has_accepted_execution_v2(request)
        { return Err(refused()); }
        let stage = self.argument_stages[1].as_ref().cloned().ok_or_else(refused)?;
        let original = self.component_control.as_ref().cloned().ok_or_else(refused)?;
        let original = original.lock().map_err(|_| refused())?;
        let mut held = stage.lock().map_err(|_| refused())?;
        original.require_accepted_terminal_v2(HostExecutionRequestBindingV2 {
            id: held.request.1, session: held.request.2, signed: held.request.3,
        })?;
        let accepted = held.accepted.as_mut().ok_or_else(refused)?;
        let actual = HostExecutionRequestBindingV2 { id: request.request_id(),
            session: request.session_binding(), signed: request.signed_request_digest() };
        if accepted.turns[1].request.is_some_and(|prior| prior != actual) { return Err(refused()); }
        accepted.turns[1].request = Some(actual);
        accepted.first.get_or_insert(1);
        accepted.turns[1].first_site.get_or_insert(FailureSiteV2::External);
        if accepted.storage_settlement_entered || accepted.storage_abort_entered { return Ok(()); }
        accepted.storage_abort_entered = true;
        AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, accepted.cutoff.ok_or_else(refused)?)
    }

    // Only closes an already-entered fixed hold; this cannot authorize work,
    // release payment, create a claim or accept a successful external result.
    pub(crate) fn abort_accepted_execution_v2(&mut self,
        id: [u8; 16], session: [u8; 32], signed: [u8; 32],
    ) -> Result<()> {
        let stage = self.argument_stages[1].as_ref().cloned().ok_or_else(refused)?;
        let original = self.component_control.as_ref().cloned().ok_or_else(refused)?;
        let original = original.lock().map_err(|_| refused())?;
        let mut held = stage.lock().map_err(|_| refused())?;
        let binding = HostExecutionRequestBindingV2 { id: held.request.1,
            session: held.request.2, signed: held.request.3 };
        original.require_accepted_terminal_v2(binding)?;
        let accepted = held.accepted.as_mut().ok_or_else(refused)?;
        let actual = HostExecutionRequestBindingV2 { id, session, signed };
        let index = accepted.turns.iter().position(|turn| turn.request == Some(actual))
            .ok_or_else(refused)?;
        accepted.first.get_or_insert(index);
        accepted.turns[index].first_site.get_or_insert(FailureSiteV2::External);
        if accepted.storage_settlement_entered || accepted.storage_abort_entered {
            return Ok(());
        }
        accepted.storage_abort_entered = true;
        AcceptedExecutionOriginalV2::abort_storage_v3(&mut accepted.capture, &accepted.capture_negative, &mut accepted.storage, accepted.cutoff.ok_or_else(refused)?)
    }

    pub(crate) fn retire_authenticated_accepted_execution_v2(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION {
            return Err(refused());
        }
        let stage = self.argument_stages[1].as_ref().cloned().ok_or_else(refused)?;
        let original = self.component_control.as_ref().cloned().ok_or_else(refused)?;
        let mut original = original.lock().map_err(|_| refused())?;
        let mut held = stage.lock().map_err(|_| refused())?;
        let binding = HostExecutionRequestBindingV2 { id: held.request.1,
            session: held.request.2, signed: held.request.3 };
        let accepted = held.accepted.as_mut().ok_or_else(refused)?;
        if accepted.first.is_some() { return Err(refused()); }
        let actual = HostExecutionRequestBindingV2 { id: request.request_id(),
            session: request.session_binding(), signed: request.signed_request_digest() };
        let index = accepted.turns.iter().position(|turn| turn.request == Some(actual))
            .ok_or_else(refused)?;
        let turn = &mut accepted.turns[index];
        if turn.authenticated || turn.primary.is_some()
            || !turn.native.as_ref().is_some_and(Result::is_ok)
            || !turn.before.as_ref().is_some_and(Result::is_ok)
            || !turn.after.as_ref().is_some_and(Result::is_ok)
        { return Err(refused()); }
        let purpose = if index == 0 { AcceptedContinuationV2::Authorize } else { AcceptedContinuationV2::Observe };
        original.finish_authenticated_accepted_execution_v2(purpose, request)?;
        turn.authenticated = true;
        if index == 0 {
            // The sealed actual Session caller reached Commit/readback/Sent and
            // every independent Host post before marking this exact phase.
            let disposal = (|| {
                original.require_authorize_samples_positive_v2(request)?;
                turn.require_positive_scratch_v2()?;
                if let Some(capture) = accepted.capture.as_mut() {
                    // All actual native/sample/alias checks precede any close.
                    // Retain the physical session; only sent writer aliases end.
                    capture.retire_transferred_pipes_once()?;
                }
                turn.dispose_positive_scratch_v2(accepted.ongoing.as_mut())?;
                original.dispose_authorize_samples_positive_v2(request)
            })();
            let positive = disposal.is_ok();
            turn.disposal = Some(disposal);
            if !positive {
                if let Some(plan) = &accepted.capture_negative {
                    plan.retain_unknown_v3();
                }
                turn.first_site.get_or_insert(FailureSiteV2::Native);
                accepted.first.get_or_insert(index);
                return Err(refused());
            }
            return Ok(());
        }
        let (execution, cutoff) = accepted.require_capture_residency_v3()?;
        drop(held);
        let residency = self.park_capture_after_observe_v3(&mut original, &stage, request,
            binding, execution, cutoff);
        let mut held = stage.lock().map_err(|_| refused())?;
        let accepted = held.accepted.as_mut().ok_or_else(refused)?;
        let positive = residency.is_ok();
        accepted.capture_residency = Some(residency);
        if !positive {
            if let Some(plan) = &accepted.capture_negative {
                plan.retain_unknown_v3();
            }
            accepted.first.get_or_insert(index);
            accepted.turns[index].first_site.get_or_insert(FailureSiteV2::Residency);
            return Err(refused());
        }
        let disposal = (|| {
            original.require_first_observe_samples_positive_v5(request)?;
            accepted.turns[index].require_positive_scratch_v2()?;
            // The original Authorize clock already belongs to ongoing. The
            // completed firstObserve temporary clock is never borrowed again.
            accepted.turns[index].dispose_positive_scratch_v2(None)?;
            original.dispose_first_observe_samples_positive_v5(request)
        })();
        let positive = disposal.is_ok();
        accepted.turns[index].disposal = Some(disposal);
        if !positive {
            if let Some(plan) = &accepted.capture_negative { plan.retain_unknown_v3(); }
            accepted.first.get_or_insert(index);
            accepted.turns[index].first_site.get_or_insert(FailureSiteV2::Native);
            return Err(refused());
        }
        drop(held);
        self.argument_stages[1].take().ok_or_else(refused)?;
        Ok(())
    }
}

#[cfg(test)]
mod before_name_retirement_tests_v6 {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[test]
    fn only_actual_complete_before_name_leaves_release_files() {
        let directory = tempfile::tempdir().unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        for name in ["history.journal", "history.journal.lock"] {
            std::fs::write(directory.path().join(name), []).unwrap();
            std::fs::set_permissions(directory.path().join(name),
                std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let parent = std::fs::File::open(directory.path()).unwrap();
        let file = std::fs::File::open(directory.path().join("history.journal")).unwrap();
        let lock = std::fs::File::open(directory.path().join("history.journal.lock")).unwrap();
        let mut turn = AcceptedTurnV2::new();
        turn.names[0][0].begin(false).unwrap();
        let observed = turn.names[0][0].observe_names_at(&parent, "history.journal", uid, &lock, &file);
        turn.name_results[0][0] = Some(turn.names[0][0].finish(observed));
        assert!(matches!(turn.name_results[0][0], Some(Ok(()))));
        assert_eq!(turn.names[0][0].retained_file_count(), 2);

        std::fs::remove_file(directory.path().join("history.journal")).unwrap();
        turn.names[0][1].begin(false).unwrap();
        let observed = turn.names[0][1].observe_names_at(&parent, "history.journal", uid, &lock, &file);
        turn.name_results[0][1] = Some(turn.names[0][1].finish(observed));
        assert!(matches!(turn.name_results[0][1], Some(Err(_))));
        let failed_files = turn.names[0][1].retained_file_count();
        let failed_cause = turn.names[0][1].failure().unwrap() as *const dyn Error;

        AcceptedTurnV2::retire_positive_before_names_v6(
            &mut turn.names[0], &turn.name_results[0],
            &mut turn.argument_names[0], &turn.argument_name_results[0]);

        assert_eq!(turn.names[0][0].retained_file_count(), 0);
        assert!(turn.names[0][0].is_complete());
        assert_eq!(turn.names[0][1].retained_file_count(), failed_files);
        assert!(std::ptr::eq(turn.names[0][1].failure().unwrap() as *const dyn Error, failed_cause));
        assert!(turn.names[0][0].begin(false).is_err());
        assert!(turn.names[0][1].begin(false).is_err());
    }
    #[test]
    fn complete_accepted_native_phases_stay_within_default_host_file_limit() {
        let demand = AcceptedExecutionOriginalV2::fixed_demand_v2().unwrap();
        assert!(demand.get(D::OpenFiles) <= 128,
            "actual accepted native phases exceed the unchanged Host file limit: {:?}", demand);
    }

}
