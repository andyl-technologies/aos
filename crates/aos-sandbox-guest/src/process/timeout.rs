//! Owns the actual pre-spawn child prefix and standing execution timeout.
//!
//! The existing worker advances finite native stages without effect/monitor
//! locks. The existing actor publishes only actual recursive-empty/reaped
//! outcomes. Failed originals stay occupied; no cold PID can recreate one.

use super::*;

pub(crate) struct LiveProcessRegistryV1 {
    pub(super) entries: std::collections::BTreeMap<[u8; 16], Box<LiveProcess>>,
    pub(super) pending: Option<Box<PendingExecutionChildV1>>,
    pub(super) pending_lent: bool,
    failed_input: Option<ChildStdin>,
    failed_registration: Option<crate::bridge::AttachIoRegistrationOriginalV1>,
}

impl LiveProcessRegistryV1 {
    pub(super) fn has_failed_input_v1(&self) -> bool {
        self.failed_input.is_some() || self.failed_registration.is_some()
    }
}

impl Default for LiveProcessRegistryV1 {
    fn default() -> Self { Self { entries: Default::default(), pending: None, pending_lent: false, failed_input: None, failed_registration: None } }
}

impl std::ops::Deref for LiveProcessRegistryV1 {
    type Target = std::collections::BTreeMap<[u8; 16], Box<LiveProcess>>;
    fn deref(&self) -> &Self::Target { &self.entries }
}

impl std::ops::DerefMut for LiveProcessRegistryV1 {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.entries }
}

pub(super) struct PendingExecutionChildV1 {
    pub(super) command: Option<Command>,
    pub(super) spawned: Option<std::io::Result<Child>>,
    pub(super) input: Option<ChildStdin>,
    pub(super) pty_master: Option<OwnedFd>,
    pub(super) pty_slave: Option<OwnedFd>,
    pub(super) pty_name: Option<std::ffi::CString>,
    pub(super) pty_result: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) lifetime: aos_sandbox_linux::process::ExecutionChildLifetimeOriginalV1,
    pub(super) tree: Option<Result<crate::execution_tree::ExecutionTree, GuestProcessEffectErrorV1>>,
    pub(super) tree_native: crate::execution_tree::ExecutionTreeOpeningOriginalV1,
    pub(super) start_ticks_native: aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1,
    pub(super) membership_native: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1,
    pub(super) record: Option<ProcessRecord>,
    pub(super) record_result: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) record_native: crate::ledger::RetainedProcessRecordWriteV1,
    pub(super) membership: Option<Result<(), GuestProcessEffectErrorV1>>,
}

impl PendingExecutionChildV1 {
    fn new() -> Self {
        Self { command: None, spawned: None, input: None,
            pty_master: None, pty_slave: None, pty_name: None, pty_result: None,
            lifetime: Default::default(), tree: None,
            tree_native: crate::execution_tree::ExecutionTreeOpeningOriginalV1::new(),
            start_ticks_native: Default::default(), membership_native: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::new(),
            record: None,
            record_result: None, record_native: crate::ledger::RetainedProcessRecordWriteV1::new(),
            membership: None }
    }
}

// Only the serial effect actor borrows the pending startup. The actual
// Child/input/tree remain owned by this loan across fallible filesystem work;
// parking on every return avoids holding the scheduler's live-map mutex.
pub(super) struct PendingExecutionChildLoanV1<'registry> {
    pub(super) registry: &'registry std::sync::Mutex<LiveProcessRegistryV1>,
    pub(super) original: Option<Box<PendingExecutionChildV1>>,
}

impl<'registry> PendingExecutionChildLoanV1<'registry> {
    pub(super) fn enter(registry: &'registry std::sync::Mutex<LiveProcessRegistryV1>)
        -> Result<Self, GuestProcessEffectErrorV1>
    {
        let mut live = registry.lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        if live.pending.is_some() || live.pending_lent {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        live.pending_lent = true;
        Ok(Self { registry, original: Some(Box::new(PendingExecutionChildV1::new())) })
    }
}

impl Drop for PendingExecutionChildLoanV1<'_> {
    fn drop(&mut self) {
        // Poison never authorizes another effect. Recover only to preserve
        // native custody, including unwinding before a normal return.
        let mut live = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        live.pending = self.original.take();
        live.pending_lent = false;
    }
}

pub(super) struct QuiescentExecutionLoanV1<'registry> {
    pub(super) registry: &'registry std::sync::Mutex<LiveProcessRegistryV1>,
    pub(super) execution: [u8; 16],
    pub(super) original: Option<Box<LiveProcess>>,
}

impl Drop for QuiescentExecutionLoanV1<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.execution, original);
        }
    }
}

pub(super) struct StartupInputLoanV1<'registry> {
    registry: &'registry std::sync::Mutex<LiveProcessRegistryV1>,
    execution: [u8; 16],
    input: Option<ChildStdin>,
}

impl<'registry> StartupInputLoanV1<'registry> {
    pub(super) fn new(registry: &'registry std::sync::Mutex<LiveProcessRegistryV1>, execution: [u8; 16]) -> Self {
        Self { registry, execution, input: None }
    }

    pub(super) fn set(&mut self, input: ChildStdin) { self.input = Some(input); }
    pub(super) fn as_mut(&mut self) -> Option<&mut ChildStdin> { self.input.as_mut() }
    pub(super) fn take(&mut self) -> Option<ChildStdin> { self.input.take() }
}

impl Drop for StartupInputLoanV1<'_> {
    fn drop(&mut self) {
        if let Some(input) = self.input.take() {
            let mut live = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(process) = live.get_mut(&self.execution) {
                process.startup_input = Some(input);
            } else {
                // The serial actor normally retains this exact live entry.
                // Poison/unwind parking still cannot discard the native pipe.
                live.failed_input = Some(input);
            }
        }
    }
}

pub(super) struct IoRegistrationLoanV1<'registry> {
    pub(super) registry: &'registry std::sync::Mutex<LiveProcessRegistryV1>,
    pub(super) execution: [u8; 16],
    pub(super) original: Option<crate::bridge::AttachIoRegistrationOriginalV1>,
}

impl Drop for IoRegistrationLoanV1<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let mut live = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(process) = live.get_mut(&self.execution) {
                process.io_registration = Some(original);
            } else {
                live.failed_registration = Some(original);
            }
        }
    }
}

pub(crate) struct LiveProcess {
    pub(super) child: Child,
    pub(super) startup_input: Option<ChildStdin>,
    pub(super) startup_write: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) io_registration: Option<crate::bridge::AttachIoRegistrationOriginalV1>,
    pub(super) lifetime: aos_sandbox_linux::process::ExecutionChildLifetimeOriginalV1,
    pub(super) lifetime_record: crate::ledger::ExecutionLifetimeRecordV1,
    pub(super) timeout_record: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) terminal_native: crate::ledger::RetainedProcessRecordWriteV1,
    pub(super) timeout_native: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) timeout_terminal: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) timeout_finish: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) normal_terminal: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) normal_finish: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) record: ProcessRecord,
    pub(super) pty_master: Option<std::sync::Arc<OwnedFd>>,
    pub(crate) tree: std::sync::Arc<crate::execution_tree::ExecutionTree>,
    pub(super) ssh_plan: Option<aos_sandbox_agent::openssh_receiving::OpenSshDescendantPlanDataV1>,
    pub(super) ssh_standing: Option<Box<super::ssh_lifetime::SshStandingExecutionV1>>,
}

/// Advances only standing timeouts of the actual owned original children.
/// This native-only step never takes the effect/monitor locks or writes a file.
/// No list or archive grows while polling: one fixed live slot owns each attempt.
pub(crate) fn poll_original_execution_timeouts_v1(ledger: &Ledger)
    -> Result<Option<[u8; 16]>, GuestProcessEffectErrorV1>
{
    let mut live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    if let Some(pending) = live.pending.as_mut() {
        if pending.input.is_some() && pending.lifetime.failure().is_none() {
            if let Some(Ok(child)) = pending.spawned.as_mut() {
                if pending.lifetime.timeout_entered_v1() {
                    if let Some(Ok(tree)) = pending.tree.as_ref() {
                        let _ = pending.lifetime.poll_termination_once(tree.population_for_original_timeout_v1(), child);
                    } else {
                        let _ = pending.lifetime.poll_unreleased_child_once(child);
                    }
                } else if pending.lifetime.is_expired().is_ok_and(|expired| expired) {
                    if let (Some(Ok(tree)), Some(record)) = (pending.tree.as_ref(), pending.record.as_ref()) {
                        let _ = tree.terminate_expired_child_v1(record, &mut pending.lifetime, child);
                    } else {
                        // This private input has never left Pending and no byte
                        // has been written: the trusted helper is still blocked
                        // before any Tenant exec/fork. Only that actual Child
                        // can be killed; no cgroup/Guardian permission follows.
                        let _ = pending.lifetime.terminate_unreleased_child_once(child);
                    }
                }
            }
        }
        // Even a reaped helper does not erase the failed startup's original
        // record/native prefix or reopen the one pending financial slot.
    }
    // Dispatch every due original kill before any filesystem publication.
    // The original accepted request and immutable v3 origin were durable before
    // releasing any Tenant specification; this is their already-authorized timeout, not a fresh control op.
    for (execution, process) in live.iter_mut() {
        // SSH keeps a distinct owned native subtree. Its startup or original
        // execution cutoff remains serviced even while main has lent the
        // actual birth/receipt owner, or a normal Tenant terminal is pending.
        if let Some(standing) = process.ssh_standing.as_mut() {
            let _ = standing.poll_due_once(&mut process.lifetime);
        }
        if process.normal_terminal.is_some() || process.timeout_finish.is_some()
            || process.timeout_native.as_ref().is_some_and(Result::is_err)
            || process.timeout_record.as_ref().is_some_and(Result::is_err)
            || process.timeout_terminal.is_some()
        { continue; }
        if process.timeout_record.is_none() {
            match process.lifetime.is_expired() {
                Ok(false) => continue,
                Err(_) => continue,
                Ok(true) => {}
            }
            let expected = process.lifetime.origin_data_v1();
            let actual = process.record.lifetime.as_ref().map(|record| (
                record.origin_boottime_nanoseconds, record.timeout_nanoseconds,
                record.deadline_boottime_nanoseconds,
            ));
            if process.record.version != 3 || process.record.execution != *execution
                || process.record.lifetime.as_ref() != Some(&process.lifetime_record)
                || expected.is_none() || actual != expected
            {
                process.timeout_record = Some(Err(GuestProcessEffectErrorV1::LedgerConflict));
                continue;
            }
            process.record.timed_out = true;
            process.timeout_record = Some(Ok(()));
            process.timeout_native = Some(process.tree.terminate_expired_child_v1(
                &process.record, &mut process.lifetime, &mut process.child));
        } else {
            process.timeout_native = Some(process.lifetime.poll_termination_once(
                process.tree.population_for_original_timeout_v1(), &mut process.child)
                .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect));
        }
    }
    Ok(live.iter().find_map(|(execution, process)| {
        (process.timeout_record.as_ref().is_some_and(Result::is_ok)
            && process.timeout_native.as_ref().is_some_and(Result::is_ok)
            && process.timeout_terminal.is_none()
            && process.lifetime.completed_status_v1().is_some()).then_some(*execution)
    }))
}

/// Publishes only an already empty and reaped original on the effect actor.
/// The scheduler never performs a record write or waits for monitor custody.
pub(crate) fn publish_original_execution_timeout_v1(ledger: &Ledger, execution: [u8; 16])
    -> Result<(), GuestProcessEffectErrorV1>
{
    let original = {
        let mut live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let process = live.get(&execution).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        if process.timeout_record.as_ref().is_none_or(Result::is_err)
            || process.timeout_native.as_ref().is_none_or(Result::is_err)
            || process.timeout_terminal.is_some() || process.lifetime.completed_status_v1().is_none()
        { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        live.remove(&execution).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
    };
    let mut loan = QuiescentExecutionLoanV1 { registry: ledger.live(), execution, original: Some(original) };
    let original = loan.original.as_mut().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let result = (|| {
        let status = original.lifetime.completed_status_v1()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let status = aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(
            u32::try_from(status.into_raw()).map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?
        ).map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
        original.record.terminal_waitstatus = Some(status.raw());
        original.record.terminal = Some(timeout_terminal_outcome_v1(status));
        ledger.replace_process_retaining_v1(ExecutionId::from_bytes(execution), &original.record,
            &mut original.terminal_native)
    })();
    original.timeout_terminal = Some(result);
    let succeeded = original.timeout_terminal.as_ref().is_some_and(Result::is_ok);
    // No new process can be reconstructed from this gap: the single effect
    // actor owns the actual reaped original, and its durable operation already
    // exists. All failures return that same owner before projecting refusal.
    drop(loan);
    if succeeded { Ok(()) } else { Err(GuestProcessEffectErrorV1::AmbiguousEffect) }
}

/// Retires only a fully reaped original after actual bridge/terminal posts pass.
pub(crate) fn settle_original_execution_timeout_v1(ledger: &Ledger, execution: [u8; 16],
    finished: Result<crate::bridge::OriginalIoDispositionV1, GuestProcessEffectErrorV1>)
    -> Result<crate::bridge::OriginalIoDispositionV1, GuestProcessEffectErrorV1>
{
    let mut live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let process = live.get_mut(&execution).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    if process.timeout_finish.is_some() || process.startup_write.as_ref().is_some_and(Result::is_err)
        || process.io_registration.as_ref().is_some_and(|original| original.failure().is_some())
        || !process.timeout_terminal.as_ref().is_some_and(Result::is_ok)
        || process.lifetime.completed_status_v1().is_none()
    { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
    if matches!(finished, Ok(crate::bridge::OriginalIoDispositionV1::Pending)) {
        return Ok(crate::bridge::OriginalIoDispositionV1::Pending);
    }
    process.timeout_finish = Some(finished.map(|_| ()));
    if !process.timeout_finish.as_ref().is_some_and(Result::is_ok) {
        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
    }
    live.remove(&execution);
    Ok(crate::bridge::OriginalIoDispositionV1::Disposed)
}

// The actual Host source-level invoice includes this existing fixed control
// reservoir in addition to the measured Linux native owner. Future headers
// cannot silently grow beyond that receiving prerequisite.
const _: () = {
    let native = std::mem::size_of::<aos_sandbox_linux::process::ExecutionChildLifetimeOriginalV1>();
    let headers = 3 * (std::mem::size_of::<LiveProcess>() - native)
        + 3 * (std::mem::size_of::<PendingExecutionChildV1>() - native)
        // The Agent owns Effects inline. Its three complete owner planes
        // already cover the effects input moving into the same constructor;
        // there is no separately retained second Effects owner here.
        + 3 * std::mem::size_of::<crate::protected_entry::ProtectedGuestAgentV1<GuestProcessEffectsV1>>()
        + crate::monitor::original_terminal_control_header_bytes_v1()
        + 2 * std::mem::size_of::<super::GuestProcessStartupErrorV1>();
    assert!(headers <= aos_sandbox_agent::capture_receiving::CAPTURE_GUEST_CONTROL_BYTES_V2);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_descendants_never_relabel_a_zero_status_leader_as_success() {
        let status = aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(0).unwrap();
        let ordinary = terminal_outcome(status, false);
        let expired = timeout_terminal_outcome_v1(status);
        assert_eq!(ordinary.phase, AgentExecutionPhaseV1::Exited.code());
        assert_eq!(expired.phase, AgentExecutionPhaseV1::Failed.code());
        assert_eq!(&expired.result[..8], b"AOSGER03");
        assert_eq!(&expired.result[13..], &0_u32.to_be_bytes());
        assert_ne!(ordinary.result, expired.result);
    }
}
