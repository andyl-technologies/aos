//! Threads the same enrolled B into the four actual initial Client captures.
//!
//! Ordinary library/qualification callers keep their explicit old connector.
//! The selected worker installs its real bank/profile context before the first
//! acquisition, parks each original before entry, and never retries a spent
//! role or substitutes a missing original with the ordinary adapter.

use std::sync::{Arc, Mutex};

use aos_sandbox_controller_domain::{
    ControllerInitialBrokerSessionClosedV1 as Closed,
    ControllerInitialBrokerSessionReceivingV1 as Receiving,
    ControllerInitialBrokerSessionRoleV1 as Role,
    ControllerResourceBankOpeningV1,
};
use aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1;
use aos_sandbox_broker_session_security::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantControllerInitialSessionOpenV1,
};

use super::{ControllerBrokerSessions, worker::CycleFailure};

type RecoveredContext = aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2;

enum Funding {
    Initial,
    Recovered(RecoveredContext),
}

pub(super) struct OriginalContextV1 {
    funding: Funding,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    runtime: Arc<tokio::runtime::Runtime>,
    foundations: Arc<super::resident_custody::ControllerFoundationOriginalsV1>,
}

#[derive(Default)]
pub(super) struct InitialSessionSlotV1 {
    original: Option<Receiving>,
    node: Option<Result<(), Closed>>,
    entry: Option<Result<(), Closed>>,
    capture: Option<Box<DormantControllerInitialSessionOpenV1>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    taken: bool,
    recovered_prepared: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    recovered_after: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    pending_session: Option<DormantAuthenticatedBrokerSessionV1>,
    body: Option<Result<(), CycleFailure>>,
    after_lock_refused: bool,
}

impl InitialSessionSlotV1 {
    pub(super) fn completed_capture_v1(&self) -> Option<&DormantControllerInitialSessionOpenV1> {
        if !self.taken || self.original.is_some()
            || !matches!(self.node, Some(Ok(()))) || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.returned, Some(Ok(())))
        {
            return None;
        }
        self.capture.as_deref()
    }
}

pub(super) fn install_original_context_v1(
    sessions: &mut ControllerBrokerSessions,
    bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &Arc<ProductionControllerNormalRootProfileV1>,
    runtime: &Arc<tokio::runtime::Runtime>,
    foundations: &Arc<super::resident_custody::ControllerFoundationOriginalsV1>,
    _controller: &super::ProductionController,
) -> Result<(), CycleFailure> {
    if let Some(original) = &sessions.initial_context {
        if Arc::ptr_eq(&original.bank, bank) && Arc::ptr_eq(&original.profile, profile)
            && Arc::ptr_eq(&original.runtime, runtime)
            && Arc::ptr_eq(&original.foundations, foundations)
        {
            return Ok(());
        }
        return Err(closed("initial Session original changed"));
    }
    if sessions.host.is_some() || sessions.mount.is_some()
        || sessions.storage.is_some() || sessions.network.is_some()
    {
        return Err(closed("an existing Session cannot replace initial original capture"));
    }
    sessions.initial_context = Some(OriginalContextV1 {
        funding: Funding::Initial,
        bank: Arc::clone(bank),
        profile: Arc::clone(profile),
        runtime: Arc::clone(runtime),
        foundations: Arc::clone(foundations),
    });
    Ok(())
}

/// Installs only the actual context consumed from this same executor.
/// A refused context is returned whole to the diverging worker's custody.
pub(super) fn install_recovered_context_v2(
    sessions: &mut ControllerBrokerSessions,
    context: RecoveredContext,
    bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &Arc<ProductionControllerNormalRootProfileV1>,
    runtime: &Arc<tokio::runtime::Runtime>,
    foundations: &Arc<super::resident_custody::ControllerFoundationOriginalsV1>,
) -> Result<(), RecoveredContext> {
    if sessions.initial_context.is_some() || sessions.host.is_some()
        || sessions.mount.is_some() || sessions.storage.is_some() || sessions.network.is_some()
        || context.failure_v2().is_some()
    {
        return Err(context);
    }
    sessions.initial_context = Some(OriginalContextV1 {
        funding: Funding::Recovered(context),
        bank: Arc::clone(bank),
        profile: Arc::clone(profile),
        runtime: Arc::clone(runtime),
        foundations: Arc::clone(foundations),
    });
    Ok(())
}

pub(super) fn is_recovered_v2(sessions: &ControllerBrokerSessions) -> bool {
    matches!(sessions.initial_context.as_ref().map(|context| &context.funding),
        Some(Funding::Recovered(_)))
}

/// Lends only the actual retained context after all four owning handoffs.
/// The SDK's opaque completed Session borrower performs the independent
/// receiver/endpoint/main comparison against this same context before use.
pub(super) fn completed_recovered_context_v2(
    sessions: &ControllerBrokerSessions,
) -> Result<&RecoveredContext, CycleFailure> {
    if sessions.initial_slots.iter().any(|slot| !slot.taken
        || slot.completed_capture_v1().is_none()
        || !matches!(slot.recovered_prepared, Some(Ok(())))
        || !matches!(slot.recovered_after, Some(Ok(()))) || slot.after_lock_refused)
    {
        return Err(closed("recovered ordinary Session roster is not complete"));
    }
    match sessions.initial_context.as_ref().map(|context| &context.funding) {
        Some(Funding::Recovered(context)) if context.failure_v2().is_none() => Ok(context),
        _ => Err(closed("recovered ordinary context is not complete")),
    }
}

fn index(role: Role) -> usize {
    match role {
        Role::Host => 0,
        Role::Mount => 1,
        Role::Storage => 2,
        Role::Network => 3,
    }
}

fn closed(message: &'static str) -> CycleFailure {
    CycleFailure::Fatal(message.to_owned())
}

pub(super) fn connect_once_v1(
    sessions: &mut ControllerBrokerSessions,
    role: Role,
    node: [u8; 16],
    controller: &mut super::ProductionController,
) -> Result<DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    connect_with_coverage_v1(sessions, role, node, controller, None)
}

pub(super) fn connect_git_coverage_once_v1(
    sessions: &mut ControllerBrokerSessions,
    role: Role,
    node: [u8; 16],
    account: &mut aos_sandbox_controller_domain::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    controller: &mut super::ProductionController,
) -> Result<DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    connect_with_coverage_v1(sessions, role, node, controller, Some(account))
}

fn connect_with_coverage_v1(
    sessions: &mut ControllerBrokerSessions,
    role: Role,
    node: [u8; 16],
    controller: &mut super::ProductionController,
    account: Option<&mut aos_sandbox_controller_domain::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
) -> Result<DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    let original = sessions.initial_context.as_mut()
        .ok_or_else(|| closed("initial Session has no genuine original context"))?;
    // The actual complete producer originals stay owned in this context and
    // the same WorkerOriginals as Controller's transferred output anchors.
    // None retains the full failed startup bound; it is never healthy credit.
    let _foundation_residency = original.foundations.completed_anchor_files_v1();
    let slot = &mut sessions.initial_slots[index(role)];
    if slot.original.is_some() || slot.capture.is_some() || slot.entry.is_some() || slot.taken {
        return Err(closed("initial Session role remains spent or occupied"));
    }
    let mut shape = DormantControllerInitialSessionOpenV1::receiving_shape_v1(role)
        .ok_or_else(|| closed("initial Session shape overflowed"))?;
    // The Runtime's resident failure destination is paid alongside Security's
    // actual capsule before its Box, paths, ModePin or endpoint can grow.
    shape.hello.actual_inline_bytes = shape.hello.actual_inline_bytes
        .checked_add(std::mem::size_of::<InitialSessionSlotV1>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalContextV1>()))
        .ok_or_else(|| closed("initial Session Runtime shape overflowed"))?;
    {
        // Only pure admission and owning handoff hold the Bank lock. The
        // endpoint/Cold engine below always runs after this guard is released.
        let mut bank = original.bank.lock()
            .map_err(|_| closed("initial Session bank lock is poisoned"))?;
        match &mut original.funding {
            Funding::Initial => {
                bank.prepare_initial_broker_session_once_v1(role, Arc::clone(&original.profile), shape)
                    .map_err(|_| closed("initial Session original preparation refused"))?;
                slot.original = bank.take_initial_broker_session_once_v1(role);
            }
            Funding::Recovered(context) => {
                slot.recovered_prepared = Some(match controller.prepare_recovered_ordinary_session_once_v2(
                    &bank, context, Arc::clone(&original.profile), Arc::clone(&original.runtime), role, shape,
                ) {
                    Ok(receiving) => {
                        slot.original = Some(receiving);
                        Ok(())
                    }
                    Err(cause) => Err(cause),
                });
            }
        }
    }
    slot.body = Some((|| -> Result<(), CycleFailure> {
        let receiving = slot.original.as_mut()
            .ok_or_else(|| closed("initial Session original was not handed off"))?;
        slot.node = Some(receiving.expected_node_v1()
            .and_then(|expected| if expected == node { Ok(()) } else { Err(Closed) }));
        if !matches!(slot.node, Some(Ok(()))) {
            return Err(closed("initial Session node differs from original enrolled bank"));
        }
        if role == Role::Storage && matches!(original.funding, Funding::Initial) {
            receiving.retain_runtime_mechanics_once_v1(Arc::clone(&original.runtime))
                .map_err(|_| closed("initial Storage Runtime mechanics changed"))?;
        }
        slot.entry = Some(receiving.begin_capture_once_v1());
        if !matches!(slot.entry, Some(Ok(()))) {
            return Err(closed("initial Session fixed entry refused with original retained"));
        }
        let image = if role == Role::Storage { sessions.launch_image.clone() } else { None };
        let Some(receiving) = slot.original.take() else { std::process::abort() };
        slot.capture = Some(Box::new(DormantControllerInitialSessionOpenV1::new(receiving, image)));
        let capture = slot.capture.as_mut()
            .ok_or_else(|| closed("initial Session capture destination is absent"))?;
        slot.returned = Some(match account {
            Some(account) => capture.open_git_coverage_once_v1(account),
            None => capture.open_once(),
        });
        if !matches!(slot.returned, Some(Ok(()))) {
            return Err(closed("initial Session acquisition failed with complete custody retained"));
        }
        slot.pending_session = capture.take_completed();
        if slot.pending_session.is_none() {
            return Err(closed("initial Session positive handoff was refused"));
        }
        Ok(())
    })());

    if let Funding::Recovered(context) = &mut original.funding {
        // The preparation may have entered a native prefix before returning
        // Err. Every reached preparation therefore invokes its prearmed after,
        // even when node, receiver entry or the Cold engine failed first.
        let bank = match original.bank.lock() {
            Ok(bank) => bank,
            Err(poisoned) => {
                // The mutex remains poisoned and this role cannot complete.
                // Its original data still permits the independently owed native
                // after; this entrance never runs a new healthy debit.
                slot.after_lock_refused = true;
                poisoned.into_inner()
            }
        };
        slot.recovered_after = Some(controller.finish_recovered_ordinary_session_native_once_v2(
            &bank, context, &original.profile, role));
    }
    if !matches!(slot.body, Some(Ok(()))) {
        if matches!(original.funding, Funding::Initial) {
            if let Some(Err(cause)) = slot.body.take() {
                return Err(cause);
            }
        }
        return Err(closed("initial Session acquisition body refused with whole custody retained"));
    }
    if slot.after_lock_refused
        || slot.recovered_prepared.as_ref().is_some_and(Result::is_err)
        || slot.recovered_after.as_ref().is_some_and(Result::is_err)
    {
        return Err(closed("recovered Session native interval refused with whole custody retained"));
    }
    let session = slot.pending_session.take()
        .ok_or_else(|| closed("initial Session positive handoff was refused"))?;
    slot.taken = true;
    Ok(session)
}

/// Lends only the installed original context after all four actual Session takes.
pub(super) fn maintenance_context_parts_v2(sessions: &ControllerBrokerSessions)
    -> Result<(&Arc<Mutex<ControllerResourceBankOpeningV1>>, &Arc<ProductionControllerNormalRootProfileV1>, &Arc<tokio::runtime::Runtime>), CycleFailure> {
    if sessions.initial_slots.iter().any(|slot| slot.completed_capture_v1().is_none()) {
        return Err(closed("catalog maintenance requires all four actual completed Sessions"));
    }
    if is_recovered_v2(sessions) { completed_recovered_context_v2(sessions)?; }
    let context = sessions.initial_context.as_ref().ok_or_else(|| closed("catalog maintenance context is absent"))?;
    Ok((&context.bank, &context.profile, &context.runtime))
}

impl OriginalContextV1 {
    pub(super) fn recovered_context_data_v2(&self) -> Option<&RecoveredContext> {
        match &self.funding { Funding::Recovered(context) => Some(context), Funding::Initial => None }
    }
}
