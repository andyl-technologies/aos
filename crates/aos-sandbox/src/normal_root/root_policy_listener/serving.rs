//! Parks the same Root writer pair behind actual terminal completion.
//!
//! The listener retains the entire pair, including captured native originals,
//! fixed writer capsules, completed issuer pins and original financial links. A failed offer
//! remains resident. Parking does not complete financial flight disposal or
//! enable a new request: those actual positive consumers remain separate.

mod execution_no_apply;
mod stop_cleanup;

use std::error::Error;
use aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1;

use crate::journal::JournalError;
use crate::policy_compiler::create_storage_current::pins::{
    RootCurrentPinsStateV1, RootServingPinsErrorV1,
};
use crate::policy_compiler::create_storage_current::{
    RootCreateStorageCurrentErrorV1, closed::RootCurrentTerminalCompletionV1,
};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;

use super::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};

// These fixed stack/Arc move carriers coexist with the retained custody. The
// Native/financial tokens and their returned Results are paid by their same
// actual policy-flight suppliers; this adds only this caller's mutex handles.
pub(super) fn disposition_construction_bytes_v1() -> usize {
    type Guard<'a> = crate::normal_root::RootReceivingGuardV1<'a>;
    2 * std::mem::size_of::<RootJournalFinancialOriginalV1>()
        + 2 * std::mem::size_of::<Guard<'_>>()
        + 2 * std::mem::size_of::<Result<Guard<'_>, NormalRootStartupErrorV1>>()
}

#[derive(Debug, thiserror::Error)]
enum ServingError {
    #[error("Root terminal completion does not bind the held writer pair")]
    Terminal(#[source] RootCreateStorageCurrentErrorV1),
    #[error("Root writer pair does not retain its original financial lifetime")]
    Financial(#[source] JournalError),
    #[error("Root serving pins do not match the same held policy rows")]
    Pins(#[source] RootServingPinsErrorV1),
}

// No public constructor, native projection, tuple adoption or Arc factory.
// The actual fixed listener is the only destination for a completed pair.
pub(super) struct RootPolicyServingCustodyV1 {
    writers: RootCreateStorageCurrentWritersV1,
    terminal: RootCurrentTerminalCompletionV1,
    pins: RootCurrentPinsStateV1,
    financial: Option<RootJournalFinancialOriginalV1>,
    validation: Result<(), ServingError>,
    ready_for_delete: bool,
}

impl RootPolicyServingCustodyV1 {
    fn from_terminal(
        writers: RootCreateStorageCurrentWritersV1,
        terminal: RootCurrentTerminalCompletionV1,
        pins: RootCurrentPinsStateV1,
        financial: Option<RootJournalFinancialOriginalV1>,
    ) -> Self {
        // The whole offer is parked before its result is projected. Neither a
        // foreign pair nor a failed financial comparison can drop native debt.
        let mut custody = Self {
            writers,
            terminal,
            pins,
            financial,
            validation: Ok(()),
            ready_for_delete: false,
        };
        custody.validation = custody.require_same_completed_pair();
        custody
    }

    fn require_same_completed_pair(&self) -> Result<(), ServingError> {
        self.terminal
            .require_serving_pair_v1(&self.writers)
            .map_err(ServingError::Terminal)?;
        let financial = self.financial.as_ref()
            .ok_or(ServingError::Financial(JournalError::ProtectedBoundary))?;
        self.writers.require_serving_financial_v1(financial)
            .map_err(ServingError::Financial)?;
        self.writers
            .require_serving_pins_v1(&self.pins)
            .map_err(ServingError::Pins)
    }

    // This lends only the actual earlier pinned comparison key, never a new
    // native capture or receiving grant. A Delete borrower must also own its
    // distinct paid flight and fresh Source/native/currentness observations.
    pub(super) fn source_signer_v1(
        &self,
    ) -> Result<
        &crate::policy_compiler::PinnedSourceHoldReadbackSignerV1,
        RootCreateStorageCurrentErrorV1,
    > {
        if !self.ready_for_delete || self.validation.is_err() {
            return Err(RootCreateStorageCurrentErrorV1::Original);
        }
        self.pins.source_signer_v1()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = self.validation.as_ref().err()?;
        if matches!(
            cause,
            ServingError::Pins(RootServingPinsErrorV1::Incomplete(_))
        ) {
            return self.pins.failure().or(Some(cause as _));
        }
        Some(cause as _)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    /// Parks a terminal producer's whole pair without clearing any flight debt.
    ///
    /// The actual Root6 producer must consume its completed typed gate and move
    /// its same pair here before disposing its positive upper carriers. This
    /// method also retains the actual completed issuer owner instead of
    /// rearming its once-only credential capture. It creates no recurring IO loan or
    /// permission to borrow an initial stage again. An invalid actual offer is
    /// retained on the same listener through intentional termination.
    ///
    /// # Errors
    /// Refuses changed terminal/pair/financial joins or an invalid accepted
    /// flight. The whole offered pair and token remain on this same listener.
    pub(crate) fn park_completed_root_writers_once_v1(
        &mut self,
        writers: RootCreateStorageCurrentWritersV1,
        terminal: RootCurrentTerminalCompletionV1,
        pins: RootCurrentPinsStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.listener.serving.is_some() {
            // The two once-native claims cannot produce another real pair.
            // Keep the newly offered owners on this stack at termination rather
            // than drop them, replace the first pair or grow a rejection list.
            std::process::abort();
        }
        let financial = self.listener.startup.receiving_financial.clone();
        self.listener.serving = Some(RootPolicyServingCustodyV1::from_terminal(
            writers, terminal, pins, financial,
        ));
        let positive_entry = self.closed.is_none()
            && self.transferred
            && !self.finished
            && self.dispatch.is_none()
            && matches!(self.before, Some(Ok(())))
            && matches!(self.controller_admission, Some(Ok(())))
            && self
                .controller_peer
                .as_ref()
                .is_some_and(|peer| peer.require_completed().is_ok())
            && self
                .listener
                .serving
                .as_ref()
                .is_some_and(|custody| custody.failure().is_none());
        if positive_entry {
            Ok(())
        } else {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
            self.listener.failed = true;
            Err(NormalRootStartupErrorV1::Service)
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum ServingDispatchV1 {
    Initial,
    Environment,
    DeletePlanning,
    DeleteCompletion,
    ExecutionNoApply,
    StopCleanup,
    StorageApply,
    FinalityRecover,
    StartAssignmentInputs,
    StartResource,
    MaintenanceStorage,
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    /// Borrows only the actual failed serving handoff's original cause.
    pub fn serving_handoff_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.listener.serving.as_ref()?.failure()
    }

    pub(super) fn complete_serving_dispatch_v1(
        &mut self,
        kind: ServingDispatchV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let positive = self.closed.is_none()
            && self.finished
            && self.rejected_dispatch.is_none()
            && matches!(self.finish_order, Some(Ok(())))
            && matches!(self.dispatch, Some(Ok(())))
            && self.socket_disposition_matches_v1(kind)
            && matches!(self.after, Some(Ok(())))
            && (!matches!(
                kind,
                ServingDispatchV1::DeleteCompletion | ServingDispatchV1::ExecutionNoApply | ServingDispatchV1::StopCleanup
            ) || self.listener.serving.as_ref().is_some_and(|custody| {
                self.listener
                    .connection_escrow
                    .as_ref()
                    .is_some_and(|escrow| {
                        escrow.require_same_empty_v1(custody.financial.as_ref()).is_ok()
                            && escrow.require_completion_armed_v2().is_ok()
                    })
            }))
            && self.controller_current_original.is_none()
            && match kind {
                ServingDispatchV1::Initial => {
                    self.controller_peer
                        .as_ref()
                        .is_some_and(|peer| peer.require_completed().is_ok())
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            !custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::Environment => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::Environment(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.environment_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v1(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::DeletePlanning => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::Delete(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.planning_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v1(native).is_ok())
                        })
                        && self.require_delete_planning_serving_pair_v1().is_ok()
                }
                ServingDispatchV1::DeleteCompletion => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::Delete(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.delete_completion_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v4(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::ExecutionNoApply => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::ExecutionNoApply(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.execution_no_apply_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v2(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }

                ServingDispatchV1::StopCleanup => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::StopCleanup(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.stop_cleanup_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v1(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::StorageApply => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::Apply(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.apply_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v1(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::StartResource => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::HostLaunch(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.start_resource_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v2(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::MaintenanceStorage => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::MaintenanceStorage(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.maintenance_storage_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v3(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::FinalityRecover => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::FinalityRecover(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self.finality_recover_work.as_ref().is_some_and(|work| {
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .is_some_and(|native| work.require_same_complete_v1(native).is_ok())
                        })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
                ServingDispatchV1::StartAssignmentInputs => {
                    matches!(self.purpose_admission, Some(Ok(())))
                        && matches!(self.purpose_peer.as_ref(),
                        Some(super::RootAcceptedPurposePeerV1::StartAssignmentInputs(peer))
                            if peer.require_completed_for_root_disposal_v1(self.listener.startup).is_ok())
                        && self
                            .start_assignment_inputs_work
                            .as_ref()
                            .is_some_and(|work| {
                                self.native
                                    .as_ref()
                                    .and_then(|result| result.as_ref().ok())
                                    .is_some_and(|native| {
                                        work.require_same_complete_v1(native).is_ok()
                                    })
                            })
                        && self.listener.serving.as_ref().is_some_and(|custody| {
                            custody.ready_for_delete && custody.failure().is_none()
                        })
                }
            };
        if !positive || self.failure().is_some() {
            self.finished = false;
            self.listener.failed = true;
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
            return Err(NormalRootStartupErrorV1::Service);
        }

        // Compare the actual lower allocation, then hold the same L+U wrapper
        // across native/upper disposition and actual financial completion.
        // Neither the permanent pair nor its Root6 completion moves or drops.
        let financial = self
            .listener
            .serving
            .as_ref()
            .and_then(|custody| custody.financial.clone())
            .ok_or(NormalRootStartupErrorV1::Service)?;
        let expected = self.listener.startup.receiving_financial.as_ref()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        financial.require_same_v1(expected).map_err(|_| NormalRootStartupErrorV1::Service)?;
        if matches!(
            kind,
            ServingDispatchV1::DeleteCompletion | ServingDispatchV1::ExecutionNoApply | ServingDispatchV1::StopCleanup
        ) {
            let plan = match kind {
                ServingDispatchV1::DeleteCompletion => self
                    .delete_completion_work
                    .as_ref()
                    .ok_or(NormalRootStartupErrorV1::Service)?
                    .completed_confirmation_plan_v2()?,
                ServingDispatchV1::ExecutionNoApply => self
                    .execution_no_apply_work
                    .as_ref()
                    .ok_or(NormalRootStartupErrorV1::Service)?
                    .completed_confirmation_plan_v2()?,
                ServingDispatchV1::StopCleanup => self
                    .stop_cleanup_work
                    .as_ref()
                    .ok_or(NormalRootStartupErrorV1::Service)?
                    .completed_confirmation_plan_v2()?,
                _ => std::process::abort(),
            };
            let escrow = match self.listener.connection_escrow.as_mut() {
                Some(escrow) => escrow,
                None => std::process::abort(),
            };
            escrow.install_completed_plan_v2(plan);
            // The actual same-cookie native owner was captured before body D
            // using this listener's already-paid permanent FD reservoir. Its
            // transfer performs no duplicate, read, recheck or financial debit.
            let native = match self.native.take() {
                Some(Ok(native)) => native,
                _ => std::process::abort(),
            };
            escrow.retain_same_native_v1(native);
        }
        let mut receiving = match self.listener.startup.lock_receiving_v1() {
            Ok(original) => original,
            Err(_) => {
                self.finished = false;
                self.listener.failed = true;
                self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
                return Err(NormalRootStartupErrorV1::Service);
            }
        };
        let refusal = receiving.original_v1().native_refusal_original_v1();
        let disposal = {
            let original = receiving.original_mut_v1();
            let prepared = match kind {
                ServingDispatchV1::Initial => {
                    original.prepare_policy_flight_disposal_v1(self.listener.startup)
                }
                ServingDispatchV1::Environment => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::Environment(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::DeletePlanning => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::Delete(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::DeleteCompletion => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::Delete(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::ExecutionNoApply => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::ExecutionNoApply(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::StopCleanup => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::StopCleanup(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::StorageApply => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::Apply(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::StartResource => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::HostLaunch(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::MaintenanceStorage => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::MaintenanceStorage(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::FinalityRecover => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::FinalityRecover(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
                ServingDispatchV1::StartAssignmentInputs => match self.purpose_peer.as_ref() {
                    Some(super::RootAcceptedPurposePeerV1::StartAssignmentInputs(peer)) => original
                        .prepare_policy_flight_disposal_for_completed_purpose_v1(
                            self.listener.startup,
                            peer,
                        ),
                    _ => Err(NormalRootStartupErrorV1::Service),
                },
            };
            match prepared {
                Ok(disposal) => disposal,
                Err(cause) => {
                    refusal.refuse_v1();
                    self.finished = false;
                    self.listener.failed = true;
                    self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
                    return Err(cause);
                }
            }
        };

        // Ordinary handlers have shut down this OFD before their Root post.
        // Delete transferred only its already-paid native connection owner to
        // permanent escrow. Drop every transaction-owned stream, model and peer
        // before completing the same transient financial operation below.
        drop(self.native.take());
        drop(self.original.take());
        drop(self.duplicate.take());
        drop(self.accepted.take());
        drop(self.controller_peer.take());
        drop(self.controller_admission.take());
        drop(self.purpose_peer.take());
        drop(self.purpose_admission.take());
        if let Some(work) = self.environment_work.take() {
            (*work).complete_upper_disposal_v1();
        }
        if let Some(work) = self.planning_work.take() {
            (*work).complete_upper_disposal_v1();
        }
        if let Some(work) = self.delete_completion_work.take() {
            (*work).complete_upper_disposal_v4();
        }
        if let Some(work) = self.execution_no_apply_work.take() {
            (*work).complete_upper_disposal_v2();
        }

        if let Some(work) = self.stop_cleanup_work.take() {
            (*work).complete_upper_disposal_v1();
        }
        if let Some(work) = self.apply_work.take() {
            (*work).complete_upper_disposal_v1();
        }
        if let Some(work) = self.start_resource_work.take() {
            (*work).complete_upper_disposal_v2();
        }
        if let Some(work) = self.maintenance_storage_work.take() {
            (*work).complete_upper_disposal_v3();
        }
        if let Some(work) = self.finality_recover_work.take() {
            (*work).complete_upper_disposal_v1();
        }
        if let Some(work) = self.start_assignment_inputs_work.take() {
            (*work).complete_upper_disposal_v1();
        }
        drop(self.controller_current_return.take());
        drop(self.before.take());
        drop(self.after.take());
        drop(self.dispatch.take());
        drop(self.finish_order.take());
        drop(self.shutdown.take());
        drop(self.listener.flight_permit.take());
        disposal.complete_after_disposal_v1();
        drop(refusal);
        drop(receiving);

        // This explicit response causally follows completed D. EOF and a still
        // live PIDFD cannot establish that fact when a process is exiting.
        // Only the same permanent escrow, prearmed native pair and passive
        // fixed plan survive. All their liability was admitted before body D.
        if matches!(
            kind,
            ServingDispatchV1::DeleteCompletion | ServingDispatchV1::ExecutionNoApply | ServingDispatchV1::StopCleanup
        ) {
            let returned = self
                .listener
                .connection_escrow
                .as_mut()
                .ok_or(NormalRootStartupErrorV1::Service)?
                .send_after_positive_disposition_once_v2(self.listener.startup);
            if returned.is_err() {
                self.finished = false;
                self.listener.failed = true;
                self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
                return returned;
            }
        }
        // No tail failure can retire this permanent native prefix or enable a
        // new accept. Its positive last drop follows all independent posts.
        drop(self.listener.connection_escrow.take());

        // This private state is written only after actual complete disposition.
        // A later Delete still needs its own genuine paid operation and actual
        // fresh same-pair native/currentness joins before any body growth or IO.
        match self.listener.serving.as_mut() {
            Some(custody) if matches!(kind, ServingDispatchV1::Initial) => {
                custody.ready_for_delete = true
            }
            Some(_) => {}
            None => std::process::abort(),
        }
        Ok(())
    }
}

macro_rules! continuation_pair_ports {
    ($cut:ident, $owner:ident, $demand:ident, $before:ident, $after:ident) => {
        impl RootPolicyAcceptedFlightV1<'_, '_> {
            pub(crate) fn $demand(&self) -> Result<aos_sandbox_core::ResourceVector, NormalRootStartupErrorV1> {
                self.$cut()?;
                let custody = self.listener.serving.as_ref().ok_or(NormalRootStartupErrorV1::Service)?;
                if !custody.ready_for_delete || custody.validation.is_err() {
                    return Err(NormalRootStartupErrorV1::Service);
                }
                custody.require_same_completed_pair().map_err(|_| NormalRootStartupErrorV1::Service)?;
                crate::policy_compiler::continuation_policy::$owner::receiving_demand_v1(&custody.writers)
                    .map_err(|_| NormalRootStartupErrorV1::Service)
            }

            pub(crate) fn $before(&self,
                original: &mut crate::policy_compiler::continuation_policy::$owner,
            ) -> Result<(), crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1> {
                use crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1 as Stop;
                self.$cut().map_err(|_| Stop::Closed)?;
                let custody = self.listener.serving.as_ref().ok_or(Stop::Closed)?;
                if !custody.ready_for_delete || custody.validation.is_err() { return Err(Stop::Closed); }
                custody.require_same_completed_pair().map_err(|_| Stop::Closed)?;
                original.begin_for_actual_pair_once_v1(&custody.writers, &custody.pins)
            }

            pub(crate) fn $after(&self,
                original: &mut crate::policy_compiler::continuation_policy::$owner,
            ) -> Result<(), crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1> {
                use crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1 as Stop;
                // The same pair stays held after a refused healthy entry. The
                // already-armed lower post alone authorizes its owed native
                // observation; no current-cut getter suppresses it here.
                let custody = self.listener.serving.as_ref().ok_or(Stop::Closed)?;
                original.finish_actual_pair_once_v1(&custody.writers, &custody.pins)
            }
        }
    };
}

macro_rules! continuation_policy_ports {
    ($cut:ident, $owner:ident, $demand:ident, $before:ident, $verify:ident, $after:ident) => {
        continuation_pair_ports!($cut, $owner, $demand, $before, $after);
        impl RootPolicyAcceptedFlightV1<'_, '_> {
            pub(crate) fn $verify(&self,
                original: &mut crate::policy_compiler::continuation_policy::$owner,
                data: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
                now: aos_sandbox_core::RawPairedClockSample,
            ) -> Result<(), crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1> {
                use crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1 as Stop;
                self.$cut().map_err(|_| Stop::Closed)?;
                let custody = self.listener.serving.as_ref().ok_or(Stop::Closed)?;
                original.verify_current_sources_once_v1(&custody.writers, data, now)
            }
        }
    };
}

continuation_policy_ports!(
    environment_cut_startup_v1,
    RootEnvironmentPolicyOriginalV1,
    environment_policy_receiving_demand_v1,
    begin_environment_policy_once_v1,
    verify_environment_policy_sources_once_v1,
    finish_environment_policy_once_v1
);
continuation_policy_ports!(
    apply_cut_startup_v1,
    RootApplyPolicyOriginalV1,
    apply_policy_receiving_demand_v1,
    begin_apply_policy_once_v1,
    verify_apply_policy_sources_once_v1,
    finish_apply_policy_once_v1
);
continuation_policy_ports!(
    host_launch_cut_startup_v1,
    RootHostLaunchPolicyOriginalV1,
    host_launch_policy_receiving_demand_v1,
    begin_host_launch_policy_once_v1,
    verify_host_launch_policy_sources_once_v1,
    finish_host_launch_policy_once_v1
);
continuation_policy_ports!(
    maintenance_storage_cut_startup_v2,
    RootMaintenanceStoragePolicyOriginalV2,
    maintenance_storage_policy_receiving_demand_v2,
    begin_maintenance_storage_policy_once_v2,
    verify_maintenance_storage_policy_sources_once_v2,
    finish_maintenance_storage_policy_once_v2
);

continuation_policy_ports!(
    execution_no_apply_cut_startup_v2,
    RootExecutionNoApplyPolicyOriginalV2,
    execution_no_apply_policy_receiving_demand_v2,
    begin_execution_no_apply_policy_once_v2,
    verify_execution_no_apply_policy_sources_once_v2,
    finish_execution_no_apply_policy_without_floor_once_v2
);

impl RootPolicyAcceptedFlightV1<'_, '_> {
    /// Lends the SAME serving pair to the distinct paid Execution78 producer.
    ///
    /// The whole custody is parked back before projecting its result. Its
    /// historical Root6 receipt and original financial allocation are retained;
    /// a completed floor alone cannot refresh serving for another invocation.
    pub(crate) fn append_execution_no_apply_floor_once_v2(
        &mut self,
        floor:&mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyFloorOriginalV2,
        original: &aos_sandbox_linux::unix_stream::RetainedUnixStream,
        policy:&mut crate::policy_compiler::continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
        readonly:&mut crate::policy_compiler::provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1,
        models:&crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyModelsOriginalV2,
        host:&crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyHostLeaseOriginalV2,
        trust:&mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyHostTrustOriginalV2,
        policy_posts_owned: &mut bool,
        acquisition: Option<&mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyAcquisitionOriginalV2>,
    ) -> Result<(), JournalError> {
        self.execution_no_apply_cut_startup_v2()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let mut custody = self
            .listener
            .serving
            .take()
            .ok_or(JournalError::ProtectedBoundary)?;
        if !custody.ready_for_delete
            || custody.validation.is_err()
            || custody.require_same_completed_pair().is_err()
        {
            self.listener.serving = Some(custody);
            return Err(JournalError::ProtectedBoundary);
        }
        // Only entry into the actual floor method transfers these earlier
        // owed policy posts. Every refusal above leaves them with the caller.
        *policy_posts_owned = true;
        let result = match acquisition {
            Some(acquisition) => floor.append_recovery_once_v2(
                self,
                original,
                &mut custody.writers,
                &custody.pins,
                policy,
                readonly,
                models,
                host,
                trust,
                acquisition,
            ),
            None => floor.append_once_v2(
                self,
                original,
                &mut custody.writers,
                &custody.pins,
                policy,
                readonly,
                models,
                host,
                trust,
            ),
        };
        self.listener.serving = Some(custody);
        result
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn delete_source_signer_pin_v1(
        &self,
    ) -> Result<
        &crate::policy_compiler::PinnedSourceHoldReadbackSignerV1,
        RootCreateStorageCurrentErrorV1,
    > {
        self.delete_cut_startup_v1()
            .map_err(|_| RootCreateStorageCurrentErrorV1::Original)?;
        self.listener
            .serving
            .as_ref()
            .ok_or(RootCreateStorageCurrentErrorV1::Original)?
            .source_signer_v1()
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn observe_delete_saved_floor_once_v1(
        &mut self,
        floor: &mut crate::policy_compiler::delete_root::RootDeleteFloorOriginalV1,
        challenge: &crate::policy_compiler::delete_root::RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
    ) -> Result<(), crate::policy_compiler::delete_root::RootDeleteErrorV1> {
        use crate::policy_compiler::delete_root::RootDeleteErrorV1 as Closed;
        self.delete_cut_startup_v1().map_err(|_| Closed::Original)?;
        let Some(mut custody) = self.listener.serving.take() else {
            return Err(Closed::Original);
        };
        if !custody.ready_for_delete || custody.validation.is_err() {
            self.listener.serving = Some(custody);
            return Err(Closed::Original);
        }
        // The actual writers, original financial Arc and all credential/native
        // custody stay resident, without any reconstructed authority or alias.
        let result = floor.observe_with_serving_once_v1(
            self,
            challenge,
            controller,
            source,
            &mut custody.writers,
            &custody.pins,
        );
        self.listener.serving = Some(custody);
        result
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    /// Compares the Apply subject to this listener's actual retained Root6.
    ///
    /// The new Apply flight supplies current R admission. This comparison does
    /// not lend the old Root6 payer or rearm an earlier native capture.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete serving custody, changed same-pair
    /// provenance or any byte substitution in the actual completed receipt.
    pub(crate) fn require_apply_storage_closed_v1(
        &self,
        encoded: &[u8],
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.apply_cut_startup_v1()?;
        self.require_completed_storage_receipt_data_v1(encoded)
    }

    /// Compares historical Root6 under the new actual Host purpose's own cut.
    pub(crate) fn require_host_launch_storage_closed_v2(
        &self,
        encoded: &[u8],
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.host_launch_cut_startup_v1()?;
        self.require_completed_storage_receipt_data_v1(encoded)
    }

    fn require_completed_storage_receipt_data_v1(
        &self,
        encoded: &[u8],
    ) -> Result<(), NormalRootStartupErrorV1> {
        let custody = self
            .listener
            .serving
            .as_ref()
            .filter(|custody| custody.ready_for_delete && custody.validation.is_ok())
            .ok_or(NormalRootStartupErrorV1::Service)?;
        custody
            .require_same_completed_pair()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        custody
            .terminal
            .require_same_receipt_data_v1(encoded)
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn require_delete_planning_serving_pair_v1(
        &self,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.delete_cut_startup_v1()?;
        let custody = self
            .listener
            .serving
            .as_ref()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        let financial = self
            .listener
            .startup
            .receiving_financial
            .as_ref()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        // These private fields were installed only by the actual completed
        // Root6 pair handoff and same-R disposal. No caller supplies a flag,
        // pair, financial handle or replacement pins to this entrance.
        if !custody.ready_for_delete
            || custody.validation.is_err()
            || custody.financial.as_ref().is_none_or(|held| held.require_same_v1(financial).is_err())
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        custody
            .require_same_completed_pair()
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }
}

continuation_pair_ports!(
    finality_recover_cut_startup_v1,
    RootFinalityRecoverPairOriginalV1,
    finality_recover_pair_receiving_demand_v1,
    begin_finality_recover_pair_once_v1,
    finish_finality_recover_pair_once_v1
);

impl RootPolicyAcceptedFlightV1<'_, '_> {
    /// Compares only historical Root6 DATA while this new purpose pays its own interval.
    pub(crate) fn require_finality_recover_storage_closed_v1(
        &self,
        encoded: &[u8],
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.finality_recover_cut_startup_v1()?;
        self.require_completed_storage_receipt_data_v1(encoded)
    }
}

// Delete keeps the same actual serving writers/pins through a separate paid
// purpose interval. No historical planning observation supplies current policy.
continuation_policy_ports!(
    delete_cut_startup_v1,
    RootDeletePolicyOriginalV2,
    delete_policy_receiving_demand_v2,
    begin_delete_policy_once_v2,
    verify_delete_policy_sources_once_v2,
    finish_delete_policy_once_v2
);

continuation_policy_ports!(
    start_assignment_inputs_cut_startup_v2,
    RootStartAssignmentInputsPolicyOriginalV2,
    start_assignment_inputs_policy_receiving_demand_v2,
    begin_start_assignment_inputs_policy_once_v2,
    verify_start_assignment_inputs_policy_sources_once_v2,
    finish_start_assignment_inputs_policy_once_v2
);
