//! Keeps the genuine Source4/C17/Root borrower through the finite signed26 flight.
//!
//! The private lexical context erases only its Rust lifetimes. It never adopts
//! a supplied grant, receiving account, clock horizon or Session.

use super::*;
mod abi;
mod apply;
mod native;
mod network;
mod mount;
mod completion;
pub(super) use completion::ControllerDeleteCompletionOriginalV4;

use native::{CaptureData, Native, Predecessor};
use crate::{DeleteStorageApplyIoOriginalV3, DeleteStoragePreparationIoOriginalV3, DeleteNetworkApplyIoOriginalV4};
use crate::DeleteMountReapIoOriginalV4;
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3 as Purpose;
use crate::controller_resource_reservation::ResourceReservationErrorV1 as Closed;
use crate::journal::DeleteSourceFrontierClockV3;
use crate::journal::SourceDeletePendingFenceV1;
use aos_sandbox_api::aos::sandbox::local::v1::{
    BrokerRequestEnvelope, PrepareStorageCatalogRequest, RequestHeader,
};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
};
use aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2;
use buffa::Message as _;

type Cause = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy)]
enum First {
    Construction,
    Entry,
    Contract,
    Clock,
    Funding,
    Capture,
    Window,
    Sdk,
    After,
    Retirement,
    Complete,
    CurrentFrame,
    CurrentSend,
    Reentry,
}

#[derive(Default)]
pub(super) struct ControllerDeleteStorageFlightOriginalV3<N> {
    started: bool,
    construction: Option<Result<(), JournalError>>,
    entry: Option<Result<(), JournalError>>,
    sdk_entry: Option<Result<(), Closed>>,
    contract: Option<Result<(), Cause>>,
    clock: Option<DeleteSourceFrontierClockV3>,
    current: Option<Result<(), JournalError>>,
    funding: Option<Result<(), JournalError>>,
    capture: Option<Result<(), JournalError>>,
    window: Option<Result<(), JournalError>>,
    after: Option<Result<(), Cause>>,
    retirement: Option<Result<(), JournalError>>,
    complete: Option<Result<(), Cause>>,
    current_send: Option<Result<(), Cause>>,
    current_frame: Option<Result<aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3, Cause>>,
    envelope: Option<Result<BrokerRequestEnvelope, Cause>>,
    header: Option<Result<RequestHeader, Cause>>,
    io: N,
    paid: ResourceVector,
    request_bound: usize,
    native_turn: u64,
    cutoff: u64,
    first: Option<First>,
    root_selected: bool,
    funding_selected: bool,
}

pub(super) type ControllerDeletePreparationOriginalV3 = ControllerDeleteStorageFlightOriginalV3<DeleteStoragePreparationIoOriginalV3>;
pub(super) type ControllerDeleteApplyOriginalV3 = ControllerDeleteStorageFlightOriginalV3<DeleteStorageApplyIoOriginalV3>;
pub(super) type ControllerDeleteNetworkOriginalV4 = ControllerDeleteStorageFlightOriginalV3<DeleteNetworkApplyIoOriginalV4>;
pub(super) type ControllerDeleteMountOriginalV4 = ControllerDeleteStorageFlightOriginalV3<DeleteMountReapIoOriginalV4>;

impl<N: Native> ControllerDeleteStorageFlightOriginalV3<N> {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn journal(slot: &Option<Result<(), JournalError>>) -> Option<&JournalError> {
            slot.as_ref()?.as_ref().err()
        }
        match self.first? {
            First::Construction => journal(&self.construction).map(|e| e as _),
            First::Entry | First::Sdk | First::Reentry => None,
            First::Contract => self
                .contract
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e.as_ref() as _)
                .or_else(|| {
                    self.envelope
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|e| e.as_ref() as _)
                })
                .or_else(|| {
                    self.header
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|e| e.as_ref() as _)
                })
                .or_else(|| self.sdk_entry.as_ref()?.as_ref().err().map(|e| e as _)),
            First::Clock => self
                .clock
                .as_ref()
                .and_then(|clock| clock.failure())
                .or_else(|| journal(&self.current).map(|e| e as _)),
            First::Funding => journal(&self.funding).map(|e| e as _),
            First::Capture => self
                .io
                .failure_v3()
                .or_else(|| journal(&self.capture).map(|e| e as _)),
            First::Window => self
                .io
                .failure_v3()
                .or_else(|| journal(&self.window).map(|e| e as _)),
            First::After => self.after.as_ref()?.as_ref().err().map(|e| e.as_ref() as _),
            First::Retirement => self
                .io
                .failure_v3()
                .or_else(|| journal(&self.retirement).map(|e| e as _)),
            First::CurrentFrame => self.io.failure_v3().or_else(|| self.current_frame.as_ref()?.as_ref().err().map(|cause|cause.as_ref() as _)),
            First::CurrentSend => self.current_send.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Complete => self
                .complete
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e.as_ref() as _),
        }
    }
}

// Exactly one implementation exists, below. No external callback or payer can
// create this context or extend the actual Source fence's lexical lifetime.
trait Context {
    fn current(&mut self) -> Result<crate::normal_root::DeleteSourceClockBoundDataV3, Cause>;
    fn completed_current_data(&mut self, session: [u8;64], identity: ([u8;32],[u8;32]))
        -> Result<aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3, Cause>;
    fn reserve(&mut self, additional: ResourceVector) -> Result<(), JournalError>;
    fn after(
        &mut self,
        latest: Option<aos_sandbox_model::RawPairedClockSample>,
        refused: bool,
    ) -> Result<(), Cause>;
    fn retire(&mut self) -> Result<(), Cause>;
    fn complete(&mut self, latest: aos_sandbox_model::RawPairedClockSample) -> Result<(), Cause>;
    fn send_current_data(&mut self, frame: aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3) -> Result<(), Cause>;
}

struct ActualContext<'held, 'root, 'source, 'original, 'authorization> {
    fence: SourceDeletePendingFenceV1<'held, 'source, 'original, 'authorization>,
    accepted: &'held crate::journal::ControllerDeleteAdmissionOriginalV3,
    root: &'held mut RootDeleteClientOriginalV1<'root>,
    controller: &'held mut Journal,
    launch: &'held ControllerBankLaunchOriginalV1,
    profile: &'held ControllerSelfProfileOriginalV1,
    purpose: Purpose,
}

impl Context for ActualContext<'_, '_, '_, '_, '_> {
    fn completed_current_data(&mut self, session:[u8;64], identity:([u8;32],[u8;32]))
        -> Result<aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3,Cause>
    {
        self.root.completed_preparation_current_data_v3(&self.fence,self.controller,self.launch,self.accepted,session,identity)
    }

    fn current(&mut self) -> Result<crate::normal_root::DeleteSourceClockBoundDataV3, Cause> {
        Ok(match self.purpose {
            Purpose::MountReap62 => self.root.require_mount_reap_before_v4(
                &self.fence, self.controller, self.launch, self.accepted)?,
            Purpose::Preparation26 => self.root.require_storage_preparation_before_v3(
                &self.fence, self.controller, self.launch, self.accepted)?,
            Purpose::Apply7 => self.root.require_storage_apply_before_v3(
                &self.fence, self.controller, self.launch, self.accepted)?,
            Purpose::Network9 => self.root.require_network_apply_before_v4(
                &self.fence, self.controller, self.launch, self.accepted)?,
        })
    }

    fn reserve(&mut self, additional: ResourceVector) -> Result<(), JournalError> {
        self.fence.reserve_preaccept_additional_v1(
            self.controller,
            self.launch,
            self.profile,
            additional,
        )
    }

    fn after(
        &mut self,
        latest: Option<aos_sandbox_model::RawPairedClockSample>,
        refused: bool,
    ) -> Result<(), Cause> {
        if refused {
            self.root.refuse_source_readiness_primary_v3();
        }
        // These posts precede every healthy/currentness recheck.
        self.root
            .finish_source_readiness_interval_once_v3(self.controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.complete(latest.ok_or(JournalError::ProtectedBoundary)?)
    }

    fn retire(&mut self) -> Result<(), Cause> {
        match self.purpose {
            Purpose::MountReap62 => self.root.retire_mount_reap_interval_once_v4(
                &self.fence, self.controller, self.accepted),
            Purpose::Preparation26 => self.root.retire_storage_preparation_interval_once_v3(
                &self.fence, self.controller, self.accepted),
            Purpose::Apply7 => self.root.retire_storage_apply_interval_once_v3(
                &self.fence, self.controller, self.accepted),
            Purpose::Network9 => self.root.retire_network_apply_interval_once_v4(
                &self.fence, self.controller, self.accepted),
        }
    }

    fn complete(&mut self, latest: aos_sandbox_model::RawPairedClockSample) -> Result<(), Cause> {
        match self.purpose {
            Purpose::MountReap62 => self.root.require_mount_reap_after_v4(
                &self.fence, self.controller, self.accepted, latest),
            Purpose::Preparation26 => self.root.require_storage_preparation_after_v3(
                &self.fence, self.controller, self.accepted, latest),
            Purpose::Apply7 => self.root.require_storage_apply_after_v3(
                &self.fence, self.controller, self.accepted, latest),
            Purpose::Network9 => self.root.require_network_apply_after_v4(
                &self.fence, self.controller, self.accepted, latest),
        }
    }

    fn send_current_data(&mut self, frame: aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3) -> Result<(), Cause> {
        self.root.send_preparation_current_once_v3(&mut self.fence, self.controller, self.launch, self.accepted, frame)
            .map_err(|cause| Box::new(cause) as Cause)
    }

}

/// Borrows the accepted Delete's exact signed26 on its one entered C17 interval.
///
/// The constructor is private. This loan cannot be made from a frame, receipt,
/// raw resource vector or another completed operation.
#[doc(hidden)]
#[must_use = "always finish the same C and Root posts after SDK return"]
pub struct OriginalDeleteStoragePreparationLoanV3<'held> {
    inner: OriginalDeleteStorageFlightLoanV3<'held, DeleteStoragePreparationIoOriginalV3>,
}

/// Borrows the exact approved7 beside the actual completed native26 owner.
///
/// Only the closed Bank constructor can create this loan. Every entered attempt
/// retains its genuine C17, Source and Root owners through independent posts.
#[doc(hidden)]
#[must_use = "always finish the same C and Root posts after SDK return"]
pub struct OriginalDeleteStorageApplyLoanV3<'held> {
    inner: OriginalDeleteStorageFlightLoanV3<'held, DeleteStorageApplyIoOriginalV3>,
}

/// Borrows actual Root9 and the genuine Source/C17 owners for one Network flight.
///
/// Only the closed pending/Bank constructor can create this borrower. The same
/// actual fresh Network19 owner must qualify its native Session before entry.
#[doc(hidden)]
#[must_use = "always finish the same C, Source and Root posts after SDK return"]
pub struct OriginalDeleteNetworkApplyLoanV4<'held> {
    inner: OriginalDeleteStorageFlightLoanV3<'held, DeleteNetworkApplyIoOriginalV4>,
}

/// Borrows actual Root62 and the same accepted Source/C17 for one Mount Reap.
///
/// Only the closed pending/Bank constructor creates this loan after the actual
/// Network9 completion and fresh Host3 receipt. The same Mount16 owner must
/// qualify its native Session before any effect request enters.
#[doc(hidden)]
#[must_use = "always finish the same C, Source and Root posts after SDK return"]
pub struct OriginalDeleteMountReapLoanV4<'held> {
    inner: OriginalDeleteStorageFlightLoanV3<'held, DeleteMountReapIoOriginalV4>,
}

struct OriginalDeleteStorageFlightLoanV3<'held, N> {
    context: Box<dyn Context + 'held>,
    state: &'held mut ControllerDeleteStorageFlightOriginalV3<N>,
    predecessor: Predecessor<'held>,
}

impl<N: Native> OriginalDeleteStorageFlightLoanV3<'_, N> {
    /// Borrows the actual completed Session native terminal without mutable state exposure.
    ///
    /// # Errors
    /// Refuses incomplete receipt or any failed independently owed Session post.
    fn completed_preparation_native_v3(&self) -> Result<&[u8; 64], Closed> {
        self.state.io.completed_native_v3()
    }

    /// Completes only the same positive C17 interval after Session window retirement.
    ///
    /// # Errors
    /// Refuses absent actual retirement or any held native/currentness failure.
    fn complete_preparation_once_v3(&mut self) -> Result<(), Closed> {
        self.require_preparation_after_v3()?;
        if !matches!(self.state.retirement, Some(Ok(()))) {
            return Err(Closed::Conflict);
        }
        self.state.complete = Some(self.context.retire());
        if matches!(self.state.complete, Some(Ok(()))) {
            Ok(())
        } else {
            self.state.first.get_or_insert(First::Complete);
            Err(Closed::Conflict)
        }
    }

    /// Prepays the actual selected SDK's fixed endpoint/native entry once.
    ///
    /// The concrete SDK derives this shape from its same held transcript and
    /// compiled flight. A failed or repeated entry permits no SDK native work;
    /// the already entered outer C17/Root interval still owes its afters.
    ///
    /// # Errors
    /// Retains reentry, changed request bound, original currentness or actual
    /// same-C17 capacity failure before SDK endpoint/native entry.
    fn prepay_preparation_entry_once_v3(
        &mut self,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), Closed> {
        use aos_sandbox_model::ResourceDimension as D;
        if self.state.sdk_entry.is_some() {
            self.state.first.get_or_insert(First::Reentry);
            return Err(Closed::Conflict);
        }
        let result = (|| {
            self.require_current_v3()?;
            if shape.request_bytes != self.state.request_bound || shape.response_bytes == 0 {
                return Err(Closed::Conflict);
            }
            let files = shape
                .receive_files
                .checked_add(shape.retained_endpoint_files)
                .ok_or(Closed::Conflict)?;
            let fixed = ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(shape.receiving_bytes).map_err(|_| Closed::Conflict)?,
                )
                .with(
                    D::OpenFiles,
                    u64::try_from(files).map_err(|_| Closed::Conflict)?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(shape.namespace_entries).map_err(|_| Closed::Conflict)?,
                );
            self.require_prepared_complete_native_v3(fixed)
        })();
        self.state.sdk_entry = Some(result);
        if matches!(self.state.sdk_entry, Some(Ok(()))) {
            Ok(())
        } else {
            self.state.first.get_or_insert(First::Contract);
            Err(Closed::Conflict)
        }
    }

    fn native_turn_data_v3(&self) -> u64 {
        self.state.native_turn
    }
    fn cutoff_data_v3(&self) -> u64 {
        self.state.cutoff
    }
    /// Returns the held canonical request ceiling as passive sizing DATA.
    #[must_use]
    fn preparation_request_bound_v3(&self) -> Option<usize> {
        Some(self.state.request_bound)
    }

    fn require_current_v3(&mut self) -> Result<(), Closed> {
        if self.state.first.is_some() || self.state.after.is_some() {
            return Err(Closed::Conflict);
        }
        self.state.contract = Some(self.context.current().map(|_| ()));
        if !matches!(self.state.contract, Some(Ok(()))) {
            self.state.root_selected = true;
            self.state.first.get_or_insert(First::Contract);
            return Err(Closed::Conflict);
        }
        self.state.current = Some(
            self.state
                .clock
                .as_mut()
                .ok_or(Closed::Conflict)?
                .observe_frontier_v3(),
        );
        if matches!(self.state.current, Some(Ok(()))) {
            Ok(())
        } else {
            self.state.first.get_or_insert(First::Clock);
            Err(Closed::Conflict)
        }
    }

    fn require_preparation_contract_v3(&mut self) -> Result<(), Closed> {
        self.require_current_v3()
    }

    fn complete_base_native_v3(
        &mut self,
        incoming: ResourceVector,
    ) -> Result<ResourceVector, Closed> {
        self.state
            .io
            .retained_demand_v3(self.state.native_turn)?
            .checked_add(incoming)
            .map_err(Into::into)
    }

    fn require_prepared_complete_native_v3(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), Closed> {
        if self.state.first.is_some() || self.state.after.is_some() {
            return Err(Closed::Conflict);
        }
        self.state.funding = Some((|| {
            let (_, delta) = crate::controller_resource_reservation::component_receiving::complete_bound_delta_v1(self.state.paid, complete)?;
            let result = self.context.reserve(delta);
            self.state.funding_selected = result.is_err();
            result
        })());
        if matches!(self.state.funding, Some(Ok(()))) {
            self.state.paid = self.state.paid.componentwise_max(complete);
            Ok(())
        } else {
            self.state.first.get_or_insert(First::Funding);
            Err(Closed::Conflict)
        }
    }

    fn require_session_association_v3(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), Closed> {
        self.state
            .io
            .require_session_v3(journal, socket, transcript)
    }

    fn require_session_journal_v3(&self, journal: &Journal) -> Result<(), Closed> {
        self.state.io.require_journal_v3(journal)
    }

    /// Copies the exact privately retained signed26 common header.
    ///
    /// # Errors
    /// Refuses an incomplete canonical body construction.
    fn preparation_header_data_v3(&self) -> Result<RequestHeader, Closed> {
        self.state
            .header
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .cloned()
            .ok_or(Closed::Conflict)
    }

    /// Copies the exact approved body and all four signed authorization artifacts.
    ///
    /// # Errors
    /// Refuses missing or failed canonical construction.
    fn preparation_request_envelope_v3(&self) -> Result<BrokerRequestEnvelope, Closed> {
        self.state
            .envelope
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .cloned()
            .ok_or(Closed::Conflict)
    }

    fn require_preparation_request_v3(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), Closed> {
        let envelope = self
            .state
            .envelope
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Closed::Conflict)?;
        let artifacts = request.authorization().ok_or(Closed::Conflict)?;
        let held = envelope.authorization.as_option().ok_or(Closed::Conflict)?;
        if request.exact_body() != envelope.body || request.method() != N::METHOD
            || artifacts.broker_plan() != held.broker_plan || artifacts.broker_plan_signature() != held.broker_plan_signature
            || artifacts.ownership_lease() != held.ownership_lease || artifacts.ownership_lease_signature() != held.ownership_lease_signature
            || request.deadline_boottime_nanoseconds() != self.state.cutoff {
            return Err(Closed::Conflict);
        }
        Ok(())
    }

    /// Closes the same primary without dropping a failed native append window.
    fn close_preparation_append_window_v3(&self) {
        self.state.io.close_append_window_v3();
    }

    /// Joins the actual held Session to the Root-approved fresh Storage answer.
    ///
    /// # Errors
    /// Retains changed packets, transcript, native file/position, capacity,
    /// protected names, socket origin or finite append-window refusal.
    fn capture_session_once_v3(
        &mut self,
        journal: &mut Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        data: CaptureData,
    ) -> Result<(), Closed> {
        self.require_current_v3()?;
        self.state.capture = Some(N::capture_v3(&mut self.state.io, journal,
            socket, transcript, &self.predecessor, outcome, data));
        if !matches!(self.state.capture, Some(Ok(()))) {
            self.state.first.get_or_insert(First::Capture);
            return Err(Closed::Conflict);
        }
        self.state.window = Some((|| {
            let demand = self
                .state
                .io
                .prepare_append_demand_v3(journal, self.state.request_bound)?;
            let result = self.context.reserve(demand);
            self.state.funding_selected = result.is_err();
            result?;
            self.state.io.install_prepaid_append_once_v3(journal)
        })());
        if matches!(self.state.window, Some(Ok(()))) {
            Ok(())
        } else {
            self.state.first.get_or_insert(First::Window);
            Err(Closed::Conflict)
        }
    }

    /// Records only an earlier SDK refusal before independently owed posts.
    fn refuse_sdk_primary_v3(&mut self) {
        self.state.first.get_or_insert(First::Sdk);
    }

    /// Runs the one entered C17 and Root afters, including after SDK refusal.
    ///
    /// # Errors
    /// Retains original native, clock or horizon failure without a fresh turn.
    fn finish_after_sdk_once_v3(&mut self) -> Result<(), Closed> {
        if self.state.after.is_some() {
            self.state.first.get_or_insert(First::Reentry);
            return Err(Closed::Conflict);
        }
        let latest = self
            .state
            .clock
            .as_ref()
            .and_then(|clock| clock.last_sample_v3().ok());
        self.state.after = Some(self.context.after(latest, self.state.first.is_some()));
        if matches!(self.state.after, Some(Ok(()))) && self.state.first.is_none() {
            Ok(())
        } else {
            self.state.first.get_or_insert(First::After);
            Err(Closed::Conflict)
        }
    }

    fn require_preparation_after_v3(&mut self) -> Result<(), Closed> {
        if self.state.first.is_some() || !matches!(self.state.after, Some(Ok(()))) {
            return Err(Closed::Conflict);
        }
        let latest = self
            .state
            .clock
            .as_ref()
            .ok_or(Closed::Conflict)?
            .last_sample_v3()
            .map_err(|_| Closed::Conflict)?;
        self.state.complete = Some(self.context.complete(latest));
        if matches!(self.state.complete, Some(Ok(()))) {
            Ok(())
        } else {
            self.state.first.get_or_insert(First::Complete);
            Err(Closed::Conflict)
        }
    }

    /// Retires only the positive two-TX Session helper after genuine outer posts.
    ///
    /// # Errors
    /// Refuses missing completion or changed Session and retains failed prefixes.
    fn retire_completed_preparation_append_once_v3(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), Closed> {
        self.require_preparation_after_v3()?;
        if self.state.retirement.is_some() {
            self.state.first.get_or_insert(First::Reentry);
            return Err(Closed::Conflict);
        }
        self.state.retirement = Some(
            self.state
                .io
                .require_journal_v3(journal)
                .map_err(|_| JournalError::ProtectedBoundary)
                .and_then(|()| {
                    self.state
                        .io
                        .completed_native_v3()
                        .map(|_| ())
                        .map_err(|_| JournalError::ProtectedBoundary)
                })
                .and_then(|()| self.state.io.retire_prepaid_append_once_v3(journal)),
        );
        if matches!(self.state.retirement, Some(Ok(()))) {
            Ok(())
        } else {
            self.state.first.get_or_insert(First::Retirement);
            Err(Closed::Conflict)
        }
    }
}

impl<'source, 'original> ControllerDeletePendingOriginalV2<'source, 'original> {
    pub(crate) fn borrow_completed_preparation_cut_v3<'held>(
        &'held mut self, controller: &Journal,
    ) -> Result<ControllerDeleteCompletedPreparationCutV3<'held, 'source, 'original>, JournalError> {
        let state = &self.readiness.acceptance;
        let preparation = &state.preparation;
        if self.outer_after.is_some() || state.first.is_some()
            || !matches!(state.complete, Some(Ok(()))) || preparation.first.is_some()
            || !matches!(preparation.complete, Some(Ok(())))
            || !matches!(preparation.after, Some(Ok(())))
            || !matches!(preparation.retirement, Some(Ok(())))
            || !matches!(preparation.current_send, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let plan = self.plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let fence = self.source.borrow_controller_committed_fence_v3(plan)?;
        state.controller.completed_native_v3(controller, &fence)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        preparation.io.completed_native_v3().map_err(|_| JournalError::ProtectedBoundary)?;
        Ok(ControllerDeleteCompletedPreparationCutV3 {
            fence, accepted: &state.controller, preparation: &preparation.io,
        })
    }

    pub(crate) fn borrow_storage_preparation_once_v3<'held, 'root>(
        &'held mut self,
        root: &'held mut RootDeleteClientOriginalV1<'root>,
        controller: &'held mut Journal,
        launch: &'held ControllerBankLaunchOriginalV1,
        profile: &'held ControllerSelfProfileOriginalV1,
        inventory: DeleteSessionInventoryCutDataV2<'_>,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<OriginalDeleteStoragePreparationLoanV3<'held>, JournalError> {
        let state = &mut self.readiness.acceptance;
        if state.first.is_some()
            || !matches!(state.complete, Some(Ok(())))
            || self.outer_after.is_some()
            || state.preparation.started
        {
            state.preparation.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        let prep = &mut state.preparation;
        prep.started = true;
        let original = self
            .plan
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let fence = self.source.borrow_controller_committed_fence_v3(original)?;
        let inner = OriginalDeleteStorageFlightLoanV3::begin_once_v3(fence, prep,
            &state.controller, root, controller, launch, profile, Some(inventory),
            None, shape, Purpose::Preparation26)?;
        Ok(OriginalDeleteStoragePreparationLoanV3 { inner })
    }
}


impl<'held, N: Native> OriginalDeleteStorageFlightLoanV3<'held, N> {
    fn begin_once_v3<'root, 'source, 'original, 'authorization>(
        mut fence: SourceDeletePendingFenceV1<'held, 'source, 'original, 'authorization>,
        state: &'held mut ControllerDeleteStorageFlightOriginalV3<N>,
        accepted: &'held crate::journal::ControllerDeleteAdmissionOriginalV3,
        root: &'held mut RootDeleteClientOriginalV1<'root>, controller: &'held mut Journal,
        launch: &'held ControllerBankLaunchOriginalV1, profile: &'held ControllerSelfProfileOriginalV1,
        inventory: Option<DeleteSessionInventoryCutDataV2<'_>>,
        preparation: Option<&'held DeleteStoragePreparationIoOriginalV3>,
        shape: crate::StorageProvisioningSessionIoShapeDataV1, purpose: Purpose,
    ) -> Result<Self, JournalError> {
        use aos_sandbox_model::ResourceDimension as D;
        state.request_bound = match (match purpose {
            Purpose::MountReap62 => root.mount_request_bound_v4(),
            Purpose::Preparation26 => root.preparation_request_bound_v3(),
            Purpose::Apply7 => root.apply_request_bound_v3(),
            Purpose::Network9 => root.network_request_bound_v4(),
        }) {
            Some(bound) => bound,
            None => {
                state.construction = Some(Err(JournalError::JournalTooLarge));
                state.first = Some(First::Construction);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        state.construction = Some((|| {
            // SDK and canonical packet/typed envelope copies coexist with the
            // retained earlier Inventory and signed26 originals. The six lanes
            // cover clear, armed, encoded, decoded, returned and SDK request
            // copies at their actual ordinary encoder/decoder boundaries.
            let model_bytes = state
                .request_bound
                .checked_mul(6)
                .and_then(|n| {
                    n.checked_add(
                        std::mem::size_of::<ActualContext<'_, '_, '_, '_, '_>>().checked_mul(3)?,
                    )
                })
                .and_then(|n| {
                    n.checked_add(
                        std::mem::size_of::<Self>()
                            .checked_mul(3)?,
                    )
                })
                .and_then(|n| n.checked_add(shape.receiving_bytes))
                .and_then(|n| u64::try_from(n).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            if shape.request_bytes != state.request_bound || shape.response_bytes == 0 {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            let fixed = ResourceVector::ZERO
                .with(D::MemoryBytes, model_bytes)
                .with(
                    D::OpenFiles,
                    u64::try_from(
                        shape
                            .receive_files
                            .checked_add(shape.retained_endpoint_files)
                            .ok_or(JournalError::JournalTooLarge)?,
                    )
                    .map_err(|_| JournalError::JournalTooLarge)?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(shape.namespace_entries)
                        .map_err(|_| JournalError::JournalTooLarge)?,
                );
            let result = fence.reserve_preaccept_additional_v1(
                controller,
                launch,
                profile,
                fixed
                    .checked_add(DeleteSourceFrontierClockV3::receiving_demand_v3()?)?
                    .checked_add(
                        N::capture_receiving_demand_v3()?,
                    )?,
            );
            state.funding_selected = result.is_err();
            result?;
            // The common member repeats this exact fixed representation as part
            // of its complete requirement. Preserve the already paid prefix;
            // later calls reserve only positive growth, never earlier traffic.
            state.paid = ResourceVector::ZERO
                .with(D::MemoryBytes, shape.receiving_bytes as u64)
                .with(D::OpenFiles, fixed.get(D::OpenFiles))
                .with(D::MetadataEntries, fixed.get(D::MetadataEntries));
            Ok(())
        })());
        if !matches!(state.construction, Some(Ok(()))) {
            state.first = Some(First::Construction);
            return Err(JournalError::ProtectedBoundary);
        }
        let predecessor = if let Some(inventory) = inventory {
            use sha2::{Digest as _, Sha256};
            let request = Sha256::digest(inventory.outcome.request().canonical_packet()).into();
            let outcome = Sha256::digest(inventory.outcome.canonical_packet()).into();
            let native = inventory.native;
            let protected = inventory.protected;
            state.contract = Some(match purpose {
                Purpose::MountReap62 => root.require_mount_inventory_v4(inventory),
                Purpose::Preparation26 => root.require_preparation_inventory_v3(inventory),
                Purpose::Network9 => root.require_network_inventory_v4(inventory),
                Purpose::Apply7 => return Err(JournalError::ProtectedBoundary),
            });
            if !matches!(state.contract, Some(Ok(()))) {
                state.first = Some(First::Contract);
                return Err(JournalError::ProtectedBoundary);
            }
            Predecessor::Inventory { request, outcome, native, protected }
        } else {
            Predecessor::Preparation(preparation.ok_or(JournalError::ProtectedBoundary)?)
        };
        state.entry = Some(match purpose {
            Purpose::MountReap62 => root.begin_mount_reap_interval_once_v4(
                &mut fence, controller, launch, accepted),
            Purpose::Preparation26 => root.begin_storage_preparation_interval_once_v3(
                &mut fence, controller, launch, accepted),
            Purpose::Apply7 => root.begin_storage_apply_interval_once_v3(
                &mut fence, controller, launch, accepted),
            Purpose::Network9 => root.begin_network_apply_interval_once_v4(
                &mut fence, controller, launch, accepted),
        }.map_err(|_| JournalError::ProtectedBoundary));
        if !matches!(state.entry, Some(Ok(()))) {
            state.first = Some(First::Entry);
            return Err(JournalError::ProtectedBoundary);
        }
        match root.storage_preparation_native_turn_v3() {
            Ok(turn) => state.native_turn = turn,
            Err(cause) => {
                state.entry = Some(Err(cause));
                state.first = Some(First::Entry);
            }
        }
        let bound = match purpose {
            Purpose::MountReap62 => root.require_mount_reap_before_v4(&fence, controller, launch, accepted),
            Purpose::Preparation26 => root.require_storage_preparation_before_v3(&fence, controller, launch, accepted),
            Purpose::Apply7 => root.require_storage_apply_before_v3(&fence, controller, launch, accepted),
            Purpose::Network9 => root.require_network_apply_before_v4(&fence, controller, launch, accepted),
        };
        match bound {
            Ok(bound) => {
                state.cutoff = bound.cutoff;
                state.clock = Some(DeleteSourceFrontierClockV3::new(bound));
                state.envelope = Some(match purpose {
                    Purpose::MountReap62 => root.mount_request_envelope_v4(),
                    Purpose::Preparation26 => root.preparation_request_envelope_v3(),
                    Purpose::Apply7 => root.apply_request_envelope_v3(),
                    Purpose::Network9 => root.network_request_envelope_v4(),
                });
                state.header = Some((|| {
                    let envelope = state
                        .envelope
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or(JournalError::ProtectedBoundary)?;
                    let header = match purpose {
                        Purpose::MountReap62 => aos_sandbox_api::aos::sandbox::local::v1::ApplyAttachmentAnchorRequestV1::decode_from_slice(&envelope.body)?
                            .header.as_option().cloned(),
                        Purpose::Preparation26 => PrepareStorageCatalogRequest::decode_from_slice(&envelope.body)?
                            .header.as_option().cloned(),
                        Purpose::Apply7 => aos_sandbox_api::aos::sandbox::local::v1::ApplyStorageRequest::decode_from_slice(&envelope.body)?
                            .header.as_option().cloned(),
                        Purpose::Network9 => aos_sandbox_api::aos::sandbox::local::v1::ApplyNetworkRequest::decode_from_slice(&envelope.body)?
                            .header.as_option().cloned(),
                    };
                    Ok(header.ok_or(JournalError::ProtectedBoundary)?)
                })());
                if !matches!(state.envelope, Some(Ok(_))) || !matches!(state.header, Some(Ok(_))) {
                    state.first = Some(First::Contract);
                }
            }
            Err(cause) => {
                state.contract = Some(Err(cause.into()));
                state.first = Some(First::Entry);
            }
        }
        let context = ActualContext {
            fence,
            accepted: accepted,
            root,
            controller,
            launch,
            profile,
            purpose,
        };
        Ok(Self { context: Box::new(context), state, predecessor })
    }
}

// Only the actual completed owner can construct this lexical cut. No tuple of
// native64s or decoded receipts can create its genuine fence and owner borrows.
pub(crate) struct ControllerDeleteCompletedPreparationCutV3<'held, 'source, 'original> {
    fence: SourceDeletePendingFenceV1<'held, 'source, 'original, 'source>,
    accepted: &'held crate::journal::ControllerDeleteAdmissionOriginalV3,
    preparation: &'held DeleteStoragePreparationIoOriginalV3,
}

impl<'held, 'source, 'original> ControllerDeleteCompletedPreparationCutV3<'held, 'source, 'original> {
    pub(crate) fn into_parts_v3(self) -> (
        SourceDeletePendingFenceV1<'held, 'source, 'original, 'source>,
        &'held crate::journal::ControllerDeleteAdmissionOriginalV3,
        &'held DeleteStoragePreparationIoOriginalV3,
    ) {
        (self.fence, self.accepted, self.preparation)
    }
}

impl ControllerDeletePendingOriginalV2<'_, '_> {
    /// Selects the actual Root/C financial/native cause before any later SDK/post marker.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_preparation_root_failure_is_selected_v3(&self) -> bool {
        let state = &self.readiness.acceptance.preparation;
        state.funding_selected
            || state.root_selected
            || matches!(
                state.first,
                Some(First::Entry | First::After | First::Complete)
            )
    }
}

impl OriginalDeleteStoragePreparationLoanV3<'_> {
    /// Borrows comparison DATA only after real SDK/window/C/Root completion.
    ///
    /// # Errors
    /// Refuses an incomplete/failed original or a changed actual Source/C/Root association.
    #[doc(hidden)]
    /// Sends the intrinsic completed26 cut on the same retained D/C17 owner.
    ///
    /// # Errors
    /// Retains exact association, receiving, transport or independent-post refusal.
    pub fn send_completed_preparation_current_once_v3(&mut self) -> Result<(), Closed> {
        if self.inner.state.current_send.is_some() { return Err(Closed::Conflict); }
        let frame = self.completed_preparation_current_data_v3()?;
        self.inner.state.current_send = Some(self.inner.context.send_current_data(frame));
        if matches!(self.inner.state.current_send, Some(Ok(()))) { Ok(()) }
        else { self.inner.state.root_selected = true; self.inner.state.first.get_or_insert(First::CurrentSend); Err(Closed::Conflict) }
    }

    /// Copies the intrinsic completed26 cut without opening another interval.
    ///
    /// # Errors
    /// Refuses incomplete SDK, Session retirement, outer posts or same-Root association.
    pub fn completed_preparation_current_data_v3(&mut self)
        -> Result<aos_sandbox_protocol::domain_ledger::delete_root::preparation_current::DeleteRootPreparationCurrentDataV3,Closed>
    {
        if self.inner.state.first.is_some() || !matches!(self.inner.state.complete,Some(Ok(())))
            || !matches!(self.inner.state.retirement,Some(Ok(()))) || !matches!(self.inner.state.after,Some(Ok(()))) {
            return Err(Closed::Conflict);
        }
        if self.inner.state.current_frame.is_none() {
            self.inner.state.current_frame=Some((|| {
                let native=*self.inner.state.io.completed_native_v3()?;
                let identity=self.inner.state.io.completed_receipt_identity_data_v3()?;
                let result = self.inner.context.completed_current_data(native,identity);
                if result.is_err() { self.inner.state.root_selected = true; }
                result
            })());
            if !matches!(self.inner.state.current_frame,Some(Ok(_))) {
                self.inner.state.first=Some(First::CurrentFrame);
            }
        }
        self.inner.state.current_frame.as_ref().and_then(|result|result.as_ref().ok()).copied().ok_or(Closed::Conflict)
    }
}
