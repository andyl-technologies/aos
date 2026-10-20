//! Drives actual post-terminal Create issuance on the same resident originals.
//!
//! The whole failed C23 destination stays inline from worker construction. Each
//! genuine positive native interval is finished before its next purpose starts;
//! every entered Root interval runs its independent after even on body failure.
//! The Core action and all original owners move together and return together.

mod storage_io;
mod start_entry;
mod start_network;
mod start_resources;
mod source_progress;
mod pre_ack;
mod final_exchange;

use std::error::Error;
use std::sync::{Arc, Mutex};

use aos_sandbox::{ControllerResourceBankOpeningV1, CreateContinuationIntakeAttemptV1,
    CreateProvisioningOriginalsV1, Journal, OriginalPublicationActionV1,
    OriginalPublicationActionClosedV1, ResourceReservationErrorV1};
use aos_sandbox::cold_launch_publication::{OriginalStorageApplyIssuanceV1,
    OriginalStorageApplyIssuanceClosedV1};
use aos_sandbox::normal_root::{ProductionControllerNormalRootProfileV1,
    RootStorageApplyClientOriginalV1, RootStorageApplyClientClosedV1};
use aos_sandbox::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox_broker::prepared_plan_signing::{PreparedBrokerPlanSigningV1,
    PreparedBrokerPlanCompletionErrorV1};
use aos_sandbox_core::{OperationId, RawPairedClockSample, ResourceVector};
use aos_sandbox_core::model::SignatureBytes;
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;

use super::super::{ControllerBrokerSessions, plan_signer::ControllerBrokerPlanSignerV1};

pub(super) use start_resources::OriginalStartResourcesV2;

type Cause = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy)]
enum First { Entry, Root, Session, Construction, Signer, SigningClock,
    Completion, Models, Body, Source, PreAck, FinalNative, FinalRoot, StorageIo, NativeAfter, RootAfter, Core, Closed }

#[derive(Debug, thiserror::Error)]
#[error("the original installed Create provisioning issuer is closed")]
pub(super) struct OriginalCreateProvisioningClosedV1;

pub(super) struct OriginalCreateProvisioningIssuerV1 {
    parent: Option<OperationId>,
    native: Option<CreateProvisioningOriginalsV1>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    root: Option<RootStorageApplyClientOriginalV1>,
    root_entry: Option<Result<(), ResourceReservationErrorV1>>,
    session: Option<Result<(), Cause>>,
    construction: Option<Result<(), RootStorageApplyClientClosedV1>>,
    issuer: OriginalStorageApplyIssuanceV1,
    normalization: Option<Result<(), OriginalStorageApplyIssuanceClosedV1>>,
    signing: Option<Result<PreparedBrokerPlanSigningV1, Cause>>,
    signing_clock: Option<Result<RawPairedClockSample, RootStorageApplyClientClosedV1>>,
    signature: Option<SignatureBytes>,
    signed: Option<Result<SignedBrokerPlan, PreparedBrokerPlanCompletionErrorV1>>,
    models: Option<Result<(), OriginalStorageApplyIssuanceClosedV1>>,
    body: Option<Result<(), Cause>>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    root_after: Option<Result<(), RootStorageApplyClientClosedV1>>,
    action: Option<OriginalPublicationActionV1>,
    returned: Option<Result<(), OriginalPublicationActionClosedV1>>,
    source: Option<Result<(), ResourceReservationErrorV1>>,
    source_disposal: Option<Result<(), ResourceReservationErrorV1>>,
    source_progress: source_progress::SourceProgressOriginalsV1,
    pre_ack: pre_ack::PreAckOriginalsV1,
    final_exchange: final_exchange::FinalOriginalsV1,
    publication: Option<Result<(), RootStorageApplyClientClosedV1>>,
    storage_io: storage_io::StorageIoOriginalsV1,
    in_core: bool,
    first: Option<First>,
    closed: Option<OriginalCreateProvisioningClosedV1>,
}

impl OriginalCreateProvisioningIssuerV1 {
    pub(super) fn new() -> Self {
        Self {
            parent: None, native: None, entry: None, root: None, root_entry: None,
            session: None, construction: None, issuer: OriginalStorageApplyIssuanceV1::new(),
            normalization: None, signing: None, signing_clock: None, signature: None,
            signed: None, models: None, body: None, after: None, root_after: None,
            action: None, returned: None, source: None, source_disposal: None,
            source_progress: source_progress::SourceProgressOriginalsV1::new(),
            pre_ack: pre_ack::PreAckOriginalsV1::new(),
            final_exchange: final_exchange::FinalOriginalsV1::new(),
            publication: None, storage_io: storage_io::StorageIoOriginalsV1::new(),
            in_core: false, first: None, closed: None,
        }
    }

    // This method stores the whole returned owning native value BEFORE looking
    // at its refusal. No late Box allocation can erase a failed entry.
    pub(super) fn begin_once_v1<T: Sized>(&mut self, runtime_header: &T, parent: OperationId,
        intake: &mut CreateContinuationIntakeAttemptV1,
        bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        driver: &super::super::inventory::OriginalCreateStorageDriverV1,
        controller: &mut Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        if self.parent.is_some() { return self.close(); }
        self.parent = Some(parent);
        self.entry = Some((|| {
            let original = intake.begin_original_provisioning_v1(parent, bank, profile,
                controller, source, ResourceVector::ZERO, runtime_header)?;
            self.native = Some(original);
            if self.native.as_ref().is_none_or(|value| value.failure().is_some()) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
        } else {
            self.root_entry = Some((|| {
                let original = self.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
                let mut loan = original.borrow_root_v1(intake, parent, controller)?;
                self.root = Some(driver.begin_original_storage_apply_root_once_v1(intake,
                    parent, &mut loan, controller, ResourceVector::ZERO)?);
                if self.root.as_ref().is_none_or(|root| root.failure().is_some()) {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                Ok(())
            })());
            if !matches!(self.root_entry, Some(Ok(()))) { self.first = Some(First::Root); }
        }
        self.finish_native_v1(controller);
        self.require_healthy()
    }

    // A new turn can retire only the same actual completed original. The lower
    // owner carries all spent traffic and native lineage forward, without reset.
    fn next_native_v1(&mut self, intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        self.require_healthy()?;
        let parent = self.parent.ok_or(OriginalCreateProvisioningClosedV1)?;
        let mut next_invoked = false;
        self.entry = Some((|| {
            let mut complete = ResourceVector::ZERO;
            if let Some(root) = self.root.as_ref() {
                complete = complete.checked_add(root.resident_receiving_demand_v1()?)?;
            }
            if let Some(action) = self.action.as_ref() {
                complete = complete.checked_add(action.resident_receiving_demand_v1(controller)?)?;
            }
            let original = self.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            next_invoked = true;
            original.begin_next_completed_create_turn_v1(intake, parent, controller, source, complete)
        })());
        if next_invoked { self.after = None; }
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
            return Err(OriginalCreateProvisioningClosedV1);
        }
        Ok(())
    }

    pub(super) fn rollover_once_v1(&mut self, intake: &CreateContinuationIntakeAttemptV1,
        sessions: &mut ControllerBrokerSessions, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        if self.session.is_some() { return self.close(); }
        let next = self.next_native_v1(intake, controller, source);
        if next.is_ok() {
            self.session = Some((|| -> Result<(), Cause> {
                let original = self.native.as_mut().ok_or(OriginalCreateProvisioningClosedV1)?;
                let mut loan = original.borrow_root_v1(intake,
                    self.parent.ok_or(OriginalCreateProvisioningClosedV1)?, controller)?;
                let resident = self.root.as_ref()
                    .ok_or(OriginalCreateProvisioningClosedV1)?
                    .resident_receiving_demand_v1()?;
                sessions.run_original_storage_apply_client_once_v1(&mut loan, controller,
                    resident).map_err(Into::into)
            })());
            if !matches!(self.session, Some(Ok(()))) { self.first = Some(First::Session); }
        }
        self.finish_native_v1(controller);
        self.require_healthy()
    }

    pub(super) fn construct_once_v1(&mut self,
        intake: &CreateContinuationIntakeAttemptV1,
        driver: &super::super::inventory::OriginalCreateStorageDriverV1,
        signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        if self.construction.is_some() { return self.close(); }
        let next = self.next_native_v1(intake, controller, source);
        if next.is_ok() {
            if let (Some(original), Some(root)) = (self.native.as_mut(), self.root.as_mut()) {
                let parent = self.parent.ok_or(OriginalCreateProvisioningClosedV1)?;
                match original.borrow_root_v1(intake, parent, controller) {
                    Ok(mut loan) => {
                        self.construction = Some(root.begin_construction_turn_once_v1(&mut loan,
                            controller, ResourceVector::ZERO));
                    }
                    Err(cause) => {
                        self.entry = Some(Err(cause));
                        self.first = Some(First::Entry);
                    }
                }
                if !matches!(self.construction, Some(Ok(()))) {
                    self.first.get_or_insert(First::Construction);
                }
            } else {
                self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
                self.first = Some(First::Closed);
            }
        }
        if self.first.is_none() { self.construct_paid_body_v1(intake, driver, signer, controller); }
        self.finish_native_v1(controller);
        if let Some(root) = self.root.as_mut() {
            self.root_after = Some(if self.construction.is_none() {
                match self.native.as_ref() {
                    Some(original) => root.observe_construction_entry_refusal_once_v1(original, controller),
                    None => Err(RootStorageApplyClientClosedV1),
                }
            } else {
                root.finish_construction_turn_once_v1(
                    self.issuer.action_for_construction_posts_v1(), self.native.as_ref(), controller)
            });
            if !matches!(self.root_after, Some(Ok(()))) { self.first.get_or_insert(First::RootAfter); }
        }
        if self.first.is_none() {
            if let (Some(original), Some(root)) = (self.native.as_ref(), self.root.as_ref()) {
                match self.issuer.take_action_once_v1(original, root, controller) {
                    Ok(action) => {
                        self.action = Some(action);
                        // Whole construction scratch is retired only after
                        // C23 and Root both completed their actual posts.
                        drop(self.signing.take());
                        drop(self.signed.take());
                    }
                    Err(_) => self.first = Some(First::Models),
                }
            }
        }
        self.require_healthy()
    }

    fn construct_paid_body_v1(&mut self, intake: &CreateContinuationIntakeAttemptV1,
        driver: &super::super::inventory::OriginalCreateStorageDriverV1,
        signer: &ControllerBrokerPlanSignerV1, controller: &Journal,
    ) {
        self.body = Some((|| -> Result<(), Cause> {
            let parent = self.parent.ok_or(OriginalCreateProvisioningClosedV1)?;
            let data = driver.completed_preparation_data_v1(intake, parent)?;
            let ready = driver.completed_ready_bytes_v1(intake, parent)?;
            let original = self.native.as_mut().ok_or(OriginalCreateProvisioningClosedV1)?;
            let root = self.root.as_mut().ok_or(OriginalCreateProvisioningClosedV1)?;
            let mut loan = original.borrow_root_v1(intake, parent, controller)?;
            let (authority, scope) = signer.create_plan_inputs_v1()?;
            self.normalization = Some(self.issuer.prepare_once_v1(&mut loan, controller, root,
                data.proposed(), ready, data.bundle().specification, data.outcome(), data.response(),
                authority, scope, ResourceVector::ZERO));
            if !matches!(self.normalization, Some(Ok(()))) {
                self.first = Some(First::Models);
                return Err(Box::new(OriginalCreateProvisioningClosedV1));
            }
            {
                let admission = root.borrow_admission_v1(&loan, controller)?;
                let construction = root.borrow_construction_turn_v1(&loan, controller)?;
                self.signing = Some(signer.prepare_original_storage_apply_plan_v1(
                    &self.issuer, &admission, &construction));
            }
            if !matches!(self.signing, Some(Ok(_))) {
                self.first = Some(First::Signer);
                return Err(Box::new(OriginalCreateProvisioningClosedV1));
            }
            let signing = self.signing.as_mut().and_then(|value| value.as_mut().ok())
                .ok_or(OriginalCreateProvisioningClosedV1)?;
            let key_message = signing.key_message_loan()?;
            self.signing_clock = Some(root.final_signing_clock_once_v1(&loan, controller));
            let now = *self.signing_clock.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or_else(|| { self.first = Some(First::SigningClock); OriginalCreateProvisioningClosedV1 })?;
            {
                let admission = root.borrow_admission_v1(&loan, controller)?;
                let construction = root.borrow_construction_turn_v1(&loan, controller)?;
                construction.require_admission_v1(&admission)?;
                self.issuer.signing_preparation_v1(&admission, &construction)?;
            }
            self.signature = Some(key_message.sign());
            let signature = self.signature.as_ref()
                .ok_or(OriginalCreateProvisioningClosedV1)?;
            self.signed = Some(signing.complete_once(signature, now.wall_seconds()));
            let signed = self.signed.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or_else(|| { self.first = Some(First::Completion); OriginalCreateProvisioningClosedV1 })?;
            self.models = Some(self.issuer.build_action_once_v1(&mut loan, controller, root, signed));
            if !matches!(self.models, Some(Ok(()))) {
                self.first = Some(First::Models);
                return Err(Box::new(OriginalCreateProvisioningClosedV1));
            }
            Ok(())
        })());
        if matches!(self.body, Some(Err(_))) {
            self.first.get_or_insert(First::Body);
        }
    }

    fn finish_native_v1(&mut self, controller: &mut Journal) {
        if self.after.is_some() { return; }
        if let Some(original) = self.native.as_mut() {
            self.after = Some(original.finish_native_once_v1(controller));
            if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::NativeAfter); }
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let original = || self.native.as_ref().and_then(|value| value.failure());
        let root = || self.root.as_ref().and_then(|root| self.native.as_ref()
            .and_then(|original| root.publication_failure_with_original_v1(original))
            .or_else(|| root.failure()));
        match self.first? {
            First::Entry => original().or_else(|| self.entry.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Root => self.root.as_ref().and_then(|root| self.native.as_ref()
                .and_then(|original| root.failure_with_original_v1(original)))
                .or_else(|| self.root_entry.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Session => self.session.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Construction | First::SigningClock | First::RootAfter => root(),
            First::Signer => self.signing.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Completion => self.signed.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Models => self.native.as_ref()
                .and_then(|original| self.issuer.failure_with_original_v1(original))
                .or_else(|| self.issuer.failure()),
            First::Source => self.native.as_ref()
                .and_then(|original| original.create_lifecycle_source_failure_v1())
                .or_else(|| self.source.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.source_disposal.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.source_progress.failure()),
            First::PreAck => {
                if self.pre_ack.attempt.root_entry_failure_is_selected_v1() {
                    return root().or_else(|| self.pre_ack.failure());
                }
                self.native.as_ref().and_then(|original|
                    self.pre_ack.attempt.failure_with_original_v1(original))
                    .or_else(|| self.pre_ack.failure())
            }
            First::FinalNative => self.native.as_ref()
                .and_then(|original| self.pre_ack.attempt.final_failure_with_original_v1(original))
                .or_else(|| self.final_exchange.failure()),
            First::FinalRoot => self.root.as_ref().and_then(|root| self.native.as_ref()
                .and_then(|original| root.failure_with_original_v1(original)))
                .or_else(|| self.final_exchange.failure()),
            First::StorageIo => {
                if self.storage_io.selected_original {
                    return self.native.as_ref().and_then(|original|
                        original.storage_io_original_failure_v1())
                        .or_else(|| self.storage_io.failure());
                }
                self.storage_io.failure().or_else(|| self.closed.as_ref().map(|cause| cause as _))
            }
            First::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::NativeAfter => original().or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Core => self.action.as_ref().and_then(|action| {
                if action.core_entry_root_failure_is_selected_v1()
                    || action.core_root_after_failure_is_selected_v1() { return root(); }
                if action.core_entry_original_failure_is_selected_v1()
                    || action.core_native_after_failure_is_selected_v1() {
                    return original().or_else(|| action.failure());
                }
                action.failure().or_else(root).or_else(original)
            }),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    pub(super) fn fmt_failure_v1(&self, formatter: &mut std::fmt::Formatter<'_>)
        -> std::fmt::Result {
        if matches!(self.first, Some(First::FinalNative)) {
            if let Some(original) = self.native.as_ref() {
                if let Some(view) = self.pre_ack.attempt.final_failure_view_with_original_v1(original) {
                    return std::fmt::Display::fmt(&view, formatter);
                }
            }
        }
        let root_selected = match self.first {
            Some(First::Root | First::Construction | First::SigningClock | First::RootAfter | First::FinalRoot) => true,
            Some(First::PreAck) => self.pre_ack.attempt.root_entry_failure_is_selected_v1(),
            Some(First::Core) => self.action.as_ref()
                .is_some_and(|action| action.core_entry_root_failure_is_selected_v1()
                    || action.core_root_after_failure_is_selected_v1()),
            _ => false,
        };
        if root_selected {
            if let (Some(root), Some(original)) = (self.root.as_ref(), self.native.as_ref()) {
                if let Some(view) = root.failure_view_with_original_v1(original) {
                    return std::fmt::Display::fmt(&view, formatter);
                }
            }
        }
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original provisioning owner has no retained failure"),
        }
    }

    fn require_healthy(&self) -> Result<(), OriginalCreateProvisioningClosedV1> {
        if self.first.is_some() { Err(OriginalCreateProvisioningClosedV1) } else { Ok(()) }
    }

    fn close<T>(&mut self) -> Result<T, OriginalCreateProvisioningClosedV1> {
        self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
        self.first.get_or_insert(First::Closed);
        Err(OriginalCreateProvisioningClosedV1)
    }
}

impl OriginalCreateProvisioningIssuerV1 {
    fn begin_publication_v1(&mut self, intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        let next = self.next_native_v1(intake, controller, source);
        if next.is_err() {
            // A next-C refusal still reaches its prearmed Root-only negative
            // destination; neither the old J nor another C is constructed.
            self.finish_native_v1(controller);
            if let (Some(root), Some(action), Some(original)) =
                (self.root.as_mut(), self.action.as_ref(), self.native.as_ref()) {
                self.root_after = Some(root.observe_publication_entry_refusal_once_v1(
                    action, original, controller));
            }
            return Err(OriginalCreateProvisioningClosedV1);
        }
        let mut root_invoked = false;
        self.publication = Some(match (self.native.as_mut(), self.root.as_mut(), self.action.as_ref()) {
            (Some(original), Some(root), Some(action)) => {
                match original.borrow_root_v1(intake,
                    self.parent.ok_or(OriginalCreateProvisioningClosedV1)?, controller) {
                    Ok(mut loan) => {
                        let resident = action.resident_receiving_demand_v1(controller);
                        match resident {
                            Ok(complete) => {
                                root_invoked = true;
                                root.begin_publication_turn_once_v1(
                                    &mut loan, controller, action, complete)
                            },
                            Err(cause) => {
                                self.entry = Some(Err(cause));
                                self.first = Some(First::Entry);
                                Err(RootStorageApplyClientClosedV1)
                            }
                        }
                    }
                    Err(cause) => {
                        self.entry = Some(Err(cause));
                        self.first = Some(First::Entry);
                        Err(RootStorageApplyClientClosedV1)
                    }
                }
            }
            _ => return self.close(),
        });
        if !matches!(self.publication, Some(Ok(()))) {
            self.first.get_or_insert(First::Construction);
            self.finish_native_v1(controller);
            if let (Some(root), Some(action)) = (self.root.as_mut(), self.action.as_ref()) {
                self.root_after = Some(if root_invoked {
                    root.finish_publication_turn_once_v1(action, self.native.as_ref(), controller)
                } else {
                    match self.native.as_ref() {
                        Some(original) => root.observe_publication_entry_refusal_once_v1(
                            action, original, controller),
                        None => Err(RootStorageApplyClientClosedV1),
                    }
                });
            }
            return Err(OriginalCreateProvisioningClosedV1);
        }
        Ok(())
    }

    pub(super) fn admit_source_once_v1(&mut self,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        if self.source.is_some() { return self.close(); }
        let entered = self.begin_publication_v1(intake, controller, source);
        if entered.is_ok() {
            self.source = Some((|| {
                let action = self.action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
                let root = self.root.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
                let original = self.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
                let turn = root.borrow_publication_turn_v1(action, original, controller)?;
                let mut loan = original.borrow_root_v1(intake,
                    self.parent.ok_or(ResourceReservationErrorV1::Conflict)?, controller)?;
                loan.admit_original_create_lifecycle_source_once_v1(action, &turn, controller, source)
            })());
            if !matches!(self.source, Some(Ok(()))) { self.first.get_or_insert(First::Source); }
            self.finish_native_v1(controller);
            if let (Some(root), Some(action)) = (self.root.as_mut(), self.action.as_ref()) {
                self.root_after = Some(root.finish_publication_turn_once_v1(
                    action, self.native.as_ref(), controller));
                if !matches!(self.root_after, Some(Ok(()))) { self.first.get_or_insert(First::RootAfter); }
            }
            if let (Some(original), Some(root), Some(action)) =
                (self.native.as_mut(), self.root.as_ref(), self.action.as_ref()) {
                self.source_disposal = Some(original.finish_original_create_lifecycle_source_after_posts_once_v1(
                    action, root, controller, source));
                if !matches!(self.source_disposal, Some(Ok(()))) { self.first.get_or_insert(First::Source); }
            }
        }
        self.require_healthy()
    }

    pub(super) fn prepare_core_v1(&mut self, intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<Option<(OriginalPublicationActionV1, CreateProvisioningOriginalsV1,
        RootStorageApplyClientOriginalV1)>, OriginalCreateProvisioningClosedV1> {
        self.require_healthy()?;
        if self.in_core { return self.close(); }
        let action = self.action.as_ref().ok_or(OriginalCreateProvisioningClosedV1)?;
        if action.child_succeeded_v1() {
            // Durable child success is not public Create completion. The later
            // genuine Source/748/160/CAS stages retain the Applying fence.
            return Ok(None);
        }
        self.begin_publication_v1(intake, controller, source)?;
        if self.action.is_none() || self.native.is_none() || self.root.is_none() {
            return self.close();
        }
        self.in_core = true;
        match (self.action.take(), self.native.take(), self.root.take()) {
            (Some(action), Some(original), Some(root)) => Ok(Some((action, original, root))),
            _ => std::process::abort(),
        }
    }

    pub(super) fn retain_core_v1(&mut self, action: OriginalPublicationActionV1,
        original: CreateProvisioningOriginalsV1, root: RootStorageApplyClientOriginalV1,
        returned: Result<(), OriginalPublicationActionClosedV1>,
    ) {
        if !self.in_core || self.action.is_some() || self.native.is_some() || self.root.is_some() {
            std::process::abort();
        }
        self.action = Some(action);
        self.native = Some(original);
        self.root = Some(root);
        self.returned = Some(returned);
        self.in_core = false;
        if !matches!(self.returned, Some(Ok(()))) { self.first.get_or_insert(First::Core); }
    }
}

impl super::ProductionEffectExecutor {
    pub(super) fn prepare_original_provisioning_turn_v1(&mut self,
        operation: OperationId,
        plan: &aos_sandbox_protocol::domain_ledger::effect_history::EffectPlan,
        controller: &mut Journal,
    ) -> Result<Option<(OriginalPublicationActionV1, CreateProvisioningOriginalsV1,
        RootStorageApplyClientOriginalV1)>, aos_sandbox::reconciler::EffectFailure> {
        use aos_sandbox::reconciler::EffectFailure;
        let stopped = || EffectFailure::Permanent(
            "the original Create provisioning owner retains a refusal".to_owned());
        if plan.public_mutation_method()
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox) {
            return Ok(None);
        }
        if self.create_provisioning.parent.is_none() {
            let bank = Arc::clone(self.resource_bank.as_ref().ok_or_else(stopped)?);
            let mut selected = self.q04.take().ok_or_else(stopped)?;
            let mut owner = std::mem::replace(&mut self.create_provisioning,
                OriginalCreateProvisioningIssuerV1::new());

            // Both inline destinations are subfields of this full compiled
            // Runtime layout. No suspension or callback observes placeholders.
            // Restore both originals before inspecting any returned Result.
            let entered = match selected.provisioning_parts_v1() {
                Some((intake, driver, profile)) => owner.begin_once_v1(
                    &*self, operation, intake, bank, Arc::clone(profile), driver,
                    controller, &self.source_domains),
                None => owner.close(),
            };
            self.q04 = Some(selected);
            self.create_provisioning = owner;
            entered.map_err(|_| stopped())?;
        } else if self.create_provisioning.parent != Some(operation) {
            return Err(stopped());
        }
        let selected = self.q04.as_mut().ok_or_else(stopped)?;
        let (intake, driver, _) = selected.provisioning_parts_v1().ok_or_else(stopped)?;
        intake.require_original_create_terminal_v1(operation).map_err(|_| stopped())?;
        let owner = &mut self.create_provisioning;
        if owner.session.is_none() {
            let mut sessions = self.sessions.lock().map_err(|_| stopped())?;
            owner.rollover_once_v1(intake, &mut sessions, controller, &self.source_domains)
                .map_err(|_| stopped())?;
        }
        if owner.action.is_none() {
            owner.construct_once_v1(intake, driver,
                self.broker_plan_signer.as_ref().ok_or_else(stopped)?, controller,
                &self.source_domains).map_err(|_| stopped())?;
        }
        if owner.source.is_none() {
            owner.admit_source_once_v1(intake, controller, &mut self.source_domains)
                .map_err(|_| stopped())?;
        }
        if owner.action.as_ref().is_some_and(OriginalPublicationActionV1::child_succeeded_v1) {
            if !owner.source_progress.completed_v1() {
                let mut sessions = self.sessions.lock().map_err(|_| stopped())?;
                owner.advance_source_progress_once_v1(intake, controller,
                    &mut self.source_domains, &mut sessions).map_err(|_| stopped())?;
            } else if !owner.pre_ack.completed_v1() {
                let mut sessions = self.sessions.lock().map_err(|_| stopped())?;
                owner.record_pre_ack_once_v1(intake, controller,
                    &mut self.source_domains, &mut sessions).map_err(|_| stopped())?;
            } else if !owner.final_exchange.completed_v1() {
                owner.finish_create_stopped_once_v1(intake, controller,
                    &mut self.source_domains).map_err(|_| stopped())?;
            }
            // Only the actual prearmed strict160/native/Source/C completion
            // may publish success. No second effect settlement occurs here. The typed preACK/748/160/final CAS
            // continuation must complete before public Create can succeed.
            return Ok(None);
        }
        owner.prepare_core_v1(intake, controller, &self.source_domains).map_err(|_| stopped())
    }
}
