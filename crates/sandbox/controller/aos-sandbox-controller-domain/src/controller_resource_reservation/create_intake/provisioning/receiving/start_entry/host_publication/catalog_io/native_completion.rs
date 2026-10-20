//! Retains the real Catalog17 send, response and native terminal stage.
//!
//! Only the genuine pending-child loan can move the actual completed IO stage
//! here. The lower owner proves native completion; the SDK separately retains
//! captured-key/context authentication and qualifies its private Session.

use super::super::super::super::storage_io::StorageIoStagesV1;
use super::*;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordBindingError, StorageSeqpacketSendAttemptV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

#[derive(Clone, Copy)]
enum First {
    Sent,
    Received,
    Packet,
    Post,
    Abandoned,
    Resident,
}

/// Retains actual native publication evidence without an external positive constructor.
///
/// A signed outcome or generation/digest tuple cannot construct this owner.
/// Its stage includes the actual retained same-Journal name/witness post and
/// protected terminal-row decoder. It does not independently authenticate the
/// SDK's captured enrolled key or authorize the later Host launch.
#[doc(hidden)]
pub struct StartHostCatalogNativeCompletionV2 {
    stages: Option<StorageIoStagesV1>,
    identity: Arc<()>,
    parent: OperationId,
    generation: u64,
    catalog_digest: [u8; 32],
    request_digest: [u8; 32],
    outcome_digest: [u8; 32],
    sent: Option<StorageSeqpacketSendAttemptV1>,
    received: Option<ReceivedRecord>,
    sent_cookie: Option<aos_sandbox_linux::Result<u64>>,
    received_cookie: Option<aos_sandbox_linux::Result<u64>>,
    sent_binding: Option<Result<(), RecordBindingError>>,
    received_binding: Option<Result<(), RecordBindingError>>,
    post: Option<Result<(), StartResourceSessionCurrentnessErrorV4>>,
    first: Option<First>,
    disposal_entered: bool,
    disposed: bool,
    session_resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
}

impl StartHostCatalogNativeCompletionV2 {
    /// Returns the existing commitment to the complete canonical signed outcome.
    ///
    /// This pure comparison DATA shares the native completion's exact packet
    /// digest with its SDK qualifier. It grants no native completion, current
    /// Session, disposed receipt or activation permission.
    #[doc(hidden)]
    #[must_use]
    pub fn canonical_outcome_digest_data_v2(outcome: &AuthenticatedBrokerMethodOutcomeV1) -> [u8; 32] {
        *blake3::hash(outcome.canonical_packet()).as_bytes()
    }


    /// Borrows the original native stopping cause without sampling again.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        fn error(result: &Option<Result<(), RecordBindingError>>) -> Option<&RecordBindingError> {
            result.as_ref().and_then(|value| value.as_ref().err())
        }
        match self.first? {
            First::Sent => self
                .sent_cookie
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| error(&self.sent_binding).map(|cause| cause as _))
                .or_else(|| self.sent.as_ref().and_then(|sent| sent.failure())),
            First::Received => self
                .received_cookie
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| error(&self.received_binding).map(|cause| cause as _)),
            First::Post => self
                .post
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _),
            First::Resident => self
                .session_resident
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _),
            First::Packet | First::Abandoned => {
                Some(&ResourceReservationErrorV1::Conflict as &(dyn Error + 'static))
            }
        }
        .or(Some(&ResourceReservationErrorV1::Conflict))
    }

    pub(crate) fn retained_demand_v2(
        &self,
        turn: u64,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.stages
            .as_ref()
            .map_or(Ok(ResourceVector::ZERO), |stages| {
                stages.retained_demand_v1(turn)
            })
    }

    pub(crate) fn require_terminal_v2(
        &self,
        identity: &Arc<()>,
        parent: OperationId,
        source: &StartHostCatalogPublicationOriginalV2,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let draft = source
            .draft_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.first.is_some()
            || !Arc::ptr_eq(&self.identity, identity)
            || self.parent != parent
            || self.generation != draft.expected_generation()
            || &self.catalog_digest != draft.expected_digest().as_bytes()
            || self.request_digest != outcome.request().signed_request_digest()
            || self.outcome_digest != Self::canonical_outcome_digest_data_v2(outcome)
            || !matches!(self.post, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

/// Keeps both offered receipts when the genuine stage cannot accept them.
#[derive(Debug)]
#[doc(hidden)]
pub struct StartHostCatalogCompletionRefusalV2 {
    sent: Option<StorageSeqpacketSendAttemptV1>,
    received: Option<ReceivedRecord>,
}

impl std::fmt::Display for StartHostCatalogCompletionRefusalV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the original Host catalog native completion remains closed")
    }
}

impl Error for StartHostCatalogCompletionRefusalV2 {}

impl StartHostCatalogIoLoanV2<'_> {
    /// Parks the actual native receipts and moves the same completed stage once.
    ///
    /// Both native bindings and the independent same-Session post are attempted
    /// after receipt parking. The SDK invokes this only from its privately
    /// authenticated completed Catalog17 flight, before dropping the short loan.
    ///
    /// # Errors
    /// Preserves offered receipts on rejected entry; reached native causes stay
    /// in the actual NativeState completion owner through all outer posts.
    #[doc(hidden)]
    pub fn prepare_native_completion_once_v2(
        &mut self,
        source: &StartHostCatalogPublicationOriginalV2,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        sent: StorageSeqpacketSendAttemptV1,
        received: ReceivedRecord,
    ) -> Result<(), StartHostCatalogCompletionRefusalV2> {
        let mut refused = StartHostCatalogCompletionRefusalV2 {
            sent: Some(sent),
            received: Some(received),
        };
        if self.require_catalog_source_v2(source).is_err()
            || self
                .require_publication_request_v2(outcome.request())
                .is_err()
            || self.native.resources.host_catalog_completion.is_some()
        {
            return Err(refused);
        }
        let draft = match source.draft_v2() {
            Ok(draft) => draft,
            Err(_) => return Err(refused),
        };
        let stages = match self
            .io_stages_v2()
            .take_completed_catalog_once_v2(journal, outcome)
        {
            Ok(stages) => stages,
            Err(_) => return Err(refused),
        };
        let mut owner = StartHostCatalogNativeCompletionV2 {
            stages: Some(stages),
            identity: Arc::clone(self.identity),
            parent: self.plan.operation_id(),
            generation: draft.expected_generation(),
            catalog_digest: *draft.expected_digest().as_bytes(),
            request_digest: outcome.request().signed_request_digest(),
            outcome_digest: StartHostCatalogNativeCompletionV2::canonical_outcome_digest_data_v2(outcome),
            sent: refused.sent.take(),
            received: refused.received.take(),
            sent_cookie: None,
            received_cookie: None,
            sent_binding: None,
            received_binding: None,
            post: None,
            first: None,
            disposal_entered: false,
            disposed: false,
            session_resident: None,
        };
        use super::super::super::super::storage_io::catalog_completion::{
            CatalogReceiptFirstV2, observe_catalog_receipts_retaining_v2,
        };
        if let Some(first) = observe_catalog_receipts_retaining_v2(
            socket, outcome.canonical_packet(), owner.sent.as_ref(), owner.received.as_ref(),
            &mut owner.sent_cookie, &mut owner.received_cookie,
            &mut owner.sent_binding, &mut owner.received_binding,
        ) {
            owner.first.get_or_insert(match first {
                CatalogReceiptFirstV2::Sent => First::Sent,
                CatalogReceiptFirstV2::Received => First::Received,
                CatalogReceiptFirstV2::Packet => First::Packet,
            });
        }
        // This native post remains owed after either earlier receipt failure.
        owner.post = Some(
            self.association
                .require_current_session_v4(journal, socket, transcript),
        );
        if !matches!(owner.post, Some(Ok(()))) {
            owner.first.get_or_insert(First::Post);
        }
        let positive = owner.first.is_none();
        self.native.resources.host_catalog_completion = Some(owner);
        if positive { Ok(()) } else { Err(refused) }
    }
}

/// Borrows the genuine completed Catalog6 native owner until physical SDK disposal.
///
/// This token has no constructor outside the actual completed Entry below.
/// Dropping it unfinished closes the owner and preserves every native prefix.
#[doc(hidden)]
#[must_use = "drop the same successful SDK Catalog17 controls before completing disposal"]
pub struct StartHostCatalogDisposalV2<'owner> {
    owner: &'owner mut StartHostCatalogNativeCompletionV2,
    completed: bool,
}

impl StartHostCatalogDisposalV2<'_> {
    /// Retires the actual positive lower native prefixes after upper controls drop.
    ///
    /// This preserves the live Host Session; it drops only this completed
    /// catalog operation's receipts, namespace witnesses and replay originals.
    pub fn complete_after_disposal_v2(mut self) {
        drop(self.owner.sent.take());
        drop(self.owner.received.take());
        drop(self.owner.stages.take());
        self.owner.disposed = true;
        self.completed = true;
    }
}

impl Drop for StartHostCatalogDisposalV2<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.first.get_or_insert(First::Abandoned);
        }
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Borrows the actual confirmed Catalog6 owner only after its C and Root posts.
    ///
    /// # Errors
    /// Refuses an unfinished Root6/C interval, changed confirmed source or
    /// native receipts, failed stage, or repeated/abandoned physical disposition.
    #[doc(hidden)]
    pub fn prepare_host_catalog_disposal_once_v2<'owner>(
        &'owner mut self,
        root: &crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &Journal,
        source: &StartHostCatalogPublicationOriginalV2,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<StartHostCatalogDisposalV2<'owner>, ResourceReservationErrorV1> {
        self.require_completed_host_catalog_turn_v2(root, controller)?;
        let native = self
            .native_state
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native
            .host_publication_action
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        source.require_native_source_v2(
            &action.contract.identity,
            action.contract.parent,
            controller,
        )?;
        source.require_confirmed_native_source_v2(controller)?;
        let owner = native
            .resources
            .host_catalog_completion
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        owner.require_terminal_v2(
            &action.contract.identity,
            action.contract.parent,
            source,
            outcome,
        )?;
        if owner.disposal_entered
            || owner.disposed
            || !matches!(owner.session_resident, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        owner.disposal_entered = true;
        Ok(StartHostCatalogDisposalV2 {
            owner,
            completed: false,
        })
    }
}

impl StartHostCatalogNativeCompletionV2 {
    /// Compares only an already disposed native completion with exact SDK coordinates.
    ///
    /// The caller must independently hold the SDK's opaque qualified borrower;
    /// this method is comparison DATA and cannot construct one or grant launch.
    ///
    /// # Errors
    /// Refuses incomplete native/physical disposition or changed exact receipt.
    #[doc(hidden)]
    pub fn require_disposed_receipt_data_v2(
        &self,
        generation: u64,
        digest: &[u8; 32],
        request: &[u8; 32],
        outcome: &[u8; 32],
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some()
            || !self.disposed
            || self.stages.is_some()
            || self.sent.is_some()
            || self.received.is_some()
            || generation != self.generation
            || digest != &self.catalog_digest
            || request != &self.request_digest
            || outcome != &self.outcome_digest
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl StartHostCatalogNativeCompletionV2 {
    // Activation compares its actual immutable private Action contract. This
    // is a negative gate on an existing native owner, never an owner factory.
    pub(crate) fn require_disposed_owner_v2(
        &self,
        identity: &Arc<()>,
        parent: OperationId,
        generation: u64,
        digest: &[u8; 32],
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some()
            || !self.disposed
            || self.stages.is_some()
            || self.sent.is_some()
            || self.received.is_some()
            || !matches!(self.session_resident, Some(Ok(_)))
            || !Arc::ptr_eq(&self.identity, identity)
            || self.parent != parent
            || self.generation != generation
            || &self.catalog_digest != digest
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Records the actual post17 Session survivors after real Catalog6 C/Root posts.
    ///
    /// The retained stage's measured final extent must equal its actual native
    /// names/writer-witness post. This reuses the sole opening survivor recipe,
    /// replaces no failed prefix and performs no new observation or late debit.
    /// The candidate must fit the same already-paid opening and IO receipts.
    ///
    /// # Errors
    /// Refuses changed source/Session, unfinished outer posts, repeated handoff,
    /// inconsistent native extent, overflow or survivors outside admitted costs.
    #[doc(hidden)]
    pub fn retain_completed_host_catalog_session_once_v2(
        &mut self,
        opening: &StartResourceSessionOpeningOriginalV2,
        root: &crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &Journal,
        source: &StartHostCatalogPublicationOriginalV2,
        sdk: crate::StartResourceSessionResidentShapeDataV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_host_catalog_turn_v2(root, controller)?;
        let native = self
            .native_state
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native
            .host_publication_action
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        source.require_native_source_v2(
            &action.contract.identity,
            action.contract.parent,
            controller,
        )?;
        source.require_confirmed_native_source_v2(controller)?;
        if native.resources.host.session_resident.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let post = native.resources.host_catalog_post.retained_demand_v2()?;
        let owner = native
            .resources
            .host_catalog_completion
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if owner.first.is_some() || owner.session_resident.is_some() || owner.disposal_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let resident = (|| {
            let stages = owner
                .stages
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let extent = stages.completed_catalog_extent_v2()?;
            let sdk = ResourceVector::ZERO
                .with(D::MemoryBytes, sdk.memory_bytes)
                .with(D::OpenFiles, sdk.open_files)
                .with(D::MetadataEntries, sdk.namespace_entries);
            let receipt = stages
                .retained_demand_v1(native.native_turn)?
                .checked_add(post)?;
            opening.completed_host_catalog_resident_from_extent_v2(
                &action.contract.identity,
                action.contract.parent,
                native.native_turn,
                &native.profile,
                extent,
                sdk,
                receipt,
            )
        })();
        owner.session_resident = Some(resident);
        let Some(Ok(demand)) = owner.session_resident.as_ref() else {
            owner.first.get_or_insert(First::Resident);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        native.resources.host.session_resident = Some(Ok(*demand));
        Ok(())
    }

    /// Retires only the disposed catalog operation's former residency liability.
    ///
    /// The new Session survivor receipt stays held. No account balance, spent
    /// traffic or reached peak is reduced, and a failed owner cannot enter here.
    ///
    /// # Errors
    /// Refuses missing outer posts, actual lower disposal or final17 handoff.
    #[doc(hidden)]
    pub fn finish_host_catalog_resident_disposal_v2(
        &mut self,
        root: &crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_host_catalog_turn_v2(root, controller)?;
        let native = self
            .native_state
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native
            .host_publication_action
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        native
            .resources
            .host_catalog_completion
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_disposed_owner_v2(
                &action.contract.identity,
                action.contract.parent,
                action.contract.catalog_generation,
                &action.contract.catalog_digest,
            )?;
        native.resources.host_catalog_opening_resident = ResourceVector::ZERO;
        native.resources.host_catalog_post.disposed = true;
        Ok(())
    }
}
