//! Consumes the actual completed shared stage and native Catalog17 receipts.
//!
//! The opaque SDK still supplies captured enrolled-key/context qualification.
//! This lower owner independently owns the genuine native stage, packet and
//! both socket-cookie probes plus the always-owed independent Session post.
//! No tuple, result marker or caller-owned snapshot can mint its completion.

use super::*;
use crate::controller_resource_reservation::create_intake::provisioning::receiving::storage_io::catalog_completion::{
    CatalogReceiptFirstV2, observe_catalog_receipts_retaining_v2,
};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2;
use aos_sandbox_linux::seqpacket::{StorageSeqpacketSendAttemptV1, ReceivedRecord};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

#[derive(Clone, Copy)]
enum CompletionFirstV2 {
    Sent,
    Received,
    Packet,
    Post,
    Disposal,
}

pub(super) struct CatalogMaintenanceCatalogNativeCompletionV2 {
    identity: ControllerCatalogMaintenanceIdentityV2,
    generation: u64,
    catalog_digest: [u8; 32],
    request_digest: [u8; 32],
    outcome_digest: [u8; 32],
    stages: Option<StorageIoStagesV1>,
    sent: Option<StorageSeqpacketSendAttemptV1>,
    received: Option<ReceivedRecord>,
    sent_cookie: Option<Result<u64, aos_linux_descriptors::Error>>,
    received_cookie: Option<Result<u64, aos_linux_descriptors::Error>>,
    sent_binding: Option<Result<(), RecordBindingError>>,
    received_binding: Option<Result<(), RecordBindingError>>,
    post: Option<Result<(), ControllerCatalogMaintenanceSessionCurrentnessErrorV2>>,
    first: Option<CompletionFirstV2>,
    disposal_entered: bool,
    disposed: bool,
}

impl CatalogMaintenanceCatalogNativeCompletionV2 {
    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(
            slot: &Option<Result<T, E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            CompletionFirstV2::Sent => cause(&self.sent_cookie)
                .or_else(|| cause(&self.sent_binding))
                .or_else(|| self.sent.as_ref().and_then(|sent| sent.failure())),
            CompletionFirstV2::Received => {
                cause(&self.received_cookie).or_else(|| cause(&self.received_binding))
            }
            CompletionFirstV2::Post => cause(&self.post),
            CompletionFirstV2::Packet | CompletionFirstV2::Disposal => {
                Some(&CatalogMaintenanceClosedV2 as &(dyn Error + 'static))
            }
        }
        .or(Some(&CatalogMaintenanceClosedV2))
    }

    pub(super) fn require_terminal_v2(
        &self,
        native: &ControllerCatalogMaintenanceReceivingV2,
        source: &StartHostCatalogPublicationOriginalV2,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let draft = source
            .draft_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.first.is_some()
            || !native.matches_identity_data_v2(&self.identity)
            || !native.matches_identity_data_v2(source.maintenance_identity_data_v2()?)
            || self.generation != draft.expected_generation()
            || self.catalog_digest != *draft.expected_digest().as_bytes()
            || self.request_digest != outcome.request().signed_request_digest()
            || self.outcome_digest
                != crate::StartHostCatalogNativeCompletionV2::canonical_outcome_digest_data_v2(
                    outcome,
                )
            || !matches!(self.post, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

/// Keeps both offered native receipts if the actual completed stage refuses them.
#[derive(Debug)]
#[doc(hidden)]
pub struct ControllerCatalogMaintenanceCompletionRefusalV2 {
    sent: Option<StorageSeqpacketSendAttemptV1>,
    received: Option<ReceivedRecord>,
}

impl std::fmt::Display for ControllerCatalogMaintenanceCompletionRefusalV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "catalog maintenance native completion refused; original receipts remain owned",
        )
    }
}

impl Error for ControllerCatalogMaintenanceCompletionRefusalV2 {}

impl ControllerCatalogMaintenanceIoLoanV2<'_> {
    /// Consumes only the actual completed stage and real sent/received originals.
    ///
    /// Both receipts park before entry checks. Once the stage is consumed, its
    /// constructor independently runs both cookie checks and its Session post
    /// even when an earlier receipt failed. The caller retains this whole lower
    /// original and the SDK flight until canonical confirmation and all posts.
    ///
    /// # Errors
    /// Preserves offered receipts on entry refusal; retains consumed originals
    /// on the actual owner after a native failure, without a retry or replacement.
    #[doc(hidden)]
    pub fn complete_catalog_native_once_v2(
        &mut self,
        source: &StartHostCatalogPublicationOriginalV2,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        sent: StorageSeqpacketSendAttemptV1,
        received: ReceivedRecord,
    ) -> Result<(), ControllerCatalogMaintenanceCompletionRefusalV2> {
        let mut refused = ControllerCatalogMaintenanceCompletionRefusalV2 {
            sent: Some(sent),
            received: Some(received),
        };
        if self.owner.catalog_io.failure_v2().is_some() {
            self.owner.first.get_or_insert(First::CatalogIo);
            return Err(refused);
        }
        if self.owner.catalog_io.completion_entry.is_some() {
            return Err(refused);
        }
        self.owner.catalog_io.completion_entry = Some((|| {
            self.require_catalog_source_v2(source)?;
            self.require_publication_request_v2(outcome.request())?;
            if self.owner.catalog_io.completion.is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(self.owner.catalog_io.completion_entry, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::CatalogIo);
            return Err(refused);
        }
        self.owner.catalog_io.completion_identity = Some((|| {
            let bank = self
                .owner
                .bank
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            bank.catalog_maintenance_identity_current_v2(
                self.owner
                    .native
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                self.controller,
                self.owner
                    .profile
                    .as_ref()
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
            )
        })());
        if !matches!(self.owner.catalog_io.completion_identity, Some(Ok(_))) {
            self.owner.first.get_or_insert(First::CatalogIo);
            return Err(refused);
        }
        let Some(Ok(identity)) = self.owner.catalog_io.completion_identity.take() else {
            return Err(refused);
        };
        let draft = match source.draft_v2() {
            Ok(draft) => draft,
            Err(_) => return Err(refused),
        };
        let stages = match self
            .io_stages_v2()
            .take_completed_catalog_once_v2(journal, outcome)
        {
            Ok(stages) => stages,
            Err(cause) => {
                self.owner.catalog_io.completion_entry = Some(Err(cause));
                self.owner.first.get_or_insert(First::CatalogIo);
                return Err(refused);
            }
        };
        let mut original = CatalogMaintenanceCatalogNativeCompletionV2 {
            identity,
            generation: draft.expected_generation(),
            catalog_digest: *draft.expected_digest().as_bytes(),
            request_digest: outcome.request().signed_request_digest(),
            outcome_digest:
                crate::StartHostCatalogNativeCompletionV2::canonical_outcome_digest_data_v2(outcome),
            stages: Some(stages),
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
        };
        if let Some(first) = observe_catalog_receipts_retaining_v2(
            socket,
            outcome.canonical_packet(),
            original.sent.as_ref(),
            original.received.as_ref(),
            &mut original.sent_cookie,
            &mut original.received_cookie,
            &mut original.sent_binding,
            &mut original.received_binding,
        ) {
            original.first = Some(match first {
                CatalogReceiptFirstV2::Sent => CompletionFirstV2::Sent,
                CatalogReceiptFirstV2::Received => CompletionFirstV2::Received,
                CatalogReceiptFirstV2::Packet => CompletionFirstV2::Packet,
            });
        }
        // This independent sampler is deliberately outside healthy Source/C.
        original.post = Some(self.require_session_association_v2(journal, socket, transcript));
        if !matches!(original.post, Some(Ok(()))) {
            original.first.get_or_insert(CompletionFirstV2::Post);
        }
        let positive = original.first.is_none();
        self.owner.catalog_io.completion = Some(original);
        if positive {
            Ok(())
        } else {
            self.owner.first.get_or_insert(First::CatalogIo);
            Err(refused)
        }
    }
}

/// Keeps the actual lower owner exclusive through physical SDK prefix disposal.
#[doc(hidden)]
#[must_use = "drop the same successful SDK flight before completing native disposal"]
pub struct ControllerCatalogMaintenanceCatalogDisposalV2<'owner> {
    owner: &'owner mut CatalogMaintenanceCatalogNativeCompletionV2,
    completed: bool,
}

impl ControllerCatalogMaintenanceCatalogDisposalV2<'_> {
    /// Drops the positive native receipts and stage after the same SDK flight.
    pub fn complete_after_disposal_v2(mut self) {
        drop(self.owner.sent.take());
        drop(self.owner.received.take());
        drop(self.owner.stages.take());
        self.owner.disposed = true;
        self.completed = true;
    }
}

impl Drop for ControllerCatalogMaintenanceCatalogDisposalV2<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.first.get_or_insert(CompletionFirstV2::Disposal);
        }
    }
}

impl CatalogMaintenanceOriginalV2 {
    /// Lends positive lower disposal only after real confirmation and all posts.
    ///
    /// The SDK must independently qualify its same opaque completed Session,
    /// then physically drop its actual successful flight before completing the
    /// returned token. This method exposes no generic Session or new IO turn.
    ///
    /// # Errors
    /// Refuses an earlier cause, changed source/receipt, missing actual posts,
    /// failed confirmation, repeated or abandoned physical disposal.
    #[doc(hidden)]
    pub fn prepare_catalog_sdk_disposal_once_v2(
        &mut self,
        controller: &Journal,
        source: &StartHostCatalogPublicationOriginalV2,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<ControllerCatalogMaintenanceCatalogDisposalV2<'_>, ResourceReservationErrorV1> {
        self.require_completed_posts_v2(controller)?;
        source.require_confirmed_native_source_v2(controller)?;
        let native = self
            .native
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let completion = self
            .catalog_io
            .completion
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        completion.require_terminal_v2(native, source, outcome)?;
        if completion.disposal_entered || completion.disposed {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        completion.disposal_entered = true;
        Ok(ControllerCatalogMaintenanceCatalogDisposalV2 {
            owner: completion,
            completed: false,
        })
    }
}

impl CatalogMaintenanceIoOriginalV2 {
    pub(in crate::controller_resource_reservation::catalog_maintenance) fn require_disposed_v2(&self) -> Result<(), ResourceReservationErrorV1> {
        let completion = self
            .completion
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if completion.first.is_some()
            || !completion.disposed
            || !completion.disposal_entered
            || completion.stages.is_some()
            || completion.sent.is_some()
            || completion.received.is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}
