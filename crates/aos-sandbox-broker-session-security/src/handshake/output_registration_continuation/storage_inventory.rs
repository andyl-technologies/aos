//! Drives only the genuine Create operation's retained Storage Inventory flight.
//!
//! The same shared clientflight signs, installs, sends, authenticates and commits
//! the request. Native owns the sole J payer and joined currentness; this owner
//! retains actual Security/native failures and the successful authenticated
//! outcome/currentness and complete validated model. It cannot send Prepare.

use std::error::Error;
use std::mem::size_of;

use aos_proto::aos::sandbox::local::v1::{InventoryStorageRequest, InventoryStorageResourcesResponse};
use aos_sandbox::{CreateStorageInventoryClosedV1, CreateStorageInventoryShapeDataV1, OriginalCreateStorageInventoryV1};
use aos_sandbox_protocol::{ProtocolValidationError, ValidatedStorageInventory};
use buffa::Message as _;

pub(super) mod wait;

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum NativeSite {
    Fixed,
    Capture,
    Prepare,
    Send,
    Receive,
    Decode,
    Outcome,
    Predecessor,
    Completion,
    Wait,
}

/// Owns the purpose-fixed signed Inventory request and complete terminal custody.
///
/// Empty construction performs no allocation or admission. The actual installed
/// coordinator must retain this owner, its same authenticated Session and the
/// genuine Native borrower through every negative result. Its successful model
/// remains historical authenticated DATA until the later B owner rechecks that
/// exact Session predecessor under its own paid original stage.
#[doc(hidden)]
#[must_use = "retain the actual Inventory flight and same Session through all posts"]
pub struct OriginalStorageInventoryClientFlightV1 {
    shared: OriginalStoragePreparationClientFlightV1,
    wait: wait::InventoryWaitOriginalsV1,
    fixed: Option<Result<(), CreateStorageInventoryClosedV1>>,
    endpoint: Option<Result<(), BrokerSessionSecurityError>>,
    floor: Option<Result<(), BrokerSessionSecurityError>>,
    capture: Option<Result<(), CreateStorageInventoryClosedV1>>,
    preparation: Option<Result<(), CreateStorageInventoryClosedV1>>,
    preparation_post: Option<Result<(), CreateStorageInventoryClosedV1>>,
    unsigned: Option<BrokerRequestEnvelope>,
    send_before: Option<Result<(), CreateStorageInventoryClosedV1>>,
    send_after: Option<Result<(), CreateStorageInventoryClosedV1>>,
    receive_before: Option<Result<(), CreateStorageInventoryClosedV1>>,
    terminal_projection: Option<Result<(), BrokerSessionSecurityError>>,
    validated: Option<Result<(ValidatedStorageInventory, InventoryStorageResourcesResponse), ProtocolValidationError>>,
    canonical_model: Option<Result<(), ProtocolValidationError>>,
    canonical_bytes: Option<Vec<u8>>,
    predecessor_preparation: Option<Result<(), CreateStorageInventoryClosedV1>>,
    predecessor_originals: Option<Box<crate::recovery::OutcomeCurrentOriginalsV1>>,
    predecessor: Option<Result<(), BrokerSessionSecurityError>>,
    completion: Option<Result<(), CreateStorageInventoryClosedV1>>,
    native_failure_site: Option<NativeSite>,
    completed: bool,
}

impl OriginalStorageInventoryClientFlightV1 {
    /// Constructs empty result custody without opening or authorizing a request.
    #[doc(hidden)]
    #[must_use]
    pub fn empty() -> Self {
        Self {
            shared: OriginalStoragePreparationClientFlightV1::empty(),
            wait: wait::InventoryWaitOriginalsV1::<aos_sandbox::CreateStorageInventoryClosedV1>::default(),
            fixed: None,
            endpoint: None,
            floor: None,
            capture: None,
            preparation: None,
            preparation_post: None,
            unsigned: None,
            send_before: None,
            send_after: None,
            receive_before: None,
            terminal_projection: None,
            validated: None,
            canonical_model: None,
            canonical_bytes: None,
            predecessor_preparation: None,
            predecessor_originals: None,
            predecessor: None,
            completion: None,
            native_failure_site: None,
            completed: false,
        }
    }

    fn shape() -> Option<CreateStorageInventoryShapeDataV1> {
        let (replay_bytes, _) = crate::recovery::OutcomeCurrentOriginalsV1::boxed_receiving_footprint_v2()?;
        Some(CreateStorageInventoryShapeDataV1 {
            flight_bytes: size_of::<Self>(),
            inventory_owner_bytes: size_of::<(ValidatedStorageInventory, InventoryStorageResourcesResponse)>(),
            send_original_bytes: size_of::<crate::handshake::StorageResponseSendAttemptV1>(),
            // Result/box headers are in Self. Hostile diagnostic/model backing
            // follows actual captured packet geometry before those decoders.
            predecessor_open_files: crate::recovery::OutcomeCurrentOriginalsV1::retained_endpoint_open_files_v1()?,
            failure_bytes: replay_bytes.checked_add(
                wait::InventoryWaitOriginalsV1::<aos_sandbox::CreateStorageInventoryClosedV1>::receiving_construction_bytes_v1()?)?,
            endpoint_revalidation: crate::endpoint::endpoint_revalidation_footprint_v1()?,
        })
    }

    pub(crate) fn prepare_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> bool {
        if self.fixed.is_some()
            || self.shared.inner.closed
            || self.predecessor_originals.is_some()
        {
            return false;
        }

        let Some(shape) = Self::shape() else {
            self.shared.inner.closed = true;
            return false;
        };
        self.fixed = Some(original.admit_fixed_once(shape));
        if !matches!(self.fixed, Some(Ok(()))) {
            self.mark_native(NativeSite::Fixed);
            return false;
        }
        let prepared = original.require_fixed_endpoint_preparation_v1(shape);
        if prepared.is_err() {
            self.fixed = Some(prepared);
            self.mark_native(NativeSite::Fixed);
            return false;
        }

        // The same fixed entry includes this distinct terminal predecessor's
        // backing and construction before any Session capture can fail.
        self.predecessor_originals = Some(Box::new(Default::default()));

        self.capture = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.capture_session_once(journal, &session.socket, &session.transcript),
            Err(cause) => {
                self.shared.inner.protected_failure = Some(cause);
                Err(CreateStorageInventoryClosedV1)
            }
        });
        if !matches!(self.capture, Some(Ok(()))) {
            self.mark_native(NativeSite::Capture);
            return false;
        }
        // The same already-paid archive belongs to this endpoint across Client,
        // Inventory and Prepare. Health checking neither allocates nor resets it.
        self.endpoint = Some(session.owner.require_original_storage_revalidation_healthy());
        if !matches!(self.endpoint, Some(Ok(()))) {
            self.shared.inner.closed = true;
            return false;
        }
        // The sidecar's separate archive was genuinely admitted by Client.
        // Inventory verifies health on the SAME held owner; it never arms it.
        self.floor = Some(if session.owner.healthy_original_storage_floor_revalidation_v1() {
            Ok(())
        } else { Err(BrokerSessionSecurityError::Currentness) });
        if !matches!(self.floor, Some(Ok(()))) {
            self.shared.inner.closed = true;
            return false;
        }
        self.preparation = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.begin_request_preparation_once(journal, &session.socket, &session.transcript),
            Err(cause) => {
                self.shared.inner.protected_failure = Some(cause);
                Err(CreateStorageInventoryClosedV1)
            }
        });
        let constructed = if matches!(self.preparation, Some(Ok(()))) {
            self.shared.inner.coordinates = Some((|| {
                let cutoff = original.original_cutoff_data_v1()
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                crate::dormant_handshake::original_create_storage_inventory_coordinates_v1(session, cutoff)
            })());
            if let Some(Ok(coordinates)) = self.shared.inner.coordinates.as_ref() {
                self.unsigned = Some(BrokerRequestEnvelope {
                    method: BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES.into(),
                    body: InventoryStorageRequest {
                        header: Some(coordinates.request_header()).into(),
                        ..Default::default()
                    }.encode_to_vec(),
                    ..Default::default()
                });
                // The original unsigned proposal stays resident if signing or
                // installing its canonical request fails in the shared engine.
                match self.unsigned.as_ref() {
                    Some(unsigned) => self.shared.inner.prepare(session, unsigned.clone()),
                    None => false,
                }
            } else { false }
        } else { self.mark_native(NativeSite::Prepare); false };
        self.preparation_post = Some(self.observe_post(session, original));
        if !matches!(self.preparation_post, Some(Ok(()))) { self.mark_native(NativeSite::Prepare); }
        if !constructed || !matches!(self.preparation_post, Some(Ok(()))) {
            self.shared.inner.closed = true;
            return false;
        }
        if original.finish_positive_io_once().is_err() {
            self.mark_native(NativeSite::Prepare);
            return false;
        }
        true
    }

    pub(crate) fn send_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> StoragePreparationClientProgressV1 {
        match super::storage_io::send_once(&mut self.shared, &mut self.wait,
            &mut self.send_before, &mut self.send_after, session, original) {
            Ok(progress) => progress,
            Err(super::storage_io::StorageIoFailureV1::Native) => {
                self.mark_native(NativeSite::Send);
                StoragePreparationClientProgressV1::Closed
            }
            Err(super::storage_io::StorageIoFailureV1::Wait) => {
                self.mark_native(NativeSite::Wait);
                StoragePreparationClientProgressV1::Closed
            }
            Err(super::storage_io::StorageIoFailureV1::Shared) => {
                self.shared.inner.closed = true;
                StoragePreparationClientProgressV1::Closed
            }
        }
    }

    pub(crate) fn receive_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> StoragePreparationClientProgressV1 {
        if self.shared.inner.closed || self.shared.pending.is_some() || self.wait.is_pending()
            || !matches!(self.shared.inner.sent, Some(Ok(()))) { return StoragePreparationClientProgressV1::Closed; }
        self.receive_before = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.begin_receive_once(journal, &session.socket, &session.transcript),
            Err(cause) => {
                self.shared.inner.protected_failure = Some(cause);
                Err(CreateStorageInventoryClosedV1)
            }
        });
        if !matches!(self.receive_before, Some(Ok(()))) {
            self.mark_native(NativeSite::Receive);
            let _ = self.observe_post(session, original);
            return StoragePreparationClientProgressV1::Closed;
        }
        let committed = self.shared.inner.receive_terminal_with_storage_io_v1(session, Some(original));
        if !committed && !self.shared.inner.closed && self.shared.inner.terminal_packet.is_nonconsuming_v1() {
            let Some(Err(receipt)) = self.shared.inner.terminal_packet.received.as_ref() else {
                self.shared.inner.closed = true; return StoragePreparationClientProgressV1::Closed;
            };
            let Ok(disposal) = original.prepare_pending_receive_disposal_once(receipt) else {
                self.mark_native(NativeSite::Receive); return StoragePreparationClientProgressV1::Closed;
            };
            // The no-sample predicate guarantees every other native slot is
            // empty. Retire the actual whole failed packet, never a clone.
            let old = std::mem::replace(&mut self.shared.inner.terminal_packet, OriginalOutputPacketV1::empty());
            drop(old);
            disposal.complete_after_receipt_disposal();
            self.shared.inner.inventory_io_post = None;
            self.receive_before = None;
            if !self.wait.arm_receive() {
                self.mark_native(NativeSite::Wait);
                return StoragePreparationClientProgressV1::Closed;
            }
            return StoragePreparationClientProgressV1::Pending;
        }
        if !committed {
            if self.shared.inner.inventory_decode.as_ref().is_some_and(Result::is_err) { self.mark_native(NativeSite::Decode); }
            else if self.shared.inner.inventory_outcome.as_ref().is_some_and(Result::is_err) { self.mark_native(NativeSite::Outcome); }
            self.finish_terminal_post(session, original);
            return StoragePreparationClientProgressV1::Closed;
        }
        self.predecessor_preparation = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.admit_retained_predecessor_once(journal),
            Err(cause) => {
                self.shared.inner.protected_failure.get_or_insert(cause);
                Err(CreateStorageInventoryClosedV1)
            }
        });
        if !matches!(self.predecessor_preparation, Some(Ok(()))) {
            self.mark_native(NativeSite::Predecessor);
            self.finish_terminal_post(session, original);
            return StoragePreparationClientProgressV1::Closed;
        }
        let terminal = match self.shared.inner.committed.as_ref() {
            Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) => terminal,
            _ => { self.shared.inner.closed = true; self.finish_terminal_post(session, original); return StoragePreparationClientProgressV1::Closed; }
        };
        self.terminal_projection = Some(terminal.storage_inventory_client_originals_v1().map(|_| ()));
        if let Ok((outcome, currentness)) = terminal.storage_inventory_client_originals_v1() {
            self.validated = Some(match outcome.result() {
                aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } =>
                    aos_sandbox_protocol::decode_storage_resource_inventory_response_with_model(exact_body,
                        outcome.request().maximum_response_bytes()),
                _ => Err(ProtocolValidationError::InvalidField("successful Storage Inventory")),
            });
            if let Some(Ok((_, model))) = self.validated.as_ref() {
                // Retain the actual canonical output before a later byte
                // mismatch or Native post; do not reconstruct it on failure.
                self.canonical_bytes = Some(model.encode_to_vec());
                self.canonical_model = Some(match outcome.result() {
                    aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. }
                        if self.canonical_bytes.as_deref() == Some(exact_body.as_slice()) => Ok(()),
                    _ => Err(ProtocolValidationError::InvalidField("canonical Storage Inventory")),
                });
            }
            self.predecessor = Some(
                self.predecessor_originals
                    .as_deref_mut()
                    .ok_or(BrokerSessionSecurityError::Currentness)
                    .and_then(|originals| session.owner
                        .compare_atomic_snapshot_predecessor_retaining_v1(
                            currentness, session.socket.peer(), originals,
                        )),
            );
        }
        self.finish_terminal_post(session, original);
        if !matches!(self.terminal_projection, Some(Ok(()))) || !matches!(self.validated, Some(Ok(_)))
            || !matches!(self.canonical_model, Some(Ok(()))) || !matches!(self.predecessor, Some(Ok(())))
            || !matches!(self.completion, Some(Ok(()))) {
            self.shared.inner.closed = true;
            return StoragePreparationClientProgressV1::Closed;
        }
        self.completed = true;
        StoragePreparationClientProgressV1::Committed
    }

    fn finish_terminal_post(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) {
        self.completion = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.observe_terminal_post_once(journal, &session.socket, &session.transcript),
            Err(cause) => { self.shared.inner.protected_failure.get_or_insert(cause); Err(CreateStorageInventoryClosedV1) }
        });
        if !matches!(self.completion, Some(Ok(()))) {
            self.mark_native(NativeSite::Completion);
            return;
        }
        if !self.shared.inner.closed && matches!(self.terminal_projection, Some(Ok(())))
            && self.validated.as_ref().is_some_and(Result::is_ok)
            && matches!(self.canonical_model, Some(Ok(())))
            && matches!(self.predecessor, Some(Ok(()))) {
            self.completion = Some(match session.owner.retained_storage_client_journal_v1() {
                Ok(journal) => original.finish_after_authenticated_inventory_once(journal, &session.socket, &session.transcript),
                Err(cause) => {
                    self.shared.inner.protected_failure.get_or_insert(cause);
                    Err(CreateStorageInventoryClosedV1)
                }
            });
            if !matches!(self.completion, Some(Ok(()))) { self.mark_native(NativeSite::Completion); }
        }
    }

    fn observe_post(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> Result<(), CreateStorageInventoryClosedV1> {
        match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.observe_io_post_once(journal, &session.socket, &session.transcript),
            Err(cause) => {
                self.shared.inner.protected_failure.get_or_insert(cause);
                Err(CreateStorageInventoryClosedV1)
            }
        }
    }

    fn mark_native(&mut self, site: NativeSite) {
        self.native_failure_site.get_or_insert(site);
        self.shared.inner.closed = true;
    }

    /// Borrows the actual validated model beside its signed terminal owner.
    ///
    /// This historical view creates no currentness or Prepare grant. The later
    /// paid B cut must recheck the same authenticated predecessor and originals.
    #[doc(hidden)]
    #[must_use]
    pub fn validated_inventory(&self) -> Option<&ValidatedStorageInventory> {
        if !self.completed {
            return None;
        }
        self.validated.as_ref()?.as_ref().ok().map(|(validated, _)| validated)
    }

    /// Borrows the complete original committed terminal without moving custody.
    #[doc(hidden)]
    #[must_use]
    pub fn committed(&self) -> Option<&crate::ProtectedBrokerOutcomeCommitResultV1> {
        self.shared.inner.committed()
    }
}

impl OriginalStorageInventoryClientFlightV1 {
    pub(crate) fn failure_with_original<'a>(
        &'a self, session: &'a DormantAuthenticatedBrokerSessionV1,
        original: &'a OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> Option<&'a (dyn Error + 'static)> {
        self.failure_with_native(session, original.failure())
    }

    pub(crate) fn failure_with_native<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
        native: Option<&'a (dyn Error + 'static)>,
    ) -> Option<&'a (dyn Error + 'static)> {
        // Upper primary request/native/crypto failures precede their independent
        // Native posts. Native admission/decoder refusals occur before any later
        // upper primary can run, so their rich owner remains next in this order.
        self.endpoint.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &dyn Error)
            .or_else(|| self.floor.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.shared.inner.failure_with_session(session))
            .or_else(|| self.terminal_projection.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.validated.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.canonical_model.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.predecessor_preparation.as_ref().filter(|result| result.is_err())
                .and_then(|_| native))
            .or_else(|| self.predecessor_originals
                .as_deref()
                .and_then(|originals| originals.failure()))
            .or_else(|| self.predecessor.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.shared.inner.postcheck_debt_with_session(session).map(|cause| {
                if let Some(returned) = cause.downcast_ref::<BrokerSessionSecurityError>() {
                    session.owner.retained_revalidation_failure_for(returned)
                        .or_else(|| session.owner.retained_storage_floor_revalidation_failure_for(returned))
                        .unwrap_or(cause)
                } else { cause }
            }))
            .or_else(|| self.wait.failure_with_native(native))
            .or_else(|| self.native_failure_site.and_then(|_| native))
            .or_else(|| self.shared.inner.closed.then_some(&OutputPreparationClosedV1 as &(dyn Error + 'static)))
    }
}


impl OriginalStorageInventoryClientFlightV1 {
    // These borrowed originals are available only beside the successful signed
    // terminal. The B owner pays and runs its own fresh predecessor checks.
    pub(super) fn bundle_model_v1(&self)
        -> Result<&InventoryStorageResourcesResponse, BrokerSessionSecurityError>
    {
        if !self.completed || self.shared.inner.closed {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validated.as_ref().and_then(|value| value.as_ref().ok())
            .map(|(_, model)| model).ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn bundle_request_v1(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.bundle_model_v1()?;
        self.shared.inner.request().map(|request| request.canonical_packet())
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn bundle_response_v1(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.bundle_model_v1()?;
        self.shared.inner.terminal_packet.payload().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn compare_bundle_predecessor_v1(&self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        originals: &mut crate::recovery::OutcomeCurrentOriginalsV1)
        -> Result<(), BrokerSessionSecurityError>
    {
        self.bundle_model_v1()?;
        let terminal = match self.shared.inner.committed.as_ref() {
            Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) => terminal,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        let (_, currentness) = terminal.storage_inventory_client_originals_v1()?;
        session.owner.compare_atomic_snapshot_predecessor_retaining_v1(
            currentness, session.socket.peer(), originals,
        )
    }
}
