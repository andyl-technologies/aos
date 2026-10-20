//! Preserves the actual Catalog17 native stage for the closed completion owner.
//!
//! No public response, phase flag or hash tuple constructs a completed stage.
//! The same held native journal row and independently owed post are mandatory.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

impl StorageIoStagesV1 {
    pub(in crate::controller_resource_reservation) fn take_completed_catalog_once_v2(
        &mut self,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let stage = &self.apply;
        if self.active != Some(false)
            || stage.phase != IoPhaseV1::Complete
            || self.failure().is_some()
            || !matches!(stage.terminal_native, Some(Ok(_)))
            || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
            || outcome.request().session_binding() != stage.binding
            || stage.terminal_identity
                != Some((
                    outcome.request().signed_request_digest(),
                    *blake3::hash(outcome.canonical_packet()).as_bytes(),
                ))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let key = stage
            .native_key
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let raw = journal
            .get(crate::RecordNamespace::BrokerSessionTraffic, key)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if stage
            .native_position
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            != Some(*blake3::hash(raw).as_bytes())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(std::mem::take(self))
    }
}

impl StorageIoStagesV1 {
    pub(in crate::controller_resource_reservation) fn completed_catalog_extent_v2(
        &self,
    ) -> Result<&ProtectedJournalPreopenReplayExtentV1, ResourceReservationErrorV1> {
        if self.active != Some(false)
            || self.apply.phase != IoPhaseV1::Complete
            || self.failure().is_some()
            || !matches!(self.apply.terminal_native, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let extent = self
            .apply
            .predecessor_extent
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let position = self
            .apply
            .terminal_native
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = u64::from_be_bytes(
            position[56..64]
                .try_into()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?,
        );
        if extent.native_bytes != bytes {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(extent)
    }
}


#[derive(Clone, Copy)]
pub(in crate::controller_resource_reservation) enum CatalogReceiptFirstV2 { Sent, Received, Packet }

// Both genuine native catalog constructors reach this SAME two-cookie recipe.
// A first receipt failure never suppresses the independent received check;
// each caller separately owes its own actual Session/native terminal post.
pub(in crate::controller_resource_reservation) fn observe_catalog_receipts_retaining_v2(
    socket: &SeqpacketSocket,
    outcome_packet: &[u8],
    sent: Option<&aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>,
    received: Option<&aos_sandbox_linux::seqpacket::ReceivedRecord>,
    sent_cookie: &mut Option<Result<u64, aos_sandbox_linux::Error>>,
    received_cookie: &mut Option<Result<u64, aos_sandbox_linux::Error>>,
    sent_binding: &mut Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
    received_binding: &mut Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
) -> Option<CatalogReceiptFirstV2> {
    let mut first = None;
    *sent_binding = sent.map(|sent| sent.require_same_socket_retaining_v4(socket, sent_cookie));
    if !matches!(sent_binding, Some(Ok(()))) || !sent.is_some_and(|sent| sent.is_sent()) {
        first = Some(CatalogReceiptFirstV2::Sent);
    }
    *received_binding = received.map(|received| {
        socket.compare_storage_preparation_received_original_retaining_v4(received, received_cookie)
    });
    if !matches!(received_binding, Some(Ok(()))) {
        first.get_or_insert(CatalogReceiptFirstV2::Received);
    }
    if received.is_none_or(|received| received.payload() != outcome_packet) {
        first.get_or_insert(CatalogReceiptFirstV2::Packet);
    }
    first
}
