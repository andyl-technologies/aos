//! Publishes a retained baseline suffix original under its single assigned cut.
//!
//! Assignment comes from the Controller's exclusive marker. No generic retry,
//! cached response, replacement sequence or operational deadline reset is used.
//! Provider-origin content/ACK traffic uses the unchanged receive-transfer path.

use super::*;
use crate::connection::ReceivedFrame;
use crate::operational_time::OperationalDeadline;
use std::mem::size_of;

impl ClientSession {
    pub(in crate::client) fn publish_original_restored_suffix_into(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        cut: OperationalDeadline,
        terminal: &mut Option<Envelope>,
        decoded: &mut Option<Box<ResponseBody>>,
    ) -> Result<(), ProviderError> {
        if terminal.is_some() || decoded.is_some() || self.original_response_loss.is_some() {
            return Err(refused());
        }
        self.authenticate_original_ack_admit_cut(original.sequence, cut)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if custody.controller.contains_key(id)
            || custody.controller.len() >= custody.maximum_requests
        {
            return Err(refused());
        }
        let maximum =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        let bytes = envelope_bytes(original)?;
        custody.ensure_journal_room(bytes.checked_add(maximum).ok_or_else(refused)?)?;
        let identity = original.request_hash(RequestOrigin::Controller)?;
        custody.retain_journal_bytes(bytes)?;
        custody.controller.insert(
            id.clone(),
            ClientOriginal {
                request: original.clone(),
                identity,
                response: None,
            },
        );
        self.authenticate_original_ack_admit_cut(original.sequence, cut)?;
        // ClientCustody already owns the exact original before a partial send.
        // The Connection validates the selected baseline method independently.
        self.send(original.clone())?;
        let signed_observation17 = crate::connection::Connection::<DeadlineStream>::is_original_restored_observation17_data(original);
        loop {
            let frame = if signed_observation17 {
                match self
                    .connection
                    .receive_original_restored_observation17_into(original, terminal, decoded)?
                {
                    Some(frame) => frame,
                    None => {
                        // The selected receiver retained this raw terminal before
                        // roster/DTO checks, and its typed owner before guard release.
                        let response = terminal.as_ref().ok_or_else(refused)?;
                        original.matches_response(response)?;
                        custody.retain_journal_bytes(envelope_bytes(response)?)?;
                        custody.controller.get_mut(id).ok_or_else(refused)?.response =
                            Some(response.clone());
                        return Ok(());
                    }
                }
            } else {
                self.connection.receive()?.ok_or_else(refused)?
            };
            match frame.body {
                ReceivedBody::Response(body) => {
                    *terminal = Some(frame.envelope);
                    *decoded = Some(body);
                    let response = terminal.as_ref().ok_or_else(refused)?;
                    original.matches_response(response)?;
                    custody.retain_journal_bytes(envelope_bytes(response)?)?;
                    custody.controller.get_mut(id).ok_or_else(refused)?.response =
                        Some(response.clone());
                    return Ok(());
                }
                ReceivedBody::Request(body) => {
                    self.receive_transfer(custody, frame.envelope, *body)?;
                }
                ReceivedBody::NativeImport18Bootstrap(_) => {
                    return Err(crate::ProviderError::Conflict(
                        "bootstrap18 requires its distinct current owner",
                    ));
                }
                ReceivedBody::Notification(_) => return Err(refused()),
            }
        }
    }

    pub(in crate::client) fn original_restored_observation17_response_counter_scratch_data(
        &self,
    ) -> usize {
        self.connection
            .original_restored_observation17_response_counter_scratch_data()
    }

    pub(in crate::client) const fn original_restored_suffix_counter_scratch_data() -> usize {
        size_of::<(U64, OperationalDeadline)>()
            + size_of::<Result<(U64, OperationalDeadline), ProviderError>>()
            + size_of::<Result<U64, crucible_node_contract::ContractError>>()
            + size_of::<Option<ReceivedFrame>>()
            + size_of::<Result<Option<ReceivedFrame>, ProviderError>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<Option<&mut ClientOriginal>>()
            + size_of::<Result<&mut ClientOriginal, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<crate::connection::ReceivedFrame>()
            + size_of::<crate::connection::ReceivedBody>()
            + size_of::<crate::bodies::RequestBody>()
            + size_of::<crate::bodies::NotificationBody>()
            + size_of::<crate::bodies::ResponseBody>()
            + size_of::<&Envelope>()
            + size_of::<&mut ClientCustody>()
            + size_of::<&mut Option<Envelope>>()
            + size_of::<&mut Option<Box<ResponseBody>>>()
            + size_of::<Option<&Id>>()
            + size_of::<Result<&Id, ProviderError>>()
            + size_of::<ClientOriginal>()
            + size_of::<crucible_node_contract::HashRef>()
            + size_of::<Result<crucible_node_contract::HashRef, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("restored suffix assigned cut or terminal changed")
}
