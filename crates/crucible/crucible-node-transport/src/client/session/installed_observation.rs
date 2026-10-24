//! Retains the exact observation terminal before selected Source postchecks.

use super::*;
use crate::connection::ReceivedFrame;

impl ClientSession {
    /// Names the actual cut, checked sequence and receive-return views.
    pub(in crate::client) const fn original_installed_restoration_observation_counter_scratch_data()
    -> usize {
        use std::mem::size_of;
        size_of::<(U64, crate::operational_time::OperationalDeadline)>()
            + size_of::<Result<(U64, crate::operational_time::OperationalDeadline), ProviderError>>(
            )
            + size_of::<Result<U64, crucible_node_format::ContractError>>()
            + size_of::<Option<ReceivedFrame>>()
            + size_of::<Result<Option<ReceivedFrame>, ProviderError>>()
    }

    pub(in crate::client) fn reserve_original_installed_restoration_observation(
        &mut self,
        original: &Envelope,
        maximum: usize,
        result: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        self.connection
            .reserve_original_assigned_installed_restoration_observation(original, maximum, result)
    }

    pub(in crate::client) fn publish_original_installed_restoration_observation(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
        cut: crate::operational_time::OperationalDeadline,
        terminal: &mut Option<Envelope>,
        decoded: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        if terminal.is_some() || decoded.is_some() {
            return Err(refused());
        }
        self.authenticate_original_ack_admit_cut(original.sequence, cut)?;
        self.connection
            .publish_original_assigned_installed_restoration_observation(original, bytes, slot)?;
        self.sequence = self.sequence.checked_add(U64::new(1))?;
        loop {
            let frame = self.connection.receive()?.ok_or_else(refused)?;
            match frame.body {
                ReceivedBody::Response(body) => {
                    // Both actual outputs precede every fallible correspondence,
                    // journal/canonical credit and Source/native evidence check.
                    *terminal = Some(frame.envelope);
                    *decoded = Some(*body);
                    let response = terminal.as_ref().ok_or_else(refused)?;
                    original.matches_response(response)?;
                    custody.retain_journal_bytes(envelope_bytes(response)?)?;
                    let id = original.request_id.0.as_ref().ok_or_else(refused)?;
                    let retained = custody.controller.get_mut(id).ok_or_else(refused)?;
                    retained.response = Some(response.clone());
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
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original installed observation terminal missing or changed")
}

impl ClientSession {
    pub(in crate::client) fn ensure_original_observation_receiver_idle_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.connection
            .ensure_original_observation_receiver_idle_data()
    }
}
