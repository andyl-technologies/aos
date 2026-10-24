//! Retains the exact activation terminal before selected Source postchecks.

use super::*;

impl ClientSession {
    pub(in crate::client) fn reserve_original_installed_restoration_activation(
        &mut self,
        original: &Envelope,
        maximum: usize,
        result: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        self.connection
            .reserve_original_assigned_installed_restoration_activation(original, maximum, result)
    }

    pub(in crate::client) fn publish_original_installed_restoration_activation(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
        cut: crate::operational_time::OperationalDeadline,
    ) -> Result<Envelope, ProviderError> {
        self.authenticate_original_ack_admit_cut(original.sequence, cut)?;
        self.connection
            .publish_original_assigned_installed_restoration_activation(original, bytes, slot)?;
        self.sequence = self.sequence.checked_add(U64::new(1))?;
        loop {
            let frame = self.connection.receive()?.ok_or_else(refused)?;
            match frame.body {
                ReceivedBody::Response(_) => {
                    original.matches_response(&frame.envelope)?;
                    custody.retain_journal_bytes(envelope_bytes(&frame.envelope)?)?;
                    let id = original.request_id.0.as_ref().ok_or_else(refused)?;
                    let retained = custody.controller.get_mut(id).ok_or_else(refused)?;
                    retained.response = Some(frame.envelope.clone());
                    return Ok(frame.envelope);
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
    ProviderError::Correlation("original installed activation terminal missing or changed")
}
