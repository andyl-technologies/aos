//! Retains exact native Blob DATA fields in the caller's typed attempt.

use super::*;
/// Owns every successfully reconstructed native transfer-key component.
#[derive(Default)]
pub(crate) struct KeyReadAttempt {
    origin: Option<RequestOrigin>,
    completed: Option<TransferKey>,
    session: Option<Id>,
    session_attempt: <Id as Native17Build>::Attempt,
    incarnation: Option<Id>,
    incarnation_attempt: <Id as Native17Build>::Attempt,
    transfer: Option<Id>,
    transfer_attempt: <Id as Native17Build>::Attempt,
}
impl KeyReadAttempt {
    pub(crate) fn read_into_data<'input>(
        &mut self,
        input: &'input [u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<TransferKeyOrder<'input>, ProviderError> {
        let (order, origin, values) = borrowed(input)?;
        self.origin = Some(origin);
        owned::<Id>(
            values[0],
            ledger,
            &mut self.session_attempt,
            &mut self.session,
        )?;
        owned::<Id>(
            values[1],
            ledger,
            &mut self.incarnation_attempt,
            &mut self.incarnation,
        )?;
        owned::<Id>(
            values[2],
            ledger,
            &mut self.transfer_attempt,
            &mut self.transfer,
        )?;
        if self.session.is_none() || self.incarnation.is_none() || self.transfer.is_none() {
            return Err(invalid());
        }
        self.completed = Some(TransferKey {
            origin,
            session: self.session.take().ok_or_else(invalid)?,
            incarnation: self.incarnation.take().ok_or_else(invalid)?,
            transfer: self.transfer.take().ok_or_else(invalid)?,
        });
        Ok(order)
    }
    pub(crate) fn preflight_data<'input>(
        input: &'input [u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<TransferKeyOrder<'input>, ProviderError> {
        let (order, _, values) = borrowed(input)?;
        for value in values {
            Id::preflight_data(value, ledger)?;
        }
        Ok(order)
    }
    pub(crate) fn output_data(&self) -> Option<&TransferKey> {
        self.completed.as_ref()
    }
    pub(crate) fn take_output_data(&mut self) -> Option<TransferKey> {
        self.completed.take()
    }
    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &self.completed {
            observe_key(value, observer)?;
        }
        if let Some(value) = &self.session {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&self.session_attempt, observer)?;
        if let Some(value) = &self.incarnation {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&self.incarnation_attempt, observer)?;
        if let Some(value) = &self.transfer {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&self.transfer_attempt, observer)?;
        Ok(())
    }
}
fn borrowed(
    input: &[u8],
) -> Result<(TransferKeyOrder<'_>, RequestOrigin, [&[u8]; 3]), ProviderError> {
    let mut fields = Fields::array(input)?;
    let (rank, origin) = match plain_string(next(&mut fields)?)? {
        "controller" => (0, RequestOrigin::Controller),
        "provider" => (1, RequestOrigin::Provider),
        _ => return Err(invalid()),
    };
    let values = [next(&mut fields)?, next(&mut fields)?, next(&mut fields)?];
    fields.finish()?;
    let order = (
        rank,
        plain_string(values[0])?,
        plain_string(values[1])?,
        plain_string(values[2])?,
    );
    Ok((order, origin, values))
}
pub(crate) fn observe_key(
    key: &TransferKey,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    Id::observe_output_data(&key.session, observer)?;
    Id::observe_output_data(&key.incarnation, observer)?;
    Id::observe_output_data(&key.transfer, observer)
}
