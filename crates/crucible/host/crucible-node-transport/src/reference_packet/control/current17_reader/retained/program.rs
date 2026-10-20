//! Keeps the concrete model builder beneath the actual current-program variant.

use super::*;

#[derive(Default)]
pub(crate) struct CurrentProgram17ReadAttempt {
    started: bool,
    completed: Option<CurrentProgram17Data>,
    model: <PacketSettledModel17Data as Native17Build>::Attempt,
}

impl Native17Build for CurrentProgram17Data {
    type Attempt = CurrentProgram17ReadAttempt;

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 current Program read already attempted",
            ));
        }
        attempt.started = true;
        if restoration_only(input)? {
            attempt.completed = Some(Self::RestorationInProgress);
        } else {
            PacketSettledModel17Data::read_into_data(input, ledger, &mut attempt.model)?;
            attempt.completed = Some(Self::Model(
                PacketSettledModel17Data::take_output_data(&mut attempt.model)
                    .ok_or_else(invalid)?,
            ));
        }
        Ok(())
    }

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        if restoration_only(input)? {
            Ok(())
        } else {
            PacketSettledModel17Data::preflight_data(input, ledger)
        }
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(completed) = &attempt.completed {
            Self::observe_output_data(completed, observer)?;
        }
        PacketSettledModel17Data::observe_attempt_data(&attempt.model, observer)
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match value {
            Self::Model(model) => model.observe_settled_history_metadata_data(observer),
            Self::RestorationInProgress => Ok(()),
        }
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }
}

fn restoration_only(input: &[u8]) -> Result<bool, ProviderError> {
    let mut fields = Fields::array(input)?;
    let kind = plain_string(fields.next_value()?.ok_or_else(invalid)?)?;
    let body = fields.next_value()?.ok_or_else(invalid)?;
    fields.finish()?;
    if kind == "restoration-in-progress" {
        if body != b"null" {
            return Err(invalid());
        }
        return Ok(true);
    }
    Ok(false)
}
