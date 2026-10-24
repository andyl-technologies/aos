//! Retains concrete model fields and pending typed children through every error.
//!
//! Attempt headers are inline in the caller's once owner. Child preflight funds
//! only the backing each real child builder allocates; no source-row credit is
//! treated as storage for these headers. Completed fields move only after the
//! final grammar check, and semantic checks run while the output remains owned.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::reference_packet::connected::continuation::settled_reader::retained::ReactiveModel17ReadAttempt;
use crate::retained_metadata::MetadataObserver;

/// Retains the concrete program child and its completed transparent wrapper.
#[derive(Default)]
pub(crate) struct ReactiveProgram17ReadAttempt {
    started: bool,
    completed: Option<ReactiveProgram17Data>,
    model: ReactiveModel17ReadAttempt,
}

impl Native17Build for ReactiveProgram17Data {
    type Attempt = ReactiveProgram17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 program wrapper already attempted",
            ));
        }
        attempt.started = true;
        attempt.model.read_fields_into_data(input, ledger, true)?;
        attempt.completed = Some(Self(attempt.model.take_output_data().ok_or_else(invalid)?));
        Ok(())
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        ReactiveModel17ReadAttempt::preflight_fields_data(input, ledger, true)
    }
    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }
    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &attempt.completed {
            observer.observe(value)?;
        }
        attempt.model.observe_attempt_data(observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(value)
    }
}

// Companions follow the exact existing object-field grammars above.
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(ReactiveAdoption17Data {
    snapshot: Option<ModelRecord>,
    effect_socket_role: Option<SocketRole>,
    state: Option<ReactiveModel17Data>,
    reactions: Vec<PacketReaction>,
    delivered_inputs: Vec<PacketDeliveredInput>,
    publications: Vec<PacketPendingPublication>,
    outputs: Vec<PacketConnectedPublication>,
    stages: Vec<OriginalStage>,
    completed: Option<ReactiveProgram17Data>,
    ready: bool,
});
