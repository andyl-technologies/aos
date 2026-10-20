//! Retains concrete model fields and pending typed children through every error.
//!
//! Attempt headers are inline in the caller's once owner. Child preflight funds
//! only the backing each real child builder allocates; no source-row credit is
//! treated as storage for these headers. Completed fields move only after the
//! final grammar check, and semantic checks run while the output remains owned.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::reference_packet::continuation_models::settled_reader::retained::ProducerModel17ReadAttempt;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};

/// Retains the concrete program child and its completed transparent wrapper.
#[derive(Default)]
pub(crate) struct ProducerProgram17ReadAttempt {
    started: bool,
    completed: Option<ProducerProgram17Data>,
    model: ProducerModel17ReadAttempt,
}

impl Native17Build for ProducerProgram17Data {
    type Attempt = ProducerProgram17ReadAttempt;
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
        ProducerModel17ReadAttempt::preflight_fields_data(input, ledger, true)
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

use crate::reference_packet::continuation_models::settled_reader::retained::atomic_model_leaf;
atomic_model_leaf!(SocketRole);
atomic_model_leaf!(ThreadRole);
atomic_model_leaf!(HoldRole);
atomic_model_leaf!(PreparedSchema);
atomic_model_leaf!(PacketModelKind);

/// Retains either real historical program branch without a live Program value.
#[derive(Default)]
pub(crate) struct OriginalProgram17ReadAttempt {
    started: bool,
    completed: Option<OriginalProgram17Data>,
    producer: <ProducerProgram17Data as Native17Build>::Attempt,
    reactive: <ReactiveProgram17Data as Native17Build>::Attempt,
}

impl Native17Build for OriginalProgram17Data {
    type Attempt = OriginalProgram17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 original program already attempted",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        let kind = plain_string(fields.named("kind")?)?;
        let data = fields.named("data")?;
        match kind {
            "producer" => {
                ProducerProgram17Data::read_into_data(data, ledger, &mut attempt.producer)?;
                fields.finish()?;
                attempt.completed = Some(Self::Producer(
                    ProducerProgram17Data::take_output_data(&mut attempt.producer)
                        .ok_or_else(invalid)?,
                ));
            }
            "reactive" => {
                ReactiveProgram17Data::read_into_data(data, ledger, &mut attempt.reactive)?;
                fields.finish()?;
                attempt.completed = Some(Self::Reactive(
                    ReactiveProgram17Data::take_output_data(&mut attempt.reactive)
                        .ok_or_else(invalid)?,
                ));
            }
            "restoration_in_progress" if data == b"null" => {
                fields.finish()?;
                attempt.completed = Some(Self::RestorationInProgress);
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut fields = Fields::object(input)?;
        let kind = plain_string(fields.named("kind")?)?;
        let data = fields.named("data")?;
        match kind {
            "producer" => ProducerProgram17Data::preflight_data(data, ledger)?,
            "reactive" => ReactiveProgram17Data::preflight_data(data, ledger)?,
            "restoration_in_progress" if data == b"null" => (),
            _ => return Err(invalid()),
        }
        fields.finish()
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
        ProducerProgram17Data::observe_attempt_data(&attempt.producer, observer)?;
        ReactiveProgram17Data::observe_attempt_data(&attempt.reactive, observer)
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

native17_struct!(ModelCapacities {
    events: usize,
    reactions: usize,
    delivered_inputs: usize,
    publications: usize,
    outputs: usize,
    stages: usize,
});

native17_struct!(ModelRecord {
    schema: String,
    kind: PacketModelKind,
    captured_process: U64,
    configuration: ContentRef,
    cut: Position,
    capacities: ModelCapacities,
    state: serde_json::Value,
});

native17_struct!(ProducerAdoption17Data {
    snapshot: Option<ModelRecord>,
    effect_socket_role: Option<SocketRole>,
    state: Option<ProducerState>,
    events: Vec<PacketEvent>,
    outputs: Vec<PacketPublication>,
    completed: Option<ProducerProgram17Data>,
    ready: bool,
});
