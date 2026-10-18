//! Retains concrete model fields and pending typed children through every error.
//!
//! Attempt headers are inline in the caller's once owner. Child preflight funds
//! only the backing each real child builder allocates; no source-row credit is
//! treated as storage for these headers. Completed fields move only after the
//! final grammar check, and semantic checks run while the output remains owned.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};
/// Owns the completed model and each unfinished defining child.
#[derive(Default)]
pub(crate) struct ProducerModel17ReadAttempt {
    started: bool,
    completed: Option<ProducerState>,
    events: Option<Vec<PacketEvent>>,
    events_attempt: <Vec<PacketEvent> as Native17Build>::Attempt,
    next_event: Option<usize>,
    next_event_attempt: <usize as Native17Build>::Attempt,
    reached: Option<Position>,
    reached_attempt: <Position as Native17Build>::Attempt,
    gate_closed: Option<bool>,
    gate_closed_attempt: <bool as Native17Build>::Attempt,
    outputs: Option<Vec<PacketPublication>>,
    outputs_attempt: <Vec<PacketPublication> as Native17Build>::Attempt,
    grants: Option<BTreeMap<Id, PacketGrant>>,
    grants_attempt: <BTreeMap<Id, PacketGrant> as Native17Build>::Attempt,
    private_mutations: Option<u64>,
    private_mutations_attempt: <u64 as Native17Build>::Attempt,
    packet_effects: Option<u64>,
    packet_effects_attempt: <u64 as Native17Build>::Attempt,
    retired: Option<BTreeMap<Id, Vec<Id>>>,
    retired_attempt: <BTreeMap<Id, Vec<Id>> as Native17Build>::Attempt,
    failed: Option<bool>,
    failed_attempt: <bool as Native17Build>::Attempt,
}

impl ProducerModel17ReadAttempt {
    pub(super) fn read_fields_into_data(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        program: bool,
    ) -> Result<(), ProviderError> {
        if self.started {
            return Err(ProviderError::Conflict(
                "native17 model read already attempted",
            ));
        }
        self.started = true;
        let mut fields = Fields::object(input)?;
        if program && plain_string(fields.named("effect_socket_role")?)? != "model-effect-socket" {
            return Err(invalid());
        }
        read_owned::<Vec<PacketEvent>>(
            fields.named("events")?,
            ledger,
            &mut self.events_attempt,
            &mut self.events,
        )?;
        read_owned::<usize>(
            fields.named("next_event")?,
            ledger,
            &mut self.next_event_attempt,
            &mut self.next_event,
        )?;
        read_owned::<Position>(
            fields.named("reached")?,
            ledger,
            &mut self.reached_attempt,
            &mut self.reached,
        )?;
        read_owned::<bool>(
            fields.named("gate_closed")?,
            ledger,
            &mut self.gate_closed_attempt,
            &mut self.gate_closed,
        )?;
        read_owned::<Vec<PacketPublication>>(
            fields.named("outputs")?,
            ledger,
            &mut self.outputs_attempt,
            &mut self.outputs,
        )?;
        read_owned::<BTreeMap<Id, PacketGrant>>(
            fields.named("grants")?,
            ledger,
            &mut self.grants_attempt,
            &mut self.grants,
        )?;
        read_owned::<u64>(
            fields.named("private_mutations")?,
            ledger,
            &mut self.private_mutations_attempt,
            &mut self.private_mutations,
        )?;
        read_owned::<u64>(
            fields.named("packet_effects")?,
            ledger,
            &mut self.packet_effects_attempt,
            &mut self.packet_effects,
        )?;
        read_owned::<BTreeMap<Id, Vec<Id>>>(
            fields.named("retired")?,
            ledger,
            &mut self.retired_attempt,
            &mut self.retired,
        )?;
        read_owned::<bool>(
            fields.named("failed")?,
            ledger,
            &mut self.failed_attempt,
            &mut self.failed,
        )?;
        fields.finish()?;

        // Check every slot before moving any child out of this retained owner.
        if self.events.is_none()
            || self.next_event.is_none()
            || self.reached.is_none()
            || self.gate_closed.is_none()
            || self.outputs.is_none()
            || self.grants.is_none()
            || self.private_mutations.is_none()
            || self.packet_effects.is_none()
            || self.retired.is_none()
            || self.failed.is_none()
        {
            return Err(invalid());
        }
        self.completed = Some(ProducerState {
            events: self.events.take().ok_or_else(invalid)?,
            next_event: self.next_event.take().ok_or_else(invalid)?,
            reached: self.reached.take().ok_or_else(invalid)?,
            gate_closed: self.gate_closed.take().ok_or_else(invalid)?,
            outputs: self.outputs.take().ok_or_else(invalid)?,
            grants: self.grants.take().ok_or_else(invalid)?,
            private_mutations: self.private_mutations.take().ok_or_else(invalid)?,
            packet_effects: self.packet_effects.take().ok_or_else(invalid)?,
            retired: self.retired.take().ok_or_else(invalid)?,
            failed: self.failed.take().ok_or_else(invalid)?,
        });
        Ok(())
    }

    pub(super) fn preflight_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        program: bool,
    ) -> Result<(), ProviderError> {
        let mut fields = Fields::object(input)?;
        if program && plain_string(fields.named("effect_socket_role")?)? != "model-effect-socket" {
            return Err(invalid());
        }
        <Vec<PacketEvent> as Native17Build>::preflight_data(fields.named("events")?, ledger)?;
        <usize as Native17Build>::preflight_data(fields.named("next_event")?, ledger)?;
        <Position as Native17Build>::preflight_data(fields.named("reached")?, ledger)?;
        <bool as Native17Build>::preflight_data(fields.named("gate_closed")?, ledger)?;
        <Vec<PacketPublication> as Native17Build>::preflight_data(
            fields.named("outputs")?,
            ledger,
        )?;
        <BTreeMap<Id, PacketGrant> as Native17Build>::preflight_data(
            fields.named("grants")?,
            ledger,
        )?;
        <u64 as Native17Build>::preflight_data(fields.named("private_mutations")?, ledger)?;
        <u64 as Native17Build>::preflight_data(fields.named("packet_effects")?, ledger)?;
        <BTreeMap<Id, Vec<Id>> as Native17Build>::preflight_data(fields.named("retired")?, ledger)?;
        <bool as Native17Build>::preflight_data(fields.named("failed")?, ledger)?;
        fields.finish()
    }

    pub(super) fn output_data(&self) -> Option<&ProducerState> {
        self.completed.as_ref()
    }
    pub(super) fn take_output_data(&mut self) -> Option<ProducerState> {
        self.completed.take()
    }

    pub(super) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &self.completed {
            observer.observe(value)?;
        }
        if let Some(value) = &self.events {
            <Vec<PacketEvent> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Vec<PacketEvent> as Native17Build>::observe_attempt_data(&self.events_attempt, observer)?;
        if let Some(value) = &self.next_event {
            <usize as Native17Build>::observe_output_data(value, observer)?;
        }
        <usize as Native17Build>::observe_attempt_data(&self.next_event_attempt, observer)?;
        if let Some(value) = &self.reached {
            <Position as Native17Build>::observe_output_data(value, observer)?;
        }
        <Position as Native17Build>::observe_attempt_data(&self.reached_attempt, observer)?;
        if let Some(value) = &self.gate_closed {
            <bool as Native17Build>::observe_output_data(value, observer)?;
        }
        <bool as Native17Build>::observe_attempt_data(&self.gate_closed_attempt, observer)?;
        if let Some(value) = &self.outputs {
            <Vec<PacketPublication> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Vec<PacketPublication> as Native17Build>::observe_attempt_data(
            &self.outputs_attempt,
            observer,
        )?;
        if let Some(value) = &self.grants {
            <BTreeMap<Id, PacketGrant> as Native17Build>::observe_output_data(value, observer)?;
        }
        <BTreeMap<Id, PacketGrant> as Native17Build>::observe_attempt_data(
            &self.grants_attempt,
            observer,
        )?;
        if let Some(value) = &self.private_mutations {
            <u64 as Native17Build>::observe_output_data(value, observer)?;
        }
        <u64 as Native17Build>::observe_attempt_data(&self.private_mutations_attempt, observer)?;
        if let Some(value) = &self.packet_effects {
            <u64 as Native17Build>::observe_output_data(value, observer)?;
        }
        <u64 as Native17Build>::observe_attempt_data(&self.packet_effects_attempt, observer)?;
        if let Some(value) = &self.retired {
            <BTreeMap<Id, Vec<Id>> as Native17Build>::observe_output_data(value, observer)?;
        }
        <BTreeMap<Id, Vec<Id>> as Native17Build>::observe_attempt_data(
            &self.retired_attempt,
            observer,
        )?;
        if let Some(value) = &self.failed {
            <bool as Native17Build>::observe_output_data(value, observer)?;
        }
        <bool as Native17Build>::observe_attempt_data(&self.failed_attempt, observer)?;
        Ok(())
    }
}

impl Native17Build for ProducerState {
    type Attempt = ProducerModel17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        attempt.read_fields_into_data(input, ledger, false)
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        ProducerModel17ReadAttempt::preflight_fields_data(input, ledger, false)
    }
    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.output_data()
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.take_output_data()
    }
    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        attempt.observe_attempt_data(observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(value)
    }
}

fn read_owned<T: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut T::Attempt,
    output: &mut Option<T>,
) -> Result<(), ProviderError> {
    T::read_into_data(input, ledger, attempt)?;
    *output = Some(T::take_output_data(attempt).ok_or_else(invalid)?);
    Ok(())
}

use crate::reference_packet::connected::continuation::settled_reader::retained::ReactiveModel17ReadAttempt;

/// Owns the concrete selected model before any nested field is reconstructed.
#[derive(Default)]
pub(crate) struct PacketSettledModel17ReadAttempt {
    started: bool,
    completed: Option<PacketSettledModel17Data>,
    producer: ProducerModel17ReadAttempt,
    reactive: ReactiveModel17ReadAttempt,
}

impl HistoricalType for PacketSettledModel17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_settled_model17_data(input, ledger, build)
    }
}

impl Native17Build for PacketSettledModel17Data {
    type Attempt = PacketSettledModel17ReadAttempt;

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 current model read already attempted",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::array(input)?;
        let kind = plain_string(fields.next()?.ok_or_else(invalid)?)?;
        let body = fields.next()?.ok_or_else(invalid)?;
        let state = match kind {
            "producer" => {
                attempt.producer.read_fields_into_data(body, ledger, true)?;
                // Validate the outer suffix while the child remains retained.
                fields.finish()?;
                CurrentModel::Producer(attempt.producer.take_output_data().ok_or_else(invalid)?)
            }
            "reactive" => {
                attempt.reactive.read_fields_into_data(body, ledger, true)?;
                fields.finish()?;
                CurrentModel::Reactive(attempt.reactive.take_output_data().ok_or_else(invalid)?)
            }
            _ => return Err(invalid()),
        };
        attempt.completed = Some(Self { state });
        Ok(())
    }

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut fields = Fields::array(input)?;
        let kind = plain_string(fields.next()?.ok_or_else(invalid)?)?;
        let body = fields.next()?.ok_or_else(invalid)?;
        match kind {
            "producer" => ProducerModel17ReadAttempt::preflight_fields_data(body, ledger, true)?,
            "reactive" => ReactiveModel17ReadAttempt::preflight_fields_data(body, ledger, true)?,
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
        if let Some(output) = &attempt.completed {
            output.observe_settled_history_metadata_data(observer)?;
        }
        attempt.producer.observe_attempt_data(observer)?;
        attempt.reactive.observe_attempt_data(observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        value.observe_settled_history_metadata_data(observer)
    }
}

/// Implements the explicit atomic boundary only for types with no owned backing.
macro_rules! atomic_model_leaf {
    ($ty:ty) => {
        impl crate::protocol_snapshot::owned11::typed::Native17Build for $ty {
            type Attempt = Option<Self>;
            fn read_into_data(
                input: &[u8],
                ledger: &mut Ledger<'_, '_, '_>,
                attempt: &mut Self::Attempt,
            ) -> Result<(), ProviderError> {
                if attempt.is_some() {
                    return Err(ProviderError::Conflict(
                        "native17 atomic model leaf already read",
                    ));
                }
                *attempt = Self::read(input, ledger, true)?;
                if attempt.is_none() {
                    return Err(invalid());
                }
                Ok(())
            }
            fn preflight_data(
                input: &[u8],
                ledger: &mut Ledger<'_, '_, '_>,
            ) -> Result<(), ProviderError> {
                Self::read(input, ledger, false).map(|_| ())
            }
            fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
                attempt.as_ref()
            }
            fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
                attempt.take()
            }
            fn observe_attempt_data(
                attempt: &Self::Attempt,
                observer: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                if let Some(value) = attempt {
                    observer.observe(value)?;
                }
                Ok(())
            }
            fn observe_output_data(
                value: &Self,
                observer: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                observer.observe(value)
            }
        }
    };
}
pub(in crate::reference_packet) use atomic_model_leaf;
