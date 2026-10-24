//! Retains concrete model fields and pending typed children through every error.
//!
//! Attempt headers are inline in the caller's once owner. Child preflight funds
//! only the backing each real child builder allocates; no source-row credit is
//! treated as storage for these headers. Completed fields move only after the
//! final grammar check, and semantic checks run while the output remains owned.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::retained_metadata::MetadataObserver;
/// Owns the completed model and each unfinished defining child.
#[derive(Default)]
pub(crate) struct ReactiveModel17ReadAttempt {
    started: bool,
    completed: Option<ReactiveModel17Data>,
    definition: Option<PacketConnectedDefinition>,
    definition_attempt: <PacketConnectedDefinition as Native17Build>::Attempt,
    native_pid: Option<u32>,
    native_pid_attempt: <u32 as Native17Build>::Attempt,
    reached: Option<Position>,
    reached_attempt: <Position as Native17Build>::Attempt,
    gate_closed: Option<bool>,
    gate_closed_attempt: <bool as Native17Build>::Attempt,
    reactions: Option<Vec<PacketReaction>>,
    reactions_attempt: <Vec<PacketReaction> as Native17Build>::Attempt,
    delivered_inputs: Option<Vec<PacketDeliveredInput>>,
    delivered_inputs_attempt: <Vec<PacketDeliveredInput> as Native17Build>::Attempt,
    publications: Option<Vec<PacketPendingPublication>>,
    publications_attempt: <Vec<PacketPendingPublication> as Native17Build>::Attempt,
    outputs: Option<Vec<PacketConnectedPublication>>,
    outputs_attempt: <Vec<PacketConnectedPublication> as Native17Build>::Attempt,
    stages: Option<Vec<OriginalStage>>,
    stages_attempt: <Vec<OriginalStage> as Native17Build>::Attempt,
    grants: Option<BTreeMap<Id, PacketConnectedGrant>>,
    grants_attempt: <BTreeMap<Id, PacketConnectedGrant> as Native17Build>::Attempt,
    retired: Option<BTreeMap<Id, Vec<Id>>>,
    retired_attempt: <BTreeMap<Id, Vec<Id>> as Native17Build>::Attempt,
    reactions_completed: Option<u64>,
    reactions_completed_attempt: <u64 as Native17Build>::Attempt,
    packet_effects: Option<u64>,
    packet_effects_attempt: <u64 as Native17Build>::Attempt,
    failed: Option<bool>,
    failed_attempt: <bool as Native17Build>::Attempt,
}

impl ReactiveModel17ReadAttempt {
    pub(in crate::reference_packet) fn read_fields_into_data(
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
        read_owned::<PacketConnectedDefinition>(
            fields.named("definition")?,
            ledger,
            &mut self.definition_attempt,
            &mut self.definition,
        )?;
        read_owned::<u32>(
            fields.named("native_pid")?,
            ledger,
            &mut self.native_pid_attempt,
            &mut self.native_pid,
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
        read_owned::<Vec<PacketReaction>>(
            fields.named("reactions")?,
            ledger,
            &mut self.reactions_attempt,
            &mut self.reactions,
        )?;
        read_owned::<Vec<PacketDeliveredInput>>(
            fields.named("delivered_inputs")?,
            ledger,
            &mut self.delivered_inputs_attempt,
            &mut self.delivered_inputs,
        )?;
        read_owned::<Vec<PacketPendingPublication>>(
            fields.named("publications")?,
            ledger,
            &mut self.publications_attempt,
            &mut self.publications,
        )?;
        read_owned::<Vec<PacketConnectedPublication>>(
            fields.named("outputs")?,
            ledger,
            &mut self.outputs_attempt,
            &mut self.outputs,
        )?;
        read_owned::<Vec<OriginalStage>>(
            fields.named("stages")?,
            ledger,
            &mut self.stages_attempt,
            &mut self.stages,
        )?;
        read_owned::<BTreeMap<Id, PacketConnectedGrant>>(
            fields.named("grants")?,
            ledger,
            &mut self.grants_attempt,
            &mut self.grants,
        )?;
        read_owned::<BTreeMap<Id, Vec<Id>>>(
            fields.named("retired")?,
            ledger,
            &mut self.retired_attempt,
            &mut self.retired,
        )?;
        read_owned::<u64>(
            fields.named("reactions_completed")?,
            ledger,
            &mut self.reactions_completed_attempt,
            &mut self.reactions_completed,
        )?;
        read_owned::<u64>(
            fields.named("packet_effects")?,
            ledger,
            &mut self.packet_effects_attempt,
            &mut self.packet_effects,
        )?;
        read_owned::<bool>(
            fields.named("failed")?,
            ledger,
            &mut self.failed_attempt,
            &mut self.failed,
        )?;
        if program && plain_string(fields.named("effect_socket_role")?)? != "model-effect-socket" {
            return Err(invalid());
        }
        fields.finish()?;

        // Check every slot before moving any child out of this retained owner.
        if self.definition.is_none()
            || self.native_pid.is_none()
            || self.reached.is_none()
            || self.gate_closed.is_none()
            || self.reactions.is_none()
            || self.delivered_inputs.is_none()
            || self.publications.is_none()
            || self.outputs.is_none()
            || self.stages.is_none()
            || self.grants.is_none()
            || self.retired.is_none()
            || self.reactions_completed.is_none()
            || self.packet_effects.is_none()
            || self.failed.is_none()
        {
            return Err(invalid());
        }
        self.completed = Some(ReactiveModel17Data(ConnectedState {
            definition: self.definition.take().ok_or_else(invalid)?,
            native_pid: self.native_pid.take().ok_or_else(invalid)?,
            reached: self.reached.take().ok_or_else(invalid)?,
            gate_closed: self.gate_closed.take().ok_or_else(invalid)?,
            reactions: self.reactions.take().ok_or_else(invalid)?,
            delivered_inputs: self.delivered_inputs.take().ok_or_else(invalid)?,
            publications: self.publications.take().ok_or_else(invalid)?,
            outputs: self.outputs.take().ok_or_else(invalid)?,
            stages: self.stages.take().ok_or_else(invalid)?,
            grants: self.grants.take().ok_or_else(invalid)?,
            retired: self.retired.take().ok_or_else(invalid)?,
            reactions_completed: self.reactions_completed.take().ok_or_else(invalid)?,
            packet_effects: self.packet_effects.take().ok_or_else(invalid)?,
            failed: self.failed.take().ok_or_else(invalid)?,
        }));
        Ok(())
    }

    pub(in crate::reference_packet) fn preflight_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        program: bool,
    ) -> Result<(), ProviderError> {
        let mut fields = Fields::object(input)?;
        <PacketConnectedDefinition as Native17Build>::preflight_data(
            fields.named("definition")?,
            ledger,
        )?;
        <u32 as Native17Build>::preflight_data(fields.named("native_pid")?, ledger)?;
        <Position as Native17Build>::preflight_data(fields.named("reached")?, ledger)?;
        <bool as Native17Build>::preflight_data(fields.named("gate_closed")?, ledger)?;
        <Vec<PacketReaction> as Native17Build>::preflight_data(fields.named("reactions")?, ledger)?;
        <Vec<PacketDeliveredInput> as Native17Build>::preflight_data(
            fields.named("delivered_inputs")?,
            ledger,
        )?;
        <Vec<PacketPendingPublication> as Native17Build>::preflight_data(
            fields.named("publications")?,
            ledger,
        )?;
        <Vec<PacketConnectedPublication> as Native17Build>::preflight_data(
            fields.named("outputs")?,
            ledger,
        )?;
        <Vec<OriginalStage> as Native17Build>::preflight_data(fields.named("stages")?, ledger)?;
        <BTreeMap<Id, PacketConnectedGrant> as Native17Build>::preflight_data(
            fields.named("grants")?,
            ledger,
        )?;
        <BTreeMap<Id, Vec<Id>> as Native17Build>::preflight_data(fields.named("retired")?, ledger)?;
        <u64 as Native17Build>::preflight_data(fields.named("reactions_completed")?, ledger)?;
        <u64 as Native17Build>::preflight_data(fields.named("packet_effects")?, ledger)?;
        <bool as Native17Build>::preflight_data(fields.named("failed")?, ledger)?;
        if program && plain_string(fields.named("effect_socket_role")?)? != "model-effect-socket" {
            return Err(invalid());
        }
        fields.finish()
    }

    pub(in crate::reference_packet) fn output_data(&self) -> Option<&ReactiveModel17Data> {
        self.completed.as_ref()
    }
    pub(in crate::reference_packet) fn take_output_data(&mut self) -> Option<ReactiveModel17Data> {
        self.completed.take()
    }

    pub(in crate::reference_packet) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &self.completed {
            value.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(value) = &self.definition {
            <PacketConnectedDefinition as Native17Build>::observe_output_data(value, observer)?;
        }
        <PacketConnectedDefinition as Native17Build>::observe_attempt_data(
            &self.definition_attempt,
            observer,
        )?;
        if let Some(value) = &self.native_pid {
            <u32 as Native17Build>::observe_output_data(value, observer)?;
        }
        <u32 as Native17Build>::observe_attempt_data(&self.native_pid_attempt, observer)?;
        if let Some(value) = &self.reached {
            <Position as Native17Build>::observe_output_data(value, observer)?;
        }
        <Position as Native17Build>::observe_attempt_data(&self.reached_attempt, observer)?;
        if let Some(value) = &self.gate_closed {
            <bool as Native17Build>::observe_output_data(value, observer)?;
        }
        <bool as Native17Build>::observe_attempt_data(&self.gate_closed_attempt, observer)?;
        if let Some(value) = &self.reactions {
            <Vec<PacketReaction> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Vec<PacketReaction> as Native17Build>::observe_attempt_data(
            &self.reactions_attempt,
            observer,
        )?;
        if let Some(value) = &self.delivered_inputs {
            <Vec<PacketDeliveredInput> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Vec<PacketDeliveredInput> as Native17Build>::observe_attempt_data(
            &self.delivered_inputs_attempt,
            observer,
        )?;
        if let Some(value) = &self.publications {
            <Vec<PacketPendingPublication> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Vec<PacketPendingPublication> as Native17Build>::observe_attempt_data(
            &self.publications_attempt,
            observer,
        )?;
        if let Some(value) = &self.outputs {
            <Vec<PacketConnectedPublication> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Vec<PacketConnectedPublication> as Native17Build>::observe_attempt_data(
            &self.outputs_attempt,
            observer,
        )?;
        if let Some(value) = &self.stages {
            <Vec<OriginalStage> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Vec<OriginalStage> as Native17Build>::observe_attempt_data(
            &self.stages_attempt,
            observer,
        )?;
        if let Some(value) = &self.grants {
            <BTreeMap<Id, PacketConnectedGrant> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <BTreeMap<Id, PacketConnectedGrant> as Native17Build>::observe_attempt_data(
            &self.grants_attempt,
            observer,
        )?;
        if let Some(value) = &self.retired {
            <BTreeMap<Id, Vec<Id>> as Native17Build>::observe_output_data(value, observer)?;
        }
        <BTreeMap<Id, Vec<Id>> as Native17Build>::observe_attempt_data(
            &self.retired_attempt,
            observer,
        )?;
        if let Some(value) = &self.reactions_completed {
            <u64 as Native17Build>::observe_output_data(value, observer)?;
        }
        <u64 as Native17Build>::observe_attempt_data(&self.reactions_completed_attempt, observer)?;
        if let Some(value) = &self.packet_effects {
            <u64 as Native17Build>::observe_output_data(value, observer)?;
        }
        <u64 as Native17Build>::observe_attempt_data(&self.packet_effects_attempt, observer)?;
        if let Some(value) = &self.failed {
            <bool as Native17Build>::observe_output_data(value, observer)?;
        }
        <bool as Native17Build>::observe_attempt_data(&self.failed_attempt, observer)?;
        Ok(())
    }
}

impl Native17Build for ReactiveModel17Data {
    type Attempt = ReactiveModel17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        attempt.read_fields_into_data(input, ledger, false)
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        ReactiveModel17ReadAttempt::preflight_fields_data(input, ledger, false)
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
        value.observe_settled_history_metadata_data(observer)
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

#[cfg(test)]
#[path = "retained/tests.rs"]
mod tests;

// Companions follow the exact existing object-field grammars above.
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(OriginalStage {
    record: PacketStageRecord,
    record_ref: ContentRef,
    reply: PacketInputReply,
    commit: Option<OriginalCommit>,
});

native17_struct!(OriginalCommit {
    record: PacketCommitRecord,
    record_ref: ContentRef,
    reply: PacketInputReply,
});
