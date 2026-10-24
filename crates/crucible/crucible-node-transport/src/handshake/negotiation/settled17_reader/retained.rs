//! Retains exact registration fields and the unfinished selected-slice builder.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::retained_metadata::MetadataObserver;

#[path = "retained/selected.rs"]
mod selected;
use selected::SelectedExtensions17ReadAttempt;

/// Keeps every typed registration child before a later error can occur.
#[derive(Default)]
pub(crate) struct HistoricalAuthority17ReadAttempt {
    started: bool,
    completed: Option<HistoricalAuthority17>,
    epoch: Option<u64>,
    observed_epoch: Option<u64>,
    gate_poisoned: Option<bool>,
    groups: Option<(usize, usize)>,
    selected: SelectedExtensions17ReadAttempt,
    connection: Option<Id>,
    connection_attempt: <Id as Native17Build>::Attempt,
    session: Option<Id>,
    session_attempt: <Id as Native17Build>::Attempt,
    incarnation: Option<Id>,
    incarnation_attempt: <Id as Native17Build>::Attempt,
    limits: Option<crate::handshake::Limits>,
    limits_attempt: <crate::handshake::Limits as Native17Build>::Attempt,
    features: Option<IdSet>,
    features_attempt: <IdSet as Native17Build>::Attempt,
    envelope_extensions: Option<BTreeSet<String>>,
    envelope_extensions_attempt: <BTreeSet<String> as Native17Build>::Attempt,
}

impl Native17Build for HistoricalAuthority17 {
    type Attempt = HistoricalAuthority17ReadAttempt;

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 authority already attempted",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.connection-authority/17",
        )?;
        exact(fields.named("gate_role")?, "registrar-gate")?;
        exact(fields.named("epoch_role")?, "registrar-epoch")?;
        attempt.epoch = Some(
            ledger
                .read::<u64>(fields.named("saved_epoch")?, true)?
                .ok_or_else(invalid)?,
        );
        let observed = fields.named("observed_epoch")?;
        attempt.observed_epoch = Some(ledger.read::<u64>(observed, true)?.ok_or_else(invalid)?);
        let poisoned = fields.named("gate_poisoned")?;
        attempt.gate_poisoned = Some(ledger.read::<bool>(poisoned, true)?.ok_or_else(invalid)?);
        attempt.groups = Some(read_registrar_groups(ledger, observed, poisoned)?);
        read_owned::<Id>(
            fields.named("connection")?,
            ledger,
            &mut attempt.connection_attempt,
            &mut attempt.connection,
        )?;
        read_owned::<Id>(
            fields.named("session")?,
            ledger,
            &mut attempt.session_attempt,
            &mut attempt.session,
        )?;
        read_owned::<Id>(
            fields.named("incarnation")?,
            ledger,
            &mut attempt.incarnation_attempt,
            &mut attempt.incarnation,
        )?;
        read_owned::<crate::handshake::Limits>(
            fields.named("limits")?,
            ledger,
            &mut attempt.limits_attempt,
            &mut attempt.limits,
        )?;
        read_owned::<IdSet>(
            fields.named("features")?,
            ledger,
            &mut attempt.features_attempt,
            &mut attempt.features,
        )?;
        read_owned::<BTreeSet<String>>(
            fields.named("envelope_extensions")?,
            ledger,
            &mut attempt.envelope_extensions_attempt,
            &mut attempt.envelope_extensions,
        )?;
        attempt
            .selected
            .read_into_data(fields.named("extensions")?, ledger)?;
        fields.finish()?;
        if attempt.connection.is_none()
            || attempt.session.is_none()
            || attempt.incarnation.is_none()
            || attempt.limits.is_none()
            || attempt.features.is_none()
            || attempt.envelope_extensions.is_none()
            || attempt.selected.output_data().is_none()
        {
            return Err(invalid());
        }
        let epoch = attempt.epoch.ok_or_else(invalid)?;
        let observed_epoch = attempt.observed_epoch.ok_or_else(invalid)?;
        let gate_poisoned = attempt.gate_poisoned.ok_or_else(invalid)?;
        let (epoch_group, gate_group) = attempt.groups.ok_or_else(invalid)?;
        // All presence checks precede the first move into the final inline DTO.
        attempt.completed = Some(Self {
            data: HistoricalAuthority {
                connection: attempt.connection.take().ok_or_else(invalid)?,
                session: attempt.session.take().ok_or_else(invalid)?,
                incarnation: attempt.incarnation.take().ok_or_else(invalid)?,
                limits: attempt.limits.take().ok_or_else(invalid)?,
                features: attempt.features.take().ok_or_else(invalid)?,
                envelope_extensions: attempt.envelope_extensions.take().ok_or_else(invalid)?,
                epoch: U64::new(epoch),
                extensions: attempt.selected.take_output_data().ok_or_else(invalid)?,
            },
            observed_epoch,
            gate_poisoned,
            epoch_group,
            gate_group,
        });
        Ok(())
    }

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        Self::preflight_settled17_fields_data(input, ledger).map(|_| ())
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
            Self::observe_output_data(output, observer)?;
        }
        if let Some(value) = &attempt.connection {
            <Id as Native17Build>::observe_output_data(value, observer)?;
        }
        <Id as Native17Build>::observe_attempt_data(&attempt.connection_attempt, observer)?;
        if let Some(value) = &attempt.session {
            <Id as Native17Build>::observe_output_data(value, observer)?;
        }
        <Id as Native17Build>::observe_attempt_data(&attempt.session_attempt, observer)?;
        if let Some(value) = &attempt.incarnation {
            <Id as Native17Build>::observe_output_data(value, observer)?;
        }
        <Id as Native17Build>::observe_attempt_data(&attempt.incarnation_attempt, observer)?;
        if let Some(value) = &attempt.limits {
            <crate::handshake::Limits as Native17Build>::observe_output_data(value, observer)?;
        }
        <crate::handshake::Limits as Native17Build>::observe_attempt_data(
            &attempt.limits_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.features {
            <IdSet as Native17Build>::observe_output_data(value, observer)?;
        }
        <IdSet as Native17Build>::observe_attempt_data(&attempt.features_attempt, observer)?;
        if let Some(value) = &attempt.envelope_extensions {
            <BTreeSet<String> as Native17Build>::observe_output_data(value, observer)?;
        }
        <BTreeSet<String> as Native17Build>::observe_attempt_data(
            &attempt.envelope_extensions_attempt,
            observer,
        )?;
        attempt.selected.observe_attempt_data(observer)
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <Id as Native17Build>::observe_output_data(&value.data.connection, observer)?;
        <Id as Native17Build>::observe_output_data(&value.data.session, observer)?;
        <Id as Native17Build>::observe_output_data(&value.data.incarnation, observer)?;
        <crate::handshake::Limits as Native17Build>::observe_output_data(
            &value.data.limits,
            observer,
        )?;
        <IdSet as Native17Build>::observe_output_data(&value.data.features, observer)?;
        <BTreeSet<String> as Native17Build>::observe_output_data(
            &value.data.envelope_extensions,
            observer,
        )?;
        // Each final selected Arc payload is counted once in the outer
        // selected_groups cache. These authority fields retain only handles.
        Ok(())
    }
}

fn read_owned<T: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    child: &mut T::Attempt,
    output: &mut Option<T>,
) -> Result<(), ProviderError> {
    T::read_into_data(input, ledger, child)?;
    *output = Some(T::take_output_data(child).ok_or_else(invalid)?);
    Ok(())
}

fn read_registrar_groups(
    ledger: &mut Ledger<'_, '_, '_>,
    observed: &[u8],
    poisoned: &[u8],
) -> Result<(usize, usize), ProviderError> {
    let epoch_layout = size_of::<std::sync::atomic::AtomicU64>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<std::sync::atomic::AtomicU64>(),
    )? != epoch_layout
    {
        return Err(invalid());
    }
    let gate_layout = size_of::<std::sync::Mutex<()>>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<std::sync::Mutex<()>>(),
    )? != gate_layout
    {
        return Err(invalid());
    }
    let epoch_group = ledger.shared(
        MetadataSharedKind::RegistrarEpoch,
        epoch_layout,
        observed,
        b"",
    )?;
    let gate_group = ledger.shared(
        MetadataSharedKind::RegistrarGate,
        gate_layout,
        poisoned,
        b"",
    )?;
    Ok((epoch_group, gate_group))
}

#[cfg(test)]
#[path = "retained/tests.rs"]
mod tests;

impl HistoricalAuthority17 {
    /// Preflights the same complete fields and returns registrar group ordinals.
    ///
    /// # Errors
    /// Refuses malformed fields, metadata, target backing or incomplete groups.
    pub(crate) fn preflight_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(usize, usize), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.connection-authority/17",
        )?;
        exact(fields.named("gate_role")?, "registrar-gate")?;
        exact(fields.named("epoch_role")?, "registrar-epoch")?;
        ledger.read::<u64>(fields.named("saved_epoch")?, false)?;
        let observed = fields.named("observed_epoch")?;
        ledger.read::<u64>(observed, false)?;
        let poisoned = fields.named("gate_poisoned")?;
        ledger.read::<bool>(poisoned, false)?;
        let groups = read_registrar_groups(ledger, observed, poisoned)?;
        <Id as Native17Build>::preflight_data(fields.named("connection")?, ledger)?;
        <Id as Native17Build>::preflight_data(fields.named("session")?, ledger)?;
        <Id as Native17Build>::preflight_data(fields.named("incarnation")?, ledger)?;
        <crate::handshake::Limits as Native17Build>::preflight_data(
            fields.named("limits")?,
            ledger,
        )?;
        <IdSet as Native17Build>::preflight_data(fields.named("features")?, ledger)?;
        <BTreeSet<String> as Native17Build>::preflight_data(
            fields.named("envelope_extensions")?,
            ledger,
        )?;
        SelectedExtensions17ReadAttempt::preflight_data(fields.named("extensions")?, ledger)?;
        fields.finish()?;
        Ok(groups)
    }
}
