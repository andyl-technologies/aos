//! Owns every completed child and pending native17 token field on refusal.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::retained_metadata::MetadataObserver;
/// Keeps concrete identity children before later role/field checks.
#[derive(Default)]
pub(crate) struct HistoricalAckIdentity17ReadAttempt {
    started: bool,
    completed: Option<HistoricalAckIdentity17>,
    authority: Option<HistoricalAuthority17>,
    authority_attempt: <HistoricalAuthority17 as Native17Build>::Attempt,
    identity: Option<Id>,
    identity_attempt: <Id as Native17Build>::Attempt,
    groups: Option<(usize, usize, usize)>,
    sequence: Option<U64>,
    index: Option<usize>,
    length: Option<usize>,
    digest: Option<[u8; 32]>,
}

impl Native17Build for HistoricalAckIdentity17 {
    type Attempt = HistoricalAckIdentity17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 identity already attempted",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-ack-connection-identity-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor_group = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        owned::<HistoricalAuthority17>(
            fields.named("authority")?,
            ledger,
            &mut attempt.authority_attempt,
            &mut attempt.authority,
        )?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        exact(fields.named("frames_role")?, "native-connection-frames")?;
        let frames_group =
            reference::<RefCell<OriginalFrameReservation>>(ledger, MetadataSharedKind::FrameBank)?;
        attempt.groups = Some((actor_group, frames_group, policy_group));
        owned::<Id>(
            fields.named("admit_id")?,
            ledger,
            &mut attempt.identity_attempt,
            &mut attempt.identity,
        )?;
        attempt.sequence = ledger.read::<U64>(fields.named("admit_sequence")?, true)?;
        attempt.index = ledger.read::<usize>(fields.named("literal_index")?, true)?;
        attempt.length = ledger.read::<usize>(fields.named("literal_length")?, true)?;
        attempt.digest = Some(inline_digest(fields.named("literal_digest")?, ledger)?);
        fields.finish()?;
        if attempt.authority.is_none() || attempt.identity.is_none() {
            return Err(invalid());
        }
        let sequence = attempt.sequence.ok_or_else(invalid)?;
        let index = attempt.index.ok_or_else(invalid)?;
        let length = attempt.length.ok_or_else(invalid)?;
        let digest = attempt.digest.ok_or_else(invalid)?;
        attempt.completed = Some(Self {
            actor_group,
            frames_group,
            policy_group,
            authority: attempt.authority.take().ok_or_else(invalid)?,
            admit_id: attempt.identity.take().ok_or_else(invalid)?,
            admit_sequence: sequence,
            literal_index: index,
            literal_length: length,
            literal_digest: digest,
        });
        Ok(())
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        HistoricalAckIdentity17ReadAttempt::preflight_fields_data(input, ledger).map(|_| ())
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
            Self::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.authority {
            HistoricalAuthority17::observe_output_data(value, observer)?;
        }
        HistoricalAuthority17::observe_attempt_data(&attempt.authority_attempt, observer)?;
        if let Some(value) = &attempt.identity {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&attempt.identity_attempt, observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        HistoricalAuthority17::observe_output_data(&value.authority, observer)?;
        Id::observe_output_data(&value.admit_id, observer)
    }
}

impl HistoricalAckIdentity17ReadAttempt {
    pub(in crate::connection::native_settled17) fn preflight_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(usize, usize, usize), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-ack-connection-identity-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        HistoricalAuthority17::preflight_data(fields.named("authority")?, ledger)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        exact(fields.named("frames_role")?, "native-connection-frames")?;
        let frames =
            reference::<RefCell<OriginalFrameReservation>>(ledger, MetadataSharedKind::FrameBank)?;
        Id::preflight_data(fields.named("admit_id")?, ledger)?;
        ledger.read::<U64>(fields.named("admit_sequence")?, false)?;
        ledger.read::<usize>(fields.named("literal_index")?, false)?;
        ledger.read::<usize>(fields.named("literal_length")?, false)?;
        inline_digest(fields.named("literal_digest")?, ledger)?;
        fields.finish()?;
        Ok((actor, frames, policy))
    }
}
/// Keeps concrete identity children before later role/field checks.
#[derive(Default)]
pub(crate) struct HistoricalRestoreIdentity17ReadAttempt {
    started: bool,
    completed: Option<HistoricalRestoreIdentity17>,
    authority: Option<HistoricalAuthority17>,
    authority_attempt: <HistoricalAuthority17 as Native17Build>::Attempt,
    identity: Option<Id>,
    identity_attempt: <Id as Native17Build>::Attempt,
    groups: Option<(usize, usize, usize)>,
    sequence: Option<U64>,
    index: Option<usize>,
    length: Option<usize>,
    digest: Option<[u8; 32]>,
}

impl Native17Build for HistoricalRestoreIdentity17 {
    type Attempt = HistoricalRestoreIdentity17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 identity already attempted",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-restoration-connection-identity-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor_group = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        owned::<HistoricalAuthority17>(
            fields.named("authority")?,
            ledger,
            &mut attempt.authority_attempt,
            &mut attempt.authority,
        )?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        exact(fields.named("frames_role")?, "native-connection-frames")?;
        let frames_group =
            reference::<RefCell<OriginalFrameReservation>>(ledger, MetadataSharedKind::FrameBank)?;
        attempt.groups = Some((actor_group, frames_group, policy_group));
        owned::<Id>(
            fields.named("request_id")?,
            ledger,
            &mut attempt.identity_attempt,
            &mut attempt.identity,
        )?;
        attempt.sequence = ledger.read::<U64>(fields.named("sequence")?, true)?;
        attempt.index = ledger.read::<usize>(fields.named("literal_slot")?, true)?;
        attempt.length = ledger.read::<usize>(fields.named("literal_length")?, true)?;
        attempt.digest = Some(inline_digest(fields.named("literal_digest")?, ledger)?);
        fields.finish()?;
        if attempt.authority.is_none() || attempt.identity.is_none() {
            return Err(invalid());
        }
        let sequence = attempt.sequence.ok_or_else(invalid)?;
        let index = attempt.index.ok_or_else(invalid)?;
        let length = attempt.length.ok_or_else(invalid)?;
        let digest = attempt.digest.ok_or_else(invalid)?;
        attempt.completed = Some(Self {
            actor_group,
            frames_group,
            policy_group,
            authority: attempt.authority.take().ok_or_else(invalid)?,
            request_id: attempt.identity.take().ok_or_else(invalid)?,
            sequence,
            literal_slot: index,
            literal_length: length,
            literal_digest: digest,
        });
        Ok(())
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        HistoricalRestoreIdentity17ReadAttempt::preflight_fields_data(input, ledger).map(|_| ())
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
            Self::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.authority {
            HistoricalAuthority17::observe_output_data(value, observer)?;
        }
        HistoricalAuthority17::observe_attempt_data(&attempt.authority_attempt, observer)?;
        if let Some(value) = &attempt.identity {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&attempt.identity_attempt, observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        HistoricalAuthority17::observe_output_data(&value.authority, observer)?;
        Id::observe_output_data(&value.request_id, observer)
    }
}

impl HistoricalRestoreIdentity17ReadAttempt {
    pub(in crate::connection::native_settled17) fn preflight_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(usize, usize, usize), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-restoration-connection-identity-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        HistoricalAuthority17::preflight_data(fields.named("authority")?, ledger)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        exact(fields.named("frames_role")?, "native-connection-frames")?;
        let frames =
            reference::<RefCell<OriginalFrameReservation>>(ledger, MetadataSharedKind::FrameBank)?;
        Id::preflight_data(fields.named("request_id")?, ledger)?;
        ledger.read::<U64>(fields.named("sequence")?, false)?;
        ledger.read::<usize>(fields.named("literal_slot")?, false)?;
        ledger.read::<usize>(fields.named("literal_length")?, false)?;
        inline_digest(fields.named("literal_digest")?, ledger)?;
        fields.finish()?;
        Ok((actor, frames, policy))
    }
}

fn owned<T: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    child: &mut T::Attempt,
    output: &mut Option<T>,
) -> Result<(), ProviderError> {
    T::read_into_data(input, ledger, child)?;
    *output = Some(T::take_output_data(child).ok_or_else(invalid)?);
    Ok(())
}

impl HistoricalAckIdentity17 {
    /// Checks builder targets and returns exact same-pass role groups.
    ///
    /// # Errors
    /// Refuses invalid fields, metadata, target demand or incomplete groups.
    pub(crate) fn preflight_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(usize, usize, usize), ProviderError> {
        HistoricalAckIdentity17ReadAttempt::preflight_fields_data(input, ledger)
    }
}

impl HistoricalRestoreIdentity17 {
    /// Checks builder targets and returns exact same-pass role groups.
    ///
    /// # Errors
    /// Refuses invalid fields, metadata, target demand or incomplete groups.
    pub(crate) fn preflight_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(usize, usize, usize), ProviderError> {
        HistoricalRestoreIdentity17ReadAttempt::preflight_fields_data(input, ledger)
    }
}
