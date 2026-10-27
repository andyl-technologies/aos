//! Owns every completed child and pending native17 token field on refusal.

use super::super::identities::retained::{
    HistoricalAckIdentity17ReadAttempt, HistoricalRestoreIdentity17ReadAttempt,
};
use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::retained_metadata::MetadataObserver;
/// Keeps all completed token children before correspondence acceptance.
#[derive(Default)]
pub(crate) struct HistoricalAckToken17ReadAttempt {
    started: bool,
    completed: Option<HistoricalAckToken17>,
    identity: Option<HistoricalAckIdentity17>,
    identity_attempt: <HistoricalAckIdentity17 as Native17Build>::Attempt,
    authority: Option<HistoricalAuthority17>,
    authority_attempt: <HistoricalAuthority17 as Native17Build>::Attempt,
    original: Option<crate::envelope::Envelope>,
    original_attempt: <crate::envelope::Envelope as Native17Build>::Attempt,
}

impl Native17Build for HistoricalAckToken17 {
    type Attempt = HistoricalAckToken17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict("native17 token already attempted"));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-admit-history/17",
        )?;
        owned::<HistoricalAckIdentity17>(
            fields.named("identity")?,
            ledger,
            &mut attempt.identity_attempt,
            &mut attempt.identity,
        )?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot_group =
            reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        owned::<HistoricalAuthority17>(
            fields.named("authority")?,
            ledger,
            &mut attempt.authority_attempt,
            &mut attempt.authority,
        )?;
        owned::<crate::envelope::Envelope>(
            fields.named("original")?,
            ledger,
            &mut attempt.original_attempt,
            &mut attempt.original,
        )?;
        fields.finish()?;
        if attempt.identity.is_none() || attempt.authority.is_none() || attempt.original.is_none() {
            return Err(invalid());
        }
        attempt.completed = Some(Self {
            identity: attempt.identity.take().ok_or_else(invalid)?,
            authority: attempt.authority.take().ok_or_else(invalid)?,
            boot_group,
            policy_group,
            original: attempt.original.take().ok_or_else(invalid)?,
        });
        // Keep the complete typed token in the attempt on a later relation error.
        let output = attempt.completed.as_ref().ok_or_else(invalid)?;
        if output.identity.group_ids_data().2 != policy_group
            || !output
                .authority
                .same_registration_data(&output.identity.authority)
        {
            return Err(invalid());
        }
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
        if let Some(value) = &attempt.completed {
            Self::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.identity {
            <HistoricalAckIdentity17 as Native17Build>::observe_output_data(value, observer)?;
        }
        <HistoricalAckIdentity17 as Native17Build>::observe_attempt_data(
            &attempt.identity_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.authority {
            <HistoricalAuthority17 as Native17Build>::observe_output_data(value, observer)?;
        }
        <HistoricalAuthority17 as Native17Build>::observe_attempt_data(
            &attempt.authority_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.original {
            <crate::envelope::Envelope as Native17Build>::observe_output_data(value, observer)?;
        }
        <crate::envelope::Envelope as Native17Build>::observe_attempt_data(
            &attempt.original_attempt,
            observer,
        )?;
        Ok(())
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <HistoricalAckIdentity17 as Native17Build>::observe_output_data(&value.identity, observer)?;
        <HistoricalAuthority17 as Native17Build>::observe_output_data(&value.authority, observer)?;
        <crate::envelope::Envelope as Native17Build>::observe_output_data(
            &value.original,
            observer,
        )?;
        Ok(())
    }
}

/// Keeps all completed token children before correspondence acceptance.
#[derive(Default)]
pub(crate) struct HistoricalPrepareToken17ReadAttempt {
    started: bool,
    completed: Option<HistoricalPrepareToken17>,
    identity: Option<HistoricalRestoreIdentity17>,
    identity_attempt: <HistoricalRestoreIdentity17 as Native17Build>::Attempt,
    authority: Option<HistoricalAuthority17>,
    authority_attempt: <HistoricalAuthority17 as Native17Build>::Attempt,
}

impl Native17Build for HistoricalPrepareToken17 {
    type Attempt = HistoricalPrepareToken17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict("native17 token already attempted"));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-prepare-history/17",
        )?;
        owned::<HistoricalRestoreIdentity17>(
            fields.named("identity")?,
            ledger,
            &mut attempt.identity_attempt,
            &mut attempt.identity,
        )?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot_group =
            reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        owned::<HistoricalAuthority17>(
            fields.named("authority")?,
            ledger,
            &mut attempt.authority_attempt,
            &mut attempt.authority,
        )?;
        exact(
            fields.named("attempt_role")?,
            "native-complete-restore-prepare",
        )?;
        let (layout, alignment) = NativeAckBoot::current_prepare_shared_layout17_data();
        if ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)? != layout {
            return Err(invalid());
        }
        let attempt_group =
            ledger.shared_reference(MetadataSharedKind::NativeRestorePrepareAttempt, layout)?;
        fields.finish()?;
        if attempt.identity.is_none() || attempt.authority.is_none() {
            return Err(invalid());
        }
        attempt.completed = Some(Self {
            identity: attempt.identity.take().ok_or_else(invalid)?,
            authority: attempt.authority.take().ok_or_else(invalid)?,
            boot_group,
            policy_group,
            attempt_group,
        });
        // Keep the complete typed token in the attempt on a later relation error.
        let output = attempt.completed.as_ref().ok_or_else(invalid)?;
        if output.identity.group_ids_data().2 != policy_group
            || !output
                .authority
                .same_registration_data(&output.identity.authority)
        {
            return Err(invalid());
        }
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
        if let Some(value) = &attempt.completed {
            Self::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.identity {
            <HistoricalRestoreIdentity17 as Native17Build>::observe_output_data(value, observer)?;
        }
        <HistoricalRestoreIdentity17 as Native17Build>::observe_attempt_data(
            &attempt.identity_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.authority {
            <HistoricalAuthority17 as Native17Build>::observe_output_data(value, observer)?;
        }
        <HistoricalAuthority17 as Native17Build>::observe_attempt_data(
            &attempt.authority_attempt,
            observer,
        )?;
        Ok(())
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <HistoricalRestoreIdentity17 as Native17Build>::observe_output_data(
            &value.identity,
            observer,
        )?;
        <HistoricalAuthority17 as Native17Build>::observe_output_data(&value.authority, observer)?;
        Ok(())
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

impl HistoricalAckToken17 {
    /// Preflights all target children and returns the same-pass role groups.
    ///
    /// # Errors
    /// Refuses malformed fields, metadata, target backing or incomplete groups.
    pub(crate) fn preflight_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(usize, usize, usize, usize), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-admit-history/17",
        )?;
        let (actor, frames, identity_policy) =
            HistoricalAckIdentity17ReadAttempt::preflight_fields_data(
                fields.named("identity")?,
                ledger,
            )?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot = reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        HistoricalAuthority17::preflight_data(fields.named("authority")?, ledger)?;
        <crate::envelope::Envelope as Native17Build>::preflight_data(
            fields.named("original")?,
            ledger,
        )?;
        fields.finish()?;
        if identity_policy != policy {
            return Err(invalid());
        }
        Ok((actor, frames, boot, policy))
    }
}

impl HistoricalPrepareToken17 {
    /// Preflights all target children and returns the same-pass role groups.
    ///
    /// # Errors
    /// Refuses malformed fields, metadata, target backing or incomplete groups.
    pub(crate) fn preflight_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(usize, usize, usize, usize, usize), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-prepare-history/17",
        )?;
        let (actor, frames, identity_policy) =
            HistoricalRestoreIdentity17ReadAttempt::preflight_fields_data(
                fields.named("identity")?,
                ledger,
            )?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot = reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        HistoricalAuthority17::preflight_data(fields.named("authority")?, ledger)?;
        exact(
            fields.named("attempt_role")?,
            "native-complete-restore-prepare",
        )?;
        let (layout, alignment) = NativeAckBoot::current_prepare_shared_layout17_data();
        if ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)? != layout {
            return Err(invalid());
        }
        let prepare =
            ledger.shared_reference(MetadataSharedKind::NativeRestorePrepareAttempt, layout)?;
        fields.finish()?;
        if identity_policy != policy {
            return Err(invalid());
        }
        Ok((actor, frames, boot, policy, prepare))
    }
}
