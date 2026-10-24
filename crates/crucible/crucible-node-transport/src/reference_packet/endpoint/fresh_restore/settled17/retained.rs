//! Supplies the concrete retained companion of the exact Fresh17 field roster.

use super::*;
use crate::protocol_snapshot::owned11::typed::{Native17Build, native17_build::native17_struct};
use crate::retained_metadata::MetadataObserver;
native17_struct!(HistoricalFreshQueryInput17 {
    frame: Option<HistoricalReceivedFrame17>,
    commitments: Option<HistoricalFreshCommitments17>,
});

/// Keeps all eight actual Fresh fields and their unfinished typed builders.
#[derive(Default)]
pub(crate) struct HistoricalFreshRestoreAttempt17ReadAttempt {
    started: bool,
    completed: Option<HistoricalFreshRestoreAttempt17>,
    creator: Option<u32>,
    creator_attempt: <u32 as Native17Build>::Attempt,
    thread: Option<HistoricalThread17>,
    thread_attempt: <HistoricalThread17 as Native17Build>::Attempt,
    startup: Option<HistoricalReportStartupAllocation17>,
    startup_attempt: <HistoricalReportStartupAllocation17 as Native17Build>::Attempt,
    prepare: Option<HistoricalPrepareStartupAllocation17>,
    prepare_attempt: <HistoricalPrepareStartupAllocation17 as Native17Build>::Attempt,
    input: Option<HistoricalFreshQueryInput17>,
    input_attempt: <HistoricalFreshQueryInput17 as Native17Build>::Attempt,
    current: Option<Option<HistoricalFreshCurrentCensus17>>,
    current_attempt: <Option<HistoricalFreshCurrentCensus17> as Native17Build>::Attempt,
    prepare_input: Option<Option<HistoricalReceivedFrame17>>,
    prepare_input_attempt: <Option<HistoricalReceivedFrame17> as Native17Build>::Attempt,
    publication: Option<HistoricalFreshReportPublication17>,
    publication_attempt: <HistoricalFreshReportPublication17 as Native17Build>::Attempt,
}
impl Native17Build for HistoricalFreshRestoreAttempt17 {
    type Attempt = HistoricalFreshRestoreAttempt17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 Fresh attempt already read",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        read_owned::<u32>(
            fields.named("creator")?,
            ledger,
            &mut attempt.creator_attempt,
            &mut attempt.creator,
        )?;
        read_owned::<HistoricalThread17>(
            fields.named("thread")?,
            ledger,
            &mut attempt.thread_attempt,
            &mut attempt.thread,
        )?;
        read_owned::<HistoricalReportStartupAllocation17>(
            fields.named("startup")?,
            ledger,
            &mut attempt.startup_attempt,
            &mut attempt.startup,
        )?;
        read_owned::<HistoricalPrepareStartupAllocation17>(
            fields.named("prepare")?,
            ledger,
            &mut attempt.prepare_attempt,
            &mut attempt.prepare,
        )?;
        read_owned::<HistoricalFreshQueryInput17>(
            fields.named("input")?,
            ledger,
            &mut attempt.input_attempt,
            &mut attempt.input,
        )?;
        read_owned::<Option<HistoricalFreshCurrentCensus17>>(
            fields.named("current")?,
            ledger,
            &mut attempt.current_attempt,
            &mut attempt.current,
        )?;
        read_owned::<Option<HistoricalReceivedFrame17>>(
            fields.named("prepare_input")?,
            ledger,
            &mut attempt.prepare_input_attempt,
            &mut attempt.prepare_input,
        )?;
        read_owned::<HistoricalFreshReportPublication17>(
            fields.named("publication")?,
            ledger,
            &mut attempt.publication_attempt,
            &mut attempt.publication,
        )?;
        fields.finish()?;
        if attempt.creator.is_none()
            || attempt.thread.is_none()
            || attempt.startup.is_none()
            || attempt.prepare.is_none()
            || attempt.input.is_none()
            || attempt.current.is_none()
            || attempt.prepare_input.is_none()
            || attempt.publication.is_none()
        {
            return Err(invalid());
        }
        attempt.completed = Some(Self {
            creator: attempt.creator.take().ok_or_else(invalid)?,
            thread: attempt.thread.take().ok_or_else(invalid)?,
            startup: attempt.startup.take().ok_or_else(invalid)?,
            prepare: attempt.prepare.take().ok_or_else(invalid)?,
            input: attempt.input.take().ok_or_else(invalid)?,
            current: attempt.current.take().ok_or_else(invalid)?,
            prepare_input: attempt.prepare_input.take().ok_or_else(invalid)?,
            publication: attempt.publication.take().ok_or_else(invalid)?,
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
        if let Some(value) = &attempt.completed {
            Self::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.creator {
            <u32 as Native17Build>::observe_output_data(value, observer)?;
        }
        <u32 as Native17Build>::observe_attempt_data(&attempt.creator_attempt, observer)?;
        if let Some(value) = &attempt.thread {
            <HistoricalThread17 as Native17Build>::observe_output_data(value, observer)?;
        }
        <HistoricalThread17 as Native17Build>::observe_attempt_data(
            &attempt.thread_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.startup {
            <HistoricalReportStartupAllocation17 as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <HistoricalReportStartupAllocation17 as Native17Build>::observe_attempt_data(
            &attempt.startup_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.prepare {
            <HistoricalPrepareStartupAllocation17 as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <HistoricalPrepareStartupAllocation17 as Native17Build>::observe_attempt_data(
            &attempt.prepare_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.input {
            <HistoricalFreshQueryInput17 as Native17Build>::observe_output_data(value, observer)?;
        }
        <HistoricalFreshQueryInput17 as Native17Build>::observe_attempt_data(
            &attempt.input_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.current {
            <Option<HistoricalFreshCurrentCensus17> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Option<HistoricalFreshCurrentCensus17> as Native17Build>::observe_attempt_data(
            &attempt.current_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.prepare_input {
            <Option<HistoricalReceivedFrame17> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Option<HistoricalReceivedFrame17> as Native17Build>::observe_attempt_data(
            &attempt.prepare_input_attempt,
            observer,
        )?;
        if let Some(value) = &attempt.publication {
            <HistoricalFreshReportPublication17 as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <HistoricalFreshReportPublication17 as Native17Build>::observe_attempt_data(
            &attempt.publication_attempt,
            observer,
        )?;
        Ok(())
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <u32 as Native17Build>::observe_output_data(&value.creator, observer)?;
        <HistoricalThread17 as Native17Build>::observe_output_data(&value.thread, observer)?;
        <HistoricalReportStartupAllocation17 as Native17Build>::observe_output_data(
            &value.startup,
            observer,
        )?;
        <HistoricalPrepareStartupAllocation17 as Native17Build>::observe_output_data(
            &value.prepare,
            observer,
        )?;
        <HistoricalFreshQueryInput17 as Native17Build>::observe_output_data(
            &value.input,
            observer,
        )?;
        <Option<HistoricalFreshCurrentCensus17> as Native17Build>::observe_output_data(
            &value.current,
            observer,
        )?;
        <Option<HistoricalReceivedFrame17> as Native17Build>::observe_output_data(
            &value.prepare_input,
            observer,
        )?;
        <HistoricalFreshReportPublication17 as Native17Build>::observe_output_data(
            &value.publication,
            observer,
        )?;
        Ok(())
    }
}

impl HistoricalFreshRestoreAttempt17 {
    /// Preflights the complete fields and returns both startup role-group pairs.
    ///
    /// # Errors
    /// Refuses malformed fields, metadata, target demand or incomplete groups.
    pub(crate) fn preflight_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<FreshRestoreRoleGroupIds17, ProviderError> {
        let mut fields = Fields::object(input)?;
        <u32 as Native17Build>::preflight_data(fields.named("creator")?, ledger)?;
        HistoricalThread17::preflight_data(fields.named("thread")?, ledger)?;
        // Startup fields are explicit allocation-free leaves. Their defining
        // strict parsers return the same-pass ordinals without building DTOs.
        let (_, startup) = HistoricalReportStartupAllocation17::read_settled17_fields_data(
            fields.named("startup")?,
            ledger,
            false,
        )?;
        let (_, prepare) = HistoricalPrepareStartupAllocation17::read_settled17_fields_data(
            fields.named("prepare")?,
            ledger,
            false,
        )?;
        HistoricalFreshQueryInput17::preflight_data(fields.named("input")?, ledger)?;
        <Option<HistoricalFreshCurrentCensus17> as Native17Build>::preflight_data(
            fields.named("current")?,
            ledger,
        )?;
        <Option<HistoricalReceivedFrame17> as Native17Build>::preflight_data(
            fields.named("prepare_input")?,
            ledger,
        )?;
        HistoricalFreshReportPublication17::preflight_data(fields.named("publication")?, ledger)?;
        fields.finish()?;
        Ok((startup, prepare))
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

// These explicit leaves contain only fixed inline arrays, numeric facts and
// archive-local ordinals. None has String, Vec, Box, map or shared backing.
macro_rules! fixed_fresh_leaf {
    ($ty:ty) => {
        impl Native17Build for $ty {
            type Attempt = Option<Self>;
            fn read_into_data(
                input: &[u8],
                ledger: &mut Ledger<'_, '_, '_>,
                attempt: &mut Self::Attempt,
            ) -> Result<(), ProviderError> {
                if attempt.is_some() {
                    return Err(ProviderError::Conflict(
                        "native17 fixed Fresh leaf already read",
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
                _: &Self::Attempt,
                _: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                Ok(())
            }
            fn observe_output_data(
                _: &Self,
                _: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                Ok(())
            }
        }
    };
}
fixed_fresh_leaf!(HistoricalFreshCommitments17);
fixed_fresh_leaf!(HistoricalFreshBanks17);
fixed_fresh_leaf!(HistoricalFreshCurrentCensus17);
fixed_fresh_leaf!(HistoricalReportStartupAllocation17);
fixed_fresh_leaf!(HistoricalPrepareStartupAllocation17);
