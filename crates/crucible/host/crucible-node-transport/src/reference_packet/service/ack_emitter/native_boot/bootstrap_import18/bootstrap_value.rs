//! Retains strict post-Hello JSON beside its original literal and live SDK.
//!
//! The closed prospective populations fund the bootstrap request grammar, not
//! arbitrary JSON graphs. The immutable lexical census must fit that population
//! before the strict parser allocates. Parsed DATA grants no assigned request,
//! proof authentication, Source allowance, ACK, model installation or readiness.

use super::bootstrap_literal::Attempt as Literal;
use super::bootstrap_normalizations::Attempt as Normalizations;
use super::bootstrap_operands::BootstrapAckOperands;
use super::hello_value::{Attempt as StrictValue, storage};
use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SelectedLaunchWireData;
use crate::retained_metadata::BootstrapBodyMetadataProfileData;
use serde_json::Value;
use std::rc::{Rc, Weak};

#[path = "bootstrap_value/populations.rs"]
mod populations;

/// Admits the parser while observing all original and external owners.
pub(in super::super) trait Admission {
    /// Admits the allocation-free lexical quote under the original whole census.
    ///
    /// Callback allocations and errors require their own enclosing funding.
    ///
    /// # Errors
    /// Refuses missing original credit or incomplete surviving custody.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &Attempt,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the stored actual parser row before any Value allocation.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete whole-owner correspondence.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes every surviving parser output or diagnostic on either outcome.
    ///
    /// # Errors
    /// Refuses missing credit or incomplete actual-owner observation.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &Attempt,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

/// Owns one strict parse occurrence and its surviving output or failure.
pub(in super::super) struct Attempt {
    started: bool,
    complete: bool,
    failed: bool,
    cut: Option<OperationalDeadline>,
    launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    row: Option<[usize; 3]>,
    value: StrictValue,
}

impl Attempt {
    /// Initializes retained slots without allocating or inspecting input.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            cut: None,
            launch: None,
            row: None,
            value: StrictValue::empty_data(),
        }
    }

    fn authenticate_alias(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<(), ProviderError> {
        if let Some(launch) = &self.launch {
            if !Weak::ptr_eq(
                launch,
                &Rc::downgrade(original.parsed.shared_launch_data()?),
            ) {
                return Err(refused());
            }
        }
        Ok(())
    }

    fn guard(&self, original: &OriginalImport18RawBootstrap) -> Result<(), ProviderError> {
        self.authenticate_alias(original)?;
        if self.cut != Some(original.cut) || original.cut.is_expired() {
            return Err(refused());
        }
        original.authenticate_channel()
    }

    fn guard_operands(
        &self,
        original: &OriginalImport18RawBootstrap,
        operands: &BootstrapAckOperands<'_>,
    ) -> Result<(), ProviderError> {
        self.guard(original)?;
        operands.ensure_current_authority_data()
    }

    /// Counts surviving Value and owned diagnostic backing after either outcome.
    ///
    /// # Errors
    /// Refuses foreign association, unsupported profiles or checked overflow.
    pub(in super::super) fn retained_requested_bytes_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.authenticate_alias(original)?;
        size_of::<Self>()
            .checked_add(self.value.retained_backing_data()?)
            .ok_or_else(exhausted)
    }

    /// Lends complete strict DATA under its original literal, Host and SDK guards.
    ///
    /// Inspection and its concrete Copy result require enclosing admission.
    ///
    /// # Errors
    /// Refuses incomplete or failed parsing, stale originals or either callback
    /// or terminal guard. The callback cannot move the retained Value out.
    pub(in super::super) fn with_value_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        inspect: impl FnOnce(&Value) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_value_and_operands_data(original, normalizations, literal, |value, _| {
            inspect(value)
        })
    }

    /// Lends strict DATA and the same original borrowed SDK without reopening it.
    ///
    /// Callback allocation and its concrete Copy result require separate credit.
    ///
    /// # Errors
    /// Refuses incomplete parsing, stale original custody, SDK or either outcome.
    pub(in super::super) fn with_value_and_operands_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        inspect: impl FnOnce(&Value, &BootstrapAckOperands<'_>) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.complete || self.failed {
            return Err(refused());
        }
        literal.with_body_and_operands_data(original, normalizations, |_, operands| {
            self.guard(original)?;
            let outcome = inspect(self.value.value_data()?, operands);
            let terminal = self
                .guard(original)
                .and_then(|()| self.value.value_data().map(|_| ()));
            let result = outcome?;
            terminal?;
            Ok(result)
        })
    }

    /// Quotes concrete nested loans and Copy result controls without allocation.
    ///
    /// # Errors
    /// Refuses checked counter accumulation overflow.
    pub(in super::super) fn value_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            size_of::<&Self>(),
            size_of::<&OriginalImport18RawBootstrap>(),
            size_of::<&Normalizations>(),
            size_of::<&Literal>(),
            size_of::<&Value>(),
            size_of::<&BootstrapAckOperands<'static>>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<R>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<(), ProviderError>>(),
            size_of::<Result<&Value, ProviderError>>(),
        ]
        .into_iter()
        .try_fold(
            Literal::body_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(exhausted),
        )
    }
}

impl OriginalImport18RawBootstrap {
    /// Strictly parses the first original post-Hello body once as retained DATA.
    ///
    /// Lexical admission precedes the census; a distinct actual row admission
    /// precedes parsing. Every parser outcome receives the original full SDK
    /// guards and actual whole-owner observation before any error propagates.
    ///
    /// # Errors
    /// Refuses retry, stale/incomplete originals, short populations or credit,
    /// invalid strict JSON, admission or terminal correspondence.
    pub(in super::super) fn decode_bootstrap_value_data(
        &mut self,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_value_started || attempt.started {
            return Err(refused());
        }
        self.bootstrap_value_started = true;
        attempt.started = true;
        let outcome =
            self.decode_current_bootstrap_value(normalizations, literal, attempt, admission);
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            attempt.failed = true;
            attempt.value.refuse_data();
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        attempt.complete = true;
        Ok(())
    }

    fn decode_current_bootstrap_value(
        &mut self,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        attempt.value.start_data()?;
        attempt.cut = Some(self.cut);
        attempt.launch = Some(Rc::downgrade(self.parsed.shared_launch_data()?));

        // The original owners remain immutably borrowed throughout this phase.
        // Check the same live authority between callbacks, and retain full
        // original/Host/SDK terminal guards around either aggregate outcome.
        literal.with_body_and_operands_data(self, normalizations, |raw, operands| {
            attempt.guard_operands(self, operands)?;
            self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
            admission.quote_data(
                self,
                normalizations,
                literal,
                attempt,
                counter_scratch_data()?,
            )?;
            attempt.guard_operands(self, operands)?;
            let maximum = self.bounds.requested_peak;
            let bound = construction_data(self.typed_bodies_data()?.launch.launch_data(), maximum)?;
            let (parser, profile) = storage::actual_data(raw, maximum)?;
            let row = parser_row_data(parser)?;
            if row
                .into_iter()
                .zip(bound)
                .any(|(actual, maximum)| actual > maximum)
            {
                return Err(exhausted());
            }
            attempt.row = Some(row);
            attempt.value.quote_data(parser, profile)?;
            let literal_retained = literal.retained_requested_bytes_data(self)?;
            let retained = self
                .retained_requested_bytes()?
                .checked_add(normalizations.retained_requested_bytes_data(self)?)
                .and_then(|sum| sum.checked_add(literal_retained))
                .and_then(|sum| sum.checked_add(row[0]))
                .ok_or_else(exhausted)?;
            self.admit_source_row([retained, row[1], row[2]])?;
            admission.construct_data(self, normalizations, literal, attempt, row)?;
            attempt.guard_operands(self, operands)?;
            let nesting = usize::try_from(
                self.typed_bodies_data()?
                    .launch
                    .launch_data()
                    .limits
                    .nesting
                    .get(),
            )
            .map_err(|_| exhausted())?;
            let outcome = attempt.value.parse_data(raw, nesting);
            let terminal = attempt.guard_operands(self, operands);
            let census = attempt
                .retained_requested_bytes_data(self)
                .and_then(|actual| {
                    admission.finish_data(self, normalizations, literal, attempt, actual)
                });
            let observed = attempt.guard_operands(self, operands);
            outcome?;
            terminal?;
            census?;
            observed
        })?;
        attempt.value.complete_data()
    }
}

/// Quotes the closed bootstrap request population before a literal exists.
///
/// The negotiated full literal bank remains a separate retained component.
/// This quote neither parses a request nor creates an allowance.
///
/// # Errors
/// Refuses invalid negotiated framing, unsupported layouts, checked overflow or
/// a complete component above the independent restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    if launch.limits.frame_bytes.get() == 0
        || launch.limits.frame_bytes.get() > crate::transport::MAX_FRAME_BYTES as u64
    {
        return Err(refused());
    }
    let (parser, _) = storage::population_data(populations::extent_data()?, maximum)?;
    let row = parser_row_data(parser)?;
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|sum| sum > maximum)
    {
        return Err(exhausted());
    }
    Ok(row)
}

/// Prices the retained maximum across normalization and subsequent decoding.
///
/// A failed normalization keeps its Value while later owners remain empty.
/// A completed normalization retains only its header before literal receipt or
/// strict or typed decoding can begin. Failed later phases retain their prefix.
/// This lifetime calculation supplies DATA only, never resource permission.
///
/// # Errors
/// Refuses checked requested-storage accumulation overflow.
pub(in crate::reference_packet::service) fn retained_schedule_data(
    normalizations: [usize; 3],
    literal: [usize; 3],
    value: [usize; 3],
    codec: [usize; 3],
    correlation: [usize; 3],
) -> Result<usize, ProviderError> {
    let normalizing = normalizations[0]
        .checked_add(size_of::<Literal>())
        .and_then(|sum| sum.checked_add(size_of::<Attempt>()))
        .and_then(|sum| sum.checked_add(size_of::<super::bootstrap_codec::Attempt>()))
        .and_then(|sum| sum.checked_add(size_of::<super::bootstrap_correlation::Attempt>()))
        .ok_or_else(exhausted)?;
    let decoding = size_of::<Normalizations>()
        .checked_add(literal[0])
        .and_then(|sum| sum.checked_add(value[0]))
        .and_then(|sum| sum.checked_add(codec[0]))
        .and_then(|sum| sum.checked_add(correlation[0]))
        .ok_or_else(exhausted)?;
    Ok(normalizing.max(decoding))
}

/// Names the fixed retained-lifetime calculation and checked sum controls.
pub(in crate::reference_packet::service) fn schedule_counter_scratch_data() -> usize {
    size_of::<[usize; 3]>() * 5
        + size_of::<usize>() * 4
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
}

fn parser_row_data(parser: [usize; 3]) -> Result<[usize; 3], ProviderError> {
    Ok([
        size_of::<Attempt>()
            .checked_add(parser[0])
            .ok_or_else(exhausted)?,
        parser[1]
            .checked_add(
                size_of::<StrictValue>()
                    + size_of::<Attempt>()
                    + size_of::<Result<Attempt, ProviderError>>(),
            )
            .ok_or_else(exhausted)?,
        parser[2]
            .checked_add(counter_scratch_data()?)
            .ok_or_else(exhausted)?,
    ])
}

/// Names actual strict-parser, population, admission and original-loan controls.
///
/// # Errors
/// Refuses checked counter-layout accumulation overflow.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> Result<usize, ProviderError> {
    [
        StrictValue::counter_scratch_data(),
        populations::counter_scratch_data(),
        size_of::<&mut Attempt>(),
        size_of::<&Attempt>(),
        size_of::<&mut OriginalImport18RawBootstrap>(),
        size_of::<&OriginalImport18RawBootstrap>(),
        size_of::<&Normalizations>(),
        size_of::<&Literal>(),
        size_of::<&BootstrapAckOperands<'static>>(),
        size_of::<&dyn Admission>(),
        size_of::<[usize; 3]>() * 4,
        size_of::<BootstrapBodyMetadataProfileData>(),
        size_of::<Result<([usize; 3], BootstrapBodyMetadataProfileData), ProviderError>>(),
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<Result<(), ProviderError>>() * 6,
        size_of::<usize>() * 4,
        size_of::<std::iter::Zip<std::array::IntoIter<usize, 3>, std::array::IntoIter<usize, 3>>>(),
        size_of::<Weak<PacketNativeImport18SelectedLaunchWireData>>(),
    ]
    .into_iter()
    .try_fold(
        Literal::body_loan_counter_scratch_data::<([usize; 3], BootstrapBodyMetadataProfileData)>(
        )?,
        |sum, field| sum.checked_add(field).ok_or_else(exhausted),
    )
    .and_then(|construction| {
        Ok(construction.max(Attempt::value_loan_counter_scratch_data::<()>()?))
    })
}

#[cfg(test)]
#[path = "bootstrap_value/tests.rs"]
pub(super) mod tests;
