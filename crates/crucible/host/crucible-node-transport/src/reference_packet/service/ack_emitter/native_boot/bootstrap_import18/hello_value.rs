//! Separately admits strict parsing of the same retained original Hello literal.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crucible_node_format::ContractError;
use serde_json::Value;

#[path = "hello_value/attempt.rs"]
mod attempt;
#[path = "hello_value/storage.rs"]
pub(super) mod storage;
pub(super) use attempt::Attempt;

/// Admits the actual strict parser without a native policy or protocol response.
pub(in super::super) trait OriginalImport18HelloValueAdmission {
    /// Admits the fixed original-literal loan and allocation-free lexical quote.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete whole-owner custody.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the stored actual parser row before the first Value allocation.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete whole-owner custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes surviving parsed or failed DATA after either parser outcome.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete whole-owner observation.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Strictly parses the same completed original Hello body once as DATA.
    ///
    /// Admission precedes the lexical quote and separately precedes parsing.
    /// Parsed Values and owned strict reasons survive later refusal. No DTO
    /// reparse, Hello authentication, response publication or model is created.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete original literal, expired/changed custody,
    /// unavailable admission, invalid strict JSON or terminal correspondence.
    pub(in super::super) fn decode_hello_value_data(
        &mut self,
        admission: &dyn OriginalImport18HelloValueAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_value.start_data()?;
        let outcome = self.decode_current_hello_value(admission);
        let terminal = self.with_hello_literal_data(|_| Ok(()));
        match outcome.and(terminal) {
            Ok(()) => self.hello_value.complete_data(),
            Err(error) => {
                self.hello_value.refuse_data();
                Err(error)
            }
        }
    }

    fn decode_current_hello_value(
        &mut self,
        admission: &dyn OriginalImport18HelloValueAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.with_hello_literal_data(|_| Ok(()))?;
        admission.quote_data(self, counter_scratch_data())?;
        let maximum = self.bounds.requested_peak;
        let (mut row, profile) =
            self.with_hello_literal_data(|raw| storage::actual_data(raw, maximum))?;
        row[2] = row[2]
            .checked_add(counter_scratch_data())
            .ok_or_else(exhausted)?;
        ensure_peak_data(row, maximum)?;
        self.hello_value.quote_data(row, profile)?;
        admission.construct_data(self, row)?;
        let outcome = self.parse_current_hello_value();
        let terminal = self
            .hello_value
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    fn parse_current_hello_value(&mut self) -> Result<(), ProviderError> {
        self.with_hello_literal_data(|_| Ok(()))?;
        let nesting = usize::try_from(
            self.typed_bodies_data()?
                .launch
                .launch_data()
                .limits
                .nesting
                .get(),
        )
        .map_err(|_| refused())?;
        let cut = self.cut;
        let Self {
            hello_exchange,
            hello_literal,
            hello_value,
            ..
        } = self;
        hello_exchange
            .as_ref()
            .ok_or_else(refused)?
            .with_exchange_data(|exchange| {
                exchange.original_stream_data().completed_data(cut)?;
                let raw = hello_literal
                    .as_ref()
                    .ok_or_else(refused)?
                    .body_data(exchange)?;
                let outcome = hello_value.parse_data(raw, nesting);
                let physical = exchange.original_stream_data().completed_data(cut);
                outcome?;
                physical
            })
    }

    /// Lends completed strict DATA under the unchanged original literal guards.
    ///
    /// The caller separately admits inspection; only Copy DATA may return.
    ///
    /// # Errors
    /// Refuses incomplete parsing, changed custody, callback or terminal guards.
    pub(in super::super) fn with_hello_value_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&Value) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_hello_literal_data(|_| {
            let outcome = inspect(self.hello_value.value_data()?);
            let terminal = self.hello_value.value_data().map(|_| ());
            let result = outcome?;
            terminal?;
            Ok(result)
        })
    }

    /// Names separately admitted original-literal and parsed-value loan controls.
    pub(in super::super) fn hello_value_loan_counter_scratch_data<R: Copy>() -> usize {
        Self::hello_literal_loan_counter_scratch_data::<R>()
            + counter_scratch_data()
            + size_of::<R>() * 2
            + size_of::<Result<R, ProviderError>>() * 2
    }
}

/// Bounds the actual strict parser for every bounded future Hello literal.
///
/// # Errors
/// Refuses unsupported parser/tree layouts, invalid framing, checked overflow
/// or a complete parser row above the independent restriction.
pub(in crate::reference_packet::service) fn construction_bound_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let bytes = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?;
    let mut row = storage::maximum_data(bytes, maximum)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(exhausted)?;
    ensure_peak_data(row, maximum)?;
    Ok(row)
}

fn ensure_peak_data(row: [usize; 3], maximum: usize) -> Result<(), ProviderError> {
    let peak = row.into_iter().try_fold(0usize, |sum, axis| {
        sum.checked_add(axis).ok_or_else(exhausted)
    })?;
    if peak > maximum {
        return Err(exhausted());
    }
    Ok(())
}

/// Names actual parser, lexical quote, original-loan and admission controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    Attempt::counter_scratch_data()
        + OriginalImport18RawBootstrap::hello_literal_loan_counter_scratch_data::<()>()
        + size_of::<&dyn OriginalImport18HelloValueAdmission>()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<[usize; 3]>()
        + size_of::<crate::retained_metadata::BootstrapBodyMetadataProfileData>()
        + size_of::<&Value>()
        + size_of::<usize>() * 5
        + size_of::<std::array::IntoIter<usize, 3>>()
}
