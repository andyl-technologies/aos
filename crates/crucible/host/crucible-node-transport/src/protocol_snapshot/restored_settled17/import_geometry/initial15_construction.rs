//! Retains the funded borrowed Initial15 validator and its fixed import geometry.
//!
//! ```text
//! admitted alias bank -> existing native11 borrowed validation -> class15 geometry
//! ```
//!
//! This constructor never rebuilds the historical host graph, parses a parallel
//! native grammar or converts copied demand into permission. The defining Core
//! caller supplies genuine same-ticket five-role loans, admits this complete
//! constructor beside all retained prior owners, and retains failures before
//! invoking a later model/future visitor. No native installer or current Source
//! owner is created here.

use super::*;
use crate::protocol_snapshot::owned11::{
    aliases::{HistoricalAliasSummary, required_summary_entries_data},
    typed::{Fields, plain_string},
};
use std::{mem::size_of, thread::ThreadId};

/// Binds one constructor's complete independent work to the actual five roles.
///
/// Private fields cannot be filled from copied old decoder demand. This row is
/// DATA only: a real Source/ticket owner independently admits and spends it.
#[derive(Clone, Copy)]
pub struct Initial15NativeImportGeometryConstructionData {
    correspondence: [u8; 32],
    decoder_limits: OwnedProtocol11DataLimits,
    import_limits: RestoredSettledNative17Limits,
    normalization_maximum: usize,
    summary_entries: usize,
    retained: usize,
    scratch: usize,
}

/// Retains actual alias-bank partials and the successful validated fixed result.
///
/// This non-Clone, non-Deserialize owner supplies historical DATA only. The Core
/// parent retains the original raw roles, its own once state and actual Source
/// origin fences; this process/thread check does not replace those authorities.
pub struct Initial15NativeImportGeometryAttempt {
    process: u32,
    thread: ThreadId,
    row: Initial15NativeImportGeometryConstructionData,
    summaries: Vec<HistoricalAliasSummary>,
    validated_demand: Option<NativeOwnedProtocol11AllocationDemand>,
    geometry: Option<RestoredSettledNativeImportGeometryData>,
    complete: bool,
}

impl Initial15NativeImportGeometryConstructionData {
    /// Quotes real alias backing and fixed borrowed validation before allocation.
    ///
    /// The caller admits [`Self::counter_scratch_data`] before this allocation-
    /// free prewalk. All five full references are checked. Alias kinds and first
    /// group topology use the defining existing alias-row reader; complete view
    /// equality and full class validation run only after constructor admission.
    ///
    /// # Errors
    /// Refuses wrong role bytes or finite limits, malformed outer/alias framing,
    /// forward/excess groups, unsupported normalization bounds or checked demand
    /// beyond the independently supplied maximum. No success grants admission.
    pub fn quote_data(
        input: &RestoredSettledNative17Input<'_>,
        decoder_limits: OwnedProtocol11DataLimits,
        import_limits: RestoredSettledNative17Limits,
        normalization_maximum: usize,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        input.authenticate_role_bytes_data(&import_limits)?;
        if input.current_protocol.1.len() > decoder_limits.json.maximum_input_bytes
            || decoder_limits.json.maximum_depth == 0
            || decoder_limits.json.maximum_depth > 64
            || normalization_maximum == 0
            || normalization_maximum > 65_536
        {
            return Err(invalid());
        }
        let aliases = aliases_data(input.current_protocol.1)?;
        let summary_entries =
            required_summary_entries_data(aliases, decoder_limits.maximum_metadata_rows)?;
        let retained = size_of::<Initial15NativeImportGeometryAttempt>()
            .checked_add(
                summary_entries
                    .checked_mul(size_of::<HistoricalAliasSummary>())
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        let scratch = Self::counter_scratch_data();
        if retained
            .checked_add(scratch)
            .is_none_or(|peak| peak > maximum)
        {
            return Err(invalid());
        }
        Ok(Self {
            correspondence: input_correspondence(input),
            decoder_limits,
            import_limits,
            normalization_maximum,
            summary_entries,
            retained,
            scratch,
        })
    }

    /// Returns retained, transient and counter axes without spending them.
    ///
    /// Borrowed validation allocates only its separately retained alias bank;
    /// its JSON/compact-content traversal arrays are declared fixed scratch.
    /// No whole graph, DOM or decoded String backing is reconstructed here.
    pub const fn requested_axes_data(&self) -> [usize; 3] {
        [self.retained, 0, self.scratch]
    }

    /// Runs the existing validator beneath an already admitted same-row owner.
    ///
    /// The failed destination precedes raw identity checks, reservation, alias
    /// initialization and validation. Any error keeps its complete row, actual
    /// allocated capacity and initialized summary partials in that same owner.
    /// Genuine Core origin/once and full simultaneous peak remain caller joins.
    ///
    /// # Errors
    /// Refuses reused destination, substituted raw roles, allocation failure,
    /// malformed or non-Initial15 native data, wrong limits, short actual row or
    /// failed complete import-geometry correspondence. No retry clears a bank.
    pub fn construct_into_data(
        &self,
        input: &RestoredSettledNative17Input<'_>,
        destination: &mut Option<Initial15NativeImportGeometryAttempt>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(invalid());
        }
        *destination = Some(Initial15NativeImportGeometryAttempt {
            process: std::process::id(),
            thread: std::thread::current().id(),
            row: *self,
            summaries: Vec::new(),
            validated_demand: None,
            geometry: None,
            complete: false,
        });
        let attempt = destination.as_mut().ok_or_else(invalid)?;
        input.authenticate_role_bytes_data(&self.import_limits)?;
        if input_correspondence(input) != self.correspondence {
            return Err(invalid());
        }
        attempt
            .summaries
            .try_reserve_exact(self.summary_entries)
            .map_err(|_| exhausted())?;
        if attempt.summaries.capacity() != self.summary_entries {
            return Err(exhausted());
        }
        attempt
            .summaries
            .resize(self.summary_entries, HistoricalAliasSummary::default());
        let plan = ValidatedNativeOwnedProtocol11::validate(
            input.current_protocol.1,
            self.decoder_limits,
            &mut attempt.summaries,
        )?;
        attempt.validated_demand = Some(*plan.allocation_demand());
        attempt.geometry = Some(
            RestoredSettledNativeImportGeometryData::from_validated_initial15_data(
                input,
                &plan,
                &self.import_limits,
                self.normalization_maximum,
            )?,
        );
        drop(plan);
        attempt.authenticate_origin_data()?;
        if attempt.retained_requested_storage_data(self.retained)? != self.retained {
            return Err(exhausted());
        }
        attempt.complete = true;
        Ok(())
    }

    /// Names the defining prewalk, existing validator and fixed owner controls.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Initial15NativeImportGeometryAttempt>()
            + size_of::<&mut Option<Initial15NativeImportGeometryAttempt>>()
            + size_of::<&RestoredSettledNative17Input<'static>>()
            + size_of::<Option<RestoredSettledNativeImportGeometryData>>()
            + size_of::<NativeOwnedProtocol11AllocationDemand>()
            + size_of::<Option<NativeOwnedProtocol11AllocationDemand>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<std::collections::TryReserveError>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<&mut Vec<HistoricalAliasSummary>>()
            + size_of::<[u8; 32]>()
            + size_of::<[usize; 3]>()
            + size_of::<usize>() * 4
            + size_of::<Option<usize>>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + super::RestoredSettledNativeImportGeometryData::counter_scratch_data()
            + ValidatedNativeOwnedProtocol11::borrowed_validation_counter_scratch_data()
            + crate::protocol_snapshot::owned11::aliases::borrowed_validation_counter_scratch_data()
            + Fields::counter_scratch_data()
            + size_of::<Fields<'static>>()
    }
}

impl Initial15NativeImportGeometryAttempt {
    /// Returns the actual inline root size for consistent enclosing accounting.
    ///
    /// The complete constructor row and retained census include this header
    /// once. A parent that already includes this exact inline payload subtracts
    /// it when composing that component beside the parent's own root header.
    pub const fn header_requested_bytes_data() -> usize {
        size_of::<Self>()
    }

    fn authenticate_origin_data(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrows only the successful actual same-input geometry, without a grant.
    ///
    /// The actual parent still supplies its same Source/ticket raw custody and
    /// real origin fences before and after the consuming model visitor.
    ///
    /// # Errors
    /// Refuses another process/thread, incomplete/failed constructor, changed
    /// role fullrefs/body bytes or a missing actual class15 validated result.
    pub fn geometry_data(
        &self,
        input: &RestoredSettledNative17Input<'_>,
    ) -> Result<&RestoredSettledNativeImportGeometryData, ProviderError> {
        self.authenticate_origin_data()?;
        if !self.complete || self.validated_demand.is_none() {
            return Err(invalid());
        }
        let geometry = self.geometry.as_ref().ok_or_else(invalid)?;
        geometry.authenticate_same_inputs_data(input, self.row.normalization_maximum)?;
        Ok(geometry)
    }

    /// Counts this actual root and every retained alias-bank capacity on failure.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, checked overflow or a short maximum.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        self.authenticate_origin_data()?;
        let Self {
            process: _,
            thread: _,
            row: _,
            summaries,
            validated_demand: _,
            geometry: _,
            complete: _,
        } = self;
        let retained = size_of::<Self>()
            .checked_add(
                summaries
                    .capacity()
                    .checked_mul(size_of::<HistoricalAliasSummary>())
                    .ok_or_else(invalid)?,
            )
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(exhausted)?;
        Ok(retained)
    }

    /// Names the actual retained-census and completed-loan controls.
    pub fn retained_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&Vec<HistoricalAliasSummary>>()
            + size_of::<&RestoredSettledNativeImportGeometryData>()
            + size_of::<ThreadId>()
            + size_of::<std::thread::Thread>()
            + size_of::<usize>() * 2
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<&RestoredSettledNativeImportGeometryData, ProviderError>>()
            + RestoredSettledNativeImportGeometryData::counter_scratch_data()
    }
}

fn aliases_data(input: &[u8]) -> Result<&[u8], ProviderError> {
    let mut fields = Fields::array(input)?;
    if plain_string(fields.next_value()?.ok_or_else(invalid)?)? != "source-private.cnp-protocol/11" {
        return Err(invalid());
    }
    fields.next_value()?.ok_or_else(invalid)?;
    fields.next_value()?.ok_or_else(invalid)?;
    let aliases = fields.next_value()?.ok_or_else(invalid)?;
    fields.finish()?;
    Ok(aliases)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("Initial15 independently admitted borrowed native geometry")
}

#[cfg(test)]
mod tests;
