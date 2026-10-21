//! Reconstructs and joins initial DATA under the original physical custody.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    InitialConstructionData, authenticate_initial_headers_data,
    initial_construction_from_wire_data, initial_quote_formatter_data,
};

impl OriginalImport18RawBootstrap {
    /// Spends independent Initial DATA reconstruction after Source correspondence.
    ///
    /// This matches all header announcements with the shared physical formula.
    /// It cannot create an opaque Initial/Recipe, native model or phase grant.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete Source checking, stale/foreign custody,
    /// insufficient construction funding, or any original header/body mismatch.
    pub(in super::super) fn reconstruct_initial_data(&mut self) -> Result<(), ProviderError> {
        if self.initial_reconstruction_started {
            return Err(refused());
        }
        self.initial_reconstruction_started = true;
        let outcome = self.reconstruct_current_initial();
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.initial_reconstructed = true;
        Ok(())
    }

    fn reconstruct_current_initial(&mut self) -> Result<(), ProviderError> {
        if !self.source_authenticated {
            return Err(refused());
        }
        let bodies = self.typed_bodies_data()?;
        let formatter = initial_quote_formatter_data(bodies.launch.launch_data())?;
        let raw = raw_storage_floor(self.bodies.each_ref().map(Vec::len))?;
        let base = self.source_authentication_row.ok_or_else(refused)?;
        // Earlier parser/comparison work is finished. Its retained outputs stay
        // owned, while this quote has its own fixed controls and formatters.
        let quote = [
            base[0],
            base[1].max(formatter[1]),
            raw[2].checked_add(formatter[2]).ok_or_else(exhausted)?,
        ];
        self.initial_reconstruction_row = Some(quote);
        self.admit_source_row(quote)?;

        let bodies = self.typed_bodies_data()?;
        let derived = initial_construction_from_wire_data(
            bodies.launch,
            bodies.boot,
            self.bounds.requested_peak,
        )?;
        let row = derived.row;
        self.initial_construction = Some(derived);
        self.initial_reconstruction_row = Some(row);
        self.admit_source_row(row)?;
        let derived = self.initial_construction.as_ref().ok_or_else(refused)?;
        for (bank, maximum) in self.bodies.iter().zip(derived.maximum_encoded_bytes) {
            if bank.len() > maximum {
                return Err(refused());
            }
        }
        let bodies = self.typed_bodies_data()?;
        authenticate_initial_headers_data(
            bodies.recipe,
            bodies.launch,
            bodies.boot,
            self.header.as_ref().ok_or_else(refused)?,
            derived,
        )
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<InitialConstructionData>()
        + size_of::<Result<InitialConstructionData, ProviderError>>()
        + size_of::<&InitialConstructionData>()
        + size_of::<Option<&InitialConstructionData>>()
        + size_of::<[usize; 3]>() * 4
        + size_of::<
            std::iter::Zip<std::slice::Iter<'static, Vec<u8>>, std::array::IntoIter<usize, 3>>,
        >()
        + size_of::<usize>() * 2
        + size_of::<Option<usize>>()
        + size_of::<Result<(), ProviderError>>() * 3
}
