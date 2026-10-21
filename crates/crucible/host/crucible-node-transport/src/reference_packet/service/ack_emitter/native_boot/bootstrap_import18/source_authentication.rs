//! Funds original Source DATA checks under the unchanged physical bootstrap cut.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    source_authentication_construction_data, source_authentication_counter_scratch_data,
    source_authentication_quote_construction_data,
};

impl OriginalImport18RawBootstrap {
    /// Spends the original Source comparison once after actual typed decoding.
    ///
    /// The formatter quote precedes every serializer. Complete parsing and
    /// comparison demand precedes the first Source parser. Matching inert DATA
    /// cannot supply an Initial, recipe, genuine Birth or native admission.
    ///
    /// # Errors
    /// Refuses stale or foreign custody, re-entry, incomplete decoding, any
    /// underfunded axis/policy, or original Source/launch correspondence failure.
    pub(in super::super) fn authenticate_source_data(&mut self) -> Result<(), ProviderError> {
        if self.source_authentication_started {
            return Err(refused());
        }
        self.source_authentication_started = true;
        let outcome = self.authenticate_current_source();
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.source_authenticated = true;
        Ok(())
    }

    fn authenticate_current_source(&mut self) -> Result<(), ProviderError> {
        let bodies = self.typed_bodies_data()?;
        let base = self.decoding_row.ok_or_else(refused)?;
        let quote = source_authentication_quote_construction_data(bodies.launch.launch_data())?;
        let required = combine(base, quote)?;
        self.source_authentication_row = Some(required);
        self.admit_source_row(required)?;

        let bodies = self.typed_bodies_data()?;
        let declaration = bodies.boot.source_binding_data().declaration_data();
        let source = source_authentication_construction_data(
            declaration,
            bodies.launch.launch_data(),
            self.bounds.requested_peak,
        )?;
        let required = combine(base, source)?;
        self.source_authentication_row = Some(required);
        self.admit_source_row(required)?;

        let bodies = self.typed_bodies_data()?;
        bodies
            .boot
            .source_binding_data()
            .declaration_data()
            .authenticate_launch_data(bodies.launch.launch_data())
    }

    pub(super) fn admit_source_row(&self, required: [usize; 3]) -> Result<(), ProviderError> {
        let announced = self
            .header
            .as_ref()
            .ok_or_else(refused)?
            .initial_funding_data()?;
        let allowances = [
            announced.retained_requested_bytes.get(),
            announced.maximum_simultaneous_transient_bytes.get(),
            announced.declared_counter_scratch_bytes.get(),
        ];
        let mut peak = 0usize;
        for (demand, allowance) in required.into_iter().zip(allowances) {
            peak = peak.checked_add(demand).ok_or_else(exhausted)?;
            if u64::try_from(demand).map_err(|_| exhausted())? > allowance {
                return Err(exhausted());
            }
        }
        if peak > self.bounds.requested_peak {
            return Err(exhausted());
        }
        Ok(())
    }
}

/// Adds one sequential check to the retained original raw and typed population.
pub(super) fn combine(base: [usize; 3], check: [usize; 3]) -> Result<[usize; 3], ProviderError> {
    Ok([
        base[0].checked_add(check[0]).ok_or_else(exhausted)?,
        base[1].max(check[1]),
        base[2].checked_add(check[2]).ok_or_else(exhausted)?,
    ])
}

pub(super) fn counter_scratch_data() -> usize {
    source_authentication_counter_scratch_data()
        + size_of::<[usize; 3]>() * 4
        + size_of::<[u64; 3]>()
        + size_of::<std::iter::Zip<std::array::IntoIter<usize, 3>, std::array::IntoIter<u64, 3>>>()
        + size_of::<Result<[usize; 3], ProviderError>>() * 2
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<usize>() * 3
}
