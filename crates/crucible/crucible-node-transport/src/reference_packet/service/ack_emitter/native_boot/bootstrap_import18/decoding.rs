//! Decodes DATA only inside the original, current inherited bootstrap owner.
//!
//! Receipt and decoding have separate spent bits under the same original cut.
//! Prefix announcements restrict independently derived demand; they produce no
//! Initial or Recipe and are never substituted for actual constructor geometry.

use super::*;
use crate::reference_packet::service::complete_restore::import18::OriginalImport18DecodedBodyLoans;

impl OriginalImport18RawBootstrap {
    /// Spends one actual three-body DATA decode after complete raw receipt.
    ///
    /// Every successful prefix remains installed after a later refusal. Full
    /// Source, recipe, semantic and native validation remain independent.
    ///
    /// # Errors
    /// Refuses stale/foreign/incomplete custody, re-entry, unsupported geometry,
    /// any underfunded axis/policy or strict JSON/typed decoder failure.
    pub(in super::super) fn decode_bodies_data(&mut self) -> Result<(), ProviderError> {
        if self.decode_started {
            return Err(refused());
        }
        self.decode_started = true;
        self.bodies_data()?;
        let raw = raw_storage_floor(self.bodies.each_ref().map(Vec::len))?;
        let parsers = self.parsed.construction_data(
            self.bodies.each_ref().map(Vec::as_slice),
            self.bounds.requested_peak,
        )?;
        let required = combine(raw, parsers)?;
        self.decoding_row = Some(required);
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

        let outcome = self.decode_current_bodies();
        // Always authenticate after an actual decoder, including its refusal;
        // retain the original parser error when both paths fail.
        let terminal = self.bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.decoded = true;
        Ok(())
    }

    fn decode_current_bodies(&mut self) -> Result<(), ProviderError> {
        self.bodies_data()?;
        self.parsed.decode_recipe(&self.bodies[0])?;
        self.bodies_data()?;
        self.parsed.decode_launch(&self.bodies[1])?;
        self.bodies_data()?;
        self.parsed.decode_boot(&self.bodies[2])?;
        Ok(())
    }

    /// Lends only completed typed DATA while the original raw/cut guards hold.
    ///
    /// # Errors
    /// Refuses incomplete parsing or unavailable original custody.
    pub(in super::super) fn typed_bodies_data(
        &self,
    ) -> Result<OriginalImport18DecodedBodyLoans<'_>, ProviderError> {
        if !self.decoded {
            return Err(refused());
        }
        self.bodies_data()?;
        let bodies = self.parsed.bodies_data()?;
        self.authenticate_channel()?;
        Ok(bodies)
    }
}

/// Combines simultaneous retained outputs with the maximum sequential work.
pub(super) fn combine(
    raw: [usize; 3],
    parsers: [[usize; 3]; 3],
) -> Result<[usize; 3], ProviderError> {
    let mut row = raw;
    for parser in parsers {
        row[0] = row[0].checked_add(parser[0]).ok_or_else(exhausted)?;
        row[1] = row[1].max(parser[1]);
        row[2] = row[2].max(raw[2].checked_add(parser[2]).ok_or_else(exhausted)?);
    }
    Ok(row)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<[usize; 3]>() * 4
        + size_of::<[[usize; 3]; 3]>()
        + size_of::<std::array::IntoIter<[usize; 3], 3>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<[[usize; 3]; 3], ProviderError>>()
        + size_of::<[u64; 3]>()
        + size_of::<std::iter::Zip<std::array::IntoIter<usize, 3>, std::array::IntoIter<u64, 3>>>()
        + size_of::<usize>() * 3
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<[&[u8]; 3], ProviderError>>()
        + size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>()
}
