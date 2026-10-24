//! Retains original reader scalars without reconstructing a stream or cut.

use super::typed::{Fields, HistoricalType, Ledger, invalid};
use crate::ProviderError;

/// Owns the exact historical reader state independently from its original stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HistoricalFrameReaderFacts {
    /// Retains the actual original reader body limit in bytes.
    pub maximum_bytes: usize,
    /// Retains the actual original reader nesting limit.
    pub maximum_nesting: usize,
    /// Retains the sticky original decoder failure state.
    pub failed: bool,
    /// Retains the actual last original bank slot, including absence.
    pub last_original_slot: Option<usize>,
}

impl HistoricalType for HistoricalFrameReaderFacts {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let maximum_bytes = ledger
            .read::<usize>(fields.named("maximum_bytes")?, true)?
            .ok_or_else(invalid)?;
        let maximum_nesting = ledger
            .read::<usize>(fields.named("maximum_nesting")?, true)?
            .ok_or_else(invalid)?;
        let failed = ledger
            .read::<bool>(fields.named("failed")?, true)?
            .ok_or_else(invalid)?;
        let last_original_slot = ledger
            .read::<Option<usize>>(fields.named("last_original_slot")?, true)?
            .ok_or_else(invalid)?;
        fields.finish()?;
        if maximum_bytes == 0 || maximum_nesting == 0 {
            return Err(invalid());
        }
        Ok(build.then_some(Self {
            maximum_bytes,
            maximum_nesting,
            failed,
            last_original_slot,
        }))
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(
    HistoricalFrameReaderFacts,
    maximum_bytes,
    maximum_nesting,
    failed,
    last_original_slot
);
