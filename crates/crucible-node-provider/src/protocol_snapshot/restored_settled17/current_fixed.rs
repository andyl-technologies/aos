//! Reads fixed native17 commitments without dynamic historical heap owners.

use crate::ProviderError;
use crate::protocol_snapshot::{
    compact_bytes::ValidatedCompactBytes,
    owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};

pub(crate) struct FixedCompact17<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> HistoricalType for FixedCompact17<N> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let plan = ValidatedCompactBytes::validate(input, ledger.limits.maximum_input_bytes, N)?;
        if plan.decoded_length() != N {
            return Err(invalid());
        }
        if !build {
            return Ok(None);
        }
        let mut bytes = [0; N];
        plan.copy_range(0, &mut bytes)?;
        Ok(Some(Self(bytes)))
    }
}

/// Retains an inline text owner that mirrors bounded original native storage.
pub(crate) struct FixedText17<const N: usize> {
    pub(crate) bytes: [u8; N],
    pub(crate) length: usize,
}

impl<const N: usize> HistoricalType for FixedText17<N> {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let text = plain_string(input)?.as_bytes();
        if text.is_empty() || text.len() > N || !text.is_ascii() {
            return Err(invalid());
        }
        if !build {
            return Ok(None);
        }
        let mut bytes = [0; N];
        bytes[..text.len()].copy_from_slice(text);
        Ok(Some(Self {
            bytes,
            length: text.len(),
        }))
    }
}

pub(crate) fn role17(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn inline17<T: super::current_inline::InlineEnum17>(
    input: &[u8],
    build: bool,
) -> Result<Option<T>, ProviderError> {
    let value = T::read_inline(input)?;
    Ok(build.then_some(value))
}

pub(crate) fn fixed_usizes17<const N: usize>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<[usize; N]>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut output = [0; N];
    for value in &mut output {
        let decoded = ledger.read::<usize>(fields.next()?.ok_or_else(invalid)?, build)?;
        if let Some(decoded) = decoded {
            *value = decoded;
        }
    }
    fields.finish()?;
    Ok(build.then_some(output))
}

/// Reads each numeric spend axis without constructing a live spending ledger.
pub(crate) fn read_ledger17(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    Option<crate::protocol_snapshot::restored_suffix_history::HistoricalRestoredSuffixLedger>,
    ProviderError,
> {
    use super::current_contracts::{CurrentDto17, CurrentField17};
    use crate::protocol_snapshot::restored_suffix_history::{
        HistoricalRestoredSuffixLedger, HistoricalRestoredSuffixLedgerStage,
    };
    use crate::reference_packet::service::native_startup::PacketRestoredSuffixReservationData;
    let mut fields = Fields::object(input)?;
    role17(
        fields.named("schema")?,
        "source-private.native-restored-suffix-ledger/1",
    )?;
    let admitted = <CurrentDto17<PacketRestoredSuffixReservationData> as CurrentField17>::read(
        fields.named("admitted")?,
        ledger,
        true,
    )?
    .ok_or_else(invalid)?;
    let originals = ledger
        .read::<u64>(fields.named("originals")?, true)?
        .ok_or_else(invalid)?;
    let ingress_retained = ledger
        .read::<u64>(fields.named("ingress_retained")?, true)?
        .ok_or_else(invalid)?;
    let action_retained = ledger
        .read::<u64>(fields.named("action_retained")?, true)?
        .ok_or_else(invalid)?;
    let stage = match plain_string(fields.named("stage")?)? {
        "idle" => HistoricalRestoredSuffixLedgerStage::Idle,
        "ingress" => HistoricalRestoredSuffixLedgerStage::Ingress,
        "action" => HistoricalRestoredSuffixLedgerStage::Action,
        "failed" => HistoricalRestoredSuffixLedgerStage::Failed,
        _ => return Err(invalid()),
    };
    fields.finish()?;
    let value = HistoricalRestoredSuffixLedger::from_actual_data(
        admitted,
        originals,
        ingress_retained,
        action_retained,
        stage,
    )?;
    Ok(build.then_some(value))
}
