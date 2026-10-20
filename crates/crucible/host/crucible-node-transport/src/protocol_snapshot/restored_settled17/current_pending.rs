//! Retains the two complete decoded pending Control/model owners as inert data.

use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::reference_packet::continuation_models::settled_reader::prepared::CurrentDecodedModelRecord17Data;
use crate::reference_packet::control::PacketSettledControlRecord17Data;

pub(crate) struct CurrentPendingControl17 {
    pub(crate) record: PacketSettledControlRecord17Data,
    pub(crate) model: CurrentDecodedModelRecord17Data,
}

impl HistoricalType for CurrentPendingControl17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        if plain_string(fields.named("schema")?)?
            != "source-private.native-pending-decoded-control/17"
        {
            return Err(invalid());
        }
        let record =
            ledger.read::<PacketSettledControlRecord17Data>(fields.named("record")?, build)?;
        let model =
            ledger.read::<CurrentDecodedModelRecord17Data>(fields.named("model")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            record: record.ok_or_else(invalid)?,
            model: model.ok_or_else(invalid)?,
        }))
    }
}
