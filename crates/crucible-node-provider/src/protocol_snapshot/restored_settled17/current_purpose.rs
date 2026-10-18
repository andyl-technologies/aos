//! Preserves the original fixed invocation projection without native provenance.

use super::current_fixed::{FixedText17, role17};
use crate::{
    ProviderError,
    protocol_snapshot::owned11::typed::{
        Fields, HistoricalType, Ledger, historical_struct, invalid, plain_string,
    },
};
use crucible_node_contract::U64;

pub(crate) struct FixedHash17 {
    pub(crate) domain: FixedText17<128>,
    pub(crate) digest: FixedText17<128>,
}
impl HistoricalType for FixedHash17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role17(fields.named("algorithm")?, "blake3-256")?;
        let domain = ledger.read::<FixedText17<128>>(fields.named("domain")?, build)?;
        let raw = fields.named("digest")?;
        let text = plain_string(raw)?;
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        let digest = ledger.read::<FixedText17<128>>(raw, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            domain: domain.ok_or_else(invalid)?,
            digest: digest.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct FixedReference17 {
    pub(crate) hash: FixedHash17,
    pub(crate) length: U64,
    pub(crate) media_type: FixedText17<128>,
}
historical_struct!(FixedReference17 { hash: FixedHash17, length: U64, media_type: FixedText17<128> });

pub(crate) struct FixedSource17 {
    pub(crate) runtime: FixedReference17,
    pub(crate) native_state: FixedReference17,
    pub(crate) owner: FixedText17<128>,
}
historical_struct!(FixedSource17 { runtime: FixedReference17, native_state: FixedReference17, owner: FixedText17<128> });

pub(crate) struct FixedTarget17 {
    pub(crate) world: FixedHash17,
    pub(crate) binding: FixedHash17,
    pub(crate) node: FixedText17<128>,
    pub(crate) owner: FixedText17<128>,
    pub(crate) session: FixedText17<128>,
    pub(crate) incarnation: FixedText17<128>,
    pub(crate) owner_generation: U64,
    pub(crate) prepared_token: FixedText17<128>,
    pub(crate) admission: FixedText17<128>,
}
historical_struct!(FixedTarget17 {
    world: FixedHash17, binding: FixedHash17, node: FixedText17<128>, owner: FixedText17<128>,
    session: FixedText17<128>, incarnation: FixedText17<128>, owner_generation: U64,
    prepared_token: FixedText17<128>, admission: FixedText17<128>,
});

pub(crate) struct CurrentPurpose17 {
    pub(crate) original_execution: bool,
    pub(crate) source: Option<FixedSource17>,
    pub(crate) target: FixedTarget17,
}
impl HistoricalType for CurrentPurpose17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role17(
            fields.named("schema")?,
            "source-owned.packet-native-invocation-purpose/1",
        )?;
        let original_execution = match plain_string(fields.named("purpose")?)? {
            "original_execution" => true,
            "restoration_target" => false,
            _ => return Err(invalid()),
        };
        let raw = fields.named("source")?;
        if original_execution != (raw == b"null") {
            return Err(invalid());
        }
        let source = ledger.read::<Option<FixedSource17>>(raw, build)?;
        let target = ledger.read::<FixedTarget17>(fields.named("target")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            original_execution,
            source: source.ok_or_else(invalid)?,
            target: target.ok_or_else(invalid)?,
        }))
    }
}
