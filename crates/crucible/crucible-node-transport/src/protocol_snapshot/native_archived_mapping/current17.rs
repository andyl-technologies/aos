//! Borrows the complete current mapping, including interrupted normalization.

use super::*;
use crate::protocol_snapshot::owned11::typed::{HistoricalType, Ledger, plain_string};
use crate::protocol_snapshot::restored_settled17::{
    current_import17::{BorrowedImport17, HistoricalSealedNativeImport17, Import17},
    current_shared::read_reference17,
};
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::mem::{align_of, size_of};

pub(crate) struct HistoricalPreparedNativeMapping17 {
    pub(crate) class: RestorationMappingClass,
    pub(crate) actor_group: usize,
    pub(crate) authority: crate::handshake::HistoricalAuthority17,
    pub(crate) codec_group: usize,
    pub(crate) reference: ContentRef,
    pub(crate) nonce: [Option<u8>; 32],
    pub(crate) normalization: Vec<u8>,
    pub(crate) historical: Option<HistoricalSealedNativeImport17>,
}

struct MappingCurrent17<'a>(&'a PreparedArchivedNativeProtocolMapping);
impl PreparedArchivedNativeProtocolMapping {
    /// Borrows current logical fields without requiring successful import.
    pub(crate) fn borrowed_current17_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        Ok(MappingCurrent17(self))
    }

    /// Appends actual mapping roles and current reconstructed heap capacities.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            class: _,
            actor,
            authority,
            codec,
            reference,
            nonce: _,
            normalization,
            historical,
        } = self;
        o.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        authority.observe_retained_metadata(o)?;
        o.shared_original(MetadataSharedKind::Codec, codec.as_ref())?;
        reference.observe_current(o)?;
        normalization.observe_current(o)?;
        historical.observe_current(o)
    }
}
impl Serialize for MappingCurrent17<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let PreparedArchivedNativeProtocolMapping {
            class,
            actor: _,
            authority,
            codec: _,
            reference,
            nonce,
            normalization,
            historical,
        } = self.0;
        let mut fields = s.serialize_struct("HistoricalPreparedNativeMapping17", 9)?;
        fields.serialize_field(
            "format",
            "source-private.current-import-prepared-mapping/17",
        )?;
        fields.serialize_field(
            "class",
            match class {
                RestorationMappingClass::Legacy11 => "legacy11",
                RestorationMappingClass::StartupCapture14 => "startup_capture14",
                RestorationMappingClass::InvocationCapture15 => "invocation_capture15",
            },
        )?;
        fields.serialize_field("actor_role", "native-connection-actor")?;
        fields.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        fields.serialize_field("codec_role", "native-connection-codec")?;
        fields.serialize_field("reference", &BorrowedImport17(reference))?;
        fields.serialize_field("nonce", &BorrowedImport17(nonce))?;
        fields.serialize_field("normalization", &BorrowedImport17(normalization))?;
        fields.serialize_field("historical", &BorrowedImport17(historical))?;
        fields.end()
    }
}
impl HistoricalType for HistoricalPreparedNativeMapping17 {
    fn read(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = crate::protocol_snapshot::owned11::typed::Fields::object(input)?;
        if plain_string(fields.named("format")?)?
            != "source-private.current-import-prepared-mapping/17"
        {
            return Err(invalid());
        }
        let class = match plain_string(fields.named("class")?)? {
            "legacy11" => RestorationMappingClass::Legacy11,
            "startup_capture14" => RestorationMappingClass::StartupCapture14,
            "invocation_capture15" => RestorationMappingClass::InvocationCapture15,
            _ => return Err(invalid()),
        };
        if plain_string(fields.named("actor_role")?)? != "native-connection-actor" {
            return Err(invalid());
        }
        let actor_group = read_reference17(
            l,
            MetadataSharedKind::ProtocolOwner,
            (
                size_of::<ProtocolCaptureOwner>(),
                align_of::<ProtocolCaptureOwner>(),
            ),
        )?;
        let authority =
            crate::handshake::read_settled17_authority_data(fields.named("authority")?, l, build)?;
        if plain_string(fields.named("codec_role")?)? != "native-connection-codec" {
            return Err(invalid());
        }
        let codec_group = read_reference17(
            l,
            MetadataSharedKind::Codec,
            (
                size_of::<crate::connection::Native5CodecOwner>(),
                align_of::<crate::connection::Native5CodecOwner>(),
            ),
        )?;
        let reference = ContentRef::read_current(fields.named("reference")?, l, build)?;
        let nonce = <[u8; 32]>::read_current(fields.named("nonce")?, l, build)?;
        let normalization = Vec::<u8>::read_current(fields.named("normalization")?, l, build)?;
        let raw = fields.named("historical")?;
        let historical = if raw == b"null" {
            build.then_some(None)
        } else {
            l.read::<HistoricalSealedNativeImport17>(raw, build)?
                .map(Some)
        };
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            class,
            actor_group,
            authority: authority.ok_or_else(invalid)?,
            codec_group,
            reference: reference.ok_or_else(invalid)?,
            nonce: nonce.ok_or_else(invalid)?,
            normalization: normalization.ok_or_else(invalid)?,
            historical: historical.ok_or_else(invalid)?,
        }))
    }
}

/// Names actual mapping borrower, source and concrete inert reader layouts.
pub(crate) fn counter_scratch_data() -> usize {
    size_of::<PreparedArchivedNativeProtocolMapping>()
        + size_of::<MappingCurrent17<'static>>()
        + size_of::<HistoricalPreparedNativeMapping17>()
        + size_of::<Result<Option<HistoricalPreparedNativeMapping17>, ProviderError>>()
}
