//! Lists the concrete ordinary DTOs admitted inside reconstructed import data.

use super::containers::ImportKey17;
use super::*;
use crate::retained_metadata::ObserveMetadata;
use crucible_node_format::*;

macro_rules! import_plain17 {
    ($($ty:ty),+ $(,)?)=>{$(impl Import17 for $ty{
        type Data=Self;
        fn write_current<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error>{self.serialize(s)}
        fn read_current(input:&[u8],l:&mut Ledger<'_, '_, '_>,build:bool)->Result<Option<Self::Data>,ProviderError>{l.read::<Self>(input,build)}
        fn observe_current(&self,o:&mut MetadataObserver<'_>)->Result<(),ProviderError>{o.observe(self)}
    })+};
}
import_plain17!(
    u8,
    u16,
    u32,
    u64,
    usize,
    bool,
    U64,
    String,
    Id,
    Bytes,
    ContentRef,
    HashRef,
    SchemaRef,
    ImplementationIdentity,
    ExtensionSelection,
    Position,
    crate::envelope::Envelope,
    serde_json::Value,
    crate::handshake::Limits,
    crate::reference_packet::control::PacketControlSelection,
    crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation,
    crate::reference_packet::service::PacketNative5CaptureProfile,
    crate::reference_packet::service::capture_allocation::PacketNativeCaptureAllocationReport
);

macro_rules! import_scalar17 {
    ($($ty:ty),+ $(,)?)=>{$(impl Import17 for $ty{
        type Data=Self;
        fn write_current<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error>{self.serialize(s)}
        fn read_current(input:&[u8],l:&mut Ledger<'_, '_, '_>,build:bool)->Result<Option<Self::Data>,ProviderError>{l.read::<Self>(input,build)}
        fn observe_current(&self,_:&mut MetadataObserver<'_>)->Result<(),ProviderError>{fn require_copy<T:Copy>(_:&T){}require_copy(self);Ok(())}
    })+};
}
import_scalar17!(crate::client::CanonicalAckCodecMetadataExtent,
    crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection,
    crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection,
    crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection,
    crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection,
    crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection,
    crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
    crate::reference_packet::service::PacketNative5ProtocolMetadataLimits,
    crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow,
    crate::connection::NativeCaptureSdkStateData,
    crate::protocol_snapshot::owned11::reader::HistoricalFrameReaderFacts);

impl Import17 for crate::reference_packet::service::native_startup::PacketNativeStartupAllocation {
    type Data = Self;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.serialize(s)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        l.read::<Self>(input, build)
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        o.observe(&self.schema)
    }
}

macro_rules! import_raw17 {
    ($($ty:ty),+ $(,)?)=>{$(impl Import17 for $ty{
        type Data=Self;
        fn write_current<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error>{self.serialize(s)}
        fn read_current(input:&[u8],l:&mut Ledger<'_, '_, '_>,build:bool)->Result<Option<Self>,ProviderError>{
            use super::super::current_contracts::{CurrentField17,CurrentDto17};
            <CurrentDto17<Self> as CurrentField17>::read(input,l,build)
        }
        fn observe_current(&self,o:&mut MetadataObserver<'_>)->Result<(),ProviderError>{super::super::current_contracts::CurrentContract17::observe_current(self,o)}
    })+};
}
import_raw17!(
    crate::reference_packet::service::ack_emitter::PacketCanonicalAckAdmissionContext,
    crate::reference_packet::service::ack_emitter::PacketCanonicalAckAdmissionProof
);

impl Import17 for crate::retained_metadata::RetainedProtocolMetadataFacts {
    type Data = super::super::current_facts::HistoricalMetadataFacts17;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        super::super::current_facts::BorrowedMetadataFacts17(self).serialize(s)
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        l.read::<Self::Data>(input, build)
    }
    fn observe_current(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        Ok(())
    }
}

macro_rules! string_key17 {
    ($ty:ty) => {
        impl ImportKey17 for $ty {
            fn compare_encoded(a: &[u8], b: &[u8]) -> Result<std::cmp::Ordering, ProviderError> {
                Ok(plain_string(a)?.cmp(plain_string(b)?))
            }
        }
    };
}
string_key17!(String);
string_key17!(Id);
macro_rules! numeric_key17 {
    ($ty:ty) => {
        impl ImportKey17 for $ty {
            fn compare_encoded(a: &[u8], b: &[u8]) -> Result<std::cmp::Ordering, ProviderError> {
                Ok(crate::protocol_snapshot::owned11::typed::unsigned(a)?
                    .cmp(&crate::protocol_snapshot::owned11::typed::unsigned(b)?))
            }
        }
    };
}
numeric_key17!(u64);
numeric_key17!(usize);

macro_rules! import_enum17 {
    ($ty:ty {$($variant:ident=>$text:literal),+ $(,)?}) => {
        impl Import17 for $ty {
            type Data = Self;

            fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(match self { $(Self::$variant => $text),+ })
            }

            fn read_current(
                input: &[u8],
                _: &mut Ledger<'_, '_, '_>,
                build: bool
            ) -> Result<Option<Self>, ProviderError> {
                let value = match plain_string(input)? {
                    $($text => Self::$variant),+,
                    _ => return Err(invalid())
                };

                Ok(build.then_some(value))
            }

            fn observe_current(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                Ok(())
            }
        }
    };
}
import_enum17!(crate::envelope::RequestOrigin{Controller=>"controller",Provider=>"provider"});
import_enum17!(crate::connection::ConnectionFailure{Read=>"read",Write=>"write",Protocol=>"protocol",Authority=>"authority",Closed=>"closed"});
import_enum17!(crate::transport::original_frames::FrameDirection{Incoming=>"incoming",Outgoing=>"outgoing"});
import_enum17!(crate::protocol_snapshot::owned11::native::blob::HistoricalNativePinPhase{Held=>"held",Quarantined=>"quarantined",Settled=>"settled"});

pub(crate) enum HistoricalImportRetirement17 {
    AbandonInert,
    Operation { owner: Id, receipt: ContentRef },
    DurableStore { receipt: ContentRef },
}
impl Import17 for crate::blob::BlobRetirement {
    type Data = HistoricalImportRetirement17;
    fn write_current<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut fields = s.serialize_struct(
            "HistoricalImportRetirement17",
            match self {
                Self::AbandonInert => 1,
                Self::Operation { .. } => 3,
                Self::DurableStore { .. } => 2,
            },
        )?;
        match self {
            Self::AbandonInert => fields.serialize_field("kind", "abandon_inert")?,
            Self::Operation { owner, receipt } => {
                fields.serialize_field("kind", "operation")?;
                fields.serialize_field("owner", &BorrowedImport17(owner))?;
                fields.serialize_field("receipt", &BorrowedImport17(receipt))?;
            }
            Self::DurableStore { receipt } => {
                fields.serialize_field("kind", "durable_store")?;
                fields.serialize_field("receipt", &BorrowedImport17(receipt))?;
            }
        }
        fields.end()
    }
    fn read_current(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError> {
        let mut f = Fields::object(input)?;
        let value = match plain_string(f.named("kind")?)? {
            "abandon_inert" => build.then_some(HistoricalImportRetirement17::AbandonInert),
            "operation" => {
                let owner = Id::read_current(f.named("owner")?, l, build)?;
                let receipt = ContentRef::read_current(f.named("receipt")?, l, build)?;
                if build {
                    Some(HistoricalImportRetirement17::Operation {
                        owner: owner.ok_or_else(invalid)?,
                        receipt: receipt.ok_or_else(invalid)?,
                    })
                } else {
                    None
                }
            }
            "durable_store" => {
                let receipt = ContentRef::read_current(f.named("receipt")?, l, build)?;
                if build {
                    Some(HistoricalImportRetirement17::DurableStore {
                        receipt: receipt.ok_or_else(invalid)?,
                    })
                } else {
                    None
                }
            }
            _ => return Err(invalid()),
        };
        f.finish()?;
        Ok(value)
    }
    fn observe_current(&self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::AbandonInert => Ok(()),
            Self::Operation { owner, receipt } => {
                owner.observe_current(o)?;
                receipt.observe_current(o)
            }
            Self::DurableStore { receipt } => receipt.observe_current(o),
        }
    }
}

impl ImportKey17 for crate::blob::TransferKey {
    fn compare_encoded(a: &[u8], b: &[u8]) -> Result<std::cmp::Ordering, ProviderError> {
        fn key(input: &[u8]) -> Result<(u8, &str, &str, &str), ProviderError> {
            let mut f = Fields::object(input)?;
            if plain_string(f.named("format")?)? != "source-private.current-import-transfer-key/17"
            {
                return Err(invalid());
            }
            let origin = match plain_string(f.named("origin")?)? {
                "controller" => 0,
                "provider" => 1,
                _ => return Err(invalid()),
            };
            let session = plain_string(f.named("session")?)?;
            let incarnation = plain_string(f.named("incarnation")?)?;
            let transfer = plain_string(f.named("transfer")?)?;
            f.finish()?;
            Ok((origin, session, incarnation, transfer))
        }
        Ok(key(a)?.cmp(&key(b)?))
    }
}
