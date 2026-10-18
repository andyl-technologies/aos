//! Pairs the actual reconstructed import heap with inert current17 data.
//!
//! Stored archive group numbers remain scalar history. New shared edges use
//! the actual second heap's Rc/Arc backing and the enclosing native17 ledger.
//! Neither complete-only archive parsing nor its old encoded bytes substitute
//! for a populated current reconstructed owner.

use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::retained_metadata::{
    MetadataObserver, aliases::MetadataSharedKind, records::MetadataRecordKind,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};

pub(crate) trait Import17: Sized {
    type Data;
    fn write_current<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Data>, ProviderError>;
    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError>;
}

pub(crate) trait SharedImport17: Import17 {
    const KIND: MetadataSharedKind;
}

pub(crate) struct BorrowedImport17<'a, T: Import17>(pub(crate) &'a T);
impl<T: Import17> Serialize for BorrowedImport17<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.write_current(serializer)
    }
}

macro_rules! import_fields17 {
    ($native:ty => $data:ident, $schema:literal, {$($field:ident:$ty:ty),+ $(,)?})=>{
        pub(crate) struct $data {$(pub(crate) $field:<$ty as $crate::protocol_snapshot::restored_settled17::current_import17::Import17>::Data),+}
        impl $crate::protocol_snapshot::restored_settled17::current_import17::Import17 for $native {
            type Data=$data;
            fn write_current<S:serde::Serializer>(&self,serializer:S)->Result<S::Ok,S::Error>{
                use serde::ser::SerializeStruct;
                let Self{$($field),+}=self;
                let mut fields=serializer.serialize_struct(stringify!($data),1+[$(stringify!($field)),+].len())?;
                fields.serialize_field("format",$schema)?;
                $(fields.serialize_field(stringify!($field),&$crate::protocol_snapshot::restored_settled17::current_import17::BorrowedImport17($field))?;)+
                fields.end()
            }
            fn read_current(input:&[u8],ledger:&mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,build:bool)->Result<Option<Self::Data>,$crate::ProviderError>{
                use $crate::protocol_snapshot::owned11::typed::{Fields,invalid,plain_string};
                let mut fields=Fields::object(input)?;
                if plain_string(fields.named("format")?)?!=$schema{return Err(invalid());}
                $(let $field=<$ty as $crate::protocol_snapshot::restored_settled17::current_import17::Import17>::read_current(fields.named(stringify!($field))?,ledger,build)?;)+
                fields.finish()?;
                if !build{return Ok(None);}
                Ok(Some($data{$($field:$field.ok_or_else(invalid)?),+}))
            }
            fn observe_current(&self,observer:&mut $crate::retained_metadata::MetadataObserver<'_>)->Result<(),$crate::ProviderError>{
                let Self{$($field),+}=self;
                $(<$ty as $crate::protocol_snapshot::restored_settled17::current_import17::Import17>::observe_current($field,observer)?;)+
                Ok(())
            }
        }
        impl $crate::protocol_snapshot::owned11::typed::HistoricalType for $data {
            fn read(input:&[u8],ledger:&mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,build:bool)->Result<Option<Self>,$crate::ProviderError>{
                <$native as $crate::protocol_snapshot::restored_settled17::current_import17::Import17>::read_current(input,ledger,build)
            }
        }
    };
}
pub(crate) use import_fields17;

mod containers;
mod leaves;

// Defining owners expose only these inert output types, never an SDK or issuer.
pub(crate) use crate::protocol_snapshot::native_archived_mapping::current17::HistoricalPreparedNativeMapping17;
pub(crate) use crate::protocol_snapshot::owned11::native::outer::current17::HistoricalSealedNativeImport17;

/// Names the concrete recursive import reader and borrowed writer headers.
pub(crate) fn current_import17_counter_scratch_data() -> usize {
    crate::protocol_snapshot::owned11::native::current17::counter_scratch_data()
        +crate::protocol_snapshot::owned11::state::current17::counter_scratch_data()
        +crate::transport::original_frames::current17::counter_scratch_data()
        +crate::transport::DecodedCompactOriginalFrames::current_import17_counter_scratch_data()
        +crate::reference_packet::service::HistoricalNativeSupervisorBanks::current_import17_counter_scratch_data()
        +crate::blob::current17::counter_scratch_data()
        +crate::connection::current17::counter_scratch_data()
        +crate::protocol_snapshot::native_archived_mapping::current17::counter_scratch_data()
}
