//! Names the original declaration's required nullable-field decoder partials.

use super::super::decoder_partials::unit_decoder;
use super::*;
use crate::reference_packet::continuation_models::serde_partials::{
    DecoderPartial, decoder_struct,
};

unit_decoder!(DeclarationSchema {
    Import18 => "source-owned.packet-native-import-source-declaration/18",
});

unit_decoder!(PacketNative5FreshRestoreAllocationSelection {
    CompletedAdmit13 => "completed_admit13",
});

decoder_struct!(PacketNativeImport18SourceDeclarationWireData {
    schema,
    source_birth,
    fresh_restore_allocation_selection,
});
