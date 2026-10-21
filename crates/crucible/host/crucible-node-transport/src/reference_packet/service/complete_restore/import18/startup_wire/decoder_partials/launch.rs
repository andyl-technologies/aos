//! Names the unchanged Launch5 decoder nested inside selected-launch9.
//!
//! Every struct roster is tied exhaustively to its actual DATA type. Bytes
//! uses the unchanged pinned base64 decoder. Dynamic string/base64 backing
//! and diagnostic allocations remain separate construction terms.

use super::*;
use crate::client::CanonicalAckCodecMetadataExtent;
use crate::reference_packet::continuation_models::serde_partials::{
    field_selector_data, maximum_fields_data, maximum_typed_layout_data, slot_layout_data,
};
use crucible_source_birth_data::profile::{
    reference_packet::{
        PacketEvent, PacketProgramDefinition,
        connected::{PacketConnectedDefinition, PacketInputConnection},
        service::PacketConnectedSourceProgram,
    },
    reference_service::InstalledContent,
};
use std::path::PathBuf;

#[path = "launch/bytes_codec.rs"]
mod bytes_codec;

impl DecoderPartial for Bytes {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = String::HEAP_LAYOUT;
    // The longest pinned base64 Display alternative interpolates one u8 and
    // one usize. Heap growth for this message is priced by the real caller.
    const DIAGNOSTIC_NAMES_BYTES: usize = "Invalid last symbol , offset .".len()
        + u8::MAX.ilog10() as usize
        + 1
        + usize::MAX.ilog10() as usize
        + 1;

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + String::partial_counter_data()
            + size_of::<Vec<u8>>()
            + size_of::<Result<Vec<u8>, base64::DecodeError>>()
            + size_of::<base64::DecodeError>()
            + bytes_codec::counter_scratch_data()
    }
}

impl DecoderPartial for PathBuf {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = String::HEAP_LAYOUT;
    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + String::partial_counter_data()
            + size_of::<&str>()
    }
}

unit_decoder!(CanonicalAckCodecMetadataExtent {
    CanonicalAck512KiB => "CanonicalAck512KiB",
});

decoder_struct!(PacketEvent {
    id,
    evaluation,
    completion,
    payload,
});

decoder_struct!(PacketProgramDefinition { schema, events });

decoder_struct!(PacketInputConnection {
    id,
    policy,
    producer,
    consumer,
    delay_ps,
});

decoder_struct!(PacketConnectedDefinition {
    schema,
    connections,
    output,
});

impl DecoderPartial for PacketConnectedSourceProgram {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        PacketProgramDefinition::HEAP_LAYOUT,
        PacketConnectedDefinition::HEAP_LAYOUT,
    );
    const EMITTED_FIELDS: (usize, usize) = maximum_fields_data(
        (2, "kind".len() + "program".len()),
        maximum_fields_data(
            PacketProgramDefinition::EMITTED_FIELDS,
            PacketConnectedDefinition::EMITTED_FIELDS,
        ),
    );
    const TYPED_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        slot_layout_data::<Self>(),
        maximum_typed_layout_data(
            PacketProgramDefinition::TYPED_LAYOUT,
            PacketConnectedDefinition::TYPED_LAYOUT,
        ),
    );
    const BUFFERED_TAG_LEVELS: usize = 1 + if PacketProgramDefinition::BUFFERED_TAG_LEVELS
        > PacketConnectedDefinition::BUFFERED_TAG_LEVELS
    {
        PacketProgramDefinition::BUFFERED_TAG_LEVELS
    } else {
        PacketConnectedDefinition::BUFFERED_TAG_LEVELS
    };
    const DIAGNOSTIC_NAMES_BYTES: usize = "PacketConnectedSourceProgram".len()
        + "kind".len()
        + "producer".len()
        + "reactive".len()
        + "program".len()
        + 4 * ("``".len() + ", ".len())
        + PacketProgramDefinition::DIAGNOSTIC_NAMES_BYTES
        + PacketConnectedDefinition::DIAGNOSTIC_NAMES_BYTES;

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + field_selector_data()
            + Option::<PacketProgramDefinition>::partial_counter_data()
            + Option::<PacketConnectedDefinition>::partial_counter_data()
    }
}

// Each typed pattern checks the actual variant payload, without constructing
// either program or calling a witness that could select the wrong variant.
const _: fn(&PacketConnectedSourceProgram) = |value| match value {
    PacketConnectedSourceProgram::Producer { program } => {
        let _: &PacketProgramDefinition = program;
    }
    PacketConnectedSourceProgram::Reactive { program } => {
        let _: &PacketConnectedDefinition = program;
    }
};

decoder_struct!(InstalledContent { reference, bytes });

decoder_struct!(PacketNative5SourceLaunch {
    schema_version,
    selection,
    program,
    controller_pid,
    controller_uid,
    controller_executable,
    admission_token,
    initial_coordinator,
    limits,
    storage,
    capture_profile,
    confirmation_selection,
    ack_emitter_selection,
    native_codec_metadata_extent,
    protocol_metadata_limits,
    complete_restore_selection,
    restore_input_emitter_selection,
    capture_allocation_selection,
    fresh_restore_allocation_selection,
    effects,
});
