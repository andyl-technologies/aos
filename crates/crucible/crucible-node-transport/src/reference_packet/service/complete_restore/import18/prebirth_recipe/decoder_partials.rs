//! Names the actual fixed recipe announcement's serde field construction DAG.
//!
//! This companion describes the inert wire parser only. No announcement can
//! construct an opaque producer recipe or supply initial parser funding.

use super::*;
use crate::reference_packet::continuation_models::serde_partials::{
    DecoderPartial, decoder_struct, maximum_typed_layout_data, slot_layout_data,
};

// serde 1.0.228 constructs each fixed array from sequential next_element
// results. Previously initialized elements, the final array/result and the
// currently decoding element can coexist. Arrays introduce no heap container.
impl<T: DecoderPartial, const N: usize> DecoderPartial for [T; N] {
    const EMITTED_FIELDS: (usize, usize) = T::EMITTED_FIELDS;
    const HEAP_LAYOUT: (usize, usize, usize, usize) = T::HEAP_LAYOUT;
    const TYPED_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(slot_layout_data::<Self>(), T::TYPED_LAYOUT);
    const BUFFERED_TAG_LEVELS: usize = T::BUFFERED_TAG_LEVELS;
    const DIAGNOSTIC_NAMES_BYTES: usize =
        T::DIAGNOSTIC_NAMES_BYTES + "an array of length ".len() + usize::MAX.ilog10() as usize + 1;

    fn partial_counter_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, serde_json::Error>>()
            + size_of::<Option<T>>()
            + size_of::<Result<Option<T>, serde_json::Error>>()
            + size_of::<usize>()
            + T::partial_counter_data()
    }
}

macro_rules! unit_decoder {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        impl DecoderPartial for $name {
            const DIAGNOSTIC_NAMES_BYTES: usize = stringify!($name).len()
                $(+ $wire.len() + "``".len() + ", ".len())+;

            fn partial_counter_data() -> usize {
                size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
            }
        }

        const _: fn(&$name) = |value| match value {
            $($name::$variant => {},)+
        };
    };
}

unit_decoder!(RecipeSchema {
    Import18 => "source-private.native-import-prebirth-recipe/18",
});

unit_decoder!(PacketNativeImport18NativeFamily {
    Snapshot17 => "snapshot17",
    Snapshot18 => "snapshot18",
});

unit_decoder!(PacketNativeImport18SourceFamily {
    Captured17 => "captured17",
    Captured18 => "captured18",
    Imported18 => "imported18",
});

unit_decoder!(PacketNativeImport18SemanticSpendFamily {
    Legacy17 => "legacy17",
    Complete18 => "complete18",
});

decoder_struct!(RecipeFields {
    schema,
    native_family,
    source_family,
    semantic_spend_family,
    geometry_identity,
    historical_shape_identity,
    selected_launch_identity,
    private_launch_identity,
    lease_identity,
    nonce,
    generation,
    archived_reference_identities,
    archived_lengths,
    semantic_reference_identity,
    semantic_length,
    decoder_limits,
    maximum_target_requested_bytes,
    maximum_before_bytes,
    normalization_projection_bytes,
    normalization_maximum,
    semantic_spend_maximum,
    escrow,
    phases,
    identity,
});

// The transparent wire wrapper adds no field selector or named map of its own.
impl DecoderPartial for PacketNativeImport18PrebirthRecipeWireData {
    const EMITTED_FIELDS: (usize, usize) = RecipeFields::EMITTED_FIELDS;
    const TYPED_LAYOUT: (usize, usize, usize, usize) = RecipeFields::TYPED_LAYOUT;
    const HEAP_LAYOUT: (usize, usize, usize, usize) = RecipeFields::HEAP_LAYOUT;
    const BUFFERED_TAG_LEVELS: usize = RecipeFields::BUFFERED_TAG_LEVELS;
    const DIAGNOSTIC_NAMES_BYTES: usize = RecipeFields::DIAGNOSTIC_NAMES_BYTES;

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, serde_json::Error>>()
            + RecipeFields::partial_counter_data()
    }
}
