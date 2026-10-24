//! Names the three actual bootstrap body's typed decoder field DAGs.
//!
//! Partial layouts and diagnostic names are DATA. Dynamic backing, raw syntax,
//! parser work and failures need their own independently admitted construction
//! row before decoding. These declarations create no initial funding result.

use super::*;
use crate::reference_packet::continuation_models::serde_partials::{
    DecoderPartial, decoder_struct,
};

#[path = "decoder_partials/launch.rs"]
mod launch;

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

pub(super) use unit_decoder;

unit_decoder!(SourceSchema {
    Import18 => "source-owned.packet-canonical-ack-source-binding/18",
});

unit_decoder!(BootSchema {
    Import18 => "source-owned.packet-canonical-ack-private-boot/18",
});

unit_decoder!(PacketNativeImport18Selection {
    SourceSignedImport18 => "SourceSignedImport18",
});

decoder_struct!(PacketNativeImport18SelectedLaunchWireData {
    schema_version,
    mechanism,
    launch,
    prebirth_recipe_identity,
    initial_funding,
});

decoder_struct!(PacketNativeImport18SourceBindingWireData {
    schema,
    declaration,
    mechanism,
    prebirth_recipe,
    initial_funding,
});

decoder_struct!(PacketNativeImport18PrivateBootWireData {
    schema,
    private_key,
    birth_id,
    source_birth,
    expected_host_registration,
    private_launch,
    host_executable,
});

/// Names actual typed partials for recipe18, selected9 and private-boot18.
///
/// This omits dynamic backing, text/Value adapters, custom codec work, error
/// formatting and every native constructor. It is a layout ingredient of an
/// independently derived initial row, never a complete parser quote or credit.
pub(in crate::reference_packet) fn private_body_typed_partials_data() -> [usize; 3] {
    [
        PacketNativeImport18PrebirthRecipeWireData::partial_counter_data(),
        PacketNativeImport18SelectedLaunchWireData::partial_counter_data(),
        PacketNativeImport18PrivateBootWireData::partial_counter_data(),
    ]
}

/// Returns each actual body's slot/map geometry, tag levels and diagnostic names.
pub(in crate::reference_packet) const fn private_body_typed_geometry_data()
-> [PrivateBodyTypedGeometryData; 3] {
    [
        PrivateBodyTypedGeometryData::of::<PacketNativeImport18PrebirthRecipeWireData>(),
        PrivateBodyTypedGeometryData::of::<PacketNativeImport18SelectedLaunchWireData>(),
        PrivateBodyTypedGeometryData::of::<PacketNativeImport18PrivateBootWireData>(),
    ]
}

/// Describes one body's real typed layout without any instance or byte demand.
#[derive(Clone, Copy)]
pub(in crate::reference_packet) struct PrivateBodyTypedGeometryData {
    /// Largest actual array/typed slot size in this body's field DAG.
    pub(in crate::reference_packet) slot_bytes: usize,
    /// Largest corresponding actual alignment.
    pub(in crate::reference_packet) slot_alignment: usize,
    /// Largest actual concrete map key and value sizes combined.
    pub(in crate::reference_packet) map_entry_bytes: usize,
    /// Largest corresponding key/value alignment.
    pub(in crate::reference_packet) map_entry_alignment: usize,
    /// Simultaneously buffered tagged enum levels in this actual type DAG.
    pub(in crate::reference_packet) buffered_tag_levels: usize,
    /// Bound for actual reached type, field and variant diagnostic names.
    pub(in crate::reference_packet) diagnostic_names_bytes: usize,
    /// Distinguishes the fixed inline recipe from the two heap-owning bodies.
    pub(in crate::reference_packet) has_heap_fields: bool,
}

impl PrivateBodyTypedGeometryData {
    pub(super) const fn of<T: DecoderPartial>() -> Self {
        let (slot_bytes, slot_alignment, map_entry_bytes, map_entry_alignment) = T::HEAP_LAYOUT;
        Self {
            slot_bytes,
            slot_alignment,
            map_entry_bytes,
            map_entry_alignment,
            buffered_tag_levels: T::BUFFERED_TAG_LEVELS,
            diagnostic_names_bytes: T::DIAGNOSTIC_NAMES_BYTES,
            has_heap_fields: std::mem::needs_drop::<T>(),
        }
    }
}
