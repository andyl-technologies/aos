//! Projects the complete closed recipe and initial row before their values exist.
//!
//! These finite declaration widths break the initial-row/recipe-body size cycle.
//! They describe JSON storage only: no recipe, row, allocation, provenance or
//! phase permission is constructed. Actual later values must fit the same types.

use super::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};

// Exhaustive patterns tie the projection roster to the defining serde fields.
// They construct no DTO and fail compilation if a defining field is added.
const _: fn(RecipeFields) = |RecipeFields {
                                 schema: _,
                                 native_family: _,
                                 source_family: _,
                                 semantic_spend_family: _,
                                 geometry_identity: _,
                                 historical_shape_identity: _,
                                 selected_launch_identity: _,
                                 private_launch_identity: _,
                                 lease_identity: _,
                                 nonce: _,
                                 generation: _,
                                 archived_reference_identities: _,
                                 archived_lengths: _,
                                 semantic_reference_identity: _,
                                 semantic_length: _,
                                 decoder_limits: _,
                                 maximum_target_requested_bytes: _,
                                 maximum_before_bytes: _,
                                 normalization_projection_bytes: _,
                                 normalization_maximum: _,
                                 semantic_spend_maximum: _,
                                 escrow: _,
                                 phases: _,
                                 identity: _,
                             }| {};

const _: fn(PacketNativeStartupAllocationRow) =
    |PacketNativeStartupAllocationRow {
         retained_requested_bytes: _,
         maximum_simultaneous_transient_bytes: _,
         declared_counter_scratch_bytes: _,
     }| {};

// Another schema spelling requires reviewing this finite declaration too.
const _: fn(RecipeSchema) = |schema| match schema {
    RecipeSchema::Import18 => {}
};

// New variants require reviewing the finite maximum spellings below.
const _: fn(PacketNativeImport18NativeFamily) = |family| match family {
    PacketNativeImport18NativeFamily::Snapshot17 | PacketNativeImport18NativeFamily::Snapshot18 => {
    }
};

const _: fn(PacketNativeImport18SourceFamily) = |family| match family {
    PacketNativeImport18SourceFamily::Captured17
    | PacketNativeImport18SourceFamily::Captured18
    | PacketNativeImport18SourceFamily::Imported18 => {}
};

const _: fn(PacketNativeImport18SemanticSpendFamily) = |family| match family {
    PacketNativeImport18SemanticSpendFamily::Legacy17
    | PacketNativeImport18SemanticSpendFamily::Complete18 => {}
};

const RECIPE_FIELDS: [&str; 24] = [
    "schema",
    "native_family",
    "source_family",
    "semantic_spend_family",
    "geometry_identity",
    "historical_shape_identity",
    "selected_launch_identity",
    "private_launch_identity",
    "lease_identity",
    "nonce",
    "generation",
    "archived_reference_identities",
    "archived_lengths",
    "semantic_reference_identity",
    "semantic_length",
    "decoder_limits",
    "maximum_target_requested_bytes",
    "maximum_before_bytes",
    "normalization_projection_bytes",
    "normalization_maximum",
    "semantic_spend_maximum",
    "escrow",
    "phases",
    "identity",
];

const ROW_FIELDS: [&str; 3] = [
    "retained_requested_bytes",
    "maximum_simultaneous_transient_bytes",
    "declared_counter_scratch_bytes",
];

fn object(out: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    out.add_object()?;
    for field in fields {
        out.add_field(field)?;
    }
    Ok(())
}

/// Adds the defining digest width before its actual commitment exists.
///
/// # Errors
/// Refuses checked projection overflow or insufficient independent restriction.
pub(in crate::reference_packet) fn digest(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_array_extent(32)?;
    for _ in 0..32 {
        // The defining digest is [u8;32], serialized as JSON numbers.
        out.add_value(&u8::MAX)?;
    }
    Ok(())
}

fn decimals(out: &mut Projection, count: usize) -> Result<(), ProviderError> {
    out.add_array_extent(count)?;
    for _ in 0..count {
        // U64 serializes an unescaped decimal string of at most twenty bytes.
        out.add_unescaped_ascii_extent(20)?;
    }
    Ok(())
}

/// Adds the complete RecipeFields24 grammar to a caller-owned projection.
///
/// The caller separately funds the projection controls and subsequent real
/// formatter/parser/DOM/JCS construction. This creates no announced DTO.
///
/// # Errors
/// Refuses checked geometry overflow or the projection's independent maximum.
pub(in crate::reference_packet) fn native_import18_prebirth_recipe_projection_data(
    out: &mut Projection,
) -> Result<(), ProviderError> {
    object(out, &RECIPE_FIELDS)?;
    out.add_string(NATIVE_IMPORT18_PREBIRTH_RECIPE_SCHEMA)?;
    // The longest actual closed serde spelling in each independent enum.
    out.add_string("snapshot18")?;
    out.add_string("captured18")?;
    out.add_string("complete18")?;

    for _ in 0..6 {
        digest(out)?;
    }
    out.add_unescaped_ascii_extent(20)?;
    out.add_array_extent(5)?;
    for _ in 0..5 {
        digest(out)?;
    }
    decimals(out, 5)?;
    digest(out)?;
    out.add_unescaped_ascii_extent(20)?;
    decimals(out, 10)?;
    for _ in 0..5 {
        out.add_unescaped_ascii_extent(20)?;
    }
    decimals(out, 3)?;
    out.add_array_extent(5)?;
    for _ in 0..5 {
        decimals(out, 3)?;
    }
    digest(out)
}

/// Adds the defining three U64 fields without creating a numeric funding row.
///
/// # Errors
/// Refuses checked geometry overflow or the projection's independent maximum.
pub(in crate::reference_packet) fn native_import18_initial_row_projection_data(
    out: &mut Projection,
) -> Result<(), ProviderError> {
    object(out, &ROW_FIELDS)?;
    for _ in 0..3 {
        out.add_unescaped_ascii_extent(20)?;
    }
    Ok(())
}

/// Quotes the closed recipe declaration independently of its future row values.
///
/// # Errors
/// Refuses a maximum too small for the complete projection or checked overflow.
pub(in crate::reference_packet) fn native_import18_prebirth_recipe_serialization_data(
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    native_import18_prebirth_recipe_projection_data(&mut out)?;
    out.finish(maximum)
}

/// Names the actual fixed controls of these allocation-free projections.
pub(in crate::reference_packet) fn native_import18_recipe_projection_counter_scratch_data() -> usize
{
    original_serialization_counter_scratch_data()
        + size_of::<Projection>()
        + size_of::<&mut Projection>() * 4
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<Result<Projection, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<&[&str]>()
        + size_of::<&&str>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<std::ops::Range<usize>>() * 3
        + size_of::<usize>() * 5
        + size_of::<u8>()
        + size_of::<&u8>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_covers_maximum_wire_widths_without_a_producer_recipe() {
        let wire = PacketNativeImport18PrebirthRecipeWireData {
            fields: RecipeFields {
                schema: RecipeSchema::Import18,
                native_family: PacketNativeImport18NativeFamily::Snapshot18,
                source_family: PacketNativeImport18SourceFamily::Captured18,
                semantic_spend_family: PacketNativeImport18SemanticSpendFamily::Complete18,
                geometry_identity: [255; 32],
                historical_shape_identity: [255; 32],
                selected_launch_identity: [255; 32],
                private_launch_identity: [255; 32],
                lease_identity: [255; 32],
                nonce: [255; 32],
                generation: U64::new(u64::MAX),
                archived_reference_identities: [[255; 32]; 5],
                archived_lengths: [U64::new(u64::MAX); 5],
                semantic_reference_identity: [255; 32],
                semantic_length: U64::new(u64::MAX),
                decoder_limits: [U64::new(u64::MAX); 10],
                maximum_target_requested_bytes: U64::new(u64::MAX),
                maximum_before_bytes: U64::new(u64::MAX),
                normalization_projection_bytes: U64::new(u64::MAX),
                normalization_maximum: U64::new(u64::MAX),
                semantic_spend_maximum: U64::new(u64::MAX),
                escrow: [U64::new(u64::MAX); 3],
                phases: [[U64::new(u64::MAX); 3]; 5],
                identity: [255; 32],
            },
        };
        let actual = serde_json::to_vec(&wire).unwrap();
        let projected = native_import18_prebirth_recipe_serialization_data(usize::MAX / 4).unwrap();
        assert!(projected.maximum_encoded_bytes >= actual.len());
        assert!(native_import18_prebirth_recipe_serialization_data(1).is_err());
    }

    #[test]
    fn initial_row_projection_covers_the_defining_three_field_serializer() {
        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::MAX),
            maximum_simultaneous_transient_bytes: U64::new(u64::MAX),
            declared_counter_scratch_bytes: U64::new(u64::MAX),
        };
        let mut out = Projection::new(usize::MAX / 4).unwrap();
        native_import18_initial_row_projection_data(&mut out).unwrap();
        let projected = out.finish(usize::MAX / 4).unwrap();
        assert!(projected.maximum_encoded_bytes >= serde_json::to_vec(&row).unwrap().len());
    }
}
