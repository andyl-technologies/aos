//! Commits every actual recipe field except its own digest without granting a phase.
//!
//! The identity is BLAKE3 derive-key over canonical JSON of the exact twenty-three
//! fields below, under the separate recipe-identity/18 domain. The enclosing
//! recipe's identity field is omitted. Self-consistency does not establish that
//! those fields were independently derived from the complete original inputs.

use super::*;
use crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data;

const IDENTITY_DOMAIN: &str = "source-owned.packet-native-import-prebirth-recipe-identity/18";

#[derive(Serialize)]
struct CommitmentView<'a> {
    schema: &'a RecipeSchema,
    native_family: &'a PacketNativeImport18NativeFamily,
    source_family: &'a PacketNativeImport18SourceFamily,
    semantic_spend_family: &'a PacketNativeImport18SemanticSpendFamily,

    geometry_identity: &'a [u8; 32],
    historical_shape_identity: &'a [u8; 32],
    selected_launch_identity: &'a [u8; 32],
    private_launch_identity: &'a [u8; 32],
    lease_identity: &'a [u8; 32],
    nonce: &'a [u8; 32],
    generation: &'a U64,

    archived_reference_identities: &'a [[u8; 32]; 5],
    archived_lengths: &'a [U64; 5],
    semantic_reference_identity: &'a [u8; 32],
    semantic_length: &'a U64,

    decoder_limits: &'a [U64; 10],
    maximum_target_requested_bytes: &'a U64,
    maximum_before_bytes: &'a U64,

    normalization_projection_bytes: &'a U64,
    normalization_maximum: &'a U64,
    semantic_spend_maximum: &'a U64,

    escrow: &'a [U64; 3],
    phases: &'a [[U64; 3]; 5],
}

impl<'a> CommitmentView<'a> {
    fn new(fields: &'a RecipeFields) -> Self {
        let RecipeFields {
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
            identity: _,
        } = fields;
        Self {
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
        }
    }
}

impl PacketNativeImport18PrebirthRecipeWireData {
    /// Reconstructs the commitment from every actual announced recipe operand.
    ///
    /// Callers first admit the defining construction row. No opaque recipe,
    /// provenance, lease or native permission follows from this digest.
    ///
    /// # Errors
    /// Refuses canonical construction or an encoded commitment above the
    /// independently admitted restriction.
    pub fn reconstructed_identity_data(&self, maximum: usize) -> Result<[u8; 32], ProviderError> {
        let value =
            serde_json::to_value(CommitmentView::new(&self.fields)).map_err(ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(invalid());
        }
        Ok(blake3::derive_key(IDENTITY_DOMAIN, &bytes))
    }

    /// Checks recipe self-consistency before independent full reconstruction.
    ///
    /// The same digest in several announcements is insufficient. This check
    /// commits their actual fields, but authenticates no original input or phase.
    ///
    /// # Errors
    /// Refuses invalid structure, construction failure or a changed commitment.
    pub fn authenticate_identity_data(&self, maximum: usize) -> Result<(), ProviderError> {
        self.validate_data()?;
        if self.reconstructed_identity_data(maximum)? != self.fields.identity {
            return Err(ProviderError::Correlation(
                "original import18 recipe commitment DATA",
            ));
        }
        Ok(())
    }
}

/// Quotes the complete recipe commitment window before any recipe exists.
///
/// The twenty-four-field declaration conservatively covers its twenty-three-field
/// commitment view. Actual future decimal/digest values cannot change this bound.
/// Prior raw/typed owners stay independently retained throughout canonicalization.
///
/// # Errors
/// Refuses checked arithmetic overflow or construction above the independent bound.
pub fn native_import18_recipe_identity_construction_data(
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    // This fixed declaration has no attacker-sized operands. Its general
    // report also projects a parser that this constructor never runs. Finish
    // the finite arithmetic first, then restrict only the actual owners below;
    // a hypothetical parser bank cannot substitute for canonicalization demand.
    let shape = projection::native_import18_prebirth_recipe_serialization_data(usize::MAX)?;
    let temporary = shape
        .dom_and_canonical_scratch_bytes
        .checked_add(shape.canonical_output_requested_bytes)
        .and_then(|bytes| bytes.checked_add(shape.serializer_temporary_requested_bytes))
        .and_then(|bytes| bytes.checked_add(size_of::<CommitmentView<'static>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<serde_json::Value>()))
        .and_then(|bytes| {
            bytes.checked_add(size_of::<Result<serde_json::Value, serde_json::Error>>())
        })
        .and_then(|bytes| bytes.checked_add(size_of::<Vec<u8>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<Result<Vec<u8>, ContractError>>()))
        .ok_or_else(invalid)?;
    let scratch = native_import18_recipe_identity_counter_scratch_data();
    if temporary
        .checked_add(scratch)
        .is_none_or(|peak| peak > maximum)
    {
        return Err(invalid());
    }
    Ok((temporary, scratch))
}

/// Names actual borrowed-roster, canonicalization and fixed hash controls.
pub fn native_import18_recipe_identity_counter_scratch_data() -> usize {
    projection::native_import18_recipe_projection_counter_scratch_data()
        + original_serialization_counter_scratch_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + native_import18_prebirth_recipe_counter_scratch_data()
        + size_of::<CommitmentView<'static>>()
        + size_of::<&RecipeFields>()
        + size_of::<&PacketNativeImport18PrebirthRecipeWireData>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<usize>() * 3
}

#[cfg(test)]
#[path = "identity/tests.rs"]
mod tests;
